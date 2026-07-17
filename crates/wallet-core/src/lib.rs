#![forbid(unsafe_code)]
//! `wallet-core` — the sans-IO facade of the EUDI wallet.
//!
//! See docs/IMPLEMENTATION_PLAN.md Section 2 (architecture) and Section 3 (FFI).
//!
//! The core is a pure state machine: the shell delivers an [`Event`], the core mutates its state
//! and returns a list of [`Effect`]s for the shell to execute. No network, clock, radio, or disk
//! lives here. It integrates the OpenID4VP remote-presentation machine ([`oid4vp`]), computes the
//! data-minimised consent screen ([`presenter`]), and verifies signatures via the pure crypto
//! backend ([`crypto_backend::AwsLc`]). Device-bound signing is an [`Effect::Sign`] the shell
//! fulfils with the Secure Enclave — the private key never enters the core.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use crypto_backend::AwsLc;
use crypto_traits::Alg;
use oid4vp::{Env, Input, ResolvedTrust, SelectedCredential, State};
use presenter::{minimum_claim_set, ConsentScreen, PaymentScreen, ScreenDescription};
use serde::{Deserialize, Serialize};
use trust::{ServiceType, TrustStore};

/// Which flow the wallet is currently driving, so a device signature is routed to the right
/// machine (presentation's key-binding JWT vs. payment's SCA authentication code).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ActiveFlow {
    None,
    Presentation,
    Payment,
}

uniffi::setup_scaffolding!();

/// A credential the wallet holds: the issuer-signed JWT plus its disclosures keyed by claim name,
/// so the core can disclose exactly the requested-and-held subset.
#[derive(Clone, Debug, Default)]
pub struct HeldCredential {
    pub issuer_jwt: String,
    pub disclosures_by_claim: BTreeMap<String, String>,
}

/// Static wallet configuration.
#[derive(Clone, Debug)]
pub struct WalletConfig {
    /// The `aud` value RPs must address requests to.
    pub wallet_client_id: String,
    /// Opaque handle to the device key (the shell maps it to a Secure Enclave key).
    pub device_key_ref: String,
}

/// Everything captured about the in-flight presentation once its request is validated.
#[derive(Clone, Debug, Default)]
struct SessionInfo {
    rp_client_id: String,
    purpose: String,
    requested_claims: Vec<String>,
    response_uri: String,
}

/// Everything that can happen *to* the core. The shell produces these (deserialised from JSON at
/// the FFI boundary).
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum Event {
    /// Set the shell's wall-clock (Unix seconds); the core has no clock of its own.
    SetClock { epoch: i64 },
    /// A remote authorization request (compact JWS) arrived via deep link / browser.
    AuthorizationRequestReceived { request: Vec<u8> },
    /// The shell fetched the RP's certificate chain (DER, leaf-first) for the pending request.
    /// Whether the RP is *registered* is decided IN-CORE against the trusted list — not here.
    RpCertChainResolved {
        rp_cert_chain: Vec<Vec<u8>>,
        registered_redirect_uris: Vec<String>,
    },
    /// The user approved the consent screen.
    UserConsented,
    /// The user declined.
    UserDeclined,
    /// The device produced the signature the core requested (routed to the active flow —
    /// presentation's key-binding JWT or payment's SCA authentication code).
    DeviceSignatureProduced { signature: Vec<u8> },
    /// The shell confirmed the vp_token reached the response_uri.
    PresentationDelivered,
    /// A payment authorization request (PSD2/TS12) arrived.
    PaymentAuthorizationRequestReceived { request: Vec<u8> },
    /// The user approved the payment confirmation screen.
    PaymentApproved,
    /// The user declined the payment.
    PaymentDeclined,
}

/// Everything the core asks the shell to do (serialised to JSON at the FFI boundary).
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum Effect {
    /// Fetch RP metadata / trust status / JWKS, then send back `RpTrustResolved`.
    ResolveRpTrust { client_id: String },
    /// Durably remember this nonce (replay protection across restarts).
    PersistNonce { nonce: u64 },
    /// Render this exact, fully-resolved screen.
    Render { screen: ScreenDescription },
    /// Sign `payload` with the device key (Secure Enclave), then send back `DeviceSignatureProduced`.
    Sign { key_ref: String, payload: Vec<u8> },
    /// Perform an HTTP POST (TLS handled by the OS), then send back `PresentationDelivered`.
    Http { url: String, body: Vec<u8> },
    /// Tear down the exchange.
    Close,
}

/// The whole wallet state.
#[derive(Debug)]
pub struct Core {
    config: WalletConfig,
    vp: State,
    seen_nonces: Vec<u64>,
    credential: Option<HeldCredential>,
    session: Option<SessionInfo>,
    now_epoch: i64,
    // Payment SCA flow.
    payment: payment::State,
    pay_seen_nonces: Vec<u64>,
    pay_pending: Option<(String, u64)>, // (response_uri, nonce) of the in-flight payment
    active: ActiveFlow,
    // Trust: the verified trusted list, used to decide RP registration in-core (not shell-supplied).
    trust_store: TrustStore,
}

impl Core {
    pub fn new(wallet_client_id: impl Into<String>, device_key_ref: impl Into<String>) -> Self {
        Core {
            config: WalletConfig {
                wallet_client_id: wallet_client_id.into(),
                device_key_ref: device_key_ref.into(),
            },
            vp: State::Idle,
            seen_nonces: Vec::new(),
            credential: None,
            session: None,
            now_epoch: 0,
            payment: payment::State::Idle,
            pay_seen_nonces: Vec::new(),
            pay_pending: None,
            active: ActiveFlow::None,
            trust_store: TrustStore::new(),
        }
    }

    /// Install/update the signed trusted list (rollback-protected). The RP-registration decision is
    /// then made in-core against these anchors — never a shell-supplied boolean.
    pub fn load_trust_list(
        &mut self,
        signed_list: &[u8],
        operator_public_key: &[u8],
    ) -> Result<(), String> {
        let list = trust::parse_and_verify(
            signed_list,
            operator_public_key,
            &AwsLc,
            Alg::Es256,
            self.now_epoch,
        )
        .map_err(|e| format!("{e:?}"))?;
        self.trust_store.update(list).map_err(|e| format!("{e:?}"))
    }

    /// Decide whether an RP cert chain is a registered relying party, in-core, via the trusted
    /// list + X.509 profile. Returns `(registered, rp_public_key_raw)`.
    fn resolve_rp(&self, chain: &[Vec<u8>]) -> (bool, Vec<u8>) {
        let anchors = self
            .trust_store
            .parsed_anchors(ServiceType::RelyingPartyAccessCa);
        match x509::check_relying_party(chain, &anchors, self.now_epoch, &AwsLc) {
            Ok(_) => {
                let key = chain
                    .first()
                    .and_then(|der| x509::parse_cert(der).ok())
                    .map(|c| c.public_key_raw)
                    .unwrap_or_default();
                (true, key)
            }
            Err(_) => (false, Vec::new()),
        }
    }

    /// Store the wallet's credential (e.g. the PID obtained via issuance).
    pub fn load_credential(&mut self, credential: HeldCredential) {
        self.credential = Some(credential);
    }

    /// The single entry point. Same state + same event ⇒ same effects (I/O is all in the shell).
    pub fn handle_event(&mut self, event: Event) -> Vec<Effect> {
        match event {
            Event::SetClock { epoch } => {
                self.now_epoch = epoch;
                Vec::new()
            }
            Event::AuthorizationRequestReceived { request } => {
                self.active = ActiveFlow::Presentation;
                self.drive(Input::AuthorizationRequest(request))
            }
            Event::RpCertChainResolved {
                rp_cert_chain,
                registered_redirect_uris,
            } => {
                // The registration decision is computed here, in-core, from the trusted list.
                let (registered, rp_public_key) = self.resolve_rp(&rp_cert_chain);
                self.drive(Input::RpTrustResolved(ResolvedTrust {
                    registered,
                    rp_public_key,
                    registered_redirect_uris,
                }))
            }
            Event::UserConsented => self.drive(Input::ConsentGranted),
            Event::UserDeclined => self.drive(Input::ConsentDeclined),
            Event::DeviceSignatureProduced { signature } => match self.active {
                // Route the device signature to whichever flow requested it.
                ActiveFlow::Payment => {
                    self.drive_payment(payment::Input::AuthCodeSignatureProduced(signature))
                }
                _ => self.drive(Input::DeviceSignatureProduced(signature)),
            },
            Event::PresentationDelivered => self.drive(Input::PresentationDelivered),
            Event::PaymentAuthorizationRequestReceived { request } => {
                self.active = ActiveFlow::Payment;
                self.drive_payment(payment::Input::PaymentAuthorizationRequest(request))
            }
            Event::PaymentApproved => self.drive_payment(payment::Input::UserApproved),
            Event::PaymentDeclined => self.drive_payment(payment::Input::UserDeclined),
        }
    }

    /// FFI-friendly wrapper: takes a JSON `Event`, returns a JSON array of `Effect`s.
    pub fn handle_event_json(&mut self, event_json: &str) -> Result<String, String> {
        let event: Event = serde_json::from_str(event_json).map_err(|e| e.to_string())?;
        let effects = self.handle_event(event);
        serde_json::to_string(&effects).map_err(|e| e.to_string())
    }

    fn drive(&mut self, input: Input) -> Vec<Effect> {
        // For consent, compute the data-minimised credential selection to present.
        let selected = self.select_credential_for(&input);

        let verifier = AwsLc;
        let digest = AwsLc;
        let (next, outputs) = {
            let env = Env {
                wallet_client_id: &self.config.wallet_client_id,
                seen_nonces: &self.seen_nonces,
                verifier: &verifier,
                digest: &digest,
                now_epoch: self.now_epoch,
                selected_credential: selected.as_ref(),
                device_key_ref: &self.config.device_key_ref,
            };
            oid4vp::step(&self.vp, &input, &env)
        };
        self.vp = next;

        // Capture session details the moment the request is validated (needed later for the
        // consent screen and the response_uri).
        if let State::RequestValidated(req) = &self.vp {
            self.session = Some(SessionInfo {
                rp_client_id: req.client_id.clone(),
                purpose: req.purpose.clone().unwrap_or_default(),
                requested_claims: req.requested_claims.clone(),
                response_uri: req.response_uri.clone(),
            });
        }

        outputs
            .into_iter()
            .flat_map(|o| self.translate(o))
            .collect()
    }

    fn drive_payment(&mut self, input: payment::Input) -> Vec<Effect> {
        let (next, outputs) = {
            let env = payment::Env {
                seen_nonces: &self.pay_seen_nonces,
                device_key_ref: &self.config.device_key_ref,
            };
            payment::step(&self.payment, &input, &env)
        };
        self.payment = next;

        // Capture the response endpoint + nonce when the confirmation screen is reached.
        if let payment::State::AwaitingConfirmation(req) = &self.payment {
            self.pay_pending = Some((req.response_uri.clone(), req.nonce));
        }
        // Record the nonce as used once the payment is authorized (replay protection).
        if let payment::State::Authorized { .. } = &self.payment {
            if let Some((_, nonce)) = self.pay_pending {
                if !self.pay_seen_nonces.contains(&nonce) {
                    self.pay_seen_nonces.push(nonce);
                }
            }
        }

        outputs
            .into_iter()
            .flat_map(|o| self.translate_payment(o))
            .collect()
    }

    fn translate_payment(&mut self, output: payment::Output) -> Vec<Effect> {
        use payment::Output as PO;
        match output {
            PO::RenderPaymentConfirmation {
                payee,
                amount_minor,
                currency,
            } => vec![Effect::Render {
                screen: ScreenDescription::PaymentConfirmation(PaymentScreen {
                    payee,
                    amount_minor,
                    currency,
                }),
            }],
            PO::SignAuthCode {
                key_ref,
                signing_input,
            } => vec![Effect::Sign {
                key_ref,
                payload: signing_input,
            }],
            PO::SendAuthorization(code) => {
                let url = self
                    .pay_pending
                    .as_ref()
                    .map(|(u, _)| u.clone())
                    .unwrap_or_default();
                vec![Effect::Http { url, body: code }]
            }
            PO::Close => vec![Effect::Close],
        }
    }

    /// The disclosures to reveal = the requested-and-held claims (data minimisation).
    fn select_credential_for(&self, input: &Input) -> Option<SelectedCredential> {
        if !matches!(input, Input::ConsentGranted) {
            return None;
        }
        let sess = self.session.as_ref()?;
        let cred = self.credential.as_ref()?;
        let held: Vec<String> = cred.disclosures_by_claim.keys().cloned().collect();
        let disclosures = minimum_claim_set(&sess.requested_claims, &held)
            .iter()
            .filter_map(|c| cred.disclosures_by_claim.get(c).cloned())
            .collect();
        Some(SelectedCredential {
            issuer_jwt: cred.issuer_jwt.clone(),
            disclosures,
        })
    }

    fn consent_screen(&self) -> ScreenDescription {
        let (rp, purpose, requested) = match &self.session {
            Some(s) => (
                s.rp_client_id.clone(),
                s.purpose.clone(),
                s.requested_claims.clone(),
            ),
            None => (String::new(), String::new(), Vec::new()),
        };
        let held: Vec<String> = self
            .credential
            .as_ref()
            .map(|c| c.disclosures_by_claim.keys().cloned().collect())
            .unwrap_or_default();
        ScreenDescription::Consent(ConsentScreen {
            rp_display_name: rp,
            purpose,
            requested_claims: minimum_claim_set(&requested, &held),
        })
    }

    fn translate(&mut self, output: oid4vp::Output) -> Vec<Effect> {
        use oid4vp::Output as O;
        match output {
            O::ResolveRpTrust { client_id } => vec![Effect::ResolveRpTrust { client_id }],
            O::PersistNonce(nonce) => {
                self.seen_nonces.push(nonce);
                vec![Effect::PersistNonce { nonce }]
            }
            O::RenderConsent { .. } => vec![Effect::Render {
                screen: self.consent_screen(),
            }],
            O::SignKeyBinding {
                key_ref,
                signing_input,
            } => vec![Effect::Sign {
                key_ref,
                payload: signing_input,
            }],
            O::SendVpToken(body) => {
                let url = self
                    .session
                    .as_ref()
                    .map(|s| s.response_uri.clone())
                    .unwrap_or_default();
                vec![Effect::Http { url, body }]
            }
            O::Close => vec![Effect::Close],
        }
    }

    /// The current presentation state (for the shell / tests to inspect).
    pub fn state(&self) -> &State {
        &self.vp
    }
}

/// The UniFFI-exposed handle the native shell (Swift now, Kotlin later) holds. It wraps [`Core`]
/// behind a mutex and speaks the FFI-friendly JSON API. The whole native surface is intentionally
/// tiny: construct, load a credential, and drive events.
#[derive(uniffi::Object)]
pub struct WalletEngine {
    inner: Mutex<Core>,
}

#[uniffi::export]
impl WalletEngine {
    /// Create an engine for a wallet instance.
    #[uniffi::constructor]
    pub fn new(wallet_client_id: String, device_key_ref: String) -> Arc<Self> {
        Arc::new(WalletEngine {
            inner: Mutex::new(Core::new(wallet_client_id, device_key_ref)),
        })
    }

    /// Install/update the signed trusted list. Returns "" on success, else an error string.
    pub fn load_trust_list(&self, signed_list: Vec<u8>, operator_public_key: Vec<u8>) -> String {
        match self
            .inner
            .lock()
            .expect("poisoned")
            .load_trust_list(&signed_list, &operator_public_key)
        {
            Ok(()) => String::new(),
            Err(e) => e,
        }
    }

    /// Load a held credential: the issuer JWT plus a JSON object mapping claim name -> disclosure.
    pub fn load_credential(&self, issuer_jwt: String, disclosures_by_claim_json: String) {
        let disclosures_by_claim: BTreeMap<String, String> =
            serde_json::from_str(&disclosures_by_claim_json).unwrap_or_default();
        self.inner
            .lock()
            .expect("poisoned")
            .load_credential(HeldCredential {
                issuer_jwt,
                disclosures_by_claim,
            });
    }

    /// Drive one event (JSON) and return the resulting effects as a JSON array. On a malformed
    /// event, returns a `{"error": "..."}` object instead of an array.
    pub fn handle_event_json(&self, event_json: String) -> String {
        match self
            .inner
            .lock()
            .expect("poisoned")
            .handle_event_json(&event_json)
        {
            Ok(effects) => effects,
            Err(err) => serde_json::json!({ "error": err }).to_string(),
        }
    }
}
