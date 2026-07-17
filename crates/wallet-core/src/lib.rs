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

use crypto_backend::AwsLc;
use oid4vp::{Env, Input, ResolvedTrust, SelectedCredential, State};
use presenter::{minimum_claim_set, ConsentScreen, ScreenDescription};
use serde::{Deserialize, Serialize};

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
    /// The shell resolved RP trust/JWKS for the pending request.
    RpTrustResolved {
        registered: bool,
        rp_public_key: Vec<u8>,
        registered_redirect_uris: Vec<String>,
    },
    /// The user approved the consent screen.
    UserConsented,
    /// The user declined.
    UserDeclined,
    /// The device produced the key-binding signature the core requested.
    DeviceSignatureProduced { signature: Vec<u8> },
    /// The shell confirmed the vp_token reached the response_uri.
    PresentationDelivered,
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
                self.drive(Input::AuthorizationRequest(request))
            }
            Event::RpTrustResolved {
                registered,
                rp_public_key,
                registered_redirect_uris,
            } => self.drive(Input::RpTrustResolved(ResolvedTrust {
                registered,
                rp_public_key,
                registered_redirect_uris,
            })),
            Event::UserConsented => self.drive(Input::ConsentGranted),
            Event::UserDeclined => self.drive(Input::ConsentDeclined),
            Event::DeviceSignatureProduced { signature } => {
                self.drive(Input::DeviceSignatureProduced(signature))
            }
            Event::PresentationDelivered => self.drive(Input::PresentationDelivered),
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
