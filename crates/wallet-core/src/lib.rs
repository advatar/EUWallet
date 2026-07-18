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
use presenter::{minimum_claim_set, ConsentScreen, PaymentScreen, ScreenDescription, SignScreen};
use serde::{Deserialize, Serialize};
use trust::{ServiceType, TrustStore};

/// Which flow the wallet is currently driving, so a device signature is routed to the right
/// machine (presentation's key-binding JWT vs. payment's SCA authentication code).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ActiveFlow {
    None,
    Presentation,
    Payment,
    Issuance,
    Qes,
}

uniffi::setup_scaffolding!();

mod demo;
pub use demo::{DemoScenario, DemoWallet};

pub mod export;

/// Verify a wallet export bundle's integrity hash (TS10). Callable from the shell before re-import.
#[uniffi::export]
pub fn verify_wallet_export(json: String) -> bool {
    export::verify_export(&AwsLc, &json)
}

fn parse_format(s: &str) -> Option<oid4vci::CredentialFormat> {
    match s {
        "mso_mdoc" => Some(oid4vci::CredentialFormat::MsoMdoc),
        "dc+sd-jwt" | "vc+sd-jwt" => Some(oid4vci::CredentialFormat::DcSdJwt),
        _ => None,
    }
}

/// Lowercase hex of a 32-byte hash (for the transaction-log JSON).
fn hex32(bytes: &[u8; 32]) -> String {
    hex_bytes(bytes)
}

/// Lowercase hex of an arbitrary byte slice.
fn hex_bytes(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn format_name(f: oid4vci::CredentialFormat) -> &'static str {
    match f {
        oid4vci::CredentialFormat::MsoMdoc => "mso_mdoc",
        oid4vci::CredentialFormat::DcSdJwt => "dc+sd-jwt",
    }
}

/// A credential the wallet holds: the issuer-signed JWT plus its disclosures keyed by claim name,
/// so the core can disclose exactly the requested-and-held subset.
#[derive(Clone, Debug, Default)]
pub struct HeldCredential {
    pub issuer_jwt: String,
    pub disclosures_by_claim: BTreeMap<String, String>,
    /// This credential's index in its Token Status List, if it has one. Checked before presenting.
    pub status_index: Option<u64>,
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
    /// The consent hash + the exact claim paths shown on the consent screen, captured when it is
    /// rendered, so the transaction log can record what was shared without storing values.
    consent_hash: [u8; 32],
    shared_claims: Vec<String>,
}

/// Everything that can happen *to* the core. The shell produces these (deserialised from JSON at
/// the FFI boundary).
#[derive(Clone, Debug, Deserialize)]
// `rename_all` renames the variant TAGS; `rename_all_fields` renames the struct-variant FIELDS
// (e.g. `rp_cert_chain` -> `rpCertChain`) so the JSON wire contract with the iOS shell is fully
// camelCase. Without the latter, multi-word fields stay snake_case and the shell fails to parse.
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
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
    /// A document-signing (QES) request arrived (JSON, see `qes::parse_request`).
    QesSignRequestReceived { request: Vec<u8> },
    /// The user authorized the QES sign-confirmation screen.
    QesAuthorized,
    /// The user declined to sign.
    QesDeclined,
    /// A credential offer (OID4VCI) arrived, with the issuer's cert chain (issuer trust is decided
    /// in-core against the trusted list — not a shell boolean).
    CredentialOfferReceived {
        offer: Vec<u8>,
        issuer_cert_chain: Vec<Vec<u8>>,
        issuer_id: String,
    },
    /// The shell pushed a PAR request (auth-code flow); reports whether PKCE S256 was used.
    ParPushed { pkce_s256: bool },
    /// The browser returned an authorization code.
    AuthorizationCodeReturned { code: Vec<u8> },
    /// The user entered the pre-authorized transaction code / PIN.
    TransactionCodeEntered { code: Vec<u8> },
    /// The token endpoint responded (sender-bound + a fresh c_nonce).
    TokenReceived { bound: bool, c_nonce: u64 },
    /// The credential endpoint returned a credential.
    CredentialReceived { format: String, bytes: Vec<u8> },
}

/// Everything the core asks the shell to do (serialised to JSON at the FFI boundary).
#[derive(Clone, Debug, PartialEq, Serialize)]
// See the note on `Event`: `rename_all_fields` makes struct-variant fields (`client_id` ->
// `clientId`, `key_ref` -> `keyRef`) camelCase so the shell's `WalletEffect` decoder matches.
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
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
    // --- Issuance (OID4VCI) actions ---
    /// Push a PAR request, then send back `ParPushed`.
    PushPar,
    /// Open the browser for the authorization-code flow, then send back `AuthorizationCodeReturned`.
    OpenAuthBrowser,
    /// Prompt the user for the transaction code, then send back `TransactionCodeEntered`.
    PromptTxCode,
    /// Exchange the code for a token, then send back `TokenReceived`.
    RequestToken,
    /// Request the credential with the assembled proof, then send back `CredentialReceived`.
    RequestCredential { proof_jwt: Vec<u8> },
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
    // Issuance (OID4VCI) flow.
    issuance: oid4vci::State,
    iss_seen_c_nonces: Vec<u64>,
    device_public_key: Vec<u8>,
    wua: Option<wua::WalletUnitAttestation>,
    issuer_trusted_current: bool,
    issuer_id_current: String,
    // Revocation: the current verified Token Status List, checked before presenting.
    status_list: Option<status::StatusList>,
    // Transaction (audit) log: privacy-preserving, tamper-evident record of completed flows (TS06).
    log: txnlog::TransactionLog,
    // Payment details captured at the confirmation screen, recorded into the log on authorization.
    pay_summary: Option<txnlog::PaymentSummary>,
    pay_consent_hash: [u8; 32],
    // Attestation catalogue: the credential types the wallet understands (TS11).
    catalogue: catalogue::Catalogue,
    // QES (qualified e-signature) flow.
    qes: qes::QesState,
    qes_seen_nonces: Vec<u64>,
    qes_consent_hash: [u8; 32],
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
            issuance: oid4vci::State::Idle,
            iss_seen_c_nonces: Vec::new(),
            device_public_key: Vec::new(),
            wua: None,
            issuer_trusted_current: false,
            issuer_id_current: String::new(),
            status_list: None,
            log: txnlog::TransactionLog::new(),
            pay_summary: None,
            pay_consent_hash: [0u8; 32],
            catalogue: catalogue::default_catalogue(),
            qes: qes::QesState::Idle,
            qes_seen_nonces: Vec::new(),
            qes_consent_hash: [0u8; 32],
        }
    }

    /// The attestation catalogue as JSON (TS11): the credential types the wallet understands, each
    /// with its claims (paths + which are mandatory), format, and trusted issuers. For the UI's
    /// "available credentials" view and for planning which credential can satisfy a request.
    pub fn attestation_catalogue_json(&self) -> String {
        let types: Vec<String> = self
            .catalogue
            .list()
            .iter()
            .map(|t| {
                let claims = t
                    .claims
                    .iter()
                    .map(|c| {
                        format!(
                            r#"{{"path":{:?},"displayName":{:?},"mandatory":{}}}"#,
                            c.path, c.display_name, c.mandatory
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(",");
                let issuers = t
                    .trusted_issuers
                    .iter()
                    .map(|i| format!("{:?}", i))
                    .collect::<Vec<_>>()
                    .join(",");
                format!(
                    r#"{{"id":{:?},"displayName":{:?},"format":{:?},"claims":[{}],"trustedIssuers":[{}]}}"#,
                    t.id, t.display_name, t.format, claims, issuers
                )
            })
            .collect();
        format!("[{}]", types.join(","))
    }

    /// The transaction (audit) log — completed presentations, payments, and issuances.
    pub fn transaction_log(&self) -> &txnlog::TransactionLog {
        &self.log
    }

    /// The transaction log as a JSON array (what the iOS history screen renders). Records claim
    /// PATHS + a committing consent hash, never raw claim values.
    pub fn transaction_log_json(&self) -> String {
        let entries: Vec<String> = self
            .log
            .entries()
            .iter()
            .map(|e| {
                let claims = e
                    .claim_paths
                    .iter()
                    .map(|c| format!("{:?}", c))
                    .collect::<Vec<_>>()
                    .join(",");
                let payment = match &e.payment {
                    Some(p) => format!(
                        r#","payment":{{"payee":{:?},"amountMinor":{},"currency":{:?}}}"#,
                        p.payee, p.amount_minor, p.currency
                    ),
                    None => String::new(),
                };
                format!(
                    r#"{{"seq":{},"epoch":{},"kind":"{}","counterparty":{:?},"outcome":"{}","consentHash":"{}","claimPaths":[{}]{}}}"#,
                    e.seq,
                    e.epoch,
                    e.kind.name(),
                    e.counterparty,
                    e.outcome.name(),
                    hex32(&e.consent_hash),
                    claims,
                    payment,
                )
            })
            .collect();
        format!("[{}]", entries.join(","))
    }

    /// Erase one transaction-log entry's content (data-subject right to erasure, TS07). Leaves a
    /// tamper-evident tombstone: the chain stays intact and the deletion is auditable, but the
    /// counterparty / claim paths / consent hash / payment detail are gone. Returns whether `seq`
    /// existed.
    pub fn redact_transaction(&mut self, seq: u64) -> bool {
        self.log.redact(seq)
    }

    /// Erase the entire transaction log (full erasure / reset).
    pub fn wipe_transaction_log(&mut self) {
        self.log.wipe();
    }

    /// A portable, integrity-protected export of the holder's own wallet data (TS10): the held
    /// credential + the transaction log, under a SHA-256 hash over canonical bytes. The holder's
    /// explicit action; the shell adds at-rest encryption before it leaves the device.
    pub fn export_json(&self) -> String {
        export::export_json(&AwsLc, self.now_epoch, self.credential.as_ref(), &self.log)
    }

    /// A privacy-preserving activity report as JSON (TS08): counts by kind, redaction count, and
    /// distinct counterparties. No claim values.
    pub fn transaction_report_json(&self) -> String {
        let r = self.log.report();
        let parties = r
            .counterparties
            .iter()
            .map(|c| format!("{:?}", c))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            r#"{{"total":{},"presentations":{},"issuances":{},"payments":{},"redacted":{},"counterparties":[{}]}}"#,
            r.total, r.presentations, r.issuances, r.payments, r.redacted, parties
        )
    }

    /// Verify + store a Token Status List used to check credential revocation before presenting.
    pub fn load_status_list(
        &mut self,
        token: &[u8],
        provider_public_key: &[u8],
    ) -> Result<(), String> {
        let list = status::parse_and_verify(
            token,
            provider_public_key,
            &AwsLc,
            Alg::Es256,
            self.now_epoch,
        )
        .map_err(|e| format!("{e:?}"))?;
        self.status_list = Some(list);
        Ok(())
    }

    /// Should the held credential be blocked from presentation because it is revoked/suspended (or
    /// its status is unavailable under a fail-closed policy)? Decided in-core.
    fn status_blocks_presentation(&self) -> bool {
        let Some(idx) = self.credential.as_ref().and_then(|c| c.status_index) else {
            return false; // no status list reference → nothing to check
        };
        let st = self.status_list.as_ref().map(|l| l.status_at(idx as usize));
        // Remote presentation is online → fail closed if the status can't be resolved.
        status::decide(st, status::FailPolicy::FailClosed) == status::Decision::Reject
    }

    /// Register the device public key (the Secure Enclave key the WUA attests). Needed to check
    /// `proof_key_attested` in-core.
    pub fn load_device_key(&mut self, device_public_key: Vec<u8>) {
        self.device_public_key = device_public_key;
    }

    /// Verify + store the Wallet Unit Attestation from the provider. Returns "" on success.
    pub fn load_wua(&mut self, wua_jwt: &[u8], provider_public_key: &[u8]) -> Result<(), String> {
        let att = wua::parse_and_verify(
            wua_jwt,
            provider_public_key,
            &AwsLc,
            Alg::Es256,
            self.now_epoch,
        )
        .map_err(|e| format!("{e:?}"))?;
        self.wua = Some(att);
        Ok(())
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
            Event::UserConsented => {
                // Never present a revoked/suspended credential (checked in-core against the
                // Token Status List) — refuse before disclosing anything.
                if self.status_blocks_presentation() {
                    return vec![
                        Effect::Render {
                            screen: ScreenDescription::Error {
                                code: "credential_revoked".into(),
                                message: "This credential is no longer valid and cannot be shared."
                                    .into(),
                            },
                        },
                        Effect::Close,
                    ];
                }
                self.drive(Input::ConsentGranted)
            }
            Event::UserDeclined => self.drive(Input::ConsentDeclined),
            Event::DeviceSignatureProduced { signature } => match self.active {
                // Route the device signature to whichever flow requested it.
                ActiveFlow::Payment => {
                    self.drive_payment(payment::Input::AuthCodeSignatureProduced(signature))
                }
                ActiveFlow::Issuance => {
                    self.drive_issuance(oid4vci::Input::ProofSignatureProduced(signature))
                }
                ActiveFlow::Qes => {
                    self.drive_qes(qes::Input::AuthorizationSignatureProduced(signature))
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
            Event::QesSignRequestReceived { request } => {
                self.active = ActiveFlow::Qes;
                self.drive_qes(qes::Input::SignatureRequest(request))
            }
            Event::QesAuthorized => self.drive_qes(qes::Input::UserAuthorized),
            Event::QesDeclined => self.drive_qes(qes::Input::UserDeclined),
            Event::CredentialOfferReceived {
                offer,
                issuer_cert_chain,
                issuer_id,
            } => {
                self.active = ActiveFlow::Issuance;
                // Issuer trust is decided in-core against the trusted list (PID/attestation CAs).
                self.issuer_trusted_current = self.resolve_issuer(&issuer_cert_chain);
                self.issuer_id_current = issuer_id;
                self.drive_issuance(oid4vci::Input::CredentialOffer(offer))
            }
            Event::ParPushed { pkce_s256 } => {
                self.drive_issuance(oid4vci::Input::ParPushed { pkce_s256 })
            }
            Event::AuthorizationCodeReturned { code } => {
                self.drive_issuance(oid4vci::Input::AuthCodeReturned(code))
            }
            Event::TransactionCodeEntered { code } => {
                self.drive_issuance(oid4vci::Input::TxCodeEntered(code))
            }
            Event::TokenReceived { bound, c_nonce } => {
                let effects = self.drive_issuance(oid4vci::Input::TokenResponse { bound, c_nonce });
                // Record the c_nonce as used once we proceed to prove possession (replay guard).
                if matches!(self.issuance, oid4vci::State::ProvingPossession { .. })
                    && !self.iss_seen_c_nonces.contains(&c_nonce)
                {
                    self.iss_seen_c_nonces.push(c_nonce);
                }
                effects
            }
            Event::CredentialReceived { format, bytes } => match parse_format(&format) {
                Some(f) => {
                    self.drive_issuance(oid4vci::Input::CredentialResponse { format: f, bytes })
                }
                None => Vec::new(),
            },
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
        let was_done = matches!(self.vp, State::Done);
        self.vp = next;

        // Capture session details the moment the request is validated (needed later for the
        // consent screen and the response_uri).
        if let State::RequestValidated(req) = &self.vp {
            self.session = Some(SessionInfo {
                rp_client_id: req.client_id.clone(),
                purpose: req.purpose.clone().unwrap_or_default(),
                requested_claims: req.requested_claims.clone(),
                response_uri: req.response_uri.clone(),
                consent_hash: [0u8; 32],
                shared_claims: Vec::new(),
            });
        }

        let effects: Vec<Effect> = outputs
            .into_iter()
            .flat_map(|o| self.translate(o))
            .collect();

        // Record a completed presentation the moment the machine reaches Done (once).
        if !was_done && matches!(self.vp, State::Done) {
            self.record_presentation();
        }
        effects
    }

    /// Is the issuer chain trusted? Validated in-core against the PID/attestation CAs in the list.
    fn resolve_issuer(&self, chain: &[Vec<u8>]) -> bool {
        let mut anchors = self.trust_store.parsed_anchors(ServiceType::PidProvider);
        anchors.extend(
            self.trust_store
                .parsed_anchors(ServiceType::AttestationProvider),
        );
        !anchors.is_empty() && x509::validate_path(chain, &anchors, self.now_epoch, &AwsLc).is_ok()
    }

    fn drive_issuance(&mut self, input: oid4vci::Input) -> Vec<Effect> {
        // proof_key_attested is computed in-core: the loaded WUA must verify AND bind this device
        // key at High assurance — never a shell boolean.
        let proof_key_attested = self
            .wua
            .as_ref()
            .map(|w| w.is_valid_for(&self.device_public_key, wua::AssuranceLevel::High))
            .unwrap_or(false);

        let (next, outputs) = {
            let env = oid4vci::Env {
                issuer_trusted: self.issuer_trusted_current,
                proof_key_attested,
                seen_c_nonces: &self.iss_seen_c_nonces,
                device_key_ref: &self.config.device_key_ref,
                issuer_id: &self.issuer_id_current,
                now_epoch: self.now_epoch,
            };
            oid4vci::step(&self.issuance, &input, &env)
        };
        let was_issued = matches!(self.issuance, oid4vci::State::CredentialIssued { .. });
        self.issuance = next;

        let effects: Vec<Effect> = outputs
            .into_iter()
            .map(|o| self.translate_issuance(o))
            .collect();

        // Record a completed issuance the moment the credential is issued (once).
        if !was_issued {
            if let oid4vci::State::CredentialIssued { format, .. } = &self.issuance {
                let fmt = format_name(*format).to_string();
                self.record_issuance(fmt);
            }
        }
        effects
    }

    fn translate_issuance(&self, output: oid4vci::Output) -> Effect {
        use oid4vci::Output as O;
        match output {
            O::PushPar => Effect::PushPar,
            O::OpenAuthBrowser => Effect::OpenAuthBrowser,
            O::PromptTxCode => Effect::PromptTxCode,
            O::RequestToken => Effect::RequestToken,
            O::SignProof {
                key_ref,
                signing_input,
            } => Effect::Sign {
                key_ref,
                payload: signing_input,
            },
            O::RequestCredential { proof_jwt } => Effect::RequestCredential { proof_jwt },
            O::Close => Effect::Close,
        }
    }

    /// The most recently issued credential (format + bytes), if issuance completed.
    pub fn issued_credential(&self) -> Option<(String, Vec<u8>)> {
        match &self.issuance {
            oid4vci::State::CredentialIssued { format, credential } => {
                Some((format_name(*format).to_string(), credential.clone()))
            }
            _ => None,
        }
    }

    fn drive_payment(&mut self, input: payment::Input) -> Vec<Effect> {
        let (next, outputs) = {
            let env = payment::Env {
                seen_nonces: &self.pay_seen_nonces,
                device_key_ref: &self.config.device_key_ref,
            };
            payment::step(&self.payment, &input, &env)
        };
        let was_authorized = matches!(self.payment, payment::State::Authorized { .. });
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

        let effects: Vec<Effect> = outputs
            .into_iter()
            .flat_map(|o| self.translate_payment(o))
            .collect();

        // Record a completed payment the moment the machine reaches Authorized (once).
        if !was_authorized && matches!(self.payment, payment::State::Authorized { .. }) {
            self.record_payment();
        }
        effects
    }

    fn translate_payment(&mut self, output: payment::Output) -> Vec<Effect> {
        use payment::Output as PO;
        match output {
            PO::RenderPaymentConfirmation {
                creditor_name,
                creditor_account,
                amount_minor,
                currency,
            } => {
                let screen = ScreenDescription::PaymentConfirmation(PaymentScreen {
                    creditor_name: creditor_name.clone(),
                    creditor_account,
                    amount_minor,
                    currency: currency.clone(),
                });
                // Capture the payer-visible essence + the committing hash for the audit log.
                self.pay_consent_hash = presenter::consent_hash(&AwsLc, &screen);
                self.pay_summary = Some(txnlog::PaymentSummary {
                    payee: creditor_name,
                    amount_minor,
                    currency,
                });
                vec![Effect::Render { screen }]
            }
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
    /// Drive the QES machine. The `consent_hash` in the env is the hash of the sign-confirmation
    /// screen captured on render, so the DTBS/R the device signs binds what the user saw.
    fn drive_qes(&mut self, input: qes::Input) -> Vec<Effect> {
        let (next, outputs) = {
            let env = qes::Env {
                seen_nonces: &self.qes_seen_nonces,
                device_key_ref: &self.config.device_key_ref,
                consent_hash: self.qes_consent_hash,
            };
            qes::step(&self.qes, &input, &env)
        };
        self.qes = next;
        // Record the request nonce once the confirmation is reached (replay protection).
        if let qes::QesState::AwaitingAuthorization(req) = &self.qes {
            if !self.qes_seen_nonces.contains(&req.nonce) {
                self.qes_seen_nonces.push(req.nonce);
            }
        }
        outputs
            .into_iter()
            .flat_map(|o| self.translate_qes(o))
            .collect()
    }

    fn translate_qes(&mut self, output: qes::Output) -> Vec<Effect> {
        use qes::Output as QO;
        match output {
            QO::RenderSignConfirmation {
                document_name,
                qtsp_id,
                document_hash,
            } => {
                let screen = ScreenDescription::SignConfirmation(SignScreen {
                    document_name,
                    qtsp_id,
                    document_hash_hex: hex_bytes(&document_hash),
                });
                // WYSIWYS anchor: bind the qualified signature to exactly this confirmation.
                self.qes_consent_hash = presenter::consent_hash(&AwsLc, &screen);
                vec![Effect::Render { screen }]
            }
            QO::SignAuthorization {
                key_ref,
                signing_input,
            } => vec![Effect::Sign {
                key_ref,
                payload: signing_input,
            }],
            // The QTSP endpoint (CSC API) is resolved by the shell; the body is the authorization.
            QO::SendToQtsp(body) => vec![Effect::Http {
                url: String::new(),
                body,
            }],
            QO::Close => vec![Effect::Close],
        }
    }

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

    /// Append a completed presentation to the audit log (paths + consent hash, never values).
    fn record_presentation(&mut self) {
        let entry = match &self.session {
            Some(sess) => txnlog::NewEntry {
                epoch: self.now_epoch,
                kind: txnlog::Kind::Presentation,
                counterparty: sess.rp_client_id.clone(),
                consent_hash: sess.consent_hash,
                claim_paths: sess.shared_claims.clone(),
                outcome: txnlog::Outcome::Completed,
                payment: None,
            },
            None => return,
        };
        self.log.append(&AwsLc, entry);
    }

    /// Append an authorised payment to the audit log (payer-visible summary + consent hash).
    fn record_payment(&mut self) {
        let summary = match &self.pay_summary {
            Some(s) => s.clone(),
            None => return,
        };
        let entry = txnlog::NewEntry {
            epoch: self.now_epoch,
            kind: txnlog::Kind::Payment,
            counterparty: summary.payee.clone(),
            consent_hash: self.pay_consent_hash,
            claim_paths: Vec::new(),
            outcome: txnlog::Outcome::Completed,
            payment: Some(summary),
        };
        self.log.append(&AwsLc, entry);
    }

    /// Append a completed issuance to the audit log (issuer identity + credential format).
    fn record_issuance(&mut self, format: String) {
        let entry = txnlog::NewEntry {
            epoch: self.now_epoch,
            kind: txnlog::Kind::Issuance,
            counterparty: self.issuer_id_current.clone(),
            consent_hash: [0u8; 32],
            claim_paths: vec![format],
            outcome: txnlog::Outcome::Completed,
            payment: None,
        };
        self.log.append(&AwsLc, entry);
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
            O::RenderConsent { .. } => {
                let screen = self.consent_screen();
                // Capture what the user is about to see: the consent hash commits to it, and the
                // exact claim paths shown are what we record when the presentation completes.
                if let (Some(sess), ScreenDescription::Consent(c)) =
                    (self.session.as_mut(), &screen)
                {
                    sess.consent_hash = presenter::consent_hash(&AwsLc, &screen);
                    sess.shared_claims = c.requested_claims.clone();
                }
                vec![Effect::Render { screen }]
            }
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

    /// Register the device public key the WUA attests (raw uncompressed point).
    pub fn load_device_key(&self, device_public_key: Vec<u8>) {
        self.inner
            .lock()
            .expect("poisoned")
            .load_device_key(device_public_key);
    }

    /// Verify + store a Token Status List (for revocation checks). Returns "" on success.
    pub fn load_status_list(&self, token: Vec<u8>, provider_public_key: Vec<u8>) -> String {
        match self
            .inner
            .lock()
            .expect("poisoned")
            .load_status_list(&token, &provider_public_key)
        {
            Ok(()) => String::new(),
            Err(e) => e,
        }
    }

    /// Verify + store the Wallet Unit Attestation. Returns "" on success, else an error string.
    pub fn load_wua(&self, wua_jwt: Vec<u8>, provider_public_key: Vec<u8>) -> String {
        match self
            .inner
            .lock()
            .expect("poisoned")
            .load_wua(&wua_jwt, &provider_public_key)
        {
            Ok(()) => String::new(),
            Err(e) => e,
        }
    }

    /// Load a held credential: the issuer JWT plus a JSON object mapping claim name -> disclosure.
    pub fn load_credential(
        &self,
        issuer_jwt: String,
        disclosures_by_claim_json: String,
        status_index: Option<u64>,
    ) {
        let disclosures_by_claim: BTreeMap<String, String> =
            serde_json::from_str(&disclosures_by_claim_json).unwrap_or_default();
        self.inner
            .lock()
            .expect("poisoned")
            .load_credential(HeldCredential {
                issuer_jwt,
                disclosures_by_claim,
                status_index,
            });
    }

    /// The transaction (audit) log as JSON — completed presentations, payments, issuances. Records
    /// claim paths + a committing consent hash, never raw claim values (TS06). For the history UI.
    pub fn transaction_log_json(&self) -> String {
        self.inner.lock().expect("poisoned").transaction_log_json()
    }

    /// Erase one transaction-log entry (right to erasure, TS07). Chain-preserving tombstone.
    pub fn redact_transaction(&self, seq: u64) -> bool {
        self.inner.lock().expect("poisoned").redact_transaction(seq)
    }

    /// Erase the entire transaction log (TS07).
    pub fn wipe_transaction_log(&self) {
        self.inner.lock().expect("poisoned").wipe_transaction_log();
    }

    /// A privacy-preserving activity report as JSON (TS08).
    pub fn transaction_report_json(&self) -> String {
        self.inner
            .lock()
            .expect("poisoned")
            .transaction_report_json()
    }

    /// A portable, integrity-protected export of the holder's wallet data as JSON (TS10).
    pub fn export_json(&self) -> String {
        self.inner.lock().expect("poisoned").export_json()
    }

    /// The attestation catalogue as JSON (TS11): known credential types + their claims/issuers.
    pub fn attestation_catalogue_json(&self) -> String {
        self.inner
            .lock()
            .expect("poisoned")
            .attestation_catalogue_json()
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
