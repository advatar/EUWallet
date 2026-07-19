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
use crypto_traits::{Alg, Digest};
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
    WalletTransfer,
}

uniffi::setup_scaffolding!();

mod demo;
pub use demo::{DemoScenario, DemoWallet, IssuanceScenario};

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

/// Parse a `dc+sd-jwt` compact serialization (`<issuer-jwt>~<disclosure>~…~`) into a held
/// credential: the issuer JWT plus each named disclosure keyed by its claim name. Returns `None`
/// if the compact is malformed. This is how an issued credential (received over the wire) becomes
/// a stored holding — the same shape the shell loads a credential in.
fn held_credential_from_compact(bytes: &[u8]) -> Option<HeldCredential> {
    let compact = core::str::from_utf8(bytes).ok()?;
    let sd = sdjwt::SdJwtVc::parse(compact).ok()?;
    let mut disclosures_by_claim = BTreeMap::new();
    for raw in &sd.disclosures {
        let d = sdjwt::Disclosure::parse(raw).ok()?;
        // Object-member disclosures ([salt, name, value]) are the claims a wallet holds.
        if let Some(name) = d.name {
            disclosures_by_claim.insert(name, raw.clone());
        }
    }
    Some(HeldCredential {
        issuer_jwt: sd.issuer_jwt,
        disclosures_by_claim,
        status_index: None,
    })
}

/// Parse an issued `mso_mdoc` credential into a holding. OpenID4VCI delivers it as a base64url
/// string of the `IssuerSigned` CBOR; we decode, parse, and read its doctype from the MSO.
fn mdoc_holding_from_credential(bytes: &[u8]) -> Option<MdocHolding> {
    use base64ct::{Base64UrlUnpadded, Encoding};
    let compact = core::str::from_utf8(bytes).ok()?;
    let cbor = Base64UrlUnpadded::decode_vec(compact.trim()).ok()?;
    let issuer_signed = mdoc::IssuerSigned::parse(&cbor).ok()?;
    let doctype = issuer_signed.doc_type().ok()?;
    Some(MdocHolding {
        doctype,
        issuer_signed,
    })
}

/// A human-readable rendering of an mdoc element value for the card display (UI hint only).
fn cbor_value_display(v: &cose::cbor::Value) -> String {
    use cose::cbor::Value as V;
    match v {
        V::Text(s) => s.clone(),
        V::Bool(b) => b.to_string(),
        V::Uint(n) => n.to_string(),
        V::Nint(n) => format!("-{}", *n as i128 + 1),
        _ => "…".into(),
    }
}

/// Drop the issuer-signed items a request did not ask for (mdoc data minimisation). The MSO
/// (`issuerAuth`) is left intact; a verifier checks each *presented* item's digest against it, so
/// omitting items is valid and reveals only the requested-and-held subset.
fn minimise_mdoc(issued: &mdoc::IssuerSigned, requested_claims: &[String]) -> mdoc::IssuerSigned {
    // mdoc DCQL claim paths are `[namespace, element]`, rendered "<namespace>.<element>". Match the
    // issuer-signed items against that namespaced identity.
    let all: Vec<String> = mdoc_claim_ids(issued);
    let keep = minimum_claim_set(requested_claims, &all);
    let name_spaces = issued
        .name_spaces
        .iter()
        .map(|(ns, items)| {
            (
                ns.clone(),
                items
                    .iter()
                    .filter(|it| keep.contains(&format!("{ns}.{}", it.element_id)))
                    .cloned()
                    .collect(),
            )
        })
        .collect();
    mdoc::IssuerSigned {
        name_spaces,
        issuer_auth: issued.issuer_auth.clone(),
    }
}

/// The namespaced claim identities (`<namespace>.<element>`) an mdoc holding carries.
fn mdoc_claim_ids(issued: &mdoc::IssuerSigned) -> Vec<String> {
    issued
        .name_spaces
        .iter()
        .flat_map(|(ns, items)| items.iter().map(move |it| format!("{ns}.{}", it.element_id)))
        .collect()
}

/// A deterministic `mdoc_generated_nonce` derived from the request nonce. The sans-IO core has no
/// RNG; a production shell should instead supply a fresh random value (bound into the JWE `apu`
/// for encrypted responses). Deriving it per-request keeps the unencrypted direct_post transcript
/// well-formed and unique per presentation.
fn mdoc_generated_nonce(nonce: u64) -> String {
    let h = AwsLc.sha256(format!("eudi-mdoc-generated-nonce:{nonce}").as_bytes());
    format!("mgn-{}", hex_bytes(&h[..12]))
}

/// Percent-decode an `application/x-www-form-urlencoded` value (reverses `form_urlencode`).
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(hi), Some(lo)) =
                ((b[i + 1] as char).to_digit(16), (b[i + 2] as char).to_digit(16))
            {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Read one field's (percent-decoded) value from a form-encoded body (`k=v&k2=v2`).
fn form_field(body: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    body.split('&')
        .find_map(|kv| kv.strip_prefix(&prefix).map(percent_decode))
}

/// Read a credential's type (`vct`) and issuer (`iss`) from its issuer JWT payload, for display.
/// Returns empty strings for anything unparseable — this is a UI hint, never a trust decision.
fn credential_vct_and_issuer(issuer_jwt: &str) -> (String, String) {
    use base64ct::{Base64UrlUnpadded, Encoding};
    let payload_b64 = match issuer_jwt.split('.').nth(1) {
        Some(p) => p,
        None => return (String::new(), String::new()),
    };
    let Ok(bytes) = Base64UrlUnpadded::decode_vec(payload_b64) else {
        return (String::new(), String::new());
    };
    let Ok(json) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return (String::new(), String::new());
    };
    let vct = json
        .get("vct")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let iss = json
        .get("iss")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    (vct, iss)
}

/// A credential the wallet holds: the issuer-signed JWT plus its disclosures keyed by claim name,
/// so the core can disclose exactly the requested-and-held subset.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HeldCredential {
    pub issuer_jwt: String,
    pub disclosures_by_claim: BTreeMap<String, String>,
    /// This credential's index in its Token Status List, if it has one. Checked before presenting.
    pub status_index: Option<u64>,
}

/// An ISO 18013-5 mdoc the wallet holds (issued in the `mso_mdoc` format): the parsed
/// issuer-signed structure and its doctype. Presented over OpenID4VP as a `DeviceResponse`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MdocHolding {
    pub doctype: String,
    pub issuer_signed: mdoc::IssuerSigned,
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
    /// The union of requested claim paths across all DCQL queries — drives the consent screen and
    /// the legacy (no-DCQL) single-credential selection. Per-query selection reads `dcql` instead.
    requested_claims: Vec<String>,
    /// The request nonce, needed to bind the mdoc OpenID4VP SessionTranscript.
    nonce: u64,
    response_uri: String,
    /// The response mode: `direct_post` (form body) or `direct_post.jwt` (JWE-encrypted response).
    response_mode: String,
    /// The verifier's response-encryption key (uncompressed P-256), present iff `direct_post.jwt`.
    response_encryption_key: Option<Vec<u8>>,
    /// The full DCQL query when present — one credential query per credential the RP wants, so the
    /// wallet can select and present ONE credential per query (multi-credential presentation).
    dcql: Option<oid4vp::dcql::DcqlQuery>,
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
    /// The holder wants to RECEIVE a credential from a peer wallet (TS09): publish an offer
    /// carrying this wallet's key + a fresh nonce over the peer transport (BLE/QR).
    WalletTransferOfferCreated,
    /// A peer sent a credential transfer. The core decides IN-CORE whether to accept: the issuer
    /// signature must validate against the trusted list (`issuer_valid`), and the sender's transfer
    /// authorization must be bound to THIS wallet's key + this credential (`peer_bound`). None of
    /// that is a shell boolean.
    WalletTransferReceived {
        /// The transferred credential (compact SD-JWT VC).
        credential: Vec<u8>,
        /// The credential issuer's certificate chain (DER, leaf-first).
        issuer_cert_chain: Vec<Vec<u8>>,
        /// The sending wallet's public key (raw), which signed the transfer authorization.
        sender_public_key: Vec<u8>,
        /// The sender's signature over `w2w::transfer_authorization_binding(...)`.
        sender_signature: Vec<u8>,
        /// The consent hash the sender bound (its WYSIWYS anchor; carried in the transfer).
        sender_consent_hash: Vec<u8>,
        /// The transfer nonce.
        nonce: u64,
    },
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
    /// Publish a wallet-to-wallet receive offer over the peer transport: this wallet's key (the
    /// binding the sender must target). The shell adds a fresh nonce + BLE/QR transport (TS09).
    PublishTransferOffer { offered_key: Vec<u8> },
    /// Tear down the exchange.
    Close,
}

/// The whole wallet state.
#[derive(Debug)]
pub struct Core {
    config: WalletConfig,
    vp: State,
    seen_nonces: Vec<u64>,
    /// The credentials the wallet holds. A real wallet holds several (a PID, an mDL, …); issuance
    /// appends, and presentation selects the one that data-minimally satisfies the request.
    credentials: Vec<HeldCredential>,
    /// mdoc holdings (ISO 18013-5), presented over OpenID4VP as DeviceResponses.
    mdoc_holdings: Vec<MdocHolding>,
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
    // Wallet-to-wallet receive (TS09): the receiver machine + the credential it accepted.
    w2w: w2w::State,
    w2w_credential: Option<Vec<u8>>,
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
            credentials: Vec::new(),
            mdoc_holdings: Vec::new(),
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
            w2w: w2w::State::Idle,
            w2w_credential: None,
        }
    }

    /// The credential accepted via a wallet-to-wallet transfer, if one completed (TS09).
    pub fn received_transfer_credential(&self) -> Option<Vec<u8>> {
        self.w2w_credential.clone()
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
                    r#"{{"seq":{},"epoch":{},"kind":"{}","counterparty":{:?},"outcome":"{}","consentHash":"{}","redacted":{},"claimPaths":[{}]{}}}"#,
                    e.seq,
                    e.epoch,
                    e.kind.name(),
                    e.counterparty,
                    e.outcome.name(),
                    hex32(&e.consent_hash),
                    e.redacted,
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
        export::export_json(&AwsLc, self.now_epoch, self.credentials.first(), &self.log)
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
            r#"{{"total":{},"presentations":{},"issuances":{},"payments":{},"transfers":{},"redacted":{},"counterparties":[{}]}}"#,
            r.total, r.presentations, r.issuances, r.payments, r.transfers, r.redacted, parties
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
        let Some(idx) = self.credentials.iter().find_map(|c| c.status_index) else {
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

    /// Add a credential to the wallet's holdings (e.g. a PID or mDL obtained via issuance).
    /// Idempotent: loading a byte-identical credential twice does not duplicate it.
    pub fn load_credential(&mut self, credential: HeldCredential) {
        if !self.credentials.contains(&credential) {
            self.credentials.push(credential);
        }
    }

    /// Add an mdoc holding (e.g. an mso_mdoc mDL obtained via issuance). Idempotent.
    pub fn load_mdoc_credential(&mut self, holding: MdocHolding) {
        if !self.mdoc_holdings.contains(&holding) {
            self.mdoc_holdings.push(holding);
        }
    }

    /// The credentials the wallet holds, as a JSON array the UI renders as cards. Each entry gives
    /// the credential `vct`, its issuer (`iss`), and the disclosures by claim (so the shell can
    /// decode the holder-visible values) — never the raw device/issuer keys. Reflects exactly what
    /// the core stores, including credentials just obtained via issuance.
    pub fn held_credentials_json(&self) -> String {
        let mut items: Vec<String> = self
            .credentials
            .iter()
            .map(|c| {
                let (vct, iss) = credential_vct_and_issuer(&c.issuer_jwt);
                let disclosures = c
                    .disclosures_by_claim
                    .iter()
                    .map(|(k, v)| format!("{:?}:{:?}", k, v))
                    .collect::<Vec<_>>()
                    .join(",");
                format!(
                    r#"{{"vct":{:?},"issuer":{:?},"format":"dc+sd-jwt","disclosuresByClaim":{{{}}}}}"#,
                    vct, iss, disclosures
                )
            })
            .collect();
        // mdoc holdings: values are already decoded (no salted disclosures) — surface them under
        // `claims` so the shell renders the card; `disclosuresByClaim` stays empty for this format.
        for h in &self.mdoc_holdings {
            let claims = h
                .issuer_signed
                .name_spaces
                .values()
                .flatten()
                .map(|it| format!("{:?}:{:?}", it.element_id, cbor_value_display(&it.element_value)))
                .collect::<Vec<_>>()
                .join(",");
            items.push(format!(
                r#"{{"vct":{:?},"issuer":"ISO 18013-5 mdoc","format":"mso_mdoc","claims":{{{}}},"disclosuresByClaim":{{}}}}"#,
                h.doctype, claims
            ));
        }
        format!("[{}]", items.join(","))
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
            Event::WalletTransferOfferCreated => {
                self.active = ActiveFlow::WalletTransfer;
                self.drive_w2w(w2w::Input::CreateOffer)
            }
            Event::WalletTransferReceived {
                credential,
                issuer_cert_chain,
                sender_public_key,
                sender_signature,
                sender_consent_hash,
                nonce,
            } => {
                // Decide acceptance IN-CORE (never shell booleans):
                //  * issuer_valid — the issuer chain is trusted AND signs this credential;
                //  * peer_bound   — the sender's authorization is bound to THIS wallet's key and
                //    this exact credential (defeats forged/misdirected transfers).
                let issuer_valid =
                    self.received_credential_issuer_valid(&credential, &issuer_cert_chain);
                let peer_bound = self.transfer_is_peer_bound(
                    &credential,
                    &sender_public_key,
                    &sender_signature,
                    &sender_consent_hash,
                    nonce,
                );
                self.active = ActiveFlow::WalletTransfer;
                self.drive_w2w(w2w::Input::TransferReceived {
                    issuer_valid,
                    peer_bound,
                    credential,
                })
            }
            Event::CredentialOfferReceived {
                offer,
                issuer_cert_chain,
                issuer_id,
            } => {
                self.active = ActiveFlow::Issuance;
                // A new offer begins a FRESH OpenID4VCI session: reset the (one-shot) issuance
                // machine to Idle so a wallet can be issued several credentials in one lifetime.
                // Replay protection (`iss_seen_c_nonces`) deliberately persists across sessions.
                self.issuance = oid4vci::State::Idle;
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
        // For consent, compute the data-minimised selection — one credential per DCQL query.
        let selected = self.select_credentials_for(&input);

        let verifier = AwsLc;
        let digest = AwsLc;
        let (next, outputs) = {
            let env = Env {
                wallet_client_id: &self.config.wallet_client_id,
                seen_nonces: &self.seen_nonces,
                verifier: &verifier,
                digest: &digest,
                now_epoch: self.now_epoch,
                selected_credentials: &selected,
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
                nonce: req.nonce,
                response_uri: req.response_uri.clone(),
                response_mode: req.response_mode.clone(),
                response_encryption_key: req.response_encryption_key.clone(),
                dcql: req.dcql.clone(),
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

        // The moment the credential is issued (once): store it as a holding so it can be presented
        // and shown on the wallet home, and record the completed issuance in the audit log.
        if !was_issued {
            if let oid4vci::State::CredentialIssued { format, credential } = &self.issuance {
                let fmt = format_name(*format).to_string();
                match *format {
                    oid4vci::CredentialFormat::DcSdJwt => {
                        if let Some(held) = held_credential_from_compact(credential) {
                            self.load_credential(held);
                        }
                    }
                    // mso_mdoc credential response = base64url(IssuerSigned CBOR); store it parsed.
                    oid4vci::CredentialFormat::MsoMdoc => {
                        if let Some(holding) = mdoc_holding_from_credential(credential) {
                            self.load_mdoc_credential(holding);
                        }
                    }
                }
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

    /// Choose what to present: one credential per DCQL credential query (multi-credential), each
    /// keyed by its query id. A legacy flat-`claims` request (no DCQL) yields a single bare SD-JWT.
    /// Selection never widens disclosure — only the requested-and-held subset is ever revealed.
    fn select_credentials_for(&self, input: &Input) -> Vec<SelectedCredential> {
        if !matches!(input, Input::ConsentGranted) {
            return Vec::new();
        }
        let Some(sess) = self.session.as_ref() else {
            return Vec::new();
        };
        match &sess.dcql {
            Some(dcql) if !dcql.credentials.is_empty() => dcql
                .credentials
                .iter()
                .filter_map(|q| self.select_for_query(sess, q))
                .collect(),
            _ => self.select_legacy_sdjwt(sess).into_iter().collect(),
        }
    }

    /// Select a credential for ONE DCQL credential query, minimised to that query's claims and
    /// keyed by its id. `mso_mdoc` → an ISO DeviceResponse; otherwise an SD-JWT VC of a matching
    /// `vct`. `None` if nothing held satisfies this query.
    fn select_for_query(
        &self,
        sess: &SessionInfo,
        q: &oid4vp::dcql::CredentialQuery,
    ) -> Option<SelectedCredential> {
        let claims: Vec<String> = q
            .claims
            .iter()
            .map(|c| c.path_string())
            .filter(|s| !s.is_empty())
            .collect();
        let dcql_id = Some(q.id.clone());

        if q.format == "mso_mdoc" {
            let doctype = q.meta.as_ref().and_then(|m| m.doctype_value.clone())?;
            let holding = self.mdoc_holdings.iter().find(|h| h.doctype == doctype)?;
            let issuer_signed = minimise_mdoc(&holding.issuer_signed, &claims);
            let mgn = mdoc_generated_nonce(sess.nonce);
            let session_transcript = mdoc::oid4vp_session_transcript(
                &AwsLc,
                &sess.rp_client_id,
                &sess.response_uri,
                &sess.nonce.to_string(),
                &mgn,
            );
            return Some(SelectedCredential::Mdoc {
                doctype: holding.doctype.clone(),
                issuer_signed,
                session_transcript,
                device_namespaces: mdoc::empty_device_namespaces_bytes(),
                mdoc_generated_nonce: mgn,
                dcql_id,
            });
        }

        // SD-JWT VC: a candidate must BE one of the query's `vct_values` (when given) — so a request
        // for `urn:eudi:pid:1` is answered by the PID, never an mDL that carries the same claim name.
        let vcts = q.meta.as_ref().map(|m| m.vct_values.clone()).unwrap_or_default();
        let type_matches = |c: &HeldCredential| -> bool {
            vcts.is_empty() || vcts.contains(&credential_vct_and_issuer(&c.issuer_jwt).0)
        };
        let carries_all =
            |c: &HeldCredential| claims.iter().all(|r| c.disclosures_by_claim.contains_key(r));
        let cred = self
            .credentials
            .iter()
            .find(|c| type_matches(c) && carries_all(c))
            .or_else(|| self.credentials.iter().find(|c| type_matches(c)))?;
        let held: Vec<String> = cred.disclosures_by_claim.keys().cloned().collect();
        let disclosures = minimum_claim_set(&claims, &held)
            .iter()
            .filter_map(|c| cred.disclosures_by_claim.get(c).cloned())
            .collect();
        Some(SelectedCredential::SdJwt {
            issuer_jwt: cred.issuer_jwt.clone(),
            disclosures,
            dcql_id,
        })
    }

    /// The legacy flat-`claims` path (no DCQL): one SD-JWT, minimised to the requested claims, sent
    /// as a bare `vp_token` (no DCQL id) — exactly the pre-DCQL behaviour.
    fn select_legacy_sdjwt(&self, sess: &SessionInfo) -> Option<SelectedCredential> {
        let carries_all = |c: &HeldCredential| {
            sess.requested_claims
                .iter()
                .all(|r| c.disclosures_by_claim.contains_key(r))
        };
        let cred = self
            .credentials
            .iter()
            .find(|c| carries_all(c))
            .or_else(|| self.credentials.first())?;
        let held: Vec<String> = cred.disclosures_by_claim.keys().cloned().collect();
        let disclosures = minimum_claim_set(&sess.requested_claims, &held)
            .iter()
            .filter_map(|c| cred.disclosures_by_claim.get(c).cloned())
            .collect();
        Some(SelectedCredential::SdJwt {
            issuer_jwt: cred.issuer_jwt.clone(),
            disclosures,
            dcql_id: None,
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

    // --- Wallet-to-wallet receive (TS09) ---

    fn drive_w2w(&mut self, input: w2w::Input) -> Vec<Effect> {
        let (next, outputs) = w2w::step(&self.w2w, &input);
        self.w2w = next;
        outputs
            .into_iter()
            .flat_map(|o| self.translate_w2w(o))
            .collect()
    }

    fn translate_w2w(&mut self, output: w2w::Output) -> Vec<Effect> {
        use w2w::Output as WO;
        match output {
            // Offer this wallet's key as the binding target; the shell adds the nonce + transport.
            WO::PublishOffer => vec![Effect::PublishTransferOffer {
                offered_key: self.device_public_key.clone(),
            }],
            WO::StoreCredential(credential) => {
                // Record the accepted transfer (privacy-preserving: no claim values) and hold the
                // credential for the shell to persist.
                let entry = txnlog::NewEntry {
                    epoch: self.now_epoch,
                    kind: txnlog::Kind::Transfer,
                    counterparty: "peer-wallet".into(),
                    consent_hash: AwsLc.sha256(&credential),
                    claim_paths: Vec::new(),
                    outcome: txnlog::Outcome::Completed,
                    payment: None,
                };
                self.log.append(&AwsLc, entry);
                self.w2w_credential = Some(credential);
                vec![]
            }
            WO::Close => vec![Effect::Close],
        }
    }

    /// In-core issuer validity for a received transfer: the issuer chain must be trusted (a PID /
    /// attestation anchor) AND must sign the transferred SD-JWT VC.
    fn received_credential_issuer_valid(
        &self,
        credential: &[u8],
        issuer_chain: &[Vec<u8>],
    ) -> bool {
        if !self.resolve_issuer(issuer_chain) {
            return false;
        }
        let Some(issuer_key) = issuer_chain
            .first()
            .and_then(|der| x509::parse_cert(der).ok())
            .map(|c| c.public_key_raw)
        else {
            return false;
        };
        core::str::from_utf8(credential)
            .ok()
            .and_then(|s| sdjwt::SdJwtVc::parse(s).ok())
            .map(|vc| {
                vc.verify_and_disclose(&AwsLc, &AwsLc, &issuer_key, Alg::Es256)
                    .is_ok()
            })
            .unwrap_or(false)
    }

    /// In-core peer binding: the sender's authorization must be signed over the transfer binding
    /// for THIS wallet's identity + key + this exact credential (and the sender's carried consent
    /// hash + nonce), by the sender's key. This is what makes a transfer non-misdirectable.
    fn transfer_is_peer_bound(
        &self,
        credential: &[u8],
        sender_public_key: &[u8],
        sender_signature: &[u8],
        sender_consent_hash: &[u8],
        nonce: u64,
    ) -> bool {
        use crypto_traits::Verifier;
        let consent_hash: [u8; 32] = match sender_consent_hash.try_into() {
            Ok(h) => h,
            Err(_) => return false,
        };
        let binding = w2w::transfer_authorization_binding(
            &self.config.wallet_client_id,
            &self.device_public_key,
            credential,
            &consent_hash,
            nonce,
        );
        AwsLc
            .verify(Alg::Es256, sender_public_key, &binding, sender_signature)
            .is_ok()
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
        // The consent screen offers the minimum subset the request needs that ANY holding can
        // provide (selection later binds to one credential). Union of held claim names across both
        // SD-JWT disclosures and mdoc issuer-signed element identifiers.
        let mut held: Vec<String> = self
            .credentials
            .iter()
            .flat_map(|c| c.disclosures_by_claim.keys().cloned())
            .collect();
        held.extend(self.mdoc_holdings.iter().flat_map(|h| mdoc_claim_ids(&h.issuer_signed)));
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
                let sess = self.session.as_ref();
                let url = sess.map(|s| s.response_uri.clone()).unwrap_or_default();
                // For `direct_post.jwt` the response is JWE-encrypted (ECDH-ES + A256GCM) to the
                // verifier's key before it leaves the device. Encryption needs RNG (ephemeral key +
                // IV), so it happens here in the facade, not in the sans-IO `oid4vp` core.
                let enc_key = sess.and_then(|s| {
                    (s.response_mode == "direct_post.jwt")
                        .then_some(s.response_encryption_key.as_deref())
                        .flatten()
                });
                match enc_key {
                    Some(key) => match self.encrypt_direct_post_jwt(&body, key) {
                        Some(encrypted) => vec![Effect::Http { url, body: encrypted }],
                        // Fail closed: the verifier asked for encryption, so never fall back to a
                        // plaintext POST that would disclose the presentation.
                        None => vec![],
                    },
                    None => vec![Effect::Http { url, body }],
                }
            }
            O::Close => vec![Effect::Close],
        }
    }

    /// Turn the `direct_post` form body into a `direct_post.jwt` body: `response=<compact JWE>`.
    /// The JWE plaintext is the OpenID4VP response object `{"vp_token": …, "state": …}`; it is
    /// encrypted with `ECDH-ES` (P-256) + `A256GCM` to `recipient_key`, binding the request nonce
    /// (`apv`) and the mdoc_generated_nonce (`apu`, when present) into the key derivation. Returns
    /// `None` — so the caller fails closed — if the body or key can't be turned into a JWE.
    fn encrypt_direct_post_jwt(&self, form_body: &[u8], recipient_key: &[u8]) -> Option<Vec<u8>> {
        let body = core::str::from_utf8(form_body).ok()?;
        let vp_token_raw = form_field(body, "vp_token")?;
        // The DCQL response object (`{"<id>": "<presentation>"}`) is embedded as a JSON value.
        let vp_token: serde_json::Value = serde_json::from_str(&vp_token_raw).ok()?;
        let mut obj = serde_json::Map::new();
        obj.insert("vp_token".to_string(), vp_token);
        if let Some(state) = form_field(body, "state") {
            obj.insert("state".to_string(), serde_json::Value::String(state));
        }
        let plaintext = serde_json::to_string(&serde_json::Value::Object(obj)).ok()?;

        let apu = form_field(body, "mdoc_generated_nonce").unwrap_or_default();
        let apv = self.session.as_ref().map(|s| s.nonce.to_string()).unwrap_or_default();
        let jwe = jwe::encrypt_ecdh_es_a256gcm(
            plaintext.as_bytes(),
            recipient_key,
            apu.as_bytes(),
            apv.as_bytes(),
            &AwsLc,
            &AwsLc,
            &AwsLc,
            &AwsLc,
        )
        .ok()?;
        Some(format!("response={jwe}").into_bytes())
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

    /// The credentials the wallet holds as a JSON array (`[{vct, issuer, disclosuresByClaim}]`),
    /// including any just obtained via issuance. The wallet home renders these as cards.
    pub fn held_credentials_json(&self) -> String {
        self.inner.lock().expect("poisoned").held_credentials_json()
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
