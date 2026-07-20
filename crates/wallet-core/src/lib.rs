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

/// Convert an already authenticated SD-JWT VC into the wallet's presentation holding.
fn held_credential_from_verified_sd(
    sd: &sdjwt::SdJwtVc,
    status_index: Option<u64>,
) -> Result<HeldCredential, CredentialIngestionError> {
    let mut disclosures_by_claim = BTreeMap::new();
    for raw in &sd.disclosures {
        let d = sdjwt::Disclosure::parse(raw)
            .map_err(|_| CredentialIngestionError::MalformedCredential)?;
        // Object-member disclosures ([salt, name, value]) are the claims a wallet holds.
        if let Some(name) = d.name {
            if disclosures_by_claim.insert(name, raw.clone()).is_some() {
                return Err(CredentialIngestionError::DuplicateClaim);
            }
        }
    }
    Ok(HeldCredential {
        issuer_jwt: sd.issuer_jwt.clone(),
        disclosures_by_claim,
        status_index,
    })
}

/// Decode the OpenID4VCI representation of an mdoc (`base64url(IssuerSigned CBOR)`).
fn decode_mdoc_credential(
    bytes: &[u8],
) -> Result<mdoc::IssuerSigned, CredentialIngestionError> {
    use base64ct::{Base64UrlUnpadded, Encoding};
    let compact = core::str::from_utf8(bytes)
        .map_err(|_| CredentialIngestionError::MalformedCredential)?;
    let cbor = Base64UrlUnpadded::decode_vec(compact.trim())
        .map_err(|_| CredentialIngestionError::MalformedCredential)?;
    mdoc::IssuerSigned::parse(&cbor)
        .map_err(|_| CredentialIngestionError::MalformedCredential)
}

fn json_epoch_claim(
    claims: &serde_json::Map<String, serde_json::Value>,
    name: &str,
) -> Result<Option<i64>, CredentialIngestionError> {
    match claims.get(name) {
        None => Ok(None),
        Some(value) => value
            .as_i64()
            .map(Some)
            .ok_or(CredentialIngestionError::MalformedCredential),
    }
}

fn validate_json_validity(
    claims: &serde_json::Map<String, serde_json::Value>,
    now: i64,
) -> Result<(), CredentialIngestionError> {
    // Permit a small positive skew for issuer clocks, but never accept a future `nbf` or an
    // expired credential. The SD-JWT VC claims are optional at the format layer; when present they
    // are security inputs and therefore must have the exact integer type.
    const IAT_CLOCK_SKEW_SECONDS: i64 = 300;
    if json_epoch_claim(claims, "iat")?.is_some_and(|iat| iat > now + IAT_CLOCK_SKEW_SECONDS) {
        return Err(CredentialIngestionError::CredentialNotYetValid);
    }
    if json_epoch_claim(claims, "nbf")?.is_some_and(|nbf| nbf > now) {
        return Err(CredentialIngestionError::CredentialNotYetValid);
    }
    if json_epoch_claim(claims, "exp")?.is_some_and(|exp| exp <= now) {
        return Err(CredentialIngestionError::CredentialExpired);
    }
    Ok(())
}

fn sdjwt_device_binding_matches(claims: &serde_json::Map<String, serde_json::Value>, key: &[u8]) -> bool {
    use base64ct::{Base64UrlUnpadded, Encoding};

    if key.len() != 65 || key.first() != Some(&0x04) {
        return false;
    }
    let Some(jwk) = claims
        .get("cnf")
        .and_then(|v| v.get("jwk"))
        .and_then(|v| v.as_object())
    else {
        return false;
    };
    // Only a local public EC key is accepted. In particular, never follow an issuer-controlled
    // URL from a confirmation method and never accept private key material in a credential.
    if jwk.get("kty").and_then(|v| v.as_str()) != Some("EC")
        || jwk.get("crv").and_then(|v| v.as_str()) != Some("P-256")
        || jwk.contains_key("d")
        || jwk.contains_key("jku")
        || jwk.contains_key("x5u")
    {
        return false;
    }
    let (Some(x), Some(y)) = (
        jwk.get("x")
            .and_then(|v| v.as_str())
            .and_then(|v| Base64UrlUnpadded::decode_vec(v).ok()),
        jwk.get("y")
            .and_then(|v| v.as_str())
            .and_then(|v| Base64UrlUnpadded::decode_vec(v).ok()),
    ) else {
        return false;
    };
    x.len() == 32 && y.len() == 32 && key[1..33] == x && key[33..65] == y
}

fn status_index_from_claims(
    claims: &serde_json::Map<String, serde_json::Value>,
) -> Result<Option<u64>, CredentialIngestionError> {
    let Some(status) = claims.get("status") else {
        return Ok(None);
    };
    let Some(reference) = status.get("status_list").and_then(|v| v.as_object()) else {
        return Err(CredentialIngestionError::UnsupportedStatusReference);
    };
    let Some(uri) = reference.get("uri").and_then(|v| v.as_str()) else {
        return Err(CredentialIngestionError::UnsupportedStatusReference);
    };
    if !uri.starts_with("https://") {
        return Err(CredentialIngestionError::UnsupportedStatusReference);
    }
    let index = reference
        .get("idx")
        .and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
        })
        .ok_or(CredentialIngestionError::UnsupportedStatusReference)?;
    Ok(Some(index))
}

fn mdoc_device_binding_matches(device_key: &cose::cbor::Value, key: &[u8]) -> bool {
    use cose::cbor::Value;

    if key.len() != 65 || key.first() != Some(&0x04) {
        return false;
    }
    let Value::Map(pairs) = device_key else {
        return false;
    };
    let get = |label: &Value| {
        pairs
            .iter()
            .find(|(candidate, _)| candidate == label)
            .map(|(_, value)| value)
    };
    let public_only = !pairs.iter().any(|(label, _)| *label == Value::Nint(3)); // -4 / `d`
    let x = get(&Value::Nint(1)); // -2
    let y = get(&Value::Nint(2)); // -3
    public_only
        && get(&Value::Uint(1)) == Some(&Value::Uint(2)) // kty: EC2
        && get(&Value::Nint(0)) == Some(&Value::Uint(1)) // crv: P-256
        && matches!(x, Some(Value::Bytes(bytes)) if bytes.as_slice() == &key[1..33])
        && matches!(y, Some(Value::Bytes(bytes)) if bytes.as_slice() == &key[33..65])
}

/// Parse the simplified mdoc profile's canonical UTC timestamp (`YYYY-MM-DDTHH:MM:SSZ`).
fn mdoc_datetime_epoch(value: &str) -> Option<i64> {
    let bytes = value.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
    {
        return None;
    }
    let number = |start: usize, end: usize| -> Option<i64> {
        bytes[start..end]
            .iter()
            .try_fold(0i64, |n, b| b.is_ascii_digit().then_some(n * 10 + i64::from(b - b'0')))
    };
    let (year, month, day, hour, minute, second) = (
        number(0, 4)?,
        number(5, 7)?,
        number(8, 10)?,
        number(11, 13)?,
        number(14, 16)?,
        number(17, 19)?,
    );
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let month_days = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if !(1970..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || day < 1
        || day > month_days[(month - 1) as usize]
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    // Howard Hinnant's civil-date conversion, with the supported years constrained to positive
    // values above. The constant makes 1970-01-01 day zero.
    let adjusted_year = year - i64::from(month <= 2);
    let era = adjusted_year / 400;
    let year_of_era = adjusted_year - era * 400;
    let shifted_month = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    Some(days * 86_400 + hour * 3_600 + minute * 60 + second)
}

fn validate_mdoc_validity(
    validity: &mdoc::ValidityInfo,
    now: i64,
) -> Result<(), CredentialIngestionError> {
    let signed = mdoc_datetime_epoch(&validity.signed)
        .ok_or(CredentialIngestionError::MalformedCredential)?;
    let valid_from = mdoc_datetime_epoch(&validity.valid_from)
        .ok_or(CredentialIngestionError::MalformedCredential)?;
    let valid_until = mdoc_datetime_epoch(&validity.valid_until)
        .ok_or(CredentialIngestionError::MalformedCredential)?;
    if signed > now + 300 || valid_from > now {
        return Err(CredentialIngestionError::CredentialNotYetValid);
    }
    if valid_until <= now {
        return Err(CredentialIngestionError::CredentialExpired);
    }
    if signed > valid_until || valid_from > valid_until {
        return Err(CredentialIngestionError::MalformedCredential);
    }
    Ok(())
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

/// The disclosed value of an SD-JWT disclosure `base64url([salt, name, value])`.
fn sd_disclosure_value(b64: &str) -> Option<serde_json::Value> {
    use base64ct::{Base64UrlUnpadded, Encoding};
    let raw = Base64UrlUnpadded::decode_vec(b64).ok()?;
    let arr: Vec<serde_json::Value> = serde_json::from_slice(&raw).ok()?;
    arr.into_iter().nth(2)
}

/// Render a JSON value the way [`cbor_value_display`] renders CBOR (strings unquoted), so a DCQL
/// `values` constraint can be compared against an mdoc element value.
fn json_value_display(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Find an mdoc element's value by its namespaced path (`<namespace>.<element>`).
fn mdoc_value_at<'a>(issued: &'a mdoc::IssuerSigned, path: &str) -> Option<&'a cose::cbor::Value> {
    issued.name_spaces.iter().find_map(|(ns, items)| {
        items
            .iter()
            .find(|it| format!("{ns}.{}", it.element_id) == path)
            .map(|it| &it.element_value)
    })
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

/// Why a credential was refused before it could enter wallet storage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CredentialIngestionError {
    ClockNotSet,
    UnsupportedFormat,
    UntrustedIssuer,
    MalformedCredential,
    UnsupportedAlgorithm,
    SignatureInvalid,
    IssuerMismatch,
    UnknownCredentialType,
    CredentialTypeFormatMismatch,
    IssuerNotAllowedForType,
    MandatoryClaimsMissing,
    CredentialNotYetValid,
    CredentialExpired,
    DeviceBindingMissing,
    DeviceBindingMismatch,
    DuplicateClaim,
    UnsupportedStatusReference,
}

/// The only values allowed across the authentication-to-storage boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
enum VerifiedCredential {
    SdJwt(HeldCredential),
    Mdoc(MdocHolding),
}

impl VerifiedCredential {
    fn format(&self) -> oid4vci::CredentialFormat {
        match self {
            Self::SdJwt(_) => oid4vci::CredentialFormat::DcSdJwt,
            Self::Mdoc(_) => oid4vci::CredentialFormat::MsoMdoc,
        }
    }
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
    /// Public key from the leaf of the currently validated issuer path.
    issuer_public_key_current: Vec<u8>,
    /// Parsed credential that crossed the authentication/policy boundary for this response.
    pending_verified_credential: Option<VerifiedCredential>,
    last_credential_ingestion_error: Option<CredentialIngestionError>,
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
            issuer_public_key_current: Vec::new(),
            pending_verified_credential: None,
            last_credential_ingestion_error: None,
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

    /// Install an unverified SD-JWT holding in a test fixture.
    ///
    /// Production callers must use issuance or [`Self::ingest_credential`]. Keeping the bypass
    /// loudly named prevents test setup from becoming an accidental storage API.
    #[doc(hidden)]
    pub fn load_unverified_credential_for_testing(&mut self, credential: HeldCredential) {
        if !self.credentials.contains(&credential) {
            self.credentials.push(credential);
        }
    }

    /// Install an unverified mdoc holding in a test fixture. Never exposed over FFI.
    #[doc(hidden)]
    pub fn load_unverified_mdoc_for_testing(&mut self, holding: MdocHolding) {
        if !self.mdoc_holdings.contains(&holding) {
            self.mdoc_holdings.push(holding);
        }
    }

    fn store_verified_credential(&mut self, credential: VerifiedCredential) {
        match credential {
            VerifiedCredential::SdJwt(holding) => {
                if !self.credentials.contains(&holding) {
                    self.credentials.push(holding);
                }
            }
            VerifiedCredential::Mdoc(holding) => {
                if !self.mdoc_holdings.contains(&holding) {
                    self.mdoc_holdings.push(holding);
                }
            }
        }
    }

    /// Authenticate, validate and store a credential obtained outside the active issuance
    /// session (for example during a verified restore). This is the production storage boundary.
    pub fn ingest_credential(
        &mut self,
        format: &str,
        bytes: &[u8],
        issuer_cert_chain: &[Vec<u8>],
        issuer_id: &str,
    ) -> Result<(), CredentialIngestionError> {
        let format = parse_format(format).ok_or(CredentialIngestionError::UnsupportedFormat)?;
        let issuer_key = self
            .resolve_issuer_key(issuer_cert_chain)
            .ok_or(CredentialIngestionError::UntrustedIssuer)?;
        let verified = self.verify_received_credential(format, bytes, &issuer_key, issuer_id)?;
        self.store_verified_credential(verified);
        self.last_credential_ingestion_error = None;
        Ok(())
    }

    pub fn last_credential_ingestion_error(&self) -> Option<&CredentialIngestionError> {
        self.last_credential_ingestion_error.as_ref()
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
                self.issuer_public_key_current = self
                    .resolve_issuer_key(&issuer_cert_chain)
                    .unwrap_or_default();
                self.issuer_trusted_current = !self.issuer_public_key_current.is_empty();
                self.issuer_id_current = issuer_id;
                self.pending_verified_credential = None;
                self.last_credential_ingestion_error = None;
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
                Some(f) => match self.verify_received_credential(
                    f,
                    &bytes,
                    &self.issuer_public_key_current,
                    &self.issuer_id_current,
                ) {
                    Ok(verified) => {
                        self.pending_verified_credential = Some(verified);
                        self.last_credential_ingestion_error = None;
                        self.drive_issuance(oid4vci::Input::CredentialResponse {
                            format: f,
                            bytes,
                            issuer_authenticated: true,
                        })
                    }
                    Err(error) => {
                        self.pending_verified_credential = None;
                        self.last_credential_ingestion_error = Some(error);
                        self.drive_issuance(oid4vci::Input::CredentialResponse {
                            format: f,
                            bytes,
                            issuer_authenticated: false,
                        })
                    }
                },
                None => {
                    self.pending_verified_credential = None;
                    self.last_credential_ingestion_error =
                        Some(CredentialIngestionError::UnsupportedFormat);
                    self.drive_issuance(oid4vci::Input::CredentialResponseRejected)
                }
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

    /// Validate the issuer path against PID/attestation anchors and return only the authenticated
    /// leaf key. A caller cannot accidentally use a key from an unvalidated chain.
    fn resolve_issuer_key(&self, chain: &[Vec<u8>]) -> Option<Vec<u8>> {
        let mut anchors = self.trust_store.parsed_anchors(ServiceType::PidProvider);
        anchors.extend(
            self.trust_store
                .parsed_anchors(ServiceType::AttestationProvider),
        );
        if anchors.is_empty() {
            return None;
        }
        x509::validate_path(chain, &anchors, self.now_epoch, &AwsLc)
            .ok()
            .and_then(|path| path.first().map(|leaf| leaf.public_key_raw.clone()))
    }

    fn verify_received_credential(
        &self,
        format: oid4vci::CredentialFormat,
        bytes: &[u8],
        issuer_public_key: &[u8],
        issuer_id: &str,
    ) -> Result<VerifiedCredential, CredentialIngestionError> {
        if self.now_epoch <= 0 {
            return Err(CredentialIngestionError::ClockNotSet);
        }
        if issuer_public_key.is_empty() {
            return Err(CredentialIngestionError::UntrustedIssuer);
        }
        if self.device_public_key.is_empty() {
            return Err(CredentialIngestionError::DeviceBindingMissing);
        }
        match format {
            oid4vci::CredentialFormat::DcSdJwt => {
                self.verify_sdjwt_credential(bytes, issuer_public_key, issuer_id)
            }
            oid4vci::CredentialFormat::MsoMdoc => {
                self.verify_mdoc_credential(bytes, issuer_public_key, issuer_id)
            }
        }
    }

    fn verify_sdjwt_credential(
        &self,
        bytes: &[u8],
        issuer_public_key: &[u8],
        issuer_id: &str,
    ) -> Result<VerifiedCredential, CredentialIngestionError> {
        let compact = core::str::from_utf8(bytes)
            .map_err(|_| CredentialIngestionError::MalformedCredential)?;
        let sd = sdjwt::SdJwtVc::parse(compact)
            .map_err(|_| CredentialIngestionError::MalformedCredential)?;
        let alg = sd
            .issuer_algorithm()
            .map_err(|_| CredentialIngestionError::MalformedCredential)?;
        // The current EUDI crypto profile and the certificate vectors use P-256. Do not silently
        // accept algorithms merely because a backend happens to implement them.
        if alg != Alg::Es256 {
            return Err(CredentialIngestionError::UnsupportedAlgorithm);
        }
        let claims = sd
            .verify_and_disclose(&AwsLc, &AwsLc, issuer_public_key, alg)
            .map_err(|_| CredentialIngestionError::SignatureInvalid)?;
        let issuer_payload = sd
            .issuer_payload()
            .map_err(|_| CredentialIngestionError::MalformedCredential)?;
        // These are protocol control claims, not holder-selectable attributes. Keeping them in the
        // signed base payload ensures type selection, issuer policy and key binding still work on
        // a data-minimised presentation that omits unrelated disclosures.
        if !["iss", "vct", "cnf"]
            .iter()
            .all(|name| issuer_payload.contains_key(*name))
            || (claims.contains_key("status") && !issuer_payload.contains_key("status"))
        {
            return Err(CredentialIngestionError::MalformedCredential);
        }

        let issuer = claims
            .get("iss")
            .and_then(|v| v.as_str())
            .ok_or(CredentialIngestionError::MalformedCredential)?;
        if issuer.is_empty() || issuer != issuer_id {
            return Err(CredentialIngestionError::IssuerMismatch);
        }
        let vct = claims
            .get("vct")
            .and_then(|v| v.as_str())
            .filter(|v| !v.is_empty())
            .ok_or(CredentialIngestionError::UnknownCredentialType)?;
        let credential_type = self
            .catalogue
            .get(vct)
            .ok_or(CredentialIngestionError::UnknownCredentialType)?;
        if credential_type.format != "dc+sd-jwt" {
            return Err(CredentialIngestionError::CredentialTypeFormatMismatch);
        }
        if !self.catalogue.issuer_allowed(vct, issuer) {
            return Err(CredentialIngestionError::IssuerNotAllowedForType);
        }
        let held_claims: Vec<String> = claims.keys().cloned().collect();
        if !self.catalogue.satisfies_mandatory(vct, &held_claims) {
            return Err(CredentialIngestionError::MandatoryClaimsMissing);
        }
        validate_json_validity(&claims, self.now_epoch)?;
        if !claims.contains_key("cnf") {
            return Err(CredentialIngestionError::DeviceBindingMissing);
        }
        if !sdjwt_device_binding_matches(&claims, &self.device_public_key) {
            return Err(CredentialIngestionError::DeviceBindingMismatch);
        }
        let status_index = status_index_from_claims(&claims)?;
        let holding = held_credential_from_verified_sd(&sd, status_index)?;
        Ok(VerifiedCredential::SdJwt(holding))
    }

    fn verify_mdoc_credential(
        &self,
        bytes: &[u8],
        issuer_public_key: &[u8],
        issuer_id: &str,
    ) -> Result<VerifiedCredential, CredentialIngestionError> {
        let issuer_signed = decode_mdoc_credential(bytes)?;
        let mso = mdoc::verify_issuer_signed(
            &issuer_signed,
            &AwsLc,
            &AwsLc,
            issuer_public_key,
            Alg::Es256,
        )
        .map_err(|_| CredentialIngestionError::SignatureInvalid)?;
        if mso.version != "1.0" || mso.digest_algorithm != "SHA-256" || mso.doc_type.is_empty() {
            return Err(CredentialIngestionError::MalformedCredential);
        }
        let credential_type = self
            .catalogue
            .get(&mso.doc_type)
            .ok_or(CredentialIngestionError::UnknownCredentialType)?;
        if credential_type.format != "mso_mdoc" {
            return Err(CredentialIngestionError::CredentialTypeFormatMismatch);
        }
        if !self.catalogue.issuer_allowed(&mso.doc_type, issuer_id) {
            return Err(CredentialIngestionError::IssuerNotAllowedForType);
        }
        let mut held_claims = Vec::new();
        for (namespace, items) in &issuer_signed.name_spaces {
            for item in items {
                held_claims.push(item.element_id.clone());
                held_claims.push(format!("{namespace}.{}", item.element_id));
            }
        }
        if !self
            .catalogue
            .satisfies_mandatory(&mso.doc_type, &held_claims)
        {
            return Err(CredentialIngestionError::MandatoryClaimsMissing);
        }
        validate_mdoc_validity(&mso.validity_info, self.now_epoch)?;
        if matches!(mso.device_key, cose::cbor::Value::Null) {
            return Err(CredentialIngestionError::DeviceBindingMissing);
        }
        if !mdoc_device_binding_matches(&mso.device_key, &self.device_public_key) {
            return Err(CredentialIngestionError::DeviceBindingMismatch);
        }
        Ok(VerifiedCredential::Mdoc(MdocHolding {
            doctype: mso.doc_type,
            issuer_signed,
        }))
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

        // The moment the credential is issued (once), consume the value that already crossed the
        // authentication/policy boundary. Raw response bytes are never parsed into storage here.
        if !was_issued {
            if let oid4vci::State::CredentialIssued { format, .. } = &self.issuance {
                let issued_format = *format;
                let fmt = format_name(issued_format).to_string();
                match self.pending_verified_credential.take() {
                    Some(verified) if verified.format() == issued_format => {
                        self.store_verified_credential(verified);
                        self.record_issuance(fmt);
                    }
                    _ => {
                        // Defensive invariant: the OID4VCI machine must never reach its success
                        // state without a corresponding authenticated value to store.
                        self.issuance = oid4vci::State::Aborted(
                            oid4vci::AbortReason::CredentialInvalid,
                        );
                        self.last_credential_ingestion_error =
                            Some(CredentialIngestionError::MalformedCredential);
                    }
                }
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

        // A DCQL `values` constraint means the RP only accepts a credential whose claim value is one
        // of the listed values (e.g. `age_over_18 ∈ [true]`). A candidate that can't satisfy it is
        // not eligible — the wallet never presents a value the verifier asked to exclude.
        let mdoc_values_ok = |issued: &mdoc::IssuerSigned| -> bool {
            q.claims.iter().all(|cq| match &cq.values {
                None => true,
                Some(allowed) => mdoc_value_at(issued, &cq.path_string())
                    .map(cbor_value_display)
                    .is_some_and(|disp| allowed.iter().any(|a| json_value_display(a) == disp)),
            })
        };
        let sdjwt_values_ok = |c: &HeldCredential| -> bool {
            q.claims.iter().all(|cq| match &cq.values {
                None => true,
                Some(allowed) => c
                    .disclosures_by_claim
                    .get(&cq.path_string())
                    .and_then(|d| sd_disclosure_value(d))
                    .is_some_and(|v| allowed.contains(&v)),
            })
        };

        if q.format == "mso_mdoc" {
            let doctype = q.meta.as_ref().and_then(|m| m.doctype_value.clone())?;
            let holding = self
                .mdoc_holdings
                .iter()
                .find(|h| h.doctype == doctype && mdoc_values_ok(&h.issuer_signed))?;
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
            .find(|c| type_matches(c) && sdjwt_values_ok(c) && carries_all(c))
            .or_else(|| {
                self.credentials
                    .iter()
                    .find(|c| type_matches(c) && sdjwt_values_ok(c))
            })?;
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
        let Some(issuer_key) = self.resolve_issuer_key(issuer_chain) else {
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

    /// Authenticate and store a credential against the current trusted list. Returns an empty
    /// string on success or a stable debug code on refusal.
    pub fn ingest_credential(
        &self,
        format: String,
        credential: Vec<u8>,
        issuer_cert_chain: Vec<Vec<u8>>,
        issuer_id: String,
    ) -> String {
        match self.inner.lock().expect("poisoned").ingest_credential(
            &format,
            &credential,
            &issuer_cert_chain,
            &issuer_id,
        ) {
            Ok(()) => String::new(),
            Err(error) => format!("{error:?}"),
        }
    }

    /// Deprecated compatibility entry point. Unauthenticated credential injection is disabled;
    /// callers must use [`Self::ingest_credential`] or the OID4VCI event flow.
    pub fn load_credential(
        &self,
        issuer_jwt: String,
        disclosures_by_claim_json: String,
        status_index: Option<u64>,
    ) {
        // Consume inputs so generated bindings remain link-compatible during migration, while no
        // untrusted value can cross into holdings.
        drop((issuer_jwt, disclosures_by_claim_json, status_index));
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
