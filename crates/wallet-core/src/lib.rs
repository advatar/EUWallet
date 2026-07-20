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

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use catalogue::IssuerTrustDomain;
use crypto_backend::AwsLc;
use crypto_traits::{Alg, Digest, Random};
use oid4vp::{AbortReason, Env, Input, ResolvedTrust, SelectedCredential, State};
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

/// Failure classes the native shells can report for a correlated operation. Values are deliberately
/// stable and low-cardinality: implementation details remain in device-local diagnostics rather
/// than crossing the core boundary or being rendered to the holder.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum OperationFailure {
    Trust,
    Storage,
    Signing,
    Transport,
    HttpStatus,
    Issuer,
    Status,
    Rendering,
    MissingDependency,
    Unsupported,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum OperationResultKind {
    RpCertChain,
    Persisted,
    Signature,
    PresentationDelivery,
    PaymentDelivery,
    QesDelivery,
    Par,
    AuthorizationCode,
    TransactionCode,
    Token,
    Credential,
    StatusList { uri: String },
    TransferOfferPublished,
    PresentationDecision,
    PaymentDecision,
    QesDecision,
}

impl OperationResultKind {
    fn result_type(&self) -> &'static str {
        match self {
            Self::RpCertChain => "rpCertChainResolved",
            Self::Persisted | Self::TransferOfferPublished => "operationSucceeded",
            Self::Signature => "deviceSignatureProduced",
            Self::PresentationDelivery => "presentationDelivered",
            Self::PaymentDelivery => "paymentAuthorizationDelivered",
            Self::QesDelivery => "qesAuthorizationDelivered",
            Self::Par => "parPushed",
            Self::AuthorizationCode => "authorizationCodeReturned",
            Self::TransactionCode => "transactionCodeEntered",
            Self::Token => "tokenReceived",
            Self::Credential => "credentialReceived",
            Self::StatusList { .. } => "statusListReceived",
            Self::PresentationDecision => "presentationDecision",
            Self::PaymentDecision => "paymentDecision",
            Self::QesDecision => "qesDecision",
        }
    }

    fn accepts_event(&self, event_type: &str) -> bool {
        match self {
            Self::PresentationDecision => matches!(event_type, "userConsented" | "userDeclined"),
            Self::PaymentDecision => {
                matches!(event_type, "paymentApproved" | "paymentDeclined")
            }
            Self::QesDecision => matches!(event_type, "qesAuthorized" | "qesDeclined"),
            _ => self.result_type() == event_type,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PendingOperation {
    flow: ActiveFlow,
    result: OperationResultKind,
    authorization_hash: Option<[u8; 32]>,
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

fn operation_id_seed() -> u64 {
    let mut random = [0u8; 8];
    AwsLc.fill(&mut random);
    // Start uniformly in 1..=2^62. This gives every process a ~62-bit restart namespace while
    // reserving at least ~2^62 signed-range values for monotonic increments.
    (u64::from_be_bytes(random) & ((1u64 << 62) - 1)) + 1
}

/// Convert an already authenticated SD-JWT VC into the wallet's presentation holding.
fn held_credential_from_verified_sd(
    sd: &sdjwt::SdJwtVc,
    processed: &sdjwt::ProcessedSdJwt,
    status: Option<StatusReference>,
) -> Result<HeldCredential, CredentialIngestionError> {
    let mut disclosures_by_claim = BTreeMap::new();
    for disclosure in &processed.disclosures {
        // Preserve the established public fixture/card API only for unambiguous top-level object
        // members. Production selection consumes `ProcessedSdJwt` directly and never flattens a
        // nested path or silently drops an array disclosure into this compatibility view.
        let [sdjwt::ClaimPathElement::Name(name)] = disclosure.path.as_slice() else {
            continue;
        };
        if disclosures_by_claim
            .insert(name.clone(), disclosure.raw.clone())
            .is_some()
        {
            return Err(CredentialIngestionError::DuplicateClaim);
        }
    }
    Ok(HeldCredential {
        issuer_jwt: sd.issuer_jwt.clone(),
        disclosures_by_claim,
        status,
    })
}

const SDJWT_CONTROL_CLAIMS: [&str; 8] = [
    "iss",
    "vct",
    "cnf",
    "iat",
    "nbf",
    "exp",
    "status",
    "vct#integrity",
];

fn contains_sdjwt_placeholder(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(object) => {
            object.contains_key("_sd")
                || object.contains_key("...")
                || object.values().any(contains_sdjwt_placeholder)
        }
        serde_json::Value::Array(values) => values.iter().any(contains_sdjwt_placeholder),
        _ => false,
    }
}

fn validate_sdjwt_issuer_profile(
    sd: &sdjwt::SdJwtVc,
    issuer_payload: &serde_json::Map<String, serde_json::Value>,
    processed: &sdjwt::ProcessedSdJwt,
) -> Result<(), CredentialIngestionError> {
    // Credential ingestion accepts an Issued SD-JWT only. A pre-existing KB-JWT is a holder
    // presentation from some other transaction and must never become a reusable wallet holding.
    if sd.key_binding_jwt.is_some() {
        return Err(CredentialIngestionError::MalformedCredential);
    }

    for required in ["iss", "vct", "cnf"] {
        if !issuer_payload.contains_key(required) || !processed.claims.contains_key(required) {
            return Err(CredentialIngestionError::MalformedCredential);
        }
    }

    for control in SDJWT_CONTROL_CLAIMS {
        let issuer_value = issuer_payload.get(control);
        let processed_value = processed.claims.get(control);
        if issuer_value.is_none() && processed_value.is_none() {
            continue;
        }
        let Some(issuer_value) = issuer_value else {
            return Err(CredentialIngestionError::MalformedCredential);
        };
        if processed_value != Some(issuer_value) || contains_sdjwt_placeholder(issuer_value) {
            return Err(CredentialIngestionError::MalformedCredential);
        }
        if processed.disclosures.iter().any(|disclosure| {
            matches!(
                disclosure.path.first(),
                Some(sdjwt::ClaimPathElement::Name(name)) if name == control
            )
        }) {
            return Err(CredentialIngestionError::MalformedCredential);
        }
    }
    Ok(())
}

/// Decode the OpenID4VCI representation of an mdoc (`base64url(IssuerSigned CBOR)`).
fn decode_mdoc_credential(bytes: &[u8]) -> Result<mdoc::IssuerSigned, CredentialIngestionError> {
    use base64ct::{Base64UrlUnpadded, Encoding};
    let compact =
        core::str::from_utf8(bytes).map_err(|_| CredentialIngestionError::MalformedCredential)?;
    let cbor = Base64UrlUnpadded::decode_vec(compact.trim())
        .map_err(|_| CredentialIngestionError::MalformedCredential)?;
    mdoc::IssuerSigned::parse(&cbor).map_err(|_| CredentialIngestionError::MalformedCredential)
}

/// Extract bounded RFC 9360 issuer-certificate evidence from the credential itself. The COSE
/// parser has already rejected malformed, colliding and over-budget header values; this function
/// deliberately does not fall back to a path supplied alongside the credential.
fn embedded_mdoc_issuer_chain(
    issuer_signed: &mdoc::IssuerSigned,
) -> Result<Vec<Vec<u8>>, CredentialIngestionError> {
    let chain = issuer_signed
        .issuer_auth
        .x5chain()
        .map_err(|_| CredentialIngestionError::MalformedCredential)?
        .ok_or(CredentialIngestionError::UntrustedIssuer)?;
    Ok(chain
        .certificates()
        .into_iter()
        .map(<[u8]>::to_vec)
        .collect())
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

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct CredentialValidity {
    issued_at: Option<i64>,
    not_before: Option<i64>,
    expires_at: Option<i64>,
}

impl CredentialValidity {
    const IAT_CLOCK_SKEW_SECONDS: i64 = 300;

    fn validate_at(&self, now: i64) -> Result<(), CredentialIngestionError> {
        if self
            .issued_at
            .is_some_and(|iat| iat > now.saturating_add(Self::IAT_CLOCK_SKEW_SECONDS))
            || self.not_before.is_some_and(|nbf| nbf > now)
        {
            return Err(CredentialIngestionError::CredentialNotYetValid);
        }
        if self.expires_at.is_some_and(|exp| exp <= now) {
            return Err(CredentialIngestionError::CredentialExpired);
        }
        Ok(())
    }
}

fn json_validity(
    claims: &serde_json::Map<String, serde_json::Value>,
    now: i64,
) -> Result<CredentialValidity, CredentialIngestionError> {
    // Permit a small positive skew for issuer clocks, but never accept a future `nbf` or an
    // expired credential. The SD-JWT VC claims are optional at the format layer; when present they
    // are security inputs and therefore must have the exact integer type.
    let validity = CredentialValidity {
        issued_at: json_epoch_claim(claims, "iat")?,
        not_before: json_epoch_claim(claims, "nbf")?,
        expires_at: json_epoch_claim(claims, "exp")?,
    };
    validity.validate_at(now)?;
    Ok(validity)
}

fn sdjwt_device_binding_matches(
    claims: &serde_json::Map<String, serde_json::Value>,
    key: &[u8],
) -> bool {
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

fn valid_status_uri(uri: &str) -> bool {
    const MAX_STATUS_URI_BYTES: usize = 2048;
    if uri.is_empty()
        || uri.len() > MAX_STATUS_URI_BYTES
        || !uri.is_ascii()
        || uri
            .bytes()
            .any(|b| b.is_ascii_control() || b == b' ' || b == b'\\')
        || uri.contains('#')
    {
        return false;
    }
    let Some(remainder) = uri.strip_prefix("https://") else {
        return false;
    };
    let authority = remainder.split(['/', '?']).next().unwrap_or_default();
    if authority.is_empty() || authority.contains('@') {
        return false;
    }
    if authority.starts_with('[') {
        return authority.find(']').is_some_and(|end| {
            if end <= 1 {
                return false;
            }
            let suffix = &authority[end + 1..];
            suffix.is_empty()
                || suffix.strip_prefix(':').is_some_and(|port| {
                    !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit())
                })
        });
    }
    if authority.matches(':').count() > 1 {
        return false;
    }
    let (host, port) = authority
        .split_once(':')
        .map_or((authority, None), |(host, port)| (host, Some(port)));
    !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
        && port.is_none_or(|port| !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()))
}

fn status_reference_from_claims(
    claims: &serde_json::Map<String, serde_json::Value>,
) -> Result<Option<StatusReference>, CredentialIngestionError> {
    let Some(status) = claims.get("status") else {
        return Ok(None);
    };
    let Some(reference) = status.get("status_list").and_then(|v| v.as_object()) else {
        return Err(CredentialIngestionError::UnsupportedStatusReference);
    };
    let Some(uri) = reference.get("uri").and_then(|v| v.as_str()) else {
        return Err(CredentialIngestionError::UnsupportedStatusReference);
    };
    if !valid_status_uri(uri) {
        return Err(CredentialIngestionError::UnsupportedStatusReference);
    }
    let index = reference
        .get("idx")
        .and_then(|v| v.as_u64())
        .ok_or(CredentialIngestionError::UnsupportedStatusReference)?;
    Ok(Some(StatusReference {
        uri: uri.to_string(),
        index,
    }))
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

fn mdoc_validity(
    validity: &mdoc::ValidityInfo,
    now: i64,
) -> Result<CredentialValidity, CredentialIngestionError> {
    let signed = mdoc::TDate::parse(&validity.signed)
        .ok_or(CredentialIngestionError::MalformedCredential)?;
    let valid_from = mdoc::TDate::parse(&validity.valid_from)
        .ok_or(CredentialIngestionError::MalformedCredential)?;
    let valid_until = mdoc::TDate::parse(&validity.valid_until)
        .ok_or(CredentialIngestionError::MalformedCredential)?;
    if signed > valid_until || valid_from > valid_until {
        return Err(CredentialIngestionError::MalformedCredential);
    }
    let validity = CredentialValidity {
        // The shell clock has whole-second precision. Ceiling fractional bounds preserves exact
        // `TDate` semantics: an instant at `...00.5` is still future at `...00` and expires before
        // `...01`, while an integral timestamp remains unchanged.
        issued_at: Some(signed.unix_seconds_ceil()),
        not_before: Some(valid_from.unix_seconds_ceil()),
        expires_at: Some(valid_until.unix_seconds_ceil()),
    };
    validity.validate_at(now)?;
    Ok(validity)
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

fn cbor_value_matches_json(cbor: &cose::cbor::Value, json: &serde_json::Value) -> bool {
    use cose::cbor::Value as Cbor;
    match (cbor, json) {
        (Cbor::Text(left), serde_json::Value::String(right)) => left == right,
        (Cbor::Bool(left), serde_json::Value::Bool(right)) => left == right,
        (Cbor::Uint(left), serde_json::Value::Number(right)) => right.as_u64() == Some(*left),
        (Cbor::Nint(argument), serde_json::Value::Number(right)) => right
            .as_i64()
            .is_some_and(|right| i128::from(right) == -1 - i128::from(*argument)),
        (Cbor::Null, serde_json::Value::Null) => true,
        (Cbor::Array(left), serde_json::Value::Array(right)) => {
            left.len() == right.len()
                && left
                    .iter()
                    .zip(right)
                    .all(|(left, right)| cbor_value_matches_json(left, right))
        }
        (Cbor::Map(left), serde_json::Value::Object(right)) => {
            left.len() == right.len()
                && left.iter().all(|(key, value)| {
                    let Cbor::Text(key) = key else {
                        return false;
                    };
                    right
                        .get(key)
                        .is_some_and(|right| cbor_value_matches_json(value, right))
                })
        }
        _ => false,
    }
}

/// The disclosed value of an SD-JWT disclosure `base64url([salt, name, value])`.
fn sd_disclosure_value(b64: &str) -> Option<serde_json::Value> {
    use base64ct::{Base64UrlUnpadded, Encoding};
    let raw = Base64UrlUnpadded::decode_vec(b64).ok()?;
    let arr: Vec<serde_json::Value> = serde_json::from_slice(&raw).ok()?;
    arr.into_iter().nth(2)
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum RequestedSdJwtPathElement {
    Name(String),
    Index(usize),
    AnyIndex,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SdJwtDisclosureSelection {
    disclosures: Vec<String>,
    revealed_claims: Vec<String>,
}

fn requested_sdjwt_path(path: &[serde_json::Value]) -> Option<Vec<RequestedSdJwtPathElement>> {
    if path.is_empty() {
        return None;
    }
    path.iter()
        .map(|element| match element {
            serde_json::Value::String(name) if !name.is_empty() => {
                Some(RequestedSdJwtPathElement::Name(name.clone()))
            }
            serde_json::Value::Number(index) => index
                .as_u64()
                .and_then(|index| usize::try_from(index).ok())
                .map(RequestedSdJwtPathElement::Index),
            serde_json::Value::Null => Some(RequestedSdJwtPathElement::AnyIndex),
            _ => None,
        })
        .collect()
}

fn collect_matching_json_paths(
    value: &serde_json::Value,
    requested: &[RequestedSdJwtPathElement],
    current: &mut Vec<sdjwt::ClaimPathElement>,
    matches: &mut Vec<(Vec<sdjwt::ClaimPathElement>, serde_json::Value)>,
) {
    let Some((head, tail)) = requested.split_first() else {
        matches.push((current.clone(), value.clone()));
        return;
    };
    match (head, value) {
        (RequestedSdJwtPathElement::Name(name), serde_json::Value::Object(object)) => {
            if let Some(child) = object.get(name) {
                current.push(sdjwt::ClaimPathElement::Name(name.clone()));
                collect_matching_json_paths(child, tail, current, matches);
                current.pop();
            }
        }
        (RequestedSdJwtPathElement::Index(index), serde_json::Value::Array(array)) => {
            if let Some(child) = array.get(*index) {
                current.push(sdjwt::ClaimPathElement::Index(*index));
                collect_matching_json_paths(child, tail, current, matches);
                current.pop();
            }
        }
        (RequestedSdJwtPathElement::AnyIndex, serde_json::Value::Array(array)) => {
            for (index, child) in array.iter().enumerate() {
                current.push(sdjwt::ClaimPathElement::Index(index));
                collect_matching_json_paths(child, tail, current, matches);
                current.pop();
            }
        }
        _ => {}
    }
}

fn matching_sdjwt_values(
    authenticated: &AuthenticatedSdJwtHolding,
    requested: &[RequestedSdJwtPathElement],
) -> Vec<(Vec<sdjwt::ClaimPathElement>, serde_json::Value)> {
    let root = serde_json::Value::Object(authenticated.processed.claims.clone());
    let mut matches = Vec::new();
    collect_matching_json_paths(&root, requested, &mut Vec::new(), &mut matches);
    matches
}

fn claim_path_is_prefix(
    prefix: &[sdjwt::ClaimPathElement],
    path: &[sdjwt::ClaimPathElement],
) -> bool {
    prefix.len() <= path.len() && prefix.iter().zip(path).all(|(left, right)| left == right)
}

fn add_sdjwt_disclosure_dependencies(
    authenticated: &AuthenticatedSdJwtHolding,
    selected: &mut BTreeSet<String>,
) -> bool {
    let mut changed = false;
    let selected_now: Vec<String> = selected.iter().cloned().collect();
    for digest in selected_now {
        let Some(disclosure) = authenticated
            .processed
            .disclosures
            .iter()
            .find(|candidate| candidate.digest == digest)
        else {
            continue;
        };
        if let Some(parent) = &disclosure.parent_digest {
            changed |= selected.insert(parent.clone());
        }
    }
    changed
}

fn sdjwt_path_string(path: &[sdjwt::ClaimPathElement]) -> String {
    let mut rendered = String::new();
    for element in path {
        match element {
            sdjwt::ClaimPathElement::Name(name) => {
                // Preserve familiar dotted labels for simple claim names, but use JSON-escaped
                // bracket notation whenever punctuation could collide with nesting or an array
                // index (for example literal `a.b` versus path `["a", "b"]`).
                let simple = !name.is_empty()
                    && name
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'));
                if simple {
                    if !rendered.is_empty() {
                        rendered.push('.');
                    }
                    rendered.push_str(name);
                } else {
                    rendered.push('[');
                    rendered.push_str(
                        &serde_json::to_string(name)
                            .expect("serializing a JSON object key cannot fail"),
                    );
                    rendered.push(']');
                }
            }
            sdjwt::ClaimPathElement::Index(index) => {
                rendered.push('[');
                rendered.push_str(&index.to_string());
                rendered.push(']');
            }
        }
    }
    rendered
}

fn collect_json_leaf_paths(
    value: &serde_json::Value,
    path: &mut Vec<sdjwt::ClaimPathElement>,
    leaves: &mut Vec<Vec<sdjwt::ClaimPathElement>>,
) {
    match value {
        serde_json::Value::Object(object) if !object.is_empty() => {
            for (name, child) in object {
                path.push(sdjwt::ClaimPathElement::Name(name.clone()));
                collect_json_leaf_paths(child, path, leaves);
                path.pop();
            }
        }
        serde_json::Value::Array(array) if !array.is_empty() => {
            for (index, child) in array.iter().enumerate() {
                path.push(sdjwt::ClaimPathElement::Index(index));
                collect_json_leaf_paths(child, path, leaves);
                path.pop();
            }
        }
        _ if !path.is_empty() => leaves.push(path.clone()),
        _ => {}
    }
}

fn visible_sdjwt_claims(
    authenticated: &AuthenticatedSdJwtHolding,
    selected: &BTreeSet<String>,
) -> Vec<String> {
    let mut leaves = Vec::new();
    collect_json_leaf_paths(
        &serde_json::Value::Object(authenticated.processed.claims.clone()),
        &mut Vec::new(),
        &mut leaves,
    );
    let mut visible = Vec::new();
    for path in leaves {
        let Some(sdjwt::ClaimPathElement::Name(root_name)) = path.first() else {
            continue;
        };
        if SDJWT_CONTROL_CLAIMS.contains(&root_name.as_str()) || root_name == "_sd_alg" {
            continue;
        }
        let all_enclosing_disclosures_selected = authenticated
            .processed
            .disclosures
            .iter()
            .filter(|disclosure| claim_path_is_prefix(&disclosure.path, &path))
            .all(|disclosure| selected.contains(&disclosure.digest));
        if all_enclosing_disclosures_selected {
            let rendered = sdjwt_path_string(&path);
            if !visible.contains(&rendered) {
                visible.push(rendered);
            }
        }
    }
    visible
}

fn select_authenticated_sdjwt_disclosures(
    authenticated: &AuthenticatedSdJwtHolding,
    requested_paths: &[Vec<RequestedSdJwtPathElement>],
) -> Option<SdJwtDisclosureSelection> {
    let mut matched_paths = Vec::new();
    for requested in requested_paths {
        let matches = matching_sdjwt_values(authenticated, requested);
        if matches.is_empty() {
            return None;
        }
        for (matched_path, _) in matches {
            if !matched_paths.contains(&matched_path) {
                matched_paths.push(matched_path);
            }
        }
    }
    Some(select_authenticated_sdjwt_disclosures_for_paths(
        authenticated,
        &matched_paths,
    ))
}

fn select_authenticated_sdjwt_disclosures_for_paths(
    authenticated: &AuthenticatedSdJwtHolding,
    matched_paths: &[Vec<sdjwt::ClaimPathElement>],
) -> SdJwtDisclosureSelection {
    let mut selected = BTreeSet::new();
    for matched_path in matched_paths {
        for disclosure in &authenticated.processed.disclosures {
            // Ancestors are needed to reach a selected leaf. When the requested value is itself an
            // object/array, descendants are needed to reconstruct that complete value rather than
            // return an accidentally partial object.
            if claim_path_is_prefix(&disclosure.path, matched_path)
                || claim_path_is_prefix(matched_path, &disclosure.path)
            {
                selected.insert(disclosure.digest.clone());
            }
        }
    }
    while add_sdjwt_disclosure_dependencies(authenticated, &mut selected) {}
    SdJwtDisclosureSelection {
        disclosures: authenticated
            .processed
            .disclosures
            .iter()
            .filter(|disclosure| selected.contains(&disclosure.digest))
            .map(|disclosure| disclosure.raw.clone())
            .collect(),
        revealed_claims: visible_sdjwt_claims(authenticated, &selected),
    }
}

fn requested_mdoc_path(path: &[serde_json::Value]) -> Option<(String, String)> {
    let [serde_json::Value::String(namespace), serde_json::Value::String(element)] = path else {
        return None;
    };
    if namespace.is_empty() || element.is_empty() {
        return None;
    }
    Some((namespace.clone(), element.clone()))
}

/// Find an mdoc element's value by its exact typed `[namespace, element]` path.
fn mdoc_value_at<'a>(
    issued: &'a mdoc::IssuerSigned,
    path: &(String, String),
) -> Option<&'a cose::cbor::Value> {
    issued.name_spaces.iter().find_map(|(namespace, items)| {
        if namespace != &path.0 {
            return None;
        }
        items
            .iter()
            .find(|item| item.element_id == path.1)
            .map(|item| &item.element_value)
    })
}

/// Drop the issuer-signed items a request did not ask for (mdoc data minimisation). The MSO
/// (`issuerAuth`) is left intact; a verifier checks each *presented* item's digest against it, so
/// omitting items is valid and reveals only the requested-and-held subset.
fn minimise_mdoc(
    issued: &mdoc::IssuerSigned,
    requested_claims: &[(String, String)],
) -> mdoc::IssuerSigned {
    let name_spaces = issued
        .name_spaces
        .iter()
        .map(|(namespace, items)| {
            (
                namespace.clone(),
                items
                    .iter()
                    .filter(|item| {
                        requested_claims
                            .iter()
                            .any(|(requested_ns, requested_element)| {
                                requested_ns == namespace && requested_element == &item.element_id
                            })
                    })
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
            if let (Some(hi), Some(lo)) = (
                (b[i + 1] as char).to_digit(16),
                (b[i + 2] as char).to_digit(16),
            ) {
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusReference {
    /// Exact HTTPS URI of the Status List Token. Its signed `sub` must be byte-for-byte equal.
    pub uri: String,
    /// Non-negative entry index within that list.
    pub index: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HeldCredential {
    pub issuer_jwt: String,
    pub disclosures_by_claim: BTreeMap<String, String>,
    /// Authenticated, indivisible status reference. URI and index can never be mixed across lists.
    pub status: Option<StatusReference>,
}

/// An ISO 18013-5 mdoc the wallet holds (issued in the `mso_mdoc` format): the parsed
/// issuer-signed structure and its doctype. Presented over OpenID4VP as a `DeviceResponse`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MdocHolding {
    pub doctype: String,
    pub issuer_signed: mdoc::IssuerSigned,
}

/// Authenticated material retained with a holding so time, trust-list, certificate-path, issuer,
/// signature, catalogue, and device-binding decisions can be repeated at presentation time.
#[derive(Clone, Debug, PartialEq, Eq)]
struct CredentialProvenance {
    format: oid4vci::CredentialFormat,
    raw_credential: Vec<u8>,
    issuer: CredentialIssuerEvidence,
}

/// Path- and profile-validated issuer evidence retained with a verified holding. The service
/// domain is selected by catalogue policy and was never inferred from shell metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
struct CredentialIssuerEvidence {
    identity: String,
    service: IssuerTrustDomain,
    public_key_raw: Vec<u8>,
    certificate_path: Vec<Vec<u8>>,
    not_before: i64,
    not_after: i64,
}

impl CredentialIssuerEvidence {
    fn is_internally_consistent(&self) -> bool {
        !self.identity.is_empty()
            && !self.public_key_raw.is_empty()
            && !self.certificate_path.is_empty()
            && self.not_before <= self.not_after
            && matches!(
                self.service,
                IssuerTrustDomain::Pid | IssuerTrustDomain::Attestation
            )
    }
}

/// The explicitly named Rust-only fixture loaders remain source-compatible for existing tests;
/// production ingestion always stores the `Authenticated` variant.
#[derive(Clone, Debug, PartialEq, Eq)]
enum StoredProvenance {
    Authenticated(CredentialProvenance),
    TestFixture,
}

/// Private authenticated SD-JWT representation. Unlike [`HeldCredential`], this retains the
/// processed document, typed object/array paths, raw disclosures and parent digest dependencies.
#[derive(Clone, Debug, PartialEq, Eq)]
struct AuthenticatedSdJwtHolding {
    processed: sdjwt::ProcessedSdJwt,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct StoredSdJwtCredential {
    holding: HeldCredential,
    /// Always `Some` for production ingestion. `None` exists solely for the explicit Rust fixture
    /// API, whose flat map remains source-compatible with older tests.
    authenticated: Option<AuthenticatedSdJwtHolding>,
    validity: CredentialValidity,
    provenance: StoredProvenance,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct StoredMdocCredential {
    holding: MdocHolding,
    validity: CredentialValidity,
    provenance: StoredProvenance,
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
    IssuerServiceMismatch,
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

/// Why a downloaded status assertion was refused before entering the bounded cache.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StatusLoadError {
    ClockNotSet,
    InvalidUri,
    UntrustedProvider,
    InvalidToken(status::StatusError),
    CacheFull,
}

/// The only values allowed across the authentication-to-storage boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
enum VerifiedCredential {
    SdJwt {
        holding: HeldCredential,
        authenticated: AuthenticatedSdJwtHolding,
        validity: CredentialValidity,
    },
    Mdoc {
        holding: MdocHolding,
        validity: CredentialValidity,
    },
}

impl VerifiedCredential {
    fn format(&self) -> oid4vci::CredentialFormat {
        match self {
            Self::SdJwt { .. } => oid4vci::CredentialFormat::DcSdJwt,
            Self::Mdoc { .. } => oid4vci::CredentialFormat::MsoMdoc,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AuthenticatedCredential {
    credential: VerifiedCredential,
    provenance: CredentialProvenance,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum PresentationCredentialReference {
    SdJwt {
        holding: HeldCredential,
        authenticated: Option<AuthenticatedSdJwtHolding>,
    },
    Mdoc(MdocHolding),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PresentationEligibilityError {
    CredentialExpired,
    CredentialNotYetValid,
    CredentialProvenanceInvalid,
    TrustEvidenceInvalid,
    NoEligibleCredential,
}

#[derive(Clone, Debug)]
struct PreparedPresentationCredential {
    selected: SelectedCredential,
    source: PresentationCredentialReference,
    /// Every holder-visible claim path that the resulting presentation reveals, including
    /// permanent PII and incidental values exposed by disclosure dependencies.
    revealed_claims: Vec<String>,
}

#[derive(Clone, Debug, Default)]
struct RelyingPartyProvenance {
    certificate_chain: Vec<Vec<u8>>,
    public_key: Vec<u8>,
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
    /// Every declared DCQL path, or the legacy flat claims when DCQL is absent. DCQL consent uses
    /// `selected_revealed_claims`; only the legacy selector reads this field directly.
    requested_claims: Vec<String>,
    /// The request nonce, needed to bind the mdoc OpenID4VP SessionTranscript.
    nonce: u64,
    response_uri: String,
    /// The response mode: `direct_post` (form body) or `direct_post.jwt` (JWE-encrypted response).
    response_mode: String,
    /// The verifier's response-encryption key (uncompressed P-256), present iff `direct_post.jwt`.
    response_encryption_key: Option<Vec<u8>>,
    /// The full DCQL query when present. Its set planner selects the complete required subset and
    /// omits optional sets without holder opt-in, with at most one held credential per supported
    /// query until `multiple=true` lands.
    dcql: Option<oid4vp::dcql::DcqlQuery>,
    /// Exact credentials selected before consent. Later phases revalidate these values instead of
    /// silently switching to a different holding after the user approved the screen.
    selected_credentials: Vec<SelectedCredential>,
    selected_sources: Vec<PresentationCredentialReference>,
    selected_revealed_claims: Vec<String>,
    /// RP certificate path + request-verification key retained for current-time revalidation.
    rp_provenance: Option<RelyingPartyProvenance>,
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
        /// Authenticated RP delivery endpoints. The legacy redirect-oriented name is retained in
        /// the FFI contract; presentation `response_uri` values are matched against this list too.
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
    /// The payment service acknowledged the dynamically linked authorization code.
    PaymentAuthorizationDelivered,
    /// The QTSP acknowledged the QES authorization response.
    QesAuthorizationDelivered,
    /// A correlated operation without a protocol-specific payload completed (currently durable
    /// nonce persistence and peer-offer publication).
    OperationSucceeded { operation_id: u64 },
    /// A correlated native operation failed. The JSON boundary validates `operation_id` before
    /// this transition can reset the owning flow.
    OperationFailed {
        operation_id: u64,
        failure: OperationFailure,
    },
    /// The OS or holder cancelled a correlated native operation.
    OperationCancelled { operation_id: u64 },
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
    /// The shell completed an HTTPS Token Status List fetch. The token is trusted only after the
    /// core validates the exact URI, 2xx response, status-provider certificate path and JWS.
    StatusListReceived {
        uri: String,
        http_status: u16,
        token: Vec<u8>,
        provider_cert_chain: Vec<Vec<u8>>,
    },
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
    /// Fetch a Token Status List over HTTPS. The shell must cap the response at
    /// `status::MAX_TOKEN_BYTES`, then return `StatusListReceived` with the status signer's chain.
    FetchStatusList { uri: String },
    /// Publish a wallet-to-wallet receive offer over the peer transport: this wallet's key (the
    /// binding the sender must target). The shell adds a fresh nonce + BLE/QR transport (TS09).
    PublishTransferOffer { offered_key: Vec<u8> },
    /// Tear down the exchange.
    Close,
}

const MAX_CACHED_STATUS_LISTS: usize = 8;
const MAX_STATUS_LISTS_PER_PRESENTATION: usize = 8;
const MAX_PENDING_OPERATIONS: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
enum StatusGate {
    Ready,
    Fetch {
        all_references: Vec<StatusReference>,
        uris: Vec<String>,
    },
    Revoked,
    Indeterminate,
}

#[derive(Clone, Debug)]
struct CachedStatusList {
    list: status::StatusList,
    provider_cert_chain: Vec<Vec<u8>>,
}

/// The whole wallet state.
#[derive(Debug)]
pub struct Core {
    config: WalletConfig,
    vp: State,
    seen_nonces: Vec<u64>,
    /// The credentials the wallet holds. A real wallet holds several (a PID, an mDL, …); issuance
    /// appends, and presentation selects the one that data-minimally satisfies the request.
    credentials: Vec<StoredSdJwtCredential>,
    /// mdoc holdings (ISO 18013-5), presented over OpenID4VP as DeviceResponses.
    mdoc_holdings: Vec<StoredMdocCredential>,
    session: Option<SessionInfo>,
    pending_rp_provenance: Option<RelyingPartyProvenance>,
    now_epoch: i64,
    // Payment SCA flow.
    payment: payment::State,
    pay_seen_nonces: Vec<u64>,
    pay_pending: Option<(String, u64)>, // (response_uri, nonce) of the in-flight payment
    active: ActiveFlow,
    /// Monotonic, process-local correlation sequence. IDs are never reused, even after a flow is
    /// cancelled, so a delayed native callback cannot target a later operation.
    next_operation_id: u64,
    /// Operations emitted over the production JSON boundary and still awaiting their exact result.
    pending_operations: BTreeMap<u64, PendingOperation>,
    // Trust: the verified trusted list, used to decide RP registration in-core (not shell-supplied).
    trust_store: TrustStore,
    // Issuance (OID4VCI) flow.
    issuance: oid4vci::State,
    iss_seen_c_nonces: Vec<u64>,
    device_public_key: Vec<u8>,
    wua: Option<wua::WalletUnitAttestation>,
    issuer_trusted_current: bool,
    /// Authenticated certificate identity used by the issuance machine and audit log.
    issuer_id_current: String,
    /// Full issuer path retained for revalidation throughout issuance and credential provenance.
    issuer_cert_chain_current: Vec<Vec<u8>>,
    /// Original shell assertion, retained only so the credential response can re-check it.
    issuer_id_assertion_current: String,
    /// Service-scoped path/profile results for the active issuer chain.
    issuer_candidates_current: Vec<CredentialIssuerEvidence>,
    /// Parsed credential that crossed the authentication/policy boundary for this response.
    pending_verified_credential: Option<AuthenticatedCredential>,
    last_credential_ingestion_error: Option<CredentialIngestionError>,
    // Revocation: URI-keyed verified lists plus the exact selected references awaiting refresh.
    // Both collections are explicitly bounded to keep hostile issuer data from growing memory.
    status_lists: BTreeMap<String, CachedStatusList>,
    pending_status_references: Vec<StatusReference>,
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
            pending_rp_provenance: None,
            now_epoch: 0,
            payment: payment::State::Idle,
            pay_seen_nonces: Vec::new(),
            pay_pending: None,
            active: ActiveFlow::None,
            next_operation_id: operation_id_seed(),
            pending_operations: BTreeMap::new(),
            trust_store: TrustStore::new(),
            issuance: oid4vci::State::Idle,
            iss_seen_c_nonces: Vec::new(),
            device_public_key: Vec::new(),
            wua: None,
            issuer_trusted_current: false,
            issuer_id_current: String::new(),
            issuer_cert_chain_current: Vec::new(),
            issuer_id_assertion_current: String::new(),
            issuer_candidates_current: Vec::new(),
            pending_verified_credential: None,
            last_credential_ingestion_error: None,
            status_lists: BTreeMap::new(),
            pending_status_references: Vec::new(),
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
                            c.path.request_path(), c.display_name, c.mandatory
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
        export::export_json(
            &AwsLc,
            self.now_epoch,
            self.credentials.first().map(|stored| &stored.holding),
            &self.log,
        )
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

    /// Verify + store one URI-bound Token Status List in the bounded cache.
    pub fn load_status_list(
        &mut self,
        uri: &str,
        token: &[u8],
        provider_cert_chain: &[Vec<u8>],
    ) -> Result<(), StatusLoadError> {
        if self.now_epoch <= 0 {
            return Err(StatusLoadError::ClockNotSet);
        }
        if !valid_status_uri(uri) {
            return Err(StatusLoadError::InvalidUri);
        }
        let provider_public_key = self
            .resolve_status_provider_key(provider_cert_chain)
            .ok_or(StatusLoadError::UntrustedProvider)?;
        let list = status::parse_and_verify(
            token,
            uri,
            &provider_public_key,
            &AwsLc,
            Alg::Es256,
            self.now_epoch,
        )
        .map_err(StatusLoadError::InvalidToken)?;

        // Drop stale entries before applying the fixed cache cardinality cap. A fresh entry may
        // replace the same URI, but an attacker cannot fill an unbounded number of distinct lists.
        let now = self.now_epoch;
        self.status_lists
            .retain(|_, cached| cached.list.is_fresh_at(now));
        if !self.status_lists.contains_key(uri)
            && self.status_lists.len() >= MAX_CACHED_STATUS_LISTS
        {
            return Err(StatusLoadError::CacheFull);
        }
        self.status_lists.insert(
            uri.to_string(),
            CachedStatusList {
                list,
                provider_cert_chain: provider_cert_chain.to_vec(),
            },
        );
        Ok(())
    }

    /// Evaluate status for exactly the credentials selected for this consent. Missing/stale lists
    /// request a refresh; known-bad, out-of-range and structurally inconsistent values fail closed.
    fn presentation_status_gate(&self) -> StatusGate {
        let mut references = Vec::<StatusReference>::new();

        let Some(session) = self.session.as_ref() else {
            return StatusGate::Indeterminate;
        };
        for source in &session.selected_sources {
            let PresentationCredentialReference::SdJwt { holding, .. } = source else {
                continue;
            };
            if let Some(reference) = &holding.status {
                if !references.contains(reference) {
                    references.push(reference.clone());
                }
            }
        }

        if references.len() > MAX_STATUS_LISTS_PER_PRESENTATION {
            return StatusGate::Indeterminate;
        }

        let mut fetch_uris = Vec::new();
        for reference in &references {
            let Some(cached) = self.status_lists.get(&reference.uri) else {
                if !fetch_uris.contains(&reference.uri) {
                    fetch_uris.push(reference.uri.clone());
                }
                continue;
            };
            if !cached.list.is_fresh_at(self.now_epoch)
                || self
                    .resolve_status_provider_key(&cached.provider_cert_chain)
                    .is_none()
            {
                if !fetch_uris.contains(&reference.uri) {
                    fetch_uris.push(reference.uri.clone());
                }
                continue;
            }
            let Ok(index) = usize::try_from(reference.index) else {
                return StatusGate::Indeterminate;
            };
            match cached.list.status_at(index) {
                status::CredentialStatus::Valid => {}
                status::CredentialStatus::Invalid | status::CredentialStatus::Suspended => {
                    return StatusGate::Revoked;
                }
                status::CredentialStatus::Unknown => return StatusGate::Indeterminate,
            }
        }

        if fetch_uris.is_empty() {
            StatusGate::Ready
        } else {
            StatusGate::Fetch {
                all_references: references,
                uris: fetch_uris,
            }
        }
    }

    fn status_block_effects(&mut self, revoked: bool) -> Vec<Effect> {
        let reason = if revoked {
            AbortReason::CredentialStatusInvalid
        } else {
            AbortReason::CredentialStatusUnavailable
        };
        self.abort_presentation(reason)
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
            .parsed_anchors_at(ServiceType::RelyingPartyAccessCa, self.now_epoch);
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
        if !self
            .credentials
            .iter()
            .any(|stored| stored.holding == credential)
        {
            self.credentials.push(StoredSdJwtCredential {
                holding: credential,
                authenticated: None,
                validity: CredentialValidity::default(),
                provenance: StoredProvenance::TestFixture,
            });
        }
    }

    /// Install an unverified mdoc holding in a test fixture. Never exposed over FFI.
    #[doc(hidden)]
    pub fn load_unverified_mdoc_for_testing(&mut self, holding: MdocHolding) {
        if !self
            .mdoc_holdings
            .iter()
            .any(|stored| stored.holding == holding)
        {
            self.mdoc_holdings.push(StoredMdocCredential {
                holding,
                validity: CredentialValidity::default(),
                provenance: StoredProvenance::TestFixture,
            });
        }
    }

    fn store_verified_credential(&mut self, authenticated: AuthenticatedCredential) {
        debug_assert!(authenticated.provenance.issuer.is_internally_consistent());
        let provenance = StoredProvenance::Authenticated(authenticated.provenance);
        match authenticated.credential {
            VerifiedCredential::SdJwt {
                holding,
                authenticated,
                validity,
            } => {
                if let Some(stored) = self
                    .credentials
                    .iter_mut()
                    .find(|stored| stored.holding == holding)
                {
                    stored.authenticated = Some(authenticated);
                    stored.validity = validity;
                    stored.provenance = provenance;
                } else {
                    self.credentials.push(StoredSdJwtCredential {
                        holding,
                        authenticated: Some(authenticated),
                        validity,
                        provenance,
                    });
                }
            }
            VerifiedCredential::Mdoc { holding, validity } => {
                if let Some(stored) = self
                    .mdoc_holdings
                    .iter_mut()
                    .find(|stored| stored.holding == holding)
                {
                    stored.validity = validity;
                    stored.provenance = provenance;
                } else {
                    self.mdoc_holdings.push(StoredMdocCredential {
                        holding,
                        validity,
                        provenance,
                    });
                }
            }
        }
    }

    fn authenticate_received_credential(
        &self,
        format: oid4vci::CredentialFormat,
        bytes: &[u8],
        issuer_cert_chain: &[Vec<u8>],
        issuer_id_assertion: &str,
    ) -> Result<AuthenticatedCredential, CredentialIngestionError> {
        if self.now_epoch <= 0 {
            return Err(CredentialIngestionError::ClockNotSet);
        }
        if self.device_public_key.is_empty() {
            return Err(CredentialIngestionError::DeviceBindingMissing);
        }

        let (credential, issuer) = match format {
            oid4vci::CredentialFormat::DcSdJwt => {
                // SD-JWT VC has no COSE issuerAuth header, so its authenticated transport/restore
                // boundary still supplies the issuer certificate bundle explicitly.
                let issuers = self.resolve_credential_issuers(issuer_cert_chain);
                if !Self::issuer_candidates_are_consistent(&issuers) {
                    return Err(CredentialIngestionError::UntrustedIssuer);
                }
                self.verify_sdjwt_credential(bytes, &issuers, issuer_id_assertion)?
            }
            oid4vci::CredentialFormat::MsoMdoc => {
                // For mdoc, the credential's own bounded x5chain is the sole certificate evidence
                // used to authenticate issuerAuth. A caller path can neither rescue nor replace it.
                let issuer_signed = decode_mdoc_credential(bytes)?;
                let embedded_chain = embedded_mdoc_issuer_chain(&issuer_signed)?;
                let issuers = self.resolve_credential_issuers(&embedded_chain);
                if !Self::issuer_candidates_are_consistent(&issuers) {
                    return Err(CredentialIngestionError::UntrustedIssuer);
                }
                self.verify_mdoc_credential(issuer_signed, &issuers, issuer_id_assertion)?
            }
        };
        Ok(AuthenticatedCredential {
            credential,
            provenance: CredentialProvenance {
                format,
                raw_credential: bytes.to_vec(),
                issuer,
            },
        })
    }

    /// Authenticate, validate and store a credential obtained outside the active issuance
    /// session (for example during a verified restore). This is the production storage boundary.
    /// `issuer_cert_chain` authenticates SD-JWT VC inputs; an mdoc is authenticated exclusively
    /// with the bounded `x5chain` embedded in its `issuerAuth` COSE header.
    pub fn ingest_credential(
        &mut self,
        format: &str,
        bytes: &[u8],
        issuer_cert_chain: &[Vec<u8>],
        issuer_id: &str,
    ) -> Result<(), CredentialIngestionError> {
        let format = parse_format(format).ok_or(CredentialIngestionError::UnsupportedFormat)?;
        let verified =
            self.authenticate_received_credential(format, bytes, issuer_cert_chain, issuer_id)?;
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
            .map(|stored| {
                let c = &stored.holding;
                let (vct, jwt_issuer) = credential_vct_and_issuer(&c.issuer_jwt);
                let issuer = match &stored.provenance {
                    StoredProvenance::Authenticated(provenance) => {
                        provenance.issuer.identity.as_str()
                    }
                    StoredProvenance::TestFixture => &jwt_issuer,
                };
                let disclosures = c
                    .disclosures_by_claim
                    .iter()
                    .map(|(k, v)| format!("{:?}:{:?}", k, v))
                    .collect::<Vec<_>>()
                    .join(",");
                format!(
                    r#"{{"vct":{:?},"issuer":{:?},"format":"dc+sd-jwt","disclosuresByClaim":{{{}}}}}"#,
                    vct, issuer, disclosures
                )
            })
            .collect();
        // mdoc holdings: values are already decoded (no salted disclosures) — surface them under
        // `claims` so the shell renders the card; `disclosuresByClaim` stays empty for this format.
        for stored in &self.mdoc_holdings {
            let h = &stored.holding;
            let issuer = match &stored.provenance {
                StoredProvenance::Authenticated(provenance) => provenance.issuer.identity.as_str(),
                StoredProvenance::TestFixture => "ISO 18013-5 mdoc",
            };
            let claims = h
                .issuer_signed
                .name_spaces
                .values()
                .flatten()
                .map(|it| {
                    format!(
                        "{:?}:{:?}",
                        it.element_id,
                        cbor_value_display(&it.element_value)
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            items.push(format!(
                r#"{{"vct":{:?},"issuer":{:?},"format":"mso_mdoc","claims":{{{}}},"disclosuresByClaim":{{}}}}"#,
                h.doctype, issuer, claims
            ));
        }
        format!("[{}]", items.join(","))
    }

    fn clear_pending_operations(&mut self, flow: ActiveFlow) {
        self.pending_operations
            .retain(|_, pending| pending.flow != flow);
    }

    /// Reset only ephemeral state. Replay sets, stored credentials, the trusted clock and audit
    /// log intentionally survive cancellation/failure.
    fn reset_flow(&mut self, flow: ActiveFlow) {
        self.clear_pending_operations(flow);
        match flow {
            ActiveFlow::Presentation => {
                self.vp = State::Idle;
                self.session = None;
                self.pending_rp_provenance = None;
                self.pending_status_references.clear();
            }
            ActiveFlow::Payment => {
                self.payment = payment::State::Idle;
                self.pay_pending = None;
                self.pay_summary = None;
                self.pay_consent_hash = [0u8; 32];
            }
            ActiveFlow::Issuance => {
                self.issuance = oid4vci::State::Idle;
                self.issuer_trusted_current = false;
                self.issuer_id_current.clear();
                self.issuer_cert_chain_current.clear();
                self.issuer_candidates_current.clear();
                self.pending_verified_credential = None;
            }
            ActiveFlow::Qes => {
                self.qes = qes::QesState::Idle;
                self.qes_consent_hash = [0u8; 32];
            }
            ActiveFlow::WalletTransfer => {
                self.w2w = w2w::State::Idle;
            }
            ActiveFlow::None => {}
        }
        if self.active == flow {
            self.active = ActiveFlow::None;
        }
    }

    fn begin_flow(&mut self, flow: ActiveFlow) {
        if self.active != ActiveFlow::None {
            self.reset_flow(self.active);
        }
        // Also reset a terminal machine whose active marker was already cleared.
        self.reset_flow(flow);
        self.active = flow;
    }

    /// Complete a successful exchange without erasing the protocol machine's exact terminal
    /// state. This preserves observable `Done`/`Authorized`/`Signed` outcomes for diagnostics and
    /// direct-core callers while scrubbing ephemeral context and making the next flow reusable.
    fn finish_flow(&mut self, flow: ActiveFlow) {
        self.clear_pending_operations(flow);
        match flow {
            ActiveFlow::Presentation => {
                self.session = None;
                self.pending_rp_provenance = None;
                self.pending_status_references.clear();
            }
            ActiveFlow::Payment => {
                self.pay_pending = None;
                self.pay_summary = None;
                self.pay_consent_hash = [0u8; 32];
            }
            ActiveFlow::Issuance => {
                self.issuer_trusted_current = false;
                self.issuer_id_current.clear();
                self.issuer_cert_chain_current.clear();
                self.issuer_candidates_current.clear();
                self.pending_verified_credential = None;
            }
            ActiveFlow::Qes => {
                self.qes_consent_hash = [0u8; 32];
            }
            ActiveFlow::WalletTransfer | ActiveFlow::None => {}
        }
        if self.active == flow {
            self.active = ActiveFlow::None;
        }
    }

    fn operation_terminal_effects(
        &mut self,
        pending: PendingOperation,
        failure: Option<OperationFailure>,
    ) -> Vec<Effect> {
        self.reset_flow(pending.flow);
        let (code, message) = match failure {
            None => (
                "operation_cancelled",
                "The wallet operation was cancelled before it completed.",
            ),
            Some(OperationFailure::Trust) => (
                "operation_trust_failed",
                "Current authenticated trust information could not be resolved.",
            ),
            Some(OperationFailure::Storage) => (
                "operation_storage_failed",
                "Required wallet state could not be stored securely.",
            ),
            Some(OperationFailure::Signing) => (
                "operation_signing_failed",
                "The protected device key could not complete the operation.",
            ),
            Some(OperationFailure::Transport | OperationFailure::HttpStatus) => (
                "operation_delivery_failed",
                "The remote service did not acknowledge the wallet operation.",
            ),
            Some(OperationFailure::Issuer) => (
                "operation_issuer_failed",
                "The credential issuer operation failed.",
            ),
            Some(OperationFailure::Status) => (
                "operation_status_failed",
                "Current authenticated credential status could not be obtained.",
            ),
            Some(OperationFailure::Rendering) => (
                "operation_rendering_failed",
                "The wallet could not show the confirmation securely.",
            ),
            Some(OperationFailure::MissingDependency) => (
                "operation_dependency_missing",
                "A required wallet service is not available.",
            ),
            Some(OperationFailure::Unsupported) => (
                "operation_unsupported",
                "This wallet operation is not supported by the native client.",
            ),
        };
        vec![
            Effect::Render {
                screen: ScreenDescription::Error {
                    code: code.into(),
                    message: message.into(),
                },
            },
            Effect::Close,
        ]
    }

    /// The single entry point. Same state + same event ⇒ same effects (I/O is all in the shell).
    pub fn handle_event(&mut self, event: Event) -> Vec<Effect> {
        match event {
            Event::SetClock { epoch } => {
                // `now_epoch` is a process-local high-water mark. A backwards update must never
                // make expired credentials, trust lists, certificates, status assertions or WUAs
                // appear current again. Keep the prior value and terminate any in-flight
                // presentation before another consent/sign/delivery effect can be emitted.
                if epoch < self.now_epoch {
                    if self.active == ActiveFlow::Presentation {
                        return self.abort_presentation(AbortReason::ClockRollback);
                    }
                    return Self::presentation_error_effects(AbortReason::ClockRollback)
                        .unwrap_or_default();
                }
                self.now_epoch = epoch;
                Vec::new()
            }
            Event::AuthorizationRequestReceived { request } => {
                self.begin_flow(ActiveFlow::Presentation);
                self.drive(Input::AuthorizationRequest(request))
            }
            Event::RpCertChainResolved {
                rp_cert_chain,
                registered_redirect_uris,
            } => {
                // The registration decision is computed here, in-core, from the trusted list.
                let (registered, rp_public_key) = self.resolve_rp(&rp_cert_chain);
                self.pending_rp_provenance = registered.then(|| RelyingPartyProvenance {
                    certificate_chain: rp_cert_chain,
                    public_key: rp_public_key.clone(),
                });
                self.drive(Input::RpTrustResolved(ResolvedTrust {
                    registered,
                    rp_public_key,
                    registered_redirect_uris,
                }))
            }
            Event::UserConsented => {
                // Preserve an already-terminal state when the shell races a stale UI event after
                // an earlier fail-closed abort (for example, no complete eligible selection).
                if self.active != ActiveFlow::Presentation {
                    return self.drive(Input::ConsentGranted);
                }
                if let Err(error) = self.presentation_evidence_is_current() {
                    return self.abort_presentation_eligibility(error);
                }
                // Status is resolved after explicit consent but before any signature/disclosure.
                // Missing or stale selected lists become bounded HTTPS fetch effects; known-bad
                // and indeterminate values fail closed immediately.
                match self.presentation_status_gate() {
                    StatusGate::Ready => {
                        self.pending_status_references.clear();
                        self.drive(Input::ConsentGranted)
                    }
                    StatusGate::Fetch {
                        all_references,
                        uris,
                    } => {
                        self.pending_status_references = all_references;
                        uris.into_iter()
                            .map(|uri| Effect::FetchStatusList { uri })
                            .collect()
                    }
                    StatusGate::Revoked => self.status_block_effects(true),
                    StatusGate::Indeterminate => self.status_block_effects(false),
                }
            }
            Event::UserDeclined => {
                self.pending_status_references.clear();
                let effects = self.drive(Input::ConsentDeclined);
                if matches!(self.vp, State::Aborted(AbortReason::UserDeclined)) {
                    self.reset_flow(ActiveFlow::Presentation);
                }
                effects
            }
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
                ActiveFlow::Presentation => {
                    if let Some(reason) = self.presentation_sensitive_abort_reason() {
                        self.abort_presentation(reason)
                    } else {
                        self.drive(Input::DeviceSignatureProduced(signature))
                    }
                }
                _ => self.drive(Input::DeviceSignatureProduced(signature)),
            },
            Event::PresentationDelivered => {
                let effects = self.drive(Input::PresentationDelivered);
                if matches!(self.vp, State::Done) {
                    self.finish_flow(ActiveFlow::Presentation);
                }
                effects
            }
            Event::PaymentAuthorizationDelivered => {
                if self.active != ActiveFlow::Payment
                    || !matches!(self.payment, payment::State::Authorized { .. })
                {
                    return Vec::new();
                }
                self.record_payment();
                self.finish_flow(ActiveFlow::Payment);
                vec![Effect::Close]
            }
            Event::QesAuthorizationDelivered => {
                if self.active != ActiveFlow::Qes
                    || !matches!(self.qes, qes::QesState::Signed { .. })
                {
                    return Vec::new();
                }
                self.finish_flow(ActiveFlow::Qes);
                vec![Effect::Close]
            }
            Event::OperationSucceeded { operation_id } => {
                self.pending_operations.remove(&operation_id);
                Vec::new()
            }
            Event::OperationFailed {
                operation_id,
                failure,
            } => self
                .pending_operations
                .remove(&operation_id)
                .map(|pending| self.operation_terminal_effects(pending, Some(failure)))
                .unwrap_or_default(),
            Event::OperationCancelled { operation_id } => self
                .pending_operations
                .remove(&operation_id)
                .map(|pending| self.operation_terminal_effects(pending, None))
                .unwrap_or_default(),
            Event::PaymentAuthorizationRequestReceived { request } => {
                self.begin_flow(ActiveFlow::Payment);
                self.drive_payment(payment::Input::PaymentAuthorizationRequest(request))
            }
            Event::PaymentApproved => self.drive_payment(payment::Input::UserApproved),
            Event::PaymentDeclined => self.drive_payment(payment::Input::UserDeclined),
            Event::QesSignRequestReceived { request } => {
                self.begin_flow(ActiveFlow::Qes);
                self.drive_qes(qes::Input::SignatureRequest(request))
            }
            Event::QesAuthorized => self.drive_qes(qes::Input::UserAuthorized),
            Event::QesDeclined => self.drive_qes(qes::Input::UserDeclined),
            Event::WalletTransferOfferCreated => {
                self.begin_flow(ActiveFlow::WalletTransfer);
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
                self.begin_flow(ActiveFlow::Issuance);
                // A new offer begins a FRESH OpenID4VCI session: reset the (one-shot) issuance
                // machine to Idle so a wallet can be issued several credentials in one lifetime.
                // Replay protection (`iss_seen_c_nonces`) deliberately persists across sessions.
                self.issuance = oid4vci::State::Idle;
                self.issuer_cert_chain_current = issuer_cert_chain;
                // Resolve each trusted-list service separately. The shell value is only a
                // compatibility assertion; proof audience and audit identity come from the
                // authenticated leaf URI and a mismatch keeps the issuance machine fail-closed.
                let issuers = self.resolve_credential_issuers(&self.issuer_cert_chain_current);
                let authenticated_identity = issuers
                    .first()
                    .map(|issuer| issuer.identity.clone())
                    .unwrap_or_default();
                let consistent_path = Self::issuer_candidates_are_consistent(&issuers);
                self.issuer_trusted_current =
                    !issuers.is_empty() && consistent_path && issuer_id == authenticated_identity;
                self.issuer_id_current = authenticated_identity;
                self.issuer_id_assertion_current = issuer_id;
                self.issuer_candidates_current = if consistent_path { issuers } else { Vec::new() };
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
                Some(f) => match self.authenticate_received_credential(
                    f,
                    &bytes,
                    &self.issuer_cert_chain_current,
                    &self.issuer_id_assertion_current,
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
            Event::StatusListReceived {
                uri,
                http_status,
                token,
                provider_cert_chain,
            } => {
                if let Err(error) = self.presentation_evidence_is_current() {
                    return self.abort_presentation_eligibility(error);
                }
                let expected = self
                    .pending_status_references
                    .iter()
                    .any(|reference| reference.uri == uri);
                if !expected || !(200..=299).contains(&http_status) {
                    self.pending_status_references.clear();
                    return self.status_block_effects(false);
                }
                if self
                    .load_status_list(&uri, &token, &provider_cert_chain)
                    .is_err()
                {
                    self.pending_status_references.clear();
                    return self.status_block_effects(false);
                }

                match self.presentation_status_gate() {
                    StatusGate::Ready => {
                        self.pending_status_references.clear();
                        self.drive(Input::ConsentGranted)
                    }
                    StatusGate::Fetch { all_references, .. } => {
                        // All missing URIs were emitted together on consent. Wait for the other
                        // in-flight responses without issuing duplicates.
                        self.pending_status_references = all_references;
                        Vec::new()
                    }
                    StatusGate::Revoked => {
                        self.pending_status_references.clear();
                        self.status_block_effects(true)
                    }
                    StatusGate::Indeterminate => {
                        self.pending_status_references.clear();
                        self.status_block_effects(false)
                    }
                }
            }
        }
    }

    /// FFI-friendly wrapper: takes a JSON `Event`, returns a JSON array of `Effect`s.
    pub fn handle_event_json(&mut self, event_json: &str) -> Result<String, String> {
        let value: serde_json::Value =
            serde_json::from_str(event_json).map_err(|e| e.to_string())?;
        let event_type = value
            .get("type")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "event type must be a string".to_string())?;
        let event: Event = serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;

        if Self::is_operation_result_event(event_type) {
            let operation_id = value
                .get("operationId")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| format!("missing or invalid operationId for {event_type}"))?;
            let pending = self
                .pending_operations
                .get(&operation_id)
                .cloned()
                .ok_or_else(|| format!("stale or unknown operationId {operation_id}"))?;
            if pending.flow != self.active {
                return Err(format!(
                    "operationId {operation_id} belongs to an inactive wallet flow"
                ));
            }

            let is_terminal = matches!(
                &event,
                Event::OperationFailed { .. } | Event::OperationCancelled { .. }
            );
            if !is_terminal && !pending.result.accepts_event(event_type) {
                return Err(format!(
                    "operationId {operation_id} expects {}, got {event_type}",
                    pending.result.result_type()
                ));
            }
            if matches!(
                event_type,
                "userConsented" | "paymentApproved" | "qesAuthorized"
            ) {
                let expected_hash = pending.authorization_hash.ok_or_else(|| {
                    format!("operationId {operation_id} has no authorization hash")
                })?;
                let actual_hash = Self::wire_authorization_hash(&value, event_type)?;
                if actual_hash != expected_hash {
                    return Err(format!(
                        "operationId {operation_id} authorizationHash does not match the rendered screen"
                    ));
                }
            }
            if !is_terminal && !self.operation_result_state_is_valid(event_type) {
                return Err(format!(
                    "operationId {operation_id} result {event_type} is invalid in the current state"
                ));
            }
            if let (
                OperationResultKind::StatusList { uri: expected },
                Event::StatusListReceived { uri: actual, .. },
            ) = (&pending.result, &event)
            {
                if expected != actual {
                    return Err(format!(
                        "operationId {operation_id} is bound to a different status resource"
                    ));
                }
            }

            // Generic terminal events remove/reset through `handle_event`; exact protocol results
            // are consumed here before the state transition so duplicates are immediately stale.
            if !matches!(
                &event,
                Event::OperationSucceeded { .. }
                    | Event::OperationFailed { .. }
                    | Event::OperationCancelled { .. }
            ) {
                self.pending_operations.remove(&operation_id);
            }
        }

        let effects = self.handle_event(event);
        match self.serialize_wire_effects(effects) {
            Ok(json) => Ok(json),
            Err(error) => {
                // `handle_event` may already have advanced a protocol machine. If its resulting
                // effects cannot be represented atomically on the native wire, no shell callback
                // can ever complete that state. Tear down the ephemeral flow and every pending
                // callback so the next request starts cleanly instead of inheriting a zombie.
                let active = self.active;
                if active != ActiveFlow::None {
                    self.reset_flow(active);
                }
                self.pending_operations.clear();
                Err(error)
            }
        }
    }

    fn is_operation_result_event(event_type: &str) -> bool {
        matches!(
            event_type,
            "rpCertChainResolved"
                | "deviceSignatureProduced"
                | "presentationDelivered"
                | "paymentAuthorizationDelivered"
                | "qesAuthorizationDelivered"
                | "parPushed"
                | "authorizationCodeReturned"
                | "transactionCodeEntered"
                | "tokenReceived"
                | "credentialReceived"
                | "statusListReceived"
                | "userConsented"
                | "userDeclined"
                | "paymentApproved"
                | "paymentDeclined"
                | "qesAuthorized"
                | "qesDeclined"
                | "operationSucceeded"
                | "operationFailed"
                | "operationCancelled"
        )
    }

    fn operation_result_state_is_valid(&self, event_type: &str) -> bool {
        match event_type {
            "presentationDelivered" => matches!(self.vp, State::Presenting),
            "paymentAuthorizationDelivered" => {
                matches!(self.payment, payment::State::Authorized { .. })
            }
            "qesAuthorizationDelivered" => matches!(self.qes, qes::QesState::Signed { .. }),
            _ => true,
        }
    }

    fn wire_authorization_hash(
        value: &serde_json::Value,
        event_type: &str,
    ) -> Result<[u8; 32], String> {
        let bytes = value
            .get("authorizationHash")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| format!("missing or invalid authorizationHash for {event_type}"))?;
        if bytes.len() != 32 {
            return Err(format!(
                "missing or invalid authorizationHash for {event_type}"
            ));
        }
        let mut hash = [0u8; 32];
        for (index, byte) in bytes.iter().enumerate() {
            let byte = byte
                .as_u64()
                .filter(|value| *value <= u8::MAX as u64)
                .ok_or_else(|| format!("authorizationHash[{index}] must be an unsigned byte"))?;
            hash[index] = byte as u8;
        }
        Ok(hash)
    }

    fn operation_result_for_effect(
        &self,
        effect: &Effect,
    ) -> Result<Option<PendingOperation>, String> {
        let mut authorization_hash = None;
        let result = match effect {
            Effect::ResolveRpTrust { .. } => OperationResultKind::RpCertChain,
            Effect::PersistNonce { .. } => OperationResultKind::Persisted,
            Effect::Sign { .. } => OperationResultKind::Signature,
            Effect::Http { .. } => match self.active {
                ActiveFlow::Presentation => OperationResultKind::PresentationDelivery,
                ActiveFlow::Payment => OperationResultKind::PaymentDelivery,
                ActiveFlow::Qes => OperationResultKind::QesDelivery,
                flow => return Err(format!("HTTP effect emitted for unsupported flow {flow:?}")),
            },
            Effect::PushPar => OperationResultKind::Par,
            Effect::OpenAuthBrowser => OperationResultKind::AuthorizationCode,
            Effect::PromptTxCode => OperationResultKind::TransactionCode,
            Effect::RequestToken => OperationResultKind::Token,
            Effect::RequestCredential { .. } => OperationResultKind::Credential,
            Effect::FetchStatusList { uri } => OperationResultKind::StatusList { uri: uri.clone() },
            Effect::PublishTransferOffer { .. } => OperationResultKind::TransferOfferPublished,
            Effect::Render { screen } => {
                let (result, stored_hash) = match screen {
                    ScreenDescription::Consent(_) => (
                        OperationResultKind::PresentationDecision,
                        self.session.as_ref().map(|session| session.consent_hash),
                    ),
                    ScreenDescription::PaymentConfirmation(_) => (
                        OperationResultKind::PaymentDecision,
                        Some(self.pay_consent_hash),
                    ),
                    ScreenDescription::SignConfirmation(_) => (
                        OperationResultKind::QesDecision,
                        Some(self.qes_consent_hash),
                    ),
                    _ => return Ok(None),
                };
                let computed_hash = presenter::consent_hash(&AwsLc, screen);
                let stored_hash = stored_hash.ok_or_else(|| {
                    "interactive render has no core authorization hash".to_string()
                })?;
                if stored_hash != computed_hash {
                    return Err("interactive render authorization hash is inconsistent".into());
                }
                authorization_hash = Some(stored_hash);
                result
            }
            Effect::Close => return Ok(None),
        };
        Ok(Some(PendingOperation {
            flow: self.active,
            result,
            authorization_hash,
        }))
    }

    fn serialize_wire_effects(&mut self, effects: Vec<Effect>) -> Result<String, String> {
        let prepared: Vec<(Effect, Option<PendingOperation>)> = effects
            .into_iter()
            .map(|effect| {
                let pending = self.operation_result_for_effect(&effect)?;
                Ok((effect, pending))
            })
            .collect::<Result<_, String>>()?;
        let operation_count = prepared
            .iter()
            .filter(|(_, pending)| pending.is_some())
            .count();
        if self.pending_operations.len() + operation_count > MAX_PENDING_OPERATIONS {
            return Err("too many pending wallet operations".into());
        }

        // Android's public contract uses a signed Long. Never emit an ID outside that common
        // Swift/Kotlin range, and preflight the complete batch before mutating the sequence/map.
        let operation_count_u64 =
            u64::try_from(operation_count).map_err(|_| "too many wallet operations")?;
        let next_after_batch = self
            .next_operation_id
            .checked_add(operation_count_u64)
            .ok_or_else(|| "wallet operationId space exhausted".to_string())?;
        if operation_count > 0 && next_after_batch - 1 > i64::MAX as u64 {
            return Err("wallet operationId space exhausted".into());
        }

        let mut next_id = self.next_operation_id;
        let mut values = Vec::with_capacity(prepared.len());
        let mut staged = Vec::with_capacity(operation_count);
        for (effect, pending) in prepared {
            let mut value = serde_json::to_value(effect).map_err(|e| e.to_string())?;
            if let Some(pending) = pending {
                let operation_id = next_id;
                next_id += 1;
                let result_type = pending.result.result_type();
                let object = value
                    .as_object_mut()
                    .ok_or_else(|| "effect did not serialize as an object".to_string())?;
                object.insert("operationId".into(), operation_id.into());
                object.insert(
                    "resultType".into(),
                    serde_json::Value::String(result_type.into()),
                );
                if let Some(hash) = pending.authorization_hash {
                    object.insert(
                        "authorizationHash".into(),
                        serde_json::to_value(hash).map_err(|e| e.to_string())?,
                    );
                }
                staged.push((operation_id, pending));
            }
            values.push(value);
        }
        let json = serde_json::to_string(&values).map_err(|e| e.to_string())?;
        self.next_operation_id = next_after_batch;
        self.pending_operations.extend(staged);
        Ok(json)
    }

    fn drive(&mut self, input: Input) -> Vec<Effect> {
        // For consent, compute the complete data-minimised DCQL set plan.
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
        let was_aborted = matches!(self.vp, State::Aborted(_));
        let newly_aborted = if was_aborted {
            None
        } else if let State::Aborted(reason) = &next {
            Some(*reason)
        } else {
            None
        };
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
                selected_credentials: Vec::new(),
                selected_sources: Vec::new(),
                selected_revealed_claims: Vec::new(),
                rp_provenance: self.pending_rp_provenance.clone(),
                consent_hash: [0u8; 32],
                shared_claims: Vec::new(),
            });
            // Freeze the complete selection while the request, RP trust and every credential are
            // current. If one query cannot be satisfied, do not render consent (or emit any of the
            // protocol outputs produced alongside it).
            if let Err(error) = self.prepare_presentation_selection() {
                return self.abort_presentation_eligibility(error);
            }
        }

        let mut effects: Vec<Effect> = outputs
            .into_iter()
            .flat_map(|o| self.translate(o))
            .collect();

        // Delivery-policy failures happen before consent and therefore have no protocol output of
        // their own. Surface a stable error screen + close effect instead of silently stalling.
        if let Some(reason) = newly_aborted {
            if let Some(error_effects) = Self::presentation_error_effects(reason) {
                self.session = None;
                effects.extend(error_effects);
            }
        }

        // Record a completed presentation the moment the machine reaches Done (once).
        if !was_done && matches!(self.vp, State::Done) {
            self.record_presentation();
        }
        effects
    }

    fn presentation_error_effects(reason: AbortReason) -> Option<Vec<Effect>> {
        let (code, message) = match reason {
            AbortReason::ResponseModeUnsupported => (
                "presentation_response_mode_unsupported",
                "The relying party requested an unsupported response mode.",
            ),
            AbortReason::ResponseUriInvalid => (
                "presentation_response_uri_invalid",
                "The relying party did not provide a valid HTTPS response endpoint.",
            ),
            AbortReason::ResponseUriNotRegistered => (
                "presentation_response_uri_not_registered",
                "The response endpoint is not registered for this relying party.",
            ),
            AbortReason::ResponseEncryptionMetadataInvalid => (
                "presentation_response_encryption_metadata_invalid",
                "The relying party did not provide valid response-encryption metadata.",
            ),
            AbortReason::ResponseEncryptionFailed => (
                "presentation_response_encryption_failed",
                "The presentation response could not be encrypted safely.",
            ),
            AbortReason::ClockRollback => (
                "clock_rollback_rejected",
                "The trusted wallet clock cannot move backwards.",
            ),
            AbortReason::CredentialExpired => (
                "credential_expired",
                "A selected credential expired before it could be shared.",
            ),
            AbortReason::CredentialNotYetValid => (
                "credential_not_yet_valid",
                "A selected credential is not currently valid.",
            ),
            AbortReason::CredentialProvenanceInvalid => (
                "credential_provenance_invalid",
                "A selected credential no longer has valid authenticated provenance.",
            ),
            AbortReason::PresentationTrustInvalid => (
                "presentation_trust_invalid",
                "Current trusted relying-party evidence is required before sharing.",
            ),
            AbortReason::NoCredential => (
                "no_eligible_credential",
                "No current credential satisfies the complete presentation request.",
            ),
            AbortReason::CredentialStatusInvalid => (
                "credential_revoked",
                "This credential is revoked or suspended and cannot be shared.",
            ),
            AbortReason::CredentialStatusUnavailable => (
                "credential_status_unavailable",
                "A fresh, trusted status assertion is required before this credential can be shared.",
            ),
            _ => return None,
        };
        Some(vec![
            Effect::Render {
                screen: ScreenDescription::Error {
                    code: code.into(),
                    message: message.into(),
                },
            },
            Effect::Close,
        ])
    }

    fn abort_presentation(&mut self, reason: AbortReason) -> Vec<Effect> {
        self.vp = State::Aborted(reason);
        self.session = None;
        self.pending_rp_provenance = None;
        self.pending_status_references.clear();
        self.clear_pending_operations(ActiveFlow::Presentation);
        self.active = ActiveFlow::None;
        Self::presentation_error_effects(reason).unwrap_or_default()
    }

    fn abort_presentation_eligibility(
        &mut self,
        error: PresentationEligibilityError,
    ) -> Vec<Effect> {
        self.abort_presentation(Self::eligibility_abort_reason(error))
    }

    fn eligibility_abort_reason(error: PresentationEligibilityError) -> AbortReason {
        match error {
            PresentationEligibilityError::CredentialExpired => AbortReason::CredentialExpired,
            PresentationEligibilityError::CredentialNotYetValid => {
                AbortReason::CredentialNotYetValid
            }
            PresentationEligibilityError::CredentialProvenanceInvalid => {
                AbortReason::CredentialProvenanceInvalid
            }
            PresentationEligibilityError::TrustEvidenceInvalid => {
                AbortReason::PresentationTrustInvalid
            }
            PresentationEligibilityError::NoEligibleCredential => {
                // Keep the established protocol-state reason for API compatibility while the
                // facade supplies the new explicit terminal error screen.
                AbortReason::NoCredential
            }
        }
    }

    /// The complete gate used immediately before any signature or HTTP disclosure. Status-list
    /// fetch/retry is supported at the consent transition; if evidence becomes stale later, abort
    /// instead of consuming a signature callback or silently reusing cached authorization.
    fn presentation_sensitive_abort_reason(&self) -> Option<AbortReason> {
        if let Err(error) = self.presentation_evidence_is_current() {
            return Some(Self::eligibility_abort_reason(error));
        }
        match self.presentation_status_gate() {
            StatusGate::Ready => None,
            StatusGate::Revoked => Some(AbortReason::CredentialStatusInvalid),
            StatusGate::Fetch { .. } | StatusGate::Indeterminate => {
                Some(AbortReason::CredentialStatusUnavailable)
            }
        }
    }

    /// Resolve a credential issuer independently in each catalogue-supported trust domain. The
    /// returned values retain authenticated identity, leaf key and validity provenance; roots are
    /// never unioned, and the signed credential type later selects exactly one required service.
    fn resolve_credential_issuers(&self, chain: &[Vec<u8>]) -> Vec<CredentialIssuerEvidence> {
        [IssuerTrustDomain::Pid, IssuerTrustDomain::Attestation]
            .into_iter()
            .filter_map(|service| {
                let trust_service = match service {
                    IssuerTrustDomain::Pid => ServiceType::PidProvider,
                    IssuerTrustDomain::Attestation => ServiceType::AttestationProvider,
                };
                let anchors = self
                    .trust_store
                    .parsed_anchors_at(trust_service, self.now_epoch);
                if anchors.is_empty() {
                    return None;
                }
                x509::check_credential_issuer(chain, &anchors, self.now_epoch, &AwsLc)
                    .ok()
                    .map(|validated| CredentialIssuerEvidence {
                        identity: validated.identity,
                        service,
                        public_key_raw: validated.public_key_raw,
                        certificate_path: chain.to_vec(),
                        not_before: validated.not_before,
                        not_after: validated.not_after,
                    })
            })
            .collect()
    }

    fn issuer_for_type<'a>(
        &self,
        issuers: &'a [CredentialIssuerEvidence],
        credential_type: &str,
    ) -> Result<&'a CredentialIssuerEvidence, CredentialIngestionError> {
        let service = self
            .catalogue
            .issuer_trust_domain(credential_type)
            .ok_or(CredentialIngestionError::UnknownCredentialType)?;
        issuers
            .iter()
            .find(|issuer| issuer.service == service)
            .ok_or(CredentialIngestionError::IssuerServiceMismatch)
    }

    /// Every service candidate comes from the same bounded certificate bundle. Reject any
    /// ambiguity before a credential verifier is allowed to use one candidate's key and another
    /// candidate's policy domain.
    fn issuer_candidates_are_consistent(issuers: &[CredentialIssuerEvidence]) -> bool {
        let Some(first) = issuers.first() else {
            return false;
        };
        first.is_internally_consistent()
            && issuers.iter().all(|issuer| {
                issuer.is_internally_consistent()
                    && issuer.identity == first.identity
                    && issuer.public_key_raw == first.public_key_raw
                    && issuer.certificate_path == first.certificate_path
                    && issuer.not_before == first.not_before
                    && issuer.not_after == first.not_after
            })
    }

    /// Resolve a status-signing key only through anchors authorised for the StatusProvider
    /// service. A PID issuer, RP or arbitrary shell-supplied key cannot sign cache entries.
    fn resolve_status_provider_key(&self, chain: &[Vec<u8>]) -> Option<Vec<u8>> {
        let anchors = self
            .trust_store
            .parsed_anchors_at(ServiceType::StatusProvider, self.now_epoch);
        if anchors.is_empty() {
            return None;
        }
        x509::validate_path(chain, &anchors, self.now_epoch, &AwsLc)
            .ok()
            .and_then(|path| {
                path.first()
                    .filter(|leaf| !leaf.is_ca)
                    .map(|leaf| leaf.public_key_raw.clone())
            })
    }

    fn verify_sdjwt_credential(
        &self,
        bytes: &[u8],
        issuers: &[CredentialIssuerEvidence],
        issuer_id_assertion: &str,
    ) -> Result<(VerifiedCredential, CredentialIssuerEvidence), CredentialIngestionError> {
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
        let processed = sd
            .verify_and_process(&AwsLc, &AwsLc, &issuers[0].public_key_raw, alg)
            .map_err(|error| match error {
                sdjwt::SdJwtError::Crypto(_) => CredentialIngestionError::SignatureInvalid,
                _ => CredentialIngestionError::MalformedCredential,
            })?;
        let issuer_payload = sd
            .issuer_payload()
            .map_err(|_| CredentialIngestionError::MalformedCredential)?;
        validate_sdjwt_issuer_profile(&sd, &issuer_payload, &processed)?;
        let claims = &processed.claims;

        let issuer = claims
            .get("iss")
            .and_then(|v| v.as_str())
            .ok_or(CredentialIngestionError::MalformedCredential)?;
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
        let authenticated_issuer = self.issuer_for_type(issuers, vct)?;
        if issuer.is_empty()
            || issuer != authenticated_issuer.identity
            || issuer_id_assertion != authenticated_issuer.identity
        {
            return Err(CredentialIngestionError::IssuerMismatch);
        }
        if !self
            .catalogue
            .issuer_allowed(vct, &authenticated_issuer.identity)
        {
            return Err(CredentialIngestionError::IssuerNotAllowedForType);
        }
        let held_claims: Vec<String> = claims.keys().cloned().collect();
        if !self.catalogue.satisfies_mandatory(vct, &held_claims) {
            return Err(CredentialIngestionError::MandatoryClaimsMissing);
        }
        let validity = json_validity(claims, self.now_epoch)?;
        if !claims.contains_key("cnf") {
            return Err(CredentialIngestionError::DeviceBindingMissing);
        }
        if !sdjwt_device_binding_matches(claims, &self.device_public_key) {
            return Err(CredentialIngestionError::DeviceBindingMismatch);
        }
        let status = status_reference_from_claims(claims)?;
        let holding = held_credential_from_verified_sd(&sd, &processed, status)?;
        Ok((
            VerifiedCredential::SdJwt {
                holding,
                authenticated: AuthenticatedSdJwtHolding { processed },
                validity,
            },
            authenticated_issuer.clone(),
        ))
    }

    fn verify_mdoc_credential(
        &self,
        issuer_signed: mdoc::IssuerSigned,
        issuers: &[CredentialIssuerEvidence],
        issuer_id_assertion: &str,
    ) -> Result<(VerifiedCredential, CredentialIssuerEvidence), CredentialIngestionError> {
        let mso = mdoc::verify_issuer_signed(
            &issuer_signed,
            &AwsLc,
            &AwsLc,
            &issuers[0].public_key_raw,
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
        let authenticated_issuer = self.issuer_for_type(issuers, &mso.doc_type)?;
        if issuer_id_assertion != authenticated_issuer.identity {
            return Err(CredentialIngestionError::IssuerMismatch);
        }
        if !self
            .catalogue
            .issuer_allowed(&mso.doc_type, &authenticated_issuer.identity)
        {
            return Err(CredentialIngestionError::IssuerNotAllowedForType);
        }
        let mut held_claims = Vec::new();
        for (namespace, items) in &issuer_signed.name_spaces {
            for item in items {
                held_claims.push((namespace.clone(), item.element_id.clone()));
            }
        }
        if !self
            .catalogue
            .satisfies_mandatory_mdoc(&mso.doc_type, &held_claims)
        {
            return Err(CredentialIngestionError::MandatoryClaimsMissing);
        }
        let validity = mdoc_validity(&mso.validity_info, self.now_epoch)?;
        if matches!(mso.device_key, cose::cbor::Value::Null) {
            return Err(CredentialIngestionError::DeviceBindingMissing);
        }
        if !mdoc_device_binding_matches(&mso.device_key, &self.device_public_key) {
            return Err(CredentialIngestionError::DeviceBindingMismatch);
        }
        Ok((
            VerifiedCredential::Mdoc {
                holding: MdocHolding {
                    doctype: mso.doc_type,
                    issuer_signed,
                },
                validity,
            },
            authenticated_issuer.clone(),
        ))
    }

    fn drive_issuance(&mut self, input: oid4vci::Input) -> Vec<Effect> {
        // proof_key_attested is computed in-core: the loaded WUA must verify AND bind this device
        // key at High assurance — never a shell boolean.
        let proof_key_attested = self
            .wua
            .as_ref()
            .map(|w| {
                w.is_valid_for_at(
                    &self.device_public_key,
                    wua::AssuranceLevel::High,
                    self.now_epoch,
                )
            })
            .unwrap_or(false);
        let current_issuers = self.resolve_credential_issuers(&self.issuer_cert_chain_current);
        let issuer_trusted = Self::issuer_candidates_are_consistent(&current_issuers)
            && current_issuers == self.issuer_candidates_current
            && current_issuers
                .first()
                .is_some_and(|issuer| issuer.identity == self.issuer_id_current)
            && self.issuer_id_assertion_current == self.issuer_id_current;
        self.issuer_trusted_current = issuer_trusted;

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
                    Some(verified) if verified.credential.format() == issued_format => {
                        self.store_verified_credential(verified);
                        self.record_issuance(fmt);
                    }
                    _ => {
                        // Defensive invariant: the OID4VCI machine must never reach its success
                        // state without a corresponding authenticated value to store.
                        self.issuance =
                            oid4vci::State::Aborted(oid4vci::AbortReason::CredentialInvalid);
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

        let mut effects: Vec<Effect> = outputs
            .into_iter()
            .flat_map(|o| self.translate_payment(o))
            .collect();

        // `Authorized` means the device produced a dynamically linked code; completion requires a
        // distinct payment-service acknowledgement. Validation/user-decline aborts are terminal
        // locally and must leave the reusable machine recoverable.
        if let payment::State::Aborted(reason) = &self.payment {
            if !effects.iter().any(|effect| matches!(effect, Effect::Close)) {
                if *reason != payment::AbortReason::UserDeclined {
                    effects.push(Effect::Render {
                        screen: ScreenDescription::Error {
                            code: "payment_aborted".into(),
                            message: "The payment authorization could not be completed.".into(),
                        },
                    });
                }
                effects.push(Effect::Close);
            }
            self.reset_flow(ActiveFlow::Payment);
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
            // The pure payment machine closes after producing the authorization. The facade waits
            // for `PaymentAuthorizationDelivered`; a decline still closes immediately.
            PO::Close if matches!(self.payment, payment::State::Authorized { .. }) => Vec::new(),
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
        let mut effects: Vec<Effect> = outputs
            .into_iter()
            .flat_map(|o| self.translate_qes(o))
            .collect();
        if let qes::QesState::Aborted(reason) = &self.qes {
            if *reason != qes::AbortReason::UserDeclined {
                effects.push(Effect::Render {
                    screen: ScreenDescription::Error {
                        code: "qes_aborted".into(),
                        message: "The qualified-signature authorization could not be completed."
                            .into(),
                    },
                });
            }
            if !effects.iter().any(|effect| matches!(effect, Effect::Close)) {
                effects.push(Effect::Close);
            }
            self.reset_flow(ActiveFlow::Qes);
        }
        effects
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
            // A produced QES authorization is not completion until the QTSP acknowledges it.
            QO::Close if matches!(self.qes, qes::QesState::Signed { .. }) => Vec::new(),
            QO::Close => vec![Effect::Close],
        }
    }

    fn eligibility_from_ingestion_error(
        error: CredentialIngestionError,
    ) -> PresentationEligibilityError {
        match error {
            CredentialIngestionError::CredentialExpired => {
                PresentationEligibilityError::CredentialExpired
            }
            CredentialIngestionError::CredentialNotYetValid => {
                PresentationEligibilityError::CredentialNotYetValid
            }
            _ => PresentationEligibilityError::CredentialProvenanceInvalid,
        }
    }

    fn sdjwt_credential_is_current(
        &self,
        stored: &StoredSdJwtCredential,
    ) -> Result<(), PresentationEligibilityError> {
        stored
            .validity
            .validate_at(self.now_epoch)
            .map_err(Self::eligibility_from_ingestion_error)?;
        let StoredProvenance::Authenticated(provenance) = &stored.provenance else {
            return Ok(()); // Explicit Rust-only fixture loader; never reachable over FFI.
        };
        let authenticated = self
            .authenticate_received_credential(
                provenance.format,
                &provenance.raw_credential,
                &provenance.issuer.certificate_path,
                &provenance.issuer.identity,
            )
            .map_err(Self::eligibility_from_ingestion_error)?;
        if authenticated.provenance != *provenance {
            return Err(PresentationEligibilityError::CredentialProvenanceInvalid);
        }
        match authenticated.credential {
            VerifiedCredential::SdJwt {
                holding,
                authenticated,
                validity,
            } if holding == stored.holding
                && stored.authenticated.as_ref() == Some(&authenticated)
                && validity == stored.validity =>
            {
                Ok(())
            }
            _ => Err(PresentationEligibilityError::CredentialProvenanceInvalid),
        }
    }

    fn mdoc_credential_is_current(
        &self,
        stored: &StoredMdocCredential,
    ) -> Result<(), PresentationEligibilityError> {
        stored
            .validity
            .validate_at(self.now_epoch)
            .map_err(Self::eligibility_from_ingestion_error)?;
        let StoredProvenance::Authenticated(provenance) = &stored.provenance else {
            return Ok(()); // Explicit Rust-only fixture loader; never reachable over FFI.
        };
        let authenticated = self
            .authenticate_received_credential(
                provenance.format,
                &provenance.raw_credential,
                &provenance.issuer.certificate_path,
                &provenance.issuer.identity,
            )
            .map_err(Self::eligibility_from_ingestion_error)?;
        if authenticated.provenance != *provenance {
            return Err(PresentationEligibilityError::CredentialProvenanceInvalid);
        }
        match authenticated.credential {
            VerifiedCredential::Mdoc { holding, validity }
                if holding == stored.holding && validity == stored.validity =>
            {
                Ok(())
            }
            _ => Err(PresentationEligibilityError::CredentialProvenanceInvalid),
        }
    }

    fn presentation_trust_is_current(
        &self,
        session: &SessionInfo,
    ) -> Result<(), PresentationEligibilityError> {
        if !self.trust_store.is_valid_at(self.now_epoch) {
            return Err(PresentationEligibilityError::TrustEvidenceInvalid);
        }
        let provenance = session
            .rp_provenance
            .as_ref()
            .ok_or(PresentationEligibilityError::TrustEvidenceInvalid)?;
        let (registered, public_key) = self.resolve_rp(&provenance.certificate_chain);
        if !registered || public_key != provenance.public_key {
            return Err(PresentationEligibilityError::TrustEvidenceInvalid);
        }
        Ok(())
    }

    fn presentation_evidence_is_current(&self) -> Result<(), PresentationEligibilityError> {
        let session = self
            .session
            .as_ref()
            .ok_or(PresentationEligibilityError::TrustEvidenceInvalid)?;
        self.presentation_trust_is_current(session)?;
        if session.selected_sources.is_empty()
            || session.selected_sources.len() != session.selected_credentials.len()
        {
            return Err(PresentationEligibilityError::NoEligibleCredential);
        }
        for source in &session.selected_sources {
            match source {
                PresentationCredentialReference::SdJwt {
                    holding,
                    authenticated,
                } => {
                    let stored = self
                        .credentials
                        .iter()
                        .find(|stored| {
                            stored.holding == *holding && stored.authenticated == *authenticated
                        })
                        .ok_or(PresentationEligibilityError::CredentialProvenanceInvalid)?;
                    self.sdjwt_credential_is_current(stored)?;
                }
                PresentationCredentialReference::Mdoc(holding) => {
                    let stored = self
                        .mdoc_holdings
                        .iter()
                        .find(|stored| stored.holding == *holding)
                        .ok_or(PresentationEligibilityError::CredentialProvenanceInvalid)?;
                    self.mdoc_credential_is_current(stored)?;
                }
            }
        }
        Ok(())
    }

    /// Freeze the complete, currently eligible DCQL plan before consent is rendered.
    fn prepare_presentation_selection(&mut self) -> Result<(), PresentationEligibilityError> {
        let session = self
            .session
            .clone()
            .ok_or(PresentationEligibilityError::TrustEvidenceInvalid)?;
        self.presentation_trust_is_current(&session)?;

        let prepared = match &session.dcql {
            Some(dcql) if !dcql.credentials.is_empty() => {
                // Evaluate every query without mutating session state, then select required
                // Credential Set options atomically. Optional sets are omitted until the holder
                // explicitly opts in, while a required unsatisfied set cannot leak a partial
                // credential through consent, signing or response assembly.
                let mut candidates = Vec::with_capacity(dcql.credentials.len());
                let mut errors = Vec::with_capacity(dcql.credentials.len());
                for query in &dcql.credentials {
                    match self.select_for_query(&session, query) {
                        Ok(candidate) => {
                            candidates.push(Some(candidate));
                            errors.push(None);
                        }
                        Err(error) => {
                            candidates.push(None);
                            errors.push(Some(error));
                        }
                    }
                }
                let satisfiable: Vec<bool> = candidates.iter().map(Option::is_some).collect();
                let indices = dcql
                    .credential_selection_plan(&satisfiable)
                    .ok_or_else(|| {
                        errors
                            .iter()
                            .flatten()
                            .copied()
                            .next()
                            .unwrap_or(PresentationEligibilityError::NoEligibleCredential)
                    })?;
                if indices.is_empty() {
                    return Err(PresentationEligibilityError::NoEligibleCredential);
                }
                let mut prepared = Vec::with_capacity(indices.len());
                for index in indices {
                    prepared.push(
                        candidates[index]
                            .take()
                            .ok_or(PresentationEligibilityError::NoEligibleCredential)?,
                    );
                }
                prepared
            }
            _ => vec![self.select_legacy_sdjwt(&session)?],
        };
        if prepared.is_empty() {
            return Err(PresentationEligibilityError::NoEligibleCredential);
        }
        let target = self
            .session
            .as_mut()
            .ok_or(PresentationEligibilityError::TrustEvidenceInvalid)?;
        target.selected_credentials = prepared.iter().map(|item| item.selected.clone()).collect();
        target.selected_revealed_claims.clear();
        for claim in prepared.iter().flat_map(|item| item.revealed_claims.iter()) {
            if !target.selected_revealed_claims.contains(claim) {
                target.selected_revealed_claims.push(claim.clone());
            }
        }
        target.selected_sources = prepared.into_iter().map(|item| item.source).collect();
        Ok(())
    }

    /// Frozen credentials are the only values the protocol state machine may sign.
    fn select_credentials_for(&self, input: &Input) -> Vec<SelectedCredential> {
        if !matches!(input, Input::ConsentGranted) {
            return Vec::new();
        }
        self.session
            .as_ref()
            .map(|session| session.selected_credentials.clone())
            .unwrap_or_default()
    }

    /// Select a current credential for one exact supported DCQL format.
    fn select_for_query(
        &self,
        sess: &SessionInfo,
        q: &oid4vp::dcql::CredentialQuery,
    ) -> Result<PreparedPresentationCredential, PresentationEligibilityError> {
        let options = q
            .claim_selection_options()
            .ok_or(PresentationEligibilityError::NoEligibleCredential)?;
        let mut first_error = None;
        for option in options {
            let claims: Vec<&oid4vp::dcql::ClaimQuery> =
                option.iter().map(|index| &q.claims[*index]).collect();
            match self.select_for_query_claims(sess, q, &claims) {
                Ok(selected) => return Ok(selected),
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        Err(first_error.unwrap_or(PresentationEligibilityError::NoEligibleCredential))
    }

    /// Select one holding for one already-resolved claim-set option. The caller tries options in
    /// verifier preference order and commits only the first complete match.
    fn select_for_query_claims(
        &self,
        sess: &SessionInfo,
        q: &oid4vp::dcql::CredentialQuery,
        requested_claims: &[&oid4vp::dcql::ClaimQuery],
    ) -> Result<PreparedPresentationCredential, PresentationEligibilityError> {
        let claims: Vec<String> = requested_claims
            .iter()
            .map(|c| c.path_string())
            .filter(|s| !s.is_empty())
            .collect();
        let dcql_id = Some(q.id.clone());

        // A DCQL `values` constraint means the RP only accepts a credential whose claim value is one
        // of the listed values (e.g. `age_over_18 ∈ [true]`). A candidate that can't satisfy it is
        // not eligible — the wallet never presents a value the verifier asked to exclude.
        let fixture_sdjwt_values_ok = |c: &HeldCredential| -> bool {
            requested_claims.iter().all(|cq| match &cq.values {
                None => true,
                Some(allowed) => c
                    .disclosures_by_claim
                    .get(&cq.path_string())
                    .and_then(|d| sd_disclosure_value(d))
                    .is_some_and(|v| allowed.contains(&v)),
            })
        };

        if q.format == "mso_mdoc" {
            let requested_mdoc_paths: Vec<(String, String)> = requested_claims
                .iter()
                .map(|claim| requested_mdoc_path(&claim.path))
                .collect::<Option<_>>()
                .ok_or(PresentationEligibilityError::NoEligibleCredential)?;
            let mdoc_claim_labels: Vec<String> = requested_mdoc_paths
                .iter()
                .map(|(namespace, element)| format!("{namespace}.{element}"))
                .collect();
            let mdoc_values_ok = |issued: &mdoc::IssuerSigned| -> bool {
                requested_claims
                    .iter()
                    .zip(&requested_mdoc_paths)
                    .all(|(claim, path)| match &claim.values {
                        None => true,
                        Some(allowed) => mdoc_value_at(issued, path).is_some_and(|value| {
                            allowed
                                .iter()
                                .any(|allowed| cbor_value_matches_json(value, allowed))
                        }),
                    })
            };
            let doctype = q
                .meta
                .as_ref()
                .and_then(|m| m.doctype_value.clone())
                .ok_or(PresentationEligibilityError::NoEligibleCredential)?;
            let mut first_error = None;
            for stored in self.mdoc_holdings.iter().filter(|stored| {
                stored.holding.doctype == doctype
                    && mdoc_values_ok(&stored.holding.issuer_signed)
                    && requested_mdoc_paths
                        .iter()
                        .all(|path| mdoc_value_at(&stored.holding.issuer_signed, path).is_some())
            }) {
                if let Err(error) = self.mdoc_credential_is_current(stored) {
                    first_error.get_or_insert(error);
                    continue;
                }
                let holding = &stored.holding;
                let issuer_signed = minimise_mdoc(&holding.issuer_signed, &requested_mdoc_paths);
                let mgn = mdoc_generated_nonce(sess.nonce);
                let session_transcript = mdoc::oid4vp_session_transcript(
                    &AwsLc,
                    &sess.rp_client_id,
                    &sess.response_uri,
                    &sess.nonce.to_string(),
                    &mgn,
                );
                return Ok(PreparedPresentationCredential {
                    selected: SelectedCredential::Mdoc {
                        doctype: holding.doctype.clone(),
                        issuer_signed,
                        session_transcript,
                        device_namespaces: mdoc::empty_device_namespaces_bytes(),
                        mdoc_generated_nonce: mgn,
                        dcql_id,
                    },
                    source: PresentationCredentialReference::Mdoc(holding.clone()),
                    revealed_claims: mdoc_claim_labels.clone(),
                });
            }
            return Err(first_error.unwrap_or(PresentationEligibilityError::NoEligibleCredential));
        }
        if q.format != "dc+sd-jwt" {
            return Err(PresentationEligibilityError::NoEligibleCredential);
        }

        let requested_paths: Vec<Vec<RequestedSdJwtPathElement>> = requested_claims
            .iter()
            .map(|claim| requested_sdjwt_path(&claim.path))
            .collect::<Option<_>>()
            .ok_or(PresentationEligibilityError::NoEligibleCredential)?;

        // SD-JWT VC: a candidate must BE one of the query's `vct_values` (when given) — so a request
        // for `urn:eudi:pid:1` is answered by the PID, never an mDL that carries the same claim name.
        let vcts = q
            .meta
            .as_ref()
            .map(|m| m.vct_values.clone())
            .unwrap_or_default();
        let mut first_error = None;
        for stored in &self.credentials {
            let credential = &stored.holding;
            match (&stored.authenticated, &stored.provenance) {
                (Some(authenticated), StoredProvenance::Authenticated(_)) => {
                    let type_matches = vcts.is_empty()
                        || authenticated
                            .processed
                            .claims
                            .get("vct")
                            .and_then(serde_json::Value::as_str)
                            .is_some_and(|vct| vcts.iter().any(|allowed| allowed == vct));
                    if !type_matches {
                        continue;
                    }

                    // Resolve typed paths against the authenticated recursive document. Under
                    // DCQL, `values` filters wildcard matches: disclose only concrete paths whose
                    // exact JSON value is allowed, and treat the claim as absent if none match.
                    let mut selected_paths = Vec::new();
                    let mut claims_match = true;
                    for (claim, requested) in requested_claims.iter().zip(&requested_paths) {
                        let matches = matching_sdjwt_values(authenticated, requested);
                        let matching_paths: Vec<Vec<sdjwt::ClaimPathElement>> = matches
                            .into_iter()
                            .filter(|(_, value)| {
                                claim
                                    .values
                                    .as_ref()
                                    .is_none_or(|allowed| allowed.contains(value))
                            })
                            .map(|(path, _)| path)
                            .collect();
                        if matching_paths.is_empty() {
                            claims_match = false;
                            break;
                        }
                        for path in matching_paths {
                            if !selected_paths.contains(&path) {
                                selected_paths.push(path);
                            }
                        }
                    }
                    if !claims_match {
                        continue;
                    }
                    let selection = select_authenticated_sdjwt_disclosures_for_paths(
                        authenticated,
                        &selected_paths,
                    );
                    if let Err(error) = self.sdjwt_credential_is_current(stored) {
                        first_error.get_or_insert(error);
                        continue;
                    }
                    return Ok(PreparedPresentationCredential {
                        selected: SelectedCredential::SdJwt {
                            issuer_jwt: credential.issuer_jwt.clone(),
                            disclosures: selection.disclosures,
                            dcql_id,
                        },
                        source: PresentationCredentialReference::SdJwt {
                            holding: credential.clone(),
                            authenticated: Some(authenticated.clone()),
                        },
                        revealed_claims: selection.revealed_claims,
                    });
                }
                (None, StoredProvenance::TestFixture) => {
                    let type_matches = vcts.is_empty()
                        || vcts.contains(&credential_vct_and_issuer(&credential.issuer_jwt).0);
                    let carries_all = claims
                        .iter()
                        .all(|claim| credential.disclosures_by_claim.contains_key(claim));
                    if !type_matches
                        || !fixture_sdjwt_values_ok(credential)
                        || (!claims.is_empty() && !carries_all)
                    {
                        continue;
                    }
                    if let Err(error) = self.sdjwt_credential_is_current(stored) {
                        first_error.get_or_insert(error);
                        continue;
                    }
                    let held: Vec<String> =
                        credential.disclosures_by_claim.keys().cloned().collect();
                    let selected_claims = minimum_claim_set(&claims, &held);
                    let disclosures = selected_claims
                        .iter()
                        .filter_map(|claim| credential.disclosures_by_claim.get(claim).cloned())
                        .collect();
                    return Ok(PreparedPresentationCredential {
                        selected: SelectedCredential::SdJwt {
                            issuer_jwt: credential.issuer_jwt.clone(),
                            disclosures,
                            dcql_id,
                        },
                        source: PresentationCredentialReference::SdJwt {
                            holding: credential.clone(),
                            authenticated: None,
                        },
                        revealed_claims: selected_claims,
                    });
                }
                _ => {
                    first_error
                        .get_or_insert(PresentationEligibilityError::CredentialProvenanceInvalid);
                }
            }
        }
        Err(first_error.unwrap_or(PresentationEligibilityError::NoEligibleCredential))
    }

    /// The legacy flat-`claims` path (no DCQL): one SD-JWT, minimised to the requested claims, sent
    /// as a bare `vp_token` (no DCQL id) — exactly the pre-DCQL behaviour.
    fn select_legacy_sdjwt(
        &self,
        sess: &SessionInfo,
    ) -> Result<PreparedPresentationCredential, PresentationEligibilityError> {
        let requested_paths: Vec<Vec<RequestedSdJwtPathElement>> = sess
            .requested_claims
            .iter()
            .map(|claim| vec![RequestedSdJwtPathElement::Name(claim.clone())])
            .collect();
        let mut first_error = None;
        for stored in &self.credentials {
            let credential = &stored.holding;
            match (&stored.authenticated, &stored.provenance) {
                (Some(authenticated), StoredProvenance::Authenticated(_)) => {
                    let Some(selection) =
                        select_authenticated_sdjwt_disclosures(authenticated, &requested_paths)
                    else {
                        continue;
                    };
                    if let Err(error) = self.sdjwt_credential_is_current(stored) {
                        first_error.get_or_insert(error);
                        continue;
                    }
                    return Ok(PreparedPresentationCredential {
                        selected: SelectedCredential::SdJwt {
                            issuer_jwt: credential.issuer_jwt.clone(),
                            disclosures: selection.disclosures,
                            dcql_id: None,
                        },
                        source: PresentationCredentialReference::SdJwt {
                            holding: credential.clone(),
                            authenticated: Some(authenticated.clone()),
                        },
                        revealed_claims: selection.revealed_claims,
                    });
                }
                (None, StoredProvenance::TestFixture) => {
                    let carries_all = sess
                        .requested_claims
                        .iter()
                        .all(|claim| credential.disclosures_by_claim.contains_key(claim));
                    if !sess.requested_claims.is_empty() && !carries_all {
                        continue;
                    }
                    if let Err(error) = self.sdjwt_credential_is_current(stored) {
                        first_error.get_or_insert(error);
                        continue;
                    }
                    let held: Vec<String> =
                        credential.disclosures_by_claim.keys().cloned().collect();
                    let selected_claims = minimum_claim_set(&sess.requested_claims, &held);
                    let disclosures = selected_claims
                        .iter()
                        .filter_map(|claim| credential.disclosures_by_claim.get(claim).cloned())
                        .collect();
                    return Ok(PreparedPresentationCredential {
                        selected: SelectedCredential::SdJwt {
                            issuer_jwt: credential.issuer_jwt.clone(),
                            disclosures,
                            dcql_id: None,
                        },
                        source: PresentationCredentialReference::SdJwt {
                            holding: credential.clone(),
                            authenticated: None,
                        },
                        revealed_claims: selected_claims,
                    });
                }
                _ => {
                    first_error
                        .get_or_insert(PresentationEligibilityError::CredentialProvenanceInvalid);
                }
            }
        }
        Err(first_error.unwrap_or(PresentationEligibilityError::NoEligibleCredential))
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
        let issuers = self.resolve_credential_issuers(issuer_chain);
        if !Self::issuer_candidates_are_consistent(&issuers) {
            return false;
        }
        let Some(signing_issuer) = issuers.first() else {
            return false;
        };
        core::str::from_utf8(credential)
            .ok()
            .and_then(|s| sdjwt::SdJwtVc::parse(s).ok())
            .and_then(|vc| {
                let alg = vc.issuer_algorithm().ok()?;
                if alg != Alg::Es256 {
                    return None;
                }
                let processed = vc
                    .verify_and_process(&AwsLc, &AwsLc, &signing_issuer.public_key_raw, alg)
                    .ok()?;
                let issuer_payload = vc.issuer_payload().ok()?;
                validate_sdjwt_issuer_profile(&vc, &issuer_payload, &processed).ok()?;
                let claims = &processed.claims;
                let issuer_id = claims.get("iss")?.as_str()?;
                let credential_type = claims.get("vct")?.as_str()?;
                let authenticated_issuer = self.issuer_for_type(&issuers, credential_type).ok()?;
                Some(
                    issuer_id == authenticated_issuer.identity
                        && self
                            .catalogue
                            .issuer_allowed(credential_type, &authenticated_issuer.identity),
                )
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
        let Some(session) = self.session.as_ref() else {
            return ScreenDescription::Consent(ConsentScreen {
                rp_display_name: String::new(),
                purpose: String::new(),
                requested_claims: Vec::new(),
            });
        };
        ScreenDescription::Consent(ConsentScreen {
            rp_display_name: session.rp_client_id.clone(),
            purpose: session.purpose.clone(),
            requested_claims: session.selected_revealed_claims.clone(),
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
                if let Err(error) = self.presentation_evidence_is_current() {
                    return self.abort_presentation_eligibility(error);
                }
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
            } => {
                if let Some(reason) = self.presentation_sensitive_abort_reason() {
                    return self.abort_presentation(reason);
                }
                vec![Effect::Sign {
                    key_ref,
                    payload: signing_input,
                }]
            }
            O::SendVpToken(body) => {
                if let Some(reason) = self.presentation_sensitive_abort_reason() {
                    return self.abort_presentation(reason);
                }
                let Some(sess) = self.session.as_ref() else {
                    return self.abort_presentation(AbortReason::ResponseUriInvalid);
                };
                let url = sess.response_uri.clone();
                // For `direct_post.jwt` the response is JWE-encrypted (ECDH-ES + A256GCM) to the
                // verifier's key before it leaves the device. Encryption needs RNG (ephemeral key +
                // IV), so it happens here in the facade, not in the sans-IO `oid4vp` core.
                match sess.response_mode.as_str() {
                    "direct_post" => vec![Effect::Http { url, body }],
                    "direct_post.jwt" => {
                        let Some(key) = sess.response_encryption_key.clone() else {
                            return self.abort_presentation(
                                AbortReason::ResponseEncryptionMetadataInvalid,
                            );
                        };
                        match self.encrypt_direct_post_jwt(&body, &key) {
                            Some(encrypted) => vec![Effect::Http {
                                url,
                                body: encrypted,
                            }],
                            // Fail closed: the verifier asked for encryption, so never fall back to a
                            // plaintext POST that would disclose the presentation. The stable abort
                            // + error effects make the failure observable to the shell and holder.
                            None => self.abort_presentation(AbortReason::ResponseEncryptionFailed),
                        }
                    }
                    _ => self.abort_presentation(AbortReason::ResponseModeUnsupported),
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
        let apv = self
            .session
            .as_ref()
            .map(|s| s.nonce.to_string())
            .unwrap_or_default();
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

    /// Verify + cache a URI-bound Token Status List from a trusted status-provider certificate.
    /// Returns "" on success.
    pub fn load_status_list(
        &self,
        uri: String,
        token: Vec<u8>,
        provider_cert_chain: Vec<Vec<u8>>,
    ) -> String {
        match self.inner.lock().expect("poisoned").load_status_list(
            &uri,
            &token,
            &provider_cert_chain,
        ) {
            Ok(()) => String::new(),
            Err(e) => format!("{e:?}"),
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

#[cfg(test)]
mod structured_sdjwt_tests {
    use super::*;
    use serde_json::json;

    fn disclosure(
        raw: &str,
        digest: &str,
        path: Vec<sdjwt::ClaimPathElement>,
        parent_digest: Option<&str>,
        value: serde_json::Value,
    ) -> sdjwt::VerifiedDisclosure {
        sdjwt::VerifiedDisclosure {
            raw: raw.into(),
            digest: digest.into(),
            path,
            parent_digest: parent_digest.map(String::from),
            value,
        }
    }

    fn holding() -> AuthenticatedSdJwtHolding {
        use sdjwt::ClaimPathElement::{Index, Name};

        AuthenticatedSdJwtHolding {
            processed: sdjwt::ProcessedSdJwt {
                claims: json!({
                    "iss":"https://issuer.example",
                    "vct":"urn:eudi:pid:1",
                    "cnf":{"jwk":{"kty":"EC"}},
                    "family_name":"Permanent",
                    "address":{"country":"DE", "street":"Main", "locality":"Berlin"},
                    "contacts":[
                        {"kind":"phone", "value":"111"},
                        {"kind":"email", "value":"alice@example.com"},
                        {"kind":"backup", "value":"backup@example.com"}
                    ]
                })
                .as_object()
                .unwrap()
                .clone(),
                disclosures: vec![
                    disclosure(
                        "address-raw",
                        "address",
                        vec![Name("address".into())],
                        None,
                        json!({"country":"DE"}),
                    ),
                    disclosure(
                        "street-raw",
                        "street",
                        vec![Name("address".into()), Name("street".into())],
                        Some("address"),
                        json!("Main"),
                    ),
                    disclosure(
                        "locality-raw",
                        "locality",
                        vec![Name("address".into()), Name("locality".into())],
                        Some("address"),
                        json!("Berlin"),
                    ),
                    disclosure(
                        "contact-0-raw",
                        "contact-0",
                        vec![Name("contacts".into()), Index(0)],
                        None,
                        json!({"kind":"phone", "value":"111"}),
                    ),
                    disclosure(
                        "contact-1-raw",
                        "contact-1",
                        vec![Name("contacts".into()), Index(1)],
                        None,
                        json!({"kind":"email", "value":"alice@example.com"}),
                    ),
                    disclosure(
                        "contact-2-raw",
                        "contact-2",
                        vec![Name("contacts".into()), Index(2)],
                        None,
                        json!({"kind":"backup", "value":"backup@example.com"}),
                    ),
                ],
            },
        }
    }

    mod operation_contract_tests {
        use super::*;

        fn operation_id(output: &str) -> u64 {
            serde_json::from_str::<serde_json::Value>(output).unwrap()[0]["operationId"]
                .as_u64()
                .unwrap()
        }

        fn emit(core: &mut Core, flow: ActiveFlow, effect: Effect) -> u64 {
            core.active = flow;
            let output = core.serialize_wire_effects(vec![effect]).unwrap();
            operation_id(&output)
        }

        fn fail(core: &mut Core, operation_id: u64) -> String {
            core.handle_event_json(&format!(
                r#"{{"type":"operationFailed","operationId":{operation_id},"failure":"transport"}}"#
            ))
            .unwrap()
        }

        #[test]
        fn missing_mismatched_and_stale_callbacks_are_rejected() {
            let mut core = Core::new("wallet.example", "device-key");
            let sign_id = emit(
                &mut core,
                ActiveFlow::Presentation,
                Effect::Sign {
                    key_ref: "device-key".into(),
                    payload: vec![1],
                },
            );

            assert!(core
                .handle_event_json(r#"{"type":"deviceSignatureProduced","signature":[1]}"#)
                .unwrap_err()
                .contains("missing or invalid operationId"));
            assert!(core
                .handle_event_json(&format!(
                    r#"{{"type":"presentationDelivered","operationId":{sign_id}}}"#
                ))
                .unwrap_err()
                .contains("expects deviceSignatureProduced"));
            assert!(fail(&mut core, sign_id).contains("operation_delivery_failed"));
            assert!(core
            .handle_event_json(&format!(
                r#"{{"type":"deviceSignatureProduced","operationId":{sign_id},"signature":[1]}}"#
            ))
            .unwrap_err()
            .contains("stale or unknown operationId"));
        }

        #[test]
        fn stale_http_status_and_credential_callbacks_are_rejected_after_recovery() {
            let cases = [
            (
                ActiveFlow::Presentation,
                Effect::Http {
                    url: "https://rp.example/cb".into(),
                    body: vec![],
                },
                "presentationDelivered",
                String::new(),
            ),
            (
                ActiveFlow::Presentation,
                Effect::FetchStatusList {
                    uri: "https://status.example/list".into(),
                },
                "statusListReceived",
                r#","uri":"https://status.example/list","httpStatus":200,"token":[],"providerCertChain":[]"#.into(),
            ),
            (
                ActiveFlow::Issuance,
                Effect::RequestCredential { proof_jwt: vec![1] },
                "credentialReceived",
                r#","format":"dc+sd-jwt","bytes":[]"#.into(),
            ),
        ];

            for (flow, effect, event_type, fields) in cases {
                let mut core = Core::new("wallet.example", "device-key");
                let operation_id = emit(&mut core, flow, effect);
                fail(&mut core, operation_id);
                let error = core
                    .handle_event_json(&format!(
                        r#"{{"type":"{event_type}","operationId":{operation_id}{fields}}}"#
                    ))
                    .unwrap_err();
                assert!(error.contains("stale or unknown operationId"), "{error}");
            }
        }

        #[test]
        fn exact_paths_select_only_parent_dependencies_and_never_array_siblings() {
            use sdjwt::ClaimPathElement::{Index, Name};

            let selection = select_authenticated_sdjwt_disclosures_for_paths(
                &holding(),
                &[
                    vec![Name("address".into()), Name("street".into())],
                    vec![Name("contacts".into()), Index(1), Name("kind".into())],
                ],
            );
            assert_eq!(
                selection.disclosures,
                vec!["address-raw", "street-raw", "contact-1-raw"]
            );
            for visible in [
                "family_name",
                "address.country",
                "address.street",
                "contacts[1].kind",
                "contacts[1].value",
            ] {
                assert!(selection.revealed_claims.contains(&visible.to_string()));
            }
            assert!(!selection
                .revealed_claims
                .contains(&"address.locality".to_string()));
            assert!(!selection
                .revealed_claims
                .contains(&"contacts[0].value".to_string()));
            assert!(!selection
                .revealed_claims
                .contains(&"contacts[2].value".to_string()));
        }

        #[test]
        fn no_requested_disclosure_keeps_only_unavoidable_permanent_pii_visible() {
            let selection = select_authenticated_sdjwt_disclosures_for_paths(&holding(), &[]);
            assert!(selection.disclosures.is_empty());
            assert_eq!(selection.revealed_claims, vec!["family_name"]);
        }

        #[test]
        fn canonical_path_rendering_cannot_confuse_literal_and_nested_claim_names() {
            use sdjwt::ClaimPathElement::Name;

            let literal = sdjwt_path_string(&[Name("a.b".into())]);
            let nested = sdjwt_path_string(&[Name("a".into()), Name("b".into())]);
            assert_eq!(literal, r#"["a.b"]"#);
            assert_eq!(nested, "a.b");
            assert_ne!(literal, nested);
            assert_ne!(
                sdjwt_path_string(&[Name("items[0]".into())]),
                sdjwt_path_string(&[Name("items".into()), sdjwt::ClaimPathElement::Index(0)])
            );
        }

        #[test]
        fn mdoc_paths_require_exact_namespace_and_element_components() {
            assert_eq!(
                requested_mdoc_path(&[json!("namespace"), json!("element")]),
                Some(("namespace".into(), "element".into()))
            );
            assert!(
                requested_mdoc_path(&[json!("namespace"), json!({}), json!("element")]).is_none()
            );
            assert!(requested_mdoc_path(&[json!("namespace"), json!("")]).is_none());
        }

        #[test]
        fn status_operation_is_bound_to_the_exact_resource() {
            let mut core = Core::new("wallet.example", "device-key");
            let operation_id = emit(
                &mut core,
                ActiveFlow::Presentation,
                Effect::FetchStatusList {
                    uri: "https://status.example/one".into(),
                },
            );
            let error = core
            .handle_event_json(&format!(
                r#"{{"type":"statusListReceived","operationId":{operation_id},"uri":"https://status.example/two","httpStatus":200,"token":[],"providerCertChain":[]}}"#
            ))
            .unwrap_err();
            assert!(error.contains("different status resource"));
            assert!(core.pending_operations.contains_key(&operation_id));
        }

        #[test]
        fn callback_is_rejected_when_its_owning_flow_is_not_active() {
            let mut core = Core::new("wallet.example", "device-key");
            let operation_id = emit(
                &mut core,
                ActiveFlow::Presentation,
                Effect::Sign {
                    key_ref: "device-key".into(),
                    payload: vec![1],
                },
            );
            // Model a corrupted/raced active marker without clearing the map. The JSON boundary must
            // verify both possession of the operation id and ownership by the currently active flow.
            core.active = ActiveFlow::Payment;

            let error = core
            .handle_event_json(&format!(
                r#"{{"type":"deviceSignatureProduced","operationId":{operation_id},"signature":[1]}}"#
            ))
            .unwrap_err();

            assert!(error.contains("inactive wallet flow"));
            assert!(core.pending_operations.contains_key(&operation_id));
        }

        #[test]
        fn delivery_acknowledgements_are_rejected_before_the_protocol_is_ready() {
            let cases = [
                (ActiveFlow::Presentation, "presentationDelivered"),
                (ActiveFlow::Payment, "paymentAuthorizationDelivered"),
                (ActiveFlow::Qes, "qesAuthorizationDelivered"),
            ];

            for (flow, event_type) in cases {
                let mut core = Core::new("wallet.example", "device-key");
                let operation_id = emit(
                    &mut core,
                    flow,
                    Effect::Http {
                        url: "https://service.example/callback".into(),
                        body: vec![],
                    },
                );

                let error = core
                    .handle_event_json(&format!(
                        r#"{{"type":"{event_type}","operationId":{operation_id}}}"#
                    ))
                    .unwrap_err();

                assert!(error.contains("invalid in the current state"), "{error}");
                assert!(core.pending_operations.contains_key(&operation_id));
            }
        }

        #[test]
        fn old_consent_cannot_authorize_a_newer_flow() {
            let consent = || Effect::Render {
                screen: ScreenDescription::Consent(ConsentScreen {
                    rp_display_name: "RP".into(),
                    purpose: "age".into(),
                    requested_claims: vec!["age_over_18".into()],
                }),
            };
            let mut core = Core::new("wallet.example", "device-key");
            core.begin_flow(ActiveFlow::Presentation);
            let old_effect = consent();
            let Effect::Render { screen: old_screen } = &old_effect else {
                unreachable!()
            };
            core.session = Some(SessionInfo {
                consent_hash: presenter::consent_hash(&AwsLc, old_screen),
                ..SessionInfo::default()
            });
            let old_id = operation_id(&core.serialize_wire_effects(vec![old_effect]).unwrap());
            core.begin_flow(ActiveFlow::Presentation);
            let current_effect = consent();
            let Effect::Render {
                screen: current_screen,
            } = &current_effect
            else {
                unreachable!()
            };
            core.session = Some(SessionInfo {
                consent_hash: presenter::consent_hash(&AwsLc, current_screen),
                ..SessionInfo::default()
            });
            let current_id =
                operation_id(&core.serialize_wire_effects(vec![current_effect]).unwrap());

            let error = core
                .handle_event_json(&format!(
                    r#"{{"type":"userConsented","operationId":{old_id}}}"#
                ))
                .unwrap_err();
            assert!(error.contains("stale or unknown operationId"));
            assert!(core.pending_operations.contains_key(&current_id));
            assert!(core
                .handle_event_json(&format!(
                    r#"{{"type":"operationCancelled","operationId":{current_id}}}"#
                ))
                .unwrap()
                .contains("operation_cancelled"));
        }

        #[test]
        fn approval_requires_the_exact_rendered_authorization_hash() {
            let screen = ScreenDescription::Consent(ConsentScreen {
                rp_display_name: "RP".into(),
                purpose: "age".into(),
                requested_claims: vec!["age_over_18".into()],
            });
            let expected_hash = presenter::consent_hash(&AwsLc, &screen);
            let mut core = Core::new("wallet.example", "device-key");
            core.active = ActiveFlow::Presentation;
            core.session = Some(SessionInfo {
                consent_hash: expected_hash,
                ..SessionInfo::default()
            });
            let output = core
                .serialize_wire_effects(vec![Effect::Render { screen }])
                .unwrap();
            let operation_id = operation_id(&output);
            let wire_hash = serde_json::from_str::<serde_json::Value>(&output).unwrap()[0]
                ["authorizationHash"]
                .clone();
            assert_eq!(wire_hash, serde_json::to_value(expected_hash).unwrap());

            let missing = core
                .handle_event_json(&format!(
                    r#"{{"type":"userConsented","operationId":{operation_id}}}"#
                ))
                .unwrap_err();
            assert!(missing.contains("missing or invalid authorizationHash"));
            let wrong_hash = serde_json::to_string(&[0u8; 32]).unwrap();
            let mismatch = core
            .handle_event_json(&format!(
                r#"{{"type":"userConsented","operationId":{operation_id},"authorizationHash":{wrong_hash}}}"#
            ))
            .unwrap_err();
            assert!(mismatch.contains("does not match the rendered screen"));
            assert!(core.pending_operations.contains_key(&operation_id));

            let different_screen = ScreenDescription::Consent(ConsentScreen {
                rp_display_name: "Other RP".into(),
                purpose: "different".into(),
                requested_claims: vec!["family_name".into()],
            });
            let cross_screen_hash =
                serde_json::to_string(&presenter::consent_hash(&AwsLc, &different_screen)).unwrap();
            let cross_screen = core
            .handle_event_json(&format!(
                r#"{{"type":"userConsented","operationId":{operation_id},"authorizationHash":{cross_screen_hash}}}"#
            ))
            .unwrap_err();
            assert!(cross_screen.contains("does not match the rendered screen"));
        }

        #[test]
        fn infrastructure_failure_resets_each_reusable_machine() {
            let mut presentation = Core::new("wallet.example", "device-key");
            presentation.vp = State::Aborted(AbortReason::MalformedRequest);
            let id = emit(
                &mut presentation,
                ActiveFlow::Presentation,
                Effect::Sign {
                    key_ref: "key".into(),
                    payload: vec![],
                },
            );
            fail(&mut presentation, id);
            assert!(matches!(presentation.vp, State::Idle));

            let mut payment = Core::new("wallet.example", "device-key");
            payment.payment = payment::State::Aborted(payment::AbortReason::MalformedRequest);
            let id = emit(
                &mut payment,
                ActiveFlow::Payment,
                Effect::Sign {
                    key_ref: "key".into(),
                    payload: vec![],
                },
            );
            fail(&mut payment, id);
            assert!(matches!(payment.payment, payment::State::Idle));

            let mut issuance = Core::new("wallet.example", "device-key");
            issuance.issuance = oid4vci::State::Aborted(oid4vci::AbortReason::CredentialInvalid);
            let id = emit(&mut issuance, ActiveFlow::Issuance, Effect::RequestToken);
            fail(&mut issuance, id);
            assert!(matches!(issuance.issuance, oid4vci::State::Idle));

            let mut qes = Core::new("wallet.example", "device-key");
            qes.qes = qes::QesState::Aborted(qes::AbortReason::MalformedRequest);
            let id = emit(
                &mut qes,
                ActiveFlow::Qes,
                Effect::Sign {
                    key_ref: "key".into(),
                    payload: vec![],
                },
            );
            fail(&mut qes, id);
            assert!(matches!(qes.qes, qes::QesState::Idle));
        }

        #[test]
        fn wire_effect_batch_is_atomic_at_id_exhaustion() {
            let mut core = Core::new("wallet.example", "device-key");
            core.active = ActiveFlow::Presentation;
            core.next_operation_id = i64::MAX as u64;
            let error = core
                .serialize_wire_effects(vec![
                    Effect::ResolveRpTrust {
                        client_id: "rp.example".into(),
                    },
                    Effect::PersistNonce { nonce: 1 },
                ])
                .unwrap_err();
            assert!(error.contains("operationId space exhausted"));
            assert!(core.pending_operations.is_empty());
            assert_eq!(core.next_operation_id, i64::MAX as u64);
        }

        #[test]
        fn wire_id_exhaustion_resets_progressed_flow_before_returning_error() {
            let mut core = Core::new("wallet.example", "device-key");
            core.next_operation_id = i64::MAX as u64 + 1;

            let error = core
                .handle_event_json(r#"{"type":"walletTransferOfferCreated"}"#)
                .unwrap_err();

            assert!(error.contains("operationId space exhausted"));
            assert_eq!(core.active, ActiveFlow::None);
            assert!(matches!(core.w2w, w2w::State::Idle));
            assert!(core.pending_operations.is_empty());

            // Exhaustion is practically unreachable and intentionally does not wrap/reuse IDs. Reset
            // the injected boundary value to prove the protocol machine itself is cleanly reusable.
            core.next_operation_id = 1;
            let output = core
                .handle_event_json(r#"{"type":"walletTransferOfferCreated"}"#)
                .unwrap();
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&output).unwrap()[0]["type"],
                "publishTransferOffer"
            );
            assert_eq!(core.active, ActiveFlow::WalletTransfer);
            assert!(matches!(core.w2w, w2w::State::AwaitingTransfer));
        }

        #[test]
        fn pending_cap_failure_clears_all_callbacks_and_allows_a_new_flow() {
            let mut core = Core::new("wallet.example", "device-key");
            for operation_id in 1..=MAX_PENDING_OPERATIONS as u64 {
                core.pending_operations.insert(
                    operation_id,
                    PendingOperation {
                        flow: ActiveFlow::Presentation,
                        result: OperationResultKind::Persisted,
                        authorization_hash: None,
                    },
                );
            }

            let error = core
                .handle_event_json(r#"{"type":"walletTransferOfferCreated"}"#)
                .unwrap_err();

            assert!(error.contains("too many pending wallet operations"));
            assert_eq!(core.active, ActiveFlow::None);
            assert!(matches!(core.w2w, w2w::State::Idle));
            assert!(core.pending_operations.is_empty());

            let output = core
                .handle_event_json(r#"{"type":"walletTransferOfferCreated"}"#)
                .unwrap();
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&output).unwrap()[0]["type"],
                "publishTransferOffer"
            );
            assert_eq!(core.active, ActiveFlow::WalletTransfer);
        }

        #[test]
        fn operation_ids_are_positive_signed_range_and_monotonic() {
            let mut core = Core::new("wallet.example", "device-key");
            assert!((1..=(1u64 << 62)).contains(&core.next_operation_id));
            let first = emit(
                &mut core,
                ActiveFlow::Presentation,
                Effect::PersistNonce { nonce: 1 },
            );
            let second = emit(
                &mut core,
                ActiveFlow::Presentation,
                Effect::PersistNonce { nonce: 2 },
            );
            assert!((1..=i64::MAX as u64).contains(&first));
            assert_eq!(second, first + 1);
        }
    }
}
