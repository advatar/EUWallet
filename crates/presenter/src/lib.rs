#![forbid(unsafe_code)]
//! `presenter` — pure snapshot->ScreenDescription presenter with a closed screen vocabulary and
//! canonical consent hashing.
//!
//! See docs/IMPLEMENTATION_PLAN.md Section 7.
//!
//! The presenter lives inside the core and emits fully-resolved [`ScreenDescription`]s (no
//! expressions/conditionals — all branching happened upstream). The consent screen is encoded
//! with the deterministic CBOR codec and hashed, so both platforms provably show the same consent
//! payload: what-you-see-is-what-you-sign, bindable to the presentation/QES intent.

use cose::cbor::Value;
use crypto_traits::Digest;
use serde::{Deserialize, Serialize};

/// Closed vocabulary of screen archetypes. No expressions/conditionals live in a description:
/// all branching happened upstream in the protocol machines.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "screen", rename_all = "camelCase")]
pub enum ScreenDescription {
    Loading,
    Error {
        code: String,
        message: String,
    },
    Consent(ConsentScreen),
    /// Payment Strong Customer Authentication confirmation. Deliberately a SEPARATE archetype from
    /// `Consent`: the register forbids mixing payment transaction data with identity consent
    /// screens. Shows exactly what the user is authorising (amount + payee) — what-you-see-is-
    /// what-you-authorise, dynamically linked by the payment machine.
    PaymentConfirmation(PaymentScreen),
    /// QES qualified-signature confirmation (what-you-see-is-what-you-sign).
    SignConfirmation(SignScreen),
    CredentialList,
    CredentialDetail,
    IssuanceOffer,
    PresentQr,
    ScanQr,
    AuthPrompt,
    TransactionHistory,
}

/// A fully-resolved payment SCA confirmation screen (PSD2 dynamic linking surfaces here). Shows
/// the creditor name AND account so the payer is aware of exactly who is paid (RTS Art. 5(1)).
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentScreen {
    pub creditor_name: String,
    pub creditor_account: String,
    /// Amount in minor units (e.g. cents) to avoid floating-point ambiguity.
    pub amount_minor: u64,
    pub currency: String,
}

/// A fully-resolved QES sign-confirmation screen (what-you-see-is-what-you-sign): the document and
/// (Q)TSP the holder is authorising a qualified signature over.
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignScreen {
    pub document_name: String,
    pub qtsp_id: String,
    /// Hex of the document hash (DTBS) being signed.
    pub document_hash_hex: String,
}

/// A fully-resolved consent screen. RP-supplied strings enter ONLY as validated data here.
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsentScreen {
    pub rp_display_name: String,
    pub purpose: String,
    pub requested_claims: Vec<String>, // already minimized to the minimum set
}

/// Minimal snapshot the presenter reads. Built by wallet-core; keeps presenter dependency-light.
#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    pub screen: Option<ScreenKind>,
    pub consent: ConsentScreen,
    pub error: Option<(String, String)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScreenKind {
    Loading,
    Consent,
    CredentialList,
    Error,
}

/// Pure presentation function.
pub fn present(snapshot: &Snapshot) -> ScreenDescription {
    match snapshot.screen {
        Some(ScreenKind::Consent) => ScreenDescription::Consent(snapshot.consent.clone()),
        Some(ScreenKind::CredentialList) => ScreenDescription::CredentialList,
        Some(ScreenKind::Error) => {
            let (c, m) = snapshot.error.clone().unwrap_or_default();
            ScreenDescription::Error {
                code: c,
                message: m,
            }
        }
        _ => ScreenDescription::Loading,
    }
}

/// Compute the minimum claim set to disclose: the requested claims we actually hold, deduped and
/// sorted for a deterministic consent screen. Never disclose a claim that was not requested.
pub fn minimum_claim_set(requested: &[String], held: &[String]) -> Vec<String> {
    let mut out: Vec<String> = requested
        .iter()
        .filter(|r| held.contains(r))
        .cloned()
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Encode a screen as a canonical CBOR value: a fixed-shape array `[tag, fields...]`. Using the
/// deterministic codec (not a debug format) makes the bytes — and therefore the hash — stable and
/// identical across platforms and compiler versions.
fn to_value(screen: &ScreenDescription) -> Value {
    let tag = |t: &str| Value::Text(t.into());
    match screen {
        ScreenDescription::Loading => Value::Array(vec![tag("loading")]),
        ScreenDescription::Error { code, message } => Value::Array(vec![
            tag("error"),
            Value::Text(code.clone()),
            Value::Text(message.clone()),
        ]),
        ScreenDescription::Consent(c) => Value::Array(vec![
            tag("consent"),
            Value::Text(c.rp_display_name.clone()),
            Value::Text(c.purpose.clone()),
            Value::Array(
                c.requested_claims
                    .iter()
                    .cloned()
                    .map(Value::Text)
                    .collect(),
            ),
        ]),
        ScreenDescription::PaymentConfirmation(p) => Value::Array(vec![
            tag("paymentConfirmation"),
            Value::Text(p.creditor_name.clone()),
            Value::Text(p.creditor_account.clone()),
            Value::Uint(p.amount_minor),
            Value::Text(p.currency.clone()),
        ]),
        ScreenDescription::SignConfirmation(s) => Value::Array(vec![
            tag("signConfirmation"),
            Value::Text(s.document_name.clone()),
            Value::Text(s.qtsp_id.clone()),
            Value::Text(s.document_hash_hex.clone()),
        ]),
        ScreenDescription::CredentialList => Value::Array(vec![tag("credentialList")]),
        ScreenDescription::CredentialDetail => Value::Array(vec![tag("credentialDetail")]),
        ScreenDescription::IssuanceOffer => Value::Array(vec![tag("issuanceOffer")]),
        ScreenDescription::PresentQr => Value::Array(vec![tag("presentQr")]),
        ScreenDescription::ScanQr => Value::Array(vec![tag("scanQr")]),
        ScreenDescription::AuthPrompt => Value::Array(vec![tag("authPrompt")]),
        ScreenDescription::TransactionHistory => Value::Array(vec![tag("transactionHistory")]),
    }
}

/// Canonical (deterministic) serialization of a screen for hashing and the transaction log.
pub fn canonical_bytes(screen: &ScreenDescription) -> Vec<u8> {
    to_value(screen).to_canonical()
}

/// What-you-see-is-what-you-sign: the consent hash is computed INSIDE the core over the canonical
/// bytes, then bound to the presentation/signature and recorded in the transaction log.
pub fn consent_hash(digest: &dyn Digest, screen: &ScreenDescription) -> [u8; 32] {
    digest.sha256(&canonical_bytes(screen))
}
