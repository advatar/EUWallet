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
    CredentialList(CredentialListScreen),
    CredentialDetail(CredentialDetailScreen),
    IssuanceOffer(IssuanceOfferScreen),
    PinPreparation {
        document_name: String,
    },
    PinHelp,
    NfcReady {
        document_name: String,
    },
    NfcReading {
        state: NfcReadState,
    },
    IssuancePreparing(DocumentSummary),
    IssuanceReady(DocumentSummary),
    IssuanceNeedsAttention {
        document: DocumentSummary,
        recovery: IssuanceRecovery,
    },
    IssuanceRecovery(IssuanceRecoveryScreen),
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CredentialFormat {
    DcSdJwt,
    MsoMdoc,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DocumentStatus {
    Preparing,
    Ready,
    NeedsAttention,
}

/// Consumer-safe document metadata. `issuer_name` is trusted display metadata associated with the
/// authenticated issuer identity; raw certificate subject text must never populate it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DocumentSummary {
    pub document_id: String,
    pub document_name: String,
    pub issuer_name: String,
    pub format: CredentialFormat,
    pub status: DocumentStatus,
    pub portrait_required: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DisplayAttribute {
    pub label: String,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialListScreen {
    pub documents: Vec<DocumentSummary>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialDetailScreen {
    pub document: DocumentSummary,
    pub attributes: Vec<DisplayAttribute>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuanceOfferScreen {
    pub issuer_name: String,
    pub document_name: String,
    pub format: CredentialFormat,
    pub attributes: Vec<String>,
    pub portrait_required: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum NfcReadState {
    WaitingForCard,
    Reading,
    ConnectionLost,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum IssuanceRecovery {
    WrongPin,
    PinBlocked,
    NfcInterrupted,
    NfcUnavailable,
    IssuerRejected,
    NetworkInterrupted,
    Delayed,
    SessionInterrupted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuanceRecoveryScreen {
    pub reason: IssuanceRecovery,
    pub document_name: String,
    /// Present only for `wrongPin`; the core supplies the authenticated eID retry counter.
    pub attempts_remaining: Option<u8>,
    pub can_resume: bool,
}

/// A fully-resolved consent screen. RP-supplied strings enter ONLY as validated data here.
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsentScreen {
    pub rp_display_name: String,
    pub purpose: String,
    pub requested_claims: Vec<String>, // already minimized to the minimum set
    /// Claim paths present in the selected credential(s) but absent from the disclosure set.
    /// Values never cross this boundary. The whole field is covered by [`consent_hash`].
    pub not_shared_claims: Vec<String>,
    pub verifier_registration: VerifierRegistration,
    pub trust_mark: Option<VerifierTrustMark>,
    pub retention: RetentionDisclosure,
    pub over_ask: OverAskResult,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum VerifierRegistration {
    Registered,
    #[default]
    CertificateValidated,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum VerifierTrustMark {
    EudiWallet,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(tag = "policy", rename_all = "camelCase")]
pub enum RetentionDisclosure {
    NotStored,
    Days {
        days: u16,
    },
    #[default]
    Unspecified,
}

#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "camelCase")]
pub enum OverAskResult {
    WithinRegisteredScope,
    ExceedsRegisteredScope {
        claims: Vec<String>,
    },
    #[default]
    RegistrationScopeUnavailable,
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
        Some(ScreenKind::CredentialList) => {
            ScreenDescription::CredentialList(CredentialListScreen {
                documents: Vec::new(),
            })
        }
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
            Value::Array(
                c.not_shared_claims
                    .iter()
                    .cloned()
                    .map(Value::Text)
                    .collect(),
            ),
            Value::Text(
                match c.verifier_registration {
                    VerifierRegistration::Registered => "registered",
                    VerifierRegistration::CertificateValidated => "certificateValidated",
                }
                .into(),
            ),
            match c.trust_mark {
                Some(VerifierTrustMark::EudiWallet) => Value::Text("eudiWallet".into()),
                None => Value::Null,
            },
            match c.retention {
                RetentionDisclosure::NotStored => {
                    Value::Array(vec![Value::Text("notStored".into())])
                }
                RetentionDisclosure::Days { days } => Value::Array(vec![
                    Value::Text("days".into()),
                    Value::Uint(u64::from(days)),
                ]),
                RetentionDisclosure::Unspecified => {
                    Value::Array(vec![Value::Text("unspecified".into())])
                }
            },
            match &c.over_ask {
                OverAskResult::WithinRegisteredScope => {
                    Value::Array(vec![Value::Text("withinRegisteredScope".into())])
                }
                OverAskResult::ExceedsRegisteredScope { claims } => Value::Array(vec![
                    Value::Text("exceedsRegisteredScope".into()),
                    Value::Array(claims.iter().cloned().map(Value::Text).collect()),
                ]),
                OverAskResult::RegistrationScopeUnavailable => {
                    Value::Array(vec![Value::Text("registrationScopeUnavailable".into())])
                }
            },
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
        ScreenDescription::CredentialList(screen) => Value::Array(vec![
            tag("credentialList"),
            document_summaries_value(&screen.documents),
        ]),
        ScreenDescription::CredentialDetail(screen) => Value::Array(vec![
            tag("credentialDetail"),
            document_summary_value(&screen.document),
            Value::Array(
                screen
                    .attributes
                    .iter()
                    .map(|attribute| {
                        Value::Array(vec![
                            Value::Text(attribute.label.clone()),
                            Value::Text(attribute.value.clone()),
                        ])
                    })
                    .collect(),
            ),
        ]),
        ScreenDescription::IssuanceOffer(screen) => Value::Array(vec![
            tag("issuanceOffer"),
            Value::Text(screen.issuer_name.clone()),
            Value::Text(screen.document_name.clone()),
            credential_format_value(screen.format),
            Value::Array(screen.attributes.iter().cloned().map(Value::Text).collect()),
            Value::Bool(screen.portrait_required),
        ]),
        ScreenDescription::PinPreparation { document_name } => Value::Array(vec![
            tag("pinPreparation"),
            Value::Text(document_name.clone()),
        ]),
        ScreenDescription::PinHelp => Value::Array(vec![tag("pinHelp")]),
        ScreenDescription::NfcReady { document_name } => {
            Value::Array(vec![tag("nfcReady"), Value::Text(document_name.clone())])
        }
        ScreenDescription::NfcReading { state } => Value::Array(vec![
            tag("nfcReading"),
            Value::Text(
                match state {
                    NfcReadState::WaitingForCard => "waitingForCard",
                    NfcReadState::Reading => "reading",
                    NfcReadState::ConnectionLost => "connectionLost",
                }
                .into(),
            ),
        ]),
        ScreenDescription::IssuancePreparing(document) => Value::Array(vec![
            tag("issuancePreparing"),
            document_summary_value(document),
        ]),
        ScreenDescription::IssuanceReady(document) => {
            Value::Array(vec![tag("issuanceReady"), document_summary_value(document)])
        }
        ScreenDescription::IssuanceNeedsAttention { document, recovery } => Value::Array(vec![
            tag("issuanceNeedsAttention"),
            document_summary_value(document),
            issuance_recovery_value(*recovery),
        ]),
        ScreenDescription::IssuanceRecovery(screen) => Value::Array(vec![
            tag("issuanceRecovery"),
            issuance_recovery_value(screen.reason),
            Value::Text(screen.document_name.clone()),
            screen
                .attempts_remaining
                .map_or(Value::Null, |attempts| Value::Uint(u64::from(attempts))),
            Value::Bool(screen.can_resume),
        ]),
        ScreenDescription::PresentQr => Value::Array(vec![tag("presentQr")]),
        ScreenDescription::ScanQr => Value::Array(vec![tag("scanQr")]),
        ScreenDescription::AuthPrompt => Value::Array(vec![tag("authPrompt")]),
        ScreenDescription::TransactionHistory => Value::Array(vec![tag("transactionHistory")]),
    }
}

fn credential_format_value(format: CredentialFormat) -> Value {
    Value::Text(
        match format {
            CredentialFormat::DcSdJwt => "dcSdJwt",
            CredentialFormat::MsoMdoc => "msoMdoc",
        }
        .into(),
    )
}

fn document_status_value(status: DocumentStatus) -> Value {
    Value::Text(
        match status {
            DocumentStatus::Preparing => "preparing",
            DocumentStatus::Ready => "ready",
            DocumentStatus::NeedsAttention => "needsAttention",
        }
        .into(),
    )
}

fn document_summary_value(document: &DocumentSummary) -> Value {
    Value::Array(vec![
        Value::Text(document.document_id.clone()),
        Value::Text(document.document_name.clone()),
        Value::Text(document.issuer_name.clone()),
        credential_format_value(document.format),
        document_status_value(document.status),
        Value::Bool(document.portrait_required),
    ])
}

fn document_summaries_value(documents: &[DocumentSummary]) -> Value {
    Value::Array(documents.iter().map(document_summary_value).collect())
}

fn issuance_recovery_value(recovery: IssuanceRecovery) -> Value {
    Value::Text(
        match recovery {
            IssuanceRecovery::WrongPin => "wrongPin",
            IssuanceRecovery::PinBlocked => "pinBlocked",
            IssuanceRecovery::NfcInterrupted => "nfcInterrupted",
            IssuanceRecovery::NfcUnavailable => "nfcUnavailable",
            IssuanceRecovery::IssuerRejected => "issuerRejected",
            IssuanceRecovery::NetworkInterrupted => "networkInterrupted",
            IssuanceRecovery::Delayed => "delayed",
            IssuanceRecovery::SessionInterrupted => "sessionInterrupted",
        }
        .into(),
    )
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
