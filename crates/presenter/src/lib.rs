#![forbid(unsafe_code)]
//! `presenter` — Pure snapshot->ScreenDescription presenter with a closed screen vocabulary and consent hashing
//!
//! See docs/IMPLEMENTATION_PLAN.md Section 7.
//! Skeleton only: public shapes are sketched; implementation follows the plan.

use crypto_traits::Digest;

/// Closed vocabulary of screen archetypes. No expressions/conditionals live in a description:
/// all branching happened upstream in the protocol machines.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScreenDescription {
    Loading,
    Error { code: String, message: String },
    Consent(ConsentScreen),
    CredentialList,
    CredentialDetail,
    IssuanceOffer,
    PresentQr,
    ScanQr,
    AuthPrompt,
    TransactionHistory,
}

/// A fully-resolved consent screen. RP-supplied strings enter ONLY as validated data here.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
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

/// Canonical (deterministic) serialization of a screen for hashing/logging. Skeleton:
/// replace with a stable canonical encoder (see plan Section 7).
pub fn canonical_bytes(screen: &ScreenDescription) -> Vec<u8> {
    format!("{screen:?}").into_bytes()
}

/// What-you-see-is-what-you-sign: the consent hash is computed INSIDE the core.
pub fn consent_hash(digest: &dyn Digest, screen: &ScreenDescription) -> [u8; 32] {
    digest.sha256(&canonical_bytes(screen))
}
