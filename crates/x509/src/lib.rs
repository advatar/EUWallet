#![forbid(unsafe_code)]
//! `x509` — X.509 parsing, path validation and the EUDI RP/issuer profile checks
//!
//! See docs/IMPLEMENTATION_PLAN.md Section 4 / Section 6.
//! Skeleton only: public shapes are sketched; implementation follows the plan.

/// A registered relying party is NOT the same as a valid TLS certificate. This type
/// represents the *profile-checked* result, not mere chain validity.
#[derive(Clone, Debug, Default)]
pub struct RelyingPartyProfile {
    pub subject: String,
    pub registered: bool,
}

/// Validate a certificate against the EUDI relying-party profile. Skeleton.
pub fn check_relying_party(_der_chain: &[Vec<u8>]) -> Option<RelyingPartyProfile> {
    None
}
