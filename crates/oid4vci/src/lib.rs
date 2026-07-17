#![forbid(unsafe_code)]
//! `oid4vci` — OpenID4VCI 1.0 credential issuance as a sans-IO state machine (HAIP flows only)
//!
//! See docs/IMPLEMENTATION_PLAN.md Section 5.
//! Skeleton only: public shapes are sketched; implementation follows the plan.

/// Issuance flow states: offer -> authorization -> token -> credential.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum State {
    Idle,
    OfferReceived,
    Authorizing,
    TokenObtained,
    CredentialIssued,
    Aborted,
}
