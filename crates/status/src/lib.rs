#![forbid(unsafe_code)]
//! `status` — Revocation/suspension via Token Status List (draft-21) and certificate status
//!
//! See docs/IMPLEMENTATION_PLAN.md Section 6.
//! Skeleton only: public shapes are sketched; implementation follows the plan.

/// Pinned wire version (change-watch: draft, not RFC).
pub const TOKEN_STATUS_LIST_DRAFT: &str = "draft-21";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialStatus {
    Valid,
    Suspended,
    Revoked,
    Unknown,
}

/// Deterministic fail policy depends on context (offline proximity vs online remote).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailPolicy {
    FailOpen,
    FailClosed,
}
