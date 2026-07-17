#![forbid(unsafe_code)]
//! `wua` — Wallet Unit Attestation and key attestation producer/verifier (TS03)
//!
//! See docs/IMPLEMENTATION_PLAN.md Section 6.
//! Skeleton only: public shapes are sketched; implementation follows the plan.

/// Result of verifying a Wallet Unit Attestation. Never trust device self-claims. Skeleton.
#[derive(Clone, Debug, Default)]
pub struct WuaVerification {
    pub valid: bool,
}
