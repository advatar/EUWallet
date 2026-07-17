#![forbid(unsafe_code)]
//! `trust` — Trusted-list parsing/verification and the trust-anchor store
//!
//! See docs/IMPLEMENTATION_PLAN.md Section 6.
//! Skeleton only: public shapes are sketched; implementation follows the plan.

/// A verified trust anchor set with freshness metadata. Skeleton.
#[derive(Clone, Debug, Default)]
pub struct TrustAnchors {
    pub anchors: Vec<Vec<u8>>, // DER certs
    pub fetched_epoch: u64,
}

/// Parse and verify a signed trusted list. Rejects stale/rolled-back lists. Skeleton.
pub fn parse_trusted_list(_signed_xml: &[u8]) -> Option<TrustAnchors> {
    None
}
