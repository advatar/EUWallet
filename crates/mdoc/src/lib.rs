#![forbid(unsafe_code)]
//! `mdoc` — ISO/IEC 18013-5 mdoc credential format with profiled canonical CBOR
//!
//! See docs/IMPLEMENTATION_PLAN.md Section 4.
//! Skeleton only: public shapes are sketched; implementation follows the plan.

/// Mobile Security Object — the signed digest catalogue of a credential. Skeleton.
#[derive(Clone, Debug, Default)]
pub struct MobileSecurityObject {
    pub version: String,
    pub digest_algorithm: String,
    pub doc_type: String,
}

/// Issuer-signed portion (COSE_Sign1 over the MSO). Skeleton.
#[derive(Clone, Debug, Default)]
pub struct IssuerSigned;

/// Device-signed portion (holder binding). Skeleton.
#[derive(Clone, Debug, Default)]
pub struct DeviceSigned;

/// Encode with canonical (deterministic) CBOR. Two equal inputs must encode identically.
pub fn to_canonical_cbor<T>(_value: &T) -> Vec<u8> {
    Vec::new()
}

/// Canonical CBOR primitives live in `cose` (COSE is defined over CBOR and `mdoc` depends on
/// `cose`, so putting them here would cycle — see plan Section 4). Re-exported so existing
/// call sites (`mdoc::cbor::encode_uint`, the Tier-1 harness) resolve unchanged.
pub use cose::cbor;
