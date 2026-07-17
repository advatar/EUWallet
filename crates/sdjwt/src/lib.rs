#![forbid(unsafe_code)]
//! `sdjwt` — SD-JWT VC credential format (IETF draft-17) with selective-disclosure
//!
//! See docs/IMPLEMENTATION_PLAN.md Section 4.
//! Skeleton only: public shapes are sketched; implementation follows the plan.

/// Pinned wire version. Isolate the codec behind this marker (change-watch: draft, not RFC).
pub const SD_JWT_VC_DRAFT: &str = "draft-17";

/// A parsed SD-JWT VC: the issuer-signed JWT plus disclosures and optional key-binding JWT. Skeleton.
#[derive(Clone, Debug, Default)]
pub struct SdJwtVc {
    pub issuer_jwt: String,
    pub disclosures: Vec<String>,
    pub key_binding_jwt: Option<String>,
}
