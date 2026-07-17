#![forbid(unsafe_code)]
//! `cose` — COSE structures over the crypto trait boundary (RFC 9052/9053)
//!
//! See docs/IMPLEMENTATION_PLAN.md Section 4.
//! Skeleton only: public shapes are sketched; implementation follows the plan.

pub mod cbor;

use crypto_traits::{Alg, CryptoError, KeyRef, Signer, Verifier};

/// A COSE_Sign1 message (used by mdoc IssuerSigned / DeviceSigned and WUA).
#[derive(Clone, Debug, Default)]
pub struct CoseSign1 {
    pub protected: Vec<u8>,   // serialized protected header (bstr)
    pub unprotected: Vec<u8>, // placeholder for the unprotected header map
    pub payload: Option<Vec<u8>>,
    pub signature: Vec<u8>,
}

impl CoseSign1 {
    /// Build the Sig_structure and sign it with a hardware key. Skeleton.
    pub fn sign(
        _signer: &dyn Signer,
        _key: &KeyRef,
        _alg: Alg,
        _payload: &[u8],
    ) -> Result<Self, CryptoError> {
        Err(CryptoError::Unsupported)
    }
    /// Verify the signature. Reject unknown critical header params. Skeleton.
    pub fn verify(
        &self,
        _verifier: &dyn Verifier,
        _alg: Alg,
        _public_key: &[u8],
    ) -> Result<(), CryptoError> {
        Err(CryptoError::Unsupported)
    }
}
