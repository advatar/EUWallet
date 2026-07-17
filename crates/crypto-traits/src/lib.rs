#![forbid(unsafe_code)]
//! `crypto_traits` — trait boundary for host/platform crypto and hardware keystores
//!
//! See docs/IMPLEMENTATION_PLAN.md Section 4 / Section 8.
//! Skeleton only: public shapes are sketched; implementation follows the plan.

/// Opaque handle to a key that lives in a hardware keystore (Secure Enclave / StrongBox).
/// The private key bytes NEVER cross this boundary.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct KeyRef(pub String);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Alg {
    Es256,
    Es384,
    EdDsa,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CryptoError {
    NotFound,
    Unsupported,
    Backend(String),
}

/// Produce signatures using a hardware-protected key (implemented by the shell).
pub trait Signer {
    fn sign(&self, key: &KeyRef, alg: Alg, payload: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

/// Verify signatures (may be implemented in pure Rust over a vetted lib behind this trait).
pub trait Verifier {
    fn verify(
        &self,
        alg: Alg,
        public_key: &[u8],
        payload: &[u8],
        sig: &[u8],
    ) -> Result<(), CryptoError>;
}

/// Cryptographic digest (e.g. SHA-256) — used for the consent hash in `presenter`.
pub trait Digest {
    fn sha256(&self, data: &[u8]) -> [u8; 32];
}

/// Authenticated encryption for session/at-rest data (never invented by us).
pub trait Aead {
    fn seal(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;
    fn open(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;
}

/// Key derivation (HKDF).
pub trait Kdf {
    fn hkdf_sha256(&self, ikm: &[u8], salt: &[u8], info: &[u8], out_len: usize) -> Vec<u8>;
}

/// Cryptographically secure randomness (from the platform).
pub trait Random {
    fn fill(&self, out: &mut [u8]);
}

/// Verify a platform key-attestation chain (used by `wua`). Never trust device self-claims.
pub trait KeyAttestation {
    fn verify_chain(
        &self,
        attestation: &[u8],
        expected_challenge: &[u8],
    ) -> Result<(), CryptoError>;
}

/// Bundle every capability the core needs, so a shell provides one object.
pub trait CryptoProvider:
    Signer + Verifier + Digest + Aead + Kdf + Random + KeyAttestation
{
}
