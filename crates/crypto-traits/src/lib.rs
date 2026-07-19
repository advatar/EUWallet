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

/// ECDH key agreement on P-256, for JWE `ECDH-ES` (OpenID4VP `direct_post.jwt` response
/// encryption). The sender generates an ephemeral keypair, agrees with the recipient's public key,
/// and returns the ephemeral public key (uncompressed SEC1, `0x04 || X || Y`) to place in the JWE
/// `epk`, plus the raw shared secret `Z` the Concat KDF turns into the content-encryption key.
pub trait KeyAgreement {
    fn ecdh_es_p256(&self, recipient_public: &[u8]) -> Result<EcdhEs, CryptoError>;
}

/// The result of an ephemeral ECDH-ES agreement: the ephemeral public key to publish and the
/// shared secret `Z` (never leaves the device except as derived key material).
#[derive(Clone, Debug)]
pub struct EcdhEs {
    /// Ephemeral public key, uncompressed SEC1 (`0x04 || X(32) || Y(32)`).
    pub ephemeral_public: Vec<u8>,
    /// The raw ECDH shared secret `Z`.
    pub shared_secret: Vec<u8>,
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
