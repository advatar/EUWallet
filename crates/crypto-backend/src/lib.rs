#![forbid(unsafe_code)]
//! `crypto-backend` — the real implementation of the `crypto-traits` boundary, backed by
//! **aws-lc-rs** (FIPS-capable). See docs/IMPLEMENTATION_PLAN.md ("platform cryptography").
//!
//! [`AwsLc`] is a stateless implementation of the algorithms the core needs to *verify* and
//! *derive*: signature verification, SHA-256, HKDF, AES-256-GCM, and secure randomness. It never
//! holds a private key — device-bound signing happens in the Secure Enclave / StrongBox, behind
//! the same [`crypto_traits::Signer`] trait, in the shell.
//!
//! [`SoftwareSigner`] is a software ECDSA P-256 key implementing [`crypto_traits::Signer`], for
//! tests and server-side roles (an issuer simulation), NOT for device keys.
//!
//! ## Key & signature encodings (the boundary contract)
//! * Public keys are the algorithm's **raw** form: an uncompressed EC point `0x04||X||Y` for
//!   ES256/ES384, or the 32-byte key for EdDSA.
//! * ECDSA signatures may be either JOSE/COSE **fixed** `r||s` or X.509 **ASN.1 DER**; the
//!   verifier accepts both (it tries DER, then fixed).

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use aws_lc_rs::agreement::{agree, PrivateKey, UnparsedPublicKey as AgreementPublicKey, ECDH_P256};
use aws_lc_rs::hkdf::{Salt, HKDF_SHA256};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use aws_lc_rs::signature::{
    self, EcdsaKeyPair, KeyPair, UnparsedPublicKey, ECDSA_P256_SHA256_ASN1,
    ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, ECDSA_P384_SHA384_ASN1,
    ECDSA_P384_SHA384_FIXED, ED25519,
};
use crypto_traits::{
    Aead, Alg, CryptoError, Digest, EcdhEs, Kdf, KeyAgreement, KeyRef, Random, Signer, Verifier,
};

/// Stateless aws-lc-rs backend: verification, digest, KDF, AEAD, randomness. No private keys.
#[derive(Clone, Copy, Debug, Default)]
pub struct AwsLc;

impl Verifier for AwsLc {
    fn verify(
        &self,
        alg: Alg,
        public_key: &[u8],
        payload: &[u8],
        sig: &[u8],
    ) -> Result<(), CryptoError> {
        let ok = |a: &'static signature::EcdsaVerificationAlgorithm| {
            UnparsedPublicKey::new(a, public_key)
                .verify(payload, sig)
                .is_ok()
        };
        let accepted = match alg {
            // Accept either DER (X.509) or fixed (JOSE/COSE) ECDSA signatures.
            Alg::Es256 => ok(&ECDSA_P256_SHA256_ASN1) || ok(&ECDSA_P256_SHA256_FIXED),
            Alg::Es384 => ok(&ECDSA_P384_SHA384_ASN1) || ok(&ECDSA_P384_SHA384_FIXED),
            Alg::EdDsa => UnparsedPublicKey::new(&ED25519, public_key)
                .verify(payload, sig)
                .is_ok(),
        };
        if accepted {
            Ok(())
        } else {
            Err(CryptoError::Backend("signature verification failed".into()))
        }
    }
}

impl Digest for AwsLc {
    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        let d = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, data);
        let mut out = [0u8; 32];
        out.copy_from_slice(d.as_ref());
        out
    }
}

impl Random for AwsLc {
    fn fill(&self, out: &mut [u8]) {
        SystemRandom::new()
            .fill(out)
            .expect("system CSPRNG must not fail");
    }
}

// Wrapper so we can request an arbitrary-length HKDF output.
struct OkmLen(usize);
impl aws_lc_rs::hkdf::KeyType for OkmLen {
    fn len(&self) -> usize {
        self.0
    }
}

impl Kdf for AwsLc {
    fn hkdf_sha256(&self, ikm: &[u8], salt: &[u8], info: &[u8], out_len: usize) -> Vec<u8> {
        let prk = Salt::new(HKDF_SHA256, salt).extract(ikm);
        let info_components = [info];
        let okm = prk
            .expand(&info_components, OkmLen(out_len))
            .expect("hkdf expand length within bounds");
        let mut out = vec![0u8; out_len];
        okm.fill(&mut out).expect("hkdf fill");
        out
    }
}

impl Aead for AwsLc {
    fn seal(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let k = aead_key(key)?;
        let nonce = nonce_from(nonce)?;
        let mut buf = plaintext.to_vec();
        k.seal_in_place_append_tag(nonce, Aad::from(aad), &mut buf)
            .map_err(|_| CryptoError::Backend("aead seal failed".into()))?;
        Ok(buf)
    }

    fn open(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let k = aead_key(key)?;
        let nonce = nonce_from(nonce)?;
        let mut buf = ciphertext.to_vec();
        let pt = k
            .open_in_place(nonce, Aad::from(aad), &mut buf)
            .map_err(|_| CryptoError::Backend("aead open failed".into()))?;
        Ok(pt.to_vec())
    }
}

fn aead_key(key: &[u8]) -> Result<LessSafeKey, CryptoError> {
    let ub = UnboundKey::new(&AES_256_GCM, key)
        .map_err(|_| CryptoError::Backend("bad AES-256-GCM key".into()))?;
    Ok(LessSafeKey::new(ub))
}

fn nonce_from(nonce: &[u8]) -> Result<Nonce, CryptoError> {
    if nonce.len() != NONCE_LEN {
        return Err(CryptoError::Backend("nonce must be 12 bytes".into()));
    }
    let mut n = [0u8; NONCE_LEN];
    n.copy_from_slice(nonce);
    Ok(Nonce::assume_unique_for_key(n))
}

impl KeyAgreement for AwsLc {
    fn ecdh_es_p256(&self, recipient_public: &[u8]) -> Result<EcdhEs, CryptoError> {
        let my_private = PrivateKey::generate(&ECDH_P256)
            .map_err(|_| CryptoError::Backend("ecdh keygen failed".into()))?;
        let my_public = my_private
            .compute_public_key()
            .map_err(|_| CryptoError::Backend("ecdh public-key derivation failed".into()))?;
        let peer = AgreementPublicKey::new(&ECDH_P256, recipient_public);
        let shared_secret = agree(
            &my_private,
            peer,
            CryptoError::Backend("ecdh agreement rejected the recipient key".into()),
            |z| Ok(z.to_vec()),
        )?;
        Ok(EcdhEs {
            ephemeral_public: my_public.as_ref().to_vec(),
            shared_secret,
        })
    }
}

/// A P-256 key-agreement keypair for a **recipient** (e.g. an OpenID4VP verifier that decrypts a
/// `direct_post.jwt` response, or a test standing in for one): holds the private key, publishes the
/// public key, and agrees with a sender's ephemeral `epk` to recover the same shared secret `Z`.
pub struct P256AgreementKey {
    private: PrivateKey,
    public: Vec<u8>,
}

impl P256AgreementKey {
    /// Generate a fresh P-256 agreement keypair.
    pub fn generate() -> Result<Self, CryptoError> {
        let private = PrivateKey::generate(&ECDH_P256)
            .map_err(|_| CryptoError::Backend("ecdh keygen failed".into()))?;
        let public = private
            .compute_public_key()
            .map_err(|_| CryptoError::Backend("ecdh public-key derivation failed".into()))?
            .as_ref()
            .to_vec();
        Ok(Self { private, public })
    }

    /// The public key, uncompressed SEC1 (`0x04 || X || Y`) — published in the request's JWKS.
    pub fn public_raw(&self) -> &[u8] {
        &self.public
    }

    /// Agree with a sender's ephemeral public key (uncompressed SEC1) → shared secret `Z`.
    pub fn agree(&self, ephemeral_public: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let peer = AgreementPublicKey::new(&ECDH_P256, ephemeral_public);
        agree(
            &self.private,
            peer,
            CryptoError::Backend("ecdh agreement rejected the ephemeral key".into()),
            |z| Ok(z.to_vec()),
        )
    }
}

/// A software ECDSA P-256 signer for tests and server-side roles (e.g. an issuer). Produces
/// JOSE/COSE **fixed** `r||s` signatures. Not for device keys — those live in the Secure Enclave.
pub struct SoftwareSigner {
    key: EcdsaKeyPair,
    public_raw: Vec<u8>,
}

impl SoftwareSigner {
    /// Generate a fresh P-256 key.
    pub fn generate_p256() -> Result<Self, CryptoError> {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|_| CryptoError::Backend("key generation failed".into()))?;
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref())
            .map_err(|_| CryptoError::Backend("key load failed".into()))?;
        let public_raw = key.public_key().as_ref().to_vec();
        Ok(SoftwareSigner { key, public_raw })
    }

    /// Load an existing P-256 key from PKCS#8 DER (e.g. an issuer/RP server key). Produces
    /// JOSE/COSE fixed `r||s` signatures.
    pub fn from_pkcs8_der(pkcs8: &[u8]) -> Result<Self, CryptoError> {
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8)
            .map_err(|_| CryptoError::Backend("pkcs8 load failed".into()))?;
        let public_raw = key.public_key().as_ref().to_vec();
        Ok(SoftwareSigner { key, public_raw })
    }

    /// The raw uncompressed public-key point (`0x04||X||Y`), the form [`AwsLc`] verifies against.
    pub fn public_key_raw(&self) -> &[u8] {
        &self.public_raw
    }
}

impl Signer for SoftwareSigner {
    fn sign(&self, _key: &KeyRef, alg: Alg, payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if alg != Alg::Es256 {
            return Err(CryptoError::Unsupported);
        }
        let rng = SystemRandom::new();
        let sig = self
            .key
            .sign(&rng, payload)
            .map_err(|_| CryptoError::Backend("signing failed".into()))?;
        Ok(sig.as_ref().to_vec())
    }
}
