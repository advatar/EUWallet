//! Default-off FIPS 203/204 primitives for the experimental hybrid profile.
//!
//! Inputs are length-checked before backend parsing. Secret wrappers do not implement `Clone`,
//! redact `Debug`, and use zeroizing backend storage.
//!
//! ```compile_fail
//! use crypto_backend::experimental_pq::MlDsa65SecretKey;
//! MlDsa65SecretKey::generate().unwrap().clone();
//! ```
//! ```compile_fail
//! use crypto_backend::experimental_pq::MlKem768SecretKey;
//! MlKem768SecretKey::generate().unwrap().clone();
//! ```

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use core::fmt;
use hybrid_pq::{
    ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_65_SIGNATURE_BYTES, ML_KEM_768_CIPHERTEXT_BYTES,
    ML_KEM_768_ENCAPSULATION_KEY_BYTES,
};
use ml_dsa::{
    EncodedVerifyingKey, Keypair, MlDsa65, Signature, SignatureEncoding, Signer, SigningKey,
    Verifier, VerifyingKey,
};
use ml_kem::{
    kem::{Ciphertext, Decapsulate, Encapsulate, Key, KeyExport},
    DecapsulationKey, EncapsulationKey, MlKem768, Seed,
};
use zeroize::Zeroize;

/// Public, non-secret failures with no backend diagnostic details.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExperimentalPqError {
    InvalidPrivateKey,
    InvalidPublicKey,
    InvalidSignature,
    InvalidCiphertext,
    VerificationFailed,
    RandomnessUnavailable,
}

/// Non-cloneable ML-DSA-65 signing capability.
pub struct MlDsa65SecretKey(SigningKey<MlDsa65>);

impl fmt::Debug for MlDsa65SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MlDsa65SecretKey([REDACTED])")
    }
}

impl MlDsa65SecretKey {
    pub fn generate() -> Result<Self, ExperimentalPqError> {
        let mut seed = ml_dsa::Seed::default();
        SystemRandom::new()
            .fill(seed.as_mut_slice())
            .map_err(|_| ExperimentalPqError::RandomnessUnavailable)?;
        let key = Self(SigningKey::from_seed(&seed));
        seed.as_mut_slice().zeroize();
        Ok(key)
    }

    /// Restore the FIPS 204 preferred 32-byte private-key representation.
    pub fn from_seed(seed: &[u8]) -> Result<Self, ExperimentalPqError> {
        let mut seed =
            ml_dsa::Seed::try_from(seed).map_err(|_| ExperimentalPqError::InvalidPrivateKey)?;
        let key = Self(SigningKey::from_seed(&seed));
        seed.as_mut_slice().zeroize();
        Ok(key)
    }

    #[must_use]
    pub fn public_key(&self) -> Vec<u8> {
        self.0.verifying_key().encode().as_slice().to_vec()
    }

    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, ExperimentalPqError> {
        let signature: Signature<MlDsa65> = self
            .0
            .try_sign(message)
            .map_err(|_| ExperimentalPqError::InvalidSignature)?;
        Ok(signature.to_bytes().as_slice().to_vec())
    }
}

/// Strict ML-DSA-65 verification.
pub fn verify_ml_dsa_65(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), ExperimentalPqError> {
    if public_key.len() != ML_DSA_65_PUBLIC_KEY_BYTES {
        return Err(ExperimentalPqError::InvalidPublicKey);
    }
    if signature.len() != ML_DSA_65_SIGNATURE_BYTES {
        return Err(ExperimentalPqError::InvalidSignature);
    }
    let encoded = EncodedVerifyingKey::<MlDsa65>::try_from(public_key)
        .map_err(|_| ExperimentalPqError::InvalidPublicKey)?;
    let key = VerifyingKey::<MlDsa65>::decode(&encoded);
    let signature = Signature::<MlDsa65>::try_from(signature)
        .map_err(|_| ExperimentalPqError::InvalidSignature)?;
    key.verify(message, &signature)
        .map_err(|_| ExperimentalPqError::VerificationFailed)
}

/// Non-cloneable ML-KEM-768 decapsulation capability.
pub struct MlKem768SecretKey(DecapsulationKey<MlKem768>);

impl fmt::Debug for MlKem768SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MlKem768SecretKey([REDACTED])")
    }
}

impl MlKem768SecretKey {
    pub fn generate() -> Result<Self, ExperimentalPqError> {
        let mut seed = Seed::default();
        SystemRandom::new()
            .fill(seed.as_mut_slice())
            .map_err(|_| ExperimentalPqError::RandomnessUnavailable)?;
        Ok(Self(DecapsulationKey::from_seed(seed)))
    }

    /// Restore the FIPS 203 preferred 64-byte private-key representation (`d || z`).
    pub fn from_seed(seed: &[u8]) -> Result<Self, ExperimentalPqError> {
        let seed = Seed::try_from(seed).map_err(|_| ExperimentalPqError::InvalidPrivateKey)?;
        Ok(Self(DecapsulationKey::from_seed(seed)))
    }

    #[must_use]
    pub fn public_key(&self) -> Vec<u8> {
        self.0.encapsulation_key().to_bytes().as_slice().to_vec()
    }

    /// Correctly sized invalid ciphertexts retain FIPS 203 implicit-rejection behavior.
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<SharedSecret, ExperimentalPqError> {
        if ciphertext.len() != ML_KEM_768_CIPHERTEXT_BYTES {
            return Err(ExperimentalPqError::InvalidCiphertext);
        }
        let ciphertext = Ciphertext::<MlKem768>::try_from(ciphertext)
            .map_err(|_| ExperimentalPqError::InvalidCiphertext)?;
        Ok(SharedSecret::new(
            self.0.decapsulate(&ciphertext).as_slice(),
        ))
    }
}

/// Encapsulate to a strictly encoded ML-KEM-768 public key using the OS CSPRNG.
pub fn encapsulate_ml_kem_768(
    public_key: &[u8],
) -> Result<(Vec<u8>, SharedSecret), ExperimentalPqError> {
    if public_key.len() != ML_KEM_768_ENCAPSULATION_KEY_BYTES {
        return Err(ExperimentalPqError::InvalidPublicKey);
    }
    let encoded = Key::<EncapsulationKey<MlKem768>>::try_from(public_key)
        .map_err(|_| ExperimentalPqError::InvalidPublicKey)?;
    let public_key = EncapsulationKey::<MlKem768>::new(&encoded)
        .map_err(|_| ExperimentalPqError::InvalidPublicKey)?;
    let (ciphertext, shared) = public_key.encapsulate();
    Ok((
        ciphertext.as_slice().to_vec(),
        SharedSecret::new(shared.as_slice()),
    ))
}

/// Non-cloneable, zeroizing KEM result.
pub struct SharedSecret([u8; 32]);

impl SharedSecret {
    fn new(bytes: &[u8]) -> Self {
        let mut out = [0; 32];
        out.copy_from_slice(bytes);
        Self(out)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SharedSecret([REDACTED])")
    }
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha256_hex(value: &[u8]) -> String {
        let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, value);
        digest
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    #[test]
    fn deterministic_public_key_anchors() {
        let dsa_seed: Vec<u8> = (0_u8..32).collect();
        let kem_seed: Vec<u8> = (0_u8..64).collect();
        let dsa = MlDsa65SecretKey::from_seed(&dsa_seed).unwrap();
        let kem = MlKem768SecretKey::from_seed(&kem_seed).unwrap();
        assert_eq!(
            sha256_hex(&dsa.public_key()),
            "d666806e11cee19a7c989f7445f90dd419cf4d2d51db8c0fdb4c0f0a542238c9"
        );
        assert_eq!(
            sha256_hex(&kem.public_key()),
            "0b7934c83125c788995e2ba6bd761e33046b3e40571be53e023309a29f398cc9"
        );
        assert_eq!(
            MlDsa65SecretKey::from_seed(&dsa_seed[..31]).unwrap_err(),
            ExperimentalPqError::InvalidPrivateKey
        );
        assert_eq!(
            MlKem768SecretKey::from_seed(&kem_seed[..63]).unwrap_err(),
            ExperimentalPqError::InvalidPrivateKey
        );
    }

    #[test]
    fn ml_dsa_round_trip_and_negative_inputs() {
        let key = MlDsa65SecretKey::generate().unwrap();
        let public = key.public_key();
        let signature = key.sign(b"hybrid-tbs").unwrap();
        verify_ml_dsa_65(&public, b"hybrid-tbs", &signature).unwrap();
        assert_eq!(
            verify_ml_dsa_65(&public, b"other", &signature),
            Err(ExperimentalPqError::VerificationFailed)
        );
        assert_eq!(
            verify_ml_dsa_65(&public[..public.len() - 1], b"hybrid-tbs", &signature),
            Err(ExperimentalPqError::InvalidPublicKey)
        );
        assert_eq!(
            verify_ml_dsa_65(&public, b"hybrid-tbs", &signature[..signature.len() - 1]),
            Err(ExperimentalPqError::InvalidSignature)
        );
        assert_eq!(format!("{key:?}"), "MlDsa65SecretKey([REDACTED])");
    }

    #[test]
    fn ml_kem_round_trip_implicit_rejection_and_negative_inputs() {
        let key = MlKem768SecretKey::generate().unwrap();
        let public = key.public_key();
        let (ciphertext, sender) = encapsulate_ml_kem_768(&public).unwrap();
        let recipient = key.decapsulate(&ciphertext).unwrap();
        assert_eq!(sender.as_bytes(), recipient.as_bytes());
        let mut corrupted = ciphertext.clone();
        corrupted[0] ^= 1;
        assert_ne!(
            sender.as_bytes(),
            key.decapsulate(&corrupted).unwrap().as_bytes()
        );
        assert_eq!(
            key.decapsulate(&ciphertext[..ciphertext.len() - 1])
                .unwrap_err(),
            ExperimentalPqError::InvalidCiphertext
        );
        assert_eq!(
            encapsulate_ml_kem_768(&public[..public.len() - 1]).unwrap_err(),
            ExperimentalPqError::InvalidPublicKey
        );
        assert_eq!(format!("{key:?}"), "MlKem768SecretKey([REDACTED])");
        assert_eq!(format!("{sender:?}"), "SharedSecret([REDACTED])");
    }
}
