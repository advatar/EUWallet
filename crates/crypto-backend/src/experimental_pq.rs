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
use zeroize::{Zeroize, Zeroizing};

use crate::AwsLc;
use crypto_traits::{Alg, Verifier as CryptoVerifier};
use hybrid_pq::{
    envelope::{
        decode_public_key, decode_signature, encode_public_key, encode_signature, EnvelopeError,
    },
    tbs::{HybridContext, HybridPurpose, HybridTbs},
    HybridErrorClass, HybridKeyRef, HybridMismatch, HybridSignatureProfile,
};

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

/// Generic external rejection with only a bounded, secret-free diagnostic class for local tests
/// and telemetry. No component-success state or backend detail is exposed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HybridVerificationRejected(HybridErrorClass);

impl HybridVerificationRejected {
    #[must_use]
    pub fn diagnostic_class(self) -> HybridErrorClass {
        self.0
    }
}

impl fmt::Display for HybridVerificationRejected {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("hybrid signature rejected")
    }
}

impl std::error::Error for HybridVerificationRejected {}

/// Complete inputs for the one atomic verification entry point. `resolved_key_ref` identifies the
/// trusted logical key that supplied the complete public-key envelope; `expected_key_ref` is the
/// identity/generation authorized by the protocol transaction.
pub struct HybridVerificationInput<'a> {
    pub signature_envelope: &'a [u8],
    pub public_key_envelope: &'a [u8],
    pub resolved_key_ref: &'a HybridKeyRef,
    pub expected_key_ref: &'a HybridKeyRef,
    pub expected_profile: HybridSignatureProfile,
    pub expected_purpose: HybridPurpose,
    pub context: &'a HybridContext,
    pub payload: &'a [u8],
    pub expected_audience: Option<&'a [u8]>,
    pub expected_nonce: &'a [u8],
    pub seen_nonces: &'a [Vec<u8>],
    pub now_epoch_seconds: u64,
    pub downgrade_attempted: bool,
}

/// Parse, bind, reconstruct, verify and apply policy without exposing partial component results.
pub fn verify_hybrid_signature_atomic(
    input: &HybridVerificationInput<'_>,
) -> Result<(), HybridVerificationRejected> {
    let fail = |class| HybridVerificationRejected(class);
    let signature_envelope = decode_signature(input.signature_envelope)
        .map_err(|error| fail(envelope_diagnostic(error)))?;
    let public_key = decode_public_key(input.public_key_envelope)
        .map_err(|error| fail(envelope_diagnostic(error)))?;

    // Re-encoding is a second, explicit canonicality invariant at the orchestration boundary.
    if encode_signature(&signature_envelope) != input.signature_envelope
        || encode_public_key(&public_key) != input.public_key_envelope
    {
        return Err(fail(HybridErrorClass::NonCanonicalInput));
    }
    let signature = signature_envelope.signature();
    if input.expected_profile != HybridSignatureProfile::Es256MlDsa65V1
        || public_key.profile() != input.expected_profile
        || signature.profile() != input.expected_profile
        || signature_envelope.purpose() != input.expected_purpose
    {
        return Err(fail(HybridErrorClass::Mismatch));
    }
    if input.resolved_key_ref.identity() != input.expected_key_ref.identity() {
        return Err(fail(
            hybrid_pq::HybridCryptoError::Mismatch {
                field: HybridMismatch::Identity,
            }
            .class(),
        ));
    }
    if input.resolved_key_ref.generation() != input.expected_key_ref.generation()
        || input.context.key_generation != input.expected_key_ref.generation()
    {
        return Err(fail(
            hybrid_pq::HybridCryptoError::Mismatch {
                field: HybridMismatch::Generation,
            }
            .class(),
        ));
    }
    if input.context.wallet_identity != input.expected_key_ref.identity().as_bytes()
        || input.context.audience.as_deref() != input.expected_audience
        || input.context.nonce != input.expected_nonce
        || input
            .seen_nonces
            .iter()
            .any(|nonce| nonce == input.expected_nonce)
        || input.context.created_at_epoch_seconds > input.now_epoch_seconds
        || input.context.expires_at_epoch_seconds <= input.now_epoch_seconds
    {
        return Err(fail(HybridErrorClass::PolicyDenied));
    }
    if input.downgrade_attempted {
        return Err(fail(HybridErrorClass::DowngradeDetected));
    }

    let tbs = HybridTbs::build(
        input.expected_profile,
        input.expected_purpose,
        input.context,
        input.payload,
    )
    .map_err(|error| fail(error.class()))?;
    AwsLc
        .verify(
            Alg::Es256,
            public_key.classical(),
            tbs.as_bytes(),
            signature.classical(),
        )
        .map_err(|_| fail(HybridErrorClass::VerificationFailure))?;
    verify_ml_dsa_65(
        public_key.post_quantum(),
        tbs.as_bytes(),
        signature.post_quantum(),
    )
    .map_err(|_| fail(HybridErrorClass::VerificationFailure))?;
    Ok(())
}

fn envelope_diagnostic(error: EnvelopeError) -> HybridErrorClass {
    match error {
        EnvelopeError::UnsupportedProfile => HybridErrorClass::UnsupportedProfile,
        EnvelopeError::MalformedComponent => HybridErrorClass::MalformedComponent,
        EnvelopeError::TooLarge => HybridErrorClass::ResourceLimitExceeded,
        _ => HybridErrorClass::NonCanonicalInput,
    }
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

    /// Copy the preferred seed into an owned zeroizing buffer for an immediate custody transfer.
    /// Callers must never persist or log the plaintext result.
    #[must_use]
    pub fn export_seed_for_custody(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.0.to_seed().as_slice().to_vec())
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

    /// Copy the preferred seed into an owned zeroizing buffer for an immediate custody transfer.
    /// Callers must never persist or log the plaintext result.
    #[must_use]
    pub fn export_seed_for_custody(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(
            self.0
                .to_seed()
                .expect("generated/imported ML-KEM keys always retain their seed")
                .as_slice()
                .to_vec(),
        )
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
    use crate::SoftwareSigner;
    use crypto_traits::{KeyRef, Signer};
    use hybrid_pq::{
        envelope::{
            decode_signature, encode_public_key, encode_signature, HybridSignatureEnvelope,
        },
        tbs::{HybridContext, HybridPurpose, HybridTbs},
        HybridKeyRef, HybridPublicKey, HybridSignature, HybridSignatureProfile,
    };

    struct VerificationFixture {
        signature_envelope: Vec<u8>,
        public_key_envelope: Vec<u8>,
        resolved: HybridKeyRef,
        expected: HybridKeyRef,
        context: HybridContext,
        payload: Vec<u8>,
    }

    impl VerificationFixture {
        fn input(&self) -> HybridVerificationInput<'_> {
            HybridVerificationInput {
                signature_envelope: &self.signature_envelope,
                public_key_envelope: &self.public_key_envelope,
                resolved_key_ref: &self.resolved,
                expected_key_ref: &self.expected,
                expected_profile: HybridSignatureProfile::Es256MlDsa65V1,
                expected_purpose: HybridPurpose::WalletExportV1,
                context: &self.context,
                payload: &self.payload,
                expected_audience: None,
                expected_nonce: &self.context.nonce,
                seen_nonces: &[],
                now_epoch_seconds: 1_700_000_010,
                downgrade_attempted: false,
            }
        }
    }

    fn verification_fixture() -> VerificationFixture {
        let profile = HybridSignatureProfile::Es256MlDsa65V1;
        let purpose = HybridPurpose::WalletExportV1;
        let context = HybridContext {
            wallet_identity: b"wallet-key".to_vec(),
            issuer_identity: None,
            key_generation: 7,
            transaction_id: None,
            session_id: None,
            audience: None,
            nonce: (0_u8..16).collect(),
            created_at_epoch_seconds: 1_700_000_000,
            expires_at_epoch_seconds: 1_700_000_100,
            transcript_hash: None,
        };
        let payload = b"export-payload".to_vec();
        let tbs = HybridTbs::build(profile, purpose, &context, &payload).unwrap();
        let classical = SoftwareSigner::generate_p256().unwrap();
        let post_quantum = MlDsa65SecretKey::generate().unwrap();
        let signature = HybridSignature::try_new(
            profile,
            classical
                .sign(&KeyRef("test".into()), Alg::Es256, tbs.as_bytes())
                .unwrap(),
            post_quantum.sign(tbs.as_bytes()).unwrap(),
        )
        .unwrap();
        let public_key = HybridPublicKey::try_new(
            profile,
            classical.public_key_raw().to_vec(),
            post_quantum.public_key(),
        )
        .unwrap();
        VerificationFixture {
            signature_envelope: encode_signature(&HybridSignatureEnvelope::new(purpose, signature)),
            public_key_envelope: encode_public_key(&public_key),
            resolved: HybridKeyRef::try_new("wallet-key".into(), 7).unwrap(),
            expected: HybridKeyRef::try_new("wallet-key".into(), 7).unwrap(),
            context,
            payload,
        }
    }

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

    #[test]
    fn atomic_verifier_succeeds_only_for_both_valid_components() {
        let fixture = verification_fixture();
        verify_hybrid_signature_atomic(&fixture.input()).unwrap();

        for offset in [100_usize, fixture.signature_envelope.len() - 1] {
            let mut corrupted = verification_fixture();
            corrupted.signature_envelope[offset] ^= 1;
            let error = verify_hybrid_signature_atomic(&corrupted.input()).unwrap_err();
            assert_eq!(error.to_string(), "hybrid signature rejected");
            assert!(matches!(
                error.diagnostic_class(),
                HybridErrorClass::VerificationFailure | HybridErrorClass::NonCanonicalInput
            ));
        }
    }

    #[test]
    fn atomic_verifier_rejects_mixed_identity_generation_replay_time_and_downgrade() {
        let mut mixed_identity = verification_fixture();
        mixed_identity.expected = HybridKeyRef::try_new("other-wallet".into(), 7).unwrap();
        assert_eq!(
            verify_hybrid_signature_atomic(&mixed_identity.input())
                .unwrap_err()
                .diagnostic_class(),
            HybridErrorClass::Mismatch
        );

        let fixture = verification_fixture();
        let wrong_generation = HybridKeyRef::try_new("wallet-key".into(), 8).unwrap();
        let mut input = fixture.input();
        input.expected_key_ref = &wrong_generation;
        assert_eq!(
            verify_hybrid_signature_atomic(&input)
                .unwrap_err()
                .diagnostic_class(),
            HybridErrorClass::Mismatch
        );

        let seen = vec![fixture.context.nonce.clone()];
        let mut input = fixture.input();
        input.seen_nonces = &seen;
        assert_eq!(
            verify_hybrid_signature_atomic(&input)
                .unwrap_err()
                .diagnostic_class(),
            HybridErrorClass::PolicyDenied
        );

        let wrong_nonce = vec![9; 16];
        let mut input = fixture.input();
        input.expected_nonce = &wrong_nonce;
        assert_eq!(
            verify_hybrid_signature_atomic(&input)
                .unwrap_err()
                .diagnostic_class(),
            HybridErrorClass::PolicyDenied
        );

        let mut input = fixture.input();
        input.expected_audience = Some(b"unexpected-audience");
        assert_eq!(
            verify_hybrid_signature_atomic(&input)
                .unwrap_err()
                .diagnostic_class(),
            HybridErrorClass::PolicyDenied
        );

        let mut input = fixture.input();
        input.now_epoch_seconds = fixture.context.expires_at_epoch_seconds;
        assert_eq!(
            verify_hybrid_signature_atomic(&input)
                .unwrap_err()
                .diagnostic_class(),
            HybridErrorClass::PolicyDenied
        );

        let mut input = fixture.input();
        input.downgrade_attempted = true;
        assert_eq!(
            verify_hybrid_signature_atomic(&input)
                .unwrap_err()
                .diagnostic_class(),
            HybridErrorClass::DowngradeDetected
        );
    }

    #[test]
    fn atomic_verifier_rejects_missing_unsupported_and_cross_key_components() {
        let mut truncated = verification_fixture();
        truncated.signature_envelope.truncate(40);
        assert_eq!(
            verify_hybrid_signature_atomic(&truncated.input())
                .unwrap_err()
                .diagnostic_class(),
            HybridErrorClass::NonCanonicalInput
        );

        let mut unsupported = verification_fixture();
        let profile = b"euwallet-hybrid-pq-v1";
        let offset = unsupported
            .signature_envelope
            .windows(profile.len())
            .position(|window| window == profile)
            .unwrap();
        unsupported.signature_envelope[offset + profile.len() - 1] = b'2';
        assert_eq!(
            verify_hybrid_signature_atomic(&unsupported.input())
                .unwrap_err()
                .diagnostic_class(),
            HybridErrorClass::UnsupportedProfile
        );

        let mut first = verification_fixture();
        let second = verification_fixture();
        let first_signature = decode_signature(&first.signature_envelope).unwrap();
        let second_signature = decode_signature(&second.signature_envelope).unwrap();
        let mixed = HybridSignature::try_new(
            HybridSignatureProfile::Es256MlDsa65V1,
            first_signature.signature().classical().to_vec(),
            second_signature.signature().post_quantum().to_vec(),
        )
        .unwrap();
        first.signature_envelope = encode_signature(&HybridSignatureEnvelope::new(
            HybridPurpose::WalletExportV1,
            mixed,
        ));
        assert_eq!(
            verify_hybrid_signature_atomic(&first.input())
                .unwrap_err()
                .diagnostic_class(),
            HybridErrorClass::VerificationFailure
        );
    }
}
