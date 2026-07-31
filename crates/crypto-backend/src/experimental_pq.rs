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
    HybridComponent, HybridCryptoError, HybridErrorClass, HybridKeyAgreementProfile,
    HybridKeyAgreementPublicKey, HybridKeyRef, HybridMismatch, HybridSignatureProfile,
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

const HYBRID_KEM_LABEL: &[u8] = b"EUWALLET-UG-P256-MLKEM768-HKDF-SHA256-V1";
const HYBRID_TRAFFIC_INFO: &[u8] = b"EUWALLET-HYBRID-TRAFFIC-KEY-V1";
const MAX_HYBRID_CONTEXT_BYTES: usize = 4_096;

/// Public wire values from one atomic P-256 + ML-KEM-768 encapsulation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridEncapsulation {
    pub profile: HybridKeyAgreementProfile,
    pub sender_identity: String,
    pub recipient_identity: String,
    pub key_generation: u64,
    pub classical_ephemeral_public: Vec<u8>,
    pub post_quantum_ciphertext: Vec<u8>,
    pub transcript_hash: [u8; 32],
}

/// Non-cloneable, zeroizing atomic traffic key. No component secret is observable.
pub struct HybridTrafficKey([u8; 32]);

impl HybridTrafficKey {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for HybridTrafficKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HybridTrafficKey([REDACTED])")
    }
}

impl Drop for HybridTrafficKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Recipient-held component keys. Both are generated together and exposed as one public profile.
pub struct HybridRecipientKey {
    reference: HybridKeyRef,
    classical: crate::P256AgreementKey,
    post_quantum: MlKem768SecretKey,
}

impl HybridRecipientKey {
    pub fn generate(reference: HybridKeyRef) -> Result<Self, HybridCryptoError> {
        let classical = crate::P256AgreementKey::generate().map_err(|_| {
            HybridCryptoError::ComponentFailure {
                component: HybridComponent::Classical,
            }
        })?;
        let post_quantum =
            MlKem768SecretKey::generate().map_err(|_| HybridCryptoError::ComponentFailure {
                component: HybridComponent::PostQuantum,
            })?;
        Ok(Self {
            reference,
            classical,
            post_quantum,
        })
    }

    pub fn public_key(&self) -> Result<HybridKeyAgreementPublicKey, HybridCryptoError> {
        HybridKeyAgreementPublicKey::try_new(
            HybridKeyAgreementProfile::P256MlKem768V1,
            self.classical.public_raw().to_vec(),
            self.post_quantum.public_key(),
        )
    }

    #[must_use]
    pub fn reference(&self) -> &HybridKeyRef {
        &self.reference
    }
}

/// Exact-profile negotiation. Classical-only, absent, duplicated or unknown offers never trigger
/// a fallback, even when the caller would otherwise permit a non-hybrid session.
pub fn negotiate_hybrid_key_agreement(
    offered_profiles: &[&str],
    hybrid_required: bool,
) -> Result<HybridKeyAgreementProfile, HybridCryptoError> {
    let exact = offered_profiles
        .iter()
        .filter(|profile| **profile == HybridKeyAgreementProfile::ID)
        .count();
    if !hybrid_required || exact != 1 || offered_profiles.len() != 1 {
        return Err(HybridCryptoError::DowngradeDetected);
    }
    Ok(HybridKeyAgreementProfile::P256MlKem768V1)
}

/// Sender side: validate the complete recipient profile, run both components, authenticate the
/// transcript, then publish one combined traffic key and both public wire values atomically.
pub fn encapsulate_hybrid_key(
    sender_identity: &str,
    recipient: &HybridKeyRef,
    recipient_public: &HybridKeyAgreementPublicKey,
    context: &[u8],
) -> Result<(HybridEncapsulation, HybridTrafficKey), HybridCryptoError> {
    validate_hybrid_identity(sender_identity)?;
    validate_hybrid_context(context)?;
    if recipient_public.profile() != HybridKeyAgreementProfile::P256MlKem768V1 {
        return Err(HybridCryptoError::UnsupportedProfile);
    }
    use crypto_traits::KeyAgreement;
    let classical = AwsLc
        .ecdh_es_p256(recipient_public.classical())
        .map_err(|_| HybridCryptoError::ComponentFailure {
            component: HybridComponent::Classical,
        })?;
    let (post_quantum_ciphertext, post_quantum_secret) =
        encapsulate_ml_kem_768(recipient_public.post_quantum()).map_err(|_| {
            HybridCryptoError::ComponentFailure {
                component: HybridComponent::PostQuantum,
            }
        })?;
    let classical_secret = Zeroizing::new(classical.shared_secret);
    let transcript_hash = hybrid_transcript_hash(
        sender_identity,
        recipient,
        context,
        recipient_public,
        &classical.ephemeral_public,
        &post_quantum_ciphertext,
    )?;
    let key = hybrid_combiner(
        post_quantum_secret.as_bytes(),
        classical_secret.as_slice(),
        &post_quantum_ciphertext,
        &classical.ephemeral_public,
        recipient_public.post_quantum(),
        recipient_public.classical(),
        &transcript_hash,
    );
    Ok((
        HybridEncapsulation {
            profile: HybridKeyAgreementProfile::P256MlKem768V1,
            sender_identity: sender_identity.into(),
            recipient_identity: recipient.identity().into(),
            key_generation: recipient.generation(),
            classical_ephemeral_public: classical.ephemeral_public,
            post_quantum_ciphertext,
            transcript_hash,
        },
        key,
    ))
}

/// Recipient side. ML-KEM's correctly-sized invalid ciphertext follows FIPS 203 implicit
/// rejection and still reaches the combiner; transcript authentication makes the resulting key
/// differ, so no validity oracle or partial success is returned here.
pub fn decapsulate_hybrid_key(
    recipient: &HybridRecipientKey,
    expected_sender_identity: &str,
    context: &[u8],
    encapsulation: &HybridEncapsulation,
    authenticated_transcript_hash: &[u8; 32],
) -> Result<HybridTrafficKey, HybridCryptoError> {
    validate_hybrid_identity(expected_sender_identity)?;
    validate_hybrid_context(context)?;
    if encapsulation.profile != HybridKeyAgreementProfile::P256MlKem768V1 {
        return Err(HybridCryptoError::UnsupportedProfile);
    }
    if encapsulation.sender_identity != expected_sender_identity
        || encapsulation.recipient_identity != recipient.reference.identity()
    {
        return Err(HybridCryptoError::Mismatch {
            field: HybridMismatch::Identity,
        });
    }
    if encapsulation.key_generation != recipient.reference.generation() {
        return Err(HybridCryptoError::Mismatch {
            field: HybridMismatch::Generation,
        });
    }
    let public = recipient.public_key()?;
    let expected_transcript = hybrid_transcript_hash(
        expected_sender_identity,
        recipient.reference(),
        context,
        &public,
        &encapsulation.classical_ephemeral_public,
        &encapsulation.post_quantum_ciphertext,
    )?;
    if expected_transcript != encapsulation.transcript_hash
        || expected_transcript != *authenticated_transcript_hash
    {
        return Err(HybridCryptoError::DowngradeDetected);
    }
    let classical_secret = Zeroizing::new(
        recipient
            .classical
            .agree(&encapsulation.classical_ephemeral_public)
            .map_err(|_| HybridCryptoError::ComponentFailure {
                component: HybridComponent::Classical,
            })?,
    );
    let post_quantum_secret = recipient
        .post_quantum
        .decapsulate(&encapsulation.post_quantum_ciphertext)
        .map_err(|_| HybridCryptoError::MalformedComponent {
            component: HybridComponent::PostQuantum,
        })?;
    Ok(hybrid_combiner(
        post_quantum_secret.as_bytes(),
        classical_secret.as_slice(),
        &encapsulation.post_quantum_ciphertext,
        &encapsulation.classical_ephemeral_public,
        public.post_quantum(),
        public.classical(),
        &encapsulation.transcript_hash,
    ))
}

fn hybrid_combiner(
    post_quantum_secret: &[u8],
    classical_secret: &[u8],
    post_quantum_ciphertext: &[u8],
    classical_ephemeral: &[u8],
    post_quantum_public: &[u8],
    classical_public: &[u8],
    transcript_hash: &[u8; 32],
) -> HybridTrafficKey {
    use crypto_traits::Kdf;
    let mut universal_input = Zeroizing::new(Vec::with_capacity(2_500));
    universal_input.extend_from_slice(post_quantum_secret);
    universal_input.extend_from_slice(classical_secret);
    universal_input.extend_from_slice(post_quantum_ciphertext);
    universal_input.extend_from_slice(classical_ephemeral);
    universal_input.extend_from_slice(post_quantum_public);
    universal_input.extend_from_slice(classical_public);
    universal_input.extend_from_slice(HYBRID_KEM_LABEL);
    universal_input.extend_from_slice(transcript_hash);
    let combined = Zeroizing::new(AwsLc.hkdf_sha256(
        universal_input.as_slice(),
        HYBRID_KEM_LABEL,
        b"EUWALLET-HYBRID-UNIVERSAL-COMBINER-EXTRACT-V1",
        32,
    ));
    let mut info = Vec::with_capacity(HYBRID_TRAFFIC_INFO.len() + transcript_hash.len());
    info.extend_from_slice(HYBRID_TRAFFIC_INFO);
    info.extend_from_slice(transcript_hash);
    let traffic =
        Zeroizing::new(AwsLc.hkdf_sha256(combined.as_slice(), transcript_hash, &info, 32));
    let mut output = [0_u8; 32];
    output.copy_from_slice(&traffic);
    HybridTrafficKey(output)
}

fn hybrid_transcript_hash(
    sender_identity: &str,
    recipient: &HybridKeyRef,
    context: &[u8],
    recipient_public: &HybridKeyAgreementPublicKey,
    classical_ephemeral: &[u8],
    post_quantum_ciphertext: &[u8],
) -> Result<[u8; 32], HybridCryptoError> {
    use crypto_traits::Digest;
    let mut transcript = Vec::with_capacity(2_500);
    transcript.extend_from_slice(b"EUWALLET-HYBRID-KEM-TRANSCRIPT-V1");
    transcript_field(&mut transcript, HybridKeyAgreementProfile::ID.as_bytes())?;
    transcript_field(&mut transcript, sender_identity.as_bytes())?;
    transcript_field(&mut transcript, recipient.identity().as_bytes())?;
    transcript_field(&mut transcript, &recipient.generation().to_be_bytes())?;
    transcript_field(&mut transcript, context)?;
    transcript_field(&mut transcript, recipient_public.classical())?;
    transcript_field(&mut transcript, recipient_public.post_quantum())?;
    transcript_field(&mut transcript, classical_ephemeral)?;
    transcript_field(&mut transcript, post_quantum_ciphertext)?;
    Ok(AwsLc.sha256(&transcript))
}

fn transcript_field(output: &mut Vec<u8>, value: &[u8]) -> Result<(), HybridCryptoError> {
    let length =
        u32::try_from(value.len()).map_err(|_| HybridCryptoError::ResourceLimitExceeded)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn validate_hybrid_identity(identity: &str) -> Result<(), HybridCryptoError> {
    if identity.is_empty() || identity.len() > HybridKeyRef::MAX_IDENTITY_BYTES {
        return Err(HybridCryptoError::Mismatch {
            field: HybridMismatch::Identity,
        });
    }
    Ok(())
}

fn validate_hybrid_context(context: &[u8]) -> Result<(), HybridCryptoError> {
    if context.is_empty() || context.len() > MAX_HYBRID_CONTEXT_BYTES {
        return Err(HybridCryptoError::NonCanonicalInput);
    }
    Ok(())
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

    fn bytes_hex(value: &[u8]) -> String {
        value.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn hybrid_key_establishment_round_trip_is_atomic() {
        let reference = HybridKeyRef::try_new("wallet-recipient".into(), 7).unwrap();
        let recipient = HybridRecipientKey::generate(reference.clone()).unwrap();
        let public = recipient.public_key().unwrap();
        let (encapsulation, sender_key) = encapsulate_hybrid_key(
            "wallet-sender",
            &reference,
            &public,
            b"authenticated-session-context",
        )
        .unwrap();
        let recipient_key = decapsulate_hybrid_key(
            &recipient,
            "wallet-sender",
            b"authenticated-session-context",
            &encapsulation,
            &encapsulation.transcript_hash,
        )
        .unwrap();

        assert_eq!(sender_key.as_bytes(), recipient_key.as_bytes());
        assert_eq!(format!("{sender_key:?}"), "HybridTrafficKey([REDACTED])");
        assert_eq!(encapsulation.key_generation, 7);
    }

    #[test]
    fn hybrid_negotiation_rejects_every_fallback_shape() {
        let profile = HybridKeyAgreementProfile::ID;
        assert_eq!(
            negotiate_hybrid_key_agreement(&[profile], true),
            Ok(HybridKeyAgreementProfile::P256MlKem768V1)
        );
        for offers in [
            vec![],
            vec!["P-256"],
            vec![profile, "P-256"],
            vec![profile, profile],
            vec!["unknown"],
        ] {
            assert_eq!(
                negotiate_hybrid_key_agreement(&offers, true),
                Err(HybridCryptoError::DowngradeDetected)
            );
        }
        assert_eq!(
            negotiate_hybrid_key_agreement(&[profile], false),
            Err(HybridCryptoError::DowngradeDetected)
        );
    }

    #[test]
    fn authenticated_transcript_binds_context_identity_generation_and_shares() {
        let reference = HybridKeyRef::try_new("wallet-recipient".into(), 3).unwrap();
        let recipient = HybridRecipientKey::generate(reference.clone()).unwrap();
        let (encapsulation, _) = encapsulate_hybrid_key(
            "wallet-sender",
            &reference,
            &recipient.public_key().unwrap(),
            b"session-a",
        )
        .unwrap();
        let authenticated = encapsulation.transcript_hash;

        assert_eq!(
            decapsulate_hybrid_key(
                &recipient,
                "wallet-sender",
                b"session-b",
                &encapsulation,
                &authenticated,
            )
            .unwrap_err(),
            HybridCryptoError::DowngradeDetected
        );

        let mut tampered = encapsulation.clone();
        tampered.post_quantum_ciphertext[0] ^= 1;
        assert_eq!(
            decapsulate_hybrid_key(
                &recipient,
                "wallet-sender",
                b"session-a",
                &tampered,
                &authenticated,
            )
            .unwrap_err(),
            HybridCryptoError::DowngradeDetected
        );

        let mut tampered = encapsulation.clone();
        tampered.classical_ephemeral_public[1] ^= 1;
        assert_eq!(
            decapsulate_hybrid_key(
                &recipient,
                "wallet-sender",
                b"session-a",
                &tampered,
                &authenticated,
            )
            .unwrap_err(),
            HybridCryptoError::DowngradeDetected
        );

        assert!(matches!(
            decapsulate_hybrid_key(
                &recipient,
                "other-sender",
                b"session-a",
                &encapsulation,
                &authenticated,
            ),
            Err(HybridCryptoError::Mismatch {
                field: HybridMismatch::Identity
            })
        ));
    }

    #[test]
    fn pinned_combiner_has_a_deterministic_interop_anchor() {
        let transcript = [7_u8; 32];
        let key = hybrid_combiner(
            &[1_u8; 32],
            &[2_u8; 32],
            &[3_u8; ML_KEM_768_CIPHERTEXT_BYTES],
            &[4_u8; 65],
            &[5_u8; ML_KEM_768_ENCAPSULATION_KEY_BYTES],
            &[6_u8; 65],
            &transcript,
        );
        assert_eq!(
            bytes_hex(key.as_bytes()),
            "3fa0d7cfe4f8857e42bacb9fc2ec2bd88d64ca29b6cd3eb5451cf6953e712ea7"
        );
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
    fn atomic_verifier_covers_the_complete_two_by_two_validity_matrix() {
        for (classical_valid, post_quantum_valid, accepted) in [
            (true, true, true),
            (false, true, false),
            (true, false, false),
            (false, false, false),
        ] {
            let mut fixture = verification_fixture();
            let envelope = decode_signature(&fixture.signature_envelope).unwrap();
            let mut classical = envelope.signature().classical().to_vec();
            let mut post_quantum = envelope.signature().post_quantum().to_vec();
            if !classical_valid {
                classical[0] ^= 1;
            }
            if !post_quantum_valid {
                post_quantum[0] ^= 1;
            }
            fixture.signature_envelope = encode_signature(&HybridSignatureEnvelope::new(
                envelope.purpose(),
                HybridSignature::try_new(
                    HybridSignatureProfile::Es256MlDsa65V1,
                    classical,
                    post_quantum,
                )
                .unwrap(),
            ));
            assert_eq!(
                verify_hybrid_signature_atomic(&fixture.input()).is_ok(),
                accepted,
                "classical_valid={classical_valid}, post_quantum_valid={post_quantum_valid}"
            );
        }
    }

    #[test]
    fn secret_bearing_debug_output_is_redacted() {
        let dsa = MlDsa65SecretKey::generate().unwrap();
        let kem = MlKem768SecretKey::generate().unwrap();
        let (_, shared) = encapsulate_ml_kem_768(&kem.public_key()).unwrap();
        let recipient = HybridRecipientKey::generate(
            HybridKeyRef::try_new("redaction-audit".into(), 1).unwrap(),
        )
        .unwrap();
        let (encapsulation, traffic) = encapsulate_hybrid_key(
            "redaction-sender",
            recipient.reference(),
            &recipient.public_key().unwrap(),
            b"redaction-context",
        )
        .unwrap();

        let debug = format!("{dsa:?} {kem:?} {shared:?} {traffic:?}");
        assert_eq!(debug.matches("[REDACTED]").count(), 4);
        assert!(!debug.contains(&bytes_hex(shared.as_bytes())));
        assert!(!debug.contains(&bytes_hex(traffic.as_bytes())));
        assert!(!debug.contains(&bytes_hex(&encapsulation.post_quantum_ciphertext)));
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
