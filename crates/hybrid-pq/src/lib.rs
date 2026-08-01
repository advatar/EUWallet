#![forbid(unsafe_code)]
//! Isolated interfaces for the private `euwallet-hybrid-pq-v1` experiment.
//!
//! This crate deliberately does not extend `crypto_traits::Alg`, implement JOSE/COSE conversions,
//! or provide cryptographic primitives. Protocol codecs and primitives arrive behind later review
//! gates.
//!
//! Certified algorithms and experimental profiles are different types:
//!
//! ```compile_fail
//! use crypto_traits::Alg;
//! use hybrid_pq::HybridSignatureProfile;
//!
//! fn certified_algorithm(_: Alg) {}
//! certified_algorithm(HybridSignatureProfile::Es256MlDsa65V1);
//! ```
//!
//! Experimental public keys likewise cannot be passed as certified algorithms:
//!
//! ```compile_fail
//! use crypto_traits::Alg;
//! use hybrid_pq::{HybridPublicKey, HybridSignatureProfile};
//!
//! let key = HybridPublicKey::try_new(
//!     HybridSignatureProfile::Es256MlDsa65V1,
//!     vec![0; 65],
//!     vec![0; 1_952],
//! )?;
//! let _: Alg = key;
//! # Ok::<(), hybrid_pq::HybridCryptoError>(())
//! ```

use std::fmt;

pub mod envelope;
pub mod rollout;
pub mod tbs;
pub mod use_cases;
pub mod wrapper;

/// Exact public component sizes frozen by `euwallet-hybrid-pq-v1`.
pub const ES256_PUBLIC_KEY_BYTES: usize = 65;
pub const ES256_SIGNATURE_BYTES: usize = 64;
pub const ML_DSA_65_PUBLIC_KEY_BYTES: usize = 1_952;
pub const ML_DSA_65_SIGNATURE_BYTES: usize = 3_309;
pub const P256_PUBLIC_SHARE_BYTES: usize = 65;
pub const ML_KEM_768_ENCAPSULATION_KEY_BYTES: usize = 1_184;
pub const ML_KEM_768_CIPHERTEXT_BYTES: usize = 1_088;
pub const HYBRID_SHARED_SECRET_BYTES: usize = 32;

/// Closed experimental signature-profile registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HybridSignatureProfile {
    Es256MlDsa65V1,
}

impl HybridSignatureProfile {
    pub const ID: &'static str = "euwallet-hybrid-pq-v1";

    pub fn id(self) -> &'static str {
        match self {
            Self::Es256MlDsa65V1 => Self::ID,
        }
    }
}

impl TryFrom<&str> for HybridSignatureProfile {
    type Error = HybridCryptoError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            Self::ID => Ok(Self::Es256MlDsa65V1),
            _ => Err(HybridCryptoError::UnsupportedProfile),
        }
    }
}

/// Closed experimental key-establishment-profile registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HybridKeyAgreementProfile {
    P256MlKem768V1,
}

impl HybridKeyAgreementProfile {
    pub const ID: &'static str = "euwallet-hybrid-pq-v1";

    pub fn id(self) -> &'static str {
        match self {
            Self::P256MlKem768V1 => Self::ID,
        }
    }
}

impl TryFrom<&str> for HybridKeyAgreementProfile {
    type Error = HybridCryptoError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            Self::ID => Ok(Self::P256MlKem768V1),
            _ => Err(HybridCryptoError::UnsupportedProfile),
        }
    }
}

/// One half of a hybrid construction, used in non-secret failure classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HybridComponent {
    Classical,
    PostQuantum,
}

/// Fields that must agree across both component keys and the selected operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HybridMismatch {
    Profile,
    Identity,
    Generation,
}

/// Stable error classes exposed by the experimental trait boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HybridErrorClass {
    UnsupportedProfile,
    MalformedComponent,
    ComponentFailure,
    VerificationFailure,
    Mismatch,
    NonCanonicalInput,
    ResourceLimitExceeded,
    DowngradeDetected,
    PolicyDenied,
    BackendFailure,
}

/// Typed, deliberately low-detail failures. Backends must not attach key material, payloads or
/// decapsulation-oracle detail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HybridCryptoError {
    UnsupportedProfile,
    MalformedComponent { component: HybridComponent },
    ComponentFailure { component: HybridComponent },
    VerificationFailure { component: HybridComponent },
    Mismatch { field: HybridMismatch },
    NonCanonicalInput,
    ResourceLimitExceeded,
    DowngradeDetected,
    PolicyDenied,
    BackendFailure,
}

impl HybridCryptoError {
    pub fn class(&self) -> HybridErrorClass {
        match self {
            Self::UnsupportedProfile => HybridErrorClass::UnsupportedProfile,
            Self::MalformedComponent { .. } => HybridErrorClass::MalformedComponent,
            Self::ComponentFailure { .. } => HybridErrorClass::ComponentFailure,
            Self::VerificationFailure { .. } => HybridErrorClass::VerificationFailure,
            Self::Mismatch { .. } => HybridErrorClass::Mismatch,
            Self::NonCanonicalInput => HybridErrorClass::NonCanonicalInput,
            Self::ResourceLimitExceeded => HybridErrorClass::ResourceLimitExceeded,
            Self::DowngradeDetected => HybridErrorClass::DowngradeDetected,
            Self::PolicyDenied => HybridErrorClass::PolicyDenied,
            Self::BackendFailure => HybridErrorClass::BackendFailure,
        }
    }
}

impl fmt::Display for HybridCryptoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.class() {
            HybridErrorClass::UnsupportedProfile => "unsupported hybrid profile",
            HybridErrorClass::MalformedComponent => "malformed hybrid component",
            HybridErrorClass::ComponentFailure => "hybrid component operation failed",
            HybridErrorClass::VerificationFailure => "hybrid verification failed",
            HybridErrorClass::Mismatch => "hybrid key binding mismatch",
            HybridErrorClass::NonCanonicalInput => "non-canonical hybrid input",
            HybridErrorClass::ResourceLimitExceeded => "hybrid resource limit exceeded",
            HybridErrorClass::DowngradeDetected => "hybrid downgrade detected",
            HybridErrorClass::PolicyDenied => "hybrid operation denied by policy",
            HybridErrorClass::BackendFailure => "hybrid backend failure",
        })
    }
}

impl std::error::Error for HybridCryptoError {}

/// Public keys forming one atomic hybrid verification identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridPublicKey {
    profile: HybridSignatureProfile,
    classical: Vec<u8>,
    post_quantum: Vec<u8>,
}

impl HybridPublicKey {
    pub fn try_new(
        profile: HybridSignatureProfile,
        classical: Vec<u8>,
        post_quantum: Vec<u8>,
    ) -> Result<Self, HybridCryptoError> {
        require_len(
            &classical,
            ES256_PUBLIC_KEY_BYTES,
            HybridComponent::Classical,
        )?;
        if classical[0] != 0x04 {
            return Err(HybridCryptoError::MalformedComponent {
                component: HybridComponent::Classical,
            });
        }
        require_len(
            &post_quantum,
            ML_DSA_65_PUBLIC_KEY_BYTES,
            HybridComponent::PostQuantum,
        )?;
        Ok(Self {
            profile,
            classical,
            post_quantum,
        })
    }

    pub fn profile(&self) -> HybridSignatureProfile {
        self.profile
    }

    pub fn classical(&self) -> &[u8] {
        &self.classical
    }

    pub fn post_quantum(&self) -> &[u8] {
        &self.post_quantum
    }
}

/// Both mandatory signatures over one common domain-separated message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridSignature {
    profile: HybridSignatureProfile,
    classical: Vec<u8>,
    post_quantum: Vec<u8>,
}

impl HybridSignature {
    pub fn try_new(
        profile: HybridSignatureProfile,
        classical: Vec<u8>,
        post_quantum: Vec<u8>,
    ) -> Result<Self, HybridCryptoError> {
        require_len(
            &classical,
            ES256_SIGNATURE_BYTES,
            HybridComponent::Classical,
        )?;
        require_len(
            &post_quantum,
            ML_DSA_65_SIGNATURE_BYTES,
            HybridComponent::PostQuantum,
        )?;
        Ok(Self {
            profile,
            classical,
            post_quantum,
        })
    }

    pub fn profile(&self) -> HybridSignatureProfile {
        self.profile
    }

    pub fn classical(&self) -> &[u8] {
        &self.classical
    }

    pub fn post_quantum(&self) -> &[u8] {
        &self.post_quantum
    }
}

/// Opaque reference to two component keys bound to one logical identity and generation.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HybridKeyRef {
    identity: String,
    generation: u64,
}

impl HybridKeyRef {
    pub const MAX_IDENTITY_BYTES: usize = 128;

    pub fn try_new(identity: String, generation: u64) -> Result<Self, HybridCryptoError> {
        if identity.is_empty() {
            return Err(HybridCryptoError::MalformedComponent {
                component: HybridComponent::Classical,
            });
        }
        if identity.len() > Self::MAX_IDENTITY_BYTES {
            return Err(HybridCryptoError::ResourceLimitExceeded);
        }
        if generation == 0 {
            return Err(HybridCryptoError::Mismatch {
                field: HybridMismatch::Generation,
            });
        }
        Ok(Self {
            identity,
            generation,
        })
    }

    pub fn identity(&self) -> &str {
        &self.identity
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }
}

/// Public shares offered for one hybrid key establishment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridKeyAgreementPublicKey {
    profile: HybridKeyAgreementProfile,
    classical: Vec<u8>,
    post_quantum: Vec<u8>,
}

impl HybridKeyAgreementPublicKey {
    pub fn try_new(
        profile: HybridKeyAgreementProfile,
        classical: Vec<u8>,
        post_quantum: Vec<u8>,
    ) -> Result<Self, HybridCryptoError> {
        require_len(
            &classical,
            P256_PUBLIC_SHARE_BYTES,
            HybridComponent::Classical,
        )?;
        if classical[0] != 0x04 {
            return Err(HybridCryptoError::MalformedComponent {
                component: HybridComponent::Classical,
            });
        }
        require_len(
            &post_quantum,
            ML_KEM_768_ENCAPSULATION_KEY_BYTES,
            HybridComponent::PostQuantum,
        )?;
        Ok(Self {
            profile,
            classical,
            post_quantum,
        })
    }

    pub fn profile(&self) -> HybridKeyAgreementProfile {
        self.profile
    }

    pub fn classical(&self) -> &[u8] {
        &self.classical
    }

    pub fn post_quantum(&self) -> &[u8] {
        &self.post_quantum
    }
}

/// Atomic result of hybrid key establishment. Implementations must not publish this until both
/// components and the reviewed combiner have succeeded.
#[derive(PartialEq, Eq)]
pub struct HybridKeyAgreementResult {
    classical_public_share: Vec<u8>,
    post_quantum_ciphertext: Vec<u8>,
    shared_secret: Vec<u8>,
}

impl core::fmt::Debug for HybridKeyAgreementResult {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("HybridKeyAgreementResult")
            .field("classical_public_share", &self.classical_public_share)
            .field("post_quantum_ciphertext", &self.post_quantum_ciphertext)
            .field("shared_secret", &"[REDACTED]")
            .finish()
    }
}

impl Drop for HybridKeyAgreementResult {
    fn drop(&mut self) {
        self.shared_secret.fill(0);
    }
}

impl HybridKeyAgreementResult {
    pub fn try_new(
        classical_public_share: Vec<u8>,
        post_quantum_ciphertext: Vec<u8>,
        shared_secret: Vec<u8>,
    ) -> Result<Self, HybridCryptoError> {
        require_len(
            &classical_public_share,
            P256_PUBLIC_SHARE_BYTES,
            HybridComponent::Classical,
        )?;
        if classical_public_share[0] != 0x04 {
            return Err(HybridCryptoError::MalformedComponent {
                component: HybridComponent::Classical,
            });
        }
        require_len(
            &post_quantum_ciphertext,
            ML_KEM_768_CIPHERTEXT_BYTES,
            HybridComponent::PostQuantum,
        )?;
        require_len(
            &shared_secret,
            HYBRID_SHARED_SECRET_BYTES,
            HybridComponent::PostQuantum,
        )?;
        Ok(Self {
            classical_public_share,
            post_quantum_ciphertext,
            shared_secret,
        })
    }

    pub fn classical_public_share(&self) -> &[u8] {
        &self.classical_public_share
    }

    pub fn post_quantum_ciphertext(&self) -> &[u8] {
        &self.post_quantum_ciphertext
    }

    pub fn shared_secret(&self) -> &[u8] {
        &self.shared_secret
    }
}

/// Produce one atomic hybrid signature over caller-supplied, already domain-separated bytes.
pub trait HybridSigner {
    fn sign_hybrid(
        &self,
        key: &HybridKeyRef,
        profile: HybridSignatureProfile,
        hybrid_tbs: &tbs::HybridTbs,
    ) -> Result<HybridSignature, HybridCryptoError>;
}

/// Verify both mandatory components against the same caller-supplied bytes.
pub trait HybridVerifier {
    fn verify_hybrid(
        &self,
        key: &HybridPublicKey,
        hybrid_tbs: &tbs::HybridTbs,
        signature: &HybridSignature,
    ) -> Result<(), HybridCryptoError>;
}

/// Perform the reviewed, transcript-bound hybrid key-establishment operation.
pub trait HybridKeyAgreement {
    fn establish_hybrid(
        &self,
        key: &HybridKeyRef,
        peer: &HybridKeyAgreementPublicKey,
        authenticated_transcript: &[u8],
    ) -> Result<HybridKeyAgreementResult, HybridCryptoError>;
}

fn require_len(
    value: &[u8],
    expected: usize,
    component: HybridComponent,
) -> Result<(), HybridCryptoError> {
    if value.len() != expected {
        return Err(HybridCryptoError::MalformedComponent { component });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classical_public_key() -> Vec<u8> {
        let mut key = vec![0; ES256_PUBLIC_KEY_BYTES];
        key[0] = 0x04;
        key
    }

    #[test]
    fn parses_only_the_frozen_profile() {
        assert_eq!(
            HybridSignatureProfile::try_from("euwallet-hybrid-pq-v1"),
            Ok(HybridSignatureProfile::Es256MlDsa65V1)
        );
        assert_eq!(
            HybridSignatureProfile::try_from("euwallet-hybrid-pq-v2"),
            Err(HybridCryptoError::UnsupportedProfile)
        );
    }

    #[test]
    fn public_key_requires_both_exact_components() {
        let valid = HybridPublicKey::try_new(
            HybridSignatureProfile::Es256MlDsa65V1,
            classical_public_key(),
            vec![0; ML_DSA_65_PUBLIC_KEY_BYTES],
        )
        .expect("valid fixed-size components");
        assert_eq!(valid.classical().len(), ES256_PUBLIC_KEY_BYTES);
        assert_eq!(valid.post_quantum().len(), ML_DSA_65_PUBLIC_KEY_BYTES);

        assert_eq!(
            HybridPublicKey::try_new(
                HybridSignatureProfile::Es256MlDsa65V1,
                vec![0; ES256_PUBLIC_KEY_BYTES],
                vec![0; ML_DSA_65_PUBLIC_KEY_BYTES],
            ),
            Err(HybridCryptoError::MalformedComponent {
                component: HybridComponent::Classical
            })
        );
        assert_eq!(
            HybridPublicKey::try_new(
                HybridSignatureProfile::Es256MlDsa65V1,
                classical_public_key(),
                vec![],
            ),
            Err(HybridCryptoError::MalformedComponent {
                component: HybridComponent::PostQuantum
            })
        );
    }

    #[test]
    fn signature_requires_both_exact_components() {
        let valid = HybridSignature::try_new(
            HybridSignatureProfile::Es256MlDsa65V1,
            vec![0; ES256_SIGNATURE_BYTES],
            vec![0; ML_DSA_65_SIGNATURE_BYTES],
        )
        .expect("valid fixed-size components");
        assert_eq!(valid.classical().len(), ES256_SIGNATURE_BYTES);
        assert_eq!(valid.post_quantum().len(), ML_DSA_65_SIGNATURE_BYTES);

        assert_eq!(
            HybridSignature::try_new(
                HybridSignatureProfile::Es256MlDsa65V1,
                vec![],
                vec![0; ML_DSA_65_SIGNATURE_BYTES],
            ),
            Err(HybridCryptoError::MalformedComponent {
                component: HybridComponent::Classical
            })
        );
    }

    #[test]
    fn key_reference_binds_identity_and_nonzero_generation() {
        let key = HybridKeyRef::try_new("wallet-key".into(), 7).expect("valid key reference");
        assert_eq!(key.identity(), "wallet-key");
        assert_eq!(key.generation(), 7);
        assert_eq!(
            HybridKeyRef::try_new("wallet-key".into(), 0),
            Err(HybridCryptoError::Mismatch {
                field: HybridMismatch::Generation
            })
        );
        assert_eq!(
            HybridKeyRef::try_new("x".repeat(HybridKeyRef::MAX_IDENTITY_BYTES + 1), 1),
            Err(HybridCryptoError::ResourceLimitExceeded)
        );
    }

    #[test]
    fn key_agreement_values_require_atomic_fixed_size_components() {
        let peer = HybridKeyAgreementPublicKey::try_new(
            HybridKeyAgreementProfile::P256MlKem768V1,
            classical_public_key(),
            vec![0; ML_KEM_768_ENCAPSULATION_KEY_BYTES],
        )
        .expect("valid peer shares");
        assert_eq!(
            peer.post_quantum().len(),
            ML_KEM_768_ENCAPSULATION_KEY_BYTES
        );

        let result = HybridKeyAgreementResult::try_new(
            classical_public_key(),
            vec![0; ML_KEM_768_CIPHERTEXT_BYTES],
            vec![0; HYBRID_SHARED_SECRET_BYTES],
        )
        .expect("valid atomic result");
        assert_eq!(result.shared_secret().len(), HYBRID_SHARED_SECRET_BYTES);
    }

    #[test]
    fn every_error_class_is_typed_and_stable() {
        let cases = [
            (
                HybridCryptoError::UnsupportedProfile,
                HybridErrorClass::UnsupportedProfile,
            ),
            (
                HybridCryptoError::MalformedComponent {
                    component: HybridComponent::Classical,
                },
                HybridErrorClass::MalformedComponent,
            ),
            (
                HybridCryptoError::ComponentFailure {
                    component: HybridComponent::PostQuantum,
                },
                HybridErrorClass::ComponentFailure,
            ),
            (
                HybridCryptoError::VerificationFailure {
                    component: HybridComponent::Classical,
                },
                HybridErrorClass::VerificationFailure,
            ),
            (
                HybridCryptoError::Mismatch {
                    field: HybridMismatch::Identity,
                },
                HybridErrorClass::Mismatch,
            ),
            (
                HybridCryptoError::NonCanonicalInput,
                HybridErrorClass::NonCanonicalInput,
            ),
            (
                HybridCryptoError::ResourceLimitExceeded,
                HybridErrorClass::ResourceLimitExceeded,
            ),
            (
                HybridCryptoError::DowngradeDetected,
                HybridErrorClass::DowngradeDetected,
            ),
            (
                HybridCryptoError::PolicyDenied,
                HybridErrorClass::PolicyDenied,
            ),
            (
                HybridCryptoError::BackendFailure,
                HybridErrorClass::BackendFailure,
            ),
        ];

        for (error, class) in cases {
            assert_eq!(error.class(), class);
            assert!(!error.to_string().is_empty());
        }
    }
}
