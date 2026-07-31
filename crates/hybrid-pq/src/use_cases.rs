//! Policy and artifact boundaries for progressively enabling experimental hybrid-PQ use cases.

use crate::{HybridCryptoError, HybridKeyAgreementProfile, HybridSignatureProfile};

pub const LEGACY_EXPORT_VERSION: u16 = 1;
pub const HYBRID_EXPORT_VERSION: u16 = 2;
pub const HYBRID_RECOVERY_SCHEMA: &str = "euwallet-hybrid-recovery-v1";
pub const EXPERIMENTAL_CATALOGUE_PREFIX: &str = "urn:advatar:experimental:pq:";
const EXPERIMENTAL_PROFILE_PRODUCTION_APPROVED: bool = false;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExperimentalUseCase {
    TestPrimitives,
    HybridWalletExport,
    HybridRecovery,
    PrivateProviderLink,
    ExperimentalCredentials,
    ProductionAdoption,
}

impl ExperimentalUseCase {
    const fn index(self) -> usize {
        match self {
            Self::TestPrimitives => 0,
            Self::HybridWalletExport => 1,
            Self::HybridRecovery => 2,
            Self::PrivateProviderLink => 3,
            Self::ExperimentalCredentials => 4,
            Self::ProductionAdoption => 5,
        }
    }
}

/// Independent, default-off runtime gates. Rolling one slice back does not reinterpret or mutate
/// artifacts created by another slice.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ExperimentalRolloutGates([bool; 6]);

impl ExperimentalRolloutGates {
    #[must_use]
    pub fn is_enabled(&self, use_case: ExperimentalUseCase) -> bool {
        self.0[use_case.index()]
    }

    pub fn enable(&mut self, use_case: ExperimentalUseCase) {
        self.0[use_case.index()] = true;
    }

    pub fn rollback(&mut self, use_case: ExperimentalUseCase) {
        self.0[use_case.index()] = false;
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HybridWalletExport {
    pub version: u16,
    pub profile: HybridSignatureProfile,
    pub payload: Vec<u8>,
    pub signature_envelope: Vec<u8>,
}

impl HybridWalletExport {
    pub fn try_new(
        payload: Vec<u8>,
        signature_envelope: Vec<u8>,
    ) -> Result<Self, HybridCryptoError> {
        if payload.is_empty() || signature_envelope.is_empty() {
            return Err(HybridCryptoError::NonCanonicalInput);
        }
        Ok(Self {
            version: HYBRID_EXPORT_VERSION,
            profile: HybridSignatureProfile::Es256MlDsa65V1,
            payload,
            signature_envelope,
        })
    }

    /// Legacy v1 exports are deliberately outside this codec and remain handled by their existing
    /// reader. No value other than the exact hybrid version is accepted here.
    pub fn require_hybrid_version(version: u16) -> Result<(), HybridCryptoError> {
        if version == HYBRID_EXPORT_VERSION {
            Ok(())
        } else {
            Err(HybridCryptoError::UnsupportedProfile)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HybridRecoveryArtifact {
    pub profile: HybridKeyAgreementProfile,
    pub schema: &'static str,
    pub key_generation: u64,
    pub ciphertext: Vec<u8>,
}

impl HybridRecoveryArtifact {
    pub fn try_new(key_generation: u64, ciphertext: Vec<u8>) -> Result<Self, HybridCryptoError> {
        if key_generation == 0 || ciphertext.is_empty() {
            return Err(HybridCryptoError::NonCanonicalInput);
        }
        Ok(Self {
            profile: HybridKeyAgreementProfile::P256MlKem768V1,
            schema: HYBRID_RECOVERY_SCHEMA,
            key_generation,
            ciphertext,
        })
    }

    /// Exact AAD for the recovery AEAD: profile, schema and generation are length-delimited.
    #[must_use]
    pub fn aad(&self) -> Vec<u8> {
        let mut aad = b"EUWALLET-HYBRID-RECOVERY-AAD-V1".to_vec();
        for field in [
            HybridKeyAgreementProfile::ID.as_bytes(),
            self.schema.as_bytes(),
            &self.key_generation.to_be_bytes(),
        ] {
            aad.extend_from_slice(&(field.len() as u32).to_be_bytes());
            aad.extend_from_slice(field);
        }
        aad
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PrivateProviderPolicy {
    allowed_origins: Vec<String>,
}

impl PrivateProviderPolicy {
    pub fn try_new(allowed_origins: Vec<String>) -> Result<Self, HybridCryptoError> {
        if allowed_origins.iter().any(|origin| {
            let authority = origin.strip_prefix("https://").unwrap_or_default();
            authority.is_empty()
                || authority.contains('/')
                || authority.contains('?')
                || authority.contains('#')
        }) {
            return Err(HybridCryptoError::NonCanonicalInput);
        }
        let mut canonical = allowed_origins;
        canonical.sort();
        canonical.dedup();
        Ok(Self {
            allowed_origins: canonical,
        })
    }

    pub fn authorize(
        &self,
        origin: &str,
        offered_profiles: &[&str],
    ) -> Result<HybridKeyAgreementProfile, HybridCryptoError> {
        if self
            .allowed_origins
            .binary_search_by(|allowed| allowed.as_str().cmp(origin))
            .is_err()
            || offered_profiles != [HybridKeyAgreementProfile::ID]
        {
            return Err(HybridCryptoError::DowngradeDetected);
        }
        Ok(HybridKeyAgreementProfile::P256MlKem768V1)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExperimentalCredentialWrapper {
    namespaced_type: String,
    payload: Vec<u8>,
}

impl ExperimentalCredentialWrapper {
    pub fn try_new(local_type: &str, payload: Vec<u8>) -> Result<Self, HybridCryptoError> {
        if local_type.is_empty()
            || local_type.contains(':')
            || local_type.contains('/')
            || payload.is_empty()
        {
            return Err(HybridCryptoError::NonCanonicalInput);
        }
        Ok(Self {
            namespaced_type: format!("{EXPERIMENTAL_CATALOGUE_PREFIX}{local_type}"),
            payload,
        })
    }

    #[must_use]
    pub fn namespaced_type(&self) -> &str {
        &self.namespaced_type
    }

    /// Experimental wrappers can never satisfy a production catalogue request.
    #[must_use]
    pub const fn satisfies_production_request(&self, _production_type: &str) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProductionApproval {
    pub standards_profile_approved: bool,
    pub cab_profile_approved: bool,
    pub conformance_approved: bool,
}

impl ProductionApproval {
    #[must_use]
    pub const fn adoption_allowed(self) -> bool {
        EXPERIMENTAL_PROFILE_PRODUCTION_APPROVED
            && self.standards_profile_approved
            && self.cab_profile_approved
            && self.conformance_approved
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rollout_gates_are_default_off_independent_and_reversible() {
        let mut gates = ExperimentalRolloutGates::default();
        let slices = [
            ExperimentalUseCase::TestPrimitives,
            ExperimentalUseCase::HybridWalletExport,
            ExperimentalUseCase::HybridRecovery,
            ExperimentalUseCase::PrivateProviderLink,
            ExperimentalUseCase::ExperimentalCredentials,
            ExperimentalUseCase::ProductionAdoption,
        ];
        assert!(slices.iter().all(|slice| !gates.is_enabled(*slice)));
        gates.enable(ExperimentalUseCase::HybridWalletExport);
        assert!(gates.is_enabled(ExperimentalUseCase::HybridWalletExport));
        assert!(!gates.is_enabled(ExperimentalUseCase::HybridRecovery));
        gates.rollback(ExperimentalUseCase::HybridWalletExport);
        assert!(!gates.is_enabled(ExperimentalUseCase::HybridWalletExport));
    }

    #[test]
    fn hybrid_export_has_a_new_exact_version() {
        let export = HybridWalletExport::try_new(vec![1], vec![2]).unwrap();
        assert_eq!(export.version, HYBRID_EXPORT_VERSION);
        HybridWalletExport::require_hybrid_version(HYBRID_EXPORT_VERSION).unwrap();
        assert_eq!(
            HybridWalletExport::require_hybrid_version(LEGACY_EXPORT_VERSION),
            Err(HybridCryptoError::UnsupportedProfile)
        );
    }

    #[test]
    fn recovery_aad_changes_with_generation_and_binds_schema_profile() {
        let first = HybridRecoveryArtifact::try_new(1, vec![9]).unwrap();
        let second = HybridRecoveryArtifact::try_new(2, vec![9]).unwrap();
        assert_ne!(first.aad(), second.aad());
        assert!(first
            .aad()
            .windows(HYBRID_RECOVERY_SCHEMA.len())
            .any(|window| window == HYBRID_RECOVERY_SCHEMA.as_bytes()));
        assert!(first
            .aad()
            .windows(HybridKeyAgreementProfile::ID.len())
            .any(|window| window == HybridKeyAgreementProfile::ID.as_bytes()));
    }

    #[test]
    fn provider_requires_allow_list_and_one_exact_hybrid_offer() {
        for invalid in [
            "http://provider.example",
            "https://provider.example/",
            "https://provider.example/path",
            "https://provider.example?query",
            "https://provider.example#fragment",
        ] {
            assert_eq!(
                PrivateProviderPolicy::try_new(vec![invalid.into()]),
                Err(HybridCryptoError::NonCanonicalInput)
            );
        }
        let policy = PrivateProviderPolicy::try_new(vec![
            "https://provider.example".into(),
            "https://provider.example".into(),
        ])
        .unwrap();
        assert_eq!(
            policy.authorize("https://provider.example", &[HybridKeyAgreementProfile::ID]),
            Ok(HybridKeyAgreementProfile::P256MlKem768V1)
        );
        for (origin, offers) in [
            ("https://other.example", vec![HybridKeyAgreementProfile::ID]),
            ("https://provider.example", vec!["P-256"]),
            (
                "https://provider.example",
                vec![HybridKeyAgreementProfile::ID, "P-256"],
            ),
            ("https://provider.example", vec![]),
        ] {
            assert_eq!(
                policy.authorize(origin, &offers),
                Err(HybridCryptoError::DowngradeDetected)
            );
        }
    }

    #[test]
    fn experimental_credentials_never_match_production_catalogue() {
        let wrapper = ExperimentalCredentialWrapper::try_new("pid", vec![1]).unwrap();
        assert_eq!(wrapper.namespaced_type(), "urn:advatar:experimental:pq:pid");
        assert!(!wrapper.satisfies_production_request("pid"));
        assert!(!wrapper.satisfies_production_request(wrapper.namespaced_type()));
    }

    #[test]
    fn production_adoption_requires_all_external_approvals() {
        assert!(!ProductionApproval::default().adoption_allowed());
        assert!(!ProductionApproval {
            standards_profile_approved: true,
            cab_profile_approved: true,
            conformance_approved: false,
        }
        .adoption_allowed());
        assert!(!ProductionApproval {
            standards_profile_approved: true,
            cab_profile_approved: true,
            conformance_approved: true,
        }
        .adoption_allowed());
    }
}
