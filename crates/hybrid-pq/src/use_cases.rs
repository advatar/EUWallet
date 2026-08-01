//! Policy and artifact boundaries for progressively enabling experimental hybrid-PQ use cases.

use crate::envelope::MAX_ENVELOPE_BYTES;
use crate::{HybridCryptoError, HybridKeyAgreementProfile, HybridKeyRef, HybridSignatureProfile};

pub const LEGACY_EXPORT_VERSION: u16 = 1;
pub const HYBRID_EXPORT_VERSION: u16 = 2;
pub const HYBRID_EXPORT_MAGIC: &[u8] = b"EUWALLET-HYBRID-EXPORT-V2\0";
pub const MAX_HYBRID_EXPORT_CHECKPOINT_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_HYBRID_EXPORT_BYTES: usize = MAX_HYBRID_EXPORT_CHECKPOINT_BYTES + 32 * 1024;
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
    pub wallet_identity: String,
    pub key_generation: u64,
    pub checkpoint_generation: u64,
    pub nonce: Vec<u8>,
    pub created_at_epoch_seconds: u64,
    pub expires_at_epoch_seconds: u64,
    pub checkpoint: Vec<u8>,
    pub checkpoint_digest: [u8; 32],
    pub public_key_envelope: Vec<u8>,
    pub signature_envelope: Vec<u8>,
}

impl HybridWalletExport {
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        wallet_identity: String,
        key_generation: u64,
        checkpoint_generation: u64,
        nonce: Vec<u8>,
        created_at_epoch_seconds: u64,
        expires_at_epoch_seconds: u64,
        checkpoint: Vec<u8>,
        checkpoint_digest: [u8; 32],
        public_key_envelope: Vec<u8>,
        signature_envelope: Vec<u8>,
    ) -> Result<Self, HybridCryptoError> {
        if wallet_identity.is_empty()
            || wallet_identity.len() > HybridKeyRef::MAX_IDENTITY_BYTES
            || key_generation == 0
            || checkpoint_generation == 0
            || !(16..=64).contains(&nonce.len())
            || created_at_epoch_seconds >= expires_at_epoch_seconds
            || checkpoint.is_empty()
            || checkpoint.len() > MAX_HYBRID_EXPORT_CHECKPOINT_BYTES
            || public_key_envelope.is_empty()
            || public_key_envelope.len() > MAX_ENVELOPE_BYTES
            || signature_envelope.is_empty()
            || signature_envelope.len() > MAX_ENVELOPE_BYTES
        {
            return Err(HybridCryptoError::NonCanonicalInput);
        }
        Ok(Self {
            version: HYBRID_EXPORT_VERSION,
            profile: HybridSignatureProfile::Es256MlDsa65V1,
            wallet_identity,
            key_generation,
            checkpoint_generation,
            nonce,
            created_at_epoch_seconds,
            expires_at_epoch_seconds,
            checkpoint,
            checkpoint_digest,
            public_key_envelope,
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

    /// Small canonical payload signed by both algorithms. The complete checkpoint stays in the
    /// artifact and is bound by its length and SHA-256 digest, avoiding a second component-specific
    /// prehash while respecting the frozen 4 KiB TBS payload bound.
    #[must_use]
    pub fn signed_commitment(&self) -> Vec<u8> {
        let mut output = b"EUWALLET-HYBRID-EXPORT-COMMITMENT-V1".to_vec();
        output.extend_from_slice(&self.checkpoint_generation.to_be_bytes());
        output.extend_from_slice(&(self.checkpoint.len() as u64).to_be_bytes());
        output.extend_from_slice(&self.checkpoint_digest);
        output
    }
}

pub fn encode_hybrid_wallet_export(export: &HybridWalletExport) -> Vec<u8> {
    let mut output = Vec::with_capacity(HYBRID_EXPORT_MAGIC.len() + export.checkpoint.len() + 5000);
    output.extend_from_slice(HYBRID_EXPORT_MAGIC);
    output.extend_from_slice(&export.version.to_be_bytes());
    write_export_field(&mut output, export.profile.id().as_bytes());
    write_export_field(&mut output, export.wallet_identity.as_bytes());
    output.extend_from_slice(&export.key_generation.to_be_bytes());
    output.extend_from_slice(&export.checkpoint_generation.to_be_bytes());
    write_export_field(&mut output, &export.nonce);
    output.extend_from_slice(&export.created_at_epoch_seconds.to_be_bytes());
    output.extend_from_slice(&export.expires_at_epoch_seconds.to_be_bytes());
    write_export_field(&mut output, &export.checkpoint);
    output.extend_from_slice(&export.checkpoint_digest);
    write_export_field(&mut output, &export.public_key_envelope);
    write_export_field(&mut output, &export.signature_envelope);
    output
}

pub fn decode_hybrid_wallet_export(input: &[u8]) -> Result<HybridWalletExport, HybridCryptoError> {
    if input.len() > MAX_HYBRID_EXPORT_BYTES || !input.starts_with(HYBRID_EXPORT_MAGIC) {
        return Err(HybridCryptoError::NonCanonicalInput);
    }
    let mut cursor = ExportCursor::new(&input[HYBRID_EXPORT_MAGIC.len()..]);
    let version = cursor.u16()?;
    HybridWalletExport::require_hybrid_version(version)?;
    let profile = core::str::from_utf8(cursor.field(64)?)
        .ok()
        .and_then(|value| HybridSignatureProfile::try_from(value).ok())
        .ok_or(HybridCryptoError::UnsupportedProfile)?;
    let wallet_identity = core::str::from_utf8(cursor.field(HybridKeyRef::MAX_IDENTITY_BYTES)?)
        .map_err(|_| HybridCryptoError::NonCanonicalInput)?
        .to_owned();
    let key_generation = cursor.u64()?;
    let checkpoint_generation = cursor.u64()?;
    let nonce = cursor.field(64)?.to_vec();
    let created_at_epoch_seconds = cursor.u64()?;
    let expires_at_epoch_seconds = cursor.u64()?;
    let checkpoint = cursor.field(MAX_HYBRID_EXPORT_CHECKPOINT_BYTES)?.to_vec();
    let checkpoint_digest: [u8; 32] = cursor
        .fixed(32)?
        .try_into()
        .map_err(|_| HybridCryptoError::NonCanonicalInput)?;
    let public_key_envelope = cursor.field(MAX_ENVELOPE_BYTES)?.to_vec();
    let signature_envelope = cursor.field(MAX_ENVELOPE_BYTES)?.to_vec();
    if !cursor.done() {
        return Err(HybridCryptoError::NonCanonicalInput);
    }
    let export = HybridWalletExport::try_new(
        wallet_identity,
        key_generation,
        checkpoint_generation,
        nonce,
        created_at_epoch_seconds,
        expires_at_epoch_seconds,
        checkpoint,
        checkpoint_digest,
        public_key_envelope,
        signature_envelope,
    )?;
    if export.profile != profile || encode_hybrid_wallet_export(&export) != input {
        return Err(HybridCryptoError::NonCanonicalInput);
    }
    Ok(export)
}

fn write_export_field(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u32).to_be_bytes());
    output.extend_from_slice(value);
}

struct ExportCursor<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> ExportCursor<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }
    fn fixed(&mut self, length: usize) -> Result<&'a [u8], HybridCryptoError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(HybridCryptoError::ResourceLimitExceeded)?;
        let value = self
            .input
            .get(self.offset..end)
            .ok_or(HybridCryptoError::NonCanonicalInput)?;
        self.offset = end;
        Ok(value)
    }
    fn u16(&mut self) -> Result<u16, HybridCryptoError> {
        Ok(u16::from_be_bytes(
            self.fixed(2)?
                .try_into()
                .map_err(|_| HybridCryptoError::NonCanonicalInput)?,
        ))
    }
    fn u64(&mut self) -> Result<u64, HybridCryptoError> {
        Ok(u64::from_be_bytes(
            self.fixed(8)?
                .try_into()
                .map_err(|_| HybridCryptoError::NonCanonicalInput)?,
        ))
    }
    fn field(&mut self, maximum: usize) -> Result<&'a [u8], HybridCryptoError> {
        let length = u32::from_be_bytes(
            self.fixed(4)?
                .try_into()
                .map_err(|_| HybridCryptoError::NonCanonicalInput)?,
        ) as usize;
        if length == 0 || length > maximum {
            return Err(HybridCryptoError::ResourceLimitExceeded);
        }
        self.fixed(length)
    }
    fn done(&self) -> bool {
        self.offset == self.input.len()
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
                || authority.contains('@')
                || authority.contains('\\')
                || authority.chars().any(char::is_whitespace)
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
        let export = HybridWalletExport::try_new(
            "wallet-1".into(),
            2,
            7,
            vec![1; 16],
            100,
            200,
            vec![9, 8, 7],
            [3; 32],
            vec![4],
            vec![5],
        )
        .unwrap();
        assert_eq!(export.version, HYBRID_EXPORT_VERSION);
        let encoded = encode_hybrid_wallet_export(&export);
        assert_eq!(decode_hybrid_wallet_export(&encoded), Ok(export.clone()));
        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            decode_hybrid_wallet_export(&trailing),
            Err(HybridCryptoError::NonCanonicalInput)
        );
        assert!(export
            .signed_commitment()
            .ends_with(&export.checkpoint_digest));
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
            "https://user@provider.example",
            "https://provider.example\\attacker.example",
            "https://provider.example evil",
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
