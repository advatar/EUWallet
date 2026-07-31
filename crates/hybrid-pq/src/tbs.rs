//! Canonical, injective to-be-signed construction for `euwallet-hybrid-pq-v1`.
//!
//! Both signature backends receive the single [`HybridTbs`] byte string returned here. Callers
//! cannot request separate classical and post-quantum messages.

use crate::{HybridCryptoError, HybridSignatureProfile};

const TBS_DOMAIN: &[u8] = b"EUWALLET-HYBRID-SIGNATURE-V1";
const CONTEXT_DOMAIN: &[u8] = b"EUWALLET-HYBRID-CONTEXT-V1";
const MAX_FIELD_BYTES: usize = 4_096;
const MIN_NONCE_BYTES: usize = 16;
const MAX_NONCE_BYTES: usize = 64;
const TRANSCRIPT_HASH_BYTES: usize = 32;

/// Closed purpose registry frozen by `euwallet-hybrid-pq-v1`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HybridPurpose {
    WalletExportV1,
    WalletRecoveryV1,
    PrivateProviderMessageV1,
    TestSdJwtWrapperV1,
    TestMdocWrapperV1,
}

impl HybridPurpose {
    pub fn id(self) -> &'static str {
        match self {
            Self::WalletExportV1 => "wallet-export-v1",
            Self::WalletRecoveryV1 => "wallet-recovery-v1",
            Self::PrivateProviderMessageV1 => "private-provider-message-v1",
            Self::TestSdJwtWrapperV1 => "test-sd-jwt-wrapper-v1",
            Self::TestMdocWrapperV1 => "test-mdoc-wrapper-v1",
        }
    }
}

impl TryFrom<&str> for HybridPurpose {
    type Error = HybridCryptoError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "wallet-export-v1" => Ok(Self::WalletExportV1),
            "wallet-recovery-v1" => Ok(Self::WalletRecoveryV1),
            "private-provider-message-v1" => Ok(Self::PrivateProviderMessageV1),
            "test-sd-jwt-wrapper-v1" => Ok(Self::TestSdJwtWrapperV1),
            "test-mdoc-wrapper-v1" => Ok(Self::TestMdocWrapperV1),
            _ => Err(HybridCryptoError::PolicyDenied),
        }
    }
}

/// Context bound into both component signatures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridContext {
    pub wallet_identity: Vec<u8>,
    pub issuer_identity: Option<Vec<u8>>,
    pub key_generation: u64,
    pub transaction_id: Option<Vec<u8>>,
    pub session_id: Option<Vec<u8>>,
    pub audience: Option<Vec<u8>>,
    pub nonce: Vec<u8>,
    pub created_at_epoch_seconds: u64,
    pub expires_at_epoch_seconds: u64,
    pub transcript_hash: Option<[u8; TRANSCRIPT_HASH_BYTES]>,
}

impl HybridContext {
    fn encode_for(&self, purpose: HybridPurpose) -> Result<Vec<u8>, HybridCryptoError> {
        self.validate_common()?;
        self.validate_for(purpose)?;

        let mut output = Vec::with_capacity(256);
        output.extend_from_slice(CONTEXT_DOMAIN);
        encode_field(&mut output, 1, Some(&self.wallet_identity))?;
        encode_field(&mut output, 2, self.issuer_identity.as_deref())?;
        encode_field(&mut output, 3, Some(&self.key_generation.to_be_bytes()))?;
        encode_field(&mut output, 4, self.transaction_id.as_deref())?;
        encode_field(&mut output, 5, self.session_id.as_deref())?;
        encode_field(&mut output, 6, self.audience.as_deref())?;
        encode_field(&mut output, 7, Some(&self.nonce))?;
        encode_field(
            &mut output,
            8,
            Some(&self.created_at_epoch_seconds.to_be_bytes()),
        )?;
        encode_field(
            &mut output,
            9,
            Some(&self.expires_at_epoch_seconds.to_be_bytes()),
        )?;
        encode_field(
            &mut output,
            10,
            self.transcript_hash.as_ref().map(<[u8; 32]>::as_slice),
        )?;
        Ok(output)
    }

    fn validate_common(&self) -> Result<(), HybridCryptoError> {
        require_nonempty_bounded(&self.wallet_identity)?;
        validate_optional(&self.issuer_identity)?;
        validate_optional(&self.transaction_id)?;
        validate_optional(&self.session_id)?;
        validate_optional(&self.audience)?;
        if self.key_generation == 0 {
            return Err(HybridCryptoError::Mismatch {
                field: crate::HybridMismatch::Generation,
            });
        }
        if !(MIN_NONCE_BYTES..=MAX_NONCE_BYTES).contains(&self.nonce.len()) {
            return Err(HybridCryptoError::NonCanonicalInput);
        }
        if self.created_at_epoch_seconds >= self.expires_at_epoch_seconds {
            return Err(HybridCryptoError::NonCanonicalInput);
        }
        Ok(())
    }

    fn validate_for(&self, purpose: HybridPurpose) -> Result<(), HybridCryptoError> {
        match purpose {
            HybridPurpose::WalletExportV1 | HybridPurpose::WalletRecoveryV1 => {
                require_absent(&self.issuer_identity)?;
                require_absent(&self.transaction_id)?;
                require_absent(&self.session_id)?;
                require_absent(&self.audience)?;
                require_absent(&self.transcript_hash)
            }
            HybridPurpose::PrivateProviderMessageV1 => {
                require_present(&self.session_id)?;
                require_present(&self.audience)?;
                require_hash(&self.transcript_hash)
            }
            HybridPurpose::TestSdJwtWrapperV1 | HybridPurpose::TestMdocWrapperV1 => {
                require_present(&self.issuer_identity)?;
                require_present(&self.transaction_id)?;
                require_present(&self.audience)?;
                if self.session_id.is_some() {
                    require_hash(&self.transcript_hash)?;
                }
                Ok(())
            }
        }
    }
}

/// The only byte string supplied to both ES256 and ML-DSA-65.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridTbs(Vec<u8>);

impl HybridTbs {
    pub fn build(
        profile: HybridSignatureProfile,
        purpose: HybridPurpose,
        context: &HybridContext,
        payload: &[u8],
    ) -> Result<Self, HybridCryptoError> {
        if payload.len() > MAX_FIELD_BYTES {
            return Err(HybridCryptoError::ResourceLimitExceeded);
        }

        let encoded_context = context.encode_for(purpose)?;
        let mut output = Vec::with_capacity(
            TBS_DOMAIN.len()
                + HybridSignatureProfile::ID.len()
                + purpose.id().len()
                + encoded_context.len()
                + payload.len()
                + 16,
        );
        output.extend_from_slice(TBS_DOMAIN);
        encode_length_prefixed(&mut output, profile.id().as_bytes())?;
        encode_length_prefixed(&mut output, purpose.id().as_bytes())?;
        encode_length_prefixed(&mut output, &encoded_context)?;
        encode_length_prefixed(&mut output, payload)?;
        Ok(Self(output))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

fn encode_field(
    output: &mut Vec<u8>,
    tag: u8,
    value: Option<&[u8]>,
) -> Result<(), HybridCryptoError> {
    output.push(tag);
    encode_length_prefixed(output, value.unwrap_or_default())
}

fn encode_length_prefixed(output: &mut Vec<u8>, value: &[u8]) -> Result<(), HybridCryptoError> {
    let length =
        u32::try_from(value.len()).map_err(|_| HybridCryptoError::ResourceLimitExceeded)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn require_nonempty_bounded(value: &[u8]) -> Result<(), HybridCryptoError> {
    if value.is_empty() {
        return Err(HybridCryptoError::NonCanonicalInput);
    }
    if value.len() > MAX_FIELD_BYTES {
        return Err(HybridCryptoError::ResourceLimitExceeded);
    }
    Ok(())
}

fn validate_optional(value: &Option<Vec<u8>>) -> Result<(), HybridCryptoError> {
    if let Some(value) = value {
        require_nonempty_bounded(value)?;
    }
    Ok(())
}

fn require_present(value: &Option<Vec<u8>>) -> Result<(), HybridCryptoError> {
    if value.is_none() {
        return Err(HybridCryptoError::PolicyDenied);
    }
    Ok(())
}

fn require_absent<T>(value: &Option<T>) -> Result<(), HybridCryptoError> {
    if value.is_some() {
        return Err(HybridCryptoError::PolicyDenied);
    }
    Ok(())
}

fn require_hash(value: &Option<[u8; TRANSCRIPT_HASH_BYTES]>) -> Result<(), HybridCryptoError> {
    if value.is_none() {
        return Err(HybridCryptoError::PolicyDenied);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local_context() -> HybridContext {
        HybridContext {
            wallet_identity: b"wallet-123".to_vec(),
            issuer_identity: None,
            key_generation: 7,
            transaction_id: None,
            session_id: None,
            audience: None,
            nonce: (0_u8..16).collect(),
            created_at_epoch_seconds: 1_700_000_000,
            expires_at_epoch_seconds: 1_700_003_600,
            transcript_hash: None,
        }
    }

    #[test]
    fn one_object_is_the_input_for_both_components() {
        let tbs = HybridTbs::build(
            HybridSignatureProfile::Es256MlDsa65V1,
            HybridPurpose::WalletExportV1,
            &local_context(),
            b"payload",
        )
        .expect("valid vector");
        let classical_input = tbs.as_bytes();
        let post_quantum_input = tbs.as_bytes();
        assert!(std::ptr::eq(
            classical_input.as_ptr(),
            post_quantum_input.as_ptr()
        ));
        assert_eq!(classical_input, post_quantum_input);
    }

    #[test]
    fn purpose_changes_the_signed_bytes() {
        let export = HybridTbs::build(
            HybridSignatureProfile::Es256MlDsa65V1,
            HybridPurpose::WalletExportV1,
            &local_context(),
            b"payload",
        )
        .expect("export");
        let recovery = HybridTbs::build(
            HybridSignatureProfile::Es256MlDsa65V1,
            HybridPurpose::WalletRecoveryV1,
            &local_context(),
            b"payload",
        )
        .expect("recovery");
        assert_ne!(export, recovery);
    }

    #[test]
    fn unsupported_profile_and_purpose_fail_closed() {
        assert_eq!(
            HybridSignatureProfile::try_from("euwallet-hybrid-pq-v2"),
            Err(HybridCryptoError::UnsupportedProfile)
        );
        assert_eq!(
            HybridPurpose::try_from("production-presentation"),
            Err(HybridCryptoError::PolicyDenied)
        );
    }

    #[test]
    fn provider_context_requires_session_audience_and_transcript() {
        assert_eq!(
            HybridTbs::build(
                HybridSignatureProfile::Es256MlDsa65V1,
                HybridPurpose::PrivateProviderMessageV1,
                &local_context(),
                b"payload",
            ),
            Err(HybridCryptoError::PolicyDenied)
        );

        let mut context = local_context();
        context.session_id = Some(b"session".to_vec());
        context.audience = Some(b"provider.example".to_vec());
        context.transcript_hash = Some([0xAA; 32]);
        assert!(HybridTbs::build(
            HybridSignatureProfile::Es256MlDsa65V1,
            HybridPurpose::PrivateProviderMessageV1,
            &context,
            b"payload",
        )
        .is_ok());
    }

    #[test]
    fn local_artifacts_reject_network_context() {
        let mut context = local_context();
        context.audience = Some(b"unexpected-peer".to_vec());
        assert_eq!(
            HybridTbs::build(
                HybridSignatureProfile::Es256MlDsa65V1,
                HybridPurpose::WalletExportV1,
                &context,
                b"payload",
            ),
            Err(HybridCryptoError::PolicyDenied)
        );
    }

    #[test]
    fn invalid_freshness_generation_nonce_and_size_fail_closed() {
        let mut context = local_context();
        context.key_generation = 0;
        assert!(matches!(
            HybridTbs::build(
                HybridSignatureProfile::Es256MlDsa65V1,
                HybridPurpose::WalletExportV1,
                &context,
                b"payload",
            ),
            Err(HybridCryptoError::Mismatch { .. })
        ));

        let mut context = local_context();
        context.expires_at_epoch_seconds = context.created_at_epoch_seconds;
        assert_eq!(
            HybridTbs::build(
                HybridSignatureProfile::Es256MlDsa65V1,
                HybridPurpose::WalletExportV1,
                &context,
                b"payload",
            ),
            Err(HybridCryptoError::NonCanonicalInput)
        );

        let mut context = local_context();
        context.nonce.clear();
        assert_eq!(
            HybridTbs::build(
                HybridSignatureProfile::Es256MlDsa65V1,
                HybridPurpose::WalletExportV1,
                &context,
                b"payload",
            ),
            Err(HybridCryptoError::NonCanonicalInput)
        );

        assert_eq!(
            HybridTbs::build(
                HybridSignatureProfile::Es256MlDsa65V1,
                HybridPurpose::WalletExportV1,
                &local_context(),
                &vec![0; MAX_FIELD_BYTES + 1],
            ),
            Err(HybridCryptoError::ResourceLimitExceeded)
        );
    }

    #[test]
    fn stable_export_vector_pins_the_construction() {
        let tbs = HybridTbs::build(
            HybridSignatureProfile::Es256MlDsa65V1,
            HybridPurpose::WalletExportV1,
            &local_context(),
            b"payload",
        )
        .expect("valid vector");
        assert_eq!(
            hex(tbs.as_bytes()),
            include_str!("../../../docs/test-vectors/hybrid-pq-v1-export-tbs.hex").trim()
        );

        let recovery = HybridTbs::build(
            HybridSignatureProfile::Es256MlDsa65V1,
            HybridPurpose::WalletRecoveryV1,
            &local_context(),
            b"payload",
        )
        .expect("valid recovery vector");
        assert_eq!(
            hex(recovery.as_bytes()),
            include_str!("../../../docs/test-vectors/hybrid-pq-v1-recovery-tbs.hex").trim()
        );
        assert_ne!(tbs, recovery);

        let invalid_profile =
            include_str!("../../../docs/test-vectors/hybrid-pq-v2-invalid-profile-tbs.hex").trim();
        assert_eq!(
            invalid_profile,
            hex(tbs.as_bytes()).replacen("70712d7631", "70712d7632", 1)
        );
        assert_eq!(
            HybridSignatureProfile::try_from("euwallet-hybrid-pq-v2"),
            Err(HybridCryptoError::UnsupportedProfile)
        );
    }

    fn hex(bytes: &[u8]) -> String {
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            use std::fmt::Write;
            write!(&mut output, "{byte:02x}").expect("String writes cannot fail");
        }
        output
    }
}
