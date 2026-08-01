//! Frozen `HybridCredentialWrapperV1` container for `euwallet-hybrid-pq-v1`.
//!
//! The wrapper carries an experimental credential payload, its disclosures, both
//! component key identifiers, the logical key generation, and both mandatory
//! signatures in one strict deterministic-CBOR map behind the shared magic
//! prefix. Key identifiers and the generation field are not signed; verifiers
//! must bind them to the trusted logical identity and to the context
//! `key_generation`. The signed TBS payload component is the committed map
//! `{1: payload, 2: [disclosures]}` fed to the frozen `HybridTbsV1`
//! construction.

use crate::envelope::{
    write_bytes_pair, write_head, write_text_pair, write_uint_pair, Decoder, EnvelopeError,
    MAGIC_PREFIX,
};
use crate::tbs::{HybridContext, HybridPurpose, HybridTbs};
use crate::{
    HybridCryptoError, HybridMismatch, HybridPublicKey, HybridSignature, HybridSignatureProfile,
    HybridVerifier, ES256_SIGNATURE_BYTES, ML_DSA_65_SIGNATURE_BYTES,
};

pub const WRAPPER_VERSION: u64 = 1;
pub const CREDENTIAL_FORMAT: &str = "dev-hybrid-pq+cbor";
pub const MAX_WRAPPER_BYTES: usize = 64 * 1024;
pub const MAX_PAYLOAD_BYTES: usize = 4_096;
pub const MAX_COMMITTED_PAYLOAD_BYTES: usize = 4_096;
pub const MAX_KEY_ID_BYTES: usize = 128;

const KEY_VERSION: u64 = 1;
const KEY_PROFILE: u64 = 2;
const KEY_PURPOSE: u64 = 3;
const KEY_FORMAT: u64 = 4;
const KEY_PAYLOAD: u64 = 5;
const KEY_DISCLOSURES: u64 = 6;
const KEY_CLASSICAL_KEY_ID: u64 = 7;
const KEY_PQ_KEY_ID: u64 = 8;
const KEY_GENERATION: u64 = 9;
const KEY_CLASSICAL_SIGNATURE: u64 = 10;
const KEY_POST_QUANTUM_SIGNATURE: u64 = 11;
const WRAPPER_FIELDS: u64 = 11;

/// One frozen experimental credential wrapper. Construction enforces every
/// bound the decoder enforces, so encode/decode round trips are byte-stable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridCredentialWrapper {
    purpose: HybridPurpose,
    payload: Vec<u8>,
    disclosures: Vec<Vec<u8>>,
    classical_key_id: String,
    pq_key_id: String,
    generation: u64,
    signature: HybridSignature,
}

/// Unsigned key-binding expectations a verifier must supply from trusted state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrapperBinding {
    pub classical_key_id: String,
    pub pq_key_id: String,
    pub generation: u64,
}

impl HybridCredentialWrapper {
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        purpose: HybridPurpose,
        payload: Vec<u8>,
        disclosures: Vec<Vec<u8>>,
        classical_key_id: String,
        pq_key_id: String,
        generation: u64,
        signature: HybridSignature,
    ) -> Result<Self, HybridCryptoError> {
        if !is_wrapper_purpose(purpose) {
            return Err(HybridCryptoError::PolicyDenied);
        }
        if payload.is_empty() {
            return Err(HybridCryptoError::NonCanonicalInput);
        }
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(HybridCryptoError::ResourceLimitExceeded);
        }
        for disclosure in &disclosures {
            if disclosure.is_empty() {
                return Err(HybridCryptoError::NonCanonicalInput);
            }
            if disclosure.len() > MAX_PAYLOAD_BYTES {
                return Err(HybridCryptoError::ResourceLimitExceeded);
            }
        }
        validate_key_id(&classical_key_id)?;
        validate_key_id(&pq_key_id)?;
        if generation == 0 {
            return Err(HybridCryptoError::Mismatch {
                field: HybridMismatch::Generation,
            });
        }
        if committed_payload(&payload, &disclosures).len() > MAX_COMMITTED_PAYLOAD_BYTES {
            return Err(HybridCryptoError::ResourceLimitExceeded);
        }
        Ok(Self {
            purpose,
            payload,
            disclosures,
            classical_key_id,
            pq_key_id,
            generation,
            signature,
        })
    }

    pub fn purpose(&self) -> HybridPurpose {
        self.purpose
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn disclosures(&self) -> &[Vec<u8>] {
        &self.disclosures
    }

    pub fn classical_key_id(&self) -> &str {
        &self.classical_key_id
    }

    pub fn pq_key_id(&self) -> &str {
        &self.pq_key_id
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn signature(&self) -> &HybridSignature {
        &self.signature
    }

    /// The exact bytes both component signatures must cover.
    pub fn tbs(&self, context: &HybridContext) -> Result<HybridTbs, HybridCryptoError> {
        HybridTbs::build(
            self.signature.profile(),
            self.purpose,
            context,
            &committed_payload(&self.payload, &self.disclosures),
        )
    }
}

/// The committed canonical-CBOR payload map `{1: payload, 2: [disclosures]}`
/// bound into the TBS, so disclosure mutation fails closed.
pub fn committed_payload(payload: &[u8], disclosures: &[Vec<u8>]) -> Vec<u8> {
    let mut output =
        Vec::with_capacity(payload.len() + disclosures.iter().map(Vec::len).sum::<usize>() + 32);
    write_head(&mut output, 5, 2);
    write_bytes_pair(&mut output, 1, payload);
    write_head(&mut output, 0, 2);
    write_head(&mut output, 4, disclosures.len() as u64);
    for disclosure in disclosures {
        write_head(&mut output, 2, disclosure.len() as u64);
        output.extend_from_slice(disclosure);
    }
    output
}

pub fn encode_credential_wrapper(wrapper: &HybridCredentialWrapper) -> Vec<u8> {
    let signature = wrapper.signature();
    let mut output = Vec::with_capacity(
        MAGIC_PREFIX.len()
            + wrapper.payload().len()
            + signature.classical().len()
            + signature.post_quantum().len()
            + 256,
    );
    output.extend_from_slice(MAGIC_PREFIX);
    write_head(&mut output, 5, WRAPPER_FIELDS);
    write_uint_pair(&mut output, KEY_VERSION, WRAPPER_VERSION);
    write_text_pair(&mut output, KEY_PROFILE, signature.profile().id());
    write_text_pair(&mut output, KEY_PURPOSE, wrapper.purpose().id());
    write_text_pair(&mut output, KEY_FORMAT, CREDENTIAL_FORMAT);
    write_bytes_pair(&mut output, KEY_PAYLOAD, wrapper.payload());
    write_head(&mut output, 0, KEY_DISCLOSURES);
    write_head(&mut output, 4, wrapper.disclosures().len() as u64);
    for disclosure in wrapper.disclosures() {
        write_head(&mut output, 2, disclosure.len() as u64);
        output.extend_from_slice(disclosure);
    }
    write_text_pair(
        &mut output,
        KEY_CLASSICAL_KEY_ID,
        wrapper.classical_key_id(),
    );
    write_text_pair(&mut output, KEY_PQ_KEY_ID, wrapper.pq_key_id());
    write_uint_pair(&mut output, KEY_GENERATION, wrapper.generation());
    write_bytes_pair(&mut output, KEY_CLASSICAL_SIGNATURE, signature.classical());
    write_bytes_pair(
        &mut output,
        KEY_POST_QUANTUM_SIGNATURE,
        signature.post_quantum(),
    );
    output
}

pub fn decode_credential_wrapper(input: &[u8]) -> Result<HybridCredentialWrapper, EnvelopeError> {
    if input.len() > MAX_WRAPPER_BYTES {
        return Err(EnvelopeError::TooLarge);
    }
    let cbor = input
        .strip_prefix(MAGIC_PREFIX)
        .ok_or(EnvelopeError::BadPrefix)?;
    let mut decoder = Decoder::new(cbor);
    let (major, entries) = decoder.read_head()?;
    if major != 5 {
        return Err(EnvelopeError::WrongType);
    }

    let mut previous_key = None;
    let mut version = None;
    let mut profile = None;
    let mut purpose = None;
    let mut format_seen = false;
    let mut payload = None;
    let mut disclosures = None;
    let mut classical_key_id = None;
    let mut pq_key_id = None;
    let mut generation = None;
    let mut classical_signature = None;
    let mut post_quantum_signature = None;

    for _ in 0..entries {
        let key = decoder.read_uint()?;
        if let Some(previous) = previous_key {
            if key == previous {
                return Err(EnvelopeError::DuplicateKey);
            }
            if key < previous {
                return Err(EnvelopeError::MapKeysNotSorted);
            }
        }
        previous_key = Some(key);
        match key {
            KEY_VERSION => version = Some(decoder.read_uint()?),
            KEY_PROFILE => {
                let value = decoder.read_text()?;
                profile = Some(
                    HybridSignatureProfile::try_from(value)
                        .map_err(|_| EnvelopeError::UnsupportedProfile)?,
                );
            }
            KEY_PURPOSE => {
                let value = decoder.read_text()?;
                let parsed = HybridPurpose::try_from(value)
                    .map_err(|_| EnvelopeError::UnsupportedPurpose)?;
                if !is_wrapper_purpose(parsed) {
                    return Err(EnvelopeError::UnsupportedPurpose);
                }
                purpose = Some(parsed);
            }
            KEY_FORMAT => {
                if decoder.read_text()? != CREDENTIAL_FORMAT {
                    return Err(EnvelopeError::UnsupportedFormat);
                }
                format_seen = true;
            }
            KEY_PAYLOAD => {
                let value = decoder.read_string(2, MAX_PAYLOAD_BYTES)?;
                if value.is_empty() {
                    return Err(EnvelopeError::EmptyField);
                }
                payload = Some(value.to_vec());
            }
            KEY_DISCLOSURES => {
                let (major, count) = decoder.read_head()?;
                if major != 4 {
                    return Err(EnvelopeError::WrongType);
                }
                let mut entries = Vec::with_capacity(usize::try_from(count).unwrap_or(0));
                for _ in 0..count {
                    let value = decoder.read_string(2, MAX_PAYLOAD_BYTES)?;
                    if value.is_empty() {
                        return Err(EnvelopeError::EmptyField);
                    }
                    entries.push(value.to_vec());
                }
                disclosures = Some(entries);
            }
            KEY_CLASSICAL_KEY_ID => classical_key_id = Some(read_key_id(&mut decoder)?),
            KEY_PQ_KEY_ID => pq_key_id = Some(read_key_id(&mut decoder)?),
            KEY_GENERATION => {
                let value = decoder.read_uint()?;
                if value == 0 {
                    return Err(EnvelopeError::ZeroGeneration);
                }
                generation = Some(value);
            }
            KEY_CLASSICAL_SIGNATURE => {
                classical_signature = Some(decoder.read_string(2, ES256_SIGNATURE_BYTES)?.to_vec());
            }
            KEY_POST_QUANTUM_SIGNATURE => {
                post_quantum_signature =
                    Some(decoder.read_string(2, ML_DSA_65_SIGNATURE_BYTES)?.to_vec());
            }
            _ => return Err(EnvelopeError::UnknownField),
        }
    }
    if !decoder.is_finished() {
        return Err(EnvelopeError::TrailingBytes);
    }
    if version.ok_or(EnvelopeError::MissingField)? != WRAPPER_VERSION {
        return Err(EnvelopeError::UnsupportedVersion);
    }
    if !format_seen {
        return Err(EnvelopeError::MissingField);
    }
    let profile = profile.ok_or(EnvelopeError::MissingField)?;
    let signature = HybridSignature::try_new(
        profile,
        classical_signature.ok_or(EnvelopeError::MissingField)?,
        post_quantum_signature.ok_or(EnvelopeError::MissingField)?,
    )
    .map_err(|_| EnvelopeError::MalformedComponent)?;
    HybridCredentialWrapper::try_new(
        purpose.ok_or(EnvelopeError::MissingField)?,
        payload.ok_or(EnvelopeError::MissingField)?,
        disclosures.ok_or(EnvelopeError::MissingField)?,
        classical_key_id.ok_or(EnvelopeError::MissingField)?,
        pq_key_id.ok_or(EnvelopeError::MissingField)?,
        generation.ok_or(EnvelopeError::MissingField)?,
        signature,
    )
    .map_err(|error| match error {
        HybridCryptoError::ResourceLimitExceeded => EnvelopeError::TooLarge,
        _ => EnvelopeError::MalformedComponent,
    })
}

/// Atomically verify one decoded wrapper: bind the unsigned key identifiers and
/// generation to trusted expectations and the context, rebuild the committed
/// TBS, and require both component signatures over the identical bytes.
pub fn verify_credential_wrapper<V: HybridVerifier>(
    wrapper: &HybridCredentialWrapper,
    expected_purpose: HybridPurpose,
    binding: &WrapperBinding,
    context: &HybridContext,
    public_key: &HybridPublicKey,
    verifier: &V,
) -> Result<(), HybridCryptoError> {
    if wrapper.purpose() != expected_purpose {
        return Err(HybridCryptoError::PolicyDenied);
    }
    if wrapper.classical_key_id() != binding.classical_key_id
        || wrapper.pq_key_id() != binding.pq_key_id
    {
        return Err(HybridCryptoError::Mismatch {
            field: HybridMismatch::Identity,
        });
    }
    if wrapper.generation() != binding.generation || context.key_generation != binding.generation {
        return Err(HybridCryptoError::Mismatch {
            field: HybridMismatch::Generation,
        });
    }
    let tbs = wrapper.tbs(context)?;
    verifier.verify_hybrid(public_key, &tbs, wrapper.signature())
}

fn is_wrapper_purpose(purpose: HybridPurpose) -> bool {
    matches!(
        purpose,
        HybridPurpose::TestSdJwtWrapperV1 | HybridPurpose::TestMdocWrapperV1
    )
}

fn validate_key_id(value: &str) -> Result<(), HybridCryptoError> {
    if value.is_empty() {
        return Err(HybridCryptoError::NonCanonicalInput);
    }
    if value.len() > MAX_KEY_ID_BYTES {
        return Err(HybridCryptoError::ResourceLimitExceeded);
    }
    Ok(())
}

fn read_key_id(decoder: &mut Decoder<'_>) -> Result<String, EnvelopeError> {
    let bytes = decoder.read_string(3, MAX_KEY_ID_BYTES)?;
    if bytes.is_empty() {
        return Err(EnvelopeError::EmptyField);
    }
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| EnvelopeError::InvalidUtf8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ES256_SIGNATURE_BYTES, ML_DSA_65_SIGNATURE_BYTES};
    use ciborium::Value;
    use proptest::prelude::*;

    fn signature(classical_fill: u8, pq_fill: u8) -> HybridSignature {
        HybridSignature::try_new(
            HybridSignatureProfile::Es256MlDsa65V1,
            vec![classical_fill; ES256_SIGNATURE_BYTES],
            vec![pq_fill; ML_DSA_65_SIGNATURE_BYTES],
        )
        .expect("valid signature components")
    }

    fn wrapper() -> HybridCredentialWrapper {
        HybridCredentialWrapper::try_new(
            HybridPurpose::TestSdJwtWrapperV1,
            b"credential payload".to_vec(),
            vec![b"disclosure one".to_vec(), b"disclosure two".to_vec()],
            "classical-kid".into(),
            "pq-kid".into(),
            9,
            signature(0x33, 0x44),
        )
        .expect("valid wrapper")
    }

    #[test]
    fn round_trip_is_byte_stable() {
        let wrapper = wrapper();
        let encoded = encode_credential_wrapper(&wrapper);
        let decoded = decode_credential_wrapper(&encoded).expect("decode emitted wrapper");
        assert_eq!(decoded, wrapper);
        assert_eq!(encode_credential_wrapper(&decoded), encoded);
    }

    #[test]
    fn independent_cbor_decoder_confirms_the_canonical_map() {
        let encoded = encode_credential_wrapper(&wrapper());
        let value: Value = ciborium::from_reader(&encoded[MAGIC_PREFIX.len()..])
            .expect("ciborium accepts emitted CBOR");
        let Value::Map(fields) = value else {
            panic!("wrapper must be a map");
        };
        assert_eq!(fields.len(), 11);
        for (index, (key, _)) in fields.iter().enumerate() {
            assert_eq!(key, &Value::Integer((index as u64 + 1).into()));
        }
    }

    #[test]
    fn committed_payload_binds_disclosures() {
        let with = committed_payload(b"payload", &[b"disclosure".to_vec()]);
        let without = committed_payload(b"payload", &[]);
        assert_ne!(with, without);
        let value: Value = ciborium::from_reader(with.as_slice()).expect("canonical CBOR");
        let Value::Map(fields) = value else {
            panic!("committed payload must be a map");
        };
        assert_eq!(fields.len(), 2);
    }

    #[test]
    fn construction_bounds_fail_closed() {
        assert_eq!(
            HybridCredentialWrapper::try_new(
                HybridPurpose::WalletExportV1,
                b"payload".to_vec(),
                vec![],
                "classical".into(),
                "pq".into(),
                1,
                signature(0x33, 0x44),
            ),
            Err(HybridCryptoError::PolicyDenied)
        );
        assert_eq!(
            HybridCredentialWrapper::try_new(
                HybridPurpose::TestSdJwtWrapperV1,
                vec![],
                vec![],
                "classical".into(),
                "pq".into(),
                1,
                signature(0x33, 0x44),
            ),
            Err(HybridCryptoError::NonCanonicalInput)
        );
        assert_eq!(
            HybridCredentialWrapper::try_new(
                HybridPurpose::TestSdJwtWrapperV1,
                vec![0; MAX_PAYLOAD_BYTES + 1],
                vec![],
                "classical".into(),
                "pq".into(),
                1,
                signature(0x33, 0x44),
            ),
            Err(HybridCryptoError::ResourceLimitExceeded)
        );
        assert!(matches!(
            HybridCredentialWrapper::try_new(
                HybridPurpose::TestSdJwtWrapperV1,
                b"payload".to_vec(),
                vec![],
                "classical".into(),
                "pq".into(),
                0,
                signature(0x33, 0x44),
            ),
            Err(HybridCryptoError::Mismatch { .. })
        ));
        assert_eq!(
            HybridCredentialWrapper::try_new(
                HybridPurpose::TestSdJwtWrapperV1,
                b"payload".to_vec(),
                vec![],
                "x".repeat(MAX_KEY_ID_BYTES + 1),
                "pq".into(),
                1,
                signature(0x33, 0x44),
            ),
            Err(HybridCryptoError::ResourceLimitExceeded)
        );
    }

    #[test]
    fn malformed_encodings_fail_closed() {
        let valid = encode_credential_wrapper(&wrapper());

        let mut trailing = valid.clone();
        trailing.push(0);
        assert_eq!(
            decode_credential_wrapper(&trailing),
            Err(EnvelopeError::TrailingBytes)
        );

        let mut bad_prefix = valid.clone();
        bad_prefix[0] ^= 1;
        assert_eq!(
            decode_credential_wrapper(&bad_prefix),
            Err(EnvelopeError::BadPrefix)
        );

        let mut noncanonical = valid.clone();
        let map_start = MAGIC_PREFIX.len();
        noncanonical.splice(map_start + 1..map_start + 2, [0x18, 0x01]);
        assert_eq!(
            decode_credential_wrapper(&noncanonical),
            Err(EnvelopeError::NonCanonical)
        );

        let mut indefinite = MAGIC_PREFIX.to_vec();
        indefinite.push(0xbf);
        assert_eq!(
            decode_credential_wrapper(&indefinite),
            Err(EnvelopeError::IndefiniteLength)
        );

        let mut truncated = valid.clone();
        truncated.pop();
        assert_eq!(
            decode_credential_wrapper(&truncated),
            Err(EnvelopeError::Truncated)
        );

        assert_eq!(
            decode_credential_wrapper(&vec![0; MAX_WRAPPER_BYTES + 1]),
            Err(EnvelopeError::TooLarge)
        );
    }

    #[test]
    fn version_profile_purpose_format_and_generation_fail_closed() {
        let valid = encode_credential_wrapper(&wrapper());
        let start = MAGIC_PREFIX.len();

        let mut version = valid.clone();
        version[start + 2] = 2;
        assert_eq!(
            decode_credential_wrapper(&version),
            Err(EnvelopeError::UnsupportedVersion)
        );

        let profile_offset = valid
            .windows(HybridSignatureProfile::ID.len())
            .position(|window| window == HybridSignatureProfile::ID.as_bytes())
            .expect("profile present");
        let mut profile = valid.clone();
        profile[profile_offset + HybridSignatureProfile::ID.len() - 1] = b'2';
        assert_eq!(
            decode_credential_wrapper(&profile),
            Err(EnvelopeError::UnsupportedProfile)
        );

        let purpose_id = HybridPurpose::TestSdJwtWrapperV1.id();
        let purpose_offset = valid
            .windows(purpose_id.len())
            .position(|window| window == purpose_id.as_bytes())
            .expect("purpose present");
        let mut purpose = valid.clone();
        purpose[purpose_offset + purpose_id.len() - 1] = b'2';
        assert_eq!(
            decode_credential_wrapper(&purpose),
            Err(EnvelopeError::UnsupportedPurpose)
        );

        let format_offset = valid
            .windows(CREDENTIAL_FORMAT.len())
            .position(|window| window == CREDENTIAL_FORMAT.as_bytes())
            .expect("format present");
        let mut format = valid.clone();
        format[format_offset] ^= 1;
        assert_eq!(
            decode_credential_wrapper(&format),
            Err(EnvelopeError::UnsupportedFormat)
        );

        let generation_offset = valid
            .windows(2)
            .rposition(|window| window == [0x09, 0x09])
            .expect("generation field present");
        let mut generation = valid.clone();
        generation[generation_offset + 1] = 0;
        assert_eq!(
            decode_credential_wrapper(&generation),
            Err(EnvelopeError::ZeroGeneration)
        );
    }

    #[test]
    fn removed_signature_components_fail_closed() {
        let full = wrapper();
        let encoded = encode_credential_wrapper(&full);
        let map_start = MAGIC_PREFIX.len();

        // Drop the trailing ML-DSA entry (key 11) and shrink the map head.
        let pq_entry = 1 + 3 + full.signature().post_quantum().len();
        let mut classical_only = encoded.clone();
        classical_only.truncate(encoded.len() - pq_entry);
        classical_only[map_start] = 0xaa;
        assert_eq!(
            decode_credential_wrapper(&classical_only),
            Err(EnvelopeError::MissingField)
        );

        // Drop the ES256 entry (key 10) instead.
        let classical_entry = 1 + 2 + full.signature().classical().len();
        let classical_start = encoded.len() - pq_entry - classical_entry;
        let mut pq_only = encoded.clone();
        pq_only.drain(classical_start..classical_start + classical_entry);
        pq_only[map_start] = 0xaa;
        assert_eq!(
            decode_credential_wrapper(&pq_only),
            Err(EnvelopeError::MissingField)
        );
    }

    #[test]
    fn duplicate_unsorted_and_unknown_keys_fail_closed() {
        let mut duplicate = MAGIC_PREFIX.to_vec();
        duplicate.extend_from_slice(&[0xa2, 0x01, 0x01, 0x01, 0x01]);
        assert_eq!(
            decode_credential_wrapper(&duplicate),
            Err(EnvelopeError::DuplicateKey)
        );

        let mut unsorted = MAGIC_PREFIX.to_vec();
        unsorted.extend_from_slice(&[0xa2, 0x09, 0x01, 0x01, 0x01]);
        assert_eq!(
            decode_credential_wrapper(&unsorted),
            Err(EnvelopeError::MapKeysNotSorted)
        );

        let mut unknown = MAGIC_PREFIX.to_vec();
        unknown.extend_from_slice(&[0xa1, 0x0c, 0x01]);
        assert_eq!(
            decode_credential_wrapper(&unknown),
            Err(EnvelopeError::UnknownField)
        );
    }

    proptest! {
        #[test]
        fn property_round_trip_is_byte_stable(
            payload_fill in any::<u8>(),
            generation in 1_u64..=u64::MAX,
        ) {
            let wrapper = HybridCredentialWrapper::try_new(
                HybridPurpose::TestMdocWrapperV1,
                vec![payload_fill.max(1); 24],
                vec![vec![payload_fill.max(1); 8]],
                "classical-kid".into(),
                "pq-kid".into(),
                generation,
                signature(payload_fill, payload_fill.wrapping_add(1)),
            ).expect("valid wrapper");
            let encoded = encode_credential_wrapper(&wrapper);
            let decoded = decode_credential_wrapper(&encoded).expect("decode emitted wrapper");
            prop_assert_eq!(encode_credential_wrapper(&decoded), encoded);
        }
    }
}
