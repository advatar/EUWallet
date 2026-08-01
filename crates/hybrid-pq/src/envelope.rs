//! Strict deterministic-CBOR envelopes for the private hybrid PQ profile.

use crate::tbs::HybridPurpose;
use crate::{HybridCryptoError, HybridPublicKey, HybridSignature, HybridSignatureProfile};

pub const MAGIC_PREFIX: &[u8] = b"EUWALLET-EXPERIMENTAL-HYBRID-PQ-V1\0";
pub const ENVELOPE_VERSION: u64 = 1;
pub const MAX_ENVELOPE_BYTES: usize = 8 * 1024;
const MAX_TEXT_BYTES: usize = 64;

const KEY_VERSION: u64 = 1;
const KEY_KIND: u64 = 2;
const KEY_PROFILE: u64 = 3;
const KEY_CLASSICAL: u64 = 4;
const KEY_POST_QUANTUM: u64 = 5;
const KEY_PURPOSE: u64 = 6;

const KIND_PUBLIC_KEY: u64 = 1;
const KIND_SIGNATURE: u64 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvelopeError {
    TooLarge,
    BadPrefix,
    Truncated,
    NonCanonical,
    IndefiniteLength,
    DuplicateKey,
    MapKeysNotSorted,
    UnknownField,
    UnsupportedVersion,
    UnsupportedKind,
    UnsupportedProfile,
    UnsupportedPurpose,
    UnsupportedFormat,
    ZeroGeneration,
    EmptyField,
    MissingField,
    UnexpectedField,
    WrongType,
    InvalidUtf8,
    MalformedComponent,
    TrailingBytes,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridSignatureEnvelope {
    purpose: HybridPurpose,
    signature: HybridSignature,
}

impl HybridSignatureEnvelope {
    pub fn new(purpose: HybridPurpose, signature: HybridSignature) -> Self {
        Self { purpose, signature }
    }

    pub fn purpose(&self) -> HybridPurpose {
        self.purpose
    }

    pub fn signature(&self) -> &HybridSignature {
        &self.signature
    }

    pub fn into_signature(self) -> HybridSignature {
        self.signature
    }
}

pub fn encode_public_key(key: &HybridPublicKey) -> Vec<u8> {
    let mut output = Vec::with_capacity(
        MAGIC_PREFIX.len() + key.classical().len() + key.post_quantum().len() + 64,
    );
    output.extend_from_slice(MAGIC_PREFIX);
    write_head(&mut output, 5, 5);
    write_uint_pair(&mut output, KEY_VERSION, ENVELOPE_VERSION);
    write_uint_pair(&mut output, KEY_KIND, KIND_PUBLIC_KEY);
    write_text_pair(&mut output, KEY_PROFILE, key.profile().id());
    write_bytes_pair(&mut output, KEY_CLASSICAL, key.classical());
    write_bytes_pair(&mut output, KEY_POST_QUANTUM, key.post_quantum());
    output
}

pub fn decode_public_key(input: &[u8]) -> Result<HybridPublicKey, EnvelopeError> {
    let parsed = parse(input)?;
    if parsed.kind != KIND_PUBLIC_KEY {
        return Err(EnvelopeError::UnsupportedKind);
    }
    if parsed.purpose.is_some() {
        return Err(EnvelopeError::UnexpectedField);
    }
    HybridPublicKey::try_new(parsed.profile, parsed.classical, parsed.post_quantum)
        .map_err(map_component_error)
}

pub fn encode_signature(envelope: &HybridSignatureEnvelope) -> Vec<u8> {
    let signature = envelope.signature();
    let mut output = Vec::with_capacity(
        MAGIC_PREFIX.len() + signature.classical().len() + signature.post_quantum().len() + 96,
    );
    output.extend_from_slice(MAGIC_PREFIX);
    write_head(&mut output, 5, 6);
    write_uint_pair(&mut output, KEY_VERSION, ENVELOPE_VERSION);
    write_uint_pair(&mut output, KEY_KIND, KIND_SIGNATURE);
    write_text_pair(&mut output, KEY_PROFILE, signature.profile().id());
    write_bytes_pair(&mut output, KEY_CLASSICAL, signature.classical());
    write_bytes_pair(&mut output, KEY_POST_QUANTUM, signature.post_quantum());
    write_text_pair(&mut output, KEY_PURPOSE, envelope.purpose().id());
    output
}

pub fn decode_signature(input: &[u8]) -> Result<HybridSignatureEnvelope, EnvelopeError> {
    let parsed = parse(input)?;
    if parsed.kind != KIND_SIGNATURE {
        return Err(EnvelopeError::UnsupportedKind);
    }
    let purpose = parsed.purpose.ok_or(EnvelopeError::MissingField)?;
    let signature = HybridSignature::try_new(parsed.profile, parsed.classical, parsed.post_quantum)
        .map_err(map_component_error)?;
    Ok(HybridSignatureEnvelope::new(purpose, signature))
}

struct ParsedEnvelope {
    kind: u64,
    profile: HybridSignatureProfile,
    classical: Vec<u8>,
    post_quantum: Vec<u8>,
    purpose: Option<HybridPurpose>,
}

fn parse(input: &[u8]) -> Result<ParsedEnvelope, EnvelopeError> {
    if input.len() > MAX_ENVELOPE_BYTES {
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
    let mut kind = None;
    let mut profile = None;
    let mut classical = None;
    let mut post_quantum = None;
    let mut purpose = None;

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
            KEY_KIND => kind = Some(decoder.read_uint()?),
            KEY_PROFILE => {
                let value = decoder.read_text()?;
                profile = Some(
                    HybridSignatureProfile::try_from(value)
                        .map_err(|_| EnvelopeError::UnsupportedProfile)?,
                );
            }
            KEY_CLASSICAL => classical = Some(decoder.read_bytes()?),
            KEY_POST_QUANTUM => post_quantum = Some(decoder.read_bytes()?),
            KEY_PURPOSE => {
                let value = decoder.read_text()?;
                purpose = Some(
                    HybridPurpose::try_from(value).map_err(|_| EnvelopeError::UnexpectedField)?,
                );
            }
            _ => return Err(EnvelopeError::UnknownField),
        }
    }
    if !decoder.is_finished() {
        return Err(EnvelopeError::TrailingBytes);
    }
    if version.ok_or(EnvelopeError::MissingField)? != ENVELOPE_VERSION {
        return Err(EnvelopeError::UnsupportedVersion);
    }
    Ok(ParsedEnvelope {
        kind: kind.ok_or(EnvelopeError::MissingField)?,
        profile: profile.ok_or(EnvelopeError::MissingField)?,
        classical: classical.ok_or(EnvelopeError::MissingField)?,
        post_quantum: post_quantum.ok_or(EnvelopeError::MissingField)?,
        purpose,
    })
}

fn map_component_error(error: HybridCryptoError) -> EnvelopeError {
    match error {
        HybridCryptoError::ResourceLimitExceeded => EnvelopeError::TooLarge,
        _ => EnvelopeError::MalformedComponent,
    }
}

pub(crate) struct Decoder<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> Decoder<'a> {
    pub(crate) fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    pub(crate) fn is_finished(&self) -> bool {
        self.position == self.input.len()
    }

    pub(crate) fn read_uint(&mut self) -> Result<u64, EnvelopeError> {
        let (major, value) = self.read_head()?;
        if major != 0 {
            return Err(EnvelopeError::WrongType);
        }
        Ok(value)
    }

    pub(crate) fn read_text(&mut self) -> Result<&'a str, EnvelopeError> {
        let bytes = self.read_string(3, MAX_TEXT_BYTES)?;
        std::str::from_utf8(bytes).map_err(|_| EnvelopeError::InvalidUtf8)
    }

    fn read_bytes(&mut self) -> Result<Vec<u8>, EnvelopeError> {
        Ok(self.read_string(2, MAX_ENVELOPE_BYTES)?.to_vec())
    }

    pub(crate) fn read_string(
        &mut self,
        expected_major: u8,
        limit: usize,
    ) -> Result<&'a [u8], EnvelopeError> {
        let (major, length) = self.read_head()?;
        if major != expected_major {
            return Err(EnvelopeError::WrongType);
        }
        let length = usize::try_from(length).map_err(|_| EnvelopeError::TooLarge)?;
        if length > limit {
            return Err(EnvelopeError::TooLarge);
        }
        let end = self
            .position
            .checked_add(length)
            .ok_or(EnvelopeError::TooLarge)?;
        let value = self
            .input
            .get(self.position..end)
            .ok_or(EnvelopeError::Truncated)?;
        self.position = end;
        Ok(value)
    }

    pub(crate) fn read_head(&mut self) -> Result<(u8, u64), EnvelopeError> {
        let first = *self
            .input
            .get(self.position)
            .ok_or(EnvelopeError::Truncated)?;
        self.position += 1;
        let major = first >> 5;
        let info = first & 0x1f;
        let value = match info {
            0..=23 => u64::from(info),
            24 => {
                let value = u64::from(self.take_array::<1>()?[0]);
                if value <= 23 {
                    return Err(EnvelopeError::NonCanonical);
                }
                value
            }
            25 => {
                let value = u64::from(u16::from_be_bytes(self.take_array::<2>()?));
                if value <= u64::from(u8::MAX) {
                    return Err(EnvelopeError::NonCanonical);
                }
                value
            }
            26 => {
                let value = u64::from(u32::from_be_bytes(self.take_array::<4>()?));
                if value <= u64::from(u16::MAX) {
                    return Err(EnvelopeError::NonCanonical);
                }
                value
            }
            27 => {
                let value = u64::from_be_bytes(self.take_array::<8>()?);
                if value <= u64::from(u32::MAX) {
                    return Err(EnvelopeError::NonCanonical);
                }
                value
            }
            31 => return Err(EnvelopeError::IndefiniteLength),
            _ => return Err(EnvelopeError::NonCanonical),
        };
        Ok((major, value))
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], EnvelopeError> {
        let end = self
            .position
            .checked_add(N)
            .ok_or(EnvelopeError::TooLarge)?;
        let bytes = self
            .input
            .get(self.position..end)
            .ok_or(EnvelopeError::Truncated)?;
        self.position = end;
        bytes.try_into().map_err(|_| EnvelopeError::Truncated)
    }
}

pub(crate) fn write_uint_pair(output: &mut Vec<u8>, key: u64, value: u64) {
    write_head(output, 0, key);
    write_head(output, 0, value);
}

pub(crate) fn write_text_pair(output: &mut Vec<u8>, key: u64, value: &str) {
    write_head(output, 0, key);
    write_head(output, 3, value.len() as u64);
    output.extend_from_slice(value.as_bytes());
}

pub(crate) fn write_bytes_pair(output: &mut Vec<u8>, key: u64, value: &[u8]) {
    write_head(output, 0, key);
    write_head(output, 2, value.len() as u64);
    output.extend_from_slice(value);
}

pub(crate) fn write_head(output: &mut Vec<u8>, major: u8, value: u64) {
    let prefix = major << 5;
    if value <= 23 {
        output.push(prefix | value as u8);
    } else if value <= u64::from(u8::MAX) {
        output.extend_from_slice(&[prefix | 24, value as u8]);
    } else if value <= u64::from(u16::MAX) {
        output.push(prefix | 25);
        output.extend_from_slice(&(value as u16).to_be_bytes());
    } else if value <= u64::from(u32::MAX) {
        output.push(prefix | 26);
        output.extend_from_slice(&(value as u32).to_be_bytes());
    } else {
        output.push(prefix | 27);
        output.extend_from_slice(&value.to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ES256_PUBLIC_KEY_BYTES, ES256_SIGNATURE_BYTES, ML_DSA_65_PUBLIC_KEY_BYTES,
        ML_DSA_65_SIGNATURE_BYTES,
    };
    use ciborium::Value;
    use proptest::prelude::*;

    fn public_key(classical_fill: u8, pq_fill: u8) -> HybridPublicKey {
        let mut classical = vec![classical_fill; ES256_PUBLIC_KEY_BYTES];
        classical[0] = 0x04;
        HybridPublicKey::try_new(
            HybridSignatureProfile::Es256MlDsa65V1,
            classical,
            vec![pq_fill; ML_DSA_65_PUBLIC_KEY_BYTES],
        )
        .expect("valid key")
    }

    fn signature(classical_fill: u8, pq_fill: u8) -> HybridSignatureEnvelope {
        HybridSignatureEnvelope::new(
            HybridPurpose::WalletExportV1,
            HybridSignature::try_new(
                HybridSignatureProfile::Es256MlDsa65V1,
                vec![classical_fill; ES256_SIGNATURE_BYTES],
                vec![pq_fill; ML_DSA_65_SIGNATURE_BYTES],
            )
            .expect("valid signature"),
        )
    }

    #[test]
    fn public_key_and_signature_round_trip_atomically() {
        let key = public_key(0x11, 0x22);
        assert_eq!(decode_public_key(&encode_public_key(&key)), Ok(key));

        let signature = signature(0x33, 0x44);
        assert_eq!(
            decode_signature(&encode_signature(&signature)),
            Ok(signature)
        );
    }

    #[test]
    fn independent_cbor_decoder_confirms_the_canonical_maps() {
        let encoded = encode_signature(&signature(0x33, 0x44));
        let value: Value = ciborium::from_reader(&encoded[MAGIC_PREFIX.len()..])
            .expect("ciborium accepts emitted CBOR");
        let Value::Map(fields) = value else {
            panic!("signature envelope must be a map");
        };
        assert_eq!(fields.len(), 6);
        assert_eq!(fields[0].0, Value::Integer(1.into()));
        assert_eq!(fields[5].0, Value::Integer(6.into()));
    }

    #[test]
    fn malformed_encodings_fail_closed() {
        let valid = encode_public_key(&public_key(0x11, 0x22));

        let mut trailing = valid.clone();
        trailing.push(0);
        assert_eq!(
            decode_public_key(&trailing),
            Err(EnvelopeError::TrailingBytes)
        );

        let mut noncanonical = valid.clone();
        let map_start = MAGIC_PREFIX.len();
        noncanonical.splice(map_start + 1..map_start + 2, [0x18, 0x01]);
        assert_eq!(
            decode_public_key(&noncanonical),
            Err(EnvelopeError::NonCanonical)
        );

        let mut indefinite = MAGIC_PREFIX.to_vec();
        indefinite.push(0xbf);
        assert_eq!(
            decode_public_key(&indefinite),
            Err(EnvelopeError::IndefiniteLength)
        );

        let mut truncated = valid;
        truncated.pop();
        assert_eq!(decode_public_key(&truncated), Err(EnvelopeError::Truncated));
    }

    #[test]
    fn duplicate_unsorted_unknown_and_missing_fields_fail_closed() {
        let mut duplicate = MAGIC_PREFIX.to_vec();
        duplicate.extend_from_slice(&[0xa2, 0x01, 0x01, 0x01, 0x01]);
        assert_eq!(
            decode_public_key(&duplicate),
            Err(EnvelopeError::DuplicateKey)
        );

        let mut unsorted = MAGIC_PREFIX.to_vec();
        unsorted.extend_from_slice(&[0xa2, 0x02, 0x01, 0x01, 0x01]);
        assert_eq!(
            decode_public_key(&unsorted),
            Err(EnvelopeError::MapKeysNotSorted)
        );

        let mut unknown = MAGIC_PREFIX.to_vec();
        unknown.extend_from_slice(&[0xa1, 0x07, 0x01]);
        assert_eq!(
            decode_public_key(&unknown),
            Err(EnvelopeError::UnknownField)
        );

        let mut missing = MAGIC_PREFIX.to_vec();
        missing.extend_from_slice(&[0xa2, 0x01, 0x01, 0x02, 0x01]);
        assert_eq!(
            decode_public_key(&missing),
            Err(EnvelopeError::MissingField)
        );
    }

    #[test]
    fn unsupported_version_kind_profile_and_missing_components_fail_closed() {
        let valid = encode_public_key(&public_key(0x11, 0x22));

        let mut version = valid.clone();
        let start = MAGIC_PREFIX.len();
        version[start + 2] = 2;
        assert_eq!(
            decode_public_key(&version),
            Err(EnvelopeError::UnsupportedVersion)
        );

        let mut kind = valid.clone();
        kind[start + 4] = KIND_SIGNATURE as u8;
        assert_eq!(
            decode_public_key(&kind),
            Err(EnvelopeError::UnsupportedKind)
        );

        let profile_offset = valid
            .windows(HybridSignatureProfile::ID.len())
            .position(|window| window == HybridSignatureProfile::ID.as_bytes())
            .expect("profile present");
        let mut profile = valid;
        profile[profile_offset + HybridSignatureProfile::ID.len() - 1] = b'2';
        assert_eq!(
            decode_public_key(&profile),
            Err(EnvelopeError::UnsupportedProfile)
        );
    }

    proptest! {
        #[test]
        fn property_round_trip_is_byte_stable(classical_fill in any::<u8>(), pq_fill in any::<u8>()) {
            let key = public_key(classical_fill, pq_fill);
            let encoded = encode_public_key(&key);
            let decoded = decode_public_key(&encoded).expect("decode emitted key");
            prop_assert_eq!(encode_public_key(&decoded), encoded);

            let signature = signature(classical_fill, pq_fill);
            let encoded = encode_signature(&signature);
            let decoded = decode_signature(&encoded).expect("decode emitted signature");
            prop_assert_eq!(encode_signature(&decoded), encoded);
        }
    }
}
