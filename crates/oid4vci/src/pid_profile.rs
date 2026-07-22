//! PID Rulebook 1.7 portrait profile validation.
//!
//! Presence is mandatory under the current wallet profile. An empty value is the Rulebook's
//! explicit opt-out representation; a non-empty value must be a bounded JPEG in the encoding
//! prescribed for the credential format. Biometric image-quality assessment remains an issuer
//! responsibility and is not inferred from container bytes by the wallet.

use base64ct::{Base64, Encoding};
use mdoc::{cbor::Value as CborValue, IssuerSigned};
use serde_json::{Map, Value};

pub const PID_MDOC_DOCTYPE: &str = "eu.europa.ec.eudi.pid.1";
pub const PID_MDOC_NAMESPACE: &str = "eu.europa.ec.eudi.pid.1";
pub const PID_SD_JWT_VCT: &str = "urn:eudi:pid:1";
pub const MAX_PID_PORTRAIT_BYTES: usize = 2 * 1024 * 1024;
const JPEG_DATA_URL_PREFIX: &str = "data:image/jpeg;base64,";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PidPortraitError {
    Missing,
    Duplicate,
    WrongType,
    TooLarge,
    InvalidDataUrl,
    InvalidJpeg,
}

/// Validate the `picture` claim in the fully processed SD-JWT claims map.
pub fn validate_sd_jwt_pid_portrait(claims: &Map<String, Value>) -> Result<(), PidPortraitError> {
    let picture = claims.get("picture").ok_or(PidPortraitError::Missing)?;
    let picture = picture.as_str().ok_or(PidPortraitError::WrongType)?;
    if picture.is_empty() {
        return Ok(());
    }
    let encoded = picture
        .strip_prefix(JPEG_DATA_URL_PREFIX)
        .ok_or(PidPortraitError::InvalidDataUrl)?;
    if encoded.is_empty() || encoded.len() > encoded_len_limit(MAX_PID_PORTRAIT_BYTES) {
        return Err(PidPortraitError::TooLarge);
    }
    let bytes = Base64::decode_vec(encoded).map_err(|_| PidPortraitError::InvalidDataUrl)?;
    validate_jpeg(&bytes)
}

/// Validate the `portrait` element in an ISO/IEC 18013-5 PID namespace.
pub fn validate_mdoc_pid_portrait(credential: &IssuerSigned) -> Result<(), PidPortraitError> {
    let mut portraits = credential
        .name_spaces
        .iter()
        .filter(|(namespace, _)| namespace.as_str() == PID_MDOC_NAMESPACE)
        .flat_map(|(_, items)| items)
        .filter(|item| item.element_id == "portrait");
    let portrait = portraits.next().ok_or(PidPortraitError::Missing)?;
    if portraits.next().is_some() {
        return Err(PidPortraitError::Duplicate);
    }
    let CborValue::Bytes(bytes) = &portrait.element_value else {
        return Err(PidPortraitError::WrongType);
    };
    if bytes.is_empty() {
        return Ok(());
    }
    validate_jpeg(bytes)
}

fn encoded_len_limit(bytes: usize) -> usize {
    bytes.div_ceil(3) * 4
}

fn validate_jpeg(bytes: &[u8]) -> Result<(), PidPortraitError> {
    if bytes.len() > MAX_PID_PORTRAIT_BYTES {
        return Err(PidPortraitError::TooLarge);
    }
    if bytes.len() < 4 || !bytes.starts_with(&[0xff, 0xd8, 0xff]) || !bytes.ends_with(&[0xff, 0xd9])
    {
        return Err(PidPortraitError::InvalidJpeg);
    }
    Ok(())
}
