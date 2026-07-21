//! ARF cross-attestation binding for issuing an attestation bound to an existing PID.

use base64ct::{Base64UrlUnpadded, Encoding};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

pub const PID_VCT: &str = "eu.europa.ec.eudi.pid.1";
const MAX_PID_VP_BYTES: usize = 32_768;
const MAX_JWT_BYTES: usize = 8_192;
const MAX_REQUEST_BYTES: usize = 48_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PidBindingPolicy {
    NotRequired,
    Required { pid_vct: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PidBindingError {
    InvalidMetadata,
    UnsupportedPolicy,
    InvalidInput,
    InvalidCredential,
    MissingBinding,
    UnexpectedBinding,
}

pub fn parse_pid_binding_policy(
    configuration: &Value,
) -> Result<PidBindingPolicy, PidBindingError> {
    let Some(binding) = configuration.get("pid_binding") else {
        return Ok(PidBindingPolicy::NotRequired);
    };
    let binding = binding
        .as_object()
        .ok_or(PidBindingError::InvalidMetadata)?;
    match binding.get("required").and_then(Value::as_bool) {
        Some(false) if binding.len() == 1 => Ok(PidBindingPolicy::NotRequired),
        Some(true)
            if binding.get("pid_vct").and_then(Value::as_str) == Some(PID_VCT)
                && binding.get("presentation_format").and_then(Value::as_str)
                    == Some("dc+sd-jwt")
                && binding
                    .get("binding_proof_alg_values_supported")
                    .and_then(Value::as_array)
                    .is_some_and(|values| values.iter().any(|value| value == "ES256")) =>
        {
            Ok(PidBindingPolicy::Required {
                pid_vct: PID_VCT.to_owned(),
            })
        }
        Some(true) => Err(PidBindingError::UnsupportedPolicy),
        _ => Err(PidBindingError::InvalidMetadata),
    }
}

/// Returns the exact input that must be signed by the existing PID holder key.
pub fn pid_binding_proof_signing_input(
    issuer: &str,
    nonce: &str,
    jti: &str,
    iat: i64,
    pid_issuer_jwt: &str,
    new_holder_jkt: &str,
) -> Result<String, PidBindingError> {
    if !issuer.starts_with("https://")
        || nonce.is_empty()
        || nonce.len() > 256
        || jti.is_empty()
        || jti.len() > 256
        || pid_issuer_jwt.is_empty()
        || pid_issuer_jwt.len() > MAX_PID_VP_BYTES
        || new_holder_jkt.is_empty()
        || new_holder_jkt.len() > 256
    {
        return Err(PidBindingError::InvalidInput);
    }
    let header = json!({"alg":"ES256", "typ":"eudi-pid-binding+jwt"});
    let payload = json!({
        "aud": issuer,
        "iat": iat,
        "nonce": nonce,
        "jti": jti,
        "pid_sd_hash": base64url(&Sha256::digest(pid_issuer_jwt.as_bytes())),
        "new_holder_jkt": new_holder_jkt,
    });
    Ok(format!(
        "{}.{}",
        base64url(&serde_json::to_vec(&header).map_err(|_| PidBindingError::InvalidInput)?),
        base64url(&serde_json::to_vec(&payload).map_err(|_| PidBindingError::InvalidInput)?)
    ))
}

pub fn assemble_pid_bound_credential_request(
    configuration_id: &str,
    credential_proof_jwt: &str,
    pid_sd_jwt_with_disclosures: &str,
    binding_signing_input: &str,
    binding_signature: &[u8],
) -> Result<Vec<u8>, PidBindingError> {
    if configuration_id.is_empty()
        || configuration_id.len() > 1_024
        || credential_proof_jwt.is_empty()
        || credential_proof_jwt.len() > MAX_JWT_BYTES
        || pid_sd_jwt_with_disclosures.is_empty()
        || pid_sd_jwt_with_disclosures.len() > MAX_PID_VP_BYTES
        || !pid_sd_jwt_with_disclosures.contains('~')
        || binding_signing_input.len() > MAX_JWT_BYTES
        || binding_signature.len() != 64
    {
        return Err(PidBindingError::InvalidInput);
    }
    let binding_proof = format!("{binding_signing_input}.{}", base64url(binding_signature));
    let pid_vp = format!(
        "{}~{}",
        pid_sd_jwt_with_disclosures.trim_end_matches('~'),
        binding_proof
    );
    let request = json!({
        "credential_configuration_id": configuration_id,
        "proof": {"proof_type":"jwt", "jwt":credential_proof_jwt},
        "pid_binding": {"pid_vp":pid_vp, "proof_jwt":binding_proof}
    });
    let bytes = serde_json::to_vec(&request).map_err(|_| PidBindingError::InvalidInput)?;
    if bytes.len() > MAX_REQUEST_BYTES {
        return Err(PidBindingError::InvalidInput);
    }
    Ok(bytes)
}

/// Applies the profile policy after normal signature, type, validity and holder-key validation.
pub fn validate_issued_pid_binding(
    compact: &str,
    policy: &PidBindingPolicy,
) -> Result<(), PidBindingError> {
    let issuer_jwt = compact
        .split('~')
        .next()
        .ok_or(PidBindingError::InvalidCredential)?;
    let mut segments = issuer_jwt.split('.');
    let _header = segments.next().ok_or(PidBindingError::InvalidCredential)?;
    let payload = segments.next().ok_or(PidBindingError::InvalidCredential)?;
    let _signature = segments.next().ok_or(PidBindingError::InvalidCredential)?;
    if segments.next().is_some() {
        return Err(PidBindingError::InvalidCredential);
    }
    let decoded =
        Base64UrlUnpadded::decode_vec(payload).map_err(|_| PidBindingError::InvalidCredential)?;
    let payload: Map<String, Value> =
        serde_json::from_slice(&decoded).map_err(|_| PidBindingError::InvalidCredential)?;
    let bound_to = payload
        .get("cryptographically_bound_to")
        .and_then(Value::as_str);
    match policy {
        PidBindingPolicy::Required { pid_vct } if bound_to == Some(pid_vct) => Ok(()),
        PidBindingPolicy::Required { .. } => Err(PidBindingError::MissingBinding),
        PidBindingPolicy::NotRequired if bound_to.is_none() => Ok(()),
        PidBindingPolicy::NotRequired => Err(PidBindingError::UnexpectedBinding),
    }
}

fn base64url(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}
