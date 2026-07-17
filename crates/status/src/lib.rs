#![forbid(unsafe_code)]
//! `status` — credential revocation/suspension via the IETF **Token Status List** (draft-21).
//!
//! See docs/IMPLEMENTATION_PLAN.md Section 6 and the register (2025/847, Token Status List draft).
//!
//! A status provider publishes a signed **Status List Token** (a JWS) whose payload contains a
//! bit-packed list (`bits` per entry, DEFLATE-compressed, base64url). Each credential references an
//! index into that list. This crate verifies the token's signature, decompresses the list, and
//! reads the status at an index — then a deterministic **fail-open/fail-closed** policy decides
//! what to do when the status cannot be fetched (e.g. offline proximity vs online remote).

use base64ct::{Base64UrlUnpadded, Encoding};
use crypto_traits::{Alg, Verifier};
use serde_json::Value as Json;

/// Pinned wire version (change-watch: draft, not RFC).
pub const TOKEN_STATUS_LIST_DRAFT: &str = "draft-21";

/// A credential's status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialStatus {
    /// 0x00 — valid.
    Valid,
    /// 0x01 — revoked (permanent).
    Invalid,
    /// 0x02 — suspended (temporary).
    Suspended,
    /// The index was out of range or the value is reserved.
    Unknown,
}

/// What the wallet does when the status is *unavailable* (could not be fetched). Chosen by context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailPolicy {
    /// Accept when the status is unavailable (e.g. offline proximity, to avoid bricking the user).
    FailOpen,
    /// Reject when the status is unavailable (e.g. high-value online presentation).
    FailClosed,
}

/// The accept/reject decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Accept,
    Reject,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatusError {
    BadSignature,
    Expired,
    Malformed,
    UnsupportedAlg,
    /// `bits` was not one of 1, 2, 4, 8.
    UnsupportedBits,
}

/// A verified, decompressed status list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusList {
    bits: u8,
    list: Vec<u8>,
}

impl StatusList {
    /// Read the status at `index`.
    pub fn status_at(&self, index: usize) -> CredentialStatus {
        let per_byte = 8 / self.bits as usize;
        let byte_idx = index / per_byte;
        let Some(&byte) = self.list.get(byte_idx) else {
            return CredentialStatus::Unknown;
        };
        let slot = index % per_byte;
        let shift = slot * self.bits as usize;
        let mask = (1u16 << self.bits) - 1;
        let value = ((byte as u16) >> shift) & mask;
        match value {
            0 => CredentialStatus::Valid,
            1 => CredentialStatus::Invalid,
            2 => CredentialStatus::Suspended,
            _ => CredentialStatus::Unknown,
        }
    }
}

/// Parse and verify a Status List Token (compact JWS), returning the decompressed list.
pub fn parse_and_verify(
    token_jwt: &[u8],
    provider_public_key: &[u8],
    verifier: &dyn Verifier,
    alg: Alg,
    now: i64,
) -> Result<StatusList, StatusError> {
    let s = core::str::from_utf8(token_jwt).map_err(|_| StatusError::Malformed)?;
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 3 {
        return Err(StatusError::Malformed);
    }
    let header: Json =
        serde_json::from_slice(&b64(parts[0])?).map_err(|_| StatusError::Malformed)?;
    match header.get("alg").and_then(|a| a.as_str()) {
        Some("ES256") | Some("ES384") | Some("EdDSA") => {}
        _ => return Err(StatusError::UnsupportedAlg),
    }
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    verifier
        .verify(
            alg,
            provider_public_key,
            signing_input.as_bytes(),
            &b64(parts[2])?,
        )
        .map_err(|_| StatusError::BadSignature)?;

    let payload: Json =
        serde_json::from_slice(&b64(parts[1])?).map_err(|_| StatusError::Malformed)?;
    // Optional expiry.
    if let Some(exp) = payload.get("exp").and_then(|v| v.as_i64()) {
        if now > exp {
            return Err(StatusError::Expired);
        }
    }
    let sl = payload.get("status_list").ok_or(StatusError::Malformed)?;
    let bits = sl
        .get("bits")
        .and_then(|v| v.as_u64())
        .ok_or(StatusError::Malformed)? as u8;
    if !matches!(bits, 1 | 2 | 4 | 8) {
        return Err(StatusError::UnsupportedBits);
    }
    let lst_b64 = sl
        .get("lst")
        .and_then(|v| v.as_str())
        .ok_or(StatusError::Malformed)?;
    let compressed = Base64UrlUnpadded::decode_vec(lst_b64).map_err(|_| StatusError::Malformed)?;
    let list =
        miniz_oxide::inflate::decompress_to_vec(&compressed).map_err(|_| StatusError::Malformed)?;

    Ok(StatusList { bits, list })
}

fn b64(s: &str) -> Result<Vec<u8>, StatusError> {
    Base64UrlUnpadded::decode_vec(s).map_err(|_| StatusError::Malformed)
}

/// Deterministic decision: a known status maps directly; an unavailable status uses the policy.
/// `Suspended` and `Invalid` both reject; only `Valid` accepts. `Unknown` is treated as
/// unavailable and defers to the policy.
pub fn decide(status: Option<CredentialStatus>, policy: FailPolicy) -> Decision {
    match status {
        Some(CredentialStatus::Valid) => Decision::Accept,
        Some(CredentialStatus::Invalid) | Some(CredentialStatus::Suspended) => Decision::Reject,
        None | Some(CredentialStatus::Unknown) => match policy {
            FailPolicy::FailOpen => Decision::Accept,
            FailPolicy::FailClosed => Decision::Reject,
        },
    }
}
