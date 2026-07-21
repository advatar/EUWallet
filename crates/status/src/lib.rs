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

/// Maximum compact JWT accepted from a status provider. The shell should enforce the same cap
/// while downloading, but the pure parser remains safe when called directly.
pub const MAX_TOKEN_BYTES: usize = 2 * 1024 * 1024;
/// Maximum decompressed status array. This is the final allocation guard against DEFLATE bombs.
pub const MAX_DECOMPRESSED_BYTES: usize = 8 * 1024 * 1024;
/// Local maximum age for a status assertion, even if an issuer supplies a longer `ttl`/`exp`.
pub const MAX_STATUS_AGE_SECONDS: i64 = 24 * 60 * 60;
/// Cache interval used when a token omits the recommended `ttl` claim.
pub const DEFAULT_CACHE_TTL_SECONDS: i64 = 60 * 60;
const CLOCK_SKEW_SECONDS: i64 = 300;

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
    NotYetValid,
    Stale,
    SubjectMismatch,
    Malformed,
    UnsupportedAlg,
    UnsupportedHeader,
    /// `bits` was not one of 1, 2, 4, 8.
    UnsupportedBits,
    /// An encoded or decompressed input exceeded the wallet's fixed resource budget.
    ResourceLimit,
}

/// A verified, decompressed status list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusList {
    subject: String,
    bits: u8,
    list: Vec<u8>,
    issued_at: i64,
    fresh_until: i64,
}

impl StatusList {
    /// The exact URI this signed list is bound to through its `sub` claim.
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Whether this cached assertion is still usable under the wallet's local freshness policy.
    pub fn is_fresh_at(&self, now: i64) -> bool {
        now.saturating_add(CLOCK_SKEW_SECONDS) >= self.issued_at && now < self.fresh_until
    }

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
    expected_uri: &str,
    provider_public_key: &[u8],
    verifier: &dyn Verifier,
    alg: Alg,
    now: i64,
) -> Result<StatusList, StatusError> {
    if token_jwt.is_empty() || token_jwt.len() > MAX_TOKEN_BYTES {
        return Err(StatusError::ResourceLimit);
    }
    let s = core::str::from_utf8(token_jwt).map_err(|_| StatusError::Malformed)?;
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 3 {
        return Err(StatusError::Malformed);
    }
    let header: Json =
        serde_json::from_slice(&b64(parts[0])?).map_err(|_| StatusError::Malformed)?;
    let expected_alg = match alg {
        Alg::Es256 => "ES256",
        Alg::Es384 => "ES384",
        Alg::EdDsa => "EdDSA",
    };
    if header.get("alg").and_then(|a| a.as_str()) != Some(expected_alg) {
        return Err(StatusError::UnsupportedAlg);
    }
    if header.get("typ").and_then(|v| v.as_str()) != Some("statuslist+jwt")
        || header.get("crit").is_some()
        || header.get("jwk").is_some()
        || header.get("jku").is_some()
        || header.get("x5u").is_some()
    {
        return Err(StatusError::UnsupportedHeader);
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
    let subject = payload
        .get("sub")
        .and_then(|v| v.as_str())
        .filter(|v| !v.is_empty())
        .ok_or(StatusError::Malformed)?;
    if subject != expected_uri {
        return Err(StatusError::SubjectMismatch);
    }
    let issued_at = payload
        .get("iat")
        .and_then(|v| v.as_i64())
        .ok_or(StatusError::Malformed)?;
    if issued_at > now.saturating_add(CLOCK_SKEW_SECONDS) {
        return Err(StatusError::NotYetValid);
    }
    if issued_at < now.saturating_sub(MAX_STATUS_AGE_SECONDS) {
        return Err(StatusError::Stale);
    }
    let expires_at = match payload.get("exp") {
        None => None,
        Some(value) => {
            let exp = value.as_i64().ok_or(StatusError::Malformed)?;
            if exp <= issued_at || now >= exp {
                return Err(StatusError::Expired);
            }
            Some(exp)
        }
    };
    let ttl = match payload.get("ttl") {
        None => DEFAULT_CACHE_TTL_SECONDS,
        Some(value) => {
            let ttl = value
                .as_i64()
                .filter(|v| *v > 0)
                .ok_or(StatusError::Malformed)?;
            ttl.min(MAX_STATUS_AGE_SECONDS)
        }
    };
    let mut fresh_until = now.checked_add(ttl).ok_or(StatusError::Malformed)?.min(
        issued_at
            .checked_add(MAX_STATUS_AGE_SECONDS)
            .ok_or(StatusError::Malformed)?,
    );
    if let Some(exp) = expires_at {
        fresh_until = fresh_until.min(exp);
    }
    let sl = payload.get("status_list").ok_or(StatusError::Malformed)?;
    let bits = sl
        .get("bits")
        .and_then(|v| v.as_u64())
        .and_then(|value| u8::try_from(value).ok())
        .ok_or(StatusError::UnsupportedBits)?;
    if !matches!(bits, 1 | 2 | 4 | 8) {
        return Err(StatusError::UnsupportedBits);
    }
    let lst_b64 = sl
        .get("lst")
        .and_then(|v| v.as_str())
        .ok_or(StatusError::Malformed)?;
    if lst_b64.len() > MAX_TOKEN_BYTES {
        return Err(StatusError::ResourceLimit);
    }
    let compressed = Base64UrlUnpadded::decode_vec(lst_b64).map_err(|_| StatusError::Malformed)?;
    let list = miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(
        &compressed,
        MAX_DECOMPRESSED_BYTES,
    )
    .map_err(|error| {
        if error.output.len() >= MAX_DECOMPRESSED_BYTES {
            StatusError::ResourceLimit
        } else {
            StatusError::Malformed
        }
    })?;
    if list.is_empty() {
        return Err(StatusError::Malformed);
    }

    Ok(StatusList {
        subject: subject.to_string(),
        bits,
        list,
        issued_at,
        fresh_until,
    })
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
