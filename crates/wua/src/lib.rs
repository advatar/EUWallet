#![forbid(unsafe_code)]
//! `wua` — Wallet Unit Attestation (WUA) verification (TS03).
//!
//! See docs/IMPLEMENTATION_PLAN.md Section 6.
//!
//! A wallet provider issues a **Wallet Unit Attestation**: a signed statement that this wallet
//! instance is genuine and that a given device key is hardware-bound at a stated assurance level.
//! This crate verifies the WUA's signature against the provider's key (which the caller obtains
//! from the trust list), checks validity, and confirms the WUA **binds a specific device key** —
//! so a relying party / issuer can require `proof_key_is_attested` rather than trusting a
//! self-claim. The platform key-attestation chain (Apple App Attest / Android Key Attestation) is
//! validated by the provider at issuance and/or by the shell via `crypto_traits::KeyAttestation`;
//! the WUA is the provider's portable vouching for it.

use base64ct::{Base64UrlUnpadded, Encoding};
use crypto_traits::{Alg, Verifier};
use serde_json::Value as Json;

/// Attestation assurance level asserted by the provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssuranceLevel {
    High,
    Substantial,
    Low,
}

impl AssuranceLevel {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "high" => Some(AssuranceLevel::High),
            "substantial" => Some(AssuranceLevel::Substantial),
            "low" => Some(AssuranceLevel::Low),
            _ => None,
        }
    }
}

/// A verified Wallet Unit Attestation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletUnitAttestation {
    /// The raw device public key the WUA attests (uncompressed EC point).
    pub device_public_key: Vec<u8>,
    pub assurance_level: AssuranceLevel,
    pub valid_until: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WuaError {
    BadSignature,
    Expired,
    Malformed,
    UnsupportedAlg,
}

/// Parse and verify a WUA (compact JWS) against the wallet provider's public key.
pub fn parse_and_verify(
    wua_jwt: &[u8],
    provider_public_key: &[u8],
    verifier: &dyn Verifier,
    alg: Alg,
    now: i64,
) -> Result<WalletUnitAttestation, WuaError> {
    let s = core::str::from_utf8(wua_jwt).map_err(|_| WuaError::Malformed)?;
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 3 {
        return Err(WuaError::Malformed);
    }
    let header: Json = serde_json::from_slice(&b64(parts[0])?).map_err(|_| WuaError::Malformed)?;
    match header.get("alg").and_then(|a| a.as_str()) {
        Some("ES256") | Some("ES384") | Some("EdDSA") => {}
        _ => return Err(WuaError::UnsupportedAlg),
    }
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    verifier
        .verify(
            alg,
            provider_public_key,
            signing_input.as_bytes(),
            &b64(parts[2])?,
        )
        .map_err(|_| WuaError::BadSignature)?;

    let payload: Json = serde_json::from_slice(&b64(parts[1])?).map_err(|_| WuaError::Malformed)?;
    let valid_until = payload
        .get("exp")
        .and_then(|v| v.as_i64())
        .ok_or(WuaError::Malformed)?;
    if now >= valid_until {
        return Err(WuaError::Expired);
    }
    let assurance_level = payload
        .get("aal")
        .and_then(|v| v.as_str())
        .and_then(AssuranceLevel::parse)
        .ok_or(WuaError::Malformed)?;
    // The attested device key lives in the confirmation claim `cnf.jwk_raw` (base64url raw point).
    let device_public_key = payload
        .get("cnf")
        .and_then(|c| c.get("jwk_raw"))
        .and_then(|v| v.as_str())
        .and_then(|s| Base64UrlUnpadded::decode_vec(s).ok())
        .ok_or(WuaError::Malformed)?;

    Ok(WalletUnitAttestation {
        device_public_key,
        assurance_level,
        valid_until,
    })
}

fn b64(s: &str) -> Result<Vec<u8>, WuaError> {
    Base64UrlUnpadded::decode_vec(s).map_err(|_| WuaError::Malformed)
}

impl WalletUnitAttestation {
    /// Does this attestation bind exactly the given device key? (Never trust a self-claim: the
    /// key used for a proof-of-possession must be the one the provider attested.)
    pub fn attests_key(&self, device_public_key: &[u8]) -> bool {
        self.device_public_key == device_public_key
    }

    /// Convenience: verified, binds this key, and meets at least the required assurance level.
    pub fn is_valid_for(&self, device_public_key: &[u8], min_level: AssuranceLevel) -> bool {
        self.attests_key(device_public_key) && self.meets(min_level)
    }

    /// Revalidate a cached attestation at the current trusted time before it authorizes a proof.
    pub fn is_valid_for_at(
        &self,
        device_public_key: &[u8],
        min_level: AssuranceLevel,
        now: i64,
    ) -> bool {
        now < self.valid_until && self.is_valid_for(device_public_key, min_level)
    }

    fn meets(&self, min: AssuranceLevel) -> bool {
        fn rank(a: AssuranceLevel) -> u8 {
            match a {
                AssuranceLevel::Low => 0,
                AssuranceLevel::Substantial => 1,
                AssuranceLevel::High => 2,
            }
        }
        rank(self.assurance_level) >= rank(min)
    }
}
