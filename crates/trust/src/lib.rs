#![forbid(unsafe_code)]
//! `trust` — trusted lists and the trust-anchor store.
//!
//! See docs/IMPLEMENTATION_PLAN.md Section 6 and the register (ETSI 119 612/119 602, CIR 2025/2164).
//!
//! The register requires "one signed-list downloader/parser/cache with pinned schemas, rollback
//! protection and offline policy." Parsing/verification here is pure; the *fetch* is an effect the
//! shell performs. The wallet consumes a **signed trust list** (a JWS over a canonical anchor
//! list); the crate verifies its signature, enforces validity and **monotonic rollback
//! protection**, and yields the granted trust anchors for a given service so `x509` can validate a
//! certificate chain against them. (A national ETSI XML TSL is transcoded to this canonical signed
//! form by the trust infrastructure; the wallet verifies the canonical list.)

use base64ct::{Base64UrlUnpadded, Encoding};
use crypto_traits::{Alg, Verifier};
use serde_json::Value as Json;

/// The kind of service a trust anchor is authorised for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceType {
    /// PID (person identification data) issuer.
    PidProvider,
    /// (Q)EAA attestation issuer.
    AttestationProvider,
    /// Relying-party access CA (issues RP reader certificates).
    RelyingPartyAccessCa,
    /// Status-list provider.
    StatusProvider,
}

impl ServiceType {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "pid" => Some(ServiceType::PidProvider),
            "attestation" => Some(ServiceType::AttestationProvider),
            "rp-access-ca" => Some(ServiceType::RelyingPartyAccessCa),
            "status" => Some(ServiceType::StatusProvider),
            _ => None,
        }
    }
}

/// The granted/withdrawn state of a service (ETSI TSL service status).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceStatus {
    Granted,
    Withdrawn,
}

/// A single trust anchor entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustAnchor {
    pub certificate_der: Vec<u8>,
    pub service_type: ServiceType,
    pub status: ServiceStatus,
}

/// A verified trust list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustList {
    /// Monotonic sequence number (rollback protection: a new list must strictly increase it).
    pub sequence_number: u64,
    pub valid_from: i64,
    pub valid_until: i64,
    pub anchors: Vec<TrustAnchor>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustError {
    /// The list signature did not verify against the list operator's key.
    BadSignature,
    /// The list is outside its validity window.
    Expired,
    /// A replayed/older list (sequence number did not strictly increase) — rollback attempt.
    Rollback,
    /// The list could not be parsed.
    Malformed,
    /// The JOSE header used an unacceptable algorithm.
    UnsupportedAlg,
}

/// Parse and verify a signed trust list (compact JWS). Verifies the operator signature, checks the
/// validity window against `now`, and returns the [`TrustList`]. Rollback protection is applied
/// separately by [`TrustStore::update`].
pub fn parse_and_verify(
    signed_list: &[u8],
    operator_public_key: &[u8],
    verifier: &dyn Verifier,
    alg: Alg,
    now: i64,
) -> Result<TrustList, TrustError> {
    let s = core::str::from_utf8(signed_list).map_err(|_| TrustError::Malformed)?;
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 3 {
        return Err(TrustError::Malformed);
    }
    // Header: require a known alg (reject none / unexpected).
    let header: Json =
        serde_json::from_slice(&b64(parts[0])?).map_err(|_| TrustError::Malformed)?;
    match header.get("alg").and_then(|a| a.as_str()) {
        Some("ES256") | Some("ES384") | Some("EdDSA") => {}
        _ => return Err(TrustError::UnsupportedAlg),
    }

    // Verify the signature over ASCII(header "." payload).
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig = b64(parts[2])?;
    verifier
        .verify(alg, operator_public_key, signing_input.as_bytes(), &sig)
        .map_err(|_| TrustError::BadSignature)?;

    // Parse the payload.
    let payload: Json =
        serde_json::from_slice(&b64(parts[1])?).map_err(|_| TrustError::Malformed)?;
    let sequence_number = payload
        .get("seq")
        .and_then(|v| v.as_u64())
        .ok_or(TrustError::Malformed)?;
    let valid_from = payload
        .get("valid_from")
        .and_then(|v| v.as_i64())
        .ok_or(TrustError::Malformed)?;
    let valid_until = payload
        .get("valid_until")
        .and_then(|v| v.as_i64())
        .ok_or(TrustError::Malformed)?;
    if now < valid_from || now > valid_until {
        return Err(TrustError::Expired);
    }

    let mut anchors = Vec::new();
    for a in payload
        .get("anchors")
        .and_then(|v| v.as_array())
        .ok_or(TrustError::Malformed)?
    {
        let cert_b64 = a
            .get("cert")
            .and_then(|v| v.as_str())
            .ok_or(TrustError::Malformed)?;
        let certificate_der =
            Base64UrlUnpadded::decode_vec(cert_b64).map_err(|_| TrustError::Malformed)?;
        let service_type = a
            .get("service")
            .and_then(|v| v.as_str())
            .and_then(ServiceType::parse)
            .ok_or(TrustError::Malformed)?;
        let status = match a.get("status").and_then(|v| v.as_str()) {
            Some("granted") => ServiceStatus::Granted,
            Some("withdrawn") => ServiceStatus::Withdrawn,
            _ => return Err(TrustError::Malformed),
        };
        anchors.push(TrustAnchor {
            certificate_der,
            service_type,
            status,
        });
    }

    Ok(TrustList {
        sequence_number,
        valid_from,
        valid_until,
        anchors,
    })
}

fn b64(s: &str) -> Result<Vec<u8>, TrustError> {
    Base64UrlUnpadded::decode_vec(s).map_err(|_| TrustError::Malformed)
}

/// Holds the current verified trust list and enforces monotonic rollback protection on update.
#[derive(Debug, Default)]
pub struct TrustStore {
    current: Option<TrustList>,
}

impl TrustStore {
    pub fn new() -> Self {
        TrustStore::default()
    }

    /// Install a newly verified list, rejecting a stale/replayed one (rollback protection).
    pub fn update(&mut self, list: TrustList) -> Result<(), TrustError> {
        if let Some(cur) = &self.current {
            if list.sequence_number <= cur.sequence_number {
                return Err(TrustError::Rollback);
            }
        }
        self.current = Some(list);
        Ok(())
    }

    /// The current sequence number, if a list is installed.
    pub fn sequence_number(&self) -> Option<u64> {
        self.current.as_ref().map(|l| l.sequence_number)
    }

    /// Whether the installed, signature-verified list is current at `now`.
    pub fn is_valid_at(&self, now: i64) -> bool {
        self.current
            .as_ref()
            .is_some_and(|list| now >= list.valid_from && now <= list.valid_until)
    }

    /// DER-encoded certificates of the *granted* anchors for a service — pass these to
    /// `x509::parse_cert` + `x509::validate_path` to decide whether a chain is trusted.
    pub fn granted_anchors(&self, service: ServiceType) -> Vec<Vec<u8>> {
        self.current
            .as_ref()
            .map(|l| {
                l.anchors
                    .iter()
                    .filter(|a| a.service_type == service && a.status == ServiceStatus::Granted)
                    .map(|a| a.certificate_der.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Granted anchors only when the signed list itself is current. This is the variant security
    /// decisions should use after the clock may have advanced since list ingestion.
    pub fn granted_anchors_at(&self, service: ServiceType, now: i64) -> Vec<Vec<u8>> {
        if self.is_valid_at(now) {
            self.granted_anchors(service)
        } else {
            Vec::new()
        }
    }

    /// Parse the granted anchors for a service into `x509::ParsedCert`s (skips unparseable ones).
    pub fn parsed_anchors(&self, service: ServiceType) -> Vec<x509::ParsedCert> {
        self.granted_anchors(service)
            .iter()
            .filter_map(|der| x509::parse_cert(der).ok())
            .collect()
    }

    /// Parsed granted anchors only while the signed trust list is current at `now`.
    pub fn parsed_anchors_at(&self, service: ServiceType, now: i64) -> Vec<x509::ParsedCert> {
        self.granted_anchors_at(service, now)
            .iter()
            .filter_map(|der| x509::parse_cert(der).ok())
            .collect()
    }
}
