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

const MAX_RP_REGISTRATIONS: usize = 1_024;
const MAX_RP_TEXT_BYTES: usize = 256;
const MAX_RP_CLAIMS: usize = 64;
const MAX_RP_REDIRECT_URIS: usize = 16;
const MAX_ISSUER_REGISTRATIONS: usize = 1_024;

/// A reviewed trust mark carried by the signed registration feed. Keeping this vocabulary closed
/// prevents arbitrary operator text from becoming a security badge in the wallet UI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustMark {
    EudiWallet,
}

/// The verifier's authenticated retention declaration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetentionPolicy {
    NotStored,
    Days(u16),
    Unspecified,
}

/// RP metadata authenticated by the same signed, rollback-protected feed as the trust anchors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelyingPartyRegistration {
    pub client_id: String,
    pub display_name: String,
    pub trust_mark: Option<TrustMark>,
    pub retention: RetentionPolicy,
    pub allowed_claims: Vec<String>,
    pub redirect_uris: Vec<String>,
}

/// Consumer display metadata for a credential issuer, authenticated by the signed trust feed and
/// keyed by the exact issuer identifier proven by certificate-path validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialIssuerRegistration {
    pub issuer_id: String,
    pub display_name: String,
}

/// A verified trust list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustList {
    /// Monotonic sequence number (rollback protection: a new list must strictly increase it).
    pub sequence_number: u64,
    pub valid_from: i64,
    pub valid_until: i64,
    pub anchors: Vec<TrustAnchor>,
    pub relying_parties: Vec<RelyingPartyRegistration>,
    pub credential_issuers: Vec<CredentialIssuerRegistration>,
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

    let registrations: &[Json] = match payload.get("relying_parties") {
        None => &[],
        Some(value) => value.as_array().ok_or(TrustError::Malformed)?.as_slice(),
    };
    let mut relying_parties = Vec::new();
    for registration in registrations {
        if relying_parties.len() >= MAX_RP_REGISTRATIONS {
            return Err(TrustError::Malformed);
        }
        let bounded_text = |name: &str| -> Result<String, TrustError> {
            let value = registration
                .get(name)
                .and_then(Json::as_str)
                .ok_or(TrustError::Malformed)?;
            if value.is_empty()
                || value.len() > MAX_RP_TEXT_BYTES
                || value.chars().any(char::is_control)
            {
                return Err(TrustError::Malformed);
            }
            Ok(value.to_owned())
        };
        let client_id = bounded_text("client_id")?;
        if relying_parties
            .iter()
            .any(|existing: &RelyingPartyRegistration| existing.client_id == client_id)
        {
            return Err(TrustError::Malformed);
        }
        let display_name = bounded_text("display_name")?;
        let trust_mark = match registration.get("trust_mark") {
            None | Some(Json::Null) => None,
            Some(Json::String(value)) if value == "eudi-wallet" => Some(TrustMark::EudiWallet),
            _ => return Err(TrustError::Malformed),
        };
        let retention = match registration.get("retention") {
            None | Some(Json::Null) => RetentionPolicy::Unspecified,
            Some(Json::String(value)) if value == "not-stored" => RetentionPolicy::NotStored,
            Some(Json::Object(value)) if value.len() == 1 => value
                .get("days")
                .and_then(Json::as_u64)
                .and_then(|days| u16::try_from(days).ok())
                .filter(|days| *days > 0)
                .map(RetentionPolicy::Days)
                .ok_or(TrustError::Malformed)?,
            _ => return Err(TrustError::Malformed),
        };
        let bounded_list = |name: &str, maximum: usize| -> Result<Vec<String>, TrustError> {
            let values = registration
                .get(name)
                .and_then(Json::as_array)
                .ok_or(TrustError::Malformed)?;
            if values.len() > maximum {
                return Err(TrustError::Malformed);
            }
            let mut parsed = Vec::with_capacity(values.len());
            for value in values {
                let value = value.as_str().ok_or(TrustError::Malformed)?;
                if value.is_empty()
                    || value.len() > MAX_RP_TEXT_BYTES
                    || value.chars().any(char::is_control)
                    || parsed.iter().any(|existing| existing == value)
                {
                    return Err(TrustError::Malformed);
                }
                parsed.push(value.to_owned());
            }
            Ok(parsed)
        };
        relying_parties.push(RelyingPartyRegistration {
            client_id,
            display_name,
            trust_mark,
            retention,
            allowed_claims: bounded_list("allowed_claims", MAX_RP_CLAIMS)?,
            redirect_uris: bounded_list("redirect_uris", MAX_RP_REDIRECT_URIS)?,
        });
    }

    let issuer_registrations: &[Json] = match payload.get("credential_issuers") {
        None => &[],
        Some(value) => value.as_array().ok_or(TrustError::Malformed)?.as_slice(),
    };
    if issuer_registrations.len() > MAX_ISSUER_REGISTRATIONS {
        return Err(TrustError::Malformed);
    }
    let mut credential_issuers = Vec::with_capacity(issuer_registrations.len());
    for registration in issuer_registrations {
        let bounded = |name: &str| -> Result<String, TrustError> {
            let value = registration
                .get(name)
                .and_then(Json::as_str)
                .ok_or(TrustError::Malformed)?;
            if value.is_empty()
                || value.len() > MAX_RP_TEXT_BYTES
                || value.chars().any(char::is_control)
            {
                return Err(TrustError::Malformed);
            }
            Ok(value.to_owned())
        };
        let issuer_id = bounded("issuer_id")?;
        if credential_issuers
            .iter()
            .any(|existing: &CredentialIssuerRegistration| existing.issuer_id == issuer_id)
        {
            return Err(TrustError::Malformed);
        }
        credential_issuers.push(CredentialIssuerRegistration {
            issuer_id,
            display_name: bounded("display_name")?,
        });
    }

    Ok(TrustList {
        sequence_number,
        valid_from,
        valid_until,
        anchors,
        relying_parties,
        credential_issuers,
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

    /// Signed registration for an exact client identifier, only while the feed is current.
    pub fn relying_party_at(&self, client_id: &str, now: i64) -> Option<&RelyingPartyRegistration> {
        self.is_valid_at(now)
            .then(|| {
                self.current
                    .as_ref()?
                    .relying_parties
                    .iter()
                    .find(|registration| registration.client_id.as_bytes() == client_id.as_bytes())
            })
            .flatten()
    }

    /// Signed issuer display registration for an exact authenticated issuer identifier.
    pub fn credential_issuer_at(
        &self,
        issuer_id: &str,
        now: i64,
    ) -> Option<&CredentialIssuerRegistration> {
        self.is_valid_at(now)
            .then(|| {
                self.current
                    .as_ref()?
                    .credential_issuers
                    .iter()
                    .find(|registration| registration.issuer_id.as_bytes() == issuer_id.as_bytes())
            })
            .flatten()
    }
}
