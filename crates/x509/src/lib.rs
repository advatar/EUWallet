#![forbid(unsafe_code)]
//! `x509` — DER parsing, path validation, and the EUDI relying-party / trusted-issuer profile.
//!
//! See docs/IMPLEMENTATION_PLAN.md Section 4.4.
//!
//! The load-bearing idea, encoded in the type system: **a valid TLS certificate is not a
//! registered relying party.** Chain validity answers "is this a well-formed cert signed by a
//! CA?"; the profile answers "is this entity authorised, in the EUDI trust framework, to request
//! these attributes?" — a separate, additional question. Path validation and the profile check
//! are two distinct steps returning distinct types, so a caller cannot mistake one for the other.
//!
//! Parsing and profile evaluation are pure logic (via the `x509-cert`/`der` crates). The one
//! cryptographic step — verifying each certificate's signature — goes through
//! [`crypto_traits::Verifier`]; this crate never implements a signature algorithm.

use crypto_traits::{Alg, Verifier};
use der::{Decode, Encode};
use x509_cert::ext::pkix::{BasicConstraints, CertificatePolicies, ExtendedKeyUsage};
use x509_cert::Certificate;

/// ISO/IEC 18013-5 mdoc **reader authentication** EKU — the real OID a relying party's reader
/// certificate carries to request an mdoc presentation. Used here as the RP-access marker.
pub const EKU_MDOC_READER_AUTH: &str = "1.0.18013.5.1.6";
/// EKU OID for TLS server authentication (what a plain web certificate carries).
pub const EKU_SERVER_AUTH: &str = "1.3.6.1.5.5.7.3.1";

// Standard extension OIDs.
const OID_EKU: &str = "2.5.29.37";
const OID_POLICIES: &str = "2.5.29.32";
const OID_BASIC_CONSTRAINTS: &str = "2.5.29.19";

#[derive(Debug, PartialEq, Eq)]
pub enum X509Error {
    /// Malformed DER / not a certificate.
    Der,
    /// The certification path failed (expiry, broken chain, bad signature, non-CA issuer).
    PathInvalid(&'static str),
    /// The chain is valid but does not satisfy the EUDI profile.
    ProfileViolation(&'static str),
    /// A signature algorithm we do not map.
    UnsupportedSignatureAlg,
}

/// A parsed certificate reduced to the fields the profile and path checks need.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedCert {
    pub tbs_der: Vec<u8>,
    pub signature: Vec<u8>,
    pub sig_alg: Alg,
    /// SubjectPublicKeyInfo (DER).
    pub spki_der: Vec<u8>,
    /// The raw public key (uncompressed EC point `0x04||X||Y`) — the form the crypto backend
    /// verifies a child certificate's signature against.
    pub public_key_raw: Vec<u8>,
    pub subject: String,
    pub issuer: String,
    pub not_before: i64,
    pub not_after: i64,
    pub is_ca: bool,
    pub eku: Vec<String>,
    pub policies: Vec<String>,
}

fn map_sig_alg(oid: &str) -> Result<Alg, X509Error> {
    match oid {
        "1.2.840.10045.4.3.2" => Ok(Alg::Es256), // ecdsa-with-SHA256
        "1.2.840.10045.4.3.3" => Ok(Alg::Es384), // ecdsa-with-SHA384
        "1.3.101.112" => Ok(Alg::EdDsa),         // Ed25519
        _ => Err(X509Error::UnsupportedSignatureAlg),
    }
}

/// Parse a DER certificate into the reduced [`ParsedCert`].
pub fn parse_cert(der_bytes: &[u8]) -> Result<ParsedCert, X509Error> {
    let cert = Certificate::from_der(der_bytes).map_err(|_| X509Error::Der)?;
    let tbs = &cert.tbs_certificate;

    let tbs_der = tbs.to_der().map_err(|_| X509Error::Der)?;
    let signature = cert.signature.as_bytes().ok_or(X509Error::Der)?.to_vec();
    let sig_alg = map_sig_alg(&cert.signature_algorithm.oid.to_string())?;
    let spki_der = tbs
        .subject_public_key_info
        .to_der()
        .map_err(|_| X509Error::Der)?;
    let public_key_raw = tbs
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .ok_or(X509Error::Der)?
        .to_vec();

    let not_before = tbs.validity.not_before.to_unix_duration().as_secs() as i64;
    let not_after = tbs.validity.not_after.to_unix_duration().as_secs() as i64;

    let mut is_ca = false;
    let mut eku = Vec::new();
    let mut policies = Vec::new();

    if let Some(exts) = &tbs.extensions {
        for ext in exts {
            match ext.extn_id.to_string().as_str() {
                OID_BASIC_CONSTRAINTS => {
                    if let Ok(bc) = BasicConstraints::from_der(ext.extn_value.as_bytes()) {
                        is_ca = bc.ca;
                    }
                }
                OID_EKU => {
                    if let Ok(e) = ExtendedKeyUsage::from_der(ext.extn_value.as_bytes()) {
                        eku = e.0.iter().map(|o| o.to_string()).collect();
                    }
                }
                OID_POLICIES => {
                    if let Ok(p) = CertificatePolicies::from_der(ext.extn_value.as_bytes()) {
                        policies =
                            p.0.iter()
                                .map(|pi| pi.policy_identifier.to_string())
                                .collect();
                    }
                }
                _ => {}
            }
        }
    }

    Ok(ParsedCert {
        tbs_der,
        signature,
        sig_alg,
        spki_der,
        public_key_raw,
        subject: tbs.subject.to_string(),
        issuer: tbs.issuer.to_string(),
        not_before,
        not_after,
        is_ca,
        eku,
        policies,
    })
}

/// Step 1 — path validation (a pragmatic RFC 5280 subset): chain the leaf up to a trust anchor,
/// checking validity windows, issuer/subject linkage, that each issuer is a CA, and each
/// signature (via the crypto boundary). Returns the validated path (leaf-first, incl. anchor).
///
/// `now` is a Unix timestamp (seconds) supplied by the shell — the core has no clock.
pub fn validate_path(
    chain_der: &[Vec<u8>],
    trust_anchors: &[ParsedCert],
    now: i64,
    verifier: &dyn Verifier,
) -> Result<Vec<ParsedCert>, X509Error> {
    if chain_der.is_empty() {
        return Err(X509Error::PathInvalid("empty chain"));
    }
    let mut path: Vec<ParsedCert> = chain_der
        .iter()
        .map(|d| parse_cert(d))
        .collect::<Result<_, _>>()?;

    // Find the anchor that issued the top of the supplied chain and append it.
    let top_issuer = path.last().unwrap().issuer.clone();
    let anchor = trust_anchors
        .iter()
        .find(|a| a.subject == top_issuer)
        .ok_or(X509Error::PathInvalid("no trust anchor for chain"))?;
    path.push(anchor.clone());

    // Every certificate authorizing the path, including the appended trust anchor, must be
    // current. Otherwise a cached path could remain usable after its root expires.
    for certificate in &path {
        if now < certificate.not_before || now > certificate.not_after {
            return Err(X509Error::PathInvalid(
                "certificate expired or not yet valid",
            ));
        }
    }

    // Walk child→parent: linkage, parent-is-CA, signature.
    for i in 0..path.len() - 1 {
        let child = &path[i];
        let parent = &path[i + 1];
        if child.issuer != parent.subject {
            return Err(X509Error::PathInvalid("issuer/subject mismatch"));
        }
        if !parent.is_ca {
            return Err(X509Error::PathInvalid("issuer is not a CA"));
        }
        verifier
            .verify(
                child.sig_alg,
                &parent.public_key_raw,
                &child.tbs_der,
                &child.signature,
            )
            .map_err(|_| X509Error::PathInvalid("signature verification failed"))?;
    }
    Ok(path)
}

/// The profile-checked result — NOT mere chain validity. The `registered` flag can only be set
/// by [`check_relying_party`] after both path validation and the profile checks pass.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RelyingPartyProfile {
    pub subject: String,
    pub registered: bool,
}

/// Step 2 — the EUDI relying-party profile. Runs ONLY after [`validate_path`] succeeds, and
/// applies the checks a generic TLS validator would not: the leaf must carry the mdoc
/// reader-authentication EKU, must be an end-entity (not a CA), and must chain to a CA from the
/// EUDI RP-access trust list (the `trust_anchors` passed here, sourced from the `trust` crate).
/// A perfectly valid `serverAuth` TLS certificate therefore fails — valid-TLS ≠ registered RP.
pub fn check_relying_party(
    chain_der: &[Vec<u8>],
    trust_anchors: &[ParsedCert],
    now: i64,
    verifier: &dyn Verifier,
) -> Result<RelyingPartyProfile, X509Error> {
    let path = validate_path(chain_der, trust_anchors, now, verifier)?;
    let leaf = &path[0];

    if leaf.is_ca {
        return Err(X509Error::ProfileViolation("leaf must be an end-entity"));
    }
    if !leaf.eku.iter().any(|o| o == EKU_MDOC_READER_AUTH) {
        return Err(X509Error::ProfileViolation("missing mdoc reader-auth EKU"));
    }
    if leaf.policies.is_empty() {
        return Err(X509Error::ProfileViolation("missing RP certificate policy"));
    }
    Ok(RelyingPartyProfile {
        subject: leaf.subject.clone(),
        registered: true,
    })
}
