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

use std::collections::BTreeSet;

use crypto_traits::{Alg, Verifier};
use der::{Decode, Encode};
use x509_cert::ext::pkix::{
    name::GeneralName, AuthorityKeyIdentifier, BasicConstraints, CertificatePolicies,
    ExtendedKeyUsage, KeyUsage, SubjectAltName, SubjectKeyIdentifier,
};
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
const OID_SUBJECT_ALT_NAME: &str = "2.5.29.17";
const OID_KEY_USAGE: &str = "2.5.29.15";
const OID_SUBJECT_KEY_IDENTIFIER: &str = "2.5.29.14";
const OID_AUTHORITY_KEY_IDENTIFIER: &str = "2.5.29.35";

// Explicit resource budgets for hostile certificate bundles. The first strict slice intentionally
// supports short wallet trust paths rather than exposing an unbounded graph search.
const MAX_SUPPLIED_CERTIFICATES: usize = 8;
const MAX_TRUST_ANCHORS: usize = 64;
const MAX_CERTIFICATE_DER_BYTES: usize = 64 * 1024;
const MAX_EXTENSIONS_PER_CERTIFICATE: usize = 32;
const MAX_ISSUER_CANDIDATES: usize = 16;
const MAX_PATH_BUILD_STEPS: usize = 256;
const MAX_COMPLETE_PATHS: usize = MAX_PATH_BUILD_STEPS;

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
    /// URI identities carried by the leaf's Subject Alternative Name extension.
    pub uri_sans: Vec<String>,
    pub not_before: i64,
    pub not_after: i64,
    pub is_ca: bool,
    pub eku: Vec<String>,
    pub policies: Vec<String>,
    constraints: CertificateConstraints,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct CertificateConstraints {
    subject_der: Vec<u8>,
    issuer_der: Vec<u8>,
    basic_constraints_present: bool,
    basic_constraints_critical: bool,
    path_len_constraint: Option<u8>,
    key_usage_present: bool,
    digital_signature: bool,
    key_cert_sign: bool,
    subject_key_identifier: Option<Vec<u8>>,
    authority_key_identifier: Option<Vec<u8>>,
    unsupported_critical_extension: bool,
    signature_algorithms_match: bool,
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
    if der_bytes.is_empty() || der_bytes.len() > MAX_CERTIFICATE_DER_BYTES {
        return Err(X509Error::Der);
    }
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
    let mut uri_sans = Vec::new();
    let mut constraints = CertificateConstraints {
        subject_der: tbs.subject.to_der().map_err(|_| X509Error::Der)?,
        issuer_der: tbs.issuer.to_der().map_err(|_| X509Error::Der)?,
        signature_algorithms_match: tbs.signature == cert.signature_algorithm,
        ..CertificateConstraints::default()
    };

    if let Some(exts) = &tbs.extensions {
        if exts.len() > MAX_EXTENSIONS_PER_CERTIFICATE {
            return Err(X509Error::Der);
        }
        let mut seen_oids = BTreeSet::new();
        for ext in exts {
            let oid = ext.extn_id.to_string();
            if !seen_oids.insert(oid.clone()) {
                return Err(X509Error::Der);
            }
            match oid.as_str() {
                OID_BASIC_CONSTRAINTS => {
                    let bc = BasicConstraints::from_der(ext.extn_value.as_bytes())
                        .map_err(|_| X509Error::Der)?;
                    if !bc.ca && bc.path_len_constraint.is_some() {
                        return Err(X509Error::Der);
                    }
                    is_ca = bc.ca;
                    constraints.basic_constraints_present = true;
                    constraints.basic_constraints_critical = ext.critical;
                    constraints.path_len_constraint = bc.path_len_constraint;
                }
                OID_KEY_USAGE => {
                    let usage = KeyUsage::from_der(ext.extn_value.as_bytes())
                        .map_err(|_| X509Error::Der)?;
                    constraints.key_usage_present = true;
                    constraints.digital_signature = usage.digital_signature();
                    constraints.key_cert_sign = usage.key_cert_sign();
                }
                OID_EKU => {
                    let parsed = ExtendedKeyUsage::from_der(ext.extn_value.as_bytes())
                        .map_err(|_| X509Error::Der)?;
                    eku = parsed.0.iter().map(|value| value.to_string()).collect();
                }
                OID_POLICIES => {
                    let parsed = CertificatePolicies::from_der(ext.extn_value.as_bytes())
                        .map_err(|_| X509Error::Der)?;
                    policies = parsed
                        .0
                        .iter()
                        .map(|policy| policy.policy_identifier.to_string())
                        .collect();
                    // Policy processing is explicitly outside this bounded slice. A non-critical
                    // policy remains available to the RP profile; a critical one must fail closed.
                    if ext.critical {
                        constraints.unsupported_critical_extension = true;
                    }
                }
                OID_SUBJECT_ALT_NAME => {
                    let san = SubjectAltName::from_der(ext.extn_value.as_bytes())
                        .map_err(|_| X509Error::Der)?;
                    uri_sans.extend(san.0.iter().filter_map(|name| match name {
                        GeneralName::UniformResourceIdentifier(uri) => Some(uri.to_string()),
                        _ => None,
                    }));
                }
                OID_SUBJECT_KEY_IDENTIFIER => {
                    let identifier = SubjectKeyIdentifier::from_der(ext.extn_value.as_bytes())
                        .map_err(|_| X509Error::Der)?;
                    constraints.subject_key_identifier = Some(identifier.0.as_bytes().to_vec());
                    if ext.critical {
                        constraints.unsupported_critical_extension = true;
                    }
                }
                OID_AUTHORITY_KEY_IDENTIFIER => {
                    let identifier = AuthorityKeyIdentifier::from_der(ext.extn_value.as_bytes())
                        .map_err(|_| X509Error::Der)?;
                    constraints.authority_key_identifier = identifier
                        .key_identifier
                        .map(|value| value.as_bytes().to_vec());
                    if ext.critical {
                        constraints.unsupported_critical_extension = true;
                    }
                }
                _ if ext.critical => constraints.unsupported_critical_extension = true,
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
        uri_sans,
        not_before,
        not_after,
        is_ca,
        eku,
        policies,
        constraints,
    })
}

/// A credential-issuer leaf that has passed both path validation and the repository's current
/// explicit issuer profile. The trust service/domain remains a caller decision because the
/// `x509` crate deliberately has no dependency on the trusted-list model.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedCredentialIssuer {
    /// The single authenticated HTTPS URI carried in the leaf certificate's SAN extension.
    pub identity: String,
    pub public_key_raw: Vec<u8>,
    pub not_before: i64,
    pub not_after: i64,
}

/// Validate a credential issuer against one already service-scoped anchor set.
///
/// This is intentionally a narrow interim EUDI profile: the leaf must be an end entity and carry
/// exactly one canonical HTTPS-origin URI SAN, which becomes the issuer identity used by
/// credential policy. The accepted grammar is `https://<lowercase ASCII DNS name>[:<port>]`, with
/// at least two DNS labels and an optional non-zero, non-default port. Paths (including `/`), IP
/// literals, userinfo, query, fragment, whitespace and alternate normalizations are rejected. It
/// does not claim to replace complete RFC 5280 or the final PID/(Q)EAA certificate profiles.
pub fn check_credential_issuer(
    chain_der: &[Vec<u8>],
    trust_anchors: &[ParsedCert],
    now: i64,
    verifier: &dyn Verifier,
) -> Result<ValidatedCredentialIssuer, X509Error> {
    let path = validate_path(chain_der, trust_anchors, now, verifier)?;
    let leaf = &path[0];
    if leaf.is_ca {
        return Err(X509Error::ProfileViolation(
            "credential issuer leaf must be an end-entity",
        ));
    }
    let identity = match leaf.uri_sans.as_slice() {
        [identity] if valid_https_issuer_identity(identity) => identity.clone(),
        [] => {
            return Err(X509Error::ProfileViolation(
                "credential issuer identity URI is missing",
            ));
        }
        [_] => {
            return Err(X509Error::ProfileViolation(
                "credential issuer identity must be an HTTPS URI",
            ));
        }
        _ => {
            return Err(X509Error::ProfileViolation(
                "credential issuer identity is ambiguous",
            ));
        }
    };
    Ok(ValidatedCredentialIssuer {
        identity,
        public_key_raw: leaf.public_key_raw.clone(),
        not_before: leaf.not_before,
        not_after: leaf.not_after,
    })
}

fn valid_https_issuer_identity(identity: &str) -> bool {
    if !identity.is_ascii()
        || identity
            .chars()
            .any(|c| c.is_ascii_control() || c.is_whitespace())
    {
        return false;
    }
    let Some(authority) = identity.strip_prefix("https://") else {
        return false;
    };
    if authority.is_empty()
        || authority.contains(['/', '?', '#', '@', '\\', '[', ']'])
        || authority.matches(':').count() > 1
    {
        return false;
    }
    let (host, port) = authority
        .rsplit_once(':')
        .map_or((authority, None), |(host, port)| (host, Some(port)));
    if !valid_canonical_dns_name(host) {
        return false;
    }
    match port {
        None => true,
        Some(port) => {
            !(port.len() > 1 && port.starts_with('0'))
                && port
                    .parse::<u16>()
                    .is_ok_and(|port| port != 0 && port != 443)
        }
    }
}

fn valid_canonical_dns_name(host: &str) -> bool {
    if host.len() > 253
        || !host.contains('.')
        || host.parse::<std::net::Ipv4Addr>().is_ok()
        || host.bytes().any(|b| b.is_ascii_uppercase())
    {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && label
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            && label
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
    })
}

#[cfg(test)]
mod issuer_identity_tests {
    use super::valid_https_issuer_identity;

    #[test]
    fn accepts_only_the_documented_canonical_https_origin_grammar() {
        for identity in [
            "https://issuer.example",
            "https://pid-1.issuer.example",
            "https://issuer.example:8443",
        ] {
            assert!(valid_https_issuer_identity(identity), "rejected {identity}");
        }

        for identity in [
            "http://issuer.example",
            "HTTPS://issuer.example",
            "https://",
            "https://issuer",
            "https://Issuer.example",
            "https://issuer.example/",
            "https://issuer.example/path",
            "https://issuer.example?tenant=1",
            "https://issuer.example#fragment",
            "https://user@issuer.example",
            "https://issuer.example\\redirect",
            "https://issuer..example",
            "https://-issuer.example",
            "https://issuer-.example",
            "https://issuer_example.test",
            "https://127.0.0.1",
            "https://[2001:db8::1]",
            "https://issuer.example:",
            "https://issuer.example:0",
            "https://issuer.example:443",
            "https://issuer.example:08443",
            "https://issuer.example:65536",
            "https://issuer.example:abc",
            "https://issuer.example :8443",
            "https://issuer.example\n",
        ] {
            assert!(
                !valid_https_issuer_identity(identity),
                "accepted {identity:?}"
            );
        }
    }
}

#[derive(Clone, Debug)]
struct BuiltPath {
    supplied_indices: Vec<usize>,
    anchor_index: usize,
}

#[derive(Debug, Default)]
struct PathSearch {
    complete: Vec<BuiltPath>,
    steps: usize,
    saw_loop: bool,
    saw_authority_key_mismatch: bool,
    budget_exceeded: bool,
}

fn certificate_eq(left: &ParsedCert, right: &ParsedCert) -> bool {
    left.tbs_der == right.tbs_der && left.signature == right.signature
}

fn issuer_name_matches(child: &ParsedCert, parent: &ParsedCert) -> bool {
    child.constraints.issuer_der == parent.constraints.subject_der
}

fn authority_key_matches(child: &ParsedCert, parent: &ParsedCert) -> bool {
    match (
        child.constraints.authority_key_identifier.as_ref(),
        parent.constraints.subject_key_identifier.as_ref(),
    ) {
        (Some(authority), Some(subject)) => authority == subject,
        _ => true,
    }
}

fn count_step(search: &mut PathSearch) -> bool {
    search.steps += 1;
    if search.steps > MAX_PATH_BUILD_STEPS {
        search.budget_exceeded = true;
        false
    } else {
        true
    }
}

fn explore_paths(
    current: usize,
    supplied: &[ParsedCert],
    anchors: &[ParsedCert],
    path: &mut Vec<usize>,
    search: &mut PathSearch,
) {
    if search.budget_exceeded || !count_step(search) {
        return;
    }

    let child = &supplied[current];
    let mut issuer_candidates = 0usize;

    for (anchor_index, anchor) in anchors.iter().enumerate() {
        if !issuer_name_matches(child, anchor) {
            continue;
        }
        if !authority_key_matches(child, anchor) {
            search.saw_authority_key_mismatch = true;
            continue;
        }
        issuer_candidates += 1;
        if issuer_candidates > MAX_ISSUER_CANDIDATES || !count_step(search) {
            search.budget_exceeded = true;
            return;
        }
        if search.complete.len() >= MAX_COMPLETE_PATHS {
            search.budget_exceeded = true;
            return;
        }
        search.complete.push(BuiltPath {
            supplied_indices: path.clone(),
            anchor_index,
        });
    }

    for (parent_index, parent) in supplied.iter().enumerate() {
        if parent_index == current || !issuer_name_matches(child, parent) {
            continue;
        }
        if !authority_key_matches(child, parent) {
            search.saw_authority_key_mismatch = true;
            continue;
        }
        issuer_candidates += 1;
        if issuer_candidates > MAX_ISSUER_CANDIDATES || !count_step(search) {
            search.budget_exceeded = true;
            return;
        }
        if path.contains(&parent_index) {
            search.saw_loop = true;
            continue;
        }
        path.push(parent_index);
        explore_paths(parent_index, supplied, anchors, path, search);
        path.pop();
        if search.budget_exceeded {
            return;
        }
    }
}

fn validate_built_path(
    path: &[ParsedCert],
    now: i64,
    verifier: &dyn Verifier,
) -> Result<(), X509Error> {
    let leaf = path
        .first()
        .ok_or(X509Error::PathInvalid("empty constructed path"))?;

    for certificate in path {
        if !certificate.constraints.signature_algorithms_match {
            return Err(X509Error::PathInvalid(
                "TBSCertificate and outer signature algorithms differ",
            ));
        }
        if certificate.constraints.unsupported_critical_extension {
            return Err(X509Error::PathInvalid(
                "unsupported critical certificate extension",
            ));
        }
        if now < certificate.not_before || now > certificate.not_after {
            return Err(X509Error::PathInvalid(
                "certificate expired or not yet valid",
            ));
        }
    }

    if leaf.is_ca {
        return Err(X509Error::PathInvalid("leaf certificate is a CA"));
    }
    if !leaf.constraints.key_usage_present {
        return Err(X509Error::PathInvalid("leaf KeyUsage is missing"));
    }
    if !leaf.constraints.digital_signature {
        return Err(X509Error::PathInvalid(
            "leaf KeyUsage lacks digitalSignature",
        ));
    }

    for (index, certificate) in path.iter().enumerate().skip(1) {
        if !certificate.constraints.basic_constraints_present || !certificate.is_ca {
            return Err(X509Error::PathInvalid(
                "issuer BasicConstraints does not authorize a CA",
            ));
        }
        if !certificate.constraints.basic_constraints_critical {
            return Err(X509Error::PathInvalid(
                "issuer BasicConstraints is not critical",
            ));
        }
        if !certificate.constraints.key_usage_present {
            return Err(X509Error::PathInvalid("issuer KeyUsage is missing"));
        }
        if !certificate.constraints.key_cert_sign {
            return Err(X509Error::PathInvalid("issuer KeyUsage lacks keyCertSign"));
        }
        let non_self_issued_ca_below = path[1..index]
            .iter()
            .filter(|subordinate| {
                subordinate.constraints.subject_der != subordinate.constraints.issuer_der
            })
            .count();
        if certificate
            .constraints
            .path_len_constraint
            .is_some_and(|limit| non_self_issued_ca_below > usize::from(limit))
        {
            return Err(X509Error::PathInvalid(
                "BasicConstraints pathLenConstraint exceeded",
            ));
        }
    }

    for pair in path.windows(2) {
        let child = &pair[0];
        let parent = &pair[1];
        if !issuer_name_matches(child, parent) {
            return Err(X509Error::PathInvalid("issuer/subject mismatch"));
        }
        if !authority_key_matches(child, parent) {
            return Err(X509Error::PathInvalid("authority key identifier mismatch"));
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
    Ok(())
}

/// Step 1 — build one deterministic, bounded leaf-to-anchor path from an unordered certificate
/// bundle, then validate the first strict RFC 5280 slice: time, signatures, AKI/SKI issuer
/// selection, unknown critical extensions, BasicConstraints/pathLen and role-specific KeyUsage.
/// Duplicate bundles, cycles and multiple complete paths fail closed. Name constraints, policy
/// processing, algorithm profiles and EUDI service profiles remain explicit follow-up work.
/// The independently configured `trust_anchors` are the only trust authority: a peer bundle that
/// redundantly supplies one of those roots is rejected instead of treating peer material as trust.
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
    if chain_der.len() > MAX_SUPPLIED_CERTIFICATES || trust_anchors.len() > MAX_TRUST_ANCHORS {
        return Err(X509Error::PathInvalid(
            "certificate path resource budget exceeded",
        ));
    }
    if trust_anchors.is_empty() {
        return Err(X509Error::PathInvalid("no trust anchor for chain"));
    }
    for (index, certificate) in chain_der.iter().enumerate() {
        if chain_der[..index].iter().any(|prior| prior == certificate) {
            return Err(X509Error::PathInvalid(
                "duplicate certificate in supplied chain",
            ));
        }
    }
    for (index, anchor) in trust_anchors.iter().enumerate() {
        if trust_anchors[..index]
            .iter()
            .any(|prior| certificate_eq(prior, anchor))
        {
            return Err(X509Error::PathInvalid("duplicate trust anchor"));
        }
    }

    let mut supplied = chain_der
        .iter()
        .map(|certificate| parse_cert(certificate))
        .collect::<Result<Vec<_>, _>>()?;
    supplied.sort_by(|left, right| {
        left.tbs_der
            .cmp(&right.tbs_der)
            .then_with(|| left.signature.cmp(&right.signature))
    });
    let mut anchors = trust_anchors.to_vec();
    anchors.sort_by(|left, right| {
        left.tbs_der
            .cmp(&right.tbs_der)
            .then_with(|| left.signature.cmp(&right.signature))
    });
    if supplied.iter().any(|certificate| {
        anchors
            .iter()
            .any(|anchor| certificate_eq(certificate, anchor))
    }) {
        return Err(X509Error::PathInvalid(
            "trust anchor must not be supplied in the certificate chain",
        ));
    }

    // A leaf is the one supplied certificate that does not issue another supplied certificate.
    // Name-only relationships identify the topology; AKI/SKI is applied while traversing so a
    // mismatch produces a path error rather than manufacturing a second apparent leaf.
    let mut is_parent = vec![false; supplied.len()];
    for (child_index, child) in supplied.iter().enumerate() {
        for (parent_index, parent) in supplied.iter().enumerate() {
            if child_index != parent_index && issuer_name_matches(child, parent) {
                is_parent[parent_index] = true;
            }
        }
    }
    let leaves = is_parent
        .iter()
        .enumerate()
        .filter_map(|(index, parent)| (!parent).then_some(index))
        .collect::<Vec<_>>();
    let leaf_index = match leaves.as_slice() {
        [leaf] => *leaf,
        [] => return Err(X509Error::PathInvalid("certificate path contains a loop")),
        _ => {
            return Err(X509Error::PathInvalid(
                "certificate bundle has ambiguous leaves",
            ));
        }
    };

    let mut search = PathSearch::default();
    let mut current_path = vec![leaf_index];
    explore_paths(
        leaf_index,
        &supplied,
        &anchors,
        &mut current_path,
        &mut search,
    );
    if search.budget_exceeded {
        return Err(X509Error::PathInvalid(
            "certificate path resource budget exceeded",
        ));
    }
    // Topology alone is not ambiguity: a same-subject decoy may fail signature or role checks.
    // Validate every bounded completion and require exactly one cryptographically valid path.
    let mut valid_path = None;
    let mut first_validation_error = None;
    for built in search.complete {
        let mut candidate = built
            .supplied_indices
            .iter()
            .map(|index| supplied[*index].clone())
            .collect::<Vec<_>>();
        candidate.push(anchors[built.anchor_index].clone());
        match validate_built_path(&candidate, now, verifier) {
            Ok(()) if valid_path.is_none() => valid_path = Some(candidate),
            Ok(()) => {
                return Err(X509Error::PathInvalid(
                    "certificate bundle has ambiguous trust paths",
                ));
            }
            Err(error) if first_validation_error.is_none() => {
                first_validation_error = Some(error);
            }
            Err(_) => {}
        }
    }
    if let Some(path) = valid_path {
        return Ok(path);
    }
    if let Some(error) = first_validation_error {
        return Err(error);
    }
    if search.saw_loop {
        return Err(X509Error::PathInvalid("certificate path contains a loop"));
    }
    if search.saw_authority_key_mismatch {
        return Err(X509Error::PathInvalid("authority key identifier mismatch"));
    }
    Err(X509Error::PathInvalid("no trust anchor for chain"))
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
