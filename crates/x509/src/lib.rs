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
//! Parsing and profile evaluation are pure logic (via RustCrypto `x509-cert`/`der`/`pkcs1`).
//! Cryptographic public-key validation and certificate-signature verification go through
//! [`crypto_traits::Verifier`]; this crate never implements a signature algorithm.

use std::collections::BTreeSet;

use crypto_traits::{CertificatePublicKeyAlg, CertificateSignatureAlg, Verifier};
use der::{asn1::ObjectIdentifier, Decode, Encode, Tag, Tagged};
use pkcs1::RsaPublicKey;
use x509_cert::ext::pkix::{
    constraints::{name::GeneralSubtree, NameConstraints},
    name::GeneralName,
    AuthorityKeyIdentifier, BasicConstraints, CertificatePolicies, ExtendedKeyUsage, KeyUsage,
    SubjectAltName, SubjectKeyIdentifier,
};
use x509_cert::name::Name;
use x509_cert::spki::AlgorithmIdentifierOwned;
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
const OID_NAME_CONSTRAINTS: &str = "2.5.29.30";

// Signature and SPKI algorithm OIDs accepted by this bounded certificate profile. The strength
// floor is P-256/P-384, Ed25519, or RSA 2048..=8192 with exponent 65537; signatures require
// SHA-256 or stronger. PKCS#1 v1.5 RSA is retained for the service-scoped GlobalSign R45 reader
// hierarchy. Final EUDI service profiles may narrow this interoperability set further.
const OID_ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";
const OID_ECDSA_SHA384: &str = "1.2.840.10045.4.3.3";
const OID_ED25519: &str = "1.3.101.112";
const OID_RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
const OID_RSA_SHA256: &str = "1.2.840.113549.1.1.11";
const OID_RSA_SHA384: &str = "1.2.840.113549.1.1.12";
const OID_RSA_SHA512: &str = "1.2.840.113549.1.1.13";
const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
const OID_P256: &str = "1.2.840.10045.3.1.7";
const OID_P384: &str = "1.3.132.0.34";

// Explicit resource budgets for hostile certificate bundles. The first strict slice intentionally
// supports short wallet trust paths rather than exposing an unbounded graph search.
const MAX_SUPPLIED_CERTIFICATES: usize = 8;
const MAX_TRUST_ANCHORS: usize = 64;
const MAX_CERTIFICATE_DER_BYTES: usize = 64 * 1024;
const MAX_EXTENSIONS_PER_CERTIFICATE: usize = 32;
const MAX_GENERAL_NAMES_PER_CERTIFICATE: usize = 64;
const MAX_NAME_CONSTRAINTS_PER_CERTIFICATE: usize = 64;
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
    /// A subject public key type, parameter set or strength outside the explicit policy.
    UnsupportedPublicKey,
}

/// A parsed certificate reduced to the fields the profile and path checks need.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedCert {
    pub tbs_der: Vec<u8>,
    pub signature: Vec<u8>,
    pub sig_alg: CertificateSignatureAlg,
    /// SubjectPublicKeyInfo (DER).
    pub spki_der: Vec<u8>,
    /// The algorithm-native public key: uncompressed SEC1 for EC, 32 raw bytes for Ed25519, or a
    /// DER PKCS#1 `RSAPublicKey`. This is the form the crypto backend validates and verifies with.
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
    canonical_subject: CanonicalName,
    canonical_issuer: CanonicalName,
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
    public_key_algorithm: Option<CertificatePublicKey>,
    names: CertificateNames,
    name_constraints_present: bool,
    name_constraints: Option<ParsedNameConstraints>,
    name_constraints_error: Option<&'static str>,
}

type CertificatePublicKey = CertificatePublicKeyAlg;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct CertificateNames {
    dns: Vec<String>,
    emails: Vec<String>,
    uris: Vec<String>,
    ips: Vec<Vec<u8>>,
    directories: Vec<CanonicalName>,
}

type CanonicalName = Vec<Vec<(String, String)>>;

#[derive(Clone, Debug, PartialEq, Eq)]
enum SupportedNameConstraint {
    Dns(String),
    Email(String),
    UriHost(String),
    Ip { address: Vec<u8>, mask: Vec<u8> },
    Directory(CanonicalName),
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct ParsedNameConstraints {
    permitted: Vec<SupportedNameConstraint>,
    excluded: Vec<SupportedNameConstraint>,
}

fn parameters_absent(algorithm: &AlgorithmIdentifierOwned) -> bool {
    algorithm.parameters.is_none()
}

fn canonical_directory_value(value: &der::asn1::Any) -> Option<String> {
    let decoded = match value.tag() {
        Tag::Utf8String => std::str::from_utf8(value.value()).ok()?.to_owned(),
        Tag::PrintableString | Tag::Ia5String | Tag::TeletexString => value
            .value()
            .is_ascii()
            .then(|| value.value().iter().map(|byte| char::from(*byte)).collect())?,
        Tag::BmpString => {
            let chunks = value.value().chunks_exact(2);
            if !chunks.remainder().is_empty() {
                return None;
            }
            char::decode_utf16(chunks.map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]])))
                .collect::<Result<String, _>>()
                .ok()?
        }
        _ => return None,
    };
    let folded = decoded
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    (!folded.is_empty()).then_some(folded)
}

fn canonical_name(name: &Name) -> Option<CanonicalName> {
    if name.0.is_empty() || name.0.len() > MAX_GENERAL_NAMES_PER_CERTIFICATE {
        return None;
    }
    name.0
        .iter()
        .map(|rdn| {
            if rdn.0.is_empty() || rdn.0.len() > MAX_GENERAL_NAMES_PER_CERTIFICATE {
                return None;
            }
            let mut attributes = rdn
                .0
                .iter()
                .map(|attribute| {
                    Some((
                        attribute.oid.to_string(),
                        canonical_directory_value(&attribute.value)?,
                    ))
                })
                .collect::<Option<Vec<_>>>()?;
            attributes.sort();
            Some(attributes)
        })
        .collect()
}

fn canonical_email(value: &str, constraint: bool) -> Option<String> {
    if value.is_empty() || !value.is_ascii() || value.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return None;
    }
    if let Some((local, domain)) = value.rsplit_once('@') {
        if constraint && value.starts_with('.') || local.is_empty() {
            return None;
        }
        let domain = canonical_dns_name(domain)?;
        return Some(format!("{local}@{domain}"));
    }
    constraint
        .then(|| canonical_uri_constraint(value))
        .flatten()
}

fn parameters_absent_or_null(algorithm: &AlgorithmIdentifierOwned) -> bool {
    algorithm
        .parameters
        .as_ref()
        .is_none_or(|parameters| parameters.tag() == Tag::Null && parameters.value().is_empty())
}

fn map_sig_alg(algorithm: &AlgorithmIdentifierOwned) -> Result<CertificateSignatureAlg, X509Error> {
    let oid = algorithm.oid.to_string();
    match oid.as_str() {
        OID_ECDSA_SHA256 if parameters_absent(algorithm) => {
            Ok(CertificateSignatureAlg::EcdsaSha256)
        }
        OID_ECDSA_SHA384 if parameters_absent(algorithm) => {
            Ok(CertificateSignatureAlg::EcdsaSha384)
        }
        OID_ED25519 if parameters_absent(algorithm) => Ok(CertificateSignatureAlg::Ed25519),
        OID_RSA_SHA256 if parameters_absent_or_null(algorithm) => {
            Ok(CertificateSignatureAlg::RsaPkcs1Sha256)
        }
        OID_RSA_SHA384 if parameters_absent_or_null(algorithm) => {
            Ok(CertificateSignatureAlg::RsaPkcs1Sha384)
        }
        OID_RSA_SHA512 if parameters_absent_or_null(algorithm) => {
            Ok(CertificateSignatureAlg::RsaPkcs1Sha512)
        }
        _ => Err(X509Error::UnsupportedSignatureAlg),
    }
}

fn parameters_are_null(algorithm: &AlgorithmIdentifierOwned) -> bool {
    algorithm
        .parameters
        .as_ref()
        .is_some_and(|parameters| parameters.tag() == Tag::Null && parameters.value().is_empty())
}

fn parse_public_key(
    algorithm: &AlgorithmIdentifierOwned,
    public_key_raw: &[u8],
) -> Result<CertificatePublicKey, X509Error> {
    let oid = algorithm.oid.to_string();
    match oid.as_str() {
        OID_EC_PUBLIC_KEY => {
            let curve = algorithm
                .parameters
                .as_ref()
                .ok_or(X509Error::UnsupportedPublicKey)?
                .decode_as::<ObjectIdentifier>()
                .map_err(|_| X509Error::UnsupportedPublicKey)?
                .to_string();
            match (curve.as_str(), public_key_raw.len(), public_key_raw.first()) {
                (OID_P256, 65, Some(0x04)) => Ok(CertificatePublicKey::EcP256),
                (OID_P384, 97, Some(0x04)) => Ok(CertificatePublicKey::EcP384),
                _ => Err(X509Error::UnsupportedPublicKey),
            }
        }
        OID_ED25519 if parameters_absent(algorithm) && public_key_raw.len() == 32 => {
            Ok(CertificatePublicKey::Ed25519)
        }
        OID_RSA_ENCRYPTION if parameters_are_null(algorithm) => {
            let key = RsaPublicKey::from_der(public_key_raw)
                .map_err(|_| X509Error::UnsupportedPublicKey)?;
            let modulus = key.modulus.as_bytes();
            let modulus_bits = modulus
                .first()
                .map(|first| (modulus.len() - 1) * 8 + (8 - first.leading_zeros() as usize))
                .unwrap_or(0);
            if !(2048..=8192).contains(&modulus_bits)
                || key.public_exponent.as_bytes() != [0x01, 0x00, 0x01]
            {
                return Err(X509Error::UnsupportedPublicKey);
            }
            Ok(CertificatePublicKey::Rsa)
        }
        _ => Err(X509Error::UnsupportedPublicKey),
    }
}

fn canonical_dns_name(value: &str) -> Option<String> {
    if value.is_empty()
        || value.len() > 253
        || value.starts_with('.')
        || value.ends_with('.')
        || value.bytes().any(|byte| !byte.is_ascii())
    {
        return None;
    }
    let canonical = value.to_ascii_lowercase();
    canonical
        .split('.')
        .all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
        .then_some(canonical)
}

fn canonical_uri_constraint(value: &str) -> Option<String> {
    let (subdomains_only, host) = value
        .strip_prefix('.')
        .map_or((false, value), |host| (true, host));
    let host = canonical_dns_name(host)?;
    if host.parse::<std::net::Ipv4Addr>().is_ok() {
        return None;
    }
    Some(if subdomains_only {
        format!(".{host}")
    } else {
        host
    })
}

fn valid_ip_constraint(address: &[u8], mask: &[u8]) -> bool {
    if address.len() != mask.len() || !matches!(address.len(), 4 | 16) {
        return false;
    }
    let mut saw_zero = false;
    for byte in mask {
        for bit in (0..8).rev() {
            let set = byte & (1 << bit) != 0;
            if saw_zero && set {
                return false;
            }
            saw_zero |= !set;
        }
    }
    address
        .iter()
        .zip(mask)
        .all(|(address, mask)| address & !mask == 0)
}

fn parse_name_constraints(parsed: NameConstraints) -> Result<ParsedNameConstraints, &'static str> {
    if parsed
        .permitted_subtrees
        .as_ref()
        .is_some_and(Vec::is_empty)
        || parsed.excluded_subtrees.as_ref().is_some_and(Vec::is_empty)
    {
        return Err("NameConstraints contains an empty GeneralSubtrees");
    }
    let permitted_subtrees = parsed.permitted_subtrees.unwrap_or_default();
    let excluded_subtrees = parsed.excluded_subtrees.unwrap_or_default();
    let total = permitted_subtrees
        .len()
        .checked_add(excluded_subtrees.len())
        .ok_or("name constraints resource budget exceeded")?;
    if total == 0 {
        return Err("NameConstraints is empty");
    }
    if total > MAX_NAME_CONSTRAINTS_PER_CERTIFICATE {
        return Err("name constraints resource budget exceeded");
    }

    fn parse_subtrees(
        subtrees: Vec<GeneralSubtree>,
    ) -> Result<Vec<SupportedNameConstraint>, &'static str> {
        subtrees
            .into_iter()
            .map(|subtree| {
                if subtree.minimum != 0 || subtree.maximum.is_some() {
                    return Err("unsupported name constraint distance");
                }
                match subtree.base {
                    GeneralName::DnsName(name) => canonical_dns_name(name.as_str())
                        .map(SupportedNameConstraint::Dns)
                        .ok_or("malformed DNS name constraint"),
                    GeneralName::UniformResourceIdentifier(host) => {
                        canonical_uri_constraint(host.as_str())
                            .map(SupportedNameConstraint::UriHost)
                            .ok_or("malformed URI name constraint")
                    }
                    GeneralName::Rfc822Name(email) => canonical_email(email.as_str(), true)
                        .map(SupportedNameConstraint::Email)
                        .ok_or("malformed rfc822Name constraint"),
                    GeneralName::DirectoryName(name) => canonical_name(&name)
                        .map(SupportedNameConstraint::Directory)
                        .ok_or("malformed directoryName constraint"),
                    GeneralName::IpAddress(value) => {
                        let bytes = value.as_bytes();
                        let half = bytes.len() / 2;
                        if !matches!(bytes.len(), 8 | 32)
                            || !valid_ip_constraint(&bytes[..half], &bytes[half..])
                        {
                            return Err("malformed IP name constraint");
                        }
                        Ok(SupportedNameConstraint::Ip {
                            address: bytes[..half].to_vec(),
                            mask: bytes[half..].to_vec(),
                        })
                    }
                    GeneralName::OtherName(_)
                    | GeneralName::EdiPartyName(_)
                    | GeneralName::RegisteredId(_) => Err("unsupported name constraint form"),
                }
            })
            .collect()
    }

    Ok(ParsedNameConstraints {
        permitted: parse_subtrees(permitted_subtrees)?,
        excluded: parse_subtrees(excluded_subtrees)?,
    })
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
    let sig_alg = map_sig_alg(&cert.signature_algorithm)?;
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
    let public_key_algorithm =
        parse_public_key(&tbs.subject_public_key_info.algorithm, &public_key_raw)?;

    let not_before = tbs.validity.not_before.to_unix_duration().as_secs() as i64;
    let not_after = tbs.validity.not_after.to_unix_duration().as_secs() as i64;

    let mut is_ca = false;
    let mut eku = Vec::new();
    let mut policies = Vec::new();
    let mut uri_sans = Vec::new();
    let mut constraints = CertificateConstraints {
        subject_der: tbs.subject.to_der().map_err(|_| X509Error::Der)?,
        issuer_der: tbs.issuer.to_der().map_err(|_| X509Error::Der)?,
        canonical_subject: canonical_name(&tbs.subject).ok_or(X509Error::Der)?,
        canonical_issuer: canonical_name(&tbs.issuer).ok_or(X509Error::Der)?,
        signature_algorithms_match: tbs.signature == cert.signature_algorithm,
        public_key_algorithm: Some(public_key_algorithm),
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
                    if san.0.is_empty() || san.0.len() > MAX_GENERAL_NAMES_PER_CERTIFICATE {
                        return Err(X509Error::Der);
                    }
                    for name in san.0 {
                        match name {
                            GeneralName::DnsName(name) => {
                                constraints.names.dns.push(name.to_string());
                            }
                            GeneralName::UniformResourceIdentifier(uri) => {
                                let uri = uri.to_string();
                                uri_sans.push(uri.clone());
                                constraints.names.uris.push(uri);
                            }
                            GeneralName::IpAddress(address) => {
                                constraints.names.ips.push(address.as_bytes().to_vec());
                            }
                            GeneralName::Rfc822Name(email) => {
                                constraints.names.emails.push(email.to_string());
                            }
                            GeneralName::DirectoryName(name) => {
                                constraints
                                    .names
                                    .directories
                                    .push(canonical_name(&name).ok_or(X509Error::Der)?);
                            }
                            GeneralName::OtherName(_)
                            | GeneralName::EdiPartyName(_)
                            | GeneralName::RegisteredId(_) => {}
                        }
                    }
                }
                OID_NAME_CONSTRAINTS => {
                    let parsed = NameConstraints::from_der(ext.extn_value.as_bytes())
                        .map_err(|_| X509Error::Der)?;
                    constraints.name_constraints_present = true;
                    if !ext.critical {
                        constraints.name_constraints_error =
                            Some("NameConstraints must be critical");
                    } else {
                        match parse_name_constraints(parsed) {
                            Ok(parsed) => constraints.name_constraints = Some(parsed),
                            Err(error) => constraints.name_constraints_error = Some(error),
                        }
                    }
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

    constraints
        .names
        .directories
        .push(constraints.canonical_subject.clone());

    if constraints.name_constraints_present
        && !is_ca
        && constraints.name_constraints_error.is_none()
    {
        constraints.name_constraints_error =
            Some("NameConstraints only permitted in CA certificates");
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
    child.constraints.canonical_issuer == parent.constraints.canonical_subject
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

fn dns_constraint_matches(name: &str, constraint: &str) -> bool {
    name == constraint
        || name
            .strip_suffix(constraint)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

fn uri_constraint_matches(host: &str, constraint: &str) -> bool {
    constraint
        .strip_prefix('.')
        .map_or(host == constraint, |domain| {
            host != domain && host.ends_with(constraint)
        })
}

fn constrained_uri_host(uri: &str) -> Option<String> {
    if !uri.is_ascii()
        || uri
            .chars()
            .any(|character| character.is_ascii_control() || character.is_whitespace())
    {
        return None;
    }
    let colon = uri.find(':')?;
    let scheme = &uri[..colon];
    if scheme.is_empty()
        || !scheme
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphabetic)
        || !scheme
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
    {
        return None;
    }
    let authority_and_rest = uri[colon + 1..].strip_prefix("//")?;
    let authority_end = authority_and_rest
        .find(['/', '?', '#'])
        .unwrap_or(authority_and_rest.len());
    let authority = &authority_and_rest[..authority_end];
    if authority.is_empty() || authority.matches('@').count() > 1 {
        return None;
    }
    let host_and_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    // A constrained URI must contain a DNS host. Bracketed IP literals, unbracketed IPv6 and
    // percent-encoded host spellings deliberately fail closed.
    if host_and_port.starts_with('[') || host_and_port.matches(':').count() > 1 {
        return None;
    }
    let (host, port) = host_and_port
        .rsplit_once(':')
        .map_or((host_and_port, None), |(host, port)| (host, Some(port)));
    if port.is_some_and(|port| port.is_empty() || port.parse::<u16>().is_err()) {
        return None;
    }
    let host = canonical_dns_name(host)?;
    (host.parse::<std::net::Ipv4Addr>().is_err()).then_some(host)
}

fn ip_constraint_matches(name: &[u8], address: &[u8], mask: &[u8]) -> bool {
    name.len() == address.len()
        && address.len() == mask.len()
        && name
            .iter()
            .zip(address)
            .zip(mask)
            .all(|((name, address), mask)| name & mask == address & mask)
}

fn email_constraint_matches(email: &str, constraint: &str) -> bool {
    if constraint.contains('@') {
        return email == constraint;
    }
    let Some((_, domain)) = email.rsplit_once('@') else {
        return false;
    };
    uri_constraint_matches(domain, constraint)
        || (!constraint.starts_with('.') && dns_constraint_matches(domain, constraint))
}

fn directory_constraint_matches(name: &CanonicalName, constraint: &CanonicalName) -> bool {
    name.len() >= constraint.len() && name[..constraint.len()] == constraint[..]
}

fn enforce_name_constraints(
    names: &CertificateNames,
    constraints: &ParsedNameConstraints,
) -> Result<(), X509Error> {
    let permitted_dns = constraints.permitted.iter().filter_map(|constraint| {
        if let SupportedNameConstraint::Dns(value) = constraint {
            Some(value.as_str())
        } else {
            None
        }
    });
    let excluded_dns = constraints.excluded.iter().filter_map(|constraint| {
        if let SupportedNameConstraint::Dns(value) = constraint {
            Some(value.as_str())
        } else {
            None
        }
    });
    let permitted_dns = permitted_dns.collect::<Vec<_>>();
    let excluded_dns = excluded_dns.collect::<Vec<_>>();
    for name in &names.dns {
        let name = canonical_dns_name(name)
            .ok_or(X509Error::PathInvalid("constrained DNS name is malformed"))?;
        if excluded_dns
            .iter()
            .any(|constraint| dns_constraint_matches(&name, constraint))
        {
            return Err(X509Error::PathInvalid(
                "name constraints exclude certificate name",
            ));
        }
        if !permitted_dns.is_empty()
            && !permitted_dns
                .iter()
                .any(|constraint| dns_constraint_matches(&name, constraint))
        {
            return Err(X509Error::PathInvalid(
                "name constraints do not permit certificate name",
            ));
        }
    }

    let permitted_email = constraints
        .permitted
        .iter()
        .filter_map(|constraint| match constraint {
            SupportedNameConstraint::Email(value) => Some(value.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();
    let excluded_email = constraints
        .excluded
        .iter()
        .filter_map(|constraint| match constraint {
            SupportedNameConstraint::Email(value) => Some(value.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();
    for email in &names.emails {
        let email = canonical_email(email, false).ok_or(X509Error::PathInvalid(
            "constrained rfc822Name is malformed",
        ))?;
        if excluded_email
            .iter()
            .any(|constraint| email_constraint_matches(&email, constraint))
        {
            return Err(X509Error::PathInvalid(
                "name constraints exclude certificate name",
            ));
        }
        if !permitted_email.is_empty()
            && !permitted_email
                .iter()
                .any(|constraint| email_constraint_matches(&email, constraint))
        {
            return Err(X509Error::PathInvalid(
                "name constraints do not permit certificate name",
            ));
        }
    }

    let permitted_uri = constraints.permitted.iter().filter_map(|constraint| {
        if let SupportedNameConstraint::UriHost(value) = constraint {
            Some(value.as_str())
        } else {
            None
        }
    });
    let excluded_uri = constraints.excluded.iter().filter_map(|constraint| {
        if let SupportedNameConstraint::UriHost(value) = constraint {
            Some(value.as_str())
        } else {
            None
        }
    });
    let permitted_uri = permitted_uri.collect::<Vec<_>>();
    let excluded_uri = excluded_uri.collect::<Vec<_>>();
    if !permitted_uri.is_empty() || !excluded_uri.is_empty() {
        for uri in &names.uris {
            let host = constrained_uri_host(uri).ok_or(X509Error::PathInvalid(
                "constrained URI has no canonical DNS host",
            ))?;
            if excluded_uri
                .iter()
                .any(|constraint| uri_constraint_matches(&host, constraint))
            {
                return Err(X509Error::PathInvalid(
                    "name constraints exclude certificate name",
                ));
            }
            if !permitted_uri.is_empty()
                && !permitted_uri
                    .iter()
                    .any(|constraint| uri_constraint_matches(&host, constraint))
            {
                return Err(X509Error::PathInvalid(
                    "name constraints do not permit certificate name",
                ));
            }
        }
    }

    let permitted_ip = constraints.permitted.iter().filter_map(|constraint| {
        if let SupportedNameConstraint::Ip { address, mask } = constraint {
            Some((address.as_slice(), mask.as_slice()))
        } else {
            None
        }
    });
    let excluded_ip = constraints.excluded.iter().filter_map(|constraint| {
        if let SupportedNameConstraint::Ip { address, mask } = constraint {
            Some((address.as_slice(), mask.as_slice()))
        } else {
            None
        }
    });
    let permitted_ip = permitted_ip.collect::<Vec<_>>();
    let excluded_ip = excluded_ip.collect::<Vec<_>>();
    for name in &names.ips {
        if !matches!(name.len(), 4 | 16) {
            return Err(X509Error::PathInvalid(
                "constrained IP address is malformed",
            ));
        }
        if excluded_ip
            .iter()
            .any(|(address, mask)| ip_constraint_matches(name, address, mask))
        {
            return Err(X509Error::PathInvalid(
                "name constraints exclude certificate name",
            ));
        }
        if !permitted_ip.is_empty()
            && !permitted_ip
                .iter()
                .any(|(address, mask)| ip_constraint_matches(name, address, mask))
        {
            return Err(X509Error::PathInvalid(
                "name constraints do not permit certificate name",
            ));
        }
    }

    let permitted_directory = constraints
        .permitted
        .iter()
        .filter_map(|constraint| match constraint {
            SupportedNameConstraint::Directory(value) => Some(value),
            _ => None,
        })
        .collect::<Vec<_>>();
    let excluded_directory = constraints
        .excluded
        .iter()
        .filter_map(|constraint| match constraint {
            SupportedNameConstraint::Directory(value) => Some(value),
            _ => None,
        })
        .collect::<Vec<_>>();
    for name in &names.directories {
        if excluded_directory
            .iter()
            .any(|constraint| directory_constraint_matches(name, constraint))
        {
            return Err(X509Error::PathInvalid(
                "name constraints exclude certificate name",
            ));
        }
        if !permitted_directory.is_empty()
            && !permitted_directory
                .iter()
                .any(|constraint| directory_constraint_matches(name, constraint))
        {
            return Err(X509Error::PathInvalid(
                "name constraints do not permit certificate name",
            ));
        }
    }
    Ok(())
}

fn validate_name_constraints(path: &[ParsedCert]) -> Result<(), X509Error> {
    for (issuer_index, issuer) in path.iter().enumerate().skip(1) {
        let Some(constraints) = issuer.constraints.name_constraints.as_ref() else {
            continue;
        };
        for (subject_index, subject) in path[..issuer_index].iter().enumerate() {
            let self_issued =
                subject.constraints.canonical_subject == subject.constraints.canonical_issuer;
            if subject_index != 0 && self_issued {
                continue;
            }
            enforce_name_constraints(&subject.constraints.names, constraints)?;
        }
    }
    Ok(())
}

fn signature_compatible_with_issuer(
    signature: CertificateSignatureAlg,
    issuer_key: CertificatePublicKey,
) -> bool {
    matches!(
        (signature, issuer_key),
        (
            CertificateSignatureAlg::EcdsaSha256 | CertificateSignatureAlg::EcdsaSha384,
            CertificatePublicKey::EcP256 | CertificatePublicKey::EcP384
        ) | (
            CertificateSignatureAlg::Ed25519,
            CertificatePublicKey::Ed25519
        ) | (
            CertificateSignatureAlg::RsaPkcs1Sha256
                | CertificateSignatureAlg::RsaPkcs1Sha384
                | CertificateSignatureAlg::RsaPkcs1Sha512,
            CertificatePublicKey::Rsa
        )
    )
}

#[cfg(test)]
mod strict_constraint_unit_tests {
    use super::*;
    use der::asn1::{Ia5String, OctetString};

    fn subtree(base: GeneralName) -> GeneralSubtree {
        GeneralSubtree {
            base,
            minimum: 0,
            maximum: None,
        }
    }

    fn permitted(subtrees: Vec<GeneralSubtree>) -> NameConstraints {
        NameConstraints {
            permitted_subtrees: Some(subtrees),
            excluded_subtrees: None,
        }
    }

    fn dns_subtree(value: &str) -> GeneralSubtree {
        subtree(GeneralName::DnsName(Ia5String::new(value).unwrap()))
    }

    #[test]
    fn supported_additional_forms_and_distances_are_checked_before_path_use() {
        let email = subtree(GeneralName::Rfc822Name(
            Ia5String::new("user@example.com").unwrap(),
        ));
        assert!(parse_name_constraints(permitted(vec![email])).is_ok());

        let directory = subtree(GeneralName::DirectoryName(Default::default()));
        assert_eq!(
            parse_name_constraints(permitted(vec![directory])),
            Err("malformed directoryName constraint")
        );

        let mut distance = dns_subtree("allowed.example");
        distance.minimum = 1;
        assert_eq!(
            parse_name_constraints(permitted(vec![distance])),
            Err("unsupported name constraint distance")
        );
        let mut maximum = dns_subtree("allowed.example");
        maximum.maximum = Some(1);
        assert_eq!(
            parse_name_constraints(permitted(vec![maximum])),
            Err("unsupported name constraint distance")
        );
    }

    #[test]
    fn canonical_names_and_new_constraint_forms_have_rfc_subtree_semantics() {
        use std::str::FromStr;

        let spaced = Name::from_str("CN= Alice   Example ,O=Example,C=DE").unwrap();
        let folded = Name::from_str("CN=alice example,O=example,C=de").unwrap();
        assert_eq!(canonical_name(&spaced), canonical_name(&folded));

        let subject =
            canonical_name(&Name::from_str("CN=Wallet Service,OU=PID,O=Example,C=DE").unwrap())
                .unwrap();
        let parent = canonical_name(&Name::from_str("O=Example,C=DE").unwrap()).unwrap();
        let sibling = canonical_name(&Name::from_str("O=Other,C=DE").unwrap()).unwrap();
        assert!(directory_constraint_matches(&subject, &parent));
        assert!(!directory_constraint_matches(&subject, &sibling));

        assert!(email_constraint_matches(
            "holder@team.example.com",
            "example.com"
        ));
        assert!(email_constraint_matches(
            "holder@team.example.com",
            ".example.com"
        ));
        assert!(!email_constraint_matches(
            "holder@example.com",
            ".example.com"
        ));
        assert!(email_constraint_matches(
            "holder@example.com",
            "holder@example.com"
        ));
        assert!(!email_constraint_matches(
            "other@example.com",
            "holder@example.com"
        ));
    }

    #[test]
    fn malformed_and_unbounded_constraints_are_rejected() {
        assert_eq!(
            parse_name_constraints(NameConstraints {
                permitted_subtrees: None,
                excluded_subtrees: None,
            }),
            Err("NameConstraints is empty")
        );
        assert_eq!(
            parse_name_constraints(NameConstraints {
                permitted_subtrees: Some(Vec::new()),
                excluded_subtrees: Some(vec![dns_subtree("blocked.example")]),
            }),
            Err("NameConstraints contains an empty GeneralSubtrees")
        );
        assert_eq!(
            parse_name_constraints(NameConstraints {
                permitted_subtrees: Some(vec![dns_subtree("allowed.example")]),
                excluded_subtrees: Some(Vec::new()),
            }),
            Err("NameConstraints contains an empty GeneralSubtrees")
        );
        assert_eq!(
            parse_name_constraints(permitted(vec![dns_subtree(".allowed.example")])),
            Err("malformed DNS name constraint")
        );
        assert_eq!(
            parse_name_constraints(permitted(vec![subtree(
                GeneralName::UniformResourceIdentifier(
                    Ia5String::new("https://allowed.example").unwrap(),
                ),
            )])),
            Err("malformed URI name constraint")
        );
        assert_eq!(
            parse_name_constraints(permitted(vec![subtree(GeneralName::IpAddress(
                OctetString::new([10, 0, 0, 0, 255, 0, 255, 0]).unwrap(),
            ))])),
            Err("malformed IP name constraint")
        );
        assert_eq!(
            parse_name_constraints(permitted(vec![dns_subtree("allowed.example"); 65])),
            Err("name constraints resource budget exceeded")
        );
    }

    #[test]
    fn uri_host_and_ip_matching_are_canonical_and_family_aware() {
        assert_eq!(
            constrained_uri_host("https://user@Issuer.Service.Example:8443/path"),
            Some("issuer.service.example".into())
        );
        assert_eq!(constrained_uri_host("urn:example:wallet"), None);
        assert_eq!(constrained_uri_host("https://192.0.2.1/path"), None);
        assert_eq!(constrained_uri_host("https://[2001:db8::1]/path"), None);
        assert!(uri_constraint_matches(
            "issuer.service.example",
            ".service.example"
        ));
        assert!(!uri_constraint_matches(
            "service.example",
            ".service.example"
        ));

        let address = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mask = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let mut inside = address;
        inside[15] = 1;
        let outside = [0x20, 0x01, 0x0d, 0xb9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert!(ip_constraint_matches(&inside, &address, &mask));
        assert!(!ip_constraint_matches(&outside, &address, &mask));
    }

    fn synthetic_cert(
        subject: &[u8],
        issuer: &[u8],
        dns: &[&str],
        name_constraints: Option<ParsedNameConstraints>,
    ) -> ParsedCert {
        ParsedCert {
            tbs_der: subject.to_vec(),
            signature: vec![1],
            sig_alg: CertificateSignatureAlg::EcdsaSha256,
            spki_der: vec![1],
            public_key_raw: vec![0x04; 65],
            subject: String::new(),
            issuer: String::new(),
            uri_sans: Vec::new(),
            not_before: 0,
            not_after: i64::MAX,
            is_ca: name_constraints.is_some(),
            eku: Vec::new(),
            policies: Vec::new(),
            constraints: CertificateConstraints {
                subject_der: subject.to_vec(),
                issuer_der: issuer.to_vec(),
                names: CertificateNames {
                    dns: dns.iter().map(|name| (*name).to_owned()).collect(),
                    ..CertificateNames::default()
                },
                name_constraints,
                ..CertificateConstraints::default()
            },
        }
    }

    #[test]
    fn self_issued_non_target_certificates_are_exempt_but_target_is_not() {
        let constraints = ParsedNameConstraints {
            permitted: vec![SupportedNameConstraint::Dns("allowed.example".into())],
            excluded: Vec::new(),
        };
        let leaf = synthetic_cert(b"leaf", b"rollover", &["wallet.allowed.example"], None);
        let rollover = synthetic_cert(b"rollover", b"rollover", &["outside.example"], None);
        let anchor = synthetic_cert(b"anchor", b"anchor", &[], Some(constraints.clone()));
        validate_name_constraints(&[leaf, rollover, anchor])
            .expect("the non-target self-issued rollover is exempt");

        let self_issued_target = synthetic_cert(b"leaf", b"leaf", &["outside.example"], None);
        let anchor = synthetic_cert(b"anchor", b"anchor", &[], Some(constraints));
        assert_eq!(
            validate_name_constraints(&[self_issued_target, anchor]),
            Err(X509Error::PathInvalid(
                "name constraints do not permit certificate name"
            ))
        );
    }

    #[test]
    fn signature_family_must_match_the_issuer_spki_not_the_subject_spki() {
        assert!(signature_compatible_with_issuer(
            CertificateSignatureAlg::EcdsaSha384,
            CertificatePublicKey::EcP256
        ));
        assert!(signature_compatible_with_issuer(
            CertificateSignatureAlg::RsaPkcs1Sha384,
            CertificatePublicKey::Rsa
        ));
        assert!(!signature_compatible_with_issuer(
            CertificateSignatureAlg::RsaPkcs1Sha384,
            CertificatePublicKey::EcP384
        ));
        assert!(!signature_compatible_with_issuer(
            CertificateSignatureAlg::EcdsaSha256,
            CertificatePublicKey::Rsa
        ));
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
        if let Some(error) = certificate.constraints.name_constraints_error {
            return Err(X509Error::PathInvalid(error));
        }
        let public_key_algorithm =
            certificate
                .constraints
                .public_key_algorithm
                .ok_or(X509Error::PathInvalid(
                    "certificate public key is unsupported",
                ))?;
        verifier
            .validate_certificate_public_key(public_key_algorithm, &certificate.public_key_raw)
            .map_err(|_| {
                X509Error::PathInvalid("certificate subject public key validation failed")
            })?;
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
                subordinate.constraints.canonical_subject
                    != subordinate.constraints.canonical_issuer
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

    validate_name_constraints(path)?;

    for pair in path.windows(2) {
        let child = &pair[0];
        let parent = &pair[1];
        if !issuer_name_matches(child, parent) {
            return Err(X509Error::PathInvalid("issuer/subject mismatch"));
        }
        if !authority_key_matches(child, parent) {
            return Err(X509Error::PathInvalid("authority key identifier mismatch"));
        }
        let issuer_key = parent
            .constraints
            .public_key_algorithm
            .ok_or(X509Error::PathInvalid("issuer public key is unsupported"))?;
        if !signature_compatible_with_issuer(child.sig_alg, issuer_key) {
            return Err(X509Error::PathInvalid(
                "certificate signature algorithm is incompatible with issuer public key",
            ));
        }
        verifier
            .verify_certificate(
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
/// bundle, then validate the current bounded RFC 5280 slice: time, profiled signature/SPKI
/// algorithms and strength, AKI/SKI issuer selection, supported name constraints, unknown critical
/// extensions, BasicConstraints/pathLen and role-specific KeyUsage. Duplicate bundles, cycles and
/// multiple complete paths fail closed. Unsupported name-constraint forms/distances also fail
/// closed. Canonical distinguished-name chaining and DNS, URI, IP, email and directory name
/// constraints are enforced; unsupported GeneralName forms still fail closed. Certificate
/// policy-tree processing, broader algorithms and final EUDI service profiles remain explicit
/// follow-up work.
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
