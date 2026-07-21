//! Bounded second-slice vectors for issue #11: RFC 5280 DNS/URI/IP name constraints and an
//! explicit certificate-only signature/SPKI policy. These do not claim policy-tree or final EUDI
//! service-profile conformance.

use base64ct::{Base64, Encoding};
use crypto_backend::AwsLc;
use x509::{parse_cert, validate_path, ParsedCert, X509Error};

const NOW: i64 = 1_800_000_000;

macro_rules! vector {
    ($name:ident, $file:literal) => {
        const $name: &str = include_str!(concat!("vectors/constraints/", $file, ".der.b64"));
    };
}

vector!(CONSTRAINED_ROOT, "constrained-root");
vector!(LEAF_ALLOWED, "leaf-allowed");
vector!(LEAF_DNS_OUTSIDE, "leaf-dns-outside");
vector!(LEAF_DNS_EXCLUDED, "leaf-dns-excluded");
vector!(LEAF_URI_APEX, "leaf-uri-apex");
vector!(LEAF_URI_NO_AUTHORITY, "leaf-uri-no-authority");
vector!(LEAF_URI_EXCLUDED, "leaf-uri-excluded");
vector!(LEAF_IP_OUTSIDE, "leaf-ip-outside");
vector!(LEAF_IP_EXCLUDED, "leaf-ip-excluded");
vector!(INTERSECTION_ROOT, "intersection-root");
vector!(INTERSECTION_INTERMEDIATE, "intersection-intermediate");
vector!(LEAF_TEAM_ALLOWED, "leaf-team-allowed");
vector!(LEAF_TEAM_OUTSIDE, "leaf-team-outside");
vector!(EMAIL_CONSTRAINT_ROOT, "email-constraint-root");
vector!(NONCRITICAL_CONSTRAINT_ROOT, "noncritical-constraint-root");
vector!(ILLEGAL_CONSTRAINT_LEAF, "illegal-constraint-leaf");
vector!(PLAIN_LEAF, "plain-leaf");
vector!(NONCRITICAL_LEAF, "noncritical-leaf");
vector!(RSA_ROOT, "rsa-root");
vector!(RSA_SIGNED_EC_LEAF, "rsa-signed-ec-leaf");
vector!(RSA_SHA256_LEAF, "rsa-sha256-leaf");
vector!(RSA_SHA512_LEAF, "rsa-sha512-leaf");
vector!(P256_SHA384_ROOT, "p256-sha384-root");
vector!(EC_SIGNED_RSA_LEAF, "ec-signed-rsa-leaf");
vector!(P384_ROOT, "p384-root");
vector!(P384_LEAF, "p384-leaf");
vector!(ED25519_ROOT, "ed25519-root");
vector!(ED25519_LEAF, "ed25519-leaf");
vector!(WEAK_RSA_ROOT, "weak-rsa-root");
vector!(EXPONENT_THREE_ROOT, "exponent-three-root");
vector!(P521_ROOT, "p521-root");
vector!(SHA1_LEAF, "sha1-leaf");

const GLOBALSIGN_R45_READER_ANCHOR: &[u8] = include_bytes!("vectors/eudiw/r45_staging.der");

fn der(encoded: &str) -> Vec<u8> {
    Base64::decode_vec(encoded.trim()).expect("valid generated certificate vector")
}

fn anchor(encoded: &str) -> ParsedCert {
    parse_cert(&der(encoded)).expect("vector must be an ingestible trust anchor")
}

fn assert_path_error(leaf: &str, anchor: &str, expected: &'static str) {
    assert_eq!(
        validate_path(&[der(leaf)], &[self::anchor(anchor)], NOW, &AwsLc),
        Err(X509Error::PathInvalid(expected))
    );
}

#[test]
fn supported_dns_uri_and_ip_constraints_accept_a_fully_permitted_leaf() {
    let path = validate_path(
        &[der(LEAF_ALLOWED)],
        &[anchor(CONSTRAINED_ROOT)],
        NOW,
        &AwsLc,
    )
    .expect("all three GeneralNames are permitted and not excluded");
    assert_eq!(path.len(), 2);
}

#[test]
fn dns_permitted_and_excluded_subtrees_are_both_enforced() {
    assert_path_error(
        LEAF_DNS_OUTSIDE,
        CONSTRAINED_ROOT,
        "name constraints do not permit certificate name",
    );
    assert_path_error(
        LEAF_DNS_EXCLUDED,
        CONSTRAINED_ROOT,
        "name constraints exclude certificate name",
    );
}

#[test]
fn uri_constraints_apply_only_to_canonical_dns_hosts_with_rfc_period_semantics() {
    assert_path_error(
        LEAF_URI_APEX,
        CONSTRAINED_ROOT,
        "name constraints do not permit certificate name",
    );
    assert_path_error(
        LEAF_URI_NO_AUTHORITY,
        CONSTRAINED_ROOT,
        "constrained URI has no canonical DNS host",
    );
    assert_path_error(
        LEAF_URI_EXCLUDED,
        CONSTRAINED_ROOT,
        "name constraints exclude certificate name",
    );
}

#[test]
fn ipv4_permitted_and_excluded_ranges_are_both_enforced() {
    assert_path_error(
        LEAF_IP_OUTSIDE,
        CONSTRAINED_ROOT,
        "name constraints do not permit certificate name",
    );
    assert_path_error(
        LEAF_IP_EXCLUDED,
        CONSTRAINED_ROOT,
        "name constraints exclude certificate name",
    );
}

#[test]
fn permitted_subtrees_from_multiple_cas_intersect() {
    let intermediate = der(INTERSECTION_INTERMEDIATE);
    validate_path(
        &[der(LEAF_TEAM_ALLOWED), intermediate.clone()],
        &[anchor(INTERSECTION_ROOT)],
        NOW,
        &AwsLc,
    )
    .expect("leaf satisfies both the root and intermediate DNS subtrees");

    assert_eq!(
        validate_path(
            &[der(LEAF_TEAM_OUTSIDE), intermediate],
            &[anchor(INTERSECTION_ROOT)],
            NOW,
            &AwsLc,
        ),
        Err(X509Error::PathInvalid(
            "name constraints do not permit certificate name"
        ))
    );
}

#[test]
fn unsupported_noncritical_and_end_entity_constraints_fail_closed() {
    assert_path_error(
        PLAIN_LEAF,
        EMAIL_CONSTRAINT_ROOT,
        "unsupported name constraint form",
    );
    assert_path_error(
        NONCRITICAL_LEAF,
        NONCRITICAL_CONSTRAINT_ROOT,
        "NameConstraints must be critical",
    );
    assert_path_error(
        ILLEGAL_CONSTRAINT_LEAF,
        CONSTRAINED_ROOT,
        "NameConstraints only permitted in CA certificates",
    );
}

#[test]
fn rsa_sha2_certificate_signatures_are_verified_without_changing_jose_algorithms() {
    let root = anchor(RSA_ROOT);
    for leaf in [RSA_SHA256_LEAF, RSA_SIGNED_EC_LEAF, RSA_SHA512_LEAF] {
        let path = validate_path(&[der(leaf)], core::slice::from_ref(&root), NOW, &AwsLc)
            .expect("RSA-2048 PKCS#1 SHA-2 issuer path must verify through the certificate API");
        assert_eq!(path.len(), 2);
    }
}

#[test]
fn p256_sha384_issuer_and_rsa_subject_key_are_handled_independently() {
    let path = validate_path(
        &[der(EC_SIGNED_RSA_LEAF)],
        &[anchor(P256_SHA384_ROOT)],
        NOW,
        &AwsLc,
    )
    .expect("the issuer EC key selects verification; the leaf RSA SPKI is independently profiled");
    assert_eq!(path.len(), 2);
}

#[test]
fn p384_and_ed25519_certificate_paths_have_real_positive_vectors() {
    for (leaf, root) in [(P384_LEAF, P384_ROOT), (ED25519_LEAF, ED25519_ROOT)] {
        let path = validate_path(&[der(leaf)], &[anchor(root)], NOW, &AwsLc)
            .expect("profiled key/signature pair must pass real backend verification");
        assert_eq!(path.len(), 2);
    }
}

#[test]
fn malformed_leaf_curve_point_is_rejected_before_its_certificate_signature() {
    let mut corrupted = der(LEAF_ALLOWED);
    let parsed = parse_cert(&corrupted).expect("original leaf parses");
    let positions = corrupted
        .windows(parsed.public_key_raw.len())
        .enumerate()
        .filter_map(|(index, bytes)| (bytes == parsed.public_key_raw).then_some(index))
        .collect::<Vec<_>>();
    let [position] = positions.as_slice() else {
        panic!("leaf SPKI point must occur exactly once in its DER")
    };
    corrupted[*position + 1..*position + parsed.public_key_raw.len()].fill(0);

    assert_eq!(
        validate_path(&[corrupted], &[anchor(CONSTRAINED_ROOT)], NOW, &AwsLc,),
        Err(X509Error::PathInvalid(
            "certificate subject public key validation failed"
        ))
    );
}

#[test]
fn checked_in_globalsign_reader_anchor_is_usable_under_the_rsa_policy() {
    let parsed = parse_cert(GLOBALSIGN_R45_READER_ANCHOR)
        .expect("GlobalSign R45 staging reader-auth anchor must parse");
    assert!(parsed.is_ca);
    assert!(parsed.subject.contains("GlobalSign"));
    assert!(!parsed.public_key_raw.is_empty());
}

#[test]
fn weak_or_unprofiled_spki_and_signature_algorithms_are_rejected() {
    assert_eq!(
        parse_cert(&der(WEAK_RSA_ROOT)),
        Err(X509Error::UnsupportedPublicKey)
    );
    assert_eq!(
        parse_cert(&der(EXPONENT_THREE_ROOT)),
        Err(X509Error::UnsupportedPublicKey)
    );
    assert_eq!(
        parse_cert(&der(P521_ROOT)),
        Err(X509Error::UnsupportedPublicKey)
    );
    assert_eq!(
        parse_cert(&der(SHA1_LEAF)),
        Err(X509Error::UnsupportedSignatureAlg)
    );
}

#[test]
fn algorithm_identifier_parameters_are_profiled_not_ignored() {
    const RSA_SHA384_OID: &[u8] = &[
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c,
    ];
    let mut bad_signature_parameters = der(RSA_SIGNED_EC_LEAF);
    let signature_occurrences = bad_signature_parameters
        .windows(RSA_SHA384_OID.len())
        .enumerate()
        .filter_map(|(index, value)| (value == RSA_SHA384_OID).then_some(index))
        .collect::<Vec<_>>();
    assert_eq!(signature_occurrences.len(), 2);
    for occurrence in signature_occurrences {
        assert_eq!(
            bad_signature_parameters[occurrence + RSA_SHA384_OID.len()],
            0x05
        );
        bad_signature_parameters[occurrence + RSA_SHA384_OID.len()] = 0x04;
    }
    assert_eq!(
        parse_cert(&bad_signature_parameters),
        Err(X509Error::UnsupportedSignatureAlg)
    );

    const RSA_ENCRYPTION_OID: &[u8] = &[
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
    ];
    let mut bad_spki_parameters = der(EC_SIGNED_RSA_LEAF);
    let spki_occurrences = bad_spki_parameters
        .windows(RSA_ENCRYPTION_OID.len())
        .enumerate()
        .filter_map(|(index, value)| (value == RSA_ENCRYPTION_OID).then_some(index))
        .collect::<Vec<_>>();
    assert_eq!(spki_occurrences.len(), 1);
    let parameters = spki_occurrences[0] + RSA_ENCRYPTION_OID.len();
    assert_eq!(bad_spki_parameters[parameters], 0x05);
    bad_spki_parameters[parameters] = 0x04;
    assert_eq!(
        parse_cert(&bad_spki_parameters),
        Err(X509Error::UnsupportedPublicKey)
    );
}
