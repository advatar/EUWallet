//! Bounded strict-path vectors for issue #11. These are intentionally the first RFC 5280 slice,
//! not a claim of complete name-constraints, policy or EUDI service-profile processing.

use base64ct::{Base64, Encoding};
use crypto_backend::AwsLc;
use x509::{parse_cert, validate_path, ParsedCert, X509Error};

const NOW: i64 = 1_800_000_000;

const ROOT_A: &str = include_str!("vectors/strict/root-a.der.b64");
const ROOT_B: &str = include_str!("vectors/strict/root-b.der.b64");
const INTERMEDIATE_A: &str = include_str!("vectors/strict/intermediate-a.der.b64");
const INTERMEDIATE_B: &str = include_str!("vectors/strict/intermediate-b.der.b64");
const LEAF: &str = include_str!("vectors/strict/leaf.der.b64");
const ROOT_ZERO: &str = include_str!("vectors/strict/root-zero.der.b64");
const INTERMEDIATE_ZERO: &str = include_str!("vectors/strict/intermediate-zero.der.b64");
const LEAF_ZERO: &str = include_str!("vectors/strict/leaf-zero.der.b64");
const INTERMEDIATE_NO_KEYCERT: &str =
    include_str!("vectors/strict/intermediate-no-keycert.der.b64");
const LEAF_NO_KEYCERT_PARENT: &str = include_str!("vectors/strict/leaf-no-keycert-parent.der.b64");
const INTERMEDIATE_MISSING_BC: &str =
    include_str!("vectors/strict/intermediate-missing-bc.der.b64");
const LEAF_MISSING_BC_PARENT: &str = include_str!("vectors/strict/leaf-missing-bc-parent.der.b64");
const ROOT_NO_KEYCERT: &str = include_str!("vectors/strict/root-no-keycert.der.b64");
const LEAF_ROOT_NO_KEYCERT: &str = include_str!("vectors/strict/leaf-root-no-keycert.der.b64");
const LEAF_NO_DIGITAL_SIGNATURE: &str =
    include_str!("vectors/strict/leaf-no-digital-signature.der.b64");
const LEAF_UNKNOWN_CRITICAL: &str = include_str!("vectors/strict/leaf-unknown-critical.der.b64");
const LEAF_AKI_MISMATCH: &str = include_str!("vectors/strict/leaf-aki-mismatch.der.b64");
const LOOP_A: &str = include_str!("vectors/strict/loop-a.der.b64");
const LOOP_B: &str = include_str!("vectors/strict/loop-b.der.b64");
const LOOP_LEAF: &str = include_str!("vectors/strict/loop-leaf.der.b64");

fn der(encoded: &str) -> Vec<u8> {
    Base64::decode_vec(encoded.trim()).expect("valid strict-path vector")
}

fn anchor(encoded: &str) -> ParsedCert {
    parse_cert(&der(encoded)).expect("valid trust-anchor vector")
}

fn assert_path_error(chain: Vec<Vec<u8>>, anchors: Vec<ParsedCert>, expected: &'static str) {
    assert_eq!(
        validate_path(&chain, &anchors, NOW, &AwsLc),
        Err(X509Error::PathInvalid(expected))
    );
}

#[test]
fn unordered_cross_signed_bundle_builds_the_one_anchored_path_deterministically() {
    let leaf = der(LEAF);
    let intermediate_a = der(INTERMEDIATE_A);
    let intermediate_b = der(INTERMEDIATE_B);
    let root_a = anchor(ROOT_A);

    let first = validate_path(
        &[intermediate_b.clone(), leaf.clone(), intermediate_a.clone()],
        core::slice::from_ref(&root_a),
        NOW,
        &AwsLc,
    )
    .expect("only the Root A cross-sign reaches the trusted anchor");
    let reordered = validate_path(
        &[leaf, intermediate_a.clone(), intermediate_b],
        &[root_a],
        NOW,
        &AwsLc,
    )
    .expect("input order cannot change path construction");

    assert_eq!(first, reordered);
    assert_eq!(first.len(), 3);
    assert_eq!(first[1], parse_cert(&intermediate_a).unwrap());
    assert!(first[2].subject.contains("Strict Root A"));
}

#[test]
fn invalid_same_subject_decoys_do_not_make_one_valid_path_ambiguous() {
    let valid_intermediate = der(INTERMEDIATE_A);
    let mut invalid_decoy_one = valid_intermediate.clone();
    let last = invalid_decoy_one.last_mut().expect("non-empty certificate");
    *last ^= 0x01;
    let mut invalid_decoy_two = valid_intermediate.clone();
    let penultimate = invalid_decoy_two.len() - 2;
    invalid_decoy_two[penultimate] ^= 0x01;

    let path = validate_path(
        &[
            invalid_decoy_one,
            der(LEAF),
            invalid_decoy_two,
            valid_intermediate.clone(),
        ],
        &[anchor(ROOT_A)],
        NOW,
        &AwsLc,
    )
    .expect("only the cryptographically valid completion counts");
    assert_eq!(path[1], parse_cert(&valid_intermediate).unwrap());
}

#[test]
fn two_valid_cross_signed_paths_are_rejected_as_ambiguous() {
    assert_path_error(
        vec![der(INTERMEDIATE_B), der(LEAF), der(INTERMEDIATE_A)],
        vec![anchor(ROOT_B), anchor(ROOT_A)],
        "certificate bundle has ambiguous trust paths",
    );
}

#[test]
fn basic_constraints_and_path_len_are_enforced_for_ca_roles() {
    assert_path_error(
        vec![der(INTERMEDIATE_A)],
        vec![anchor(ROOT_A)],
        "leaf certificate is a CA",
    );
    assert_path_error(
        vec![der(LEAF_ZERO), der(INTERMEDIATE_ZERO)],
        vec![anchor(ROOT_ZERO)],
        "BasicConstraints pathLenConstraint exceeded",
    );
    assert_path_error(
        vec![der(LEAF_MISSING_BC_PARENT), der(INTERMEDIATE_MISSING_BC)],
        vec![anchor(ROOT_A)],
        "issuer BasicConstraints does not authorize a CA",
    );
}

#[test]
fn key_usage_is_enforced_for_leaf_intermediate_and_anchor_roles() {
    assert_path_error(
        vec![der(LEAF_NO_DIGITAL_SIGNATURE), der(INTERMEDIATE_A)],
        vec![anchor(ROOT_A)],
        "leaf KeyUsage lacks digitalSignature",
    );
    assert_path_error(
        vec![der(LEAF_NO_KEYCERT_PARENT), der(INTERMEDIATE_NO_KEYCERT)],
        vec![anchor(ROOT_A)],
        "issuer KeyUsage lacks keyCertSign",
    );
    assert_path_error(
        vec![der(LEAF_ROOT_NO_KEYCERT)],
        vec![anchor(ROOT_NO_KEYCERT)],
        "issuer KeyUsage lacks keyCertSign",
    );
}

#[test]
fn unknown_critical_extensions_and_aki_mismatches_fail_closed() {
    assert_path_error(
        vec![der(LEAF_UNKNOWN_CRITICAL), der(INTERMEDIATE_A)],
        vec![anchor(ROOT_A)],
        "unsupported critical certificate extension",
    );
    assert_path_error(
        vec![der(LEAF_AKI_MISMATCH), der(INTERMEDIATE_A)],
        vec![anchor(ROOT_A)],
        "authority key identifier mismatch",
    );
}

#[test]
fn loops_duplicates_and_redundantly_supplied_roots_are_rejected() {
    assert_path_error(
        vec![der(LOOP_B), der(LOOP_LEAF), der(LOOP_A)],
        vec![anchor(ROOT_A)],
        "certificate path contains a loop",
    );

    let intermediate = der(INTERMEDIATE_A);
    assert_path_error(
        vec![der(LEAF), intermediate.clone(), intermediate],
        vec![anchor(ROOT_A)],
        "duplicate certificate in supplied chain",
    );
    assert_path_error(
        vec![der(LEAF), der(INTERMEDIATE_A)],
        vec![anchor(ROOT_A), anchor(ROOT_A)],
        "duplicate trust anchor",
    );
    assert_path_error(
        vec![der(LEAF), der(INTERMEDIATE_A), der(ROOT_A)],
        vec![anchor(ROOT_A)],
        "trust anchor must not be supplied in the certificate chain",
    );
}

#[test]
fn tbs_and_outer_signature_algorithms_must_match() {
    let mut leaf = der(LEAF);
    let es256_oid = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
    let occurrences = leaf
        .windows(es256_oid.len())
        .enumerate()
        .filter_map(|(index, window)| (window == es256_oid).then_some(index))
        .collect::<Vec<_>>();
    let outer = *occurrences.last().expect("outer signatureAlgorithm OID");
    leaf[outer + es256_oid.len() - 1] = 0x03; // ecdsa-with-SHA384, same DER length

    assert_path_error(
        vec![leaf, der(INTERMEDIATE_A)],
        vec![anchor(ROOT_A)],
        "TBSCertificate and outer signature algorithms differ",
    );
}

#[test]
fn certificate_count_budget_is_explicit() {
    assert_path_error(
        vec![der(LEAF); 9],
        vec![anchor(ROOT_A)],
        "certificate path resource budget exceeded",
    );
}
