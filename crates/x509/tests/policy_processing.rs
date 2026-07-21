//! Bounded RFC 5280 certificate-policy vectors for issue #22.

use base64ct::{Base64, Encoding};
use crypto_backend::AwsLc;
use x509::{parse_cert, validate_path, ParsedCert, X509Error};

const NOW: i64 = 1_800_000_000;

macro_rules! vector {
    ($name:ident, $file:literal) => {
        const $name: &str = include_str!(concat!("vectors/constraints/", $file, ".der.b64"));
    };
}

vector!(ROOT, "policy-root");
vector!(MAPPED_CA, "policy-mapped-intermediate");
vector!(MAPPED_LEAF, "policy-mapped-leaf");
vector!(UNMAPPED_CA, "policy-unmapped-intermediate");
vector!(UNMAPPED_LEAF, "policy-unmapped-leaf");
vector!(
    MAPPING_INHIBITED_CA,
    "policy-mapping-inhibited-intermediate"
);
vector!(MAPPING_INHIBITED_LEAF, "policy-mapping-inhibited-leaf");
vector!(MAPPING_INHIBITOR, "policy-mapping-inhibitor");
vector!(ANY_ALLOWED_CA, "policy-any-allowed-intermediate");
vector!(ANY_ALLOWED_LEAF, "policy-any-allowed-leaf");
vector!(ANY_INHIBITED_CA, "policy-any-inhibited-intermediate");
vector!(ANY_INHIBITED_LEAF, "policy-any-inhibited-leaf");
vector!(ANY_INHIBITOR, "policy-any-inhibitor");

fn der(encoded: &str) -> Vec<u8> {
    Base64::decode_vec(encoded.trim()).expect("valid generated certificate vector")
}

fn anchor() -> ParsedCert {
    parse_cert(&der(ROOT)).expect("policy root parses")
}

fn validate(leaf: &str, intermediate: &str) -> Result<Vec<ParsedCert>, X509Error> {
    validate_path(&[der(leaf), der(intermediate)], &[anchor()], NOW, &AwsLc)
}

#[test]
fn policy_mapping_preserves_only_the_effective_leaf_policy() {
    let path = validate(MAPPED_LEAF, MAPPED_CA).expect("mapped explicit policy path is valid");
    assert_eq!(path[0].policies, ["1.2.3.5"]);
}

#[test]
fn explicit_policy_rejects_an_unmapped_leaf_policy() {
    assert_eq!(
        validate(UNMAPPED_LEAF, UNMAPPED_CA),
        Err(X509Error::PathInvalid(
            "explicit certificate policy is required"
        ))
    );
}

#[test]
fn inhibited_mapping_cannot_translate_the_policy_domain() {
    assert_eq!(
        validate_path(
            &[
                der(MAPPING_INHIBITED_LEAF),
                der(MAPPING_INHIBITED_CA),
                der(MAPPING_INHIBITOR),
            ],
            &[anchor()],
            NOW,
            &AwsLc,
        ),
        Err(X509Error::PathInvalid(
            "certificate policy mapping is inhibited"
        ))
    );
}

#[test]
fn any_policy_expands_only_before_its_inhibition_boundary() {
    let path = validate(ANY_ALLOWED_LEAF, ANY_ALLOWED_CA)
        .expect("uninhibited anyPolicy carries the concrete leaf policy");
    assert_eq!(path[0].policies, ["1.2.3.5"]);

    let inhibited = validate_path(
        &[
            der(ANY_INHIBITED_LEAF),
            der(ANY_INHIBITED_CA),
            der(ANY_INHIBITOR),
        ],
        &[anchor()],
        NOW,
        &AwsLc,
    )
    .expect("without explicit-policy, an empty policy tree does not invalidate the path");
    assert!(inhibited[0].policies.is_empty());
}
