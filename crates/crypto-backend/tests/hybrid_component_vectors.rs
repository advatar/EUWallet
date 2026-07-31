#![cfg(feature = "experimental-pq-primitives")]

use aws_lc_rs::digest::{digest, SHA256};
use crypto_backend::{experimental_pq::verify_ml_dsa_65, AwsLc};
use crypto_traits::{Alg, Verifier};
use hybrid_pq::{
    envelope::{decode_public_key, decode_signature},
    tbs::HybridPurpose,
};
use serde_json::Value;

const TBS_HEX: &str = include_str!("../../../docs/test-vectors/hybrid-pq-v1-component-tbs.hex");
const PUBLIC_KEY_ENVELOPE_HEX: &str =
    include_str!("../../../docs/test-vectors/hybrid-pq-v1-public-key-envelope.hex");
const SIGNATURE_ENVELOPE_HEX: &str =
    include_str!("../../../docs/test-vectors/hybrid-pq-v1-signature-envelope.hex");
const MUTATIONS_JSON: &str =
    include_str!("../../../docs/test-vectors/hybrid-pq-v1-component-mutations.json");

fn decode_hex(value: &str) -> Vec<u8> {
    let value = value.trim().as_bytes();
    assert_eq!(value.len() % 2, 0, "hex input length");
    value
        .chunks_exact(2)
        .map(|pair| {
            let digit = |byte: u8| match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                b'A'..=b'F' => byte - b'A' + 10,
                _ => panic!("invalid hex digit"),
            };
            (digit(pair[0]) << 4) | digit(pair[1])
        })
        .collect()
}

fn sha256_hex(value: &[u8]) -> String {
    digest(&SHA256, value)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn apply_operations(mut bytes: Vec<u8>, operations: &[Value]) -> Vec<u8> {
    for operation in operations {
        match operation["op"].as_str().expect("mutation operation") {
            "xor" => {
                let offset = operation["offset"].as_u64().expect("xor offset") as usize;
                bytes[offset] ^= operation["value"].as_u64().expect("xor value") as u8;
            }
            "truncate" => {
                let count = operation["count"].as_u64().expect("truncate count") as usize;
                bytes.truncate(bytes.len() - count);
            }
            "append" => {
                bytes.extend_from_slice(&decode_hex(operation["hex"].as_str().expect("append hex")))
            }
            "replace" => {
                let offset = operation["offset"].as_u64().expect("replace offset") as usize;
                let delete = operation["delete"].as_u64().expect("replace delete") as usize;
                bytes.splice(
                    offset..offset + delete,
                    decode_hex(operation["hex"].as_str().expect("replace hex")),
                );
            }
            "remove" => {
                let offset = operation["offset"].as_u64().expect("remove offset") as usize;
                let count = operation["count"].as_u64().expect("remove count") as usize;
                bytes.drain(offset..offset + count);
            }
            _ => panic!("unknown mutation operation"),
        }
    }
    bytes
}

#[test]
fn verifies_the_vcissuer_component_corpus_with_independent_backends() {
    let tbs = decode_hex(TBS_HEX);
    let public_envelope = decode_hex(PUBLIC_KEY_ENVELOPE_HEX);
    let signature_envelope = decode_hex(SIGNATURE_ENVELOPE_HEX);
    let public_key = decode_public_key(&public_envelope).expect("frozen public-key envelope");
    let signature = decode_signature(&signature_envelope).expect("frozen signature envelope");
    assert_eq!(signature.purpose(), HybridPurpose::TestSdJwtWrapperV1);

    AwsLc
        .verify(
            Alg::Es256,
            public_key.classical(),
            &tbs,
            signature.signature().classical(),
        )
        .expect("independent ES256 verification");
    verify_ml_dsa_65(
        public_key.post_quantum(),
        &tbs,
        signature.signature().post_quantum(),
    )
    .expect("independent ML-DSA-65 verification");

    assert_eq!(
        sha256_hex(&tbs),
        "ebdf4ddf9bdd7f72172f623ae94fa19dad62023574d1d68c62aff6a52c2b2805"
    );
    assert_eq!(
        sha256_hex(&public_envelope),
        "6f252c80edfb3a902ea26abe6eabd98e883f4828238810a07be165653e4eb42c"
    );
    assert_eq!(
        sha256_hex(&signature_envelope),
        "ff348f5a043989ee5f2fb329bc25f5778f8750b5685041eaf8753db90eb386a7"
    );
}

#[test]
fn rejects_every_shared_component_mutation() {
    let tbs = decode_hex(TBS_HEX);
    let public_envelope = decode_hex(PUBLIC_KEY_ENVELOPE_HEX);
    let signature_envelope = decode_hex(SIGNATURE_ENVELOPE_HEX);
    let public_key = decode_public_key(&public_envelope).expect("frozen public-key envelope");
    let mutations: Value = serde_json::from_str(MUTATIONS_JSON).expect("shared mutations");

    for mutation in mutations["mutations"].as_array().expect("mutation list") {
        let target = mutation["target"].as_str().expect("mutation target");
        let base = match target {
            "public-key-envelope" => public_envelope.clone(),
            "signature-envelope" => signature_envelope.clone(),
            _ => panic!("unknown mutation target"),
        };
        let mutated =
            apply_operations(base, mutation["operations"].as_array().expect("operations"));
        if target == "public-key-envelope" {
            assert!(
                decode_public_key(&mutated).is_err(),
                "{} must reject",
                mutation["name"]
            );
            continue;
        }
        match decode_signature(&mutated) {
            Err(_) => {}
            Ok(decoded) => {
                let classical_valid = AwsLc
                    .verify(
                        Alg::Es256,
                        public_key.classical(),
                        &tbs,
                        decoded.signature().classical(),
                    )
                    .is_ok();
                let pq_valid = verify_ml_dsa_65(
                    public_key.post_quantum(),
                    &tbs,
                    decoded.signature().post_quantum(),
                )
                .is_ok();
                assert!(
                    !(classical_valid && pq_valid),
                    "{} must reject",
                    mutation["name"]
                );
            }
        }
    }
}
