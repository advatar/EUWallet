#![cfg(feature = "experimental-pq-primitives")]

use aws_lc_rs::digest::{digest, SHA256};
use crypto_backend::{experimental_pq::verify_ml_dsa_65, AwsLc};
use crypto_traits::{Alg, Verifier};
use hybrid_pq::{
    envelope::decode_public_key,
    tbs::{HybridContext, HybridPurpose},
    wrapper::{decode_credential_wrapper, HybridCredentialWrapper},
};
use serde_json::Value;

const TBS_HEX: &str = include_str!("../../../docs/test-vectors/hybrid-pq-v1-component-tbs.hex");
const PUBLIC_KEY_ENVELOPE_HEX: &str =
    include_str!("../../../docs/test-vectors/hybrid-pq-v1-public-key-envelope.hex");
const WRAPPER_ENVELOPE_HEX: &str =
    include_str!("../../../docs/test-vectors/hybrid-pq-v1-wrapper-envelope.hex");
const MUTATIONS_JSON: &str =
    include_str!("../../../docs/test-vectors/hybrid-pq-v1-wrapper-mutations.json");

const EXPECTED_CLASSICAL_KEY_ID: &str = "shared-classical-kid-v1";
const EXPECTED_PQ_KEY_ID: &str = "shared-pq-kid-v1";
const EXPECTED_GENERATION: u64 = 9;

fn corpus_context() -> HybridContext {
    HybridContext {
        wallet_identity: b"FNTotPeVek-MEChStrtHEZ9__f_R0R6CnaCg3QzzSQw".to_vec(),
        issuer_identity: Some(b"https://issuer.example".to_vec()),
        key_generation: EXPECTED_GENERATION,
        transaction_id: Some(b"transaction-123".to_vec()),
        session_id: None,
        audience: Some(b"https://issuer.example".to_vec()),
        nonce: (0_u8..32).collect(),
        created_at_epoch_seconds: 1_700_000_000,
        expires_at_epoch_seconds: 1_700_003_600,
        transcript_hash: None,
    }
}

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

/// The complete fail-closed acceptance rule for one candidate wrapper: strict
/// decode, unsigned key-identifier/generation binding, committed-TBS
/// reconstruction, and both component signatures over the identical bytes.
fn accept_wrapper(candidate: &[u8], classical_public: &[u8], pq_public: &[u8]) -> bool {
    let Ok(wrapper) = decode_credential_wrapper(candidate) else {
        return false;
    };
    if wrapper.purpose() != HybridPurpose::TestSdJwtWrapperV1
        || wrapper.classical_key_id() != EXPECTED_CLASSICAL_KEY_ID
        || wrapper.pq_key_id() != EXPECTED_PQ_KEY_ID
        || wrapper.generation() != EXPECTED_GENERATION
    {
        return false;
    }
    let Ok(tbs) = wrapper.tbs(&corpus_context()) else {
        return false;
    };
    AwsLc
        .verify(
            Alg::Es256,
            classical_public,
            tbs.as_bytes(),
            wrapper.signature().classical(),
        )
        .is_ok()
        && verify_ml_dsa_65(
            pq_public,
            tbs.as_bytes(),
            wrapper.signature().post_quantum(),
        )
        .is_ok()
}

fn corpus() -> (Vec<u8>, HybridCredentialWrapper, Vec<u8>, Vec<u8>) {
    let wrapper_envelope = decode_hex(WRAPPER_ENVELOPE_HEX);
    let wrapper = decode_credential_wrapper(&wrapper_envelope).expect("frozen wrapper envelope");
    let public_key = decode_public_key(&decode_hex(PUBLIC_KEY_ENVELOPE_HEX))
        .expect("frozen public-key envelope");
    (
        wrapper_envelope,
        wrapper,
        public_key.classical().to_vec(),
        public_key.post_quantum().to_vec(),
    )
}

#[test]
fn verifies_the_vcissuer_wrapper_corpus_with_independent_backends() {
    let (wrapper_envelope, wrapper, classical_public, pq_public) = corpus();
    assert_eq!(wrapper.purpose(), HybridPurpose::TestSdJwtWrapperV1);
    assert_eq!(wrapper.classical_key_id(), EXPECTED_CLASSICAL_KEY_ID);
    assert_eq!(wrapper.pq_key_id(), EXPECTED_PQ_KEY_ID);
    assert_eq!(wrapper.generation(), EXPECTED_GENERATION);
    assert_eq!(wrapper.disclosures().len(), 2);

    let tbs = wrapper
        .tbs(&corpus_context())
        .expect("committed wrapper TBS");
    assert_eq!(
        tbs.as_bytes(),
        decode_hex(TBS_HEX).as_slice(),
        "the wrapper commits to the shared component TBS"
    );
    assert!(accept_wrapper(
        &wrapper_envelope,
        &classical_public,
        &pq_public
    ));

    assert_eq!(
        sha256_hex(WRAPPER_ENVELOPE_HEX.as_bytes()),
        "21e5e55352ac03cdf554704399173ec3a89f9870d4b84e257489f057e1b63a90"
    );
    assert_eq!(
        sha256_hex(MUTATIONS_JSON.as_bytes()),
        "e3677250fa44e3b5965c172ac00ec0e4a6de5e8373abe95533022751eedfd575"
    );
}

#[test]
fn rejects_every_shared_wrapper_mutation() {
    let (wrapper_envelope, _, classical_public, pq_public) = corpus();
    let mutations: Value = serde_json::from_str(MUTATIONS_JSON).expect("shared mutations");
    let mutation_list = mutations["mutations"].as_array().expect("mutation list");
    assert!(
        mutation_list.len() >= 21,
        "complete wrapper mutation corpus"
    );

    for mutation in mutation_list {
        assert_eq!(
            mutation["target"].as_str().expect("mutation target"),
            "wrapper-envelope"
        );
        let mutated = apply_operations(
            wrapper_envelope.clone(),
            mutation["operations"].as_array().expect("operations"),
        );
        assert!(
            !accept_wrapper(&mutated, &classical_public, &pq_public),
            "{} must reject",
            mutation["name"]
        );
    }
}
