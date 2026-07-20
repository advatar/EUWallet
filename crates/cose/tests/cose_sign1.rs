//! COSE_Sign1 tests (plan Section 4.1): Sig_structure golden, sign/verify wiring over the
//! crypto boundary, unknown-crit rejection, tamper detection, and algorithm binding.
//! Crypto is a deterministic STUB implementing the crypto-traits boundary — enough to prove
//! wiring without real ECDSA (real crypto is aws-lc-rs/Secure Enclave behind the same traits).
use cose::cbor::Value;
use cose::{
    encode_protected_header, encode_protected_header_with_crit, sig_structure, CoseError,
    CoseSign1, UnprotectedHeader, X5Chain, MAX_X5CHAIN_CERTIFICATES, MAX_X5CHAIN_CERTIFICATE_BYTES,
    MAX_X5CHAIN_TOTAL_BYTES,
};
use crypto_traits::{Alg, CryptoError, KeyRef, Signer, Verifier};

/// Deterministic, non-cryptographic "signature" = FNV-1a(payload) as 8 bytes.
fn fnv(payload: &[u8]) -> Vec<u8> {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in payload {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h.to_be_bytes().to_vec()
}

struct StubCrypto;
impl Signer for StubCrypto {
    fn sign(&self, _key: &KeyRef, _alg: Alg, payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Ok(fnv(payload))
    }
}
impl Verifier for StubCrypto {
    fn verify(
        &self,
        _alg: Alg,
        _public_key: &[u8],
        payload: &[u8],
        sig: &[u8],
    ) -> Result<(), CryptoError> {
        if fnv(payload) == sig {
            Ok(())
        } else {
            Err(CryptoError::Backend("signature mismatch".into()))
        }
    }
}

#[test]
fn sig_structure_matches_rfc9052_shape() {
    // protected header {1: -7} (ES256) → canonical CBOR: a1 01 26
    // Sig_structure = ["Signature1", h'a10126', h'', h'']
    let protected = [0xa1, 0x01, 0x26];
    let tbs = sig_structure(&protected, &[], &[]);
    let expected = vec![
        0x84, // array(4)
        0x6a, // text(10)
        b'S', b'i', b'g', b'n', b'a', b't', b'u', b'r', b'e', b'1', 0x43, 0xa1, 0x01,
        0x26, // bstr(3) = protected header
        0x40, // bstr(0) = external_aad
        0x40, // bstr(0) = payload
    ];
    assert_eq!(tbs, expected);
}

#[test]
fn sign_then_verify_roundtrip() {
    let crypto = StubCrypto;
    let key = KeyRef("issuer-key".into());
    let payload = b"mobile security object bytes";

    let msg = CoseSign1::sign(
        &crypto,
        &key,
        Alg::Es256,
        payload,
        &[],
        UnprotectedHeader::default(),
    )
    .expect("sign");
    assert!(msg
        .verify(&crypto, Alg::Es256, b"issuer-pub", &[], None)
        .is_ok());
}

#[test]
fn unprotected_x5chain_wire_shape_is_preserved_as_untrusted_evidence() {
    let crypto = StubCrypto;
    for chain in [
        X5Chain::Single(vec![0x30, 0x01]),
        X5Chain::Chain(vec![vec![0x30, 0x02], vec![0x30, 0x03]]),
    ] {
        let message = CoseSign1::sign(
            &crypto,
            &KeyRef("issuer".into()),
            Alg::Es256,
            b"payload",
            &[],
            UnprotectedHeader {
                kid: Some(b"issuer-key".to_vec()),
                x5chain: Some(Box::new(chain.clone())),
            },
        )
        .expect("sign");
        let parsed = CoseSign1::from_value(&message.to_value()).expect("parse");
        assert_eq!(parsed.unprotected.x5chain.as_deref(), Some(&chain));
        assert_eq!(parsed.x5chain().expect("valid headers"), Some(chain));
        parsed
            .verify(&crypto, Alg::Es256, b"issuer-pub", &[], None)
            .expect("verify");
    }
}

#[test]
fn protected_critical_x5chain_is_exposed_in_leaf_first_order() {
    let protected = Value::Map(vec![
        (Value::Uint(1), Value::Nint(6)),
        (Value::Uint(2), Value::Array(vec![Value::Uint(33)])),
        (
            Value::Uint(33),
            Value::Array(vec![
                Value::Bytes(vec![0x30, 0x11]),
                Value::Bytes(vec![0x30, 0x22]),
            ]),
        ),
    ])
    .to_canonical();
    let payload = b"payload".to_vec();
    let message = CoseSign1 {
        signature: fnv(&sig_structure(&protected, &[], &payload)),
        protected,
        unprotected: UnprotectedHeader::default(),
        payload: Some(payload),
    };

    let evidence = message.x5chain().expect("valid headers").expect("x5chain");
    assert_eq!(
        evidence.certificates(),
        vec![&[0x30, 0x11][..], &[0x30, 0x22][..]]
    );
    message
        .verify(&StubCrypto, Alg::Es256, b"issuer-pub", &[], None)
        .expect("verify");

    let parsed = CoseSign1::from_value(&message.to_value()).expect("parse");
    assert_eq!(parsed.protected, message.protected);
    assert_eq!(parsed.x5chain().unwrap(), Some(evidence));
}

#[test]
fn malformed_or_colliding_x5chain_headers_are_rejected() {
    let sign1 = |protected: Vec<u8>, unprotected: Value| {
        Value::Array(vec![
            Value::Bytes(protected),
            unprotected,
            Value::Bytes(b"payload".to_vec()),
            Value::Bytes(vec![0; 8]),
        ])
    };
    for malformed in [
        Value::Array(vec![Value::Bytes(vec![0x30, 0x01])]),
        Value::Array(vec![]),
        Value::Bytes(vec![]),
        Value::Array(vec![
            Value::Bytes(vec![1]),
            Value::Text("not DER bytes".into()),
        ]),
    ] {
        let value = sign1(
            encode_protected_header(Alg::Es256),
            Value::Map(vec![(Value::Uint(33), malformed)]),
        );
        assert_eq!(
            CoseSign1::from_value(&value),
            Err(CoseError::MalformedHeader)
        );
    }

    let protected_with_chain = Value::Map(vec![
        (Value::Uint(1), Value::Nint(6)),
        (Value::Uint(33), Value::Bytes(vec![0x30, 0x01])),
    ])
    .to_canonical();
    let collision = sign1(
        protected_with_chain,
        Value::Map(vec![(Value::Uint(33), Value::Bytes(vec![0x30, 0x02]))]),
    );
    assert_eq!(
        CoseSign1::from_value(&collision),
        Err(CoseError::MalformedHeader)
    );

    let absent_critical_parameter = sign1(
        encode_protected_header_with_crit(Alg::Es256, &[33]),
        Value::Map(vec![]),
    );
    assert_eq!(
        CoseSign1::from_value(&absent_critical_parameter),
        Err(CoseError::MalformedHeader)
    );

    for malformed_crit in [
        encode_protected_header_with_crit(Alg::Es256, &[]),
        encode_protected_header_with_crit(Alg::Es256, &[1, 1]),
        encode_protected_header_with_crit(Alg::Es256, &[2]),
    ] {
        assert_eq!(
            CoseSign1::from_value(&sign1(malformed_crit, Value::Map(vec![]))),
            Err(CoseError::MalformedHeader)
        );
    }
}

#[test]
fn x5chain_resource_limits_and_duplicate_header_labels_fail_closed() {
    let sign1 = |protected: Vec<u8>, unprotected: Value| {
        Value::Array(vec![
            Value::Bytes(protected),
            unprotected,
            Value::Bytes(b"payload".to_vec()),
            Value::Bytes(vec![0; 8]),
        ])
    };
    let aggregate_certificate_size = MAX_X5CHAIN_TOTAL_BYTES / 5 + 1;
    for oversized_chain in [
        Value::Array(
            (0..=MAX_X5CHAIN_CERTIFICATES)
                .map(|_| Value::Bytes(vec![1]))
                .collect(),
        ),
        Value::Bytes(vec![1; MAX_X5CHAIN_CERTIFICATE_BYTES + 1]),
        Value::Array(
            (0..5)
                .map(|_| Value::Bytes(vec![1; aggregate_certificate_size]))
                .collect(),
        ),
    ] {
        assert_eq!(
            CoseSign1::from_value(&sign1(
                encode_protected_header(Alg::Es256),
                Value::Map(vec![(Value::Uint(33), oversized_chain)]),
            )),
            Err(CoseError::MalformedHeader)
        );
    }

    for duplicate_label in [1, 4, 33, 99] {
        let duplicate = Value::Map(vec![
            (Value::Uint(duplicate_label), Value::Bytes(vec![1])),
            (Value::Uint(duplicate_label), Value::Bytes(vec![2])),
        ]);
        assert_eq!(
            CoseSign1::from_value(&sign1(encode_protected_header(Alg::Es256), duplicate,)),
            Err(CoseError::MalformedHeader)
        );
    }

    // A duplicate protected `alg` label is rejected by the canonical protected-map decoder.
    let duplicate_protected_alg = vec![0xa2, 0x01, 0x26, 0x01, 0x26];
    assert_eq!(
        CoseSign1::from_value(&sign1(duplicate_protected_alg, Value::Map(vec![]))),
        Err(CoseError::MalformedHeader)
    );
}

#[test]
fn unknown_noncritical_unprotected_labels_are_ignored_and_not_reemitted() {
    let value = Value::Array(vec![
        Value::Bytes(encode_protected_header(Alg::Es256)),
        Value::Map(vec![(Value::Uint(99), Value::Text("extension".into()))]),
        Value::Bytes(b"payload".to_vec()),
        Value::Bytes(vec![0; 8]),
    ]);
    let parsed = CoseSign1::from_value(&value).expect("unknown noncritical label is permitted");
    let Value::Array(reencoded) = parsed.to_value() else {
        panic!("COSE_Sign1 must be an array");
    };
    assert_eq!(reencoded[1], Value::Map(vec![]));
}

#[test]
fn verify_rejects_tampered_detached_payload() {
    let crypto = StubCrypto;
    let key = KeyRef("k".into());
    // Sign detached (payload None on the wire), then verify with the WRONG detached payload.
    let mut msg = CoseSign1::sign(
        &crypto,
        &key,
        Alg::Es256,
        b"real",
        &[],
        UnprotectedHeader::default(),
    )
    .unwrap();
    msg.payload = None; // detach
    let err = msg
        .verify(&crypto, Alg::Es256, b"pub", &[], Some(b"forged"))
        .unwrap_err();
    assert!(matches!(err, CoseError::Crypto(_)));
}

#[test]
fn verify_rejects_algorithm_mismatch() {
    let crypto = StubCrypto;
    let key = KeyRef("k".into());
    let msg = CoseSign1::sign(
        &crypto,
        &key,
        Alg::Es256,
        b"x",
        &[],
        UnprotectedHeader::default(),
    )
    .unwrap();
    // Signed with ES256 but the caller expects ES384.
    let err = msg
        .verify(&crypto, Alg::Es384, b"pub", &[], None)
        .unwrap_err();
    assert_eq!(err, CoseError::AlgMismatch);
}

#[test]
fn verify_rejects_unknown_critical_param() {
    let crypto = StubCrypto;
    // Protected header declares crit label 99, which we do not implement → fail closed.
    let msg = CoseSign1 {
        protected: encode_protected_header_with_crit(Alg::Es256, &[99]),
        unprotected: UnprotectedHeader::default(),
        payload: Some(b"x".to_vec()),
        signature: vec![0; 8],
    };
    let err = msg
        .verify(&crypto, Alg::Es256, b"pub", &[], None)
        .unwrap_err();
    assert_eq!(err, CoseError::UnknownCriticalParam(99));
}

#[test]
fn verify_rejects_malformed_protected_header() {
    let crypto = StubCrypto;
    let msg = CoseSign1 {
        protected: vec![0xff, 0xff, 0xff], // not canonical CBOR
        unprotected: UnprotectedHeader::default(),
        payload: Some(b"x".to_vec()),
        signature: vec![0; 8],
    };
    let err = msg
        .verify(&crypto, Alg::Es256, b"pub", &[], None)
        .unwrap_err();
    assert_eq!(err, CoseError::MalformedHeader);
}
