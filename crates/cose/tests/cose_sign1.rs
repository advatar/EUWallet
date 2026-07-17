//! COSE_Sign1 tests (plan Section 4.1): Sig_structure golden, sign/verify wiring over the
//! crypto boundary, unknown-crit rejection, tamper detection, and algorithm binding.
//! Crypto is a deterministic STUB implementing the crypto-traits boundary — enough to prove
//! wiring without real ECDSA (real crypto is aws-lc-rs/Secure Enclave behind the same traits).
use cose::{
    encode_protected_header_with_crit, sig_structure, CoseError, CoseSign1, UnprotectedHeader,
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
