//! Unit tests for the aws-lc-rs backend: known-answer vectors + primitive round-trips.
use crypto_backend::{AwsLc, SoftwareSigner};
use crypto_traits::{Aead, Alg, Digest, Kdf, KeyRef, Random, Signer, Verifier};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn sha256_known_answer() {
    // FIPS 180-4 example: SHA-256("abc").
    let got = AwsLc.sha256(b"abc");
    let want = hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    assert_eq!(got.to_vec(), want);
}

#[test]
fn hkdf_rfc5869_test_case_1() {
    let ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = hex("000102030405060708090a0b0c");
    let info = hex("f0f1f2f3f4f5f6f7f8f9");
    let okm = AwsLc.hkdf_sha256(&ikm, &salt, &info, 42);
    let want =
        hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
    assert_eq!(okm, want);
}

#[test]
fn aes_256_gcm_round_trip_and_tamper() {
    let key = [7u8; 32];
    let nonce = [1u8; 12];
    let aad = b"header";
    let pt = b"secret session data";
    let ct = AwsLc.seal(&key, &nonce, aad, pt).unwrap();
    assert_ne!(ct, pt); // encrypted + tag appended
    let back = AwsLc.open(&key, &nonce, aad, &ct).unwrap();
    assert_eq!(back, pt);
    // Wrong AAD must fail authentication.
    assert!(AwsLc.open(&key, &nonce, b"other", &ct).is_err());
    // Flipped ciphertext byte must fail.
    let mut bad = ct.clone();
    bad[0] ^= 0xff;
    assert!(AwsLc.open(&key, &nonce, aad, &bad).is_err());
}

#[test]
fn random_fills_distinct_buffers() {
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    AwsLc.fill(&mut a);
    AwsLc.fill(&mut b);
    assert_ne!(a, b);
    assert_ne!(a, [0u8; 32]);
}

#[test]
fn ecdsa_sign_then_verify_and_tamper() {
    let signer = SoftwareSigner::generate_p256().unwrap();
    let msg = b"to be signed";
    let sig = signer.sign(&KeyRef("k".into()), Alg::Es256, msg).unwrap();

    // Real verification against the signer's raw public key.
    assert!(AwsLc
        .verify(Alg::Es256, signer.public_key_raw(), msg, &sig)
        .is_ok());
    // Tampered message fails.
    assert!(AwsLc
        .verify(Alg::Es256, signer.public_key_raw(), b"other", &sig)
        .is_err());
    // Tampered signature fails.
    let mut bad = sig.clone();
    bad[0] ^= 0xff;
    assert!(AwsLc
        .verify(Alg::Es256, signer.public_key_raw(), msg, &bad)
        .is_err());
}
