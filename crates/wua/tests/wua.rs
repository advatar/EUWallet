//! wua tests (plan Section 6): Wallet Unit Attestation verification with real crypto, key binding,
//! assurance level, and negatives (wrong provider key, expired, key mismatch).
use base64ct::{Base64UrlUnpadded, Encoding};
use crypto_backend::{AwsLc, SoftwareSigner};
use crypto_traits::{Alg, KeyRef, Signer};
use wua::{parse_and_verify, AssuranceLevel, WuaError};

fn b64(b: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(b)
}

/// The wallet provider issues a WUA binding `device_pub` at the given assurance level.
fn issue_wua(provider: &SoftwareSigner, device_pub: &[u8], aal: &str, exp: i64) -> Vec<u8> {
    let header = b64(br#"{"alg":"ES256","typ":"wallet-unit-attestation+jwt"}"#);
    let payload = b64(serde_json::json!({
        "iss": "https://wallet-provider.example",
        "exp": exp,
        "aal": aal,
        "cnf": { "jwk_raw": b64(device_pub) }
    })
    .to_string()
    .as_bytes());
    let si = format!("{header}.{payload}");
    let sig = provider
        .sign(&KeyRef("wp".into()), Alg::Es256, si.as_bytes())
        .unwrap();
    format!("{si}.{}", b64(&sig)).into_bytes()
}

#[test]
fn verifies_and_binds_device_key() {
    let provider = SoftwareSigner::generate_p256().unwrap();
    let device = SoftwareSigner::generate_p256().unwrap();
    let wua = issue_wua(&provider, device.public_key_raw(), "high", 4_000_000_000);

    let att = parse_and_verify(
        &wua,
        provider.public_key_raw(),
        &AwsLc,
        Alg::Es256,
        1_790_000_000,
    )
    .expect("verify");
    assert_eq!(att.assurance_level, AssuranceLevel::High);
    assert!(att.attests_key(device.public_key_raw()));
    assert!(att.is_valid_for(device.public_key_raw(), AssuranceLevel::Substantial));

    // A different key is NOT attested (defeats self-claims).
    let other = SoftwareSigner::generate_p256().unwrap();
    assert!(!att.attests_key(other.public_key_raw()));
}

#[test]
fn rejects_wrong_provider() {
    let provider = SoftwareSigner::generate_p256().unwrap();
    let attacker = SoftwareSigner::generate_p256().unwrap();
    let device = SoftwareSigner::generate_p256().unwrap();
    let wua = issue_wua(&provider, device.public_key_raw(), "high", 4_000_000_000);
    assert_eq!(
        parse_and_verify(&wua, attacker.public_key_raw(), &AwsLc, Alg::Es256, 1).unwrap_err(),
        WuaError::BadSignature
    );
}

#[test]
fn rejects_expired() {
    let provider = SoftwareSigner::generate_p256().unwrap();
    let device = SoftwareSigner::generate_p256().unwrap();
    let wua = issue_wua(&provider, device.public_key_raw(), "high", 1_000_000);
    assert_eq!(
        parse_and_verify(
            &wua,
            provider.public_key_raw(),
            &AwsLc,
            Alg::Es256,
            1_790_000_000
        )
        .unwrap_err(),
        WuaError::Expired
    );
}

#[test]
fn assurance_level_gate() {
    let provider = SoftwareSigner::generate_p256().unwrap();
    let device = SoftwareSigner::generate_p256().unwrap();
    let wua = issue_wua(
        &provider,
        device.public_key_raw(),
        "substantial",
        4_000_000_000,
    );
    let att = parse_and_verify(&wua, provider.public_key_raw(), &AwsLc, Alg::Es256, 1).unwrap();
    // Substantial does not meet a High requirement.
    assert!(!att.is_valid_for(device.public_key_raw(), AssuranceLevel::High));
    assert!(att.is_valid_for(device.public_key_raw(), AssuranceLevel::Substantial));
}
