//! status tests (plan Section 6): Token Status List verification with real crypto + real DEFLATE,
//! index lookup, and the deterministic fail-open/fail-closed policy.
use base64ct::{Base64UrlUnpadded, Encoding};
use crypto_backend::{AwsLc, SoftwareSigner};
use crypto_traits::{Alg, KeyRef, Signer};
use status::{decide, parse_and_verify, CredentialStatus, Decision, FailPolicy, StatusError};

fn b64(b: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(b)
}

/// Build a signed Status List Token. `list` is the raw (uncompressed) bit-packed status bytes.
fn signed_token(provider: &SoftwareSigner, bits: u8, list: &[u8], exp: i64) -> Vec<u8> {
    let compressed = miniz_oxide::deflate::compress_to_vec(list, 6);
    let header = b64(br#"{"alg":"ES256","typ":"statuslist+jwt"}"#);
    let payload = b64(serde_json::json!({
        "exp": exp,
        "status_list": { "bits": bits, "lst": b64(&compressed) }
    })
    .to_string()
    .as_bytes());
    let si = format!("{header}.{payload}");
    let sig = provider
        .sign(&KeyRef("p".into()), Alg::Es256, si.as_bytes())
        .unwrap();
    format!("{si}.{}", b64(&sig)).into_bytes()
}

#[test]
fn looks_up_statuses_with_real_crypto_and_deflate() {
    let provider = SoftwareSigner::generate_p256().unwrap();
    // bits=2, one byte encodes 4 entries: idx0=Valid(0), idx1=Invalid(1), idx2=Suspended(2), idx3=Valid(0)
    // byte = 0 | 1<<2 | 2<<4 | 0<<6 = 0x24
    let token = signed_token(&provider, 2, &[0x24], 4_000_000_000);
    let list = parse_and_verify(
        &token,
        provider.public_key_raw(),
        &AwsLc,
        Alg::Es256,
        1_790_000_000,
    )
    .expect("verify");

    assert_eq!(list.status_at(0), CredentialStatus::Valid);
    assert_eq!(list.status_at(1), CredentialStatus::Invalid);
    assert_eq!(list.status_at(2), CredentialStatus::Suspended);
    assert_eq!(list.status_at(3), CredentialStatus::Valid);
    assert_eq!(list.status_at(9999), CredentialStatus::Unknown); // out of range
}

#[test]
fn rejects_wrong_provider_signature() {
    let provider = SoftwareSigner::generate_p256().unwrap();
    let attacker = SoftwareSigner::generate_p256().unwrap();
    let token = signed_token(&provider, 1, &[0x00], 4_000_000_000);
    assert_eq!(
        parse_and_verify(&token, attacker.public_key_raw(), &AwsLc, Alg::Es256, 1).unwrap_err(),
        StatusError::BadSignature
    );
}

#[test]
fn rejects_expired_token() {
    let provider = SoftwareSigner::generate_p256().unwrap();
    let token = signed_token(&provider, 1, &[0x00], 1_000_000);
    assert_eq!(
        parse_and_verify(
            &token,
            provider.public_key_raw(),
            &AwsLc,
            Alg::Es256,
            1_790_000_000
        )
        .unwrap_err(),
        StatusError::Expired
    );
}

#[test]
fn fail_policy_is_deterministic() {
    assert_eq!(
        decide(Some(CredentialStatus::Valid), FailPolicy::FailClosed),
        Decision::Accept
    );
    assert_eq!(
        decide(Some(CredentialStatus::Invalid), FailPolicy::FailOpen),
        Decision::Reject
    );
    assert_eq!(
        decide(Some(CredentialStatus::Suspended), FailPolicy::FailOpen),
        Decision::Reject
    );
    // Unavailable status: policy decides (offline proximity vs online remote).
    assert_eq!(decide(None, FailPolicy::FailOpen), Decision::Accept);
    assert_eq!(decide(None, FailPolicy::FailClosed), Decision::Reject);
}
