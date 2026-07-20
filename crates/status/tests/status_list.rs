//! status tests (plan Section 6): Token Status List verification with real crypto + real DEFLATE,
//! index lookup, and the deterministic fail-open/fail-closed policy.
use base64ct::{Base64UrlUnpadded, Encoding};
use crypto_backend::{AwsLc, SoftwareSigner};
use crypto_traits::{Alg, KeyRef, Signer};
use status::{decide, parse_and_verify, CredentialStatus, Decision, FailPolicy, StatusError};

const URI: &str = "https://status.example/lists/1";
const NOW: i64 = 1_790_000_000;

fn b64(b: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(b)
}

/// Build a signed Status List Token. `list` is the raw (uncompressed) bit-packed status bytes.
fn signed_token_with(
    provider: &SoftwareSigner,
    bits: u8,
    list: &[u8],
    subject: &str,
    issued_at: i64,
    exp: i64,
    ttl: i64,
) -> Vec<u8> {
    let compressed = miniz_oxide::deflate::compress_to_vec_zlib(list, 6);
    let header = b64(br#"{"alg":"ES256","typ":"statuslist+jwt"}"#);
    let payload = b64(serde_json::json!({
        "sub": subject,
        "iat": issued_at,
        "exp": exp,
        "ttl": ttl,
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

fn signed_token(provider: &SoftwareSigner, bits: u8, list: &[u8]) -> Vec<u8> {
    signed_token_with(provider, bits, list, URI, NOW, NOW + 3600, 300)
}

#[test]
fn looks_up_statuses_with_real_crypto_and_deflate() {
    let provider = SoftwareSigner::generate_p256().unwrap();
    // bits=2, one byte encodes 4 entries: idx0=Valid(0), idx1=Invalid(1), idx2=Suspended(2), idx3=Valid(0)
    // byte = 0 | 1<<2 | 2<<4 | 0<<6 = 0x24
    let token = signed_token(&provider, 2, &[0x24]);
    let list = parse_and_verify(
        &token,
        URI,
        provider.public_key_raw(),
        &AwsLc,
        Alg::Es256,
        NOW,
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
    let token = signed_token(&provider, 1, &[0x00]);
    assert_eq!(
        parse_and_verify(
            &token,
            URI,
            attacker.public_key_raw(),
            &AwsLc,
            Alg::Es256,
            NOW
        )
        .unwrap_err(),
        StatusError::BadSignature
    );
}

#[test]
fn rejects_expired_token() {
    let provider = SoftwareSigner::generate_p256().unwrap();
    let token = signed_token_with(&provider, 1, &[0x00], URI, NOW - 100, NOW - 1, 300);
    assert_eq!(
        parse_and_verify(
            &token,
            URI,
            provider.public_key_raw(),
            &AwsLc,
            Alg::Es256,
            NOW
        )
        .unwrap_err(),
        StatusError::Expired
    );
}

#[test]
fn rejects_list_substitution_and_stale_or_future_tokens() {
    let provider = SoftwareSigner::generate_p256().unwrap();
    let token = signed_token(&provider, 1, &[0]);
    assert_eq!(
        parse_and_verify(
            &token,
            "https://status.example/lists/attacker",
            provider.public_key_raw(),
            &AwsLc,
            Alg::Es256,
            NOW
        )
        .unwrap_err(),
        StatusError::SubjectMismatch
    );

    let stale = signed_token_with(
        &provider,
        1,
        &[0],
        URI,
        NOW - status::MAX_STATUS_AGE_SECONDS - 1,
        NOW + 300,
        300,
    );
    assert_eq!(
        parse_and_verify(
            &stale,
            URI,
            provider.public_key_raw(),
            &AwsLc,
            Alg::Es256,
            NOW
        )
        .unwrap_err(),
        StatusError::Stale
    );

    let future = signed_token_with(&provider, 1, &[0], URI, NOW + 301, NOW + 900, 300);
    assert_eq!(
        parse_and_verify(
            &future,
            URI,
            provider.public_key_raw(),
            &AwsLc,
            Alg::Es256,
            NOW
        )
        .unwrap_err(),
        StatusError::NotYetValid
    );
}

#[test]
fn cache_freshness_is_bounded_by_ttl() {
    let provider = SoftwareSigner::generate_p256().unwrap();
    let token = signed_token_with(&provider, 1, &[0], URI, NOW, NOW + 3600, 10);
    let list = parse_and_verify(
        &token,
        URI,
        provider.public_key_raw(),
        &AwsLc,
        Alg::Es256,
        NOW,
    )
    .unwrap();
    assert!(list.is_fresh_at(NOW + 9));
    assert!(!list.is_fresh_at(NOW + 10));
}

#[test]
fn rejects_zlib_decompression_bomb_at_fixed_limit() {
    let provider = SoftwareSigner::generate_p256().unwrap();
    let oversized = vec![0u8; status::MAX_DECOMPRESSED_BYTES + 1];
    let token = signed_token(&provider, 1, &oversized);
    assert_eq!(
        parse_and_verify(
            &token,
            URI,
            provider.public_key_raw(),
            &AwsLc,
            Alg::Es256,
            NOW
        )
        .unwrap_err(),
        StatusError::ResourceLimit
    );
}

#[test]
fn rejects_bits_values_that_would_truncate_to_a_supported_u8() {
    let provider = SoftwareSigner::generate_p256().unwrap();
    let token = signed_token(&provider, 1, &[0]);
    let compact = String::from_utf8(token).unwrap();
    let mut parts = compact.split('.');
    let header = parts.next().unwrap();
    let payload = parts.next().unwrap();
    let decoded = Base64UrlUnpadded::decode_vec(payload).unwrap();
    let mut claims: serde_json::Value = serde_json::from_slice(&decoded).unwrap();
    claims["status_list"]["bits"] = serde_json::json!(257);
    let payload = b64(claims.to_string().as_bytes());
    let signing_input = format!("{header}.{payload}");
    let signature = provider
        .sign(&KeyRef("p".into()), Alg::Es256, signing_input.as_bytes())
        .unwrap();
    let token = format!("{signing_input}.{}", b64(&signature));

    assert_eq!(
        parse_and_verify(
            token.as_bytes(),
            URI,
            provider.public_key_raw(),
            &AwsLc,
            Alg::Es256,
            NOW,
        )
        .unwrap_err(),
        StatusError::UnsupportedBits
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
