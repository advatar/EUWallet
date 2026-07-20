//! trust tests (plan Section 6): signed trusted-list verification with real crypto, rollback
//! protection, validity, and anchor queries backed by a real X.509 CA certificate.
use base64ct::{Base64UrlUnpadded, Encoding};
use crypto_backend::{AwsLc, SoftwareSigner};
use crypto_traits::{Alg, KeyRef, Signer};
use trust::{parse_and_verify, ServiceType, TrustError, TrustStore};

const CA_DER: &[u8] = include_bytes!("../../x509/tests/vectors/ca.der");

fn b64(b: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(b)
}

/// Build a signed trust list (compact JWS) with the given sequence + validity window.
fn signed_list(operator: &SoftwareSigner, seq: u64, valid_from: i64, valid_until: i64) -> Vec<u8> {
    let header = b64(br#"{"alg":"ES256"}"#);
    let payload = b64(serde_json::json!({
        "seq": seq,
        "valid_from": valid_from,
        "valid_until": valid_until,
        "anchors": [
            { "cert": b64(CA_DER), "service": "rp-access-ca", "status": "granted" },
            { "cert": b64(CA_DER), "service": "pid", "status": "withdrawn" },
        ]
    })
    .to_string()
    .as_bytes());
    let si = format!("{header}.{payload}");
    let sig = operator
        .sign(&KeyRef("op".into()), Alg::Es256, si.as_bytes())
        .unwrap();
    format!("{si}.{}", b64(&sig)).into_bytes()
}

#[test]
fn verifies_and_exposes_granted_anchors() {
    let op = SoftwareSigner::generate_p256().unwrap();
    let list = signed_list(&op, 1, 0, 4_000_000_000);
    let parsed = parse_and_verify(
        &list,
        op.public_key_raw(),
        &AwsLc,
        Alg::Es256,
        1_790_000_000,
    )
    .expect("verify");
    assert_eq!(parsed.sequence_number, 1);

    let mut store = TrustStore::new();
    store.update(parsed).unwrap();
    // The granted RP-access CA is exposed; the withdrawn PID anchor is not.
    assert_eq!(
        store
            .granted_anchors(ServiceType::RelyingPartyAccessCa)
            .len(),
        1
    );
    assert_eq!(store.granted_anchors(ServiceType::PidProvider).len(), 0);
    // ...and it parses as a real X.509 cert usable for path validation.
    let anchors = store.parsed_anchors(ServiceType::RelyingPartyAccessCa);
    assert_eq!(anchors.len(), 1);
    assert!(anchors[0].is_ca);
}

#[test]
fn cached_anchors_are_not_authorizing_after_the_list_expires() {
    let op = SoftwareSigner::generate_p256().unwrap();
    let parsed = parse_and_verify(
        &signed_list(&op, 1, 10, 20),
        op.public_key_raw(),
        &AwsLc,
        Alg::Es256,
        15,
    )
    .unwrap();
    let mut store = TrustStore::new();
    store.update(parsed).unwrap();

    assert!(store.is_valid_at(20));
    assert_eq!(
        store
            .parsed_anchors_at(ServiceType::RelyingPartyAccessCa, 20)
            .len(),
        1
    );
    assert!(!store.is_valid_at(21));
    assert!(store
        .parsed_anchors_at(ServiceType::RelyingPartyAccessCa, 21)
        .is_empty());
}

#[test]
fn rejects_wrong_operator_signature() {
    let op = SoftwareSigner::generate_p256().unwrap();
    let attacker = SoftwareSigner::generate_p256().unwrap();
    let list = signed_list(&op, 1, 0, 4_000_000_000);
    let err = parse_and_verify(
        &list,
        attacker.public_key_raw(),
        &AwsLc,
        Alg::Es256,
        1_790_000_000,
    )
    .unwrap_err();
    assert_eq!(err, TrustError::BadSignature);
}

#[test]
fn rejects_expired_list() {
    let op = SoftwareSigner::generate_p256().unwrap();
    let list = signed_list(&op, 1, 0, 1_000_000); // valid_until far in the past
    let err = parse_and_verify(
        &list,
        op.public_key_raw(),
        &AwsLc,
        Alg::Es256,
        1_790_000_000,
    )
    .unwrap_err();
    assert_eq!(err, TrustError::Expired);
}

#[test]
fn store_enforces_monotonic_rollback_protection() {
    let op = SoftwareSigner::generate_p256().unwrap();
    let mut store = TrustStore::new();
    let l5 = parse_and_verify(
        &signed_list(&op, 5, 0, 4_000_000_000),
        op.public_key_raw(),
        &AwsLc,
        Alg::Es256,
        1,
    )
    .unwrap();
    store.update(l5).unwrap();
    // A replayed/older list (seq <= current) is rejected.
    let l5b = parse_and_verify(
        &signed_list(&op, 5, 0, 4_000_000_000),
        op.public_key_raw(),
        &AwsLc,
        Alg::Es256,
        1,
    )
    .unwrap();
    assert_eq!(store.update(l5b), Err(TrustError::Rollback));
    let l4 = parse_and_verify(
        &signed_list(&op, 4, 0, 4_000_000_000),
        op.public_key_raw(),
        &AwsLc,
        Alg::Es256,
        1,
    )
    .unwrap();
    assert_eq!(store.update(l4), Err(TrustError::Rollback));
    // A newer list is accepted.
    let l6 = parse_and_verify(
        &signed_list(&op, 6, 0, 4_000_000_000),
        op.public_key_raw(),
        &AwsLc,
        Alg::Es256,
        1,
    )
    .unwrap();
    store.update(l6).unwrap();
    assert_eq!(store.sequence_number(), Some(6));
}
