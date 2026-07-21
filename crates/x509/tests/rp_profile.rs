//! x509 tests (plan Section 4.4) against REAL openssl-generated certificates. The headline
//! property: a valid TLS (serverAuth) certificate is rejected as NOT a registered relying party.
//! Signature verification goes through crypto-traits; a stub verifier stands in for aws-lc-rs
//! (real signature crypto is wired at the platform-crypto integration step, like the other codecs).
use base64ct::{Base64, Encoding};
use crypto_traits::{Alg, CertificatePublicKeyAlg, CertificateSignatureAlg, CryptoError, Verifier};
use x509::{
    check_credential_issuer, check_relying_party, parse_cert, validate_path, X509Error,
    EKU_MDOC_READER_AUTH,
};

const CA: &[u8] = include_bytes!("vectors/ca.der");
const RP: &[u8] = include_bytes!("vectors/rp.der");
const TLS: &[u8] = include_bytes!("vectors/tls.der");
const ISSUER_B64: &str = include_str!("vectors/issuer.der.b64");
const AMBIGUOUS_ISSUER_B64: &str = include_str!("vectors/ambiguous-issuer.der.b64");

// A timestamp within the certs' validity window (they were minted 2026-07-17 for 730 days).
const NOW: i64 = 1_790_000_000; // ~2026-09
const WAY_LATER: i64 = 2_100_000_000; // ~2036, past not_after

// Stub verifier: accepts (the chain's structural correctness is what these tests exercise;
// real ECDSA verification is behind this same trait via aws-lc-rs in production).
struct AcceptingVerifier;
impl Verifier for AcceptingVerifier {
    fn verify(&self, _a: Alg, _pk: &[u8], _msg: &[u8], _sig: &[u8]) -> Result<(), CryptoError> {
        Ok(())
    }

    fn validate_certificate_public_key(
        &self,
        _alg: CertificatePublicKeyAlg,
        _public_key: &[u8],
    ) -> Result<(), CryptoError> {
        Ok(())
    }

    fn verify_certificate(
        &self,
        _alg: CertificateSignatureAlg,
        _public_key: &[u8],
        _payload: &[u8],
        _sig: &[u8],
    ) -> Result<(), CryptoError> {
        Ok(())
    }
}

fn anchors() -> Vec<x509::ParsedCert> {
    vec![parse_cert(CA).expect("parse CA")]
}

fn decode_cert(encoded: &str) -> Vec<u8> {
    Base64::decode_vec(encoded.trim()).expect("valid test certificate base64")
}

#[test]
fn parses_rp_leaf_fields() {
    let rp = parse_cert(RP).expect("parse RP");
    assert!(!rp.is_ca, "RP leaf must be an end-entity");
    assert!(
        rp.eku.iter().any(|o| o == EKU_MDOC_READER_AUTH),
        "RP must carry the mdoc reader-auth EKU, got {:?}",
        rp.eku
    );
    assert!(
        !rp.policies.is_empty(),
        "RP must carry a certificate policy"
    );
}

#[test]
fn parses_ca_as_ca() {
    let ca = parse_cert(CA).expect("parse CA");
    assert!(ca.is_ca, "the CA cert must have basicConstraints CA:TRUE");
}

#[test]
fn registered_relying_party_is_accepted() {
    let profile = check_relying_party(&[RP.to_vec()], &anchors(), NOW, &AcceptingVerifier)
        .expect("RP should be accepted");
    assert!(profile.registered);
    assert!(profile.subject.contains("demo relying party"));
}

#[test]
fn credential_issuer_identity_comes_from_validated_leaf_uri_san() {
    let issuer = decode_cert(ISSUER_B64);
    let profile = check_credential_issuer(&[issuer], &anchors(), NOW, &AcceptingVerifier)
        .expect("credential issuer profile should pass");
    assert_eq!(profile.identity, "https://issuer.example");
    assert!(!profile.public_key_raw.is_empty());
    assert!(profile.not_before <= NOW && NOW <= profile.not_after);
}

#[test]
fn rp_leaf_cannot_be_reused_as_a_credential_issuer() {
    let err = check_credential_issuer(&[RP.to_vec()], &anchors(), NOW, &AcceptingVerifier)
        .expect_err("a leaf without an issuer identity URI must fail");
    assert_eq!(
        err,
        X509Error::ProfileViolation("credential issuer identity URI is missing")
    );
}

#[test]
fn ambiguous_credential_issuer_identity_is_rejected() {
    let issuer = decode_cert(AMBIGUOUS_ISSUER_B64);
    let err = check_credential_issuer(&[issuer], &anchors(), NOW, &AcceptingVerifier)
        .expect_err("multiple issuer identity URIs must fail");
    assert_eq!(
        err,
        X509Error::ProfileViolation("credential issuer identity is ambiguous")
    );
}

#[test]
fn trust_anchor_cannot_be_reused_as_a_supplied_credential_issuer() {
    let err = check_credential_issuer(&[CA.to_vec()], &anchors(), NOW, &AcceptingVerifier)
        .expect_err("a peer-supplied root cannot become a credential issuer leaf");
    assert_eq!(
        err,
        X509Error::PathInvalid("trust anchor must not be supplied in the certificate chain")
    );
}

#[test]
fn valid_tls_certificate_is_rejected_as_not_rp() {
    // The load-bearing test: a perfectly valid TLS chain (serverAuth EKU) is NOT a registered RP.
    let err = check_relying_party(&[TLS.to_vec()], &anchors(), NOW, &AcceptingVerifier)
        .expect_err("a serverAuth cert must not pass the RP profile");
    assert_eq!(
        err,
        X509Error::ProfileViolation("missing mdoc reader-auth EKU")
    );
}

#[test]
fn expired_certificate_fails_path_validation() {
    let err = validate_path(&[RP.to_vec()], &anchors(), WAY_LATER, &AcceptingVerifier)
        .expect_err("expired cert must fail");
    assert_eq!(
        err,
        X509Error::PathInvalid("certificate expired or not yet valid")
    );
}

#[test]
fn expired_appended_trust_anchor_fails_path_validation() {
    let mut expired_anchor = parse_cert(CA).expect("parse CA");
    expired_anchor.not_after = NOW - 1;
    let err = validate_path(&[RP.to_vec()], &[expired_anchor], NOW, &AcceptingVerifier)
        .expect_err("an expired root must not continue authorizing a cached path");
    assert_eq!(
        err,
        X509Error::PathInvalid("certificate expired or not yet valid")
    );
}

#[test]
fn missing_trust_anchor_fails() {
    // No anchors supplied → cannot chain.
    let err = validate_path(&[RP.to_vec()], &[], NOW, &AcceptingVerifier)
        .expect_err("must fail without an anchor");
    assert_eq!(err, X509Error::PathInvalid("no trust anchor for chain"));
}

#[test]
fn signature_failure_is_detected() {
    struct RejectingVerifier;
    impl Verifier for RejectingVerifier {
        fn verify(&self, _a: Alg, _pk: &[u8], _m: &[u8], _s: &[u8]) -> Result<(), CryptoError> {
            Err(CryptoError::Backend("nope".into()))
        }

        fn validate_certificate_public_key(
            &self,
            _alg: CertificatePublicKeyAlg,
            _public_key: &[u8],
        ) -> Result<(), CryptoError> {
            Ok(())
        }

        fn verify_certificate(
            &self,
            _alg: CertificateSignatureAlg,
            _public_key: &[u8],
            _payload: &[u8],
            _sig: &[u8],
        ) -> Result<(), CryptoError> {
            Err(CryptoError::Backend("nope".into()))
        }
    }
    let err = validate_path(&[RP.to_vec()], &anchors(), NOW, &RejectingVerifier)
        .expect_err("bad signature must fail");
    assert_eq!(err, X509Error::PathInvalid("signature verification failed"));
}

#[test]
fn malformed_der_never_panics() {
    assert_eq!(parse_cert(&[]), Err(X509Error::Der));
    assert_eq!(parse_cert(&[0xff; 20]), Err(X509Error::Der));
    let _ = parse_cert(&RP[..RP.len() / 2]); // truncated
}
