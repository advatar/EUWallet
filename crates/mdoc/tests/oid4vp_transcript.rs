//! The OpenID4VP SessionTranscript binds an mdoc presentation to the verifier's client_id,
//! response_uri, the request nonce, and the wallet's mdoc_generated_nonce — the anti-relay anchor
//! the device signature covers. These tests pin its structure and its sensitivity to every input.

use cose::cbor::{self, Value};
use crypto_backend::AwsLc;
use mdoc::oid4vp_session_transcript;

const CID: &str = "x509_san_dns:verifier.example";
const RURI: &str = "https://verifier.example/response";
const NONCE: &str = "n-0S6_WzA2Mj";
const MGN: &str = "mdoc-generated-nonce-abc";

#[test]
fn transcript_has_the_openid4vp_handover_shape() {
    let t = oid4vp_session_transcript(&AwsLc, CID, RURI, NONCE, MGN);
    let v = cbor::from_canonical_slice(&t).expect("canonical CBOR");
    let Value::Array(top) = v else { panic!("SessionTranscript is an array") };
    assert_eq!(top.len(), 3);
    assert_eq!(top[0], Value::Null, "DeviceEngagementBytes is null for OID4VP");
    assert_eq!(top[1], Value::Null, "EReaderKeyBytes is null for OID4VP");
    let Value::Array(handover) = &top[2] else { panic!("Handover is an array") };
    assert_eq!(handover.len(), 3);
    assert!(matches!(handover[0], Value::Bytes(ref b) if b.len() == 32), "clientIdHash = SHA-256");
    assert!(matches!(handover[1], Value::Bytes(ref b) if b.len() == 32), "responseUriHash = SHA-256");
    assert_eq!(handover[2], Value::Text(NONCE.into()), "nonce carried verbatim");
}

#[test]
fn transcript_is_deterministic() {
    assert_eq!(
        oid4vp_session_transcript(&AwsLc, CID, RURI, NONCE, MGN),
        oid4vp_session_transcript(&AwsLc, CID, RURI, NONCE, MGN),
    );
}

#[test]
fn transcript_changes_with_every_field() {
    let base = oid4vp_session_transcript(&AwsLc, CID, RURI, NONCE, MGN);
    assert_ne!(base, oid4vp_session_transcript(&AwsLc, "other.example", RURI, NONCE, MGN));
    assert_ne!(base, oid4vp_session_transcript(&AwsLc, CID, "https://evil.example/r", NONCE, MGN));
    assert_ne!(base, oid4vp_session_transcript(&AwsLc, CID, RURI, "different-nonce", MGN));
    assert_ne!(
        base,
        oid4vp_session_transcript(&AwsLc, CID, RURI, NONCE, "different-mdoc-nonce"),
        "a different mdoc_generated_nonce must yield a different transcript"
    );
}
