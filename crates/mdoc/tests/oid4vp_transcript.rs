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
    let Value::Array(top) = v else {
        panic!("SessionTranscript is an array")
    };
    assert_eq!(top.len(), 3);
    assert_eq!(
        top[0],
        Value::Null,
        "DeviceEngagementBytes is null for OID4VP"
    );
    assert_eq!(top[1], Value::Null, "EReaderKeyBytes is null for OID4VP");
    let Value::Array(handover) = &top[2] else {
        panic!("Handover is an array")
    };
    assert_eq!(handover.len(), 3);
    assert!(
        matches!(handover[0], Value::Bytes(ref b) if b.len() == 32),
        "clientIdHash = SHA-256"
    );
    assert!(
        matches!(handover[1], Value::Bytes(ref b) if b.len() == 32),
        "responseUriHash = SHA-256"
    );
    assert_eq!(
        handover[2],
        Value::Text(NONCE.into()),
        "nonce carried verbatim"
    );
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
    assert_ne!(
        base,
        oid4vp_session_transcript(&AwsLc, "other.example", RURI, NONCE, MGN)
    );
    assert_ne!(
        base,
        oid4vp_session_transcript(&AwsLc, CID, "https://evil.example/r", NONCE, MGN)
    );
    assert_ne!(
        base,
        oid4vp_session_transcript(&AwsLc, CID, RURI, "different-nonce", MGN)
    );
    assert_ne!(
        base,
        oid4vp_session_transcript(&AwsLc, CID, RURI, NONCE, "different-mdoc-nonce"),
        "a different mdoc_generated_nonce must yield a different transcript"
    );
}

#[test]
fn issuer_signed_round_trips_through_bytes() {
    use crypto_backend::SoftwareSigner;
    use crypto_traits::{Alg, KeyRef};
    use mdoc::{
        build_and_sign, verify_issuer_signed, IssuerSigned, IssuerSignedItem, ValidityInfo,
    };
    use std::collections::BTreeMap;

    let issuer = SoftwareSigner::generate_p256().unwrap();
    let item = IssuerSignedItem {
        digest_id: 0,
        random: vec![0x22; 16],
        element_id: "age_over_18".into(),
        element_value: Value::Bool(true),
    };
    let mut ns = BTreeMap::new();
    ns.insert("org.iso.18013.5.1".to_string(), vec![item]);
    let issued = build_and_sign(
        ns,
        "org.iso.18013.5.1.mDL",
        Value::Map(vec![]),
        ValidityInfo {
            signed: "2026-07-19T00:00:00Z".into(),
            valid_from: "2026-07-19T00:00:00Z".into(),
            valid_until: "2035-01-01T00:00:00Z".into(),
        },
        &AwsLc,
        &issuer,
        &KeyRef("issuer".into()),
        Alg::Es256,
    )
    .unwrap();

    // Serialize → parse → identical structure + recoverable doctype.
    let bytes = issued.to_value().to_canonical();
    let parsed = IssuerSigned::parse(&bytes).expect("round-trips from bytes");
    assert_eq!(parsed, issued);
    assert_eq!(parsed.doc_type().unwrap(), "org.iso.18013.5.1.mDL");
    // The parsed credential still verifies against the issuer key + item digests.
    verify_issuer_signed(&parsed, &AwsLc, &AwsLc, issuer.public_key_raw(), Alg::Es256)
        .expect("parsed IssuerSigned verifies");
}
