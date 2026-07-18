//! A real ISO 18013-5 `DeviceResponse` must assemble from the genuine structures (issuer-signed
//! MSO + device-authenticated response) and decode back to the standard shape. This exercises the
//! faithful CBOR builders (`device_response`, `device_authentication_bytes`, `IssuerSigned::to_value`).

use std::collections::BTreeMap;

use cose::cbor::{self, Value};
use cose::{CoseSign1, UnprotectedHeader};
use crypto_backend::{AwsLc, SoftwareSigner};
use crypto_traits::{Alg, KeyRef};
use mdoc::{
    build_and_sign, device_authentication_bytes, device_response, IssuerSignedItem, ValidityInfo,
};

const DOC_TYPE: &str = "org.iso.18013.5.1.mDL";
const NS: &str = "org.iso.18013.5.1";

fn map_get<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    match v {
        Value::Map(pairs) => pairs
            .iter()
            .find(|(k, _)| matches!(k, Value::Text(t) if t == key))
            .map(|(_, val)| val),
        _ => None,
    }
}

#[test]
fn assembles_and_decodes_a_real_device_response() {
    let issuer = SoftwareSigner::generate_p256().unwrap();
    let device = SoftwareSigner::generate_p256().unwrap();

    // One disclosed item in the mDL namespace.
    let mut name_spaces = BTreeMap::new();
    name_spaces.insert(
        NS.to_string(),
        vec![IssuerSignedItem {
            digest_id: 0,
            random: vec![0u8; 16],
            element_id: "family_name".into(),
            element_value: Value::Text("Andersson".into()),
        }],
    );

    // Issuer builds + signs the MSO over the item digests.
    let issuer_signed = build_and_sign(
        name_spaces,
        DOC_TYPE,
        Value::Text("device-key-cose".into()),
        ValidityInfo {
            signed: "2026-01-01T00:00:00Z".into(),
            valid_from: "2026-01-01T00:00:00Z".into(),
            valid_until: "2027-01-01T00:00:00Z".into(),
        },
        &AwsLc,
        &issuer,
        &KeyRef("issuer".into()),
        Alg::Es256,
    )
    .expect("issuer signs MSO");

    // Session transcript (canonical CBOR array) + empty device namespaces.
    let session_transcript = Value::Array(vec![
        Value::Text("DeviceEngagement".into()),
        Value::Bytes(vec![1, 2, 3]),
    ])
    .to_canonical();
    let device_ns_bytes = Value::Map(vec![]).to_canonical();

    // Device signs the DeviceAuthenticationBytes.
    let dab = device_authentication_bytes(&session_transcript, DOC_TYPE, &device_ns_bytes)
        .expect("device authentication bytes");
    let device_sig = CoseSign1::sign(
        &device,
        &KeyRef("device".into()),
        Alg::Es256,
        &dab,
        &[],
        UnprotectedHeader::default(),
    )
    .expect("device signs");

    let response = device_response(DOC_TYPE, &issuer_signed, &device_ns_bytes, &device_sig);

    // Decode and assert the real DeviceResponse shape.
    let v = cbor::from_canonical_slice(&response).expect("valid CBOR");
    assert!(matches!(map_get(&v, "version"), Some(Value::Text(s)) if s == "1.0"));
    assert!(matches!(map_get(&v, "status"), Some(Value::Uint(0))));

    let docs = match map_get(&v, "documents") {
        Some(Value::Array(a)) => a,
        _ => panic!("documents must be an array"),
    };
    assert_eq!(docs.len(), 1);
    let doc = &docs[0];
    assert!(matches!(map_get(doc, "docType"), Some(Value::Text(s)) if s == DOC_TYPE));

    // issuerSigned has nameSpaces + issuerAuth (a COSE_Sign1 array).
    let issuer_signed_v = map_get(doc, "issuerSigned").expect("issuerSigned");
    assert!(map_get(issuer_signed_v, "nameSpaces").is_some());
    assert!(matches!(map_get(issuer_signed_v, "issuerAuth"), Some(Value::Array(a)) if a.len() == 4));

    // deviceSigned has nameSpaces (tag-24) + deviceAuth.deviceSignature (COSE_Sign1).
    let device_signed_v = map_get(doc, "deviceSigned").expect("deviceSigned");
    let device_auth = map_get(device_signed_v, "deviceAuth").expect("deviceAuth");
    assert!(matches!(map_get(device_auth, "deviceSignature"), Some(Value::Array(a)) if a.len() == 4));
}

#[test]
fn device_authentication_binds_transcript_doctype_and_namespaces() {
    let st = Value::Array(vec![Value::Text("t".into())]).to_canonical();
    let ns = Value::Map(vec![]).to_canonical();
    let a = device_authentication_bytes(&st, DOC_TYPE, &ns).unwrap();
    // Different doctype or transcript ⇒ different bytes (the device signature is specific to them).
    let other_doc = device_authentication_bytes(&st, "other.doctype", &ns).unwrap();
    let st2 = Value::Array(vec![Value::Text("u".into())]).to_canonical();
    let other_st = device_authentication_bytes(&st2, DOC_TYPE, &ns).unwrap();
    assert_ne!(a, other_doc);
    assert_ne!(a, other_st);
}
