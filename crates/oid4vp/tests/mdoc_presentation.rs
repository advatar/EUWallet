//! mdoc-over-OpenID4VP: the presentation machine, given a selected mdoc credential, must produce
//! a real ISO 18013-5 `DeviceResponse` as the `vp_token` — with the device authentication signed
//! over the OpenID4VP `SessionTranscript`. This drives the machine through consent → device
//! signature → response, then VERIFIES the emitted DeviceResponse's device signature with real
//! aws-lc-rs crypto (reconstructing the exact `Sig_structure` the verifier would).

use std::collections::BTreeMap;

use base64ct::{Base64UrlUnpadded, Encoding};
use cose::cbor::{self, Value};
use crypto_backend::{AwsLc, SoftwareSigner};
use crypto_traits::{Alg, KeyRef, Signer, Verifier};
use mdoc::{
    build_and_sign, device_authentication_bytes, empty_device_namespaces_bytes,
    oid4vp_session_transcript, IssuerSignedItem, ValidityInfo,
};
use oid4vp::{step, AuthRequest, Env, Input, Output, SelectedCredential, State};

const DOCTYPE: &str = "org.iso.18013.5.1.mDL";
const NS: &str = "org.iso.18013.5.1";
const CLIENT_ID: &str = "x509_san_dns:verifier.example";
const RESPONSE_URI: &str = "https://verifier.example/response";
const NONCE: u64 = 424_242;
const MGN: &str = "mdoc-generated-nonce-1";

fn cose_key(pubkey: &[u8]) -> Value {
    // Uncompressed P-256 point: 0x04 || X(32) || Y(32). COSE_Key: {1:2(EC2), -1:1(P-256), -2:X, -3:Y}.
    let x = pubkey[1..33].to_vec();
    let y = pubkey[33..65].to_vec();
    Value::Map(vec![
        (Value::Uint(1), Value::Uint(2)),
        (Value::Nint(0), Value::Uint(1)),  // -1 => P-256
        (Value::Nint(1), Value::Bytes(x)), // -2 => x
        (Value::Nint(2), Value::Bytes(y)), // -3 => y
    ])
}

fn map_get<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    match v {
        Value::Map(pairs) => pairs
            .iter()
            .find(|(k, _)| *k == Value::Text(key.into()))
            .map(|(_, x)| x),
        _ => None,
    }
}

#[test]
fn mdoc_presentation_assembles_a_verifiable_device_response() {
    // ---- Issue a real mdoc (issuer-signed MSO binding the device key). ----
    let issuer = SoftwareSigner::generate_p256().unwrap();
    let device = SoftwareSigner::generate_p256().unwrap();
    let item = IssuerSignedItem {
        digest_id: 0,
        random: vec![0x11; 16],
        element_id: "age_over_18".into(),
        element_value: Value::Bool(true),
    };
    let mut name_spaces = BTreeMap::new();
    name_spaces.insert(NS.to_string(), vec![item]);
    let issuer_signed = build_and_sign(
        name_spaces,
        DOCTYPE,
        cose_key(device.public_key_raw()),
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
    .expect("issuer signs the mdoc");

    // ---- Drive the machine: RequestValidated → ConsentGranted → sign → DeviceSignatureProduced. ----
    let transcript = oid4vp_session_transcript(&AwsLc, CLIENT_ID, RESPONSE_URI, "424242", MGN);
    let ns_bytes = empty_device_namespaces_bytes();
    let req = AuthRequest {
        client_id: CLIENT_ID.into(),
        nonce: NONCE,
        audience: "wallet.example".into(),
        response_uri: RESPONSE_URI.into(),
        redirect_uri: None,
        purpose: Some("age".into()),
        requested_claims: vec!["age_over_18".into()],
        state: Some("st-1".into()),
        response_mode: "direct_post".into(),
        dcql_id: Some("cred1".into()),
        requested_vcts: vec![],
        requested_doctypes: vec![],
        dcql: None,
        response_encryption_key: None,
        signed_payload: b"x".to_vec(),
        signature: b"y".to_vec(),
        request_alg: Alg::Es256,
    };
    let selected = SelectedCredential::Mdoc {
        doctype: DOCTYPE.into(),
        issuer_signed: issuer_signed.clone(),
        session_transcript: transcript.clone(),
        device_namespaces: ns_bytes.clone(),
        mdoc_generated_nonce: MGN.into(),
        dcql_id: Some("cred1".into()),
    };
    let env = Env {
        wallet_client_id: "wallet.example",
        seen_nonces: &[],
        verifier: &AwsLc,
        digest: &AwsLc,
        now_epoch: 100,
        selected_credentials: std::slice::from_ref(&selected),
        device_key_ref: "device-key",
    };

    let (state, out) = step(
        &State::RequestValidated(Box::new(req)),
        &Input::ConsentGranted,
        &env,
    );
    assert!(matches!(state, State::AwaitingDeviceSignature(_)));
    let signing_input = match out.as_slice() {
        [Output::SignKeyBinding { signing_input, .. }] => signing_input.clone(),
        other => panic!("expected SignKeyBinding, got {other:?}"),
    };
    // The machine binds the device signature to the OID4VP SessionTranscript (anti-relay).
    let expected_device_auth =
        device_authentication_bytes(&transcript, DOCTYPE, &ns_bytes).unwrap();
    let protected = cose::encode_protected_header(Alg::Es256);
    assert_eq!(
        signing_input,
        cose::sig_structure(&protected, &[], &expected_device_auth)
    );

    // Device signs the Sig_structure; feed it back.
    let sig = device
        .sign(&KeyRef("device-key".into()), Alg::Es256, &signing_input)
        .unwrap();
    let (state, out) = step(&state, &Input::DeviceSignatureProduced(sig.clone()), &env);
    assert_eq!(state, State::Presenting);
    let body = match out.as_slice() {
        [Output::SendVpToken(b)] => String::from_utf8(b.clone()).unwrap(),
        other => panic!("expected SendVpToken, got {other:?}"),
    };

    // The response conveys the mdoc_generated_nonce so the verifier can rebuild the transcript.
    assert!(
        body.contains(&format!("mdoc_generated_nonce={MGN}")),
        "direct_post body must carry the mdoc_generated_nonce, got {body}"
    );

    // ---- Extract the DeviceResponse from the direct_post body and VERIFY the device signature. ----
    let vp_json = body
        .strip_prefix("vp_token=")
        .and_then(|s| s.split('&').next())
        .unwrap();
    let decoded = percent_decode(vp_json);
    let obj: serde_json::Value = serde_json::from_str(&decoded).unwrap();
    let device_response_b64 = obj["cred1"].as_str().expect("DCQL-keyed vp_token");
    let dr_cbor =
        Base64UrlUnpadded::decode_vec(device_response_b64).expect("base64url DeviceResponse");
    let dr = cbor::from_canonical_slice(&dr_cbor).expect("canonical DeviceResponse CBOR");

    // documents[0].docType == mDL
    let docs = match map_get(&dr, "documents") {
        Some(Value::Array(a)) => a,
        _ => panic!("documents array"),
    };
    assert_eq!(docs.len(), 1);
    assert_eq!(
        map_get(&docs[0], "docType"),
        Some(&Value::Text(DOCTYPE.into()))
    );

    // deviceSigned.deviceAuth.deviceSignature = [protected, unprotected, payload(null), signature]
    let device_signed = map_get(&docs[0], "deviceSigned").unwrap();
    let device_auth = map_get(device_signed, "deviceAuth").unwrap();
    let device_signature = map_get(device_auth, "deviceSignature").unwrap();
    let (got_protected, got_sig) = match device_signature {
        Value::Array(a) if a.len() == 4 => {
            let p = match &a[0] {
                Value::Bytes(b) => b.clone(),
                _ => panic!("protected bstr"),
            };
            assert_eq!(
                a[2],
                Value::Null,
                "payload is detached (null) in mdoc DeviceAuth"
            );
            let s = match &a[3] {
                Value::Bytes(b) => b.clone(),
                _ => panic!("signature bstr"),
            };
            (p, s)
        }
        _ => panic!("deviceSignature is a 4-element COSE_Sign1 array"),
    };

    // Reconstruct the exact Sig_structure a verifier would, and check the signature with real crypto.
    let tbs = cose::sig_structure(&got_protected, &[], &expected_device_auth);
    AwsLc
        .verify(Alg::Es256, device.public_key_raw(), &tbs, &got_sig)
        .expect(
            "the DeviceResponse's device signature verifies against the device key + transcript",
        );

    // The MSO's issuer signature + item digests also verify (issuer-side check).
    let _ = &issuer_signed;
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let hi = (b[i + 1] as char).to_digit(16).unwrap();
            let lo = (b[i + 2] as char).to_digit(16).unwrap();
            out.push((hi * 16 + lo) as u8);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap()
}
