//! End-to-end OpenID4VP-over-Digital-Credentials-API presentation driven through the real
//! `handle_event_json` FFI boundary (the path the iOS provider extension uses).
//!
//! A simulated browser verifier sends an unsigned `dc_api` request (mso_mdoc DCQL query) with an
//! OS-authenticated Origin; the wallet renders consent (WYSIWYS operationId + hash), signs the
//! DeviceAuthentication, and returns a `vp_token`. The test proves (a) the consent render binds an
//! operationId + 32-byte hash, (b) the DeviceAuth signing input is bound byte-exactly to the
//! `OpenID4VPDCAPIHandover` (Origin + nonce), and (c) the returned DeviceResponse discloses exactly
//! the requested element and not the withheld one.

use cose::cbor::{decode_value, Value};
use crypto_backend::{AwsLc, SoftwareSigner};
use crypto_traits::{Alg, KeyRef, Signer};
use mdoc::{build_and_sign, IssuerSignedItem, ValidityInfo};
use std::collections::BTreeMap;
use wallet_core::proximity_session::sec1_to_cose_ec2;
use wallet_core::{Core, Event, MdocHolding};

const DOCTYPE: &str = "eu.europa.ec.eudi.pid.1";
const NS: &str = "eu.europa.ec.eudi.pid.1";
const ORIGIN: &str = "https://verifier.example.com";
const NONCE: &str = "n-0S6_WzA2Mj";

fn json_u8s(bytes: &[u8]) -> String {
    let nums: Vec<String> = bytes.iter().map(ToString::to_string).collect();
    format!("[{}]", nums.join(","))
}
fn effects(json: &str) -> Vec<serde_json::Value> {
    serde_json::from_str(json).expect("effect array")
}
fn find<'a>(fx: &'a [serde_json::Value], ty: &str) -> Option<&'a serde_json::Value> {
    fx.iter().find(|e| e["type"] == serde_json::json!(ty))
}

fn cose_key_value(sec1: &[u8]) -> Value {
    decode_value(&sec1_to_cose_ec2(sec1).expect("SEC1"), 0)
        .expect("COSE_Key decodes")
        .0
}

fn seed_pid_mdoc(core: &mut Core, issuer: &SoftwareSigner, device: &SoftwareSigner) {
    let mut name_spaces = BTreeMap::new();
    name_spaces.insert(
        NS.to_string(),
        vec![
            IssuerSignedItem {
                digest_id: 0,
                random: vec![0x11; 16],
                element_id: "age_over_18".into(),
                element_value: Value::Bool(true),
            },
            IssuerSignedItem {
                digest_id: 1,
                random: vec![0x22; 16],
                element_id: "family_name".into(),
                element_value: Value::Text("Andersson".into()),
            },
        ],
    );
    let issuer_signed = build_and_sign(
        name_spaces,
        DOCTYPE,
        cose_key_value(device.public_key_raw()),
        ValidityInfo {
            signed: "2026-07-19T00:00:00Z".into(),
            valid_from: "2026-07-19T00:00:00Z".into(),
            valid_until: "2035-01-01T00:00:00Z".into(),
        },
        &AwsLc,
        issuer,
        &KeyRef("issuer".into()),
        Alg::Es256,
    )
    .expect("issue PID mdoc");
    core.load_unverified_mdoc_for_testing(MdocHolding {
        doctype: DOCTYPE.into(),
        issuer_signed,
    });
}

fn dcapi_request() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "response_type": "vp_token",
        "response_mode": "dc_api",
        "nonce": NONCE,
        "dcql_query": { "credentials": [ {
            "id": "pid", "format": "mso_mdoc",
            "meta": { "doctype_value": DOCTYPE },
            "claims": [ { "path": [NS, "age_over_18"] } ]
        } ] }
    }))
    .unwrap()
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|w| w == needle.as_bytes())
}

#[test]
fn dcapi_presentation_binds_the_origin_and_returns_a_minimised_vp_token() {
    let issuer = SoftwareSigner::generate_p256().unwrap();
    let device = SoftwareSigner::generate_p256().unwrap();
    let mut core = Core::new("wallet-client", "device-key");
    core.handle_event(Event::SetClock {
        epoch: 1_790_000_000,
    });
    seed_pid_mdoc(&mut core, &issuer, &device);

    // 1. The browser hands the wallet a DC-API request + the OS-verified Origin.
    let out = core
        .handle_event_json(&format!(
            r#"{{"type":"dcApiRequestReceived","request":{},"origin":{}}}"#,
            json_u8s(&dcapi_request()),
            serde_json::to_string(ORIGIN).unwrap()
        ))
        .expect("request accepted");
    let fx = effects(&out);
    let render = find(&fx, "render").expect("a consent render");
    assert_eq!(
        render["screen"]["screen"],
        serde_json::json!("dcApiConsent")
    );
    assert_eq!(render["screen"]["origin"], serde_json::json!(ORIGIN));
    // The consent screen exposes the minimised claim set under the camelCase key the bindings decode
    // (`requestedClaims`, NOT snake_case) — guards the `rename_all_fields` serde attribute.
    assert_eq!(
        render["screen"]["requestedClaims"],
        serde_json::json!(["eu.europa.ec.eudi.pid.1/age_over_18"]),
        "dcApiConsent must expose requestedClaims (camelCase) minimised to the requested element"
    );
    let operation_id = render["operationId"].as_u64().expect("operationId");
    let auth_hash_json =
        serde_json::to_string(&render["authorizationHash"]).expect("authorizationHash");
    assert_eq!(
        render["authorizationHash"].as_array().map(Vec::len),
        Some(32)
    );

    // 2. Consent → the core asks the device to sign the DeviceAuthentication.
    let out = core
        .handle_event_json(&format!(
            r#"{{"type":"userConsented","operationId":{operation_id},"authorizationHash":{auth_hash_json}}}"#
        ))
        .expect("userConsented accepted");
    let fx = effects(&out);
    let sign = find(&fx, "sign").expect("sign");
    let sign_operation_id = sign["operationId"].as_u64().expect("sign operationId");
    let signing_input: Vec<u8> = sign["payload"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap() as u8)
        .collect();

    // The signing input is bound byte-exactly to the OpenID4VPDCAPIHandover (Origin + nonce).
    let transcript = mdoc::oid4vp_dcapi_session_transcript(&AwsLc, ORIGIN, NONCE, None);
    let device_auth = mdoc::device_authentication_bytes(
        &transcript,
        DOCTYPE,
        &mdoc::empty_device_namespaces_bytes(),
    )
    .unwrap();
    let expected = cose::sig_structure(
        &cose::encode_protected_header(Alg::Es256),
        &[],
        &device_auth,
    );
    assert_eq!(
        signing_input, expected,
        "DeviceAuth signing input must bind the DC-API Origin+nonce handover"
    );

    // 3. Device signs → the wallet returns the vp_token to the browser.
    let signature = device
        .sign(&KeyRef("device-key".into()), Alg::Es256, &signing_input)
        .unwrap();
    let out = core
        .handle_event_json(&format!(
            r#"{{"type":"deviceSignatureProduced","operationId":{sign_operation_id},"signature":{}}}"#,
            json_u8s(&signature)
        ))
        .expect("signature accepted");
    let response: Vec<u8> = find(&effects(&out), "emitDcApiResponse").expect("dc-api response")
        ["response"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap() as u8)
        .collect();

    // The response is { "vp_token": { "pid": [ base64url(DeviceResponse) ] } }.
    let body: serde_json::Value = serde_json::from_slice(&response).unwrap();
    let b64 = body["vp_token"]["pid"][0].as_str().expect("vp_token entry");
    use base64ct::{Base64UrlUnpadded, Encoding};
    let device_response = Base64UrlUnpadded::decode_vec(b64).unwrap();

    assert!(contains(&device_response, "documents"), "a DeviceResponse");
    assert!(
        contains(&device_response, "age_over_18"),
        "discloses the requested element"
    );
    assert!(
        !contains(&device_response, "family_name"),
        "withholds the un-requested element (minimised)"
    );
}
