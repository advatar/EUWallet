//! The real **HAIP mdoc presentation profile**: mdoc-over-OpenID4VP *and* an encrypted
//! (`direct_post.jwt`) response, composed. The verifier requests an mDL by doctype with
//! `response_mode: "direct_post.jwt"`; the wallet answers with a compact JWE. Critically, the
//! `mdoc_generated_nonce` travels as the JWE `apu` — so the verifier, after decrypting, rebuilds
//! the ISO SessionTranscript from `apu` and checks the DeviceResponse's device signature. This
//! proves the two features (mdoc DeviceResponse + JWE response encryption) interlock exactly as a
//! HAIP mdoc verifier expects. All real aws-lc-rs crypto.
use base64ct::{Base64UrlUnpadded, Encoding};
use cose::cbor::{self, Value};
use crypto_backend::{AwsLc, P256AgreementKey, SoftwareSigner};
use crypto_traits::{Alg, KeyRef, Signer, Verifier};
use mdoc::{
    build_and_sign, device_authentication_bytes, empty_device_namespaces_bytes,
    oid4vp_session_transcript, IssuerSignedItem, ValidityInfo,
};
use serde_json::json;
use std::collections::BTreeMap;
use wallet_core::{Core, Effect, Event, MdocHolding};

const DOCTYPE: &str = "org.iso.18013.5.1.mDL";
const NS: &str = "org.iso.18013.5.1";
const CLIENT_ID: &str = "rp.example";
const RESPONSE_URI: &str = "https://rp.example/response";
const NONCE: u64 = 424_242;

fn b64(b: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(b)
}

const CA_DER: &[u8] = include_bytes!("../../x509/tests/vectors/ca.der");
const RP_DER: &[u8] = include_bytes!("../../x509/tests/vectors/rp.der");
const RP_PKCS8: &[u8] = include_bytes!("../../x509/tests/vectors/rp.pkcs8.der");

fn signed_trust_list(operator: &SoftwareSigner) -> Vec<u8> {
    let header = b64(br#"{"alg":"ES256"}"#);
    let payload = b64(json!({
        "seq": 1, "valid_from": 0, "valid_until": 4_000_000_000i64,
        "anchors": [{ "cert": b64(CA_DER), "service": "rp-access-ca", "status": "granted" }]
    })
    .to_string()
    .as_bytes());
    let si = format!("{header}.{payload}");
    let sig = operator.sign(&KeyRef("op".into()), Alg::Es256, si.as_bytes()).unwrap();
    format!("{si}.{}", b64(&sig)).into_bytes()
}

fn cose_key(pubkey: &[u8]) -> Value {
    Value::Map(vec![
        (Value::Uint(1), Value::Uint(2)),
        (Value::Nint(0), Value::Uint(1)),
        (Value::Nint(1), Value::Bytes(pubkey[1..33].to_vec())),
        (Value::Nint(2), Value::Bytes(pubkey[33..65].to_vec())),
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

/// RP-signed DCQL `mso_mdoc` request with `direct_post.jwt` + the verifier's encryption JWK.
fn sign_encrypted_mdoc_request(rp: &SoftwareSigner, nonce: u64, recipient_pub: &[u8]) -> Vec<u8> {
    let (x, y) = (&recipient_pub[1..33], &recipient_pub[33..65]);
    let header = b64(br#"{"alg":"ES256","typ":"oauth-authz-req+jwt"}"#);
    let payload = b64(serde_json::to_string(&json!({
        "client_id": CLIENT_ID,
        "nonce": nonce,
        "aud": "wallet.example",
        "response_uri": RESPONSE_URI,
        "response_mode": "direct_post.jwt",
        "purpose": "Prove you are over 18 (mDL)",
        "client_metadata": { "jwks": { "keys": [{
            "kty": "EC", "crv": "P-256", "use": "enc", "alg": "ECDH-ES", "x": b64(x), "y": b64(y)
        }]}},
        "dcql_query": { "credentials": [{
            "id": "mdl",
            "format": "mso_mdoc",
            "meta": { "doctype_value": DOCTYPE },
            "claims": [{ "path": [NS, "age_over_18"] }]
        }]},
    }))
    .unwrap()
    .as_bytes());
    let si = format!("{header}.{payload}");
    let sig = rp.sign(&KeyRef("r".into()), Alg::Es256, si.as_bytes()).unwrap();
    format!("{si}.{}", b64(&sig)).into_bytes()
}

#[test]
fn haip_mdoc_profile_encrypted_device_response_round_trips() {
    let issuer = SoftwareSigner::generate_p256().unwrap();
    let device = SoftwareSigner::generate_p256().unwrap();
    let rp = SoftwareSigner::from_pkcs8_der(RP_PKCS8).unwrap();
    let trust_operator = SoftwareSigner::generate_p256().unwrap();
    let verifier_enc = P256AgreementKey::generate().unwrap();

    // Issue + hold an mDL bound to the device key.
    let mut name_spaces = BTreeMap::new();
    name_spaces.insert(
        NS.to_string(),
        vec![IssuerSignedItem {
            digest_id: 0,
            random: vec![0x33; 16],
            element_id: "age_over_18".into(),
            element_value: Value::Bool(true),
        }],
    );
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
    .expect("issue mDL");

    let mut core = Core::new("wallet.example", "device-key");
    core.load_unverified_mdoc_for_testing(MdocHolding {
        doctype: DOCTYPE.into(),
        issuer_signed,
    });
    core.handle_event(Event::SetClock { epoch: 1_790_000_000 });
    core.load_trust_list(&signed_trust_list(&trust_operator), trust_operator.public_key_raw())
        .expect("trust list loads");

    // Drive the presentation.
    let request = sign_encrypted_mdoc_request(&rp, NONCE, verifier_enc.public_raw());
    core.handle_event(Event::AuthorizationRequestReceived { request });
    core.handle_event(Event::RpCertChainResolved {
        rp_cert_chain: vec![RP_DER.to_vec()],
        registered_redirect_uris: vec![],
    });
    let fx = core.handle_event(Event::UserConsented);
    let signing_input = fx
        .iter()
        .find_map(|e| match e {
            Effect::Sign { payload, .. } => Some(payload.clone()),
            _ => None,
        })
        .expect("consent → Sign the DeviceAuth");
    let sig = device.sign(&KeyRef("device-key".into()), Alg::Es256, &signing_input).unwrap();
    let fx = core.handle_event(Event::DeviceSignatureProduced { signature: sig });
    let body = fx
        .iter()
        .find_map(|e| match e {
            Effect::Http { body, .. } => Some(String::from_utf8(body.clone()).unwrap()),
            _ => None,
        })
        .expect("Http response");

    // Encrypted on the wire.
    assert!(body.starts_with("response="), "encrypted response, got {body}");
    assert!(!body.contains("vp_token="), "no plaintext vp_token on the wire");
    let compact = body.strip_prefix("response=").unwrap();

    // ---- VERIFIER: decrypt, recover mdoc_generated_nonce from apu, rebuild transcript, verify. ----
    let parts = jwe::parse_compact(compact).expect("parse JWE");
    let mgn = String::from_utf8(parts.apu.clone()).expect("apu is the mdoc_generated_nonce");
    assert!(!mgn.is_empty(), "the mdoc_generated_nonce must travel as the JWE apu");
    let z = verifier_enc.agree(&parts.ephemeral_public).unwrap();
    let plaintext = parts.open(&z, &AwsLc, &AwsLc).expect("verifier opens the JWE");
    let response: serde_json::Value = serde_json::from_slice(&plaintext).unwrap();

    let dr_b64 = response["vp_token"]["mdl"].as_str().expect("DCQL-keyed DeviceResponse");
    let dr = cbor::from_canonical_slice(&Base64UrlUnpadded::decode_vec(dr_b64).unwrap()).unwrap();
    let docs = match map_get(&dr, "documents") {
        Some(Value::Array(a)) => a,
        _ => panic!("documents"),
    };
    assert_eq!(map_get(&docs[0], "docType"), Some(&Value::Text(DOCTYPE.into())));

    // Rebuild the SessionTranscript from the verifier's own values + the apu-carried mgn.
    let transcript = oid4vp_session_transcript(&AwsLc, CLIENT_ID, RESPONSE_URI, &NONCE.to_string(), &mgn);
    let expected_device_auth =
        device_authentication_bytes(&transcript, DOCTYPE, &empty_device_namespaces_bytes()).unwrap();

    let device_signed = map_get(&docs[0], "deviceSigned").unwrap();
    let device_auth = map_get(device_signed, "deviceAuth").unwrap();
    let (protected, dsig) = match map_get(device_auth, "deviceSignature").unwrap() {
        Value::Array(a) if a.len() == 4 => {
            let p = match &a[0] {
                Value::Bytes(b) => b.clone(),
                _ => panic!("protected"),
            };
            assert_eq!(a[2], Value::Null, "detached payload");
            let s = match &a[3] {
                Value::Bytes(b) => b.clone(),
                _ => panic!("sig"),
            };
            (p, s)
        }
        _ => panic!("deviceSignature COSE_Sign1"),
    };
    let tbs = cose::sig_structure(&protected, &[], &expected_device_auth);
    AwsLc
        .verify(Alg::Es256, device.public_key_raw(), &tbs, &dsig)
        .expect("decrypted DeviceResponse verifies against the device key + apu-derived transcript");
}
