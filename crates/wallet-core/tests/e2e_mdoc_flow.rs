//! End-to-end **mdoc-over-OpenID4VP** presentation driven entirely through
//! `wallet-core::Core::handle_event`, with REAL crypto (aws-lc-rs). The wallet holds an ISO
//! 18013-5 mDL (`mso_mdoc`), a verifier asks for `age_over_18` via a DCQL `mso_mdoc` query, and
//! the core produces a `direct_post` response whose `vp_token` is a real ISO `DeviceResponse`.
//!
//! The test then acts as an INDEPENDENT verifier: using only what travelled on the wire (the
//! DeviceResponse and the companion `mdoc_generated_nonce`), it rebuilds the OpenID4VP
//! SessionTranscript and checks the device signature with real crypto — proving the wallet emits
//! a third-party-verifiable mdoc presentation, not merely a self-consistent blob.
use base64ct::{Base64UrlUnpadded, Encoding};
use cose::cbor::{self, Value};
use crypto_backend::{AwsLc, SoftwareSigner};
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

// Real openssl-generated RP chain: rp.der (leaf) issued by ca.der; rp.pkcs8.der is the leaf key.
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
    let sig = operator
        .sign(&KeyRef("op".into()), Alg::Es256, si.as_bytes())
        .unwrap();
    format!("{si}.{}", b64(&sig)).into_bytes()
}

/// A COSE_Key (EC2 / P-256) for an uncompressed SEC1 public key `0x04 || X(32) || Y(32)`.
fn cose_key(pubkey: &[u8]) -> Value {
    Value::Map(vec![
        (Value::Uint(1), Value::Uint(2)),
        (Value::Nint(0), Value::Uint(1)), // -1 => P-256
        (Value::Nint(1), Value::Bytes(pubkey[1..33].to_vec())), // -2 => x
        (Value::Nint(2), Value::Bytes(pubkey[33..65].to_vec())), // -3 => y
    ])
}

/// An RP-signed OpenID4VP request with a DCQL `mso_mdoc` query for `age_over_18` (namespaced path).
fn sign_mdoc_request(rp: &SoftwareSigner, nonce: u64) -> Vec<u8> {
    let header = b64(br#"{"alg":"ES256","typ":"oauth-authz-req+jwt"}"#);
    let payload = b64(serde_json::to_string(&json!({
        "client_id": CLIENT_ID,
        "nonce": nonce.to_string(),
        "aud": "wallet.example",
        "response_uri": RESPONSE_URI,
        "response_mode": "direct_post",
        "purpose": "Prove you are over 18",
        "dcql_query": {
            "credentials": [{
                "id": "mdl",
                "format": "mso_mdoc",
                "meta": { "doctype_value": DOCTYPE },
                "claims": [{
                    "path": [NS, "age_over_18"],
                    "intent_to_retain": true
                }]
            }]
        },
    }))
    .unwrap()
    .as_bytes());
    let si = format!("{header}.{payload}");
    let sig = rp
        .sign(&KeyRef("r".into()), Alg::Es256, si.as_bytes())
        .unwrap();
    format!("{si}.{}", b64(&sig)).into_bytes()
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

fn field(body: &str, key: &str) -> Option<String> {
    body.split('&')
        .find_map(|kv| kv.strip_prefix(&format!("{key}=")).map(percent_decode))
}

#[test]
fn full_mdoc_presentation_through_wallet_core_is_third_party_verifiable() {
    let issuer = SoftwareSigner::generate_p256().unwrap();
    let device = SoftwareSigner::generate_p256().unwrap();
    let rp = SoftwareSigner::from_pkcs8_der(RP_PKCS8).unwrap();
    let trust_operator = SoftwareSigner::generate_p256().unwrap();

    // ---- The wallet holds a real mDL binding the device key; it carries TWO elements. ----
    let mut name_spaces = BTreeMap::new();
    name_spaces.insert(
        NS.to_string(),
        vec![
            IssuerSignedItem {
                digest_id: 0,
                random: vec![0x11; 16],
                element_id: "family_name".into(),
                element_value: Value::Text("Andersson".into()),
            },
            IssuerSignedItem {
                digest_id: 1,
                random: vec![0x22; 16],
                element_id: "age_over_18".into(),
                element_value: Value::Bool(true),
            },
        ],
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
    .expect("issuer signs the mDL");

    let mut core = Core::new("wallet.example", "device-key");
    core.load_unverified_mdoc_for_testing(MdocHolding {
        doctype: DOCTYPE.into(),
        issuer_signed: issuer_signed.clone(),
    });
    core.handle_event(Event::SetClock {
        epoch: 1_790_000_000,
    });
    core.load_trust_list(
        &signed_trust_list(&trust_operator),
        trust_operator.public_key_raw(),
    )
    .expect("trust list loads");

    // ---- 1) DCQL mso_mdoc request → ResolveRpTrust. ----
    let request = sign_mdoc_request(&rp, NONCE);
    let fx = core.handle_event(Event::AuthorizationRequestReceived { request });
    assert!(
        matches!(fx.as_slice(), [Effect::ResolveRpTrust { .. }]),
        "got {fx:?}"
    );

    // ---- 2) Shell supplies the RP cert chain; core validates against the trusted list → consent. ----
    let fx = core.handle_event(Event::RpCertChainResolved {
        rp_cert_chain: vec![RP_DER.to_vec()],
        registered_redirect_uris: vec![RESPONSE_URI.into()],
    });
    let screen = fx.iter().find_map(|e| match e {
        Effect::Render { screen } => Some(screen.clone()),
        _ => None,
    });
    match screen {
        Some(presenter::ScreenDescription::Consent(c)) => {
            // Data minimisation: only the requested (namespaced) mdoc element is offered.
            assert_eq!(
                c.requested_claims,
                vec![format!("{NS}.age_over_18 [retained]")]
            );
        }
        other => panic!("expected a consent screen, got {other:?}"),
    }

    // ---- 3) consent → Sign (device-auth signing input). ----
    let fx = core.handle_event(Event::UserConsented);
    let signing_input = fx
        .iter()
        .find_map(|e| match e {
            Effect::Sign { payload, .. } => Some(payload.clone()),
            _ => None,
        })
        .expect("expected a Sign effect");

    // ---- 4) device signs → Http(vp_token). ----
    let device_sig = device
        .sign(&KeyRef("device-key".into()), Alg::Es256, &signing_input)
        .unwrap();
    let fx = core.handle_event(Event::DeviceSignatureProduced {
        signature: device_sig,
    });
    let body = fx
        .iter()
        .find_map(|e| match e {
            Effect::Http { body, .. } => Some(String::from_utf8(body.clone()).unwrap()),
            _ => None,
        })
        .expect("expected an Http effect carrying the vp_token");

    // ================= INDEPENDENT VERIFIER (only wire data) =================
    // The response is a DCQL-keyed vp_token object plus the companion mdoc_generated_nonce.
    let vp_field = field(&body, "vp_token").expect("vp_token field");
    let mgn = field(&body, "mdoc_generated_nonce").expect("mdoc_generated_nonce field");
    let obj: serde_json::Value = serde_json::from_str(&vp_field).expect("vp_token JSON object");
    let dr_b64 = obj["mdl"][0].as_str().expect("DCQL-keyed DeviceResponse");
    let dr_cbor = Base64UrlUnpadded::decode_vec(dr_b64).expect("base64url DeviceResponse");
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

    // Data minimisation on the WIRE: parse the emitted issuerSigned and confirm only age_over_18
    // survived — family_name never left the wallet.
    let issuer_signed_out = map_get(&docs[0], "issuerSigned").expect("issuerSigned");
    let parsed = mdoc::IssuerSigned::from_value(issuer_signed_out).expect("parse issuerSigned");
    let disclosed: Vec<String> = parsed
        .name_spaces
        .get(NS)
        .map(|items| items.iter().map(|it| it.element_id.clone()).collect())
        .unwrap_or_default();
    assert_eq!(
        disclosed,
        vec!["age_over_18".to_string()],
        "only the requested element is disclosed; family_name is withheld"
    );

    // Rebuild the SessionTranscript from the verifier's own values + the conveyed mdoc_generated_nonce.
    let transcript =
        oid4vp_session_transcript(&AwsLc, CLIENT_ID, RESPONSE_URI, &NONCE.to_string(), &mgn);
    let expected_device_auth =
        device_authentication_bytes(&transcript, DOCTYPE, &empty_device_namespaces_bytes())
            .unwrap();

    // deviceSigned.deviceAuth.deviceSignature = [protected, unprotected, payload(null), signature].
    let device_signed = map_get(&docs[0], "deviceSigned").unwrap();
    let device_auth = map_get(device_signed, "deviceAuth").unwrap();
    let device_signature = map_get(device_auth, "deviceSignature").unwrap();
    let (protected, sig) = match device_signature {
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

    // Reconstruct the exact Sig_structure and verify with real crypto against the device key.
    let tbs = cose::sig_structure(&protected, &[], &expected_device_auth);
    AwsLc
        .verify(Alg::Es256, device.public_key_raw(), &tbs, &sig)
        .expect("the DeviceResponse device signature verifies against the device key + transcript");

    // The issuer signature + item digests on the (minimised) credential also verify.
    let parsed = mdoc::IssuerSigned::from_value(issuer_signed_out).expect("parse issuerSigned");
    mdoc::verify_issuer_signed(&parsed, &AwsLc, &AwsLc, issuer.public_key_raw(), Alg::Es256)
        .expect("issuer-signed MSO + disclosed-item digests verify");

    // ---- 5) delivery → Done. ----
    let fx = core.handle_event(Event::PresentationDelivered);
    assert!(fx.iter().any(|e| matches!(e, Effect::Close)));
    assert_eq!(core.state(), &oid4vp::State::Done);
    assert!(
        core.transaction_log_json()
            .contains(&format!(r#"{NS}.age_over_18 [retained]"#)),
        "the completed audit record preserves the exact authorized retention declaration"
    );
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
