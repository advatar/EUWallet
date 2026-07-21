//! End-to-end **multi-credential presentation**: one OpenID4VP request whose DCQL query asks for
//! TWO credentials at once — a PID (SD-JWT VC) *and* an mDL (ISO 18013-5 mdoc). The wallet signs
//! each in its own device round and returns a SINGLE `vp_token` object keyed by the two DCQL ids.
//! The test verifies BOTH presentations with real aws-lc-rs crypto: the PID's KB-JWT and the mDL's
//! DeviceResponse device signature (over its SessionTranscript). This is the common real-verifier
//! ask ("prove your identity AND your driving entitlement") in a single round trip.
use base64ct::{Base64UrlUnpadded, Encoding};
use cose::cbor::{self, Value};
use crypto_backend::{AwsLc, SoftwareSigner};
use crypto_traits::{Alg, Digest, KeyRef, Signer, Verifier};
use mdoc::{
    build_and_sign, device_authentication_bytes, empty_device_namespaces_bytes,
    oid4vp_session_transcript, IssuerSignedItem, ValidityInfo,
};
use serde_json::json;
use std::collections::BTreeMap;
use wallet_core::{Core, Effect, Event, HeldCredential, MdocHolding};

const DOCTYPE: &str = "org.iso.18013.5.1.mDL";
const NS: &str = "org.iso.18013.5.1";
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
    let sig = operator
        .sign(&KeyRef("op".into()), Alg::Es256, si.as_bytes())
        .unwrap();
    format!("{si}.{}", b64(&sig)).into_bytes()
}

fn issue_pid(issuer: &SoftwareSigner) -> (String, BTreeMap<String, String>) {
    let mut by_claim = BTreeMap::new();
    let mut sd = Vec::new();
    for (i, (name, value)) in [
        ("family_name", json!("Andersson")),
        ("age_over_18", json!(true)),
    ]
    .iter()
    .enumerate()
    {
        let raw = b64(
            serde_json::to_string(&json!([format!("s{i}"), name, value]))
                .unwrap()
                .as_bytes(),
        );
        sd.push(json!(b64(&AwsLc.sha256(raw.as_bytes()))));
        by_claim.insert((*name).to_string(), raw);
    }
    let header = b64(br#"{"alg":"ES256","typ":"dc+sd-jwt"}"#);
    let payload = b64(serde_json::to_string(&json!({
        "iss": "https://issuer.example", "vct": "urn:eudi:pid:1", "_sd_alg": "sha-256", "_sd": sd
    }))
    .unwrap()
    .as_bytes());
    let si = format!("{header}.{payload}");
    let sig = issuer
        .sign(&KeyRef("i".into()), Alg::Es256, si.as_bytes())
        .unwrap();
    (format!("{si}.{}", b64(&sig)), by_claim)
}

fn cose_key(pubkey: &[u8]) -> Value {
    Value::Map(vec![
        (Value::Uint(1), Value::Uint(2)),
        (Value::Nint(0), Value::Uint(1)),
        (Value::Nint(1), Value::Bytes(pubkey[1..33].to_vec())),
        (Value::Nint(2), Value::Bytes(pubkey[33..65].to_vec())),
    ])
}

/// An RP-signed request whose DCQL asks for BOTH a PID (SD-JWT) and an mDL (mdoc) at once.
fn sign_multi_request(rp: &SoftwareSigner, nonce: u64) -> Vec<u8> {
    let header = b64(br#"{"alg":"ES256","typ":"oauth-authz-req+jwt"}"#);
    let payload = b64(serde_json::to_string(&json!({
        "client_id": "rp.example",
        "nonce": nonce,
        "aud": "wallet.example",
        "response_uri": RESPONSE_URI,
        "response_mode": "direct_post",
        "purpose": "Prove your identity and driving entitlement",
        "dcql_query": { "credentials": [
            {
                "id": "pid",
                "format": "dc+sd-jwt",
                "meta": { "vct_values": ["urn:eudi:pid:1"] },
                "claims": [{ "path": ["age_over_18"] }]
            },
            {
                "id": "mdl",
                "format": "mso_mdoc",
                "meta": { "doctype_value": DOCTYPE },
                "claims": [{ "path": [NS, "age_over_18"] }]
            }
        ]},
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
        Value::Map(p) => p
            .iter()
            .find(|(k, _)| *k == Value::Text(key.into()))
            .map(|(_, x)| x),
        _ => None,
    }
}

fn field(body: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    body.split('&')
        .find_map(|kv| kv.strip_prefix(&prefix).map(percent_decode))
}

/// Feed a device signature and return the next Sign payload, or `None` if the flow finished.
fn next_sign(fx: &[Effect]) -> Option<Vec<u8>> {
    fx.iter().find_map(|e| match e {
        Effect::Sign { payload, .. } => Some(payload.clone()),
        _ => None,
    })
}

#[test]
fn one_request_presents_a_pid_and_an_mdl_together() {
    let issuer = SoftwareSigner::generate_p256().unwrap();
    let device = SoftwareSigner::generate_p256().unwrap();
    let rp = SoftwareSigner::from_pkcs8_der(RP_PKCS8).unwrap();
    let trust_operator = SoftwareSigner::generate_p256().unwrap();

    // Hold a PID (SD-JWT) AND an mDL (mdoc), both bound to the same device key.
    let (issuer_jwt, by_claim) = issue_pid(&issuer);
    let mut name_spaces = BTreeMap::new();
    name_spaces.insert(
        NS.to_string(),
        vec![IssuerSignedItem {
            digest_id: 0,
            random: vec![0x44; 16],
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
    core.load_unverified_credential_for_testing(HeldCredential {
        issuer_jwt,
        disclosures_by_claim: by_claim,
        status: None,
    });
    core.load_unverified_mdoc_for_testing(MdocHolding {
        doctype: DOCTYPE.into(),
        issuer_signed,
    });
    core.handle_event(Event::SetClock {
        epoch: 1_790_000_000,
    });
    core.load_trust_list(
        &signed_trust_list(&trust_operator),
        trust_operator.public_key_raw(),
    )
    .expect("trust list loads");

    // Request → trust → consent.
    core.handle_event(Event::AuthorizationRequestReceived {
        request: sign_multi_request(&rp, NONCE),
    });
    core.handle_event(Event::RpCertChainResolved {
        rp_cert_chain: vec![RP_DER.to_vec()],
        registered_redirect_uris: vec![RESPONSE_URI.into()],
    });

    // Two credentials ⇒ two sequential device-signing rounds. Sign each; the last yields the Http.
    let fx = core.handle_event(Event::UserConsented);
    let p1 = next_sign(&fx).expect("first Sign (credential #1)");
    let fx = core.handle_event(Event::DeviceSignatureProduced {
        signature: device
            .sign(&KeyRef("device-key".into()), Alg::Es256, &p1)
            .unwrap(),
    });
    let p2 = next_sign(&fx).expect("second Sign (credential #2) — the machine signs one at a time");
    assert!(
        !fx.iter().any(|e| matches!(e, Effect::Http { .. })),
        "nothing is posted until BOTH credentials are signed"
    );
    let fx = core.handle_event(Event::DeviceSignatureProduced {
        signature: device
            .sign(&KeyRef("device-key".into()), Alg::Es256, &p2)
            .unwrap(),
    });
    let body = fx
        .iter()
        .find_map(|e| match e {
            Effect::Http { body, .. } => Some(String::from_utf8(body.clone()).unwrap()),
            _ => None,
        })
        .expect("the assembled multi-credential vp_token is posted");

    // ---- One vp_token object, two keys. ----
    let vp = field(&body, "vp_token").expect("vp_token field");
    let obj: serde_json::Value = serde_json::from_str(&vp).expect("vp_token JSON object");

    // 1) PID (SD-JWT): the KB-JWT verifies; only age_over_18 was disclosed.
    let pid_pres = obj["pid"].as_str().expect("pid presentation");
    let sd = sdjwt::SdJwtVc::parse(pid_pres).expect("SD-JWT parses");
    let kb = sdjwt::KeyBindingCheck {
        device_public_key: device.public_key_raw(),
        expected_aud: "rp.example",
        expected_nonce: NONCE,
        device_alg: Alg::Es256,
    };
    let claims = sd
        .verify_presentation(&AwsLc, &AwsLc, issuer.public_key_raw(), Alg::Es256, &kb)
        .expect("PID presentation verifies");
    assert_eq!(claims.get("age_over_18"), Some(&json!(true)));
    assert!(
        claims.get("family_name").is_none(),
        "PID minimised to age_over_18"
    );

    // 2) mDL (mdoc): the DeviceResponse device signature verifies over the SessionTranscript.
    let mgn = field(&body, "mdoc_generated_nonce").expect("mdoc_generated_nonce companion field");
    let dr_b64 = obj["mdl"].as_str().expect("mdl DeviceResponse");
    let dr = cbor::from_canonical_slice(&Base64UrlUnpadded::decode_vec(dr_b64).unwrap()).unwrap();
    let docs = match map_get(&dr, "documents") {
        Some(Value::Array(a)) => a,
        _ => panic!("documents"),
    };
    assert_eq!(
        map_get(&docs[0], "docType"),
        Some(&Value::Text(DOCTYPE.into()))
    );
    let transcript =
        oid4vp_session_transcript(&AwsLc, "rp.example", RESPONSE_URI, &NONCE.to_string(), &mgn);
    let expected =
        device_authentication_bytes(&transcript, DOCTYPE, &empty_device_namespaces_bytes())
            .unwrap();
    let device_signature = map_get(map_get(&docs[0], "deviceSigned").unwrap(), "deviceAuth")
        .and_then(|da| map_get(da, "deviceSignature"))
        .unwrap();
    let (protected, dsig) = match device_signature {
        Value::Array(a) if a.len() == 4 => {
            let p = match &a[0] {
                Value::Bytes(b) => b.clone(),
                _ => panic!("protected"),
            };
            let s = match &a[3] {
                Value::Bytes(b) => b.clone(),
                _ => panic!("sig"),
            };
            (p, s)
        }
        _ => panic!("deviceSignature"),
    };
    let tbs = cose::sig_structure(&protected, &[], &expected);
    AwsLc
        .verify(Alg::Es256, device.public_key_raw(), &tbs, &dsig)
        .expect("mDL DeviceResponse verifies against the device key + transcript");

    // Delivery → Done.
    let fx = core.handle_event(Event::PresentationDelivered);
    assert!(fx.iter().any(|e| matches!(e, Effect::Close)));
    assert_eq!(core.state(), &oid4vp::State::Done);
}

#[test]
fn an_incomplete_multi_query_aborts_atomically_before_consent_or_signing() {
    let issuer = SoftwareSigner::generate_p256().unwrap();
    let rp = SoftwareSigner::from_pkcs8_der(RP_PKCS8).unwrap();
    let trust_operator = SoftwareSigner::generate_p256().unwrap();
    let (issuer_jwt, by_claim) = issue_pid(&issuer);

    // The PID satisfies query #1, but the wallet has no mdoc for query #2. The request is one
    // atomic authorization decision: it must not fall back to presenting only the PID.
    let mut core = Core::new("wallet.example", "device-key");
    core.load_unverified_credential_for_testing(HeldCredential {
        issuer_jwt,
        disclosures_by_claim: by_claim,
        status: None,
    });
    core.handle_event(Event::SetClock {
        epoch: 1_790_000_000,
    });
    core.load_trust_list(
        &signed_trust_list(&trust_operator),
        trust_operator.public_key_raw(),
    )
    .unwrap();
    core.handle_event(Event::AuthorizationRequestReceived {
        request: sign_multi_request(&rp, NONCE),
    });
    let effects = core.handle_event(Event::RpCertChainResolved {
        rp_cert_chain: vec![RP_DER.to_vec()],
        registered_redirect_uris: vec![RESPONSE_URI.into()],
    });

    assert!(effects.iter().any(|effect| matches!(
        effect,
        Effect::Render {
            screen: presenter::ScreenDescription::Error { code, .. }
        } if code == "no_eligible_credential"
    )));
    assert!(effects.contains(&Effect::Close));
    assert!(!effects.iter().any(|effect| matches!(
        effect,
        Effect::Render {
            screen: presenter::ScreenDescription::Consent(_)
        } | Effect::Sign { .. }
            | Effect::Http { .. }
    )));
    let late_consent = core.handle_event(Event::UserConsented);
    assert!(!late_consent
        .iter()
        .any(|effect| matches!(effect, Effect::Sign { .. } | Effect::Http { .. })));
    assert_eq!(
        core.state(),
        &oid4vp::State::Aborted(oid4vp::AbortReason::NoCredential)
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
