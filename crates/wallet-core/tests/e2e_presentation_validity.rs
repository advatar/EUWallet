//! Presentation-time validity and clock monotonicity. Credentials in these tests cross the real
//! authenticated ingestion boundary and retain their issuer certificate provenance; no unverified
//! fixture loader is used.

use std::collections::BTreeMap;

use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use cose::cbor::Value;
use crypto_backend::{AwsLc, SoftwareSigner};
use crypto_traits::{Alg, Digest, KeyRef, Signer};
use mdoc::{build_and_sign, IssuerSignedItem, ValidityInfo};
use presenter::ScreenDescription;
use serde_json::json;
use wallet_core::{Core, Effect, Event};

const CA_DER: &[u8] = include_bytes!("../../x509/tests/vectors/ca.der");
const RP_DER: &[u8] = include_bytes!("../../x509/tests/vectors/rp.der");
const ISSUER_DER_B64: &str = include_str!("../../x509/tests/vectors/issuer.der.b64");
const ISSUER_PKCS8: &[u8] = include_bytes!("../../x509/tests/vectors/rp.pkcs8.der");
const NOW: i64 = 1_790_000_000; // 2026-09-21T14:13:20Z
const EXPIRY: i64 = NOW + 10;
const RESPONSE_URI: &str = "https://rp.example/response";
const ISSUER_ID: &str = "https://issuer.example";
const MDOC_TYPE: &str = "org.iso.18013.5.1.mDL";
const MDOC_NAMESPACE: &str = "org.iso.18013.5.1";

fn b64(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

fn issuer_der() -> Vec<u8> {
    Base64::decode_vec(ISSUER_DER_B64.trim()).expect("issuer certificate vector")
}

fn signed_trust_list(operator: &SoftwareSigner) -> Vec<u8> {
    let header = b64(br#"{"alg":"ES256"}"#);
    let payload = b64(json!({
        "seq": 1,
        "valid_from": 0,
        "valid_until": 4_000_000_000i64,
        "anchors": [
            { "cert": b64(CA_DER), "service": "pid", "status": "granted" },
            { "cert": b64(CA_DER), "service": "attestation", "status": "granted" },
            { "cert": b64(CA_DER), "service": "rp-access-ca", "status": "granted" }
        ]
    })
    .to_string()
    .as_bytes());
    let signing_input = format!("{header}.{payload}");
    let signature = operator
        .sign(
            &KeyRef("operator".into()),
            Alg::Es256,
            signing_input.as_bytes(),
        )
        .unwrap();
    format!("{signing_input}.{}", b64(&signature)).into_bytes()
}

fn device_jwk(device_public_key: &[u8]) -> serde_json::Value {
    json!({
        "kty": "EC",
        "crv": "P-256",
        "x": b64(&device_public_key[1..33]),
        "y": b64(&device_public_key[33..65]),
    })
}

fn issued_sd_jwt(issuer: &SoftwareSigner, device_public_key: &[u8], expires_at: i64) -> Vec<u8> {
    let disclosures: Vec<String> = [
        ("family_name", json!("Andersson")),
        ("given_name", json!("Astrid")),
        ("birthdate", json!("1988-04-12")),
        ("picture", json!("data:image/jpeg;base64,/9j/2Q==")),
        ("age_over_18", json!(true)),
    ]
    .into_iter()
    .enumerate()
    .map(|(index, (name, value))| {
        b64(json!([format!("salt-{index}"), name, value])
            .to_string()
            .as_bytes())
    })
    .collect();
    let digests: Vec<String> = disclosures
        .iter()
        .map(|disclosure| b64(&AwsLc.sha256(disclosure.as_bytes())))
        .collect();
    let header = b64(br#"{"alg":"ES256","typ":"dc+sd-jwt"}"#);
    let payload = b64(json!({
        "iss": ISSUER_ID,
        "iat": NOW,
        "nbf": NOW,
        "exp": expires_at,
        "vct": "urn:eudi:pid:1",
        "_sd_alg": "sha-256",
        "_sd": digests,
        "cnf": { "jwk": device_jwk(device_public_key) }
    })
    .to_string()
    .as_bytes());
    let signing_input = format!("{header}.{payload}");
    let signature = issuer
        .sign(
            &KeyRef("issuer".into()),
            Alg::Es256,
            signing_input.as_bytes(),
        )
        .unwrap();
    format!(
        "{signing_input}.{}~{}~",
        b64(&signature),
        disclosures.join("~")
    )
    .into_bytes()
}

fn cose_key(public_key: &[u8]) -> Value {
    Value::Map(vec![
        (Value::Uint(1), Value::Uint(2)),
        (Value::Nint(0), Value::Uint(1)),
        (Value::Nint(1), Value::Bytes(public_key[1..33].to_vec())),
        (Value::Nint(2), Value::Bytes(public_key[33..65].to_vec())),
    ])
}

fn issued_mdoc(issuer: &SoftwareSigner, device_public_key: &[u8]) -> Vec<u8> {
    let mut name_spaces = BTreeMap::new();
    name_spaces.insert(
        MDOC_NAMESPACE.to_string(),
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
                element_id: "given_name".into(),
                element_value: Value::Text("Astrid".into()),
            },
            IssuerSignedItem {
                digest_id: 2,
                random: vec![0x33; 16],
                element_id: "age_over_18".into(),
                element_value: Value::Bool(true),
            },
        ],
    );
    let mut credential = build_and_sign(
        name_spaces,
        MDOC_TYPE,
        cose_key(device_public_key),
        ValidityInfo {
            signed: "2026-09-21T14:13:20Z".into(),
            valid_from: "2026-09-21T14:13:20Z".into(),
            valid_until: "2026-09-21T14:13:30Z".into(),
        },
        &AwsLc,
        issuer,
        &KeyRef("issuer".into()),
        Alg::Es256,
    )
    .unwrap();
    credential.issuer_auth.unprotected.x5chain =
        Some(Box::new(cose::X5Chain::Single(issuer_der())));
    b64(&credential.to_value().to_canonical()).into_bytes()
}

fn signed_request(rp: &SoftwareSigner, mdoc: bool) -> Vec<u8> {
    let request = if mdoc {
        json!({
            "client_id": "rp.example",
            "nonce": 77u64,
            "aud": "wallet.example",
            "response_uri": RESPONSE_URI,
            "response_mode": "direct_post",
            "purpose": "Prove current driving entitlement",
            "dcql_query": { "credentials": [{
                "id": "mdl",
                "format": "mso_mdoc",
                "meta": { "doctype_value": MDOC_TYPE },
                "claims": [{ "path": [MDOC_NAMESPACE, "age_over_18"] }]
            }] }
        })
    } else {
        json!({
            "client_id": "rp.example",
            "nonce": 77u64,
            "aud": "wallet.example",
            "response_uri": RESPONSE_URI,
            "response_mode": "direct_post",
            "purpose": "Prove age",
            "claims": ["age_over_18"]
        })
    };
    let header = b64(br#"{"alg":"ES256","typ":"oauth-authz-req+jwt"}"#);
    let payload = b64(request.to_string().as_bytes());
    let signing_input = format!("{header}.{payload}");
    let signature = rp
        .sign(&KeyRef("rp".into()), Alg::Es256, signing_input.as_bytes())
        .unwrap();
    format!("{signing_input}.{}", b64(&signature)).into_bytes()
}

fn authenticated_core(mdoc: bool) -> (Core, SoftwareSigner, SoftwareSigner) {
    let issuer_and_rp = SoftwareSigner::from_pkcs8_der(ISSUER_PKCS8).unwrap();
    let device = SoftwareSigner::generate_p256().unwrap();
    let operator = SoftwareSigner::generate_p256().unwrap();
    let mut core = Core::new("wallet.example", "device-key");
    assert!(core.handle_event(Event::SetClock { epoch: NOW }).is_empty());
    core.load_device_key(device.public_key_raw().to_vec());
    core.load_trust_list(&signed_trust_list(&operator), operator.public_key_raw())
        .unwrap();
    let credential = if mdoc {
        issued_mdoc(&issuer_and_rp, device.public_key_raw())
    } else {
        issued_sd_jwt(&issuer_and_rp, device.public_key_raw(), EXPIRY)
    };
    core.ingest_credential(
        if mdoc { "mso_mdoc" } else { "dc+sd-jwt" },
        &credential,
        &[issuer_der()],
        ISSUER_ID,
    )
    .unwrap();
    (core, device, issuer_and_rp)
}

fn drive_to_consent(core: &mut Core, rp: &SoftwareSigner, mdoc: bool) {
    let effects = core.handle_event(Event::AuthorizationRequestReceived {
        request: signed_request(rp, mdoc),
    });
    assert!(matches!(
        effects.as_slice(),
        [Effect::ResolveRpTrust { .. }]
    ));
    let effects = core.handle_event(Event::RpCertChainResolved {
        rp_cert_chain: vec![RP_DER.to_vec()],
        registered_redirect_uris: vec![RESPONSE_URI.into()],
    });
    assert!(effects.iter().any(|effect| matches!(
        effect,
        Effect::Render {
            screen: ScreenDescription::Consent(_)
        }
    )));
}

fn assert_terminal_error(effects: &[Effect], expected_code: &str) {
    assert!(effects.iter().any(|effect| matches!(
        effect,
        Effect::Render {
            screen: ScreenDescription::Error { code, .. }
        } if code == expected_code
    )));
    assert!(effects.contains(&Effect::Close));
    assert!(!effects
        .iter()
        .any(|effect| matches!(effect, Effect::Sign { .. } | Effect::Http { .. })));
}

#[test]
fn sd_jwt_expiring_at_consent_is_rejected_before_signing() {
    let (mut core, _device, rp) = authenticated_core(false);
    drive_to_consent(&mut core, &rp, false);

    assert!(core
        .handle_event(Event::SetClock { epoch: EXPIRY })
        .is_empty());
    let effects = core.handle_event(Event::UserConsented);
    assert_terminal_error(&effects, "credential_expired");
}

#[test]
fn mdoc_expiring_at_consent_is_rejected_before_signing() {
    let (mut core, _device, rp) = authenticated_core(true);
    drive_to_consent(&mut core, &rp, true);

    assert!(core
        .handle_event(Event::SetClock { epoch: EXPIRY })
        .is_empty());
    let effects = core.handle_event(Event::UserConsented);
    assert_terminal_error(&effects, "credential_expired");
}

#[test]
fn sd_jwt_expiring_while_a_device_signature_is_pending_cannot_be_delivered() {
    let (mut core, device, rp) = authenticated_core(false);
    drive_to_consent(&mut core, &rp, false);
    let signing_effects = core.handle_event(Event::UserConsented);
    let payload = signing_effects
        .iter()
        .find_map(|effect| match effect {
            Effect::Sign { payload, .. } => Some(payload.clone()),
            _ => None,
        })
        .expect("credential is current when signing begins");

    assert!(core
        .handle_event(Event::SetClock { epoch: EXPIRY })
        .is_empty());
    let signature = device
        .sign(&KeyRef("device-key".into()), Alg::Es256, &payload)
        .unwrap();
    let effects = core.handle_event(Event::DeviceSignatureProduced { signature });
    assert_terminal_error(&effects, "credential_expired");
}

#[test]
fn clock_rollback_aborts_a_presentation_with_a_signature_pending() {
    let (mut core, device, rp) = authenticated_core(false);
    drive_to_consent(&mut core, &rp, false);

    // Equal and forward updates are deterministic no-ops apart from advancing the high-water mark.
    assert!(core.handle_event(Event::SetClock { epoch: NOW }).is_empty());
    let signing_effects = core.handle_event(Event::UserConsented);
    let payload = signing_effects
        .iter()
        .find_map(|effect| match effect {
            Effect::Sign { payload, .. } => Some(payload.clone()),
            _ => None,
        })
        .expect("current credential proceeds to device signing");
    assert!(core
        .handle_event(Event::SetClock { epoch: NOW + 1 })
        .is_empty());

    let rollback_effects = core.handle_event(Event::SetClock { epoch: NOW });
    assert_terminal_error(&rollback_effects, "clock_rollback_rejected");

    // Even a valid late device signature from the superseded operation cannot produce delivery.
    let signature = device
        .sign(&KeyRef("device-key".into()), Alg::Es256, &payload)
        .unwrap();
    let late_effects = core.handle_event(Event::DeviceSignatureProduced { signature });
    assert!(!late_effects
        .iter()
        .any(|effect| matches!(effect, Effect::Sign { .. } | Effect::Http { .. })));
}
