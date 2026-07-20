//! Fail-closed OpenID4VP delivery policy through the real wallet-core facade.
//! Rejected modes/endpoints/encryption metadata must surface a stable error and never emit HTTP.

use base64ct::{Base64UrlUnpadded, Encoding};
use crypto_backend::SoftwareSigner;
use crypto_traits::{Alg, KeyRef, Signer};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use wallet_core::{Core, Effect, Event, HeldCredential};

const CA_DER: &[u8] = include_bytes!("../../x509/tests/vectors/ca.der");
const RP_DER: &[u8] = include_bytes!("../../x509/tests/vectors/rp.der");
const RP_PKCS8: &[u8] = include_bytes!("../../x509/tests/vectors/rp.pkcs8.der");
const RESPONSE_URI: &str = "https://rp.example/response";

fn b64(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

fn signed_trust_list(operator: &SoftwareSigner) -> Vec<u8> {
    let header = b64(br#"{"alg":"ES256"}"#);
    let payload = b64(json!({
        "seq": 1,
        "valid_from": 0,
        "valid_until": 4_000_000_000i64,
        "anchors": [{ "cert": b64(CA_DER), "service": "rp-access-ca", "status": "granted" }]
    })
    .to_string()
    .as_bytes());
    let signing_input = format!("{header}.{payload}");
    let sig = operator
        .sign(
            &KeyRef("operator".into()),
            Alg::Es256,
            signing_input.as_bytes(),
        )
        .unwrap();
    format!("{signing_input}.{}", b64(&sig)).into_bytes()
}

fn core() -> Core {
    let operator = SoftwareSigner::generate_p256().unwrap();
    let mut core = Core::new("wallet.example", "device-key");
    core.handle_event(Event::SetClock {
        epoch: 1_790_000_000,
    });
    core.load_trust_list(&signed_trust_list(&operator), operator.public_key_raw())
        .unwrap();

    let disclosure = b64(br#"["salt","age_over_18",true]"#);
    core.load_credential(HeldCredential {
        issuer_jwt: "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIn0.c2ln".into(),
        disclosures_by_claim: BTreeMap::from([("age_over_18".into(), disclosure)]),
        status_index: None,
    });
    core
}

fn base_request() -> Value {
    json!({
        "client_id": "rp.example",
        "nonce": 424_242,
        "aud": "wallet.example",
        "response_uri": RESPONSE_URI,
        "response_mode": "direct_post",
        "purpose": "Prove you are over 18",
        "claims": ["age_over_18"]
    })
}

fn signed_request(payload: &Value) -> Vec<u8> {
    let rp = SoftwareSigner::from_pkcs8_der(RP_PKCS8).unwrap();
    let header = b64(br#"{"alg":"ES256","typ":"oauth-authz-req+jwt"}"#);
    let payload = b64(serde_json::to_string(payload).unwrap().as_bytes());
    let signing_input = format!("{header}.{payload}");
    let sig = rp
        .sign(&KeyRef("rp".into()), Alg::Es256, signing_input.as_bytes())
        .unwrap();
    format!("{signing_input}.{}", b64(&sig)).into_bytes()
}

fn resolve(core: &mut Core, payload: &Value, registered: &[&str]) -> Vec<Effect> {
    let first = core.handle_event(Event::AuthorizationRequestReceived {
        request: signed_request(payload),
    });
    assert!(matches!(first.as_slice(), [Effect::ResolveRpTrust { .. }]));
    core.handle_event(Event::RpCertChainResolved {
        rp_cert_chain: vec![RP_DER.to_vec()],
        registered_redirect_uris: registered.iter().map(|uri| (*uri).into()).collect(),
    })
}

fn assert_error_without_http(effects: &[Effect], expected_code: &str) {
    assert!(
        !effects
            .iter()
            .any(|effect| matches!(effect, Effect::Http { .. })),
        "a rejected presentation must never emit HTTP: {effects:?}"
    );
    assert!(
        effects.iter().any(|effect| matches!(
            effect,
            Effect::Render {
                screen: presenter::ScreenDescription::Error { code, .. }
            } if code == expected_code
        )),
        "expected stable error {expected_code:?}, got {effects:?}"
    );
    assert!(effects.iter().any(|effect| matches!(effect, Effect::Close)));
}

#[test]
fn arbitrary_response_modes_abort_without_network_delivery() {
    for mode in [
        "",
        "Direct_Post",
        "direct_post.jwt.extra",
        "query",
        "fragment",
    ] {
        let mut core = core();
        let mut request = base_request();
        request["response_mode"] = json!(mode);
        let effects = resolve(&mut core, &request, &[RESPONSE_URI]);
        assert_eq!(
            core.state(),
            &oid4vp::State::Aborted(oid4vp::AbortReason::ResponseModeUnsupported)
        );
        assert_error_without_http(&effects, "presentation_response_mode_unsupported");
    }

    let mut core = core();
    let mut request = base_request();
    request.as_object_mut().unwrap().remove("response_mode");
    let effects = resolve(&mut core, &request, &[RESPONSE_URI]);
    assert_eq!(
        core.state(),
        &oid4vp::State::Aborted(oid4vp::AbortReason::ResponseModeUnsupported)
    );
    assert_error_without_http(&effects, "presentation_response_mode_unsupported");
}

#[test]
fn response_uri_must_be_https_and_registered_for_the_rp() {
    for uri in ["", "http://rp.example/response", "https:///response"] {
        let mut core = core();
        let mut request = base_request();
        request["response_uri"] = json!(uri);
        let effects = resolve(&mut core, &request, &[uri]);
        assert_eq!(
            core.state(),
            &oid4vp::State::Aborted(oid4vp::AbortReason::ResponseUriInvalid)
        );
        assert_error_without_http(&effects, "presentation_response_uri_invalid");
    }

    let mut core = core();
    let effects = resolve(&mut core, &base_request(), &["https://rp.example/other"]);
    assert_eq!(
        core.state(),
        &oid4vp::State::Aborted(oid4vp::AbortReason::ResponseUriNotRegistered)
    );
    assert_error_without_http(&effects, "presentation_response_uri_not_registered");
}

#[test]
fn encrypted_mode_requires_strict_key_metadata_before_consent() {
    let cases = [
        None,
        Some(json!({ "jwks": { "keys": [] } })),
        Some(json!({
            "authorization_encrypted_response_alg": "RSA-OAEP",
            "authorization_encrypted_response_enc": "A256GCM",
            "jwks": { "keys": [] }
        })),
        Some(json!({
            "authorization_encrypted_response_alg": "ECDH-ES",
            "authorization_encrypted_response_enc": "A128GCM",
            "jwks": { "keys": [] }
        })),
        Some(json!({
            "authorization_encrypted_response_alg": "ECDH-ES",
            "authorization_encrypted_response_enc": "A256GCM",
            "jwks": { "keys": [{
                "kty": "EC", "crv": "P-256", "use": "sig", "alg": "ECDH-ES",
                "x": b64(&[0u8; 32]), "y": b64(&[0u8; 32])
            }] }
        })),
        Some(json!({
            "authorization_encrypted_response_alg": "ECDH-ES",
            "authorization_encrypted_response_enc": "A256GCM",
            "jwks": { "keys": [{
                "kty": "EC", "crv": "P-256", "use": "enc", "alg": "ECDH-ES+A256KW",
                "x": b64(&[0u8; 32]), "y": b64(&[0u8; 32])
            }] }
        })),
        Some(json!({
            "authorization_encrypted_response_alg": "ECDH-ES",
            "authorization_encrypted_response_enc": "A256GCM",
            "jwks": { "keys": [{
                "kty": "EC", "crv": "P-256", "use": "enc", "alg": "ECDH-ES",
                "x": b64(&[0u8; 31]), "y": b64(&[0u8; 32])
            }] }
        })),
    ];

    for metadata in cases {
        let mut core = core();
        let mut request = base_request();
        request["response_mode"] = json!("direct_post.jwt");
        if let Some(metadata) = metadata {
            request["client_metadata"] = metadata;
        }
        let effects = resolve(&mut core, &request, &[RESPONSE_URI]);
        assert_eq!(
            core.state(),
            &oid4vp::State::Aborted(oid4vp::AbortReason::ResponseEncryptionMetadataInvalid)
        );
        assert_error_without_http(
            &effects,
            "presentation_response_encryption_metadata_invalid",
        );
    }
}

#[test]
fn off_curve_encryption_key_aborts_at_ecdh_without_plaintext_fallback() {
    // Correctly shaped SEC1 coordinates survive metadata parsing, but (0,0) is not a P-256 point.
    let mut request = base_request();
    request["response_mode"] = json!("direct_post.jwt");
    request["client_metadata"] = json!({
        "authorization_encrypted_response_alg": "ECDH-ES",
        "authorization_encrypted_response_enc": "A256GCM",
        "jwks": { "keys": [{
            "kty": "EC", "crv": "P-256", "use": "enc", "alg": "ECDH-ES",
            "x": b64(&[0u8; 32]), "y": b64(&[0u8; 32])
        }] }
    });

    let mut core = core();
    let effects = resolve(&mut core, &request, &[RESPONSE_URI]);
    assert!(matches!(core.state(), oid4vp::State::RequestValidated(_)));
    assert!(!effects
        .iter()
        .any(|effect| matches!(effect, Effect::Http { .. })));

    let effects = core.handle_event(Event::UserConsented);
    assert!(effects
        .iter()
        .any(|effect| matches!(effect, Effect::Sign { .. })));
    let effects = core.handle_event(Event::DeviceSignatureProduced {
        signature: vec![0xAB; 64],
    });
    assert_eq!(
        core.state(),
        &oid4vp::State::Aborted(oid4vp::AbortReason::ResponseEncryptionFailed)
    );
    assert_error_without_http(&effects, "presentation_response_encryption_failed");
}

#[test]
fn registered_https_direct_post_emits_only_the_bound_endpoint() {
    let mut core = core();
    let effects = resolve(&mut core, &base_request(), &[RESPONSE_URI]);
    assert!(matches!(core.state(), oid4vp::State::RequestValidated(_)));
    assert!(!effects
        .iter()
        .any(|effect| matches!(effect, Effect::Http { .. })));

    core.handle_event(Event::UserConsented);
    let effects = core.handle_event(Event::DeviceSignatureProduced {
        signature: vec![0xAB; 64],
    });
    assert!(matches!(
        effects.as_slice(),
        [Effect::Http { url, body }]
            if url == RESPONSE_URI && body.starts_with(b"vp_token=")
    ));
}
