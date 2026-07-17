//! Revocation: the wallet refuses to present a revoked/suspended credential, decided in-core
//! against a verified Token Status List (real crypto + real DEFLATE via the status crate).
use base64ct::{Base64UrlUnpadded, Encoding};
use crypto_backend::SoftwareSigner;
use crypto_traits::{Alg, KeyRef, Signer};
use serde_json::json;
use wallet_core::{Core, Effect, Event, HeldCredential};

const CA_DER: &[u8] = include_bytes!("../../x509/tests/vectors/ca.der");
const RP_DER: &[u8] = include_bytes!("../../x509/tests/vectors/rp.der");
const RP_PKCS8: &[u8] = include_bytes!("../../x509/tests/vectors/rp.pkcs8.der");
const NOW: i64 = 1_790_000_000;

fn b64(b: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(b)
}

fn signed_trust_list(op: &SoftwareSigner) -> Vec<u8> {
    let header = b64(br#"{"alg":"ES256"}"#);
    let payload = b64(json!({
        "seq":1,"valid_from":0,"valid_until":4_000_000_000i64,
        "anchors":[{"cert":b64(CA_DER),"service":"rp-access-ca","status":"granted"}]
    })
    .to_string()
    .as_bytes());
    let si = format!("{header}.{payload}");
    let sig = op
        .sign(&KeyRef("op".into()), Alg::Es256, si.as_bytes())
        .unwrap();
    format!("{si}.{}", b64(&sig)).into_bytes()
}

/// A status token where index 0 = valid, index 1 = revoked (bits=2, byte = 0 | 1<<2 = 0x04).
fn signed_status(provider: &SoftwareSigner) -> Vec<u8> {
    let compressed = miniz_oxide::deflate::compress_to_vec(&[0x04u8], 6);
    let header = b64(br#"{"alg":"ES256","typ":"statuslist+jwt"}"#);
    let payload = b64(json!({
        "exp": 4_000_000_000i64,
        "status_list": { "bits": 2, "lst": b64(&compressed) }
    })
    .to_string()
    .as_bytes());
    let si = format!("{header}.{payload}");
    let sig = provider
        .sign(&KeyRef("s".into()), Alg::Es256, si.as_bytes())
        .unwrap();
    format!("{si}.{}", b64(&sig)).into_bytes()
}

fn sign_request(rp: &SoftwareSigner) -> Vec<u8> {
    let header = b64(br#"{"alg":"ES256","typ":"oauth-authz-req+jwt"}"#);
    let payload = b64(json!({
        "client_id":"rp.example","nonce":7u64,"aud":"wallet.example",
        "response_uri":"https://rp.example/response","purpose":"age","claims":["age_over_18"]
    })
    .to_string()
    .as_bytes());
    let si = format!("{header}.{payload}");
    let sig = rp
        .sign(&KeyRef("r".into()), Alg::Es256, si.as_bytes())
        .unwrap();
    format!("{si}.{}", b64(&sig)).into_bytes()
}

fn issued(issuer: &SoftwareSigner) -> String {
    let header = b64(br#"{"alg":"ES256","typ":"dc+sd-jwt"}"#);
    let payload = b64(
        json!({"iss":"i","vct":"urn:eudi:pid:1","_sd_alg":"sha-256","_sd":[]})
            .to_string()
            .as_bytes(),
    );
    let si = format!("{header}.{payload}");
    let sig = issuer
        .sign(&KeyRef("i".into()), Alg::Es256, si.as_bytes())
        .unwrap();
    format!("{si}.{}", b64(&sig))
}

fn drive_to_consent(status_index: Option<u64>, load_status: bool) -> Vec<Effect> {
    let issuer = SoftwareSigner::generate_p256().unwrap();
    let rp = SoftwareSigner::from_pkcs8_der(RP_PKCS8).unwrap();
    let trust_op = SoftwareSigner::generate_p256().unwrap();
    let status_provider = SoftwareSigner::generate_p256().unwrap();

    let mut core = Core::new("wallet.example", "device-key");
    core.handle_event(Event::SetClock { epoch: NOW });
    core.load_trust_list(&signed_trust_list(&trust_op), trust_op.public_key_raw())
        .unwrap();
    if load_status {
        core.load_status_list(
            &signed_status(&status_provider),
            status_provider.public_key_raw(),
        )
        .unwrap();
    }
    core.load_credential(HeldCredential {
        issuer_jwt: issued(&issuer),
        disclosures_by_claim: Default::default(),
        status_index,
    });

    core.handle_event(Event::AuthorizationRequestReceived {
        request: sign_request(&rp),
    });
    core.handle_event(Event::RpCertChainResolved {
        rp_cert_chain: vec![RP_DER.to_vec()],
        registered_redirect_uris: vec![],
    });
    core.handle_event(Event::UserConsented)
}

#[test]
fn revoked_credential_is_not_presented() {
    // status_index 1 is revoked in the list → consent produces an error, NOT a Sign effect.
    let fx = drive_to_consent(Some(1), true);
    assert!(fx.iter().any(|e| matches!(e, Effect::Render { screen: presenter::ScreenDescription::Error { code, .. } } if code == "credential_revoked")));
    assert!(
        !fx.iter().any(|e| matches!(e, Effect::Sign { .. })),
        "a revoked credential must not be signed/presented"
    );
}

#[test]
fn valid_credential_is_presented() {
    // status_index 0 is valid → consent proceeds to signing.
    let fx = drive_to_consent(Some(0), true);
    assert!(
        fx.iter().any(|e| matches!(e, Effect::Sign { .. })),
        "a valid credential should proceed"
    );
}

#[test]
fn missing_status_list_fails_closed_for_remote() {
    // Credential has a status index but no list is loaded → fail closed (remote is online).
    let fx = drive_to_consent(Some(1), false);
    assert!(
        !fx.iter().any(|e| matches!(e, Effect::Sign { .. })),
        "unresolved status must fail closed"
    );
}

#[test]
fn credential_without_status_index_is_unaffected() {
    // No status reference → the check is skipped and presentation proceeds.
    let fx = drive_to_consent(None, false);
    assert!(fx.iter().any(|e| matches!(e, Effect::Sign { .. })));
}
