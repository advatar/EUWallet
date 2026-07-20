//! Revocation: the wallet refuses to present a revoked/suspended credential, decided in-core
//! against a verified Token Status List (real crypto + real DEFLATE via the status crate).
use base64ct::{Base64UrlUnpadded, Encoding};
use crypto_backend::SoftwareSigner;
use crypto_traits::{Alg, KeyRef, Signer};
use serde_json::json;
use wallet_core::{Core, Effect, Event, HeldCredential, StatusLoadError, StatusReference};

const CA_DER: &[u8] = include_bytes!("../../x509/tests/vectors/ca.der");
const RP_DER: &[u8] = include_bytes!("../../x509/tests/vectors/rp.der");
const RP_PKCS8: &[u8] = include_bytes!("../../x509/tests/vectors/rp.pkcs8.der");
const NOW: i64 = 1_790_000_000;
const STATUS_URI: &str = "https://status.example/lists/pid-1";

fn b64(b: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(b)
}

fn signed_trust_list(op: &SoftwareSigner) -> Vec<u8> {
    let header = b64(br#"{"alg":"ES256"}"#);
    let payload = b64(json!({
        "seq":1,"valid_from":0,"valid_until":4_000_000_000i64,
        "anchors":[
            {"cert":b64(CA_DER),"service":"rp-access-ca","status":"granted"},
            {"cert":b64(CA_DER),"service":"status","status":"granted"}
        ]
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
fn signed_status(provider: &SoftwareSigner, uri: &str) -> Vec<u8> {
    let compressed = miniz_oxide::deflate::compress_to_vec_zlib(&[0x04u8], 6);
    let header = b64(br#"{"alg":"ES256","typ":"statuslist+jwt"}"#);
    let payload = b64(json!({
        "sub": uri,
        "iat": NOW,
        "exp": NOW + 3600,
        "ttl": 300,
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
        "response_uri":"https://rp.example/response","response_mode":"direct_post",
        "purpose":"age","claims":["age_over_18"]
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

fn status_ref(index: u64) -> StatusReference {
    StatusReference {
        uri: STATUS_URI.into(),
        index,
    }
}

fn core_at_consent_with_extra(
    status: Option<StatusReference>,
    load_status: bool,
    extra: Option<HeldCredential>,
) -> (Core, SoftwareSigner) {
    let issuer = SoftwareSigner::generate_p256().unwrap();
    let rp = SoftwareSigner::from_pkcs8_der(RP_PKCS8).unwrap();
    let trust_op = SoftwareSigner::generate_p256().unwrap();

    let mut core = Core::new("wallet.example", "device-key");
    core.handle_event(Event::SetClock { epoch: NOW });
    core.load_trust_list(&signed_trust_list(&trust_op), trust_op.public_key_raw())
        .unwrap();
    if load_status {
        core.load_status_list(
            STATUS_URI,
            &signed_status(&rp, STATUS_URI),
            &[RP_DER.to_vec()],
        )
        .unwrap();
    }
    if let Some(credential) = extra {
        core.load_unverified_credential_for_testing(credential);
    }
    core.load_unverified_credential_for_testing(HeldCredential {
        issuer_jwt: issued(&issuer),
        disclosures_by_claim: [("age_over_18".into(), "disclosure".into())]
            .into_iter()
            .collect(),
        status,
    });

    core.handle_event(Event::AuthorizationRequestReceived {
        request: sign_request(&rp),
    });
    core.handle_event(Event::RpCertChainResolved {
        rp_cert_chain: vec![RP_DER.to_vec()],
        registered_redirect_uris: vec!["https://rp.example/response".into()],
    });
    (core, rp)
}

fn core_at_consent(status: Option<StatusReference>, load_status: bool) -> (Core, SoftwareSigner) {
    core_at_consent_with_extra(status, load_status, None)
}

fn drive_to_consent(status: Option<StatusReference>, load_status: bool) -> Vec<Effect> {
    let (mut core, _) = core_at_consent(status, load_status);
    core.handle_event(Event::UserConsented)
}

#[test]
fn revoked_credential_is_not_presented() {
    // Index 1 is revoked in the bound list → consent produces an error, NOT a Sign effect.
    let fx = drive_to_consent(Some(status_ref(1)), true);
    assert!(fx.iter().any(|e| matches!(e, Effect::Render { screen: presenter::ScreenDescription::Error { code, .. } } if code == "credential_revoked")));
    assert!(
        !fx.iter().any(|e| matches!(e, Effect::Sign { .. })),
        "a revoked credential must not be signed/presented"
    );
}

#[test]
fn valid_credential_is_presented() {
    // Index 0 is valid → consent proceeds to signing.
    let fx = drive_to_consent(Some(status_ref(0)), true);
    assert!(
        fx.iter().any(|e| matches!(e, Effect::Sign { .. })),
        "a valid credential should proceed"
    );
}

#[test]
fn missing_status_list_fails_closed_for_remote() {
    // Credential has a status index but no list is loaded → fail closed (remote is online).
    let fx = drive_to_consent(Some(status_ref(1)), false);
    assert!(
        !fx.iter().any(|e| matches!(e, Effect::Sign { .. })),
        "unresolved status must fail closed"
    );
    assert_eq!(
        fx,
        vec![Effect::FetchStatusList {
            uri: STATUS_URI.into()
        }]
    );
}

#[test]
fn credential_without_status_reference_is_unaffected() {
    // No status reference → the check is skipped and presentation proceeds.
    let fx = drive_to_consent(None, false);
    assert!(fx.iter().any(|e| matches!(e, Effect::Sign { .. })));
}

#[test]
fn a_trusted_download_resumes_consent_without_a_plaintext_fallback() {
    let (mut core, status_provider) = core_at_consent(Some(status_ref(0)), false);
    assert_eq!(
        core.handle_event(Event::UserConsented),
        vec![Effect::FetchStatusList {
            uri: STATUS_URI.into()
        }]
    );

    let fx = core.handle_event(Event::StatusListReceived {
        uri: STATUS_URI.into(),
        http_status: 200,
        token: signed_status(&status_provider, STATUS_URI),
        provider_cert_chain: vec![RP_DER.to_vec()],
    });
    assert!(fx
        .iter()
        .any(|effect| matches!(effect, Effect::Sign { .. })));
}

#[test]
fn status_provider_must_chain_to_the_status_service_and_match_the_exact_uri() {
    let status_provider = SoftwareSigner::from_pkcs8_der(RP_PKCS8).unwrap();
    let trust_op = SoftwareSigner::generate_p256().unwrap();
    let mut core = Core::new("wallet.example", "device-key");
    core.handle_event(Event::SetClock { epoch: NOW });
    core.load_trust_list(&signed_trust_list(&trust_op), trust_op.public_key_raw())
        .unwrap();

    assert_eq!(
        core.load_status_list(
            STATUS_URI,
            &signed_status(&status_provider, "https://status.example/lists/other"),
            &[RP_DER.to_vec()],
        ),
        Err(StatusLoadError::InvalidToken(
            status::StatusError::SubjectMismatch
        ))
    );
    assert_eq!(
        core.load_status_list(
            STATUS_URI,
            &signed_status(&status_provider, STATUS_URI),
            &[CA_DER.to_vec()],
        ),
        Err(StatusLoadError::UntrustedProvider)
    );
}

#[test]
fn a_stale_cached_list_is_refetched_before_signing() {
    let (mut core, _) = core_at_consent(Some(status_ref(0)), true);
    core.handle_event(Event::SetClock { epoch: NOW + 300 });
    assert_eq!(
        core.handle_event(Event::UserConsented),
        vec![Effect::FetchStatusList {
            uri: STATUS_URI.into()
        }]
    );
}

#[test]
fn status_expiring_while_a_device_signature_is_pending_aborts_before_delivery() {
    let (mut core, _) = core_at_consent(Some(status_ref(0)), true);
    let effects = core.handle_event(Event::UserConsented);
    assert!(effects
        .iter()
        .any(|effect| matches!(effect, Effect::Sign { .. })));

    core.handle_event(Event::SetClock { epoch: NOW + 300 });
    let effects = core.handle_event(Event::DeviceSignatureProduced {
        signature: vec![0x55; 64],
    });
    assert!(effects.iter().any(|effect| matches!(
        effect,
        Effect::Render {
            screen: presenter::ScreenDescription::Error { code, .. }
        } if code == "credential_status_unavailable"
    )));
    assert!(!effects
        .iter()
        .any(|effect| matches!(effect, Effect::Sign { .. } | Effect::Http { .. })));
}

#[test]
fn cache_cardinality_is_bounded() {
    let status_provider = SoftwareSigner::from_pkcs8_der(RP_PKCS8).unwrap();
    let trust_op = SoftwareSigner::generate_p256().unwrap();
    let mut core = Core::new("wallet.example", "device-key");
    core.handle_event(Event::SetClock { epoch: NOW });
    core.load_trust_list(&signed_trust_list(&trust_op), trust_op.public_key_raw())
        .unwrap();

    for index in 0..8 {
        let uri = format!("https://status.example/lists/{index}");
        core.load_status_list(
            &uri,
            &signed_status(&status_provider, &uri),
            &[RP_DER.to_vec()],
        )
        .unwrap();
    }
    let ninth = "https://status.example/lists/8";
    assert_eq!(
        core.load_status_list(
            ninth,
            &signed_status(&status_provider, ninth),
            &[RP_DER.to_vec()],
        ),
        Err(StatusLoadError::CacheFull)
    );
}

#[test]
fn a_revoked_unselected_holding_does_not_poison_the_selected_credential() {
    let second_issuer = SoftwareSigner::generate_p256().unwrap();
    let (mut core, _) = core_at_consent_with_extra(
        Some(status_ref(1)),
        true,
        Some(HeldCredential {
            issuer_jwt: issued(&second_issuer),
            disclosures_by_claim: [("age_over_18".into(), "disclosure".into())]
                .into_iter()
                .collect(),
            status: Some(status_ref(0)),
        }),
    );

    let fx = core.handle_event(Event::UserConsented);
    assert!(fx
        .iter()
        .any(|effect| matches!(effect, Effect::Sign { .. })));
    assert!(!fx.iter().any(|effect| matches!(
        effect,
        Effect::Render {
            screen: presenter::ScreenDescription::Error { .. }
        }
    )));
}
