//! End-to-end OpenID4VP presentation driven entirely through `wallet-core::Core::handle_event`,
//! with REAL crypto (aws-lc-rs) and REAL data minimisation. This is the integrated flow the iOS
//! shell will drive over the FFI.
use base64ct::{Base64UrlUnpadded, Encoding};
use crypto_backend::{AwsLc, SoftwareSigner};
use crypto_traits::{Alg, Digest, KeyRef, Signer};
use serde_json::json;
use std::collections::BTreeMap;
use wallet_core::{Core, Effect, Event, HeldCredential};

fn b64(b: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(b)
}

// Real openssl-generated RP chain: rp.der (leaf) issued by ca.der; rp.pkcs8.der is the leaf key.
const CA_DER: &[u8] = include_bytes!("../../x509/tests/vectors/ca.der");
const RP_DER: &[u8] = include_bytes!("../../x509/tests/vectors/rp.der");
const RP_PKCS8: &[u8] = include_bytes!("../../x509/tests/vectors/rp.pkcs8.der");

/// A signed trusted list granting the CA as an RP-access CA.
fn signed_trust_list(operator: &SoftwareSigner, allowed_claims: &[&str]) -> Vec<u8> {
    let header = b64(br#"{"alg":"ES256"}"#);
    let payload = b64(serde_json::json!({
        "seq": 1, "valid_from": 0, "valid_until": 4_000_000_000i64,
        "anchors": [{ "cert": b64(CA_DER), "service": "rp-access-ca", "status": "granted" }],
        "relying_parties": [{
            "client_id": "rp.example",
            "display_name": "Example Verifier",
            "trust_mark": "eudi-wallet",
            "retention": "not-stored",
            "allowed_claims": allowed_claims,
            "redirect_uris": ["https://rp.example/response"]
        }]
    })
    .to_string()
    .as_bytes());
    let si = format!("{header}.{payload}");
    let sig = operator
        .sign(&KeyRef("op".into()), Alg::Es256, si.as_bytes())
        .unwrap();
    format!("{si}.{}", b64(&sig)).into_bytes()
}

/// Issue an SD-JWT VC; return (issuer_jwt, disclosures_by_claim).
fn issue(
    issuer: &SoftwareSigner,
    claims: &[(&str, serde_json::Value)],
) -> (String, BTreeMap<String, String>) {
    let mut by_claim = BTreeMap::new();
    let mut sd = Vec::new();
    for (i, (name, value)) in claims.iter().enumerate() {
        let raw = b64(
            serde_json::to_string(&json!([format!("s{i}"), name, value]))
                .unwrap()
                .as_bytes(),
        );
        sd.push(json!(b64(&AwsLc.sha256(raw.as_bytes()))));
        by_claim.insert(name.to_string(), raw);
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

fn sign_request(rp: &SoftwareSigner, nonce: u64, requested: &[&str]) -> Vec<u8> {
    let header = b64(br#"{"alg":"ES256","typ":"oauth-authz-req+jwt"}"#);
    let payload = b64(serde_json::to_string(&json!({
        "client_id": "rp.example",
        "nonce": nonce.to_string(),
        "aud": "wallet.example",
        "response_uri": "https://rp.example/response",
        "response_mode": "direct_post",
        "purpose": "Prove you are over 18",
        "claims": requested,
    }))
    .unwrap()
    .as_bytes());
    let si = format!("{header}.{payload}");
    let sig = rp
        .sign(&KeyRef("r".into()), Alg::Es256, si.as_bytes())
        .unwrap();
    format!("{si}.{}", b64(&sig)).into_bytes()
}

#[test]
fn full_presentation_through_wallet_core_with_data_minimisation() {
    let issuer = SoftwareSigner::generate_p256().unwrap();
    let device = SoftwareSigner::generate_p256().unwrap();
    // The RP signs its request with the private key of its real (openssl) reader certificate.
    let rp = SoftwareSigner::from_pkcs8_der(RP_PKCS8).unwrap();
    let trust_operator = SoftwareSigner::generate_p256().unwrap();

    // Wallet holds a PID with TWO claims.
    let (issuer_jwt, by_claim) = issue(
        &issuer,
        &[
            ("family_name", json!("Andersson")),
            ("age_over_18", json!(true)),
        ],
    );
    let mut core = Core::new("wallet.example", "device-key");
    core.load_unverified_credential_for_testing(HeldCredential {
        issuer_jwt: issuer_jwt.clone(),
        disclosures_by_claim: by_claim,
        status: None,
    });
    core.handle_event(Event::SetClock {
        epoch: 1_790_000_000,
    });
    // Install the signed trusted list; RP registration is now decided in-core against it.
    core.load_trust_list(
        &signed_trust_list(&trust_operator, &["age_over_18"]),
        trust_operator.public_key_raw(),
    )
    .expect("trust list loads");

    // RP requests ONLY age_over_18.
    const NONCE: u64 = 424242;
    let request = sign_request(&rp, NONCE, &["age_over_18"]);

    // 1) request → ResolveRpTrust
    let fx = core.handle_event(Event::AuthorizationRequestReceived { request });
    assert!(
        matches!(fx.as_slice(), [Effect::ResolveRpTrust { .. }]),
        "got {fx:?}"
    );

    // 2) the shell supplies the RP CERT CHAIN; the core validates it against the trusted list
    //    (registration is NOT a shell boolean) → PersistNonce + Render(consent)
    let fx = core.handle_event(Event::RpCertChainResolved {
        rp_cert_chain: vec![RP_DER.to_vec()],
        registered_redirect_uris: vec!["https://rp.example/response".into()],
    });
    let screen = fx.iter().find_map(|e| match e {
        Effect::Render { screen } => Some(screen.clone()),
        _ => None,
    });
    match screen {
        Some(presenter::ScreenDescription::Consent(c)) => {
            // Data minimisation: only the requested-and-held claim is shown, NOT family_name.
            assert_eq!(c.requested_claims, vec!["age_over_18".to_string()]);
            assert_eq!(c.not_shared_claims, vec!["family_name".to_string()]);
            assert_eq!(c.rp_display_name, "Example Verifier");
            assert_eq!(
                c.verifier_registration,
                presenter::VerifierRegistration::Registered
            );
            assert_eq!(c.trust_mark, Some(presenter::VerifierTrustMark::EudiWallet));
            assert_eq!(c.retention, presenter::RetentionDisclosure::NotStored);
            assert_eq!(c.over_ask, presenter::OverAskResult::WithinRegisteredScope);
            let mut covered = c.requested_claims.clone();
            covered.extend(c.not_shared_claims.clone());
            covered.sort();
            assert_eq!(covered, vec!["age_over_18", "family_name"]);
        }
        other => panic!("expected a consent screen, got {other:?}"),
    }

    // 3) consent → Sign (device key binding)
    let fx = core.handle_event(Event::UserConsented);
    let signing_input = fx
        .iter()
        .find_map(|e| match e {
            Effect::Sign { payload, .. } => Some(payload.clone()),
            _ => None,
        })
        .expect("expected a Sign effect");

    // 4) device signs → Http(vp_token)
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

    // The core now posts the OpenID4VP `direct_post` form body; this request used the legacy
    // `claims` array (no DCQL id), so `vp_token` carries the bare presentation.
    let vp_token = body
        .strip_prefix("vp_token=")
        .and_then(|s| s.split('&').next())
        .expect("vp_token form field");

    // 5) RP verifies the presentation with real crypto.
    let sd = sdjwt::SdJwtVc::parse(vp_token).unwrap();
    let kb = sdjwt::KeyBindingCheck {
        device_public_key: device.public_key_raw(),
        expected_aud: "rp.example",
        expected_nonce: &NONCE.to_string(),
        device_alg: Alg::Es256,
    };
    let claims = sd
        .verify_presentation(&AwsLc, &AwsLc, issuer.public_key_raw(), Alg::Es256, &kb)
        .expect("RP accepts the presentation");
    // Only age_over_18 was disclosed; family_name stayed private.
    assert_eq!(claims.get("age_over_18"), Some(&json!(true)));
    assert!(
        claims.get("family_name").is_none(),
        "family_name must NOT be disclosed"
    );

    // 6) delivery → Done
    let fx = core.handle_event(Event::PresentationDelivered);
    assert!(fx.iter().any(|e| matches!(e, Effect::Close)));
    assert_eq!(core.state(), &oid4vp::State::Done);
}

#[test]
fn consent_warns_when_authenticated_registration_does_not_entitle_a_claim() {
    let issuer = SoftwareSigner::generate_p256().unwrap();
    let rp = SoftwareSigner::from_pkcs8_der(RP_PKCS8).unwrap();
    let trust_operator = SoftwareSigner::generate_p256().unwrap();
    let (issuer_jwt, by_claim) = issue(
        &issuer,
        &[
            ("family_name", json!("Andersson")),
            ("age_over_18", json!(true)),
        ],
    );
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
        &signed_trust_list(&trust_operator, &["age_over_18"]),
        trust_operator.public_key_raw(),
    )
    .unwrap();
    core.handle_event(Event::AuthorizationRequestReceived {
        request: sign_request(&rp, 424_243, &["family_name"]),
    });
    let effects = core.handle_event(Event::RpCertChainResolved {
        rp_cert_chain: vec![RP_DER.to_vec()],
        // Signed registration metadata is authoritative; this shell-supplied decoy is ignored.
        registered_redirect_uris: vec!["https://attacker.example/cb".into()],
    });
    let consent = effects
        .iter()
        .find_map(|effect| match effect {
            Effect::Render {
                screen: presenter::ScreenDescription::Consent(consent),
            } => Some(consent),
            _ => None,
        })
        .expect("consent is rendered with an over-ask warning");
    assert_eq!(
        consent.over_ask,
        presenter::OverAskResult::ExceedsRegisteredScope {
            claims: vec!["family_name".into()],
        }
    );
}

#[test]
fn json_ffi_surface_round_trips() {
    // The exact API the iOS shell calls over UniFFI: JSON in, JSON array of effects out.
    let mut core = Core::new("wallet.example", "device-key");
    let out = core
        .handle_event_json(r#"{"type":"setClock","epoch":1790000000}"#)
        .unwrap();
    assert_eq!(out, "[]");
    let out = core
        .handle_event_json(r#"{"type":"authorizationRequestReceived","request":[110,111]}"#)
        .unwrap();
    // "no" is not a valid JWS → the machine visibly aborts and releases its active marker.
    let effects: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(effects[0]["type"], "render", "wire effects: {effects}");
    assert_eq!(
        effects[0]["screen"]["code"],
        "presentation_request_malformed"
    );
    assert_eq!(effects[1]["type"], "close");
    assert!(matches!(
        core.state(),
        oid4vp::State::Aborted(oid4vp::AbortReason::MalformedRequest)
    ));
    assert_eq!(
        core.handle_event_json(r#"{"type":"wipeTransactionLog"}"#)
            .unwrap(),
        "[]",
        "terminal presentation abort must not block a later history event"
    );
}
