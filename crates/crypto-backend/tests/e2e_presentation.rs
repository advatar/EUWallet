//! End-to-end OpenID4VP remote presentation with REAL crypto (plan M2).
//!
//! An issuer signs an SD-JWT VC PID; a relying party sends a signed authorization request; the
//! `oid4vp` sans-IO machine drives the flow; the device (Secure Enclave, simulated by a software
//! key here) signs the key-binding JWT via the effect boundary; the RP verifies the resulting
//! vp_token — issuer signature, disclosures, and holder key binding — all with aws-lc-rs.
use base64ct::{Base64UrlUnpadded, Encoding};
use crypto_backend::{AwsLc, SoftwareSigner};
use crypto_traits::{Alg, Digest, KeyRef, Signer};
use oid4vp::{step, Env, Input, Output, ResolvedTrust, SelectedCredential, State};
use serde_json::json;

fn b64(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

/// Issuer builds and signs an SD-JWT VC with the given selectively-disclosable claims.
/// Returns (issuer_jwt, disclosures).
fn issue_sd_jwt(
    issuer: &SoftwareSigner,
    claims: &[(&str, serde_json::Value)],
) -> (String, Vec<String>) {
    let mut disclosures = Vec::new();
    let mut sd = Vec::new();
    for (i, (name, value)) in claims.iter().enumerate() {
        let raw = b64(
            serde_json::to_string(&json!([format!("salt{i}"), name, value]))
                .unwrap()
                .as_bytes(),
        );
        sd.push(json!(b64(&AwsLc.sha256(raw.as_bytes()))));
        disclosures.push(raw);
    }
    let header = b64(br#"{"alg":"ES256","typ":"dc+sd-jwt"}"#);
    let payload = b64(serde_json::to_string(&json!({
        "iss": "https://issuer.example",
        "vct": "urn:eudi:pid:1",
        "_sd_alg": "sha-256",
        "_sd": sd,
    }))
    .unwrap()
    .as_bytes());
    let signing_input = format!("{header}.{payload}");
    let sig = issuer
        .sign(
            &KeyRef("issuer".into()),
            Alg::Es256,
            signing_input.as_bytes(),
        )
        .unwrap();
    (format!("{signing_input}.{}", b64(&sig)), disclosures)
}

/// RP builds and signs an OpenID4VP authorization request object (compact JWS).
fn sign_request(rp: &SoftwareSigner, client_id: &str, nonce: u64, aud: &str) -> Vec<u8> {
    let header = b64(br#"{"alg":"ES256","typ":"oauth-authz-req+jwt"}"#);
    let payload = b64(serde_json::to_string(&json!({
        "client_id": client_id,
        "nonce": nonce,
        "aud": aud,
        "response_uri": "https://rp.example/response",
        "purpose": "Prove you are over 18",
    }))
    .unwrap()
    .as_bytes());
    let signing_input = format!("{header}.{payload}");
    let sig = rp
        .sign(&KeyRef("rp".into()), Alg::Es256, signing_input.as_bytes())
        .unwrap();
    format!("{signing_input}.{}", b64(&sig)).into_bytes()
}

#[test]
fn full_remote_presentation_with_real_crypto() {
    // Three independent keys: the issuer, the wallet's device key, and the RP's request key.
    let issuer = SoftwareSigner::generate_p256().unwrap();
    let device = SoftwareSigner::generate_p256().unwrap();
    let rp = SoftwareSigner::generate_p256().unwrap();

    // Issuer issues a PID with two selectively-disclosable claims.
    let (issuer_jwt, disclosures) = issue_sd_jwt(
        &issuer,
        &[
            ("family_name", json!("Andersson")),
            ("age_over_18", json!(true)),
        ],
    );

    // RP sends a signed request.
    const NONCE: u64 = 987654321;
    let request = sign_request(&rp, "rp.example", NONCE, "wallet.example");

    // The wallet drives the sans-IO machine.
    let seen: Vec<u64> = vec![];
    let cred = SelectedCredential {
        issuer_jwt: issuer_jwt.clone(),
        disclosures: disclosures.clone(),
    };
    let env = Env {
        wallet_client_id: "wallet.example",
        seen_nonces: &seen,
        verifier: &AwsLc,
        digest: &AwsLc,
        now_epoch: 1_790_000_000,
        selected_credential: Some(&cred),
        device_key_ref: "device-key",
    };

    // 1) Request received → resolve trust.
    let (s, out) = step(&State::Idle, &Input::AuthorizationRequest(request), &env);
    assert!(matches!(s, State::ResolvingTrust(_)), "state: {s:?}");
    assert!(matches!(out.as_slice(), [Output::ResolveRpTrust { .. }]));

    // 2) Trust resolved with the RP's REAL public key → the signed-request guard verifies for real.
    let trust = ResolvedTrust {
        registered: true,
        rp_public_key: rp.public_key_raw().to_vec(),
        registered_redirect_uris: vec![],
    };
    let (s, out) = step(&s, &Input::RpTrustResolved(trust), &env);
    assert!(
        matches!(s, State::RequestValidated(_)),
        "guards should pass, got {s:?}"
    );
    assert!(out
        .iter()
        .any(|o| matches!(o, Output::RenderConsent { .. })));

    // 3) User consents → the machine asks the device to sign the key-binding JWT.
    let (s, out) = step(&s, &Input::ConsentGranted, &env);
    let signing_input = match out.as_slice() {
        [Output::SignKeyBinding { signing_input, .. }] => signing_input.clone(),
        other => panic!("expected SignKeyBinding, got {other:?}"),
    };
    assert!(matches!(s, State::AwaitingDeviceSignature(_)));

    // 4) The device (Secure Enclave, here a software key) signs and feeds the result back.
    let device_sig = device
        .sign(&KeyRef("device-key".into()), Alg::Es256, &signing_input)
        .unwrap();
    let (s, out) = step(&s, &Input::DeviceSignatureProduced(device_sig), &env);
    assert_eq!(s, State::Presenting);
    let vp_token = match out.as_slice() {
        [Output::SendVpToken(t)] => String::from_utf8(t.clone()).unwrap(),
        other => panic!("expected SendVpToken, got {other:?}"),
    };

    // 5) RP side: verify the whole presentation with real crypto.
    let sd = sdjwt::SdJwtVc::parse(&vp_token).expect("parse vp_token");
    let kb = sdjwt::KeyBindingCheck {
        device_public_key: device.public_key_raw(),
        expected_aud: "rp.example",
        expected_nonce: NONCE,
        device_alg: Alg::Es256,
    };
    let claims = sd
        .verify_presentation(&AwsLc, &AwsLc, issuer.public_key_raw(), Alg::Es256, &kb)
        .expect("RP must accept a well-formed, key-bound presentation");

    assert_eq!(claims.get("family_name"), Some(&json!("Andersson")));
    assert_eq!(claims.get("age_over_18"), Some(&json!(true)));

    // 6) Negative: the SAME presentation replayed to a DIFFERENT nonce must be rejected
    //    (key binding ties it to this request).
    let wrong = sdjwt::KeyBindingCheck {
        device_public_key: device.public_key_raw(),
        expected_aud: "rp.example",
        expected_nonce: NONCE + 1,
        device_alg: Alg::Es256,
    };
    assert!(sd
        .verify_presentation(&AwsLc, &AwsLc, issuer.public_key_raw(), Alg::Es256, &wrong)
        .is_err());
}
