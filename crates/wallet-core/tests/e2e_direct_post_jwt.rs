//! End-to-end **`direct_post.jwt`** (encrypted OpenID4VP response) through `wallet-core`. A verifier
//! asks for `age_over_18` with `response_mode: "direct_post.jwt"` and publishes its
//! response-encryption key in `client_metadata.jwks`. The wallet presents, and — because the mode is
//! encrypted — the body that leaves the device is `response=<compact JWE>`, NOT a plaintext form.
//!
//! The test then acts as the verifier: it agrees to the ECDH-ES shared secret with its private key,
//! opens the JWE, and recovers the `{vp_token, state}` response — proving the presentation is
//! confidential on the wire and decryptable only by the intended recipient (real aws-lc-rs crypto).
use base64ct::{Base64UrlUnpadded, Encoding};
use crypto_backend::{AwsLc, P256AgreementKey, SoftwareSigner};
use crypto_traits::{Alg, Digest, KeyRef, Signer};
use serde_json::json;
use std::collections::BTreeMap;
use wallet_core::{Core, Effect, Event, HeldCredential};

fn b64(b: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(b)
}

const CA_DER: &[u8] = include_bytes!("../../x509/tests/vectors/ca.der");
const RP_DER: &[u8] = include_bytes!("../../x509/tests/vectors/rp.der");
const RP_PKCS8: &[u8] = include_bytes!("../../x509/tests/vectors/rp.pkcs8.der");
const NONCE: u64 = 424_242;

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

/// An RP-signed `direct_post.jwt` request: DCQL for the PID's `age_over_18`, with the verifier's
/// response-encryption key (P-256) published in `client_metadata.jwks`.
fn sign_encrypted_request(rp: &SoftwareSigner, nonce: u64, recipient_pub: &[u8]) -> Vec<u8> {
    let (x, y) = (&recipient_pub[1..33], &recipient_pub[33..65]);
    let header = b64(br#"{"alg":"ES256","typ":"oauth-authz-req+jwt"}"#);
    let payload = b64(serde_json::to_string(&json!({
        "client_id": "rp.example",
        "nonce": nonce,
        "aud": "wallet.example",
        "response_uri": "https://rp.example/response",
        "response_mode": "direct_post.jwt",
        "purpose": "Prove you are over 18",
        "client_metadata": {
            "authorization_encrypted_response_alg": "ECDH-ES",
            "authorization_encrypted_response_enc": "A256GCM",
            "jwks": { "keys": [{
                "kty": "EC", "crv": "P-256", "use": "enc", "alg": "ECDH-ES",
                "x": b64(x), "y": b64(y)
            }]}
        },
        "dcql_query": {
            "credentials": [{
                "id": "pid",
                "format": "dc+sd-jwt",
                "meta": { "vct_values": ["urn:eudi:pid:1"] },
                "claims": [{ "path": ["age_over_18"] }]
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

#[test]
fn encrypted_response_leaves_the_device_as_a_jwe_only_the_verifier_can_open() {
    let issuer = SoftwareSigner::generate_p256().unwrap();
    let device = SoftwareSigner::generate_p256().unwrap();
    let rp = SoftwareSigner::from_pkcs8_der(RP_PKCS8).unwrap();
    let trust_operator = SoftwareSigner::generate_p256().unwrap();
    let verifier_enc = P256AgreementKey::generate().unwrap();

    let (issuer_jwt, by_claim) = issue_pid(&issuer);
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
    .expect("trust list loads");

    // Drive: request → trust → consent → device signature → the posted response.
    let request = sign_encrypted_request(&rp, NONCE, verifier_enc.public_raw());
    let fx = core.handle_event(Event::AuthorizationRequestReceived { request });
    assert!(
        matches!(fx.as_slice(), [Effect::ResolveRpTrust { .. }]),
        "got {fx:?}"
    );
    core.handle_event(Event::RpCertChainResolved {
        rp_cert_chain: vec![RP_DER.to_vec()],
        registered_redirect_uris: vec!["https://rp.example/response".into()],
    });
    let fx = core.handle_event(Event::UserConsented);
    let signing_input = fx
        .iter()
        .find_map(|e| match e {
            Effect::Sign { payload, .. } => Some(payload.clone()),
            _ => None,
        })
        .expect("consent → Sign the KB-JWT");
    let sig = device
        .sign(&KeyRef("device-key".into()), Alg::Es256, &signing_input)
        .unwrap();
    let fx = core.handle_event(Event::DeviceSignatureProduced { signature: sig });
    let body = fx
        .iter()
        .find_map(|e| match e {
            Effect::Http { body, .. } => Some(String::from_utf8(body.clone()).unwrap()),
            _ => None,
        })
        .expect("an Http effect carries the response");

    // Confidential on the wire: an encrypted `response=<JWE>`, never a plaintext `vp_token=`.
    assert!(
        body.starts_with("response="),
        "encrypted response body, got: {body}"
    );
    assert!(
        !body.contains("vp_token="),
        "the plaintext vp_token must NOT appear on the wire"
    );
    let compact = body.strip_prefix("response=").unwrap();

    // ---- VERIFIER: agree to Z with the private key, open the JWE, recover {vp_token, state}. ----
    let parts = jwe::parse_compact(compact).expect("parse compact JWE");
    let z = verifier_enc
        .agree(&parts.ephemeral_public)
        .expect("verifier agrees to Z");
    let plaintext = parts
        .open(&z, &AwsLc, &AwsLc)
        .expect("verifier opens the JWE");
    let response: serde_json::Value = serde_json::from_slice(&plaintext).expect("response JSON");

    // The decrypted response is the OpenID4VP object: vp_token keyed by the DCQL id, with a
    // verifiable SD-JWT presentation that disclosed exactly age_over_18.
    let presentation = response["vp_token"]["pid"][0]
        .as_str()
        .expect("DCQL-keyed vp_token");
    let sd = sdjwt::SdJwtVc::parse(presentation).expect("SD-JWT presentation parses");
    let kb = sdjwt::KeyBindingCheck {
        device_public_key: device.public_key_raw(),
        expected_aud: "rp.example",
        expected_nonce: NONCE,
        device_alg: Alg::Es256,
    };
    let claims = sd
        .verify_presentation(&AwsLc, &AwsLc, issuer.public_key_raw(), Alg::Es256, &kb)
        .expect("verifier accepts the decrypted presentation");
    assert_eq!(claims.get("age_over_18"), Some(&json!(true)));
    assert!(
        claims.get("family_name").is_none(),
        "family_name stayed minimised AND encrypted"
    );

    // A wrong key cannot open it (confidentiality really depends on the recipient key).
    let attacker = P256AgreementKey::generate().unwrap();
    let z_bad = attacker.agree(&parts.ephemeral_public).unwrap();
    assert!(
        parts.open(&z_bad, &AwsLc, &AwsLc).is_err(),
        "only the intended verifier can decrypt"
    );
}
