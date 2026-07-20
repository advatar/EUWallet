//! OID4VCI issuance driven through wallet-core, proving issuer_trusted and proof_key_attested are
//! computed IN-CORE (trust+x509 for the issuer chain; a verified WUA bound to the device key) —
//! not shell booleans. Real aws-lc-rs crypto throughout.
use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use crypto_backend::{AwsLc, SoftwareSigner};
use crypto_traits::{Alg, Digest, KeyRef, Signer};
use serde_json::json;
use wallet_core::{Core, CredentialIngestionError, Effect, Event};

// The issuer leaf carries exactly one authenticated URI SAN and chains to the PID CA.
const CA_DER: &[u8] = include_bytes!("../../x509/tests/vectors/ca.der");
const ISSUER_CHAIN_LEAF_B64: &str = include_str!("../../x509/tests/vectors/issuer.der.b64");
const ISSUER_PKCS8: &[u8] = include_bytes!("../../x509/tests/vectors/rp.pkcs8.der");
const NOW: i64 = 1_790_000_000;

fn b64(b: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(b)
}

fn issuer_chain_leaf() -> Vec<u8> {
    Base64::decode_vec(ISSUER_CHAIN_LEAF_B64.trim()).expect("embedded issuer certificate")
}

fn signed_trust_list(operator: &SoftwareSigner) -> Vec<u8> {
    let header = b64(br#"{"alg":"ES256"}"#);
    let payload = b64(json!({
        "seq": 1, "valid_from": 0, "valid_until": 4_000_000_000i64,
        "anchors": [{ "cert": b64(CA_DER), "service": "pid", "status": "granted" }]
    })
    .to_string()
    .as_bytes());
    let si = format!("{header}.{payload}");
    let sig = operator
        .sign(&KeyRef("op".into()), Alg::Es256, si.as_bytes())
        .unwrap();
    format!("{si}.{}", b64(&sig)).into_bytes()
}

fn issue_wua(provider: &SoftwareSigner, device_pub: &[u8]) -> Vec<u8> {
    let header = b64(br#"{"alg":"ES256","typ":"wallet-unit-attestation+jwt"}"#);
    let payload = b64(
        json!({ "iss": "https://wp.example", "exp": 4_000_000_000i64, "aal": "high",
                "cnf": { "jwk_raw": b64(device_pub) } })
        .to_string()
        .as_bytes(),
    );
    let si = format!("{header}.{payload}");
    let sig = provider
        .sign(&KeyRef("wp".into()), Alg::Es256, si.as_bytes())
        .unwrap();
    format!("{si}.{}", b64(&sig)).into_bytes()
}

/// An issuer-authenticated, device-bound PID with every mandatory catalogue claim.
fn issued_sd_jwt(
    issuer: &SoftwareSigner,
    device_pub: &[u8],
    status: Option<serde_json::Value>,
) -> Vec<u8> {
    let disclosures: Vec<String> = [
        ("family_name", json!("Andersson")),
        ("given_name", json!("Astrid")),
        ("birthdate", json!("1988-04-12")),
    ]
    .into_iter()
    .enumerate()
    .map(|(i, (name, value))| {
        b64(json!([format!("salt-{i}"), name, value])
            .to_string()
            .as_bytes())
    })
    .collect();
    let digests: Vec<String> = disclosures
        .iter()
        .map(|raw| b64(&AwsLc.sha256(raw.as_bytes())))
        .collect();
    let header = b64(br#"{"alg":"ES256","typ":"dc+sd-jwt"}"#);
    let mut claims = json!({
        "iss":"https://issuer.example",
        "iat": NOW,
        "exp": 4_000_000_000i64,
        "vct":"urn:eudi:pid:1",
        "_sd_alg": "sha-256",
        "_sd": digests,
        "cnf": { "jwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": b64(&device_pub[1..33]),
            "y": b64(&device_pub[33..65]),
        }}
    });
    if let Some(status) = status {
        claims["status"] = status;
    }
    let payload = b64(claims.to_string().as_bytes());
    let si = format!("{header}.{payload}");
    let sig = issuer
        .sign(&KeyRef("i".into()), Alg::Es256, si.as_bytes())
        .unwrap();
    format!("{si}.{}~{}~", b64(&sig), disclosures.join("~")).into_bytes()
}

fn issued_sd_jwt_with_selective_exp(issuer: &SoftwareSigner, device_pub: &[u8]) -> Vec<u8> {
    let disclosures: Vec<String> = [
        ("family_name", json!("Andersson")),
        ("given_name", json!("Astrid")),
        ("birthdate", json!("1988-04-12")),
        ("exp", json!(4_000_000_000i64)),
    ]
    .into_iter()
    .enumerate()
    .map(|(index, (name, value))| {
        b64(json!([format!("control-salt-{index}"), name, value])
            .to_string()
            .as_bytes())
    })
    .collect();
    let digests: Vec<String> = disclosures
        .iter()
        .map(|raw| b64(&AwsLc.sha256(raw.as_bytes())))
        .collect();
    let header = b64(br#"{"alg":"ES256","typ":"dc+sd-jwt"}"#);
    let payload = b64(json!({
        "iss": "https://issuer.example",
        "iat": NOW,
        "vct": "urn:eudi:pid:1",
        "_sd_alg": "sha-256",
        "_sd": digests,
        "cnf": { "jwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": b64(&device_pub[1..33]),
            "y": b64(&device_pub[33..65]),
        }}
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

const OFFER: &[u8] = br#"{"format":"dc+sd-jwt","grant":"pre-authorized","tx_code_required":false}"#;

fn setup(load_trust: bool, load_wua: bool) -> (Core, SoftwareSigner, SoftwareSigner) {
    let device = SoftwareSigner::generate_p256().unwrap();
    let issuer = SoftwareSigner::from_pkcs8_der(ISSUER_PKCS8).unwrap();
    let trust_op = SoftwareSigner::generate_p256().unwrap();
    let wp = SoftwareSigner::generate_p256().unwrap();

    let mut core = Core::new("wallet.example", "device-key");
    core.handle_event(Event::SetClock { epoch: NOW });
    core.load_device_key(device.public_key_raw().to_vec());
    if load_trust {
        core.load_trust_list(&signed_trust_list(&trust_op), trust_op.public_key_raw())
            .unwrap();
    }
    if load_wua {
        core.load_wua(
            &issue_wua(&wp, device.public_key_raw()),
            wp.public_key_raw(),
        )
        .unwrap();
    }
    (core, device, issuer)
}

fn offer_event() -> Event {
    Event::CredentialOfferReceived {
        offer: OFFER.to_vec(),
        issuer_cert_chain: vec![issuer_chain_leaf()],
        issuer_id: "https://issuer.example".into(),
    }
}

#[test]
fn full_issuance_with_in_core_trust_and_attestation() {
    let (mut core, device, issuer) = setup(true, true);

    // Offer accepted (issuer trusted in-core) → RequestToken.
    let fx = core.handle_event(offer_event());
    assert!(
        fx.contains(&Effect::RequestToken),
        "issuer should be trusted, got {fx:?}"
    );

    // Token → the core requires proof_key_attested (in-core WUA check) before signing → Sign.
    let fx = core.handle_event(Event::TokenReceived {
        bound: true,
        c_nonce: 111,
    });
    let signing_input = fx
        .iter()
        .find_map(|e| match e {
            Effect::Sign { payload, .. } => Some(payload.clone()),
            _ => None,
        })
        .expect("proof key attested → Sign effect");

    // Device signs the proof → RequestCredential.
    let proof_sig = device
        .sign(&KeyRef("device-key".into()), Alg::Es256, &signing_input)
        .unwrap();
    let fx = core.handle_event(Event::DeviceSignatureProduced {
        signature: proof_sig,
    });
    assert!(fx
        .iter()
        .any(|e| matches!(e, Effect::RequestCredential { .. })));

    // Credential returned → issued.
    let cred = issued_sd_jwt(&issuer, device.public_key_raw(), None);
    core.handle_event(Event::CredentialReceived {
        format: "dc+sd-jwt".into(),
        bytes: cred.clone(),
    });
    let (fmt, bytes) = core.issued_credential().expect("credential issued");
    assert_eq!(fmt, "dc+sd-jwt");
    assert_eq!(bytes, cred);
}

#[test]
fn issuer_provided_key_binding_jwt_is_rejected_during_issuance() {
    let (mut core, device, issuer) = setup(true, true);
    assert!(core
        .handle_event(offer_event())
        .contains(&Effect::RequestToken));
    let signing_input = core
        .handle_event(Event::TokenReceived {
            bound: true,
            c_nonce: 112,
        })
        .into_iter()
        .find_map(|effect| match effect {
            Effect::Sign { payload, .. } => Some(payload),
            _ => None,
        })
        .expect("proof signature requested");
    let proof_signature = device
        .sign(&KeyRef("device-key".into()), Alg::Es256, &signing_input)
        .unwrap();
    assert!(core
        .handle_event(Event::DeviceSignatureProduced {
            signature: proof_signature,
        })
        .iter()
        .any(|effect| matches!(effect, Effect::RequestCredential { .. })));

    let mut issued_presentation =
        String::from_utf8(issued_sd_jwt(&issuer, device.public_key_raw(), None)).unwrap();
    // The credential builder ends in `~` (empty KB slot). Filling that slot turns it into a
    // presentation received from another transaction, which must never become a reusable holding.
    issued_presentation.push_str("fake.kb.jwt");
    let effects = core.handle_event(Event::CredentialReceived {
        format: "dc+sd-jwt".into(),
        bytes: issued_presentation.into_bytes(),
    });
    assert_eq!(effects, vec![Effect::Close]);
    assert!(core.issued_credential().is_none());
    assert_eq!(core.held_credentials_json(), "[]");
    assert_eq!(
        core.last_credential_ingestion_error(),
        Some(&CredentialIngestionError::MalformedCredential)
    );
}

#[test]
fn selectively_disclosed_protocol_control_is_rejected_at_storage_boundary() {
    let (mut core, device, issuer) = setup(true, false);
    let credential = issued_sd_jwt_with_selective_exp(&issuer, device.public_key_raw());
    assert_eq!(
        core.ingest_credential(
            "dc+sd-jwt",
            &credential,
            &[issuer_chain_leaf()],
            "https://issuer.example",
        ),
        Err(CredentialIngestionError::MalformedCredential)
    );
    assert_eq!(core.held_credentials_json(), "[]");
}

#[test]
fn untrusted_issuer_is_rejected_in_core() {
    // No trust list loaded → issuer_trusted is false → the offer is refused in-core.
    let (mut core, _device, _issuer) = setup(false, true);
    let fx = core.handle_event(offer_event());
    assert!(
        !fx.contains(&Effect::RequestToken),
        "an untrusted issuer must not proceed"
    );
}

#[test]
fn shell_issuer_id_is_only_a_checked_compatibility_assertion() {
    let (mut core, _device, _issuer) = setup(true, true);
    let fx = core.handle_event(Event::CredentialOfferReceived {
        offer: OFFER.to_vec(),
        issuer_cert_chain: vec![issuer_chain_leaf()],
        issuer_id: "https://other-issuer.example".into(),
    });
    assert!(
        !fx.contains(&Effect::RequestToken),
        "a shell identity mismatch must not authorize issuance: {fx:?}"
    );
}

#[test]
fn unattested_proof_key_is_rejected_in_core() {
    // Trust loaded but NO WUA → proof_key_attested is false → no Sign effect at token time.
    let (mut core, _device, _issuer) = setup(true, false);
    let _ = core.handle_event(offer_event());
    let fx = core.handle_event(Event::TokenReceived {
        bound: true,
        c_nonce: 222,
    });
    assert!(
        !fx.iter().any(|e| matches!(e, Effect::Sign { .. })),
        "without a valid WUA the proof key is not attested → no signing"
    );
}

#[test]
fn forged_credential_response_aborts_and_is_not_stored() {
    let (mut core, device, _issuer) = setup(true, true);
    let attacker = SoftwareSigner::generate_p256().unwrap();
    assert!(core
        .handle_event(offer_event())
        .contains(&Effect::RequestToken));
    let fx = core.handle_event(Event::TokenReceived {
        bound: true,
        c_nonce: 333,
    });
    let signing_input = fx
        .iter()
        .find_map(|effect| match effect {
            Effect::Sign { payload, .. } => Some(payload.clone()),
            _ => None,
        })
        .expect("proof signature requested");
    let proof_signature = device
        .sign(&KeyRef("device-key".into()), Alg::Es256, &signing_input)
        .unwrap();
    core.handle_event(Event::DeviceSignatureProduced {
        signature: proof_signature,
    });

    // The response is well-formed and device-bound, but the signer is not the key from the
    // validated issuer certificate path.
    let forged = issued_sd_jwt(&attacker, device.public_key_raw(), None);
    let effects = core.handle_event(Event::CredentialReceived {
        format: "dc+sd-jwt".into(),
        bytes: forged,
    });

    assert_eq!(effects, vec![Effect::Close]);
    assert!(core.issued_credential().is_none());
    assert_eq!(core.held_credentials_json(), "[]");
    assert_eq!(
        core.last_credential_ingestion_error(),
        Some(&CredentialIngestionError::SignatureInvalid)
    );
}

#[test]
fn authenticated_status_uri_and_index_are_preserved_as_one_reference() {
    let (mut core, device, issuer) = setup(true, false);
    let credential = issued_sd_jwt(
        &issuer,
        device.public_key_raw(),
        Some(json!({
            "status_list": {
                "idx": 17,
                "uri": "https://status.example/lists/pid-1"
            }
        })),
    );

    core.ingest_credential(
        "dc+sd-jwt",
        &credential,
        &[issuer_chain_leaf()],
        "https://issuer.example",
    )
    .unwrap();

    let export: serde_json::Value = serde_json::from_str(&core.export_json()).unwrap();
    assert_eq!(
        export["credential"]["status"]["uri"],
        "https://status.example/lists/pid-1"
    );
    assert_eq!(export["credential"]["status"]["index"], 17);
}

#[test]
fn non_integer_or_non_https_status_references_never_enter_storage() {
    for reference in [
        json!({"idx": "17", "uri": "https://status.example/lists/pid-1"}),
        json!({"idx": 17, "uri": "http://status.example/lists/pid-1"}),
        json!({"idx": 17, "uri": "https://status.example:bad/lists/pid-1"}),
        json!({"idx": 17, "uri": "https://attacker@status.example/lists/pid-1"}),
        json!({"idx": 17, "uri": "https://status.example/lists/pid-1#fragment"}),
    ] {
        let (mut core, device, issuer) = setup(true, false);
        let credential = issued_sd_jwt(
            &issuer,
            device.public_key_raw(),
            Some(json!({"status_list": reference})),
        );
        assert_eq!(
            core.ingest_credential(
                "dc+sd-jwt",
                &credential,
                &[issuer_chain_leaf()],
                "https://issuer.example",
            ),
            Err(CredentialIngestionError::UnsupportedStatusReference)
        );
        assert_eq!(core.held_credentials_json(), "[]");
    }
}
