//! OID4VCI issuance driven through wallet-core, proving issuer_trusted and proof_key_attested are
//! computed IN-CORE (trust+x509 for the issuer chain; a verified WUA bound to the device key) —
//! not shell booleans. Real aws-lc-rs crypto throughout.
use base64ct::{Base64UrlUnpadded, Encoding};
use crypto_backend::SoftwareSigner;
use crypto_traits::{Alg, KeyRef, Signer};
use serde_json::json;
use wallet_core::{Core, Effect, Event};

// The issuer chain reuses the real openssl leaf (rp.der) chaining to the trusted CA (ca.der);
// issuer trust is chain validity to a trusted PID anchor, independent of the EKU profile.
const CA_DER: &[u8] = include_bytes!("../../x509/tests/vectors/ca.der");
const ISSUER_CHAIN_LEAF: &[u8] = include_bytes!("../../x509/tests/vectors/rp.der");
const NOW: i64 = 1_790_000_000;

fn b64(b: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(b)
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

/// A minimal issuer-signed SD-JWT VC (no disclosures) that parses as a credential.
fn issued_sd_jwt(issuer: &SoftwareSigner) -> Vec<u8> {
    let header = b64(br#"{"alg":"ES256","typ":"dc+sd-jwt"}"#);
    let payload = b64(
        json!({"iss":"https://issuer.example","vct":"urn:eudi:pid:1"})
            .to_string()
            .as_bytes(),
    );
    let si = format!("{header}.{payload}");
    let sig = issuer
        .sign(&KeyRef("i".into()), Alg::Es256, si.as_bytes())
        .unwrap();
    format!("{si}.{}~", b64(&sig)).into_bytes()
}

const OFFER: &[u8] = br#"{"format":"dc+sd-jwt","grant":"pre-authorized","tx_code_required":false}"#;

fn setup(load_trust: bool, load_wua: bool) -> (Core, SoftwareSigner, SoftwareSigner) {
    let device = SoftwareSigner::generate_p256().unwrap();
    let issuer = SoftwareSigner::generate_p256().unwrap();
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
        issuer_cert_chain: vec![ISSUER_CHAIN_LEAF.to_vec()],
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
    let cred = issued_sd_jwt(&issuer);
    core.handle_event(Event::CredentialReceived {
        format: "dc+sd-jwt".into(),
        bytes: cred.clone(),
    });
    let (fmt, bytes) = core.issued_credential().expect("credential issued");
    assert_eq!(fmt, "dc+sd-jwt");
    assert_eq!(bytes, cred);
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
