//! DCQL **value constraints** (`claims[].values`) through wallet-core: a verifier can require a
//! claim to be one of a set of values (e.g. `age_over_18 ∈ [true]`), and the wallet presents the
//! credential only when its held value satisfies the constraint — never disclosing a value the
//! verifier asked to exclude. When nothing satisfies it, the presentation aborts (NoCredential).
use base64ct::{Base64UrlUnpadded, Encoding};
use crypto_backend::{AwsLc, SoftwareSigner};
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
    let sig = operator.sign(&KeyRef("op".into()), Alg::Es256, si.as_bytes()).unwrap();
    format!("{si}.{}", b64(&sig)).into_bytes()
}

fn issue_pid(issuer: &SoftwareSigner) -> (String, BTreeMap<String, String>) {
    let mut by_claim = BTreeMap::new();
    let mut sd = Vec::new();
    for (i, (name, value)) in [("age_over_18", json!(true)), ("nationality", json!("SE"))]
        .iter()
        .enumerate()
    {
        let raw = b64(serde_json::to_string(&json!([format!("s{i}"), name, value])).unwrap().as_bytes());
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
    let sig = issuer.sign(&KeyRef("i".into()), Alg::Es256, si.as_bytes()).unwrap();
    (format!("{si}.{}", b64(&sig)), by_claim)
}

/// A DCQL request for the PID's `age_over_18`, constrained to `allowed` values.
fn sign_values_request(rp: &SoftwareSigner, nonce: u64, claim: &str, allowed: serde_json::Value) -> Vec<u8> {
    let header = b64(br#"{"alg":"ES256","typ":"oauth-authz-req+jwt"}"#);
    let payload = b64(serde_json::to_string(&json!({
        "client_id": "rp.example",
        "nonce": nonce,
        "aud": "wallet.example",
        "response_uri": "https://rp.example/response",
        "purpose": "Check a constrained claim",
        "dcql_query": { "credentials": [{
            "id": "pid",
            "format": "dc+sd-jwt",
            "meta": { "vct_values": ["urn:eudi:pid:1"] },
            "claims": [{ "path": [claim], "values": allowed }]
        }]},
    }))
    .unwrap()
    .as_bytes());
    let si = format!("{header}.{payload}");
    let sig = rp.sign(&KeyRef("r".into()), Alg::Es256, si.as_bytes()).unwrap();
    format!("{si}.{}", b64(&sig)).into_bytes()
}

fn ready_core(issuer: &SoftwareSigner, operator: &SoftwareSigner) -> Core {
    let (issuer_jwt, by_claim) = issue_pid(issuer);
    let mut core = Core::new("wallet.example", "device-key");
    core.load_credential(HeldCredential {
        issuer_jwt,
        disclosures_by_claim: by_claim,
        status_index: None,
    });
    core.handle_event(Event::SetClock { epoch: 1_790_000_000 });
    core.load_trust_list(&signed_trust_list(operator), operator.public_key_raw())
        .expect("trust list loads");
    core
}

fn drive_to_consent(core: &mut Core, request: Vec<u8>) {
    core.handle_event(Event::AuthorizationRequestReceived { request });
    core.handle_event(Event::RpCertChainResolved {
        rp_cert_chain: vec![RP_DER.to_vec()],
        registered_redirect_uris: vec![],
    });
}

#[test]
fn a_matching_value_constraint_presents_the_credential() {
    let issuer = SoftwareSigner::generate_p256().unwrap();
    let device = SoftwareSigner::generate_p256().unwrap();
    let rp = SoftwareSigner::from_pkcs8_der(RP_PKCS8).unwrap();
    let operator = SoftwareSigner::generate_p256().unwrap();
    let mut core = ready_core(&issuer, &operator);

    // The holder IS over 18; the RP requires age_over_18 ∈ [true] → satisfied.
    drive_to_consent(&mut core, sign_values_request(&rp, NONCE, "age_over_18", json!([true])));
    let fx = core.handle_event(Event::UserConsented);
    let signing_input = fx
        .iter()
        .find_map(|e| match e {
            Effect::Sign { payload, .. } => Some(payload.clone()),
            _ => None,
        })
        .expect("value constraint satisfied → the machine signs the KB-JWT");
    let fx = core.handle_event(Event::DeviceSignatureProduced {
        signature: device.sign(&KeyRef("device-key".into()), Alg::Es256, &signing_input).unwrap(),
    });
    let body = fx
        .iter()
        .find_map(|e| match e {
            Effect::Http { body, .. } => Some(String::from_utf8(body.clone()).unwrap()),
            _ => None,
        })
        .expect("a vp_token is posted");
    assert!(body.contains("%22pid%22"), "the PID is presented under its DCQL id: {body}");
}

#[test]
fn an_unsatisfiable_value_constraint_presents_nothing() {
    let issuer = SoftwareSigner::generate_p256().unwrap();
    let rp = SoftwareSigner::from_pkcs8_der(RP_PKCS8).unwrap();
    let operator = SoftwareSigner::generate_p256().unwrap();
    let mut core = ready_core(&issuer, &operator);

    // The RP demands nationality ∈ ["DE"], but the holder's is "SE" → no credential qualifies.
    drive_to_consent(&mut core, sign_values_request(&rp, NONCE, "nationality", json!(["DE"])));
    let fx = core.handle_event(Event::UserConsented);
    assert!(
        !fx.iter().any(|e| matches!(e, Effect::Sign { .. } | Effect::Http { .. })),
        "an unsatisfiable value constraint discloses nothing: {fx:?}"
    );
    assert_eq!(
        core.state(),
        &oid4vp::State::Aborted(oid4vp::AbortReason::NoCredential),
        "the presentation aborts because no held credential satisfies the value constraint"
    );
}
