//! Production SD-JWT holding tests: recursive authenticated paths survive ingestion and repeated
//! presentation-time verification, while disclosure selection and consent stay dependency-closed.

use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use crypto_backend::{AwsLc, SoftwareSigner};
use crypto_traits::{Alg, Digest, KeyRef, Signer};
use presenter::ScreenDescription;
use serde_json::{json, Value};
use wallet_core::{Core, Effect, Event};

const CA_DER: &[u8] = include_bytes!("../../x509/tests/vectors/ca.der");
const RP_DER: &[u8] = include_bytes!("../../x509/tests/vectors/rp.der");
const ISSUER_DER_B64: &str = include_str!("../../x509/tests/vectors/issuer.der.b64");
const ISSUER_PKCS8: &[u8] = include_bytes!("../../x509/tests/vectors/rp.pkcs8.der");
const NOW: i64 = 1_790_000_000;
const RESPONSE_URI: &str = "https://rp.example/response";
const ISSUER_ID: &str = "https://issuer.example";

fn b64(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

fn issuer_der() -> Vec<u8> {
    Base64::decode_vec(ISSUER_DER_B64.trim()).expect("valid issuer certificate vector")
}

fn signed_trust_list(operator: &SoftwareSigner) -> Vec<u8> {
    let header = b64(br#"{"alg":"ES256"}"#);
    let payload = b64(json!({
        "seq": 1,
        "valid_from": 0,
        "valid_until": 4_000_000_000i64,
        "anchors": [
            { "cert": b64(CA_DER), "service": "rp-access-ca", "status": "granted" },
            { "cert": b64(CA_DER), "service": "pid", "status": "granted" }
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

fn device_jwk(device_public_key: &[u8]) -> Value {
    json!({
        "kty": "EC",
        "crv": "P-256",
        "x": b64(&device_public_key[1..33]),
        "y": b64(&device_public_key[33..65]),
    })
}

fn object_disclosure(salt: &str, name: &str, value: Value) -> (String, String) {
    let raw = b64(json!([salt, name, value]).to_string().as_bytes());
    let digest = b64(&AwsLc.sha256(raw.as_bytes()));
    (raw, digest)
}

fn array_disclosure(salt: &str, value: Value) -> (String, String) {
    let raw = b64(json!([salt, value]).to_string().as_bytes());
    let digest = b64(&AwsLc.sha256(raw.as_bytes()));
    (raw, digest)
}

#[derive(Clone)]
struct NestedCredential {
    compact: Vec<u8>,
    address: String,
    street: String,
    locality: String,
    contact_0: String,
    contact_1: String,
    contact_2: String,
}

fn nested_credential(issuer: &SoftwareSigner, device_public_key: &[u8]) -> NestedCredential {
    let (street, street_digest) = object_disclosure("street-salt", "street", json!("Main Street"));
    let (locality, locality_digest) =
        object_disclosure("locality-salt", "locality", json!("Berlin"));
    let (address, address_digest) = object_disclosure(
        "address-salt",
        "address",
        json!({
            "country": "DE",
            "_sd": [street_digest, locality_digest]
        }),
    );
    let (contact_0, contact_0_digest) =
        array_disclosure("contact-0-salt", json!({"kind":"phone", "value":"+49-111"}));
    let (contact_1, contact_1_digest) = array_disclosure(
        "contact-1-salt",
        json!({"kind":"email", "value":"alice@example.com"}),
    );
    let (contact_2, contact_2_digest) = array_disclosure(
        "contact-2-salt",
        json!({"kind":"backup", "value":"backup@example.com"}),
    );

    let header = b64(br#"{"alg":"ES256","typ":"dc+sd-jwt"}"#);
    let payload = b64(json!({
        "iss": ISSUER_ID,
        "iat": NOW,
        "nbf": NOW,
        "exp": 4_000_000_000i64,
        "vct": "urn:eudi:pid:1",
        "_sd_alg": "sha-256",
        "_sd": [address_digest],
        "cnf": { "jwk": device_jwk(device_public_key) },
        // These mandatory PID attributes are permanent and therefore unavoidable whenever the
        // issuer JWT is presented, even though the RP does not request them.
        "family_name": "Andersson",
        "given_name": "Astrid",
        "birthdate": "1988-04-12",
        "picture": "data:image/jpeg;base64,/9j/2Q==",
        "contacts": [
            {"...": contact_0_digest},
            {"...": contact_1_digest},
            {"...": contact_2_digest}
        ]
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
    // Deliberately scramble wire order: authenticated parent relations, not input order, drive
    // selection and presentation ordering.
    let compact = format!(
        "{signing_input}.{}~{}~{}~{}~{}~{}~{}~",
        b64(&signature),
        street,
        contact_2,
        address,
        contact_0,
        locality,
        contact_1,
    )
    .into_bytes();
    NestedCredential {
        compact,
        address,
        street,
        locality,
        contact_0,
        contact_1,
        contact_2,
    }
}

fn signed_request(rp: &SoftwareSigner, nonce: u64, credential_query: Value) -> Vec<u8> {
    let header = b64(br#"{"alg":"ES256","typ":"oauth-authz-req+jwt"}"#);
    let payload = b64(json!({
        "client_id": "rp.example",
        "nonce": nonce.to_string(),
        "aud": "wallet.example",
        "response_uri": RESPONSE_URI,
        "response_mode": "direct_post",
        "purpose": "Contact verification",
        "dcql_query": { "credentials": [credential_query] }
    })
    .to_string()
    .as_bytes());
    let signing_input = format!("{header}.{payload}");
    let signature = rp
        .sign(&KeyRef("rp".into()), Alg::Es256, signing_input.as_bytes())
        .unwrap();
    format!("{signing_input}.{}", b64(&signature)).into_bytes()
}

fn setup() -> (
    Core,
    SoftwareSigner,
    SoftwareSigner,
    SoftwareSigner,
    NestedCredential,
) {
    let issuer_and_rp = SoftwareSigner::from_pkcs8_der(ISSUER_PKCS8).unwrap();
    let device = SoftwareSigner::generate_p256().unwrap();
    let operator = SoftwareSigner::generate_p256().unwrap();
    let credential = nested_credential(&issuer_and_rp, device.public_key_raw());
    let mut core = Core::new("wallet.example", "device-key");
    core.handle_event(Event::SetClock { epoch: NOW });
    core.load_device_key(device.public_key_raw().to_vec());
    core.load_trust_list(&signed_trust_list(&operator), operator.public_key_raw())
        .unwrap();
    core.ingest_credential("dc+sd-jwt", &credential.compact, &[issuer_der()], ISSUER_ID)
        .expect("recursive credential crosses authenticated storage boundary");
    (core, device, issuer_and_rp, operator, credential)
}

fn drive_to_consent(core: &mut Core, request: Vec<u8>) -> Vec<String> {
    assert!(matches!(
        core.handle_event(Event::AuthorizationRequestReceived { request })
            .as_slice(),
        [Effect::ResolveRpTrust { .. }]
    ));
    let effects = core.handle_event(Event::RpCertChainResolved {
        rp_cert_chain: vec![RP_DER.to_vec()],
        registered_redirect_uris: vec![RESPONSE_URI.into()],
    });
    effects
        .iter()
        .find_map(|effect| match effect {
            Effect::Render {
                screen: ScreenDescription::Consent(consent),
            } => Some(consent.requested_claims.clone()),
            _ => None,
        })
        .expect("validated request renders exact consent")
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let high = (bytes[index + 1] as char).to_digit(16).unwrap();
            let low = (bytes[index + 2] as char).to_digit(16).unwrap();
            output.push((high * 16 + low) as u8);
            index += 3;
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(output).unwrap()
}

fn finish_presentation(core: &mut Core, device: &SoftwareSigner) -> String {
    let signing_input = core
        .handle_event(Event::UserConsented)
        .into_iter()
        .find_map(|effect| match effect {
            Effect::Sign { payload, .. } => Some(payload),
            _ => None,
        })
        .expect("current structured holding passes pre-sign reauthentication");
    let signature = device
        .sign(&KeyRef("device-key".into()), Alg::Es256, &signing_input)
        .unwrap();
    let body = core
        .handle_event(Event::DeviceSignatureProduced { signature })
        .into_iter()
        .find_map(|effect| match effect {
            Effect::Http { body, .. } => String::from_utf8(body).ok(),
            _ => None,
        })
        .expect("structured holding passes pre-delivery reauthentication");
    let encoded = body
        .strip_prefix("vp_token=")
        .and_then(|body| body.split('&').next())
        .unwrap();
    let tokens: Value = serde_json::from_str(&percent_decode(encoded)).unwrap();
    tokens["pid"][0].as_str().unwrap().to_string()
}

#[test]
fn recursive_paths_wildcard_filter_dependencies_and_consent_round_trip() {
    const NONCE: u64 = 77;
    let (mut core, device, issuer, _operator, credential) = setup();
    let request = signed_request(
        &issuer,
        NONCE,
        json!({
            "id": "pid",
            "format": "dc+sd-jwt",
            "meta": { "vct_values": ["urn:eudi:pid:1"] },
            "claims": [
                { "path": ["address", "street"] },
                { "path": ["contacts", null, "kind"], "values": ["email"] }
            ]
        }),
    );
    let consent = drive_to_consent(&mut core, request);
    for visible in [
        "family_name",
        "given_name",
        "birthdate",
        "address.country",
        "address.street",
        "contacts[1].kind",
        "contacts[1].value",
    ] {
        assert!(consent.contains(&visible.to_string()), "missing {visible}");
    }
    assert!(!consent.contains(&"address.locality".to_string()));
    assert!(!consent.contains(&"contacts[0].kind".to_string()));
    assert!(!consent.contains(&"contacts[2].kind".to_string()));

    let presentation = finish_presentation(&mut core, &device);
    let parsed = sdjwt::SdJwtVc::parse(&presentation).unwrap();
    for selected in [
        &credential.address,
        &credential.street,
        &credential.contact_1,
    ] {
        assert!(parsed.disclosures.contains(selected));
    }
    assert!(!parsed.disclosures.contains(&credential.locality));
    assert!(!parsed.disclosures.contains(&credential.contact_0));
    assert!(!parsed.disclosures.contains(&credential.contact_2));

    let claims = parsed
        .verify_presentation(
            &AwsLc,
            &AwsLc,
            issuer.public_key_raw(),
            Alg::Es256,
            &sdjwt::KeyBindingCheck {
                device_public_key: device.public_key_raw(),
                expected_aud: "rp.example",
                expected_nonce: &NONCE.to_string(),
                device_alg: Alg::Es256,
            },
        )
        .expect("verifier accepts dependency-closed presentation");
    assert_eq!(claims["address"]["street"], json!("Main Street"));
    assert!(claims["address"].get("locality").is_none());
    assert_eq!(claims["contacts"].as_array().unwrap().len(), 1);
    assert_eq!(claims["contacts"][0]["kind"], json!("email"));

    assert!(core
        .handle_event(Event::PresentationDelivered)
        .contains(&Effect::Close));
    let audit = core.transaction_log_json();
    assert!(audit.contains("address.street"));
    assert!(audit.contains("contacts[1].value"));
    assert!(!audit.contains("contacts[0].value"));
    assert!(!audit.contains("address.locality"));
}

#[test]
fn absent_dcql_claims_reveals_no_selective_disclosures() {
    let (mut core, device, issuer, _operator, _credential) = setup();
    let request = signed_request(
        &issuer,
        88,
        json!({
            "id": "pid",
            "format": "dc+sd-jwt",
            "meta": { "vct_values": ["urn:eudi:pid:1"] }
        }),
    );
    let consent = drive_to_consent(&mut core, request);
    for permanent in ["family_name", "given_name", "birthdate"] {
        assert!(consent.contains(&permanent.to_string()));
    }
    assert!(!consent.iter().any(|path| path.starts_with("address")));
    assert!(!consent.iter().any(|path| path.starts_with("contacts")));

    let presentation = finish_presentation(&mut core, &device);
    let parsed = sdjwt::SdJwtVc::parse(&presentation).unwrap();
    assert!(parsed.disclosures.is_empty());
}
