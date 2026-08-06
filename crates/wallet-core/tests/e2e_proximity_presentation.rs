//! End-to-end in-person (ISO/IEC 18013-5) proximity presentation driven entirely through the
//! wallet-core `Event`/`Effect` facade, with a **simulated reader** completing the crypto half.
//!
//! Covers the full B3a+B3b path without a physical reader:
//!   engagement → the reader's encrypted ItemsRequest in SessionEstablishment → real ECDH + HKDF
//!   key derivation → credential selection + data minimisation → consent (listing the requested
//!   elements) → device signature → a real, minimised ISO 18013-5 DeviceResponse, AES-256-GCM
//!   encrypted as SessionData, which the simulated reader decrypts and inspects.
//!
//! The remaining step needs a real reader/second device: reader authentication and a hardware
//! interop run.

use cose::cbor::{decode_value, Value};
use crypto_backend::{AwsLc, P256AgreementKey, SoftwareSigner};
use crypto_traits::{Alg, KeyRef, Signer};
use mdoc::{build_and_sign, IssuerSignedItem, ValidityInfo};
use std::collections::BTreeMap;
use wallet_core::proximity_session::{
    cose_ec2_to_sec1, derive_session_keys, device_key_from_engagement, parse_session_data,
    sec1_to_cose_ec2, SessionCipher,
};
use wallet_core::{Core, Effect, Event, MdocHolding};

const DOCTYPE: &str = "org.iso.18013.5.1.mDL";
const NS: &str = "org.iso.18013.5.1";

fn find_engagement(effects: &[Effect]) -> Option<Vec<u8>> {
    effects.iter().find_map(|e| match e {
        Effect::EmitDeviceEngagement { engagement } => Some(engagement.clone()),
        _ => None,
    })
}

fn find_sign_payload(effects: &[Effect]) -> Option<Vec<u8>> {
    effects.iter().find_map(|e| match e {
        Effect::Sign { payload, .. } => Some(payload.clone()),
        _ => None,
    })
}

fn find_device_response(effects: &[Effect]) -> Option<Vec<u8>> {
    effects.iter().find_map(|e| match e {
        Effect::EmitDeviceResponse { response } => Some(response.clone()),
        _ => None,
    })
}

/// COSE_Key (EC2/P-256) as a CBOR `Value`, for the MSO device key — via the same SEC1→COSE_Key
/// conversion the wallet uses, then decoded back to a `Value` for `build_and_sign`.
fn cose_key_value(sec1: &[u8]) -> Value {
    let bytes = sec1_to_cose_ec2(sec1).expect("valid SEC1");
    decode_value(&bytes, 0).expect("COSE_Key decodes").0
}

/// Seed the wallet with an mDL holding bound to `device`, carrying two data elements.
fn seed_mdl(core: &mut Core, issuer: &SoftwareSigner, device: &SoftwareSigner) {
    let mut name_spaces = BTreeMap::new();
    name_spaces.insert(
        NS.to_string(),
        vec![
            IssuerSignedItem {
                digest_id: 0,
                random: vec![0x11; 16],
                element_id: "age_over_18".into(),
                element_value: Value::Bool(true),
            },
            IssuerSignedItem {
                digest_id: 1,
                random: vec![0x22; 16],
                element_id: "family_name".into(),
                element_value: Value::Text("Andersson".into()),
            },
        ],
    );
    let issuer_signed = build_and_sign(
        name_spaces,
        DOCTYPE,
        cose_key_value(device.public_key_raw()),
        ValidityInfo {
            signed: "2026-07-19T00:00:00Z".into(),
            valid_from: "2026-07-19T00:00:00Z".into(),
            valid_until: "2035-01-01T00:00:00Z".into(),
        },
        &AwsLc,
        issuer,
        &KeyRef("issuer".into()),
        Alg::Es256,
    )
    .expect("issue mDL");
    core.load_unverified_mdoc_for_testing(MdocHolding {
        doctype: DOCTYPE.into(),
        issuer_signed,
    });
}

/// A reader's DeviceRequest asking for exactly `elements` of `DOCTYPE`.
fn device_request(elements: &[&str]) -> Vec<u8> {
    let items: Vec<(Value, Value)> = elements
        .iter()
        .map(|e| (Value::Text((*e).into()), Value::Bool(false)))
        .collect();
    let items_request = Value::Map(vec![
        (Value::Text("docType".into()), Value::Text(DOCTYPE.into())),
        (
            Value::Text("nameSpaces".into()),
            Value::Map(vec![(Value::Text(NS.into()), Value::Map(items))]),
        ),
    ])
    .to_canonical();
    let doc_request = Value::Map(vec![(
        Value::Text("itemsRequest".into()),
        Value::Tag(24, Box::new(Value::Bytes(items_request))),
    )]);
    Value::Map(vec![
        (Value::Text("version".into()), Value::Text("1.0".into())),
        (
            Value::Text("docRequests".into()),
            Value::Array(vec![doc_request]),
        ),
    ])
    .to_canonical()
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|w| w == needle.as_bytes())
}

#[test]
fn in_person_presentation_returns_a_minimised_device_response() {
    let issuer = SoftwareSigner::generate_p256().unwrap();
    let device = SoftwareSigner::generate_p256().unwrap();
    let mut core = Core::new("wallet-client", "device-key");
    core.handle_event(Event::SetClock {
        epoch: 1_790_000_000,
    });
    seed_mdl(&mut core, &issuer, &device);

    // 1. Engagement.
    let effects = core.handle_event(Event::ProximityEngagementRequested {
        ble_uuid: vec![0x11; 16],
    });
    let engagement = find_engagement(&effects).expect("DeviceEngagement is emitted");

    // ---- Simulated reader: scan engagement, make an ephemeral key, derive the SAME session keys,
    // and encrypt an ItemsRequest asking for ONLY age_over_18 (not family_name).
    let device_cose = device_key_from_engagement(&engagement).unwrap();
    let device_sec1 = cose_ec2_to_sec1(&device_cose).unwrap();
    let reader = P256AgreementKey::generate().unwrap();
    let reader_cose = sec1_to_cose_ec2(reader.public_raw()).unwrap();
    let z = reader.agree(&device_sec1).unwrap();
    let transcript = iso18013_5::session_transcript(&engagement, &reader_cose);
    let keys = derive_session_keys(&AwsLc, &z, &transcript);
    let mut reader_cipher = SessionCipher::new(keys);
    let encrypted_request = reader_cipher
        .seal_from_reader(&AwsLc, &device_request(&["age_over_18"]))
        .unwrap();

    // 2. SessionEstablishment { eReaderKey, data }.
    let establishment = Value::Map(vec![
        (
            Value::Text("eReaderKey".into()),
            Value::Tag(24, Box::new(Value::Bytes(reader_cose.clone()))),
        ),
        (Value::Text("data".into()), Value::Bytes(encrypted_request)),
    ])
    .to_canonical();
    let effects = core.handle_event(Event::ProximityReaderEstablishment {
        session_establishment: establishment,
    });
    // The consent screen lists exactly the requested element.
    let consent_lists_age = effects.iter().any(|e| {
        matches!(e, Effect::Render { screen }
            if format!("{screen:?}").contains("age_over_18")
            && !format!("{screen:?}").contains("family_name"))
    });
    assert!(
        consent_lists_age,
        "consent surfaces only the requested element"
    );

    // 3. Consent → the core asks the device to sign DeviceAuthentication.
    let effects = core.handle_event(Event::UserConsented);
    let signing_input = find_sign_payload(&effects).expect("device-auth signing requested");
    let signature = device
        .sign(&KeyRef("device-key".into()), Alg::Es256, &signing_input)
        .unwrap();

    // 4. Device signature → encrypted SessionData DeviceResponse.
    let effects = core.handle_event(Event::DeviceSignatureProduced { signature });
    let response = find_device_response(&effects).expect("encrypted DeviceResponse emitted");

    // ---- Reader decrypts + inspects the DeviceResponse.
    let ciphertext = parse_session_data(&response).unwrap();
    let device_response = reader_cipher
        .open_from_device(&AwsLc, &ciphertext)
        .expect("reader decrypts the SessionData with SKDevice");

    // It is a well-formed CBOR DeviceResponse...
    let (parsed, rest) = decode_value(&device_response, 0).expect("DeviceResponse decodes");
    assert!(rest.is_empty());
    assert!(matches!(parsed, Value::Map(_)), "DeviceResponse is a map");
    assert!(
        contains(&device_response, "documents"),
        "carries a document"
    );
    // ...disclosing EXACTLY the requested element — data minimisation held end-to-end.
    assert!(
        contains(&device_response, "age_over_18"),
        "the requested element is disclosed"
    );
    assert!(
        !contains(&device_response, "family_name"),
        "the un-requested element is NOT disclosed (minimised)"
    );
}

#[test]
fn declining_in_person_consent_closes_the_session() {
    let issuer = SoftwareSigner::generate_p256().unwrap();
    let device = SoftwareSigner::generate_p256().unwrap();
    let mut core = Core::new("wallet-client", "device-key");
    core.handle_event(Event::SetClock {
        epoch: 1_790_000_000,
    });
    seed_mdl(&mut core, &issuer, &device);

    let effects = core.handle_event(Event::ProximityEngagementRequested {
        ble_uuid: vec![0x22; 16],
    });
    let engagement = find_engagement(&effects).unwrap();
    let device_cose = device_key_from_engagement(&engagement).unwrap();
    let device_sec1 = cose_ec2_to_sec1(&device_cose).unwrap();
    let reader = P256AgreementKey::generate().unwrap();
    let reader_cose = sec1_to_cose_ec2(reader.public_raw()).unwrap();
    let z = reader.agree(&device_sec1).unwrap();
    let transcript = iso18013_5::session_transcript(&engagement, &reader_cose);
    let mut reader_cipher = SessionCipher::new(derive_session_keys(&AwsLc, &z, &transcript));
    let encrypted_request = reader_cipher
        .seal_from_reader(&AwsLc, &device_request(&["age_over_18"]))
        .unwrap();
    let establishment = Value::Map(vec![
        (
            Value::Text("eReaderKey".into()),
            Value::Tag(24, Box::new(Value::Bytes(reader_cose))),
        ),
        (Value::Text("data".into()), Value::Bytes(encrypted_request)),
    ])
    .to_canonical();
    core.handle_event(Event::ProximityReaderEstablishment {
        session_establishment: establishment,
    });

    let effects = core.handle_event(Event::UserDeclined);
    assert!(
        effects.iter().any(|e| matches!(e, Effect::Close)),
        "declining consent tears the exchange down before anything is disclosed"
    );
}

/// The iOS shell can only reach the core through `handle_event_json`, which gates
/// `userConsented`/`userDeclined` on a valid `operationId` + `authorizationHash`. This drives the
/// proximity flow over that JSON boundary (the typed-`handle_event` tests bypass it) to prove the
/// consent render registers a `ProximityDecision` pending operation and that `userConsented`
/// carrying the rendered screen's hash is accepted.
#[test]
fn proximity_consent_is_accepted_over_the_json_ffi_boundary() {
    fn json_u8s(bytes: &[u8]) -> String {
        let nums: Vec<String> = bytes.iter().map(ToString::to_string).collect();
        format!("[{}]", nums.join(","))
    }
    fn effects(json: &str) -> Vec<serde_json::Value> {
        serde_json::from_str(json).expect("effect array")
    }
    fn find<'a>(fx: &'a [serde_json::Value], ty: &str) -> Option<&'a serde_json::Value> {
        fx.iter().find(|e| e["type"] == serde_json::json!(ty))
    }

    let issuer = SoftwareSigner::generate_p256().unwrap();
    let device = SoftwareSigner::generate_p256().unwrap();
    let mut core = Core::new("wallet-client", "device-key");
    core.handle_event(Event::SetClock {
        epoch: 1_790_000_000,
    });
    seed_mdl(&mut core, &issuer, &device);

    // 1. Engagement over JSON.
    let out = core
        .handle_event_json(&format!(
            r#"{{"type":"proximityEngagementRequested","bleUuid":{}}}"#,
            json_u8s(&[0x11; 16])
        ))
        .expect("engagement accepted");
    let fx = effects(&out);
    let engagement: Vec<u8> = find(&fx, "emitDeviceEngagement").expect("engagement")["engagement"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap() as u8)
        .collect();

    // Simulated reader builds an encrypted ItemsRequest + SessionEstablishment.
    let device_sec1 = cose_ec2_to_sec1(&device_key_from_engagement(&engagement).unwrap()).unwrap();
    let reader = P256AgreementKey::generate().unwrap();
    let reader_cose = sec1_to_cose_ec2(reader.public_raw()).unwrap();
    let z = reader.agree(&device_sec1).unwrap();
    let transcript = iso18013_5::session_transcript(&engagement, &reader_cose);
    let mut reader_cipher = SessionCipher::new(derive_session_keys(&AwsLc, &z, &transcript));
    let encrypted_request = reader_cipher
        .seal_from_reader(&AwsLc, &device_request(&["age_over_18"]))
        .unwrap();
    let establishment = Value::Map(vec![
        (
            Value::Text("eReaderKey".into()),
            Value::Tag(24, Box::new(Value::Bytes(reader_cose))),
        ),
        (Value::Text("data".into()), Value::Bytes(encrypted_request)),
    ])
    .to_canonical();

    // 2. Establishment over JSON → the consent render MUST carry an operationId + 32-byte hash.
    let out = core
        .handle_event_json(&format!(
            r#"{{"type":"proximityReaderEstablishment","sessionEstablishment":{}}}"#,
            json_u8s(&establishment)
        ))
        .expect("establishment accepted");
    let fx = effects(&out);
    let render = find(&fx, "render").expect("a consent render");
    assert_eq!(
        render["screen"]["screen"],
        serde_json::json!("proximityConsent"),
        "render carries the proximity consent screen (got {})",
        render["screen"]
    );
    let operation_id = render["operationId"]
        .as_u64()
        .expect("render has operationId");
    let auth_hash = render["authorizationHash"]
        .as_array()
        .expect("render has authorizationHash");
    assert_eq!(auth_hash.len(), 32, "32-byte WYSIWYS hash");
    let auth_hash_json =
        serde_json::to_string(&render["authorizationHash"]).expect("hash re-encodes");

    // 3. userConsented echoing the rendered operationId + hash is ACCEPTED and yields a Sign effect
    //    — proving the FFI boundary now admits in-person consent.
    let out = core
        .handle_event_json(&format!(
            r#"{{"type":"userConsented","operationId":{operation_id},"authorizationHash":{auth_hash_json}}}"#
        ))
        .expect("userConsented accepted over the FFI boundary");
    assert!(
        find(&effects(&out), "sign").is_some(),
        "consent triggers device-auth signing over the FFI"
    );

    // 4. A tampered authorization hash is rejected (WYSIWYS binding holds). Fresh core to avoid the
    //    consumed pending operation.
    let mut core2 = Core::new("wallet-client", "device-key");
    core2.handle_event(Event::SetClock {
        epoch: 1_790_000_000,
    });
    seed_mdl(&mut core2, &issuer, &device);
    let out = core2
        .handle_event_json(&format!(
            r#"{{"type":"proximityEngagementRequested","bleUuid":{}}}"#,
            json_u8s(&[0x11; 16])
        ))
        .unwrap();
    let engagement2: Vec<u8> = find(&effects(&out), "emitDeviceEngagement").unwrap()["engagement"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap() as u8)
        .collect();
    let device_sec1_2 =
        cose_ec2_to_sec1(&device_key_from_engagement(&engagement2).unwrap()).unwrap();
    let reader2 = P256AgreementKey::generate().unwrap();
    let reader_cose2 = sec1_to_cose_ec2(reader2.public_raw()).unwrap();
    let z2 = reader2.agree(&device_sec1_2).unwrap();
    let transcript2 = iso18013_5::session_transcript(&engagement2, &reader_cose2);
    let mut reader_cipher2 = SessionCipher::new(derive_session_keys(&AwsLc, &z2, &transcript2));
    let req2 = reader_cipher2
        .seal_from_reader(&AwsLc, &device_request(&["age_over_18"]))
        .unwrap();
    let est2 = Value::Map(vec![
        (
            Value::Text("eReaderKey".into()),
            Value::Tag(24, Box::new(Value::Bytes(reader_cose2))),
        ),
        (Value::Text("data".into()), Value::Bytes(req2)),
    ])
    .to_canonical();
    let out = core2
        .handle_event_json(&format!(
            r#"{{"type":"proximityReaderEstablishment","sessionEstablishment":{}}}"#,
            json_u8s(&est2)
        ))
        .unwrap();
    let oid2 = find(&effects(&out), "render").unwrap()["operationId"]
        .as_u64()
        .unwrap();
    let bad = core2.handle_event_json(&format!(
        r#"{{"type":"userConsented","operationId":{oid2},"authorizationHash":{}}}"#,
        json_u8s(&[0u8; 32])
    ));
    assert!(
        bad.is_err(),
        "a userConsented whose hash does not match the rendered screen is rejected"
    );
}
