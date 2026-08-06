//! End-to-end in-person (ISO/IEC 18013-5) proximity presentation driven entirely through the
//! wallet-core `Event`/`Effect` facade, with a **simulated reader** completing the crypto half.
//!
//! This exercises the full B3a wiring without a physical reader: engagement → establishment (real
//! ECDH + HKDF key derivation) → consent → device signature → an AES-256-GCM-encrypted SessionData
//! response that the simulated reader decrypts. The DeviceResponse *content* the core wraps is still
//! the placeholder from the sans-IO core (real mdoc assembly from holdings is the remaining B3
//! step); what this proves end-to-end is the driver + the SessionData session encryption.

use cose::cbor::Value;
use crypto_backend::{AwsLc, P256AgreementKey};
use wallet_core::proximity_session::{
    cose_ec2_to_sec1, derive_session_keys, device_key_from_engagement, parse_session_data,
    sec1_to_cose_ec2, SessionCipher,
};
use wallet_core::{Core, Effect, Event};

fn find_engagement(effects: &[Effect]) -> Option<Vec<u8>> {
    effects.iter().find_map(|e| match e {
        Effect::EmitDeviceEngagement { engagement } => Some(engagement.clone()),
        _ => None,
    })
}

fn find_device_response(effects: &[Effect]) -> Option<Vec<u8>> {
    effects.iter().find_map(|e| match e {
        Effect::EmitDeviceResponse { response } => Some(response.clone()),
        _ => None,
    })
}

#[test]
fn in_person_presentation_drives_the_machine_and_encrypts_the_response() {
    let mut core = Core::new("wallet-client", "device-key");

    // 1. The shell asks to present in person, supplying the BLE service UUID it will advertise.
    let effects = core.handle_event(Event::ProximityEngagementRequested {
        ble_uuid: vec![0x11; 16],
    });
    let engagement = find_engagement(&effects).expect("DeviceEngagement is emitted");

    // ---- Simulated reader: scan the engagement, pull the device key, make its own ephemeral key.
    let device_cose = device_key_from_engagement(&engagement).expect("device key in engagement");
    let device_sec1 = cose_ec2_to_sec1(&device_cose).expect("device COSE_Key → SEC1");
    let reader = P256AgreementKey::generate().unwrap();
    let reader_cose = sec1_to_cose_ec2(reader.public_raw()).unwrap();

    // 2. The reader's SessionEstablishment = { eReaderKey: #6.24(bstr COSE_Key), data: bstr }.
    let establishment = Value::Map(vec![
        (
            Value::Text("eReaderKey".into()),
            Value::Tag(24, Box::new(Value::Bytes(reader_cose.clone()))),
        ),
        (
            Value::Text("data".into()),
            Value::Bytes(b"encrypted-itemsrequest-placeholder".to_vec()),
        ),
    ])
    .to_canonical();
    let effects = core.handle_event(Event::ProximityReaderEstablishment {
        session_establishment: establishment,
    });
    assert!(
        effects.iter().any(|e| matches!(e, Effect::Render { .. })),
        "establishing the session renders a consent prompt"
    );

    // 3. The holder approves → the core asks the Secure Enclave to sign DeviceAuthentication.
    let effects = core.handle_event(Event::UserConsented);
    assert!(
        effects.iter().any(|e| matches!(e, Effect::Sign { .. })),
        "consent triggers a device-auth signing request"
    );

    // 4. The enclave returns a signature (opaque to the machine) → encrypted SessionData response.
    let effects = core.handle_event(Event::DeviceSignatureProduced {
        signature: vec![0xAB; 64],
    });
    let response = find_device_response(&effects).expect("an encrypted DeviceResponse is emitted");

    // ---- Simulated reader decrypts: same ECDH Z, same transcript, same derived SKDevice.
    let z = reader.agree(&device_sec1).unwrap();
    let transcript = iso18013_5::session_transcript(&engagement, &reader_cose);
    let keys = derive_session_keys(&AwsLc, &z, &transcript);
    let mut reader_cipher = SessionCipher::new(keys);
    let ciphertext = parse_session_data(&response).expect("SessionData carries a data field");
    let plaintext = reader_cipher
        .open_from_device(&AwsLc, &ciphertext)
        .expect("the reader decrypts the wallet's SessionData with SKDevice");
    assert!(
        !plaintext.is_empty(),
        "the decrypted DeviceResponse is non-empty"
    );

    // The SessionData is genuinely encrypted (not the plaintext response) and authenticated (a
    // tampered byte fails the GCM tag under a fresh cipher at the same counter).
    assert_ne!(ciphertext, plaintext);
    let mut tampered = ciphertext.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    let mut fresh_reader = SessionCipher::new(derive_session_keys(&AwsLc, &z, &transcript));
    assert!(
        fresh_reader.open_from_device(&AwsLc, &tampered).is_err(),
        "a tampered SessionData ciphertext is rejected"
    );
}

#[test]
fn declining_in_person_consent_closes_the_session() {
    let mut core = Core::new("wallet-client", "device-key");
    core.handle_event(Event::ProximityEngagementRequested {
        ble_uuid: vec![0x22; 16],
    });
    let reader = P256AgreementKey::generate().unwrap();
    let reader_cose = sec1_to_cose_ec2(reader.public_raw()).unwrap();
    let establishment = Value::Map(vec![
        (
            Value::Text("eReaderKey".into()),
            Value::Tag(24, Box::new(Value::Bytes(reader_cose))),
        ),
        (Value::Text("data".into()), Value::Bytes(b"x".to_vec())),
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
