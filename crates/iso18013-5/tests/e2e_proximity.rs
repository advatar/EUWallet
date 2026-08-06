//! Real-crypto proximity e2e: the device signs the DeviceAuthentication over the SessionTranscript,
//! and a reader verifies it with aws-lc-rs. Tampering the transcript breaks the signature (anti-relay).
use crypto_backend::{AwsLc, SoftwareSigner};
use crypto_traits::{Alg, KeyRef, Signer, Verifier};
use iso18013_5::{device_auth_signing_input, session_transcript, step, Env, Input, Output, State};

#[test]
fn device_response_is_signed_over_the_session_transcript() {
    let device = SoftwareSigner::generate_p256().unwrap();
    let env = Env {
        reader_key_on_curve: true,
        transcript_bound: true,
        reader_auth_present: false,
        reader_auth_valid: false,
        device_key_ref: "device-key",
    };

    let s = step(
        &State::Idle,
        &Input::StartEngagement {
            device_key_cose: vec![0xA1, 0x01, 0x02],
            ble_uuid: [0x11; 16],
        },
        &env,
    )
    .0;
    let s = step(
        &s,
        &Input::ReaderEstablishment {
            e_reader_key_cose: b"reader-hello".to_vec(),
        },
        &env,
    )
    .0;
    // Capture the bound transcript from the session state.
    let transcript = match &s {
        State::SessionEstablished { session_transcript } => session_transcript.clone(),
        other => panic!("expected SessionEstablished, got {other:?}"),
    };

    let (s, out) = step(&s, &Input::ConsentGranted, &env);
    let signing_input = match out.as_slice() {
        [Output::SignDeviceAuth { signing_input, .. }] => signing_input.clone(),
        other => panic!("expected SignDeviceAuth, got {other:?}"),
    };
    assert_eq!(signing_input, device_auth_signing_input(&transcript));

    // Device signs; reader verifies with real crypto.
    let sig = device
        .sign(&KeyRef("device-key".into()), Alg::Es256, &signing_input)
        .unwrap();
    let (s, _out) = step(&s, &Input::DeviceSignatureProduced(sig.clone()), &env);
    assert_eq!(s, State::Responded);
    assert!(AwsLc
        .verify(
            Alg::Es256,
            device.public_key_raw(),
            &device_auth_signing_input(&transcript),
            &sig
        )
        .is_ok());

    // Anti-relay: verifying against a DIFFERENT (but well-formed) transcript fails — a relayed
    // signature can't be replayed into another session's transcript.
    let relayed = session_transcript(b"other-engagement", b"other-reader-key");
    let other = device_auth_signing_input(&relayed);
    assert_ne!(other, device_auth_signing_input(&transcript));
    assert!(AwsLc
        .verify(Alg::Es256, device.public_key_raw(), &other, &sig)
        .is_err());
}
