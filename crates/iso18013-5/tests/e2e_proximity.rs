//! Real-crypto proximity e2e: the device signs the DeviceAuthentication over the SessionTranscript,
//! and a reader verifies it with aws-lc-rs. Tampering the transcript breaks the signature (anti-relay).
use crypto_backend::{AwsLc, SoftwareSigner};
use crypto_traits::{Alg, KeyRef, Signer, Verifier};
use iso18013_5::{device_auth_signing_input, step, Env, Input, Output, State};

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

    let s = step(&State::Idle, &Input::StartEngagement, &env).0;
    let s = step(
        &s,
        &Input::ReaderEstablishment(b"reader-hello".to_vec()),
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

    // Anti-relay: verifying against a DIFFERENT transcript fails.
    let other = device_auth_signing_input(b"different-transcript");
    assert!(AwsLc
        .verify(Alg::Es256, device.public_key_raw(), &other, &sig)
        .is_err());
}
