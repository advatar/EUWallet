//! iso18013-5 proximity transition tests (plan Section 5.3): happy path + every abort path.
use iso18013_5::{step, AbortReason, Env, Input, Output, State};

fn env<'a>() -> Env<'a> {
    Env {
        reader_key_on_curve: true,
        transcript_bound: true,
        reader_auth_present: false,
        reader_auth_valid: false,
        device_key_ref: "device-key",
    }
}

#[test]
fn happy_path_engagement_to_response() {
    let e = env();
    let (s, out) = step(&State::Idle, &Input::StartEngagement, &e);
    assert!(matches!(s, State::Engaged { .. }));
    assert!(matches!(out.as_slice(), [Output::EmitDeviceEngagement(_)]));

    let (s, out) = step(&s, &Input::ReaderEstablishment(vec![1, 2, 3]), &e);
    assert!(matches!(s, State::SessionEstablished { .. }));
    assert_eq!(out, vec![Output::RenderConsent]);

    let (s, out) = step(&s, &Input::ConsentGranted, &e);
    assert!(matches!(s, State::SigningResponse { .. }));
    assert!(matches!(out.as_slice(), [Output::SignDeviceAuth { .. }]));

    let (s, out) = step(&s, &Input::DeviceSignatureProduced(vec![0xAB; 64]), &e);
    assert_eq!(s, State::Responded);
    assert!(matches!(out.as_slice(), [Output::EmitDeviceResponse(_)]));
}

fn engaged() -> State {
    step(&State::Idle, &Input::StartEngagement, &env()).0
}

#[test]
fn abort_reader_key_invalid() {
    let e = Env {
        reader_key_on_curve: false,
        ..env()
    };
    let (s, _) = step(&engaged(), &Input::ReaderEstablishment(vec![1]), &e);
    assert_eq!(s, State::Aborted(AbortReason::ReaderKeyInvalid));
}

#[test]
fn abort_transcript_unbound() {
    let e = Env {
        transcript_bound: false,
        ..env()
    };
    let (s, _) = step(&engaged(), &Input::ReaderEstablishment(vec![1]), &e);
    assert_eq!(s, State::Aborted(AbortReason::SessionTranscriptUnbound));
}

#[test]
fn abort_reader_auth_invalid() {
    let e = Env {
        reader_auth_present: true,
        reader_auth_valid: false,
        ..env()
    };
    let (s, _) = step(&engaged(), &Input::ReaderEstablishment(vec![1]), &e);
    assert_eq!(s, State::Aborted(AbortReason::ReaderAuthInvalid));
}

#[test]
fn reader_auth_present_and_valid_is_accepted() {
    let e = Env {
        reader_auth_present: true,
        reader_auth_valid: true,
        ..env()
    };
    let (s, _) = step(&engaged(), &Input::ReaderEstablishment(vec![1]), &e);
    assert!(matches!(s, State::SessionEstablished { .. }));
}

#[test]
fn abort_request_out_of_order() {
    // Consent before a session is established.
    let (s, _) = step(&engaged(), &Input::ConsentGranted, &env());
    assert_eq!(s, State::Aborted(AbortReason::RequestOutOfOrder));
}

#[test]
fn abort_no_consent() {
    let e = env();
    let session = step(&engaged(), &Input::ReaderEstablishment(vec![1]), &e).0;
    let (s, out) = step(&session, &Input::ConsentDeclined, &e);
    assert_eq!(s, State::Aborted(AbortReason::NoConsent));
    assert_eq!(out, vec![Output::EmitTermination]);
}

#[test]
fn termination_from_any_state() {
    let (s, out) = step(&engaged(), &Input::ReaderTermination, &env());
    assert_eq!(s, State::Terminated);
    assert_eq!(out, vec![Output::EmitTermination]);
}
