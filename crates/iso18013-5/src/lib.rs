#![forbid(unsafe_code)]
//! `iso18013-5` — ISO/IEC 18013-5 proximity presentation, as a sans-IO state machine.
//!
//! See docs/IMPLEMENTATION_PLAN.md Section 5.3.
//!
//! In-person mdoc presentation over BLE/NFC/QR. Three phases: **device engagement** (the wallet
//! emits an engagement structure the reader scans), **session establishment** (the reader replies;
//! the wallet binds a `SessionTranscript` over the engagement + reader key — the anti-relay
//! binding), and **device response** (after consent, a device-signed mdoc response). All transport
//! framing (BLE/NFC/QR) is the shell's job — this machine only consumes/produces opaque bytes, and
//! the device signature over the `DeviceAuthentication` is a `SignDeviceAuth` effect so the private
//! key never crosses the FFI. Every state/transition/guard carries an `HLR-ISO-*` id.

use cose::cbor::Value;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum State {
    /// HLR-ISO-S-001 — idle.
    Idle,
    /// HLR-ISO-S-002 — engagement emitted; awaiting the reader. Holds the engagement bytes.
    Engaged { device_engagement: Vec<u8> },
    /// HLR-ISO-S-003 — session keys derived and the SessionTranscript bound; awaiting consent.
    SessionEstablished { session_transcript: Vec<u8> },
    /// HLR-ISO-S-004 — consent granted; the device is signing the DeviceAuthentication.
    SigningResponse { session_transcript: Vec<u8> },
    /// HLR-ISO-S-005 — device response emitted (terminal).
    Responded,
    /// HLR-ISO-S-006 — session torn down (terminal).
    Terminated,
    /// HLR-ISO-S-007 — aborted (terminal).
    Aborted(AbortReason),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbortReason {
    /// HLR-ISO-G-001 — session_transcript_is_bound failed (relay / unbound transcript).
    SessionTranscriptUnbound,
    /// HLR-ISO-G-002 — reader_ephemeral_key_valid failed (bad point / identity element).
    ReaderKeyInvalid,
    /// HLR-ISO-G-003 — a request/response was attempted before the session existed.
    RequestOutOfOrder,
    /// HLR-ISO-G-004 — the user declined (no response without consent).
    NoConsent,
    /// HLR-ISO-G-005 — reader_auth was present but invalid.
    ReaderAuthInvalid,
}

#[derive(Clone, Debug)]
pub enum Input {
    /// Begin: the shell will transmit the engagement over QR/NFC/BLE.
    StartEngagement,
    /// Opaque SessionEstablishment message from the reader (eReaderKey + encrypted request).
    ReaderEstablishment(Vec<u8>),
    ConsentGranted,
    ConsentDeclined,
    /// The device produced the DeviceAuthentication signature.
    DeviceSignatureProduced(Vec<u8>),
    ReaderTermination,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Output {
    /// Hand the shell the engagement bytes to broadcast (QR / NFC / BLE).
    EmitDeviceEngagement(Vec<u8>),
    RenderConsent,
    /// Sign the DeviceAuthentication with the device key (Secure Enclave / StrongBox in the shell).
    SignDeviceAuth {
        key_ref: String,
        signing_input: Vec<u8>,
    },
    /// Hand the shell the encrypted device response to transmit.
    EmitDeviceResponse(Vec<u8>),
    EmitTermination,
}

/// Facts the shell resolves (from the reader's message + our engagement) via the crypto boundary.
pub struct Env<'a> {
    /// The reader's ephemeral key is a valid curve point (not identity) — blocks invalid-curve
    /// attacks on the ECDH.
    pub reader_key_on_curve: bool,
    /// The SessionTranscript binds engagement + eReaderKey + handover (anti-relay / anti-MITM).
    pub transcript_bound: bool,
    /// Whether ReaderAuth was present, and if so whether it verified.
    pub reader_auth_present: bool,
    pub reader_auth_valid: bool,
    /// The device key the shell signs the DeviceAuthentication with.
    pub device_key_ref: &'a str,
}

pub mod guards {
    use super::Env;

    /// HLR-ISO-G-001 — the SessionTranscript binds this exchange (anti-relay).
    pub fn session_transcript_is_bound(env: &Env) -> bool {
        env.transcript_bound
    }

    /// HLR-ISO-G-002 — the reader's ephemeral key is a valid curve point.
    pub fn reader_ephemeral_key_valid(env: &Env) -> bool {
        env.reader_key_on_curve
    }

    /// HLR-ISO-G-005 — reader authentication: absent is allowed (18013-5 makes it optional), but a
    /// PRESENT-but-invalid ReaderAuth aborts.
    pub fn reader_auth_valid(env: &Env) -> bool {
        !env.reader_auth_present || env.reader_auth_valid
    }
}

/// Pure transition function — exhaustive match.
pub fn step(state: &State, input: &Input, env: &Env) -> (State, Vec<Output>) {
    match (state, input) {
        // HLR-ISO-T-001 — begin: build engagement (holds our ephemeral pubkey) & emit it.
        (State::Idle, Input::StartEngagement) => {
            let de = build_device_engagement();
            (
                State::Engaged {
                    device_engagement: de.clone(),
                },
                vec![Output::EmitDeviceEngagement(de)],
            )
        }

        // HLR-ISO-T-002 — reader replied: validate its key, bind the transcript, derive keys.
        (State::Engaged { device_engagement }, Input::ReaderEstablishment(reader_msg)) => {
            if !guards::reader_ephemeral_key_valid(env) {
                return (State::Aborted(AbortReason::ReaderKeyInvalid), vec![]);
            }
            if !guards::session_transcript_is_bound(env) {
                return (
                    State::Aborted(AbortReason::SessionTranscriptUnbound),
                    vec![],
                );
            }
            if !guards::reader_auth_valid(env) {
                return (State::Aborted(AbortReason::ReaderAuthInvalid), vec![]);
            }
            let session_transcript = session_transcript(device_engagement, reader_msg);
            (
                State::SessionEstablished { session_transcript },
                vec![Output::RenderConsent],
            )
        }

        // HLR-ISO-T-003 — consent → ask the device to sign the DeviceAuthentication.
        (State::SessionEstablished { session_transcript }, Input::ConsentGranted) => {
            let signing_input = device_auth_signing_input(session_transcript);
            (
                State::SigningResponse {
                    session_transcript: session_transcript.clone(),
                },
                vec![Output::SignDeviceAuth {
                    key_ref: env.device_key_ref.to_string(),
                    signing_input,
                }],
            )
        }
        // HLR-ISO-T-004 — refusal before any data leaves.
        (State::SessionEstablished { .. }, Input::ConsentDeclined) => (
            State::Aborted(AbortReason::NoConsent),
            vec![Output::EmitTermination],
        ),

        // HLR-ISO-T-005 — device signature ready → assemble & emit the encrypted device response.
        (State::SigningResponse { session_transcript }, Input::DeviceSignatureProduced(sig)) => {
            let response = assemble_device_response(session_transcript, sig);
            (State::Responded, vec![Output::EmitDeviceResponse(response)])
        }

        // HLR-ISO-T-006 — a request/response attempt before the session exists is rejected.
        (State::Engaged { .. }, Input::ConsentGranted) => {
            (State::Aborted(AbortReason::RequestOutOfOrder), vec![])
        }

        // HLR-ISO-T-007 — clean teardown from any state.
        (_, Input::ReaderTermination) => (State::Terminated, vec![Output::EmitTermination]),

        // HLR-ISO-T-999 — defensive no-op keeps the match exhaustive.
        (s, _) => (s.clone(), vec![]),
    }
}

/// The device engagement structure (holds our ephemeral public key + transport hints). Skeleton
/// deterministic bytes; the full 18013-5 DeviceEngagement is built here in production.
fn build_device_engagement() -> Vec<u8> {
    Value::Array(vec![Value::Text("DeviceEngagement".into()), Value::Uint(1)]).to_canonical()
}

/// The SessionTranscript binds our engagement to the reader's message (anti-relay). Deterministic
/// canonical CBOR over both.
pub fn session_transcript(device_engagement: &[u8], reader_msg: &[u8]) -> Vec<u8> {
    Value::Array(vec![
        Value::Bytes(device_engagement.to_vec()),
        Value::Bytes(reader_msg.to_vec()),
    ])
    .to_canonical()
}

/// The DeviceAuthentication bytes the device key signs (18013-5 §9.1.3), over the transcript.
pub fn device_auth_signing_input(session_transcript: &[u8]) -> Vec<u8> {
    Value::Array(vec![
        Value::Text("DeviceAuthentication".into()),
        Value::Bytes(session_transcript.to_vec()),
    ])
    .to_canonical()
}

/// Assemble the (canonical) device response carrying the transcript binding + device signature.
fn assemble_device_response(session_transcript: &[u8], signature: &[u8]) -> Vec<u8> {
    Value::Array(vec![
        Value::Text("DeviceResponse".into()),
        Value::Bytes(session_transcript.to_vec()),
        Value::Bytes(signature.to_vec()),
    ])
    .to_canonical()
}
