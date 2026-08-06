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

use cose::cbor::{decode_value, Value};

/// Cipher suite 1 — the only suite ISO/IEC 18013-5 defines (ECDH P-256 + HKDF-SHA-256 + AES-256-GCM).
const CIPHER_SUITE: u64 = 1;
/// BLE device-retrieval method type (18013-5 Table 12).
const RETRIEVAL_METHOD_BLE: u64 = 2;
/// Default mdoc doctype for the DeviceAuthentication.
const DOC_TYPE_MDL: &str = "org.iso.18013.5.1.mDL";

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
    /// Begin: the shell supplies the device ephemeral public key (a COSE_Key, CBOR-encoded) and the
    /// BLE service UUID to advertise (peripheral-server mode); it then transmits the engagement over
    /// QR/NFC/BLE.
    StartEngagement {
        device_key_cose: Vec<u8>,
        ble_uuid: [u8; 16],
    },
    /// The reader's SessionEstablishment. The shell parses it and hands us the reader ephemeral key
    /// (a COSE_Key, CBOR-encoded); the encrypted request stays opaque to this sans-IO core.
    ReaderEstablishment {
        e_reader_key_cose: Vec<u8>,
    },
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
        // HLR-ISO-T-001 — begin: build engagement (holds our ephemeral pubkey + BLE UUID) & emit it.
        (
            State::Idle,
            Input::StartEngagement {
                device_key_cose,
                ble_uuid,
            },
        ) => {
            let de = build_device_engagement(device_key_cose, ble_uuid);
            (
                State::Engaged {
                    device_engagement: de.clone(),
                },
                vec![Output::EmitDeviceEngagement(de)],
            )
        }

        // HLR-ISO-T-002 — reader replied: validate its key, bind the transcript, derive keys.
        (
            State::Engaged { device_engagement },
            Input::ReaderEstablishment { e_reader_key_cose },
        ) => {
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
            let session_transcript = session_transcript(device_engagement, e_reader_key_cose);
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

/// Build the real ISO/IEC 18013-5 §8.2.1.1 `DeviceEngagement` for BLE peripheral-server mode.
///
/// ```text
/// DeviceEngagement = {
///   0: "1.0",                                      ; version
///   1: Security,                                   ; [cipherSuite, DeviceKeyBytes]
///   2: DeviceRetrievalMethods                      ; [ BleRetrievalMethod ]
/// }
/// Security             = [ 1, #6.24(bstr .cbor COSE_Key) ]     ; suite 1, DeviceKeyBytes
/// BleRetrievalMethod   = [ 2, 1, { 0: true, 11: bstr } ]       ; type BLE, ver 1, peripheral-server UUID
/// ```
///
/// `device_key_cose` is the device ephemeral public key already encoded as a COSE_Key; `ble_uuid`
/// is the 16-byte service UUID the peripheral advertises. The returned bytes are what the shell
/// broadcasts (QR / NFC / BLE) and what the SessionTranscript binds as `DeviceEngagementBytes`.
fn build_device_engagement(device_key_cose: &[u8], ble_uuid: &[u8; 16]) -> Vec<u8> {
    // DeviceKeyBytes = #6.24(bstr .cbor COSE_Key)
    let device_key_bytes = Value::Tag(24, Box::new(Value::Bytes(device_key_cose.to_vec())));
    let security = Value::Array(vec![Value::Uint(CIPHER_SUITE), device_key_bytes]);

    // BLE peripheral-server-mode retrieval options (18013-5 Table 13):
    //   0  => peripheral server mode supported (bool)
    //   11 => service UUID for peripheral server mode (bstr)
    let ble_options = Value::Map(vec![
        (Value::Uint(0), Value::Bool(true)),
        (Value::Uint(11), Value::Bytes(ble_uuid.to_vec())),
    ]);
    let ble_method = Value::Array(vec![
        Value::Uint(RETRIEVAL_METHOD_BLE),
        Value::Uint(1),
        ble_options,
    ]);

    Value::Map(vec![
        (Value::Uint(0), Value::Text("1.0".into())),
        (Value::Uint(1), security),
        (Value::Uint(2), Value::Array(vec![ble_method])),
    ])
    .to_canonical()
}

/// Build the real ISO/IEC 18013-5 §9.1.5.1 `SessionTranscript` — the anti-relay binding both sides
/// sign and verify against:
///
/// ```text
/// SessionTranscript = [ DeviceEngagementBytes, EReaderKeyBytes, Handover ]
/// DeviceEngagementBytes = #6.24(bstr .cbor DeviceEngagement)
/// EReaderKeyBytes       = #6.24(bstr .cbor COSE_Key)
/// Handover              = null                       ; QR / NFC engagement
/// ```
///
/// `device_engagement` is the exact bytes emitted by [`build_device_engagement`]; `e_reader_key_cose`
/// is the reader's ephemeral public key (COSE_Key) the shell extracted from SessionEstablishment.
pub fn session_transcript(device_engagement: &[u8], e_reader_key_cose: &[u8]) -> Vec<u8> {
    Value::Array(vec![
        Value::Tag(24, Box::new(Value::Bytes(device_engagement.to_vec()))),
        Value::Tag(24, Box::new(Value::Bytes(e_reader_key_cose.to_vec()))),
        Value::Null,
    ])
    .to_canonical()
}

/// Build the real ISO/IEC 18013-5 §9.1.3.4 `DeviceAuthenticationBytes` the device key signs:
///
/// ```text
/// DeviceAuthentication      = [ "DeviceAuthentication", SessionTranscript, DocType, DeviceNameSpacesBytes ]
/// DeviceAuthenticationBytes = #6.24(bstr .cbor DeviceAuthentication)
/// ```
///
/// The anti-relay binding lives in the embedded `SessionTranscript`; `DeviceNameSpacesBytes` is the
/// empty map here (the mdoc namespaces the reader requested are assembled by the mdoc layer).
pub fn device_auth_signing_input(session_transcript: &[u8]) -> Vec<u8> {
    // The transcript is already canonical CBOR; embed it as a parsed item so DeviceAuthentication is
    // a single well-formed CBOR value (not a nested bstr).
    let transcript = decode_value(session_transcript, 0)
        .map(|(v, _)| v)
        .unwrap_or(Value::Null);
    let device_namespaces_bytes = Value::Tag(
        24,
        Box::new(Value::Bytes(Value::Map(vec![]).to_canonical())),
    );
    let device_authentication = Value::Array(vec![
        Value::Text("DeviceAuthentication".into()),
        transcript,
        Value::Text(DOC_TYPE_MDL.into()),
        device_namespaces_bytes,
    ]);
    Value::Tag(
        24,
        Box::new(Value::Bytes(device_authentication.to_canonical())),
    )
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

/// Reference model that MIRRORS the Lean Tier-2 model (formal/lean/ProximityModel.lean).
///
/// The Lean model proves the consent / session-binding / ordering invariants and emits
/// conformance traces; this module is the Rust side those traces replay against (plan Section 10).
/// The production `step` above must refine it. `tests/conformance.rs` checks they agree.
pub mod model {
    #[derive(Clone, PartialEq, Eq, Debug)]
    pub enum St {
        Idle,
        Engaged,
        SessionEstablished,
        SigningResponse,
        Responded,
        Aborted,
        Terminated,
    }

    #[derive(Clone, Debug)]
    pub enum Ev {
        StartEngagement,
        ReaderEstablish(bool), // valid ⇔ reader key + auth ok AND transcript binds
        ConsentGrant,
        ConsentDecline,
        DeviceSign,
        Terminate,
    }

    #[derive(Clone, Debug)]
    pub struct Ctx {
        pub st: St,
        pub session_bound: bool,
        pub consented: bool,
    }

    impl Ctx {
        pub fn init() -> Self {
            Ctx {
                st: St::Idle,
                session_bound: false,
                consented: false,
            }
        }
    }

    /// Transition function — the exact analogue of `ProximityModel.step` in Lean.
    pub fn step(mut c: Ctx, ev: &Ev) -> Ctx {
        match ev {
            Ev::StartEngagement => {
                if c.st == St::Idle {
                    c.st = St::Engaged;
                }
            }
            Ev::ReaderEstablish(valid) => {
                if c.st == St::Engaged {
                    if *valid {
                        c.st = St::SessionEstablished;
                        c.session_bound = true;
                    } else {
                        c.st = St::Aborted; // guard: reader/transcript invalid
                    }
                }
            }
            Ev::ConsentGrant => match c.st {
                St::SessionEstablished => {
                    c.st = St::SigningResponse;
                    c.consented = true;
                }
                St::Engaged => c.st = St::Aborted, // guard: RequestOutOfOrder
                _ => {}
            },
            Ev::ConsentDecline => {
                if c.st == St::SessionEstablished {
                    c.st = St::Aborted; // guard: NoConsent
                }
            }
            Ev::DeviceSign => {
                if c.st == St::SigningResponse {
                    c.st = St::Responded;
                }
            }
            Ev::Terminate => c.st = St::Terminated,
        }
        c
    }

    pub fn run(evs: &[Ev]) -> Ctx {
        evs.iter().fold(Ctx::init(), step)
    }

    /// Stable state string, matching the Lean exporter's `stJson`.
    pub fn state_name(st: &St) -> &'static str {
        match st {
            St::Idle => "idle",
            St::Engaged => "engaged",
            St::SessionEstablished => "sessionEstablished",
            St::SigningResponse => "signingResponse",
            St::Responded => "responded",
            St::Aborted => "aborted",
            St::Terminated => "terminated",
        }
    }
}

/// Structural tests for the real ISO/IEC 18013-5 engagement / transcript / device-auth CBOR.
#[cfg(test)]
mod engagement_tests {
    use super::{build_device_engagement, device_auth_signing_input, session_transcript};
    use cose::cbor::{decode_value, Value};

    /// A stand-in for the device/reader ephemeral COSE_Key — its content is opaque to these
    /// structural checks (the real COSE_Key is encoded by the crypto layer). We only need
    /// deterministic, distinguishable bytes.
    fn dummy_cose_key(tag: u8) -> Vec<u8> {
        Value::Map(vec![
            (Value::Uint(1), Value::Uint(2)), // kty: EC2
            (Value::Uint(2), Value::Bytes(vec![tag; 32])),
        ])
        .to_canonical()
    }

    #[test]
    fn device_engagement_is_real_18013_5() {
        let uuid = [0x11u8; 16];
        let de = build_device_engagement(&dummy_cose_key(0xAB), &uuid);
        let (v, rest) = decode_value(&de, 0).expect("DeviceEngagement decodes");
        assert!(rest.is_empty(), "no trailing bytes");
        let map = match v {
            Value::Map(m) => m,
            other => panic!("DeviceEngagement must be a map, got {other:?}"),
        };
        // 0 => "1.0"
        assert!(
            map.iter()
                .any(|(k, val)| *k == Value::Uint(0) && *val == Value::Text("1.0".into())),
            "version 1.0 present"
        );
        // 1 => Security = [1 (cipher suite), DeviceKeyBytes = #6.24(bstr)]
        let security = map
            .iter()
            .find(|(k, _)| *k == Value::Uint(1))
            .map(|(_, v)| v)
            .expect("Security element");
        match security {
            Value::Array(items) => {
                assert_eq!(items.len(), 2);
                assert_eq!(items[0], Value::Uint(1), "cipher suite 1");
                assert!(
                    matches!(items[1], Value::Tag(24, _)),
                    "DeviceKeyBytes is #6.24 tagged"
                );
            }
            other => panic!("Security must be an array, got {other:?}"),
        }
        // 2 => DeviceRetrievalMethods = [[2 (BLE), 1, {..uuid..}]]
        let methods = map
            .iter()
            .find(|(k, _)| *k == Value::Uint(2))
            .map(|(_, v)| v)
            .expect("DeviceRetrievalMethods");
        match methods {
            Value::Array(list) => {
                let first = &list[0];
                match first {
                    Value::Array(m) => {
                        assert_eq!(m[0], Value::Uint(2), "BLE retrieval method type")
                    }
                    other => panic!("retrieval method must be an array, got {other:?}"),
                }
            }
            other => panic!("DeviceRetrievalMethods must be an array, got {other:?}"),
        }
        // The advertised UUID must appear verbatim in the bytes.
        assert!(
            de.windows(16).any(|w| w == uuid),
            "advertised BLE UUID embedded in engagement"
        );
    }

    #[test]
    fn session_transcript_is_three_element_with_null_handover() {
        let de = build_device_engagement(&dummy_cose_key(0x01), &[0x22u8; 16]);
        let ereader = dummy_cose_key(0x02);
        let st = session_transcript(&de, &ereader);
        let (v, rest) = decode_value(&st, 0).expect("SessionTranscript decodes");
        assert!(rest.is_empty());
        match v {
            Value::Array(items) => {
                assert_eq!(
                    items.len(),
                    3,
                    "DeviceEngagementBytes, EReaderKeyBytes, Handover"
                );
                assert!(
                    matches!(items[0], Value::Tag(24, _)),
                    "DeviceEngagementBytes #6.24"
                );
                assert!(
                    matches!(items[1], Value::Tag(24, _)),
                    "EReaderKeyBytes #6.24"
                );
                assert_eq!(items[2], Value::Null, "QR/NFC handover is null");
            }
            other => panic!("SessionTranscript must be a 3-element array, got {other:?}"),
        }
    }

    #[test]
    fn device_auth_binds_the_transcript() {
        let de = build_device_engagement(&dummy_cose_key(0x03), &[0x33u8; 16]);
        let st = session_transcript(&de, &dummy_cose_key(0x04));
        let signing_input = device_auth_signing_input(&st);
        // DeviceAuthenticationBytes = #6.24(bstr .cbor DeviceAuthentication)
        let (v, rest) = decode_value(&signing_input, 0).expect("DeviceAuthenticationBytes decodes");
        assert!(rest.is_empty());
        let inner = match v {
            Value::Tag(24, inner) => match *inner {
                Value::Bytes(b) => b,
                other => panic!("#6.24 wraps a bstr, got {other:?}"),
            },
            other => panic!("DeviceAuthenticationBytes must be #6.24, got {other:?}"),
        };
        let (auth, _) = decode_value(&inner, 0).expect("DeviceAuthentication decodes");
        match auth {
            Value::Array(items) => {
                assert_eq!(items.len(), 4);
                assert_eq!(items[0], Value::Text("DeviceAuthentication".into()));
                assert_eq!(items[2], Value::Text("org.iso.18013.5.1.mDL".into()));
            }
            other => panic!("DeviceAuthentication must be a 4-element array, got {other:?}"),
        }
        // Anti-relay: a different transcript yields different signing bytes.
        let other = session_transcript(&de, &dummy_cose_key(0x99));
        assert_ne!(
            device_auth_signing_input(&other),
            signing_input,
            "signing input must be bound to the exact transcript"
        );
    }
}
