#![forbid(unsafe_code)]
//! `qes` — the qualified/advanced electronic signature authorization flow (P1 / QES).
//!
//! When a holder signs a document with a (Q)TSP-hosted key, the security property that matters is
//! **what-you-see-is-what-you-sign**: the authorization the device produces must be bound to the
//! exact document AND the exact confirmation screen the user approved. This crate is the sans-IO
//! state machine for that; the remote QTSP/QSCD interaction (CSC API) is the shell's I/O.
//!
//! The binding reuses the same `consent_hash` mechanism as the presenter (plan §7.9): the shell
//! passes the hash of the fully-resolved sign-confirmation screen in [`Env`], and the DTBS/R the
//! device signs commits to it together with the document hash. So a signature can never be
//! obtained over a document or terms the user did not actually see.

use cose::cbor::Value;

/// The document-to-be-signed request (parsed from the shell's opaque bytes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignRequest {
    pub document_name: String,
    /// Hash of the document to be signed (the DTBS).
    pub document_hash: Vec<u8>,
    /// The (Q)TSP that will complete the signature with the holder's remote key.
    pub qtsp_id: String,
    pub nonce: u64,
}

/// Captured when the user authorizes: the request plus the consent hash of what they saw.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingAuthorization {
    pub request: SignRequest,
    pub consent_hash: [u8; 32],
}

/// The machine state (payload-carrying).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QesState {
    /// QES-S-001 — idle.
    Idle,
    /// QES-S-002 — showing the sign confirmation (document name + QTSP + document hash).
    AwaitingAuthorization(Box<SignRequest>),
    /// QES-S-003 — user authorized; the device is signing the DTBS/R (SCA).
    AwaitingSca(Box<PendingAuthorization>),
    /// QES-S-004 — the signed authorization was produced (terminal).
    Signed { authorization: Vec<u8> },
    /// QES-S-005 — aborted (terminal).
    Aborted(AbortReason),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbortReason {
    /// QES-G-001 — the request could not be parsed.
    MalformedRequest,
    /// QES-G-002 — the document hash was missing/empty.
    DocumentHashMissing,
    /// QES-G-003 — nonce already used (replay).
    NonceReplayed,
    /// QES-G-004 — the user declined to sign.
    UserDeclined,
}

#[derive(Clone, Debug)]
pub enum Input {
    /// A document-signing request arrived (JSON, see `parse_request`).
    SignatureRequest(Vec<u8>),
    /// The user approved the sign-confirmation screen.
    UserAuthorized,
    /// The user declined.
    UserDeclined,
    /// The device produced the SCA signature over the DTBS/R authorization binding.
    AuthorizationSignatureProduced(Vec<u8>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Output {
    /// Render the sign-confirmation screen — what the user is authorising to sign (WYSIWYS).
    RenderSignConfirmation {
        document_name: String,
        qtsp_id: String,
        document_hash: Vec<u8>,
    },
    /// Sign the DTBS/R authorization binding with the device key (biometric-gated Secure Enclave).
    SignAuthorization {
        key_ref: String,
        signing_input: Vec<u8>,
    },
    /// Send the signed authorization to the remote QTSP/QSCD (CSC API) to complete the signature.
    SendToQtsp(Vec<u8>),
    Close,
}

/// Pure facts the machine reads. `consent_hash` is the hash of the sign-confirmation screen the
/// shell rendered — the WYSIWYS anchor the authorization binds to.
pub struct Env<'a> {
    pub seen_nonces: &'a [u64],
    pub device_key_ref: &'a str,
    pub consent_hash: [u8; 32],
}

/// Compute the DTBS/R (data-to-be-signed / representation) authorization binding: a canonical CBOR
/// array over a domain tag and the fields the qualified signature must be specific to — the
/// document hash, the consent hash of what the user saw, the QTSP, and the nonce. Deterministic,
/// so the QTSP derives identical bytes when it verifies the authorization.
pub fn qes_authorization_binding(req: &SignRequest, consent_hash: &[u8; 32]) -> Vec<u8> {
    Value::Array(vec![
        Value::Text("eudi-qes-authorization-v1".into()),
        Value::Bytes(req.document_hash.clone()),
        Value::Bytes(consent_hash.to_vec()),
        Value::Text(req.qtsp_id.clone()),
        Value::Uint(req.nonce),
    ])
    .to_canonical()
}

/// Pure transition function — exhaustive match.
pub fn step(state: &QesState, input: &Input, env: &Env) -> (QesState, Vec<Output>) {
    match (state, input) {
        (QesState::Idle, Input::SignatureRequest(bytes)) => match parse_request(bytes) {
            Ok(req) => {
                if req.document_hash.is_empty() {
                    return (QesState::Aborted(AbortReason::DocumentHashMissing), vec![]);
                }
                if env.seen_nonces.contains(&req.nonce) {
                    return (QesState::Aborted(AbortReason::NonceReplayed), vec![]);
                }
                let out = Output::RenderSignConfirmation {
                    document_name: req.document_name.clone(),
                    qtsp_id: req.qtsp_id.clone(),
                    document_hash: req.document_hash.clone(),
                };
                (QesState::AwaitingAuthorization(Box::new(req)), vec![out])
            }
            Err(()) => (QesState::Aborted(AbortReason::MalformedRequest), vec![]),
        },

        (QesState::AwaitingAuthorization(req), Input::UserAuthorized) => {
            let signing_input = qes_authorization_binding(req, &env.consent_hash);
            (
                QesState::AwaitingSca(Box::new(PendingAuthorization {
                    request: (**req).clone(),
                    consent_hash: env.consent_hash,
                })),
                vec![Output::SignAuthorization {
                    key_ref: env.device_key_ref.to_string(),
                    signing_input,
                }],
            )
        }

        (QesState::AwaitingAuthorization(_), Input::UserDeclined) => {
            (QesState::Aborted(AbortReason::UserDeclined), vec![])
        }

        (QesState::AwaitingSca(_), Input::AuthorizationSignatureProduced(sig)) => (
            QesState::Signed {
                authorization: sig.clone(),
            },
            vec![Output::SendToQtsp(sig.clone()), Output::Close],
        ),

        // Defensive no-op for any other combination.
        (s, _) => (s.clone(), vec![]),
    }
}

/// Parse the shell's request JSON: `{document_name, document_hash_hex, qtsp_id, nonce}`.
fn parse_request(bytes: &[u8]) -> Result<SignRequest, ()> {
    let v: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| ())?;
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).map(|x| x.to_string());
    let document_hash = hex_decode(&s("document_hash_hex").unwrap_or_default()).ok_or(())?;
    Ok(SignRequest {
        document_name: s("document_name").unwrap_or_default(),
        document_hash,
        qtsp_id: s("qtsp_id").ok_or(())?,
        nonce: v.get("nonce").and_then(|x| x.as_u64()).ok_or(())?,
    })
}

/// Decode a lowercase/uppercase hex string to bytes. Returns None on odd length or a non-hex digit.
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    let nibble = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    let mut i = 0;
    while i < b.len() {
        out.push((nibble(b[i])? << 4) | nibble(b[i + 1])?);
        i += 2;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_backend::{AwsLc, SoftwareSigner};
    use crypto_traits::{Alg, Digest, KeyRef, Signer, Verifier};

    fn env<'a>(seen: &'a [u64], ch: [u8; 32]) -> Env<'a> {
        Env { seen_nonces: seen, device_key_ref: "device-key", consent_hash: ch }
    }

    fn request_json(nonce: u64, doc_hex: &str) -> Vec<u8> {
        format!(
            r#"{{"document_name":"Contract.pdf","document_hash_hex":"{doc_hex}","qtsp_id":"qtsp.example","nonce":{nonce}}}"#
        )
        .into_bytes()
    }

    #[test]
    fn full_qes_authorization_binds_document_and_consent() {
        let device = SoftwareSigner::generate_p256().unwrap();
        let consent = AwsLc.sha256(b"You are signing Contract.pdf with qtsp.example");

        // 1) request → sign confirmation.
        let (s, out) = step(
            &QesState::Idle,
            &Input::SignatureRequest(request_json(1, "deadbeef")),
            &env(&[], consent),
        );
        assert!(matches!(out.as_slice(), [Output::RenderSignConfirmation { .. }]));

        // 2) authorize → SignAuthorization over the DTBS/R.
        let (s, out) = step(&s, &Input::UserAuthorized, &env(&[], consent));
        let signing_input = out
            .iter()
            .find_map(|o| match o {
                Output::SignAuthorization { signing_input, .. } => Some(signing_input.clone()),
                _ => None,
            })
            .expect("expected a SignAuthorization output");

        // 3) device signs → SendToQtsp.
        let sig = device
            .sign(&KeyRef("device-key".into()), Alg::Es256, &signing_input)
            .unwrap();
        let (s, out) = step(
            &s,
            &Input::AuthorizationSignatureProduced(sig.clone()),
            &env(&[], consent),
        );
        assert!(matches!(s, QesState::Signed { .. }));
        assert!(out.iter().any(|o| matches!(o, Output::SendToQtsp(_))));

        // The QTSP verifies the authorization over the DTBS/R it recomputes for the same document
        // + consent hash; a different consent hash (a screen the user did NOT see) fails.
        let req = SignRequest {
            document_name: "Contract.pdf".into(),
            document_hash: vec![0xde, 0xad, 0xbe, 0xef],
            qtsp_id: "qtsp.example".into(),
            nonce: 1,
        };
        assert!(AwsLc
            .verify(Alg::Es256, device.public_key_raw(), &qes_authorization_binding(&req, &consent), &sig)
            .is_ok());
        let other = AwsLc.sha256(b"a different screen");
        assert!(AwsLc
            .verify(Alg::Es256, device.public_key_raw(), &qes_authorization_binding(&req, &other), &sig)
            .is_err());
    }

    #[test]
    fn decline_aborts_without_signing() {
        let (s, _) = step(
            &QesState::Idle,
            &Input::SignatureRequest(request_json(2, "abcd")),
            &env(&[], [0u8; 32]),
        );
        let (s, out) = step(&s, &Input::UserDeclined, &env(&[], [0u8; 32]));
        assert_eq!(s, QesState::Aborted(AbortReason::UserDeclined));
        assert!(out.is_empty());
    }

    #[test]
    fn replayed_nonce_is_rejected() {
        let (s, _) = step(
            &QesState::Idle,
            &Input::SignatureRequest(request_json(7, "aa")),
            &env(&[7], [0u8; 32]),
        );
        assert_eq!(s, QesState::Aborted(AbortReason::NonceReplayed));
    }

    #[test]
    fn missing_document_hash_is_rejected() {
        let (s, _) = step(
            &QesState::Idle,
            &Input::SignatureRequest(request_json(3, "")),
            &env(&[], [0u8; 32]),
        );
        assert_eq!(s, QesState::Aborted(AbortReason::DocumentHashMissing));
    }
}

/// Reference model that MIRRORS the Lean Tier-2 model (formal/lean/QesModel.lean).
///
/// The Lean model proves the SCA / WYSIWYS-binding / replay invariants and emits conformance
/// traces; this module is the Rust side those traces replay against (plan Section 10). The
/// production `step` above refines it. `tests/conformance.rs` checks they agree.
pub mod model {
    /// The signable essence: an abstract document id (document + consent hash) + nonce.
    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct Doc {
        pub doc_id: u64,
        pub nonce: u64,
    }

    #[derive(Clone, PartialEq, Eq, Debug)]
    pub enum St {
        Idle,
        AwaitingAuthorization(Doc),
        AwaitingSca(Doc),
        Signed(Doc),
        Aborted,
    }

    #[derive(Clone, Debug)]
    pub enum Ev {
        Request(Doc),
        Authorize,
        Decline,
        Sign,
    }

    #[derive(Clone, Debug)]
    pub struct Ctx {
        pub st: St,
        pub seen: Vec<u64>,
        pub confirmed: Option<Doc>,
        pub authorized: bool,
    }

    impl Ctx {
        pub fn init() -> Self {
            Ctx { st: St::Idle, seen: Vec::new(), confirmed: None, authorized: false }
        }
    }

    /// Transition function — the exact analogue of `QesModel.step` in Lean.
    pub fn step(mut c: Ctx, ev: &Ev) -> Ctx {
        match ev {
            Ev::Request(d) => {
                if let St::Idle = c.st {
                    if d.doc_id == 0 {
                        c.st = St::Aborted; // guard: DocumentHashMissing
                    } else if c.seen.contains(&d.nonce) {
                        c.st = St::Aborted; // guard: NonceReplayed
                    } else {
                        c.st = St::AwaitingAuthorization(d.clone());
                        c.confirmed = Some(d.clone());
                        c.seen.push(d.nonce);
                    }
                }
            }
            Ev::Authorize => {
                if let St::AwaitingAuthorization(d) = c.st.clone() {
                    c.st = St::AwaitingSca(d);
                    c.authorized = true;
                }
            }
            Ev::Decline => {
                if let St::AwaitingAuthorization(_) = c.st {
                    c.st = St::Aborted;
                }
            }
            Ev::Sign => {
                if let St::AwaitingSca(d) = c.st.clone() {
                    c.st = St::Signed(d); // binds the document carried in-flight
                }
            }
        }
        c
    }

    pub fn run(evs: &[Ev]) -> Ctx {
        evs.iter().fold(Ctx::init(), step)
    }

    pub fn state_name(st: &St) -> &'static str {
        match st {
            St::Idle => "idle",
            St::AwaitingAuthorization(_) => "awaitingAuthorization",
            St::AwaitingSca(_) => "awaitingSca",
            St::Signed(_) => "signed",
            St::Aborted => "aborted",
        }
    }

    /// WYSIWYS flag: in the accepting state, is the signature bound to the confirmed document?
    pub fn bound(c: &Ctx) -> bool {
        match &c.st {
            St::Signed(d) => c.confirmed.as_ref() == Some(d),
            _ => false,
        }
    }
}
