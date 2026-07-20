#![forbid(unsafe_code)]
//! `w2w` — wallet-to-wallet credential transfer (P1 / TS09).
//!
//! Two security-critical decisions live here, both sans-IO (the BLE/QR transport is the shell's):
//!
//!  * **Receiver accept-after-validate** ([`step`]): a wallet accepts a credential handed to it by
//!    a peer ONLY IF the credential's issuer signature validates AND it was bound to THIS receiver
//!    (the peer key it offered), defeating forged credentials and misdirected/replayed transfers.
//!    This is the machine we model and prove (`formal/lean/W2wModel.lean`).
//!
//!  * **Sender consent-bound transfer** ([`transfer_authorization_binding`]): the sender's device
//!    signs a binding over the credential id, the receiver's key, the consent hash of what the
//!    sender saw, and a nonce — so a transfer authorization is specific to this credential and this
//!    peer (the same what-you-see-is-what-you-authorise pattern as payment/QES).

use cose::cbor::Value;

/// Receiver states (mirror of the tier-2 model).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum State {
    /// Idle.
    Idle,
    /// The receiver published an offer (its ephemeral key + nonce) and awaits a transfer.
    AwaitingTransfer,
    /// Accepting: a validated, correctly-bound credential was received (terminal).
    Accepted { credential: Vec<u8> },
    /// Rejected (terminal).
    Rejected(RejectReason),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectReason {
    /// W2W-G-001 — the transferred credential's issuer signature did not validate.
    IssuerInvalid,
    /// W2W-G-002 — the transfer was not bound to this receiver (wrong peer / replayed elsewhere).
    PeerMismatch,
    /// W2W-G-003 — a transfer arrived before the receiver made an offer.
    OutOfOrder,
}

#[derive(Clone, Debug)]
pub enum Input {
    /// The receiver creates an offer to receive (its ephemeral key + a fresh nonce).
    CreateOffer,
    /// A transfer arrived. `issuer_valid` and `peer_bound` are computed by the shell/core from the
    /// credential's issuer signature and the transfer authorization's binding to this receiver.
    TransferReceived {
        issuer_valid: bool,
        peer_bound: bool,
        credential: Vec<u8>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Output {
    /// Publish the receiver's offer over the peer transport.
    PublishOffer,
    /// Store the accepted credential.
    StoreCredential(Vec<u8>),
    Close,
}

/// Pure transition function — exhaustive match.
pub fn step(state: &State, input: &Input) -> (State, Vec<Output>) {
    match (state, input) {
        (State::Idle, Input::CreateOffer) => (State::AwaitingTransfer, vec![Output::PublishOffer]),

        (
            State::AwaitingTransfer,
            Input::TransferReceived {
                issuer_valid,
                peer_bound,
                credential,
            },
        ) => {
            if !*issuer_valid {
                (State::Rejected(RejectReason::IssuerInvalid), vec![])
            } else if !*peer_bound {
                (State::Rejected(RejectReason::PeerMismatch), vec![])
            } else {
                (
                    State::Accepted {
                        credential: credential.clone(),
                    },
                    vec![Output::StoreCredential(credential.clone()), Output::Close],
                )
            }
        }

        // A transfer before an offer is out of order.
        (State::Idle, Input::TransferReceived { .. }) => {
            (State::Rejected(RejectReason::OutOfOrder), vec![])
        }

        // Defensive no-op for any other combination.
        (s, _) => (s.clone(), vec![]),
    }
}

/// The sender's transfer-authorization binding (DTBS): canonical CBOR over a domain tag, the
/// receiver IDENTITY, the receiver's key, the transferred CREDENTIAL, the consent hash of what the
/// sender saw, and a nonce.
///
/// Binding the receiver identity AND the credential is not incidental: the Tier-3 Tamarin analysis
/// (`formal/tamarin/w2w.spthy`) showed that binding only the (public) ephemeral key lets an
/// attacker (a) redirect the sender to believe it is transferring to a different party, and (b)
/// swap the encrypted credential while keeping a valid signature. Both are closed by including
/// `receiver_id` and `credential` here.
pub fn transfer_authorization_binding(
    receiver_id: &str,
    receiver_key: &[u8],
    credential: &[u8],
    consent_hash: &[u8; 32],
    nonce: u64,
) -> Vec<u8> {
    Value::Array(vec![
        Value::Text("eudi-w2w-transfer-v1".into()),
        Value::Text(receiver_id.into()),
        Value::Bytes(receiver_key.to_vec()),
        Value::Bytes(credential.to_vec()),
        Value::Bytes(consent_hash.to_vec()),
        Value::Uint(nonce),
    ])
    .to_canonical()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offered() -> State {
        let (s, out) = step(&State::Idle, &Input::CreateOffer);
        assert_eq!(out, vec![Output::PublishOffer]);
        s
    }

    #[test]
    fn accepts_a_validated_bound_transfer() {
        let (s, out) = step(
            &offered(),
            &Input::TransferReceived {
                issuer_valid: true,
                peer_bound: true,
                credential: b"cred".to_vec(),
            },
        );
        assert_eq!(
            s,
            State::Accepted {
                credential: b"cred".to_vec()
            }
        );
        assert!(out.iter().any(|o| matches!(o, Output::StoreCredential(_))));
    }

    #[test]
    fn rejects_an_unsigned_credential() {
        let (s, _) = step(
            &offered(),
            &Input::TransferReceived {
                issuer_valid: false,
                peer_bound: true,
                credential: b"forged".to_vec(),
            },
        );
        assert_eq!(s, State::Rejected(RejectReason::IssuerInvalid));
    }

    #[test]
    fn rejects_a_misdirected_transfer() {
        let (s, _) = step(
            &offered(),
            &Input::TransferReceived {
                issuer_valid: true,
                peer_bound: false, // bound to a different receiver / replayed
                credential: b"cred".to_vec(),
            },
        );
        assert_eq!(s, State::Rejected(RejectReason::PeerMismatch));
    }

    #[test]
    fn rejects_a_transfer_before_an_offer() {
        let (s, _) = step(
            &State::Idle,
            &Input::TransferReceived {
                issuer_valid: true,
                peer_bound: true,
                credential: b"cred".to_vec(),
            },
        );
        assert_eq!(s, State::Rejected(RejectReason::OutOfOrder));
    }

    #[test]
    fn binding_is_specific_to_receiver_and_credential() {
        let ch = [9u8; 32];
        let a = transfer_authorization_binding("wallet-B", b"ephA", b"cred-bytes", &ch, 1);
        let same = transfer_authorization_binding("wallet-B", b"ephA", b"cred-bytes", &ch, 1);
        let other_id = transfer_authorization_binding("wallet-C", b"ephA", b"cred-bytes", &ch, 1);
        let other_key = transfer_authorization_binding("wallet-B", b"ephX", b"cred-bytes", &ch, 1);
        let other_cred = transfer_authorization_binding("wallet-B", b"ephA", b"other-cred", &ch, 1);
        assert_eq!(a, same);
        // Each field the Tamarin analysis proved must be bound changes the DTBS.
        assert_ne!(a, other_id, "binding must differ per receiver identity");
        assert_ne!(a, other_key, "binding must differ per receiver key");
        assert_ne!(a, other_cred, "binding must differ per credential");
    }
}

/// Reference model that MIRRORS the Lean Tier-2 model (formal/lean/W2wModel.lean) — the receiver
/// accept-after-validate machine. Replayed against the Lean oracle by tests/conformance.rs.
pub mod model {
    #[derive(Clone, PartialEq, Eq, Debug)]
    pub enum St {
        Idle,
        AwaitingTransfer,
        Accepted,
        Rejected,
    }

    #[derive(Clone, Debug)]
    pub enum Ev {
        CreateOffer,
        TransferReceived {
            issuer_valid: bool,
            peer_bound: bool,
        },
    }

    #[derive(Clone, Debug)]
    pub struct Ctx {
        pub st: St,
        pub issuer_valid: bool,
        pub peer_bound: bool,
    }

    impl Ctx {
        pub fn init() -> Self {
            Ctx {
                st: St::Idle,
                issuer_valid: false,
                peer_bound: false,
            }
        }
    }

    /// Transition function — the exact analogue of `W2wModel.step` in Lean.
    pub fn step(mut c: Ctx, ev: &Ev) -> Ctx {
        match ev {
            Ev::CreateOffer => {
                if c.st == St::Idle {
                    c.st = St::AwaitingTransfer;
                }
            }
            Ev::TransferReceived {
                issuer_valid,
                peer_bound,
            } => match c.st {
                St::AwaitingTransfer => {
                    if !*issuer_valid {
                        c.st = St::Rejected; // IssuerInvalid
                    } else if !*peer_bound {
                        c.st = St::Rejected; // PeerMismatch
                    } else {
                        c.st = St::Accepted;
                        c.issuer_valid = true;
                        c.peer_bound = true;
                    }
                }
                St::Idle => c.st = St::Rejected, // OutOfOrder
                _ => {}
            },
        }
        c
    }

    pub fn run(evs: &[Ev]) -> Ctx {
        evs.iter().fold(Ctx::init(), step)
    }

    pub fn state_name(st: &St) -> &'static str {
        match st {
            St::Idle => "idle",
            St::AwaitingTransfer => "awaitingTransfer",
            St::Accepted => "accepted",
            St::Rejected => "rejected",
        }
    }
}
