#![forbid(unsafe_code)]
//! `oid4vp` — OpenID4VP 1.0 remote presentation as an exhaustive, sans-IO state machine
//!
//! See docs/IMPLEMENTATION_PLAN.md Section 5.
//! Skeleton only: public shapes are sketched; implementation follows the plan.

//! HLR-traceable states/transitions/guards. All I/O is expressed as effects handled by the shell.

/// States of the remote-presentation flow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum State {
    Idle,
    RequestReceived,
    RequestValidated,
    AwaitingConsent,
    Presenting,
    Done,
    Aborted(AbortReason),
}

/// Named, individually-testable security guards (each maps to one or more HLR IDs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbortReason {
    RequestNotSignedOrBound,   // guard: request_object_is_signed_and_bound
    RelyingPartyNotRegistered, // guard: rp_is_registered
    NonceReplayed,             // guard: nonce_is_fresh
    PurposeUndeclared,         // guard: purpose_is_declared
    AudienceMismatch,          // guard: audience_matches
    UserDeclined,
}

/// Inputs to the machine.
#[derive(Clone, Debug)]
pub enum Input {
    AuthorizationRequest(Vec<u8>),
    ConsentGranted,
    ConsentDeclined,
}

/// Outputs (effects) requested by the machine.
#[derive(Clone, Debug)]
pub enum Output {
    RenderConsent,
    SendVpToken(Vec<u8>),
}

/// Pure transition function — exhaustive match. Skeleton showing the shape.
pub fn step(state: &State, input: &Input) -> (State, Vec<Output>) {
    match (state, input) {
        (State::Idle, Input::AuthorizationRequest(_bytes)) => {
            // Validate signature/binding, RP registration, nonce, purpose, audience (guards).
            (State::RequestValidated, vec![])
        }
        (State::RequestValidated, _) => (State::AwaitingConsent, vec![Output::RenderConsent]),
        (State::AwaitingConsent, Input::ConsentGranted) => {
            (State::Presenting, vec![Output::SendVpToken(Vec::new())])
        }
        (State::AwaitingConsent, Input::ConsentDeclined) => {
            (State::Aborted(AbortReason::UserDeclined), vec![])
        }
        (s, _) => (s.clone(), vec![]),
    }
}

/// Reference model that MIRRORS the Lean Tier-2 model (formal/lean/WalletModel.lean).
///
/// The Lean model proves the safety invariants and emits conformance traces; this module
/// is the Rust side those traces are replayed against (plan Section 10). The production
/// `step` above must refine this model. Keeping them byte-for-byte behaviourally identical
/// is exactly what the conformance test (`tests/conformance.rs`) checks.
pub mod model {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum St {
        Idle,
        Requested,
        Validated,
        AwaitingConsent,
        Presenting,
        Aborted,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum Ev {
        Request(u64),
        ValidateSig,
        Consent,
        Disclose,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Ctx {
        pub st: St,
        pub sig_validated: bool,
        pub consented: bool,
        pub used_nonces: Vec<u64>,
        pub disclosed: bool,
    }

    impl Ctx {
        pub fn init() -> Self {
            Ctx {
                st: St::Idle,
                sig_validated: false,
                consented: false,
                used_nonces: Vec::new(),
                disclosed: false,
            }
        }
    }

    /// Transition function — the exact analogue of `WalletModel.step` in Lean.
    pub fn step(mut c: Ctx, ev: &Ev) -> Ctx {
        match ev {
            Ev::Request(n) => {
                if c.used_nonces.contains(n) {
                    c.st = St::Aborted; // guard: nonce_is_fresh (replay → abort)
                } else {
                    c.st = St::Requested;
                    c.used_nonces.push(*n);
                }
            }
            Ev::ValidateSig => {
                if c.st == St::Requested {
                    c.st = St::Validated;
                    c.sig_validated = true;
                }
            }
            Ev::Consent => {
                if c.st == St::Validated {
                    c.st = St::AwaitingConsent;
                    c.consented = true;
                }
            }
            Ev::Disclose => {
                if c.consented && c.sig_validated {
                    c.st = St::Presenting;
                    c.disclosed = true;
                } else {
                    c.st = St::Aborted; // guard: no disclosure before consent + validation
                }
            }
        }
        c
    }

    /// Run a whole trace from `init`.
    pub fn run(evs: &[Ev]) -> Ctx {
        evs.iter().fold(Ctx::init(), step)
    }

    /// Stable string form of a state, matching the Lean exporter's `stJson`.
    pub fn state_name(st: St) -> &'static str {
        match st {
            St::Idle => "idle",
            St::Requested => "requested",
            St::Validated => "validated",
            St::AwaitingConsent => "awaitingConsent",
            St::Presenting => "presenting",
            St::Aborted => "aborted",
        }
    }
}
