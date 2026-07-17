#![forbid(unsafe_code)]
//! `wallet-core` — the sans-IO facade of the EUDI wallet.
//!
//! See docs/IMPLEMENTATION_PLAN.md Section 2 (architecture) and Section 3 (FFI).
//!
//! The core is a pure state machine: the shell delivers an [`Event`], the core mutates
//! its state and returns a list of [`Effect`]s for the shell to execute. No network,
//! clock, radio, or disk lives here — which is exactly what makes the whole protocol
//! layer deterministic and replay-testable (see Section 10, the Lean oracle).

use presenter::{present, ScreenDescription, ScreenKind, Snapshot};

/// A correlation id linking an [`Effect`] request to the [`Event`] carrying its result.
pub type EffectId = u64;

/// Everything that can happen *to* the core. The shell produces these.
#[derive(Clone, Debug)]
pub enum Event {
    /// A remote authorization request (OpenID4VP) arrived via deep link / browser.
    AuthorizationRequestReceived(Vec<u8>),
    /// The user approved the consent screen currently displayed.
    UserConsented,
    /// The user declined.
    UserDeclined,
    /// A hardware signature the core previously requested is ready.
    SignatureProduced { id: EffectId, signature: Vec<u8> },
    /// An HTTP response to a request the core previously emitted.
    HttpResponse {
        id: EffectId,
        status: u16,
        body: Vec<u8>,
    },
}

/// Everything the core asks the shell to do. The shell executes these and feeds
/// results back as [`Event`]s (using the matching [`EffectId`]).
#[derive(Clone, Debug, PartialEq)]
pub enum Effect {
    /// Render this exact, fully-resolved screen. The only UI contract.
    Render(ScreenDescription),
    /// Sign `payload` with the hardware key referenced by `key_ref` (Secure Enclave).
    Sign {
        id: EffectId,
        key_ref: String,
        payload: Vec<u8>,
    },
    /// Perform an HTTP request (TLS handled by the OS).
    Http {
        id: EffectId,
        url: String,
        body: Vec<u8>,
    },
    /// Persist a record to secure storage.
    Store { key: String, value: Vec<u8> },
}

/// The whole wallet state. In the full implementation this holds each sub-machine's state
/// (oid4vp, oid4vci, iso18013-5, ...). Kept minimal in the skeleton.
#[derive(Debug, Default)]
pub struct Core {
    next_effect_id: EffectId,
    snapshot: Snapshot,
}

impl Core {
    pub fn new() -> Self {
        Core::default()
    }

    fn fresh_id(&mut self) -> EffectId {
        self.next_effect_id += 1;
        self.next_effect_id
    }

    /// The single entry point. Pure with respect to I/O: same state + same event ⇒ same effects.
    pub fn handle_event(&mut self, event: Event) -> Vec<Effect> {
        match event {
            Event::AuthorizationRequestReceived(_bytes) => {
                // Full impl: drive oid4vp::step, run the security guards, compute the
                // minimum claim set, then build the consent snapshot.
                self.snapshot.screen = Some(ScreenKind::Consent);
                vec![Effect::Render(present(&self.snapshot))]
            }
            Event::UserConsented => {
                let id = self.fresh_id();
                vec![Effect::Sign {
                    id,
                    key_ref: "device-key".to_string(),
                    payload: b"vp_token_to_be_signed".to_vec(),
                }]
            }
            Event::UserDeclined => {
                self.snapshot.screen = Some(ScreenKind::Error);
                self.snapshot.error =
                    Some(("user_declined".into(), "You declined the request.".into()));
                vec![Effect::Render(present(&self.snapshot))]
            }
            Event::SignatureProduced { .. } => {
                let id = self.fresh_id();
                vec![Effect::Http {
                    id,
                    url: "https://rp.example/response".into(),
                    body: Vec::new(),
                }]
            }
            Event::HttpResponse { .. } => {
                self.snapshot.screen = Some(ScreenKind::CredentialList);
                vec![Effect::Render(present(&self.snapshot))]
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Section 2 definition-of-done: drive a two-step flow purely in Rust, no I/O,
    /// and assert the emitted effects.
    #[test]
    fn consent_then_sign_flow_is_pure_and_deterministic() {
        let mut core = Core::new();

        let effects = core.handle_event(Event::AuthorizationRequestReceived(vec![1, 2, 3]));
        assert_eq!(effects.len(), 1);
        assert!(matches!(
            effects[0],
            Effect::Render(ScreenDescription::Consent(_))
        ));

        let effects = core.handle_event(Event::UserConsented);
        assert_eq!(
            effects,
            vec![Effect::Sign {
                id: 1,
                key_ref: "device-key".into(),
                payload: b"vp_token_to_be_signed".to_vec()
            }]
        );
    }

    #[test]
    fn same_input_same_output() {
        let run = || {
            let mut c = Core::new();
            let _ = c.handle_event(Event::AuthorizationRequestReceived(vec![9]));
            c.handle_event(Event::UserConsented)
        };
        assert_eq!(run(), run());
    }
}
