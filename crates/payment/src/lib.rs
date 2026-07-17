#![forbid(unsafe_code)]
//! `payment` — PSD2 / TS12 payment **Strong Customer Authentication** with **dynamic linking**,
//! as a sans-IO state machine.
//!
//! See docs/IMPLEMENTATION_PLAN.md (P2 Payment SCA). Register guidance: *"Add as an isolated
//! transaction-authorisation module after identity presentation is stable. Do not mix payment
//! transaction data with generic identity consent screens."*
//!
//! ## Dynamic linking (PSD2 RTS Art. 5) — the load-bearing property
//!
//! The authentication code the wallet produces MUST be specific to the exact **amount** and
//! **payee**; any change to either must invalidate it. We achieve this by having the device key
//! sign a canonical, deterministic binding over `(payee, amount, currency, nonce)`. Change any
//! field and the binding — and therefore the signature — changes, so a payment service verifying
//! the code against the real amount/payee will reject a tampered transaction. The device signature
//! (possession, biometric-gated in the shell = inherence) provides the two SCA factors; the
//! private key never crosses the FFI.

use cose::cbor::Value;

/// A payment authorization request presented to the wallet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentRequest {
    pub payee: String,
    /// Amount in minor units (cents) — integer, never a float.
    pub amount_minor: u64,
    /// ISO 4217 currency code.
    pub currency: String,
    /// Transaction nonce (replay protection).
    pub nonce: u64,
}

/// The dynamic-linking binding the device signs, plus a summary for the SCA screen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingAuthorization {
    pub request: PaymentRequest,
    /// Canonical bytes over `(payee, amount, currency, nonce)` — the dynamic-linking binding.
    pub binding: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum State {
    /// PAY-S-001 — idle.
    Idle,
    /// PAY-S-002 — showing the dedicated payment confirmation (amount + payee).
    AwaitingConfirmation(Box<PaymentRequest>),
    /// PAY-S-003 — user approved; the device is signing the dynamic-linking binding (SCA).
    AwaitingSca(Box<PendingAuthorization>),
    /// PAY-S-004 — authorization code produced (terminal).
    Authorized { auth_code: Vec<u8> },
    /// PAY-S-005 — aborted (terminal).
    Aborted(AbortReason),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbortReason {
    /// PAY-G-001 — the request could not be parsed.
    MalformedRequest,
    /// PAY-G-002 — amount must be positive.
    InvalidAmount,
    /// PAY-G-003 — payee must be present.
    PayeeMissing,
    /// PAY-G-004 — nonce already used (replay).
    NonceReplayed,
    /// PAY-G-005 — user declined the payment.
    UserDeclined,
}

#[derive(Clone, Debug)]
pub enum Input {
    PaymentAuthorizationRequest(Vec<u8>),
    UserApproved,
    UserDeclined,
    /// The device produced the SCA signature over the dynamic-linking binding.
    AuthCodeSignatureProduced(Vec<u8>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Output {
    /// Render the DEDICATED payment confirmation screen (never the identity consent screen).
    RenderPaymentConfirmation {
        payee: String,
        amount_minor: u64,
        currency: String,
    },
    /// Sign the dynamic-linking binding with the device key (biometric-gated Secure Enclave).
    SignAuthCode {
        key_ref: String,
        signing_input: Vec<u8>,
    },
    /// Send the authentication code (dynamically linked to amount + payee) to the payment service.
    SendAuthorization(Vec<u8>),
    Close,
}

/// Pure facts the machine reads (assembled by the shell).
pub struct Env<'a> {
    pub seen_nonces: &'a [u64],
    pub device_key_ref: &'a str,
}

/// Compute the dynamic-linking binding: a canonical CBOR array over a domain tag and the fields
/// PSD2 RTS Art. 5 requires the code to be specific to. Deterministic, so both the wallet and the
/// verifying payment service derive identical bytes.
pub fn dynamic_linking_binding(req: &PaymentRequest) -> Vec<u8> {
    Value::Array(vec![
        Value::Text("eudi-payment-sca-v1".into()),
        Value::Text(req.payee.clone()),
        Value::Uint(req.amount_minor),
        Value::Text(req.currency.clone()),
        Value::Uint(req.nonce),
    ])
    .to_canonical()
}

/// Pure transition function — exhaustive match.
pub fn step(state: &State, input: &Input, env: &Env) -> (State, Vec<Output>) {
    match (state, input) {
        // PAY-T-001 — parse + validate the request, then show the dedicated confirmation screen.
        (State::Idle, Input::PaymentAuthorizationRequest(bytes)) => match parse_request(bytes) {
            Ok(req) => {
                if req.amount_minor == 0 {
                    return (State::Aborted(AbortReason::InvalidAmount), vec![]);
                }
                if req.payee.trim().is_empty() {
                    return (State::Aborted(AbortReason::PayeeMissing), vec![]);
                }
                if env.seen_nonces.contains(&req.nonce) {
                    return (State::Aborted(AbortReason::NonceReplayed), vec![]);
                }
                let out = Output::RenderPaymentConfirmation {
                    payee: req.payee.clone(),
                    amount_minor: req.amount_minor,
                    currency: req.currency.clone(),
                };
                (State::AwaitingConfirmation(Box::new(req)), vec![out])
            }
            Err(()) => (State::Aborted(AbortReason::MalformedRequest), vec![]),
        },

        // PAY-T-002 — user approves → build the dynamic-linking binding and ask the device to sign.
        (State::AwaitingConfirmation(req), Input::UserApproved) => {
            let binding = dynamic_linking_binding(req);
            let signing_input = binding.clone();
            (
                State::AwaitingSca(Box::new(PendingAuthorization {
                    request: (**req).clone(),
                    binding,
                })),
                vec![Output::SignAuthCode {
                    key_ref: env.device_key_ref.to_string(),
                    signing_input,
                }],
            )
        }
        // PAY-T-003 — user declines → abort, authorise nothing.
        (State::AwaitingConfirmation(_), Input::UserDeclined) => (
            State::Aborted(AbortReason::UserDeclined),
            vec![Output::Close],
        ),

        // PAY-T-004 — SCA signature ready → the auth code IS that signature (dynamically linked).
        (State::AwaitingSca(_), Input::AuthCodeSignatureProduced(sig)) => (
            State::Authorized {
                auth_code: sig.clone(),
            },
            vec![Output::SendAuthorization(sig.clone()), Output::Close],
        ),

        // PAY-T-999 — defensive no-op.
        (s, _) => (s.clone(), vec![]),
    }
}

fn parse_request(bytes: &[u8]) -> Result<PaymentRequest, ()> {
    let v: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| ())?;
    Ok(PaymentRequest {
        payee: v
            .get("payee")
            .and_then(|x| x.as_str())
            .ok_or(())?
            .to_string(),
        amount_minor: v.get("amount_minor").and_then(|x| x.as_u64()).ok_or(())?,
        currency: v
            .get("currency")
            .and_then(|x| x.as_str())
            .ok_or(())?
            .to_string(),
        nonce: v.get("nonce").and_then(|x| x.as_u64()).ok_or(())?,
    })
}
