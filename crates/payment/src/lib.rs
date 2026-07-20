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

/// A payment authorization request presented to the wallet (TS12 / PSD2 shape).
///
/// PSD2 RTS Art. 5 requires the authentication code to be specific to the **amount** and the
/// **payee**. The payee here is the *creditor* — both its display name and its account (IBAN) —
/// so the code binds the account the money actually goes to, not just a display string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentRequest {
    /// Creditor (payee) display name shown to the user.
    pub creditor_name: String,
    /// Creditor account identifier (e.g. IBAN) the funds are sent to.
    pub creditor_account: String,
    /// Amount in minor units (cents) — integer, never a float.
    pub amount_minor: u64,
    /// ISO 4217 currency code.
    pub currency: String,
    /// Merchant/PSP transaction reference.
    pub transaction_id: String,
    /// Transaction nonce (replay protection).
    pub nonce: u64,
    /// Where the authentication code is posted (the payment service). Empty if delivered
    /// out of band by the shell.
    pub response_uri: String,
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
    /// Render the DEDICATED payment confirmation screen (never the identity consent screen). Shows
    /// the creditor (name + account) and amount the payer is authorising (RTS Art. 5(1)).
    RenderPaymentConfirmation {
        creditor_name: String,
        creditor_account: String,
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
        Value::Text(req.creditor_name.clone()),
        Value::Text(req.creditor_account.clone()),
        Value::Uint(req.amount_minor),
        Value::Text(req.currency.clone()),
        Value::Text(req.transaction_id.clone()),
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
                if req.creditor_name.trim().is_empty() || req.creditor_account.trim().is_empty() {
                    return (State::Aborted(AbortReason::PayeeMissing), vec![]);
                }
                if env.seen_nonces.contains(&req.nonce) {
                    return (State::Aborted(AbortReason::NonceReplayed), vec![]);
                }
                let out = Output::RenderPaymentConfirmation {
                    creditor_name: req.creditor_name.clone(),
                    creditor_account: req.creditor_account.clone(),
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
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).map(|x| x.to_string());
    Ok(PaymentRequest {
        creditor_name: s("creditor_name").ok_or(())?,
        creditor_account: s("creditor_account").ok_or(())?,
        amount_minor: v.get("amount_minor").and_then(|x| x.as_u64()).ok_or(())?,
        currency: s("currency").ok_or(())?,
        transaction_id: s("transaction_id").unwrap_or_default(),
        nonce: v.get("nonce").and_then(|x| x.as_u64()).ok_or(())?,
        response_uri: s("response_uri").unwrap_or_default(),
    })
}

/// Reference model that MIRRORS the Lean Tier-2 model (formal/lean/PaymentModel.lean).
///
/// The Lean model proves the SCA / dynamic-linking / replay invariants and emits conformance
/// traces; this module is the Rust side those traces are replayed against (plan Section 10). The
/// production `step` above must refine this model. `tests/conformance.rs` checks they agree.
pub mod model {
    /// The payer-visible essence of a payment (the fields dynamic linking binds).
    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct Payment {
        pub payee: String,
        pub amount: u64,
        pub nonce: u64,
    }

    #[derive(Clone, PartialEq, Eq, Debug)]
    pub enum St {
        Idle,
        AwaitingConfirmation(Payment),
        AwaitingSca(Payment),
        Authorized(Payment),
        Aborted,
    }

    #[derive(Clone, Debug)]
    pub enum Ev {
        Request(Payment),
        Approve,
        Decline,
        Sign,
    }

    #[derive(Clone, Debug)]
    pub struct Ctx {
        pub st: St,
        pub seen: Vec<u64>,
        pub confirmed: Option<Payment>,
        pub approved: bool,
    }

    impl Ctx {
        pub fn init() -> Self {
            Ctx {
                st: St::Idle,
                seen: Vec::new(),
                confirmed: None,
                approved: false,
            }
        }
    }

    /// Transition function — the exact analogue of `PaymentModel.step` in Lean.
    pub fn step(mut c: Ctx, ev: &Ev) -> Ctx {
        match ev {
            Ev::Request(p) => {
                if let St::Idle = c.st {
                    if p.amount == 0 {
                        c.st = St::Aborted; // guard: InvalidAmount
                    } else if c.seen.contains(&p.nonce) {
                        c.st = St::Aborted; // guard: NonceReplayed
                    } else {
                        c.st = St::AwaitingConfirmation(p.clone());
                        c.confirmed = Some(p.clone());
                        c.seen.push(p.nonce);
                    }
                }
            }
            Ev::Approve => {
                if let St::AwaitingConfirmation(p) = c.st.clone() {
                    c.st = St::AwaitingSca(p);
                    c.approved = true;
                }
            }
            Ev::Decline => {
                if let St::AwaitingConfirmation(_) = c.st {
                    c.st = St::Aborted;
                }
            }
            Ev::Sign => {
                if let St::AwaitingSca(p) = c.st.clone() {
                    c.st = St::Authorized(p); // binds the payment carried in-flight
                }
            }
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
            St::AwaitingConfirmation(_) => "awaitingConfirmation",
            St::AwaitingSca(_) => "awaitingSca",
            St::Authorized(_) => "authorized",
            St::Aborted => "aborted",
        }
    }

    /// Dynamic-linking flag: in the accepting state, is the auth code bound to the confirmed payment?
    pub fn bound(c: &Ctx) -> bool {
        match &c.st {
            St::Authorized(p) => c.confirmed.as_ref() == Some(p),
            _ => false,
        }
    }
}

/// OpenID4VP `transaction_data` (1.0 §5.4) — the standardized carrier for the TS12/PSD2 payment
/// envelope. The RP puts an array of base64url(JSON) entries in the authorization request; the
/// wallet parses the payment entry, shows the SCA confirmation, and binds the presentation/auth to
/// the entry by including `SHA-256(entry)` (base64url) in the key-binding — so the payment the user
/// authorises is exactly the one the RP requested (dynamic linking, at the transport layer).
pub mod transaction_data {
    use super::PaymentRequest;
    use base64ct::{Base64UrlUnpadded, Encoding};
    use crypto_traits::Digest;

    /// A parsed payment `transaction_data` entry.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct PaymentTransactionData {
        /// The `type` (e.g. `payment_data`).
        pub kind: String,
        /// The DCQL credential query ids this transaction is bound to.
        pub credential_ids: Vec<String>,
        /// The payment fields (creditor + amount + currency + txn/nonce/response_uri).
        pub request: PaymentRequest,
        /// The exact base64url string the hash is computed over.
        pub raw_b64: String,
    }

    /// Parse one base64url(JSON) `transaction_data` entry. The JSON carries `type`,
    /// `credential_ids`, and the payment fields (top level, matching the payment request shape).
    pub fn parse(entry_b64: &str) -> Option<PaymentTransactionData> {
        let json = Base64UrlUnpadded::decode_vec(entry_b64).ok()?;
        let v: serde_json::Value = serde_json::from_slice(&json).ok()?;
        let s = |k: &str| v.get(k).and_then(|x| x.as_str()).map(str::to_string);
        let credential_ids = v
            .get("credential_ids")
            .and_then(|x| x.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        Some(PaymentTransactionData {
            kind: s("type")?,
            credential_ids,
            request: PaymentRequest {
                creditor_name: s("creditor_name")?,
                creditor_account: s("creditor_account")?,
                amount_minor: v.get("amount_minor").and_then(|x| x.as_u64())?,
                currency: s("currency")?,
                transaction_id: s("transaction_id").unwrap_or_default(),
                nonce: v.get("nonce").and_then(|x| x.as_u64())?,
                response_uri: s("response_uri").unwrap_or_default(),
            },
            raw_b64: entry_b64.to_string(),
        })
    }

    /// The `transaction_data_hash` (OpenID4VP §5.4): base64url(SHA-256(entry_b64)). The wallet
    /// echoes this in the KB-JWT, binding the presentation to this exact transaction_data entry.
    pub fn transaction_data_hash(entry_b64: &str, digest: &dyn Digest) -> String {
        Base64UrlUnpadded::encode_string(&digest.sha256(entry_b64.as_bytes()))
    }
}

#[cfg(test)]
mod transaction_data_tests {
    use super::transaction_data::{parse, transaction_data_hash};
    use base64ct::{Base64UrlUnpadded, Encoding};
    use crypto_backend::AwsLc;

    fn entry() -> String {
        let json = br#"{"type":"payment_data","credential_ids":["pid"],"creditor_name":"Acme Store","creditor_account":"DE89370400440532013000","amount_minor":1299,"currency":"EUR","transaction_id":"txn-1","nonce":7,"response_uri":"https://psp.example/authorize"}"#;
        Base64UrlUnpadded::encode_string(json)
    }

    #[test]
    fn parses_a_payment_transaction_data_entry() {
        let e = entry();
        let td = parse(&e).expect("valid transaction_data");
        assert_eq!(td.kind, "payment_data");
        assert_eq!(td.credential_ids, vec!["pid".to_string()]);
        assert_eq!(td.request.creditor_name, "Acme Store");
        assert_eq!(td.request.amount_minor, 1299);
        assert_eq!(td.request.currency, "EUR");
        assert_eq!(td.raw_b64, e);
    }

    #[test]
    fn hash_is_over_the_base64url_string_and_binds_the_entry() {
        let e = entry();
        let h1 = transaction_data_hash(&e, &AwsLc);
        let h2 = transaction_data_hash(&e, &AwsLc);
        assert_eq!(h1, h2, "deterministic");
        // A tampered entry (different amount) yields a different hash.
        let tampered = Base64UrlUnpadded::encode_string(
            br#"{"type":"payment_data","credential_ids":["pid"],"creditor_name":"Acme Store","creditor_account":"DE89370400440532013000","amount_minor":9999,"currency":"EUR","transaction_id":"txn-1","nonce":7,"response_uri":"https://psp.example/authorize"}"#,
        );
        assert_ne!(transaction_data_hash(&tampered, &AwsLc), h1);
    }

    #[test]
    fn rejects_malformed_entries() {
        assert!(parse("!!!not-base64!!!").is_none());
        assert!(parse(&Base64UrlUnpadded::encode_string(b"not json")).is_none());
    }
}
