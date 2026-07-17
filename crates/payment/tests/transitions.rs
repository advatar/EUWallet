//! payment SCA transition tests + the dynamic-linking property (PSD2 RTS Art. 5).
use payment::{
    dynamic_linking_binding, step, AbortReason, Env, Input, Output, PaymentRequest, State,
};

fn env<'a>(seen: &'a [u64]) -> Env<'a> {
    Env {
        seen_nonces: seen,
        device_key_ref: "device-key",
    }
}

fn req_json(payee: &str, amount: u64, currency: &str, nonce: u64) -> Vec<u8> {
    format!(
        r#"{{"creditor_name":"{payee}","creditor_account":"DE89370400440532013000","amount_minor":{amount},"currency":"{currency}","transaction_id":"txn-1","nonce":{nonce}}}"#
    )
    .into_bytes()
}

#[test]
fn happy_path_to_authorized() {
    let seen: Vec<u64> = vec![];
    let e = env(&seen);
    let (s, out) = step(
        &State::Idle,
        &Input::PaymentAuthorizationRequest(req_json("Acme Store", 1299, "EUR", 7)),
        &e,
    );
    assert!(matches!(s, State::AwaitingConfirmation(_)));
    assert_eq!(
        out,
        vec![Output::RenderPaymentConfirmation {
            creditor_name: "Acme Store".into(),
            creditor_account: "DE89370400440532013000".into(),
            amount_minor: 1299,
            currency: "EUR".into()
        }]
    );

    let (s, out) = step(&s, &Input::UserApproved, &e);
    assert!(matches!(s, State::AwaitingSca(_)));
    assert!(matches!(out.as_slice(), [Output::SignAuthCode { .. }]));

    let (s, out) = step(&s, &Input::AuthCodeSignatureProduced(vec![0xAB; 64]), &e);
    assert!(matches!(s, State::Authorized { .. }));
    assert_eq!(
        out,
        vec![Output::SendAuthorization(vec![0xAB; 64]), Output::Close]
    );
}

#[test]
fn abort_invalid_amount() {
    let seen: Vec<u64> = vec![];
    let (s, _) = step(
        &State::Idle,
        &Input::PaymentAuthorizationRequest(req_json("Acme", 0, "EUR", 1)),
        &env(&seen),
    );
    assert_eq!(s, State::Aborted(AbortReason::InvalidAmount));
}

#[test]
fn abort_payee_missing() {
    let seen: Vec<u64> = vec![];
    let (s, _) = step(
        &State::Idle,
        &Input::PaymentAuthorizationRequest(req_json("", 100, "EUR", 1)),
        &env(&seen),
    );
    assert_eq!(s, State::Aborted(AbortReason::PayeeMissing));
}

#[test]
fn abort_nonce_replayed() {
    let seen = vec![7u64];
    let (s, _) = step(
        &State::Idle,
        &Input::PaymentAuthorizationRequest(req_json("Acme", 100, "EUR", 7)),
        &env(&seen),
    );
    assert_eq!(s, State::Aborted(AbortReason::NonceReplayed));
}

#[test]
fn abort_malformed() {
    let seen: Vec<u64> = vec![];
    let (s, _) = step(
        &State::Idle,
        &Input::PaymentAuthorizationRequest(b"not json".to_vec()),
        &env(&seen),
    );
    assert_eq!(s, State::Aborted(AbortReason::MalformedRequest));
}

#[test]
fn user_declines() {
    let seen: Vec<u64> = vec![];
    let e = env(&seen);
    let s = step(
        &State::Idle,
        &Input::PaymentAuthorizationRequest(req_json("Acme", 100, "EUR", 1)),
        &e,
    )
    .0;
    let (s, out) = step(&s, &Input::UserDeclined, &e);
    assert_eq!(s, State::Aborted(AbortReason::UserDeclined));
    assert_eq!(out, vec![Output::Close]);
}

// --- Dynamic linking: the binding is specific to amount AND payee (PSD2 RTS Art. 5) ---

fn req(payee: &str, amount: u64, currency: &str, nonce: u64) -> PaymentRequest {
    PaymentRequest {
        creditor_name: payee.into(),
        creditor_account: "DE89370400440532013000".into(),
        amount_minor: amount,
        currency: currency.into(),
        transaction_id: "txn-1".into(),
        nonce,
        response_uri: String::new(),
    }
}

#[test]
fn binding_is_deterministic() {
    assert_eq!(
        dynamic_linking_binding(&req("Acme", 1299, "EUR", 7)),
        dynamic_linking_binding(&req("Acme", 1299, "EUR", 7))
    );
}

#[test]
fn binding_changes_with_amount() {
    assert_ne!(
        dynamic_linking_binding(&req("Acme", 1299, "EUR", 7)),
        dynamic_linking_binding(&req("Acme", 1300, "EUR", 7)),
        "a changed amount MUST change the binding (dynamic linking)"
    );
}

#[test]
fn binding_changes_with_payee() {
    assert_ne!(
        dynamic_linking_binding(&req("Acme", 1299, "EUR", 7)),
        dynamic_linking_binding(&req("Evil Corp", 1299, "EUR", 7)),
        "a changed payee MUST change the binding (dynamic linking)"
    );
}

#[test]
fn binding_changes_with_currency_and_nonce() {
    let base = dynamic_linking_binding(&req("Acme", 1299, "EUR", 7));
    assert_ne!(base, dynamic_linking_binding(&req("Acme", 1299, "USD", 7)));
    assert_ne!(base, dynamic_linking_binding(&req("Acme", 1299, "EUR", 8)));
}
