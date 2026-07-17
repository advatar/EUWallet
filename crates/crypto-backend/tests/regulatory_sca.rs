//! Regulatory SCA test-case suite — the payment "completion evidence" the register calls for
//! ("dynamic-linking and SCA regulatory test cases"). Each test names the PSD2 RTS (Commission
//! Delegated Regulation (EU) 2018/389) requirement it exercises, with REAL aws-lc-rs crypto.
//!
//! These map the wallet's payment SCA behaviour to the regulation so an assessor can trace each
//! article to a passing test.
use crypto_backend::{AwsLc, SoftwareSigner};
use crypto_traits::{Alg, KeyRef, Signer, Verifier};
use payment::{dynamic_linking_binding, step, Env, Input, Output, PaymentRequest, State};

fn request_json(
    name: &str,
    account: &str,
    amount: u64,
    currency: &str,
    txn: &str,
    nonce: u64,
) -> Vec<u8> {
    format!(
        r#"{{"creditor_name":"{name}","creditor_account":"{account}","amount_minor":{amount},"currency":"{currency}","transaction_id":"{txn}","nonce":{nonce}}}"#
    )
    .into_bytes()
}

fn base_request() -> Vec<u8> {
    request_json(
        "Acme Store",
        "DE89370400440532013000",
        1299,
        "EUR",
        "txn-1",
        7,
    )
}

fn base_parsed() -> PaymentRequest {
    PaymentRequest {
        creditor_name: "Acme Store".into(),
        creditor_account: "DE89370400440532013000".into(),
        amount_minor: 1299,
        currency: "EUR".into(),
        transaction_id: "txn-1".into(),
        nonce: 7,
        response_uri: String::new(),
    }
}

/// Drive the machine to a device-signed authentication code with the given device key.
fn produce_auth_code(device: &SoftwareSigner, request: Vec<u8>) -> (Vec<u8>, Vec<Output>) {
    let seen: Vec<u64> = vec![];
    let env = Env {
        seen_nonces: &seen,
        device_key_ref: "device-key",
    };
    let (s, _) = step(
        &State::Idle,
        &Input::PaymentAuthorizationRequest(request),
        &env,
    );
    let (s, out) = step(&s, &Input::UserApproved, &env);
    let binding = match out.as_slice() {
        [Output::SignAuthCode { signing_input, .. }] => signing_input.clone(),
        other => panic!("expected SignAuthCode, got {other:?}"),
    };
    let sig = device
        .sign(&KeyRef("device-key".into()), Alg::Es256, &binding)
        .unwrap();
    let (_s, out) = step(&s, &Input::AuthCodeSignatureProduced(sig.clone()), &env);
    (sig, out)
}

// RTS Art. 4(1) — the SCA produces an authentication code that the payment service can verify.
#[test]
fn rts_art4_authentication_code_is_produced_and_verifiable() {
    let device = SoftwareSigner::generate_p256().unwrap();
    let (code, out) = produce_auth_code(&device, base_request());
    assert!(out.contains(&Output::SendAuthorization(code.clone())));
    assert!(AwsLc
        .verify(
            Alg::Es256,
            device.public_key_raw(),
            &dynamic_linking_binding(&base_parsed()),
            &code
        )
        .is_ok());
}

// RTS Art. 4(3)(b) — the code cannot be forged: one produced by a different key is rejected.
#[test]
fn rts_art4_code_cannot_be_forged() {
    let device = SoftwareSigner::generate_p256().unwrap();
    let attacker = SoftwareSigner::generate_p256().unwrap();
    let (_code, _) = produce_auth_code(&device, base_request());
    let forged = attacker
        .sign(
            &KeyRef("x".into()),
            Alg::Es256,
            &dynamic_linking_binding(&base_parsed()),
        )
        .unwrap();
    assert!(AwsLc
        .verify(
            Alg::Es256,
            device.public_key_raw(),
            &dynamic_linking_binding(&base_parsed()),
            &forged
        )
        .is_err());
}

// RTS Art. 5(1) — the payer is made aware of the amount and the payee: the dedicated confirmation
// screen carries the amount and the creditor (name AND account).
#[test]
fn rts_art5_1_payer_is_made_aware_of_amount_and_payee() {
    let seen: Vec<u64> = vec![];
    let env = Env {
        seen_nonces: &seen,
        device_key_ref: "device-key",
    };
    let (_s, out) = step(
        &State::Idle,
        &Input::PaymentAuthorizationRequest(base_request()),
        &env,
    );
    match out.as_slice() {
        [Output::RenderPaymentConfirmation {
            creditor_name,
            creditor_account,
            amount_minor,
            currency,
        }] => {
            assert_eq!(creditor_name, "Acme Store");
            assert_eq!(creditor_account, "DE89370400440532013000");
            assert_eq!(*amount_minor, 1299);
            assert_eq!(currency, "EUR");
        }
        other => panic!("expected a payment confirmation screen, got {other:?}"),
    }
}

// RTS Art. 5(1)(c) / 5(3) — dynamic linking: the code is specific to the amount; a change breaks it.
#[test]
fn rts_art5_dynamic_linking_amount() {
    let device = SoftwareSigner::generate_p256().unwrap();
    let (code, _) = produce_auth_code(&device, base_request());
    let tampered = PaymentRequest {
        amount_minor: 9999,
        ..base_parsed()
    };
    assert!(AwsLc
        .verify(
            Alg::Es256,
            device.public_key_raw(),
            &dynamic_linking_binding(&tampered),
            &code
        )
        .is_err());
}

// RTS Art. 5 — dynamic linking to the payee: a changed creditor NAME breaks the code.
#[test]
fn rts_art5_dynamic_linking_payee_name() {
    let device = SoftwareSigner::generate_p256().unwrap();
    let (code, _) = produce_auth_code(&device, base_request());
    let tampered = PaymentRequest {
        creditor_name: "Evil Corp".into(),
        ..base_parsed()
    };
    assert!(AwsLc
        .verify(
            Alg::Es256,
            device.public_key_raw(),
            &dynamic_linking_binding(&tampered),
            &code
        )
        .is_err());
}

// RTS Art. 5 — dynamic linking to the payee: a changed creditor ACCOUNT (IBAN) breaks the code.
// This is the strongest form — redirecting funds to a different account invalidates the code.
#[test]
fn rts_art5_dynamic_linking_payee_account() {
    let device = SoftwareSigner::generate_p256().unwrap();
    let (code, _) = produce_auth_code(&device, base_request());
    let tampered = PaymentRequest {
        creditor_account: "DE00000000000000000000".into(),
        ..base_parsed()
    };
    assert!(AwsLc
        .verify(
            Alg::Es256,
            device.public_key_raw(),
            &dynamic_linking_binding(&tampered),
            &code
        )
        .is_err());
}

// RTS Art. 5 — a changed currency breaks the code.
#[test]
fn rts_art5_dynamic_linking_currency() {
    let device = SoftwareSigner::generate_p256().unwrap();
    let (code, _) = produce_auth_code(&device, base_request());
    let tampered = PaymentRequest {
        currency: "USD".into(),
        ..base_parsed()
    };
    assert!(AwsLc
        .verify(
            Alg::Es256,
            device.public_key_raw(),
            &dynamic_linking_binding(&tampered),
            &code
        )
        .is_err());
}

// RTS Art. 5(2) — integrity/authenticity of the code: any corruption of the code fails verification.
#[test]
fn rts_art5_2_integrity_of_authentication_code() {
    let device = SoftwareSigner::generate_p256().unwrap();
    let (mut code, _) = produce_auth_code(&device, base_request());
    code[0] ^= 0xff;
    assert!(AwsLc
        .verify(
            Alg::Es256,
            device.public_key_raw(),
            &dynamic_linking_binding(&base_parsed()),
            &code
        )
        .is_err());
}

// RTS Art. 4 / 5 — transaction uniqueness: a replayed nonce is rejected before any code is produced.
#[test]
fn rts_transaction_uniqueness_replay_rejected() {
    let seen = vec![7u64]; // nonce 7 already used
    let env = Env {
        seen_nonces: &seen,
        device_key_ref: "device-key",
    };
    let (s, out) = step(
        &State::Idle,
        &Input::PaymentAuthorizationRequest(base_request()),
        &env,
    );
    assert_eq!(s, State::Aborted(payment::AbortReason::NonceReplayed));
    assert!(
        out.is_empty(),
        "no confirmation/authorisation for a replayed transaction"
    );
}

// SCA possession factor — no authentication code exists without the device signature (the code
// cannot be produced from the request alone; it requires the hardware key).
#[test]
fn sca_possession_factor_required() {
    let seen: Vec<u64> = vec![];
    let env = Env {
        seen_nonces: &seen,
        device_key_ref: "device-key",
    };
    let (s, _) = step(
        &State::Idle,
        &Input::PaymentAuthorizationRequest(base_request()),
        &env,
    );
    let (s, out) = step(&s, &Input::UserApproved, &env);
    // After approval we are awaiting the device signature; nothing is authorised yet.
    assert!(matches!(s, State::AwaitingSca(_)));
    assert!(!out
        .iter()
        .any(|o| matches!(o, Output::SendAuthorization(_))));
}
