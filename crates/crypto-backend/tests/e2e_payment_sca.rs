//! End-to-end payment SCA with REAL crypto, proving PSD2 dynamic linking: the device signs the
//! dynamic-linking binding, a payment service verifies the authentication code against the actual
//! amount/payee with aws-lc-rs, and a tampered amount is rejected.
use crypto_backend::{AwsLc, SoftwareSigner};
use crypto_traits::{Alg, KeyRef, Signer, Verifier};
use payment::{dynamic_linking_binding, step, Env, Input, Output, PaymentRequest, State};

#[test]
fn payment_sca_dynamic_linking_end_to_end() {
    let device = SoftwareSigner::generate_p256().unwrap();
    let seen: Vec<u64> = vec![];
    let env = Env {
        seen_nonces: &seen,
        device_key_ref: "device-key",
    };

    let request = br#"{"creditor_name":"Acme Store","creditor_account":"DE89370400440532013000","amount_minor":1299,"currency":"EUR","transaction_id":"txn-1","nonce":7}"#.to_vec();

    // Machine: request → confirmation → approve → SignAuthCode(binding).
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

    // Device signs the binding (biometric-gated Secure Enclave in production).
    let auth_code = device
        .sign(&KeyRef("device-key".into()), Alg::Es256, &binding)
        .unwrap();
    let (s, out) = step(
        &s,
        &Input::AuthCodeSignatureProduced(auth_code.clone()),
        &env,
    );
    assert!(matches!(s, State::Authorized { .. }));
    assert!(out.contains(&Output::SendAuthorization(auth_code.clone())));

    // Payment service verifies the code against the ACTUAL transaction (real crypto).
    let actual = PaymentRequest {
        creditor_name: "Acme Store".into(),
        creditor_account: "DE89370400440532013000".into(),
        amount_minor: 1299,
        currency: "EUR".into(),
        transaction_id: "txn-1".into(),
        nonce: 7,
        response_uri: String::new(),
    };
    assert!(AwsLc
        .verify(
            Alg::Es256,
            device.public_key_raw(),
            &dynamic_linking_binding(&actual),
            &auth_code
        )
        .is_ok());

    // Dynamic linking: the SAME code against a tampered amount MUST fail.
    let tampered = PaymentRequest {
        amount_minor: 9999,
        ..actual.clone()
    };
    assert!(
        AwsLc
            .verify(
                Alg::Es256,
                device.public_key_raw(),
                &dynamic_linking_binding(&tampered),
                &auth_code
            )
            .is_err(),
        "a tampered amount must break the authentication code"
    );

    // ...and against a tampered payee.
    let tampered_payee = PaymentRequest {
        creditor_name: "Evil Corp".into(),
        ..actual
    };
    assert!(
        AwsLc
            .verify(
                Alg::Es256,
                device.public_key_raw(),
                &dynamic_linking_binding(&tampered_payee),
                &auth_code
            )
            .is_err(),
        "a tampered payee must break the authentication code"
    );
}
