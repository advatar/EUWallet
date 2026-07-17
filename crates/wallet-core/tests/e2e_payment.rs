//! Payment SCA driven through wallet-core::Core::handle_event with REAL crypto, proving the flow
//! is routed correctly (device signature → payment machine) and dynamically linked.
use crypto_backend::{AwsLc, SoftwareSigner};
use crypto_traits::{Alg, KeyRef, Signer, Verifier};
use payment::{dynamic_linking_binding, PaymentRequest};
use wallet_core::{Core, Effect, Event};

#[test]
fn payment_sca_through_wallet_core() {
    let device = SoftwareSigner::generate_p256().unwrap();
    let mut core = Core::new("wallet.example", "device-key");
    core.handle_event(Event::SetClock {
        epoch: 1_790_000_000,
    });

    // Payment request arrives.
    let request = br#"{"creditor_name":"Acme Store","creditor_account":"DE89370400440532013000","amount_minor":1299,"currency":"EUR","transaction_id":"txn-1","nonce":7,"response_uri":"https://psp.example/authorize"}"#.to_vec();
    let fx = core.handle_event(Event::PaymentAuthorizationRequestReceived { request });
    match fx.as_slice() {
        [Effect::Render { screen }] => match screen {
            presenter::ScreenDescription::PaymentConfirmation(p) => {
                assert_eq!(p.creditor_name, "Acme Store");
                assert_eq!(p.creditor_account, "DE89370400440532013000");
                assert_eq!(p.amount_minor, 1299);
                assert_eq!(p.currency, "EUR");
            }
            other => panic!("expected a payment confirmation screen, got {other:?}"),
        },
        other => panic!("expected Render, got {other:?}"),
    }

    // User approves → the core asks the device to sign (SCA).
    let fx = core.handle_event(Event::PaymentApproved);
    let binding = fx
        .iter()
        .find_map(|e| match e {
            Effect::Sign { payload, .. } => Some(payload.clone()),
            _ => None,
        })
        .expect("expected a Sign effect");

    // Device signs the dynamic-linking binding.
    let auth_code = device
        .sign(&KeyRef("device-key".into()), Alg::Es256, &binding)
        .unwrap();
    let fx = core.handle_event(Event::DeviceSignatureProduced {
        signature: auth_code.clone(),
    });
    let (url, body) = fx
        .iter()
        .find_map(|e| match e {
            Effect::Http { url, body } => Some((url.clone(), body.clone())),
            _ => None,
        })
        .expect("expected the auth code to be posted");
    assert_eq!(url, "https://psp.example/authorize");
    assert_eq!(body, auth_code);

    // The PSP verifies the code against the true transaction (real crypto), and dynamic linking
    // rejects any tampering.
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
    let tampered = PaymentRequest {
        amount_minor: 9999,
        ..actual
    };
    assert!(AwsLc
        .verify(
            Alg::Es256,
            device.public_key_raw(),
            &dynamic_linking_binding(&tampered),
            &auth_code
        )
        .is_err());
}
