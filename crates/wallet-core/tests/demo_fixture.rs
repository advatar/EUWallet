//! The demo fixtures ([`wallet_core::DemoWallet`]) must drive the SAME flows to completion that
//! the iOS simulator app drives over the FFI. If these pass, the app's on-simulator run is
//! exercising a genuine end-to-end flow (real crypto, real data minimisation, real trust), not a
//! scripted mock. Mirrors `e2e_flow.rs`/`e2e_payment.rs` but sourced entirely from the fixture.

use wallet_core::{Core, DemoWallet, Effect, Event, HeldCredential};

#[test]
fn demo_presentation_drives_to_done() {
    let wallet = DemoWallet::new();
    let s = wallet.scenario();

    let mut core = Core::new("wallet.example", "device-key");
    core.load_credential(HeldCredential {
        issuer_jwt: s.issuer_jwt.clone(),
        disclosures_by_claim: serde_json::from_str(&s.disclosures_by_claim_json).unwrap(),
        status_index: None,
    });
    core.load_device_key(s.device_public_key.clone());
    core.handle_event(Event::SetClock { epoch: s.epoch });
    core.load_trust_list(&s.trust_list, &s.operator_public_key)
        .expect("demo trusted list loads");

    // request → ResolveRpTrust
    let fx = core.handle_event(Event::AuthorizationRequestReceived {
        request: s.presentation_request.clone(),
    });
    assert!(
        matches!(fx.as_slice(), [Effect::ResolveRpTrust { .. }]),
        "expected ResolveRpTrust, got {fx:?}"
    );

    // cert chain resolved → Render(consent) with data minimisation (only age_over_18)
    let fx = core.handle_event(Event::RpCertChainResolved {
        rp_cert_chain: s.rp_cert_chain.clone(),
        registered_redirect_uris: s.registered_redirect_uris.clone(),
    });
    let consent = fx.iter().find_map(|e| match e {
        Effect::Render { screen } => Some(screen.clone()),
        _ => None,
    });
    match consent {
        Some(presenter::ScreenDescription::Consent(c)) => {
            assert_eq!(c.requested_claims, vec!["age_over_18".to_string()]);
        }
        other => panic!("expected a consent screen, got {other:?}"),
    }

    // consent → Sign, device signs, → Http(vp_token)
    let fx = core.handle_event(Event::UserConsented);
    let payload = fx
        .iter()
        .find_map(|e| match e {
            Effect::Sign { payload, .. } => Some(payload.clone()),
            _ => None,
        })
        .expect("expected a Sign effect");
    let signature = wallet.sign_device(payload);
    let fx = core.handle_event(Event::DeviceSignatureProduced { signature });
    assert!(
        fx.iter().any(|e| matches!(e, Effect::Http { .. })),
        "expected the vp_token to be posted, got {fx:?}"
    );

    // delivery → Close, Done
    let fx = core.handle_event(Event::PresentationDelivered);
    assert!(fx.iter().any(|e| matches!(e, Effect::Close)));
    assert_eq!(core.state(), &oid4vp::State::Done);
}

#[test]
fn demo_payment_drives_to_signed_auth_code() {
    let wallet = DemoWallet::new();
    let s = wallet.scenario();

    let mut core = Core::new("wallet.example", "device-key");
    core.handle_event(Event::SetClock { epoch: s.epoch });

    // request → Render(paymentConfirmation)
    let fx = core.handle_event(Event::PaymentAuthorizationRequestReceived {
        request: s.payment_request.clone(),
    });
    match fx.as_slice() {
        [Effect::Render { screen }] => match screen {
            presenter::ScreenDescription::PaymentConfirmation(p) => {
                assert_eq!(p.creditor_name, "Acme Store");
                assert_eq!(p.amount_minor, 1299);
                assert_eq!(p.currency, "EUR");
            }
            other => panic!("expected a payment confirmation, got {other:?}"),
        },
        other => panic!("expected a single Render, got {other:?}"),
    }

    // approve → Sign(SCA binding), device signs → Http(auth code)
    let fx = core.handle_event(Event::PaymentApproved);
    let binding = fx
        .iter()
        .find_map(|e| match e {
            Effect::Sign { payload, .. } => Some(payload.clone()),
            _ => None,
        })
        .expect("expected a Sign effect for the SCA binding");
    let auth_code = wallet.sign_device(binding);
    let fx = core.handle_event(Event::DeviceSignatureProduced {
        signature: auth_code,
    });
    assert!(
        fx.iter().any(|e| matches!(e, Effect::Http { .. })),
        "expected the auth code to be posted, got {fx:?}"
    );
}
