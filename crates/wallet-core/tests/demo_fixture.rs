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
    core.load_unverified_credential_for_testing(HeldCredential {
        issuer_jwt: s.issuer_jwt.clone(),
        disclosures_by_claim: serde_json::from_str(&s.disclosures_by_claim_json).unwrap(),
        status: None,
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

/// The ARF-mandated mdoc half of the demo PID must issue AND store through the real OpenID4VCI
/// path — the same silent seed the iOS app runs before the SD-JWT half. This is a regression guard:
/// the mdoc PID previously lacked the mandatory `portrait` element, so issuance rejected it and the
/// holding never stored — invisibly, because the shell added it with a discarded result. Without a
/// stored PID mdoc, in-person (ISO 18013-5) and Digital Credentials API presentment cannot work.
#[test]
fn demo_pid_mdoc_issues_and_stores() {
    let wallet = DemoWallet::new();
    let s = wallet.issuance_scenario();

    let mut core = Core::new("wallet.example", "device-key");
    core.handle_event(Event::SetClock { epoch: s.epoch });
    core.load_device_key(s.device_public_key.clone());
    core.load_trust_list(&s.trust_list, &s.operator_public_key)
        .expect("demo trusted list loads");
    core.load_wua(&s.wua_jwt, &s.wallet_provider_public_key)
        .expect("demo WUA loads");

    // Offer (mso_mdoc) → issuance review → accept → RequestToken.
    let offer =
        br#"{"format":"mso_mdoc","grant":"pre-authorized","tx_code_required":false}"#.to_vec();
    let review = core.handle_event(Event::CredentialOfferReceived {
        offer,
        issuer_cert_chain: s.issuer_cert_chain.clone(),
        issuer_id: s.issuer_id.clone(),
    });
    assert!(matches!(
        review.as_slice(),
        [Effect::Render {
            screen: presenter::ScreenDescription::IssuanceOffer(_)
        }]
    ));
    let fx = core.handle_event(Event::CredentialOfferAccepted);
    assert!(
        fx.contains(&Effect::RequestToken),
        "expected RequestToken, got {fx:?}"
    );

    // Token → proof-of-possession Sign → device signs → RequestCredential.
    let fx = core.handle_event(Event::TokenReceived {
        bound: true,
        c_nonce: 111,
    });
    let signing_input = fx
        .iter()
        .find_map(|e| match e {
            Effect::Sign { payload, .. } => Some(payload.clone()),
            _ => None,
        })
        .expect("proof key attested → Sign effect");
    let proof_sig = wallet.sign_device(signing_input);
    let fx = core.handle_event(Event::DeviceSignatureProduced {
        signature: proof_sig,
    });
    assert!(
        fx.iter()
            .any(|e| matches!(e, Effect::RequestCredential { .. })),
        "expected RequestCredential, got {fx:?}"
    );

    // The demo PID mdoc is returned → must be authenticated and STORED, not rejected.
    let effects = core.handle_event(Event::CredentialReceived {
        format: "mso_mdoc".into(),
        bytes: s.pid_mdoc_credential.clone().into_bytes(),
    });
    assert!(
        !effects.iter().any(|e| matches!(
            e,
            Effect::Render {
                screen: presenter::ScreenDescription::Error { code, .. }
            } if code == "credential_issuance_rejected"
        )),
        "PID mdoc issuance must not be rejected, got {effects:?}"
    );
    assert!(effects.iter().any(|e| matches!(
        e,
        Effect::Render {
            screen: presenter::ScreenDescription::IssuanceReady(_)
        }
    )));
    // `Close` must be the terminal effect: the "ready" render precedes it and NOTHING follows it,
    // so the shell's drain reports `.succeeded` (not `.effectAfterClose`) for a stored credential.
    assert!(
        matches!(effects.last(), Some(Effect::Close)),
        "Close must be the final issuance effect, got {effects:?}"
    );
    let close_index = effects
        .iter()
        .position(|e| matches!(e, Effect::Close))
        .expect("a terminal Close");
    let ready_index = effects
        .iter()
        .position(|e| {
            matches!(
                e,
                Effect::Render {
                    screen: presenter::ScreenDescription::IssuanceReady(_)
                }
            )
        })
        .expect("an IssuanceReady render");
    assert!(
        ready_index < close_index,
        "IssuanceReady must be rendered before Close, got {effects:?}"
    );

    let held = core.held_credentials_json();
    assert!(held.contains("mso_mdoc"), "PID mdoc must be held: {held}");
    assert!(
        held.contains("eu.europa.ec.eudi.pid.1"),
        "held PID mdoc must carry the PID doctype: {held}"
    );
}
