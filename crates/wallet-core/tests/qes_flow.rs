//! QES is now a first-class wallet-core flow: a document-signing request drives a
//! sign-confirmation screen, and after the holder authorizes, the device signature is routed to
//! the QES machine and the authorization is emitted to the QTSP. Driven through the real core.

use wallet_core::{Core, Effect, Event};

#[test]
fn qes_flow_renders_confirmation_then_signs_and_delivers() {
    let mut core = Core::new("wallet.example", "device-key");
    core.handle_event(Event::SetClock {
        epoch: 1_790_000_000,
    });

    // A document-signing request → the sign-confirmation screen (WYSIWYS).
    let request =
        br#"{"document_name":"Contract.pdf","document_hash_hex":"deadbeef","qtsp_id":"qtsp.example","nonce":1}"#
            .to_vec();
    let fx = core.handle_event(Event::QesSignRequestReceived { request });
    let is_sign_screen = fx.iter().any(|e| {
        matches!(e, Effect::Render { screen }
            if matches!(screen, presenter::ScreenDescription::SignConfirmation(_)))
    });
    assert!(
        is_sign_screen,
        "expected a QES sign-confirmation screen, got {fx:?}"
    );

    // Authorize → the core asks the device to sign the DTBS/R.
    let fx = core.handle_event(Event::QesAuthorized);
    let signing_input = fx
        .iter()
        .find_map(|e| match e {
            Effect::Sign { payload, .. } => Some(payload.clone()),
            _ => None,
        })
        .expect("expected a Sign effect");
    assert!(!signing_input.is_empty());

    // Device signs → the authorization is posted to the QTSP (CSC API) and the flow closes.
    let fx = core.handle_event(Event::DeviceSignatureProduced {
        signature: vec![0xAB; 64],
    });
    assert!(
        fx.iter().any(|e| matches!(e, Effect::Http { .. })),
        "expected the authorization to be delivered to the QTSP, got {fx:?}"
    );
}
