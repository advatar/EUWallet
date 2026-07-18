//! The transaction (audit) log records completed flows privacy-preservingly (TS06): claim PATHS
//! and a committing consent hash, never raw claim values. Driven through the real core with the
//! demo fixtures, exactly as the iOS app does.

use wallet_core::{Core, DemoWallet, Effect, Event, HeldCredential};

/// Drive a full presentation, then a full payment, and inspect the resulting audit log JSON.
#[test]
fn presentation_and_payment_are_logged_without_values() {
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
    core.load_trust_list(&s.trust_list, &s.operator_public_key).unwrap();

    // --- Presentation ---
    core.handle_event(Event::AuthorizationRequestReceived {
        request: s.presentation_request.clone(),
    });
    core.handle_event(Event::RpCertChainResolved {
        rp_cert_chain: s.rp_cert_chain.clone(),
        registered_redirect_uris: s.registered_redirect_uris.clone(),
    });
    let fx = core.handle_event(Event::UserConsented);
    let payload = fx
        .iter()
        .find_map(|e| match e {
            Effect::Sign { payload, .. } => Some(payload.clone()),
            _ => None,
        })
        .expect("sign");
    core.handle_event(Event::DeviceSignatureProduced {
        signature: wallet.sign_device(payload),
    });
    core.handle_event(Event::PresentationDelivered);

    // --- Payment ---
    core.handle_event(Event::PaymentAuthorizationRequestReceived {
        request: s.payment_request.clone(),
    });
    let fx = core.handle_event(Event::PaymentApproved);
    let binding = fx
        .iter()
        .find_map(|e| match e {
            Effect::Sign { payload, .. } => Some(payload.clone()),
            _ => None,
        })
        .expect("sign");
    core.handle_event(Event::DeviceSignatureProduced {
        signature: wallet.sign_device(binding),
    });

    // --- The log must hold exactly two tamper-evident entries. ---
    let log = core.transaction_log();
    assert_eq!(log.len(), 2, "one presentation + one payment");
    assert!(log.verify_integrity(&crypto_backend::AwsLc), "chain intact");

    let presentation = &log.entries()[0];
    assert_eq!(presentation.kind, txnlog::Kind::Presentation);
    assert_eq!(presentation.counterparty, "rp.example");
    assert_eq!(presentation.claim_paths, vec!["age_over_18".to_string()]); // path only
    assert_ne!(presentation.consent_hash, [0u8; 32], "consent hash committed");

    let payment = &log.entries()[1];
    assert_eq!(payment.kind, txnlog::Kind::Payment);
    let ps = payment.payment.as_ref().expect("payment summary");
    assert_eq!(ps.payee, "Acme Store");
    assert_eq!(ps.amount_minor, 1299);
    assert_eq!(ps.currency, "EUR");

    // The JSON the UI reads records paths + hashes, and NONE of the actual claim values.
    let json = core.transaction_log_json();
    assert!(json.contains("age_over_18"), "claim path present");
    assert!(json.contains("\"kind\":\"presentation\""));
    assert!(json.contains("\"kind\":\"payment\""));
    assert!(
        !json.contains("Andersson"),
        "the family_name VALUE must never appear in the audit log: {json}"
    );
}
