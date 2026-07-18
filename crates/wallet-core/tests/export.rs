//! Data portability (TS10): the holder can export their own wallet data (credential + audit log)
//! as an integrity-protected bundle, and tampering with a saved export is detectable.

use crypto_backend::AwsLc;
use wallet_core::{Core, DemoWallet, Effect, Event, HeldCredential};

#[test]
fn export_round_trips_and_detects_tampering() {
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
        .unwrap();

    // Complete a presentation so the export carries both a credential and a log entry.
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
        .unwrap();
    core.handle_event(Event::DeviceSignatureProduced {
        signature: wallet.sign_device(payload),
    });
    core.handle_event(Event::PresentationDelivered);

    let export = core.export_json();

    // The bundle carries the holder's credential and the log entry.
    assert!(
        export.contains(&s.issuer_jwt),
        "credential material is exported"
    );
    assert!(export.contains("\"transactionLog\""));
    assert!(export.contains("rp.example"));
    assert!(export.contains("\"integrityHash\""));

    // A faithful export verifies.
    assert!(
        wallet_core::export::verify_export(&AwsLc, &export),
        "untampered export verifies"
    );
    assert!(
        wallet_core::verify_wallet_export(export.clone()),
        "same, via the FFI free fn"
    );

    // Tamper with a value in the saved bundle → integrity check fails.
    let tampered = export.replace("rp.example", "evil.example");
    assert_ne!(tampered, export);
    assert!(
        !wallet_core::export::verify_export(&AwsLc, &tampered),
        "tampering with an exported field is detected"
    );

    // Garbage isn't a valid export.
    assert!(!wallet_core::export::verify_export(&AwsLc, "{not json"));
}
