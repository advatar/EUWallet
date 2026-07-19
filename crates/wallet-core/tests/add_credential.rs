//! "Add a credential" driven through the real core: a wallet that starts EMPTY is issued two
//! DIFFERENT credentials (a PID and an mDL) via the full OpenID4VCI machine — in-core issuer-trust
//! decision, WUA key-attestation gate, device-signed proof-of-possession — then holds BOTH and can
//! present the one that data-minimally satisfies a request. This is the core-level evidence behind
//! the iOS "Add credential" button; only the (stubbed) issuer transport is not a live socket.

use wallet_core::{Core, DemoWallet, Effect, Event, IssuanceScenario};

/// Run ONE pre-authorized OID4VCI issuance to completion against `core`. `wallet` supplies the
/// device signature over the proof — the same key the loaded WUA attests, so the in-core
/// attestation gate is real. The (stub) issuer hands back `credential_compact`.
fn add_credential(
    core: &mut Core,
    wallet: &DemoWallet,
    scn: &IssuanceScenario,
    c_nonce: u64,
    credential_compact: &str,
) {
    // Offer → the core decides issuer trust in-core → RequestToken.
    let fx = core.handle_event(Event::CredentialOfferReceived {
        offer: scn.offer.clone(),
        issuer_cert_chain: scn.issuer_cert_chain.clone(),
        issuer_id: scn.issuer_id.clone(),
    });
    assert!(
        fx.contains(&Effect::RequestToken),
        "trusted issuer should proceed to token, got {fx:?}"
    );

    // Token (stub) → the core requires proof_key_attested (in-core WUA check) → Sign the proof.
    let fx = core.handle_event(Event::TokenReceived {
        bound: true,
        c_nonce,
    });
    let signing_input = sign_payload(&fx).expect("attested proof key → Sign effect");

    // Device signs (demo key stands in for the Secure Enclave) → RequestCredential.
    let sig = wallet.sign_device(signing_input);
    let fx = core.handle_event(Event::DeviceSignatureProduced { signature: sig });
    assert!(
        fx.iter()
            .any(|e| matches!(e, Effect::RequestCredential { .. })),
        "signed proof → RequestCredential, got {fx:?}"
    );

    // The issuer (stub) returns the issuer-signed credential → issued & stored as a holding.
    let fx = core.handle_event(Event::CredentialReceived {
        format: "dc+sd-jwt".into(),
        bytes: credential_compact.as_bytes().to_vec(),
    });
    assert!(fx.iter().any(|e| matches!(e, Effect::Close)));
}

/// The payload of the first `Sign` effect in `fx`, if any.
fn sign_payload(fx: &[Effect]) -> Option<Vec<u8>> {
    fx.iter().find_map(|e| match e {
        Effect::Sign { payload, .. } => Some(payload.clone()),
        _ => None,
    })
}

fn issuance_ready_core(scn: &IssuanceScenario) -> Core {
    let mut core = Core::new("wallet.example", "device-key");
    core.handle_event(Event::SetClock { epoch: scn.epoch });
    core.load_device_key(scn.device_public_key.clone());
    core.load_trust_list(&scn.trust_list, &scn.operator_public_key)
        .expect("trust list loads");
    core.load_wua(&scn.wua_jwt, &scn.wallet_provider_public_key)
        .expect("WUA verifies and binds the device key");
    core
}

#[test]
fn empty_wallet_gains_two_distinct_credentials_then_presents_one() {
    let wallet = DemoWallet::new();
    let scn = wallet.issuance_scenario();
    let mut core = issuance_ready_core(&scn);

    // The wallet starts empty.
    assert_eq!(core.held_credentials_json(), "[]", "fresh wallet holds nothing");

    // ---- Add the PID. ----
    add_credential(&mut core, &wallet, &scn, 111, &scn.pid_credential_compact);
    let held = core.held_credentials_json();
    assert!(held.contains("urn:eudi:pid:1"), "PID now held: {held}");
    assert!(
        held.contains("https://issuer.example"),
        "issuer surfaced for the card: {held}"
    );

    // ---- Add the mDL (a fresh c_nonce; the core rejects a replayed one). ----
    add_credential(&mut core, &wallet, &scn, 222, &scn.mdl_credential_compact);
    let held = core.held_credentials_json();
    assert!(
        held.contains("urn:eudi:pid:1") && held.contains("urn:eudi:mdl:1"),
        "both credentials held after two issuances: {held}"
    );

    // Re-issuing the SAME credential does not duplicate the holding.
    add_credential(&mut core, &wallet, &scn, 333, &scn.pid_credential_compact);
    assert_eq!(
        core.held_credentials_json().matches("urn:eudi:pid:1").count(),
        1,
        "re-issuing the PID is idempotent in the holdings"
    );

    // ---- Add a passport (a third, document-shaped type with its own claims). ----
    add_credential(&mut core, &wallet, &scn, 444, &scn.passport_credential_compact);
    let held = core.held_credentials_json();
    assert!(held.contains("urn:eudi:passport:1"), "passport held: {held}");
    assert!(
        held.contains("document_number") && held.contains("nationality"),
        "passport carries its discriminating claims: {held}"
    );

    // ---- Present age_over_18: the core selects a holding that satisfies it and minimises. ----
    let s = wallet.scenario(); // RP-signed request for age_over_18, bound to this wallet's keys
    let fx = core.handle_event(Event::AuthorizationRequestReceived {
        request: s.presentation_request.clone(),
    });
    assert!(
        matches!(fx.as_slice(), [Effect::ResolveRpTrust { .. }]),
        "request → resolve RP trust, got {fx:?}"
    );
    let fx = core.handle_event(Event::RpCertChainResolved {
        rp_cert_chain: s.rp_cert_chain.clone(),
        registered_redirect_uris: s.registered_redirect_uris.clone(),
    });
    let screen = fx
        .iter()
        .find_map(|e| match e {
            Effect::Render { screen } => Some(screen.clone()),
            _ => None,
        })
        .expect("consent screen rendered");
    match screen {
        presenter::ScreenDescription::Consent(c) => assert_eq!(
            c.requested_claims,
            vec!["age_over_18".to_string()],
            "minimised to the single requested-and-held claim"
        ),
        other => panic!("expected consent, got {other:?}"),
    }

    // Consent → device signs the KB-JWT → the assembled vp_token is delivered to the RP.
    let fx = core.handle_event(Event::UserConsented);
    let signing_input = sign_payload(&fx).expect("consent → Sign the KB-JWT");
    let fx = core.handle_event(Event::DeviceSignatureProduced {
        signature: wallet.sign_device(signing_input),
    });
    let vp = fx.iter().find_map(|e| match e {
        Effect::Http { body, .. } => Some(String::from_utf8(body.clone()).unwrap()),
        _ => None,
    });
    let vp = vp.expect("a vp_token is posted to the RP");
    assert!(
        vp.contains('~'),
        "the delivered vp_token is an SD-JWT presentation"
    );
}
