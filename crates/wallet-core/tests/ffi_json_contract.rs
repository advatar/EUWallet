//! Locks the JSON wire contract between the Rust core and the iOS shell for the presentation
//! path, driven exactly as the `EffectExecutor` drives it. This is the regression test for the
//! camelCase field-name contract: struct-variant fields (`client_id`/`rp_cert_chain`/`key_ref`)
//! MUST serialise as camelCase (`clientId`/`rpCertChain`/`keyRef`), or the shell's `WalletEffect`
//! / `Event` codecs silently fail to parse. Single-word fields hid this before; multi-word ones
//! (RP trust resolution) expose it.
use wallet_core::{Core, DemoWallet};

fn byte_array(b: &[u8]) -> String {
    format!(
        "[{}]",
        b.iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .join(",")
    )
}

#[test]
fn presentation_json_contract_is_camel_case() {
    let wallet = DemoWallet::new();
    let s = wallet.scenario();
    let mut core = Core::new("wallet.example", "device-key");
    core.load_credential(wallet_core::HeldCredential {
        issuer_jwt: s.issuer_jwt.clone(),
        disclosures_by_claim: serde_json::from_str(&s.disclosures_by_claim_json).unwrap(),
        status_index: None,
    });
    core.load_device_key(s.device_public_key.clone());
    core.handle_event_json(&format!(r#"{{"type":"setClock","epoch":{}}}"#, s.epoch))
        .unwrap();
    core.load_trust_list(&s.trust_list, &s.operator_public_key)
        .unwrap();

    // request → ResolveRpTrust, with a camelCase `clientId` field.
    let out = core
        .handle_event_json(&format!(
            r#"{{"type":"authorizationRequestReceived","request":{}}}"#,
            byte_array(&s.presentation_request)
        ))
        .unwrap();
    assert!(
        out.contains(r#""clientId""#),
        "expected camelCase clientId, got: {out}"
    );
    assert!(!out.contains("client_id"), "leaked snake_case field: {out}");

    // The shell echoes the RP cert chain via a camelCase `rpCertChain` event field; the core must
    // accept it and emit a consent render minimised to the one requested-and-held claim.
    let certs = s
        .rp_cert_chain
        .iter()
        .map(|c| byte_array(c))
        .collect::<Vec<_>>()
        .join(",");
    let out = core
        .handle_event_json(&format!(
            r#"{{"type":"rpCertChainResolved","rpCertChain":[{certs}],"registeredRedirectUris":["https://rp.example/response"]}}"#
        ))
        .unwrap();
    assert!(
        out.contains(r#""render""#),
        "expected a render effect, got: {out}"
    );
    assert!(
        out.contains(r#""screen":"consent""#),
        "expected a consent screen, got: {out}"
    );
    assert!(
        out.contains(r#""age_over_18""#),
        "expected the minimised claim, got: {out}"
    );
}
