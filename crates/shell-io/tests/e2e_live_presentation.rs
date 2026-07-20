//! The reference shell speaks plaintext HTTP only for local protocol testing. OpenID4VP delivery,
//! however, is security-sensitive and the core must reject such an endpoint before consent or any
//! network effect. This regression locks that production policy at the shell boundary.

use presenter::ScreenDescription;
use shell_io::{DeviceSigner, ShellRunner, TrustFetcher};
use wallet_core::{Core, DemoWallet, Event, HeldCredential};

struct DemoSigner<'a>(&'a DemoWallet);
impl DeviceSigner for DemoSigner<'_> {
    fn sign(&self, _key_ref: &str, payload: &[u8]) -> Vec<u8> {
        self.0.sign_device(payload.to_vec())
    }
}

struct DemoTrust {
    chain: Vec<Vec<u8>>,
    uris: Vec<String>,
}
impl TrustFetcher for DemoTrust {
    fn fetch(&self, _client_id: &str) -> (Vec<Vec<u8>>, Vec<String>) {
        (self.chain.clone(), self.uris.clone())
    }
}

#[test]
fn plaintext_http_presentation_endpoint_is_rejected_before_disclosure() {
    let wallet = DemoWallet::new();
    let s = wallet.scenario_with_response_uri("http://127.0.0.1:1/response");

    let mut core = Core::new("wallet.example", "device-key");
    core.load_unverified_credential_for_testing(HeldCredential {
        issuer_jwt: s.issuer_jwt.clone(),
        disclosures_by_claim: serde_json::from_str(&s.disclosures_by_claim_json).unwrap(),
        status_index: None,
    });
    core.load_device_key(s.device_public_key.clone());
    core.handle_event(Event::SetClock { epoch: s.epoch });
    core.load_trust_list(&s.trust_list, &s.operator_public_key)
        .expect("trust list loads");

    let mut shell = ShellRunner::new(
        core,
        DemoSigner(&wallet),
        DemoTrust {
            chain: s.rp_cert_chain.clone(),
            uris: s.registered_redirect_uris.clone(),
        },
    );

    let outcome = shell.handle(Event::AuthorizationRequestReceived {
        request: s.presentation_request.clone(),
    });
    assert!(outcome.errors.is_empty(), "{:?}", outcome.errors);
    assert!(
        outcome.http_posts.is_empty(),
        "unsafe endpoint must never be contacted"
    );
    assert!(
        outcome.persisted_nonces.is_empty(),
        "rejected requests are not persisted"
    );
    assert!(outcome.closed, "the deterministic error closes the flow");
    assert_eq!(
        shell.core.state(),
        &oid4vp::State::Aborted(oid4vp::AbortReason::ResponseUriInvalid)
    );
    assert!(matches!(
        shell.last_screen(),
        Some(ScreenDescription::Error { code, .. })
            if code == "presentation_response_uri_invalid"
    ));
}
