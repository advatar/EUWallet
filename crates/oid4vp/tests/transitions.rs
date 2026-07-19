//! oid4vp transition tests (plan Section 5.1): the happy path plus EVERY abort path, each mapped
//! to the guard that trips it. Crypto is a stub over crypto-traits.
use crypto_traits::{Alg, CryptoError, Digest, Verifier};
use oid4vp::{
    step, AbortReason, AuthRequest, Env, Input, Output, ResolvedTrust, SelectedCredential, State,
};

struct Accept;
impl Verifier for Accept {
    fn verify(&self, _a: Alg, _pk: &[u8], _m: &[u8], _s: &[u8]) -> Result<(), CryptoError> {
        Ok(())
    }
}
struct Reject;
impl Verifier for Reject {
    fn verify(&self, _a: Alg, _pk: &[u8], _m: &[u8], _s: &[u8]) -> Result<(), CryptoError> {
        Err(CryptoError::Backend("no".into()))
    }
}
struct StubDigest;
impl Digest for StubDigest {
    fn sha256(&self, _data: &[u8]) -> [u8; 32] {
        [0u8; 32]
    }
}

fn req() -> AuthRequest {
    AuthRequest {
        client_id: "rp.example".into(),
        nonce: 42,
        audience: "wallet.example".into(),
        response_uri: "https://rp.example/resp".into(),
        redirect_uri: None,
        purpose: Some("age verification".into()),
        requested_claims: vec!["age_over_18".into()],
        state: None,
        response_mode: "direct_post".into(),
        dcql_id: None,
        requested_vcts: vec![],
        requested_doctypes: vec![],
        response_encryption_key: None,
        signed_payload: b"request-object".to_vec(),
        signature: b"sig".to_vec(),
        request_alg: Alg::Es256,
    }
}

fn trust() -> ResolvedTrust {
    ResolvedTrust {
        registered: true,
        rp_public_key: b"rp-pub".to_vec(),
        registered_redirect_uris: vec![],
    }
}

fn env<'a>(seen: &'a [u64], v: &'a dyn Verifier, d: &'a dyn Digest) -> Env<'a> {
    Env {
        wallet_client_id: "wallet.example",
        seen_nonces: seen,
        verifier: v,
        digest: d,
        now_epoch: 1_790_000_000,
        selected_credential: None,
        device_key_ref: "device-key",
    }
}

#[test]
fn happy_path_idle_free_to_done() {
    let seen: Vec<u64> = vec![];
    let cred = SelectedCredential::SdJwt {
        issuer_jwt: "hdr.pay.sig".into(),
        disclosures: vec!["disc1".into()],
    };
    let e = Env {
        wallet_client_id: "wallet.example",
        seen_nonces: &seen,
        verifier: &Accept,
        digest: &StubDigest,
        now_epoch: 1_790_000_000,
        selected_credential: Some(&cred),
        device_key_ref: "device-key",
    };

    // ResolvingTrust -> RequestValidated with PersistNonce + RenderConsent.
    let (s, out) = step(
        &State::ResolvingTrust(Box::new(req())),
        &Input::RpTrustResolved(trust()),
        &e,
    );
    assert!(matches!(s, State::RequestValidated(_)));
    assert_eq!(
        out,
        vec![
            Output::PersistNonce(42),
            Output::RenderConsent {
                rp_client_id: "rp.example".into(),
                purpose: "age verification".into()
            }
        ]
    );

    // Consent -> AwaitingDeviceSignature, emitting a device-signing effect. Nothing has left yet.
    let (s, out) = step(&s, &Input::ConsentGranted, &e);
    assert!(matches!(s, State::AwaitingDeviceSignature(_)));
    assert_eq!(out.len(), 1);
    assert!(matches!(out[0], Output::SignKeyBinding { .. }));

    // Device signature arrives -> Presenting, emitting the assembled vp_token.
    let (s, out) = step(&s, &Input::DeviceSignatureProduced(vec![0xAB; 64]), &e);
    assert_eq!(s, State::Presenting);
    match &out[0] {
        Output::SendVpToken(token) => {
            let t = String::from_utf8(token.clone()).unwrap();
            // direct_post body; this req() has no DCQL id → the bare presentation under vp_token.
            // vp_token = <issuer-jwt>~<disclosure>~<kb-jwt>
            assert!(t.starts_with("vp_token=hdr.pay.sig~disc1~"), "form body, got {t}");
            assert_eq!(t.matches('~').count(), 2);
        }
        other => panic!("expected SendVpToken, got {other:?}"),
    }

    // Delivered -> Done.
    let (s, out) = step(&s, &Input::PresentationDelivered, &e);
    assert_eq!(s, State::Done);
    assert_eq!(out, vec![Output::Close]);
}

fn resolve_with(
    mutate: impl FnOnce(&mut AuthRequest, &mut ResolvedTrust),
    seen: &[u64],
    v: &dyn Verifier,
    wallet_id: &str,
) -> State {
    let mut r = req();
    let mut t = trust();
    mutate(&mut r, &mut t);
    let e = Env {
        wallet_client_id: wallet_id,
        seen_nonces: seen,
        verifier: v,
        digest: &StubDigest,
        now_epoch: 1_790_000_000,
        selected_credential: None,
        device_key_ref: "device-key",
    };
    step(
        &State::ResolvingTrust(Box::new(r)),
        &Input::RpTrustResolved(t),
        &e,
    )
    .0
}

#[test]
fn abort_rp_not_registered() {
    let s = resolve_with(|_, t| t.registered = false, &[], &Accept, "wallet.example");
    assert_eq!(s, State::Aborted(AbortReason::RelyingPartyNotRegistered));
}

#[test]
fn abort_redirect_not_registered() {
    let s = resolve_with(
        |r, _| r.redirect_uri = Some("https://evil.example".into()),
        &[],
        &Accept,
        "wallet.example",
    );
    assert_eq!(s, State::Aborted(AbortReason::RedirectUriNotRegistered));
}

#[test]
fn abort_audience_mismatch() {
    let s = resolve_with(|_, _| {}, &[], &Accept, "other.wallet");
    assert_eq!(s, State::Aborted(AbortReason::AudienceMismatch));
}

#[test]
fn abort_purpose_undeclared() {
    let s = resolve_with(|r, _| r.purpose = None, &[], &Accept, "wallet.example");
    assert_eq!(s, State::Aborted(AbortReason::PurposeUndeclared));
}

#[test]
fn abort_nonce_replayed() {
    let s = resolve_with(|_, _| {}, &[42], &Accept, "wallet.example");
    assert_eq!(s, State::Aborted(AbortReason::NonceReplayed));
}

#[test]
fn abort_unsigned_request() {
    // signature present but verifier rejects → not signed/bound
    let s = resolve_with(|_, _| {}, &[], &Reject, "wallet.example");
    assert_eq!(s, State::Aborted(AbortReason::RequestNotSignedOrBound));
}

#[test]
fn abort_empty_signature() {
    let s = resolve_with(|r, _| r.signature.clear(), &[], &Accept, "wallet.example");
    assert_eq!(s, State::Aborted(AbortReason::RequestNotSignedOrBound));
}

#[test]
fn consent_declined_aborts_without_disclosure() {
    let seen: Vec<u64> = vec![];
    let e = env(&seen, &Accept, &StubDigest);
    let (s, out) = step(
        &State::RequestValidated(Box::new(req())),
        &Input::ConsentDeclined,
        &e,
    );
    assert_eq!(s, State::Aborted(AbortReason::UserDeclined));
    assert_eq!(out, vec![Output::Close]);
}

#[test]
fn malformed_request_aborts() {
    let seen: Vec<u64> = vec![];
    let e = env(&seen, &Accept, &StubDigest);
    let (s, _) = step(
        &State::Idle,
        &Input::AuthorizationRequest(vec![0xff, 0xff]),
        &e,
    );
    assert_eq!(s, State::Aborted(AbortReason::MalformedRequest));
}
