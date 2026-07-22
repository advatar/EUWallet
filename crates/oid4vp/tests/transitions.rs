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
        nonce: "42".into(),
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
        dcql: None,
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
        registered_redirect_uris: vec!["https://rp.example/resp".into()],
        leaf_dns_sans: vec![],
    }
}

fn env<'a>(seen: &'a [String], v: &'a dyn Verifier, d: &'a dyn Digest) -> Env<'a> {
    Env {
        wallet_client_id: "wallet.example",
        seen_nonces: seen,
        verifier: v,
        digest: d,
        now_epoch: 1_790_000_000,
        selected_credentials: &[],
        device_key_ref: "device-key",
    }
}

#[test]
fn happy_path_idle_free_to_done() {
    let seen: Vec<String> = vec![];
    let creds = [SelectedCredential::SdJwt {
        issuer_jwt: "hdr.pay.sig".into(),
        disclosures: vec!["disc1".into()],
        dcql_id: None,
    }];
    let e = Env {
        wallet_client_id: "wallet.example",
        seen_nonces: &seen,
        verifier: &Accept,
        digest: &StubDigest,
        now_epoch: 1_790_000_000,
        selected_credentials: &creds,
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
            Output::PersistNonce("42".into()),
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
            assert!(
                t.starts_with("vp_token=hdr.pay.sig~disc1~"),
                "form body, got {t}"
            );
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
    seen: &[String],
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
        selected_credentials: &[],
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
fn aborts_every_unsupported_response_mode_exactly() {
    for mode in [
        "",
        "Direct_Post",
        "direct_post.jwt.extra",
        "query",
        "fragment",
    ] {
        let s = resolve_with(
            |r, _| r.response_mode = mode.into(),
            &[],
            &Accept,
            "wallet.example",
        );
        assert_eq!(
            s,
            State::Aborted(AbortReason::ResponseModeUnsupported),
            "mode {mode:?} must not fall through"
        );
    }
}

#[test]
fn accepts_only_nonempty_absolute_https_response_uris() {
    for uri in [
        "",
        "http://rp.example/resp",
        "https:///resp",
        "https://user@rp.example/resp",
        "https://rp.example/resp#fragment",
        "https://rp.example\\resp",
        "https://rp.example:0/resp",
        "https://rp.example:/resp",
        "https://bad_host.example/resp",
        "https://[not-ipv6]/resp",
        "/relative",
    ] {
        let s = resolve_with(
            |r, t| {
                r.response_uri = uri.into();
                t.registered_redirect_uris = vec![uri.into()];
            },
            &[],
            &Accept,
            "wallet.example",
        );
        assert_eq!(
            s,
            State::Aborted(AbortReason::ResponseUriInvalid),
            "URI {uri:?} must not be accepted"
        );
    }
}

#[test]
fn abort_response_uri_not_registered_for_rp() {
    let s = resolve_with(
        |r, t| {
            r.response_uri = "https://other.example/resp".into();
            t.registered_redirect_uris = vec!["https://rp.example/resp".into()];
        },
        &[],
        &Accept,
        "wallet.example",
    );
    assert_eq!(s, State::Aborted(AbortReason::ResponseUriNotRegistered));
}

#[test]
fn direct_post_jwt_requires_well_formed_key_metadata() {
    for key in [
        None,
        Some(vec![]),
        Some(vec![0x04; 64]),
        Some(vec![0x03; 65]),
    ] {
        let s = resolve_with(
            |r, _| {
                r.response_mode = "direct_post.jwt".into();
                r.response_encryption_key = key;
            },
            &[],
            &Accept,
            "wallet.example",
        );
        assert_eq!(
            s,
            State::Aborted(AbortReason::ResponseEncryptionMetadataInvalid)
        );
    }

    let s = resolve_with(
        |r, _| {
            r.response_mode = "direct_post.jwt".into();
            r.response_encryption_key = Some(vec![0x04; 65]);
        },
        &[],
        &Accept,
        "wallet.example",
    );
    assert!(matches!(s, State::RequestValidated(_)));
}

#[test]
fn abort_audience_mismatch() {
    let s = resolve_with(|_, _| {}, &[], &Accept, "other.wallet");
    assert_eq!(s, State::Aborted(AbortReason::AudienceMismatch));
}

#[test]
fn request_without_top_level_purpose_is_accepted() {
    // OpenID4VP 1.0 has NO mandatory top-level `purpose` request parameter; a conformant request
    // that omits it must be accepted (previously it aborted with PurposeUndeclared).
    let s = resolve_with(|r, _| r.purpose = None, &[], &Accept, "wallet.example");
    assert!(matches!(s, State::RequestValidated(_)), "got {s:?}");
}

#[test]
fn x509_san_dns_client_id_binds_to_the_authenticated_leaf() {
    // §5.10: an `x509_san_dns:<host>` client_id whose host is a SAN of the RP leaf is accepted.
    let s = resolve_with(
        |r, t| {
            r.client_id = "x509_san_dns:verifier.example".into();
            t.leaf_dns_sans = vec!["verifier.example".into()];
        },
        &[],
        &Accept,
        "wallet.example",
    );
    assert!(matches!(s, State::RequestValidated(_)), "got {s:?}");
}

#[test]
fn x509_san_dns_client_id_not_matching_the_leaf_is_rejected() {
    // The signature verifies (same RP-CA domain), but the claimed host is not a SAN of the leaf →
    // impersonation → abort before consent.
    let s = resolve_with(
        |r, t| {
            r.client_id = "x509_san_dns:evil.example".into();
            t.leaf_dns_sans = vec!["verifier.example".into()];
        },
        &[],
        &Accept,
        "wallet.example",
    );
    assert_eq!(s, State::Aborted(AbortReason::ClientIdBindingInvalid));
}

#[test]
fn abort_nonce_replayed() {
    let s = resolve_with(|_, _| {}, &["42".to_string()], &Accept, "wallet.example");
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
    let seen: Vec<String> = vec![];
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
    let seen: Vec<String> = vec![];
    let e = env(&seen, &Accept, &StubDigest);
    let (s, _) = step(
        &State::Idle,
        &Input::AuthorizationRequest(vec![0xff, 0xff]),
        &e,
    );
    assert_eq!(s, State::Aborted(AbortReason::MalformedRequest));
}
