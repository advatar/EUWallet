//! oid4vci transition tests (plan Section 5.2): both HAIP happy paths + every abort path.
use oid4vci::{step, AbortReason, CredentialFormat, Env, Input, Output, State};

fn env<'a>(seen: &'a [u64]) -> Env<'a> {
    Env {
        issuer_trusted: true,
        proof_key_attested: true,
        seen_c_nonces: seen,
        device_key_ref: "device-key",
        issuer_id: "https://issuer.example",
        now_epoch: 1_790_000_000,
    }
}

fn offer(grant: &str, format: &str, tx: bool) -> Vec<u8> {
    format!(r#"{{"format":"{format}","grant":"{grant}","tx_code_required":{tx}}}"#).into_bytes()
}

fn drive(state: &State, input: Input, seen: &[u64]) -> (State, Vec<Output>) {
    step(state, &input, &env(seen))
}

#[test]
fn happy_pre_authorized_no_pin_to_issued() {
    let seen: Vec<u64> = vec![];
    // Offer (pre-auth, no PIN) → RequestToken
    let (s, out) = drive(
        &State::Idle,
        Input::CredentialOffer(offer("pre-authorized", "dc+sd-jwt", false)),
        &seen,
    );
    assert!(matches!(s, State::RequestingToken { .. }));
    assert_eq!(out, vec![Output::RequestToken]);

    // Token (bound, fresh c_nonce, attested key) → SignProof
    let (s, out) = drive(
        &s,
        Input::TokenResponse {
            bound: true,
            c_nonce: 111,
        },
        &seen,
    );
    assert!(matches!(s, State::ProvingPossession { .. }));
    assert!(matches!(out.as_slice(), [Output::SignProof { .. }]));

    // Proof signed → RequestCredential
    let (s, out) = drive(&s, Input::ProofSignatureProduced(vec![0xAB; 64]), &seen);
    assert!(matches!(s, State::RequestingCredential { .. }));
    assert!(matches!(out.as_slice(), [Output::RequestCredential { .. }]));

    // Credential returned (valid SD-JWT VC) → CredentialIssued
    let cred = b"aGVhZGVy.cGF5bG9hZA.c2ln~".to_vec(); // <jwt>~ (parses as SD-JWT VC)
    let (s, out) = drive(
        &s,
        Input::CredentialResponse {
            format: CredentialFormat::DcSdJwt,
            bytes: cred,
            issuer_authenticated: true,
        },
        &seen,
    );
    assert!(matches!(
        s,
        State::CredentialIssued {
            format: CredentialFormat::DcSdJwt,
            ..
        }
    ));
    assert_eq!(out, vec![Output::Close]);
}

#[test]
fn happy_pre_authorized_with_pin() {
    let seen: Vec<u64> = vec![];
    let (s, out) = drive(
        &State::Idle,
        Input::CredentialOffer(offer("pre-authorized", "mso_mdoc", true)),
        &seen,
    );
    assert!(matches!(s, State::AwaitingTxCode { .. }));
    assert_eq!(out, vec![Output::PromptTxCode]);

    let (s, out) = drive(&s, Input::TxCodeEntered(b"1234".to_vec()), &seen);
    assert!(matches!(s, State::RequestingToken { .. }));
    assert_eq!(out, vec![Output::RequestToken]);
}

#[test]
fn happy_authorization_code_par_pkce() {
    let seen: Vec<u64> = vec![];
    let (s, out) = drive(
        &State::Idle,
        Input::CredentialOffer(offer("authorization_code", "dc+sd-jwt", false)),
        &seen,
    );
    assert!(matches!(s, State::OfferParsed { .. }));
    assert_eq!(out, vec![Output::PushPar]);

    let (s, out) = drive(&s, Input::ParPushed { pkce_s256: true }, &seen);
    assert!(matches!(s, State::Authorizing { .. }));
    assert_eq!(out, vec![Output::OpenAuthBrowser]);

    let (s, out) = drive(&s, Input::AuthCodeReturned(b"code".to_vec()), &seen);
    assert!(matches!(s, State::RequestingToken { .. }));
    assert_eq!(out, vec![Output::RequestToken]);
}

#[test]
fn abort_untrusted_issuer() {
    let seen: Vec<u64> = vec![];
    let e = Env {
        issuer_trusted: false,
        ..env(&seen)
    };
    let (s, _) = step(
        &State::Idle,
        &Input::CredentialOffer(offer("pre-authorized", "dc+sd-jwt", false)),
        &e,
    );
    assert_eq!(s, State::Aborted(AbortReason::IssuerNotTrusted));
}

#[test]
fn abort_unsupported_format() {
    let seen: Vec<u64> = vec![];
    let (s, _) = drive(
        &State::Idle,
        Input::CredentialOffer(offer("pre-authorized", "ldp_vc", false)),
        &seen,
    );
    assert_eq!(s, State::Aborted(AbortReason::UnsupportedGrant)); // parse fails on the format
}

#[test]
fn abort_unsupported_grant() {
    let seen: Vec<u64> = vec![];
    let (s, _) = drive(
        &State::Idle,
        Input::CredentialOffer(offer("client_credentials", "dc+sd-jwt", false)),
        &seen,
    );
    assert_eq!(s, State::Aborted(AbortReason::UnsupportedGrant));
}

#[test]
fn abort_pkce_missing() {
    let seen: Vec<u64> = vec![];
    let (s, _) = drive(
        &State::Idle,
        Input::CredentialOffer(offer("authorization_code", "dc+sd-jwt", false)),
        &seen,
    );
    let (s, _) = drive(&s, Input::ParPushed { pkce_s256: false }, &seen);
    assert_eq!(s, State::Aborted(AbortReason::PkceMissing));
}

#[test]
fn abort_tx_code_invalid() {
    let seen: Vec<u64> = vec![];
    let (s, _) = drive(
        &State::Idle,
        Input::CredentialOffer(offer("pre-authorized", "dc+sd-jwt", true)),
        &seen,
    );
    let (s, _) = drive(&s, Input::TxCodeEntered(vec![]), &seen);
    assert_eq!(s, State::Aborted(AbortReason::TxCodeInvalid));
}

fn to_requesting_token(seen: &[u64]) -> State {
    drive(
        &State::Idle,
        Input::CredentialOffer(offer("pre-authorized", "dc+sd-jwt", false)),
        seen,
    )
    .0
}

#[test]
fn abort_token_not_bound() {
    let seen: Vec<u64> = vec![];
    let s = to_requesting_token(&seen);
    let (s, _) = drive(
        &s,
        Input::TokenResponse {
            bound: false,
            c_nonce: 1,
        },
        &seen,
    );
    assert_eq!(s, State::Aborted(AbortReason::TokenNotBound));
}

#[test]
fn abort_c_nonce_replayed() {
    let seen = vec![42u64];
    let s = to_requesting_token(&seen);
    let (s, _) = drive(
        &s,
        Input::TokenResponse {
            bound: true,
            c_nonce: 42,
        },
        &seen,
    );
    assert_eq!(s, State::Aborted(AbortReason::CNonceStale));
}

#[test]
fn abort_proof_key_not_attested() {
    let seen: Vec<u64> = vec![];
    let s = to_requesting_token(&seen);
    let e = Env {
        proof_key_attested: false,
        ..env(&seen)
    };
    let (s, _) = step(
        &s,
        &Input::TokenResponse {
            bound: true,
            c_nonce: 7,
        },
        &e,
    );
    assert_eq!(s, State::Aborted(AbortReason::ProofKeyNotAttested));
}

#[test]
fn abort_credential_invalid() {
    let seen: Vec<u64> = vec![];
    let s = drive(
        &State::RequestingCredential {
            format: CredentialFormat::DcSdJwt,
        },
        Input::CredentialResponse {
            format: CredentialFormat::DcSdJwt,
            bytes: b"not-a-sd-jwt".to_vec(),
            issuer_authenticated: true,
        },
        &seen,
    )
    .0;
    assert_eq!(s, State::Aborted(AbortReason::CredentialInvalid));
}

#[test]
fn aborts_structurally_valid_but_unauthenticated_credential() {
    let seen: Vec<u64> = vec![];
    let (s, out) = drive(
        &State::RequestingCredential {
            format: CredentialFormat::DcSdJwt,
        },
        Input::CredentialResponse {
            format: CredentialFormat::DcSdJwt,
            bytes: b"aGVhZGVy.cGF5bG9hZA.c2ln~".to_vec(),
            issuer_authenticated: false,
        },
        &seen,
    );
    assert_eq!(s, State::Aborted(AbortReason::CredentialInvalid));
    assert_eq!(out, vec![Output::Close]);
}

#[test]
fn abort_format_mismatch_on_response() {
    let seen: Vec<u64> = vec![];
    let s = drive(
        &State::RequestingCredential {
            format: CredentialFormat::DcSdJwt,
        },
        Input::CredentialResponse {
            format: CredentialFormat::MsoMdoc,
            bytes: b"x".to_vec(),
            issuer_authenticated: true,
        },
        &seen,
    )
    .0;
    assert_eq!(s, State::Aborted(AbortReason::UnsupportedFormat));
}

#[test]
fn decline_aborts() {
    let seen: Vec<u64> = vec![];
    let s = to_requesting_token(&seen);
    let (s, out) = drive(&s, Input::Decline, &seen);
    assert_eq!(s, State::Aborted(AbortReason::UserDeclined));
    assert_eq!(out, vec![Output::Close]);
}
