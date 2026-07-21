use base64ct::{Base64UrlUnpadded, Encoding};
use crypto_backend::AwsLc;
use crypto_traits::{Digest as _, KeyRef, Random};
use oid4vci::authorization::{
    AuthorizationEffect, AuthorizationEnvironment, AuthorizationError, AuthorizationFlow,
    AuthorizationFlowConfig, AuthorizationInput, AuthorizationRedirect, CorrelationId,
    DpopKeyBinding, DpopSignature, EndpointPurpose, EndpointResponse, Es256PublicJwk, FlowStatus,
    WalletClientAuthentication, WalletClientAuthenticationRequest, MAX_ACCESS_TOKEN_BYTES,
    MAX_CALLBACK_QUERY_BYTES, MAX_DPOP_NONCE_RETRIES, MAX_PAR_EXPIRES_IN_SECONDS,
    MAX_PAR_RESPONSE_BYTES, MAX_TOKEN_RESPONSE_BYTES,
};
use oid4vci::foundation::{
    parse_credential_offer, AuthorizationCodeGrant, CredentialOffer, CredentialSigningAlgorithm,
    GermanPidFormat, GermanPidIssuancePlan, HolderBindingMethod, HttpsEndpoint, HttpsIdentifier,
    OfferGrantSource, PidProviderTrust,
};
use std::cell::Cell;

const ISSUER: &str = "https://issuer.example/tenant";
const AS: &str = "https://as.example/tenant";
const REDIRECT: &str = "https://wallet.example/callback";
const CLIENT_ID: &str = "https://wallet-provider.example/wallet-type";
const PAR: &str = "https://as.example/par";
const TOKEN: &str = "https://as.example/token?tenant=de";

struct SequenceRandom(Cell<u8>);

impl SequenceRandom {
    fn new() -> Self {
        Self(Cell::new(1))
    }
}

impl Random for SequenceRandom {
    fn fill(&self, output: &mut [u8]) {
        let value = self.0.get();
        output.fill(value);
        self.0.set(value.wrapping_add(1));
    }
}

struct FixedRandom(u8);

impl Random for FixedRandom {
    fn fill(&self, output: &mut [u8]) {
        output.fill(self.0);
    }
}

fn plan() -> GermanPidIssuancePlan {
    GermanPidIssuancePlan {
        credential_issuer: HttpsIdentifier::parse(ISSUER).unwrap(),
        authorization_server: HttpsIdentifier::parse(AS).unwrap(),
        configuration_id: "pid-sd-jwt".to_owned(),
        format: GermanPidFormat::DcSdJwt,
        scope: "pid".to_owned(),
        holder_binding: HolderBindingMethod::Jwk,
        credential_signing_algorithm: CredentialSigningAlgorithm::JoseEs256,
        proof_signing_algorithm: "ES256".to_owned(),
        credential_endpoint: HttpsEndpoint::parse("https://issuer.example/credential").unwrap(),
        nonce_endpoint: HttpsEndpoint::parse("https://issuer.example/nonce").unwrap(),
        authorization_endpoint: HttpsEndpoint::parse("https://as.example/authorize").unwrap(),
        token_endpoint: HttpsEndpoint::parse(TOKEN).unwrap(),
        pushed_authorization_request_endpoint: HttpsEndpoint::parse(PAR).unwrap(),
        pid_provider_trust: PidProviderTrust::Unresolved,
    }
}

fn offer() -> CredentialOffer {
    CredentialOffer {
        credential_issuer: HttpsIdentifier::parse(ISSUER).unwrap(),
        credential_configuration_ids: vec!["pid-sd-jwt".to_owned()],
        authorization_code: Some(AuthorizationCodeGrant {
            issuer_state: None,
            authorization_server: Some(HttpsIdentifier::parse(AS).unwrap()),
        }),
        pre_authorized_code: None,
        grant_source: OfferGrantSource::Explicit,
    }
}

fn key() -> DpopKeyBinding {
    let x = Base64UrlUnpadded::encode_string(&[1u8; 32]);
    let y = Base64UrlUnpadded::encode_string(&[2u8; 32]);
    DpopKeyBinding::new(
        KeyRef("hardware-key-reference".to_owned()),
        Es256PublicJwk::parse(&x, &y).unwrap(),
    )
    .unwrap()
}

fn config() -> AuthorizationFlowConfig {
    AuthorizationFlowConfig::from_plan_and_offer(&plan(), &offer(), CLIENT_ID, REDIRECT, key())
        .unwrap()
}

fn environment<'a>(random: &'a dyn Random, now: i64) -> AuthorizationEnvironment<'a> {
    AuthorizationEnvironment {
        random,
        digest: &AwsLc,
        now_epoch_seconds: now,
    }
}

fn par_response(
    request_id: CorrelationId,
    status: u16,
    content_type: &str,
    cache: bool,
    dpop_nonce_headers: Vec<String>,
    body: Vec<u8>,
) -> EndpointResponse {
    EndpointResponse::new(
        request_id,
        PAR,
        "POST",
        status,
        content_type,
        if cache {
            vec!["no-cache, no-store".to_owned()]
        } else {
            vec!["no-cache".to_owned()]
        },
        vec![],
        dpop_nonce_headers,
        body,
    )
}

fn token_response(
    request_id: CorrelationId,
    status: u16,
    content_type: &str,
    cache: bool,
    dpop_nonce_headers: Vec<String>,
    body: Vec<u8>,
) -> EndpointResponse {
    EndpointResponse::new(
        request_id,
        TOKEN,
        "POST",
        status,
        content_type,
        if cache {
            vec!["no-store".to_owned()]
        } else {
            vec!["private".to_owned()]
        },
        if cache {
            vec!["no-cache".to_owned()]
        } else {
            vec!["cache".to_owned()]
        },
        dpop_nonce_headers,
        body,
    )
}

fn take_client_auth_effect(effect: AuthorizationEffect) -> WalletClientAuthenticationRequest {
    match effect {
        AuthorizationEffect::AcquireWalletClientAuthentication(request) => request,
        other => panic!("expected client authentication, got {other:?}"),
    }
}

fn client_auth(
    request: &WalletClientAuthenticationRequest,
    marker: u8,
) -> WalletClientAuthentication {
    let signature = Base64UrlUnpadded::encode_string(&[marker; 8]);
    WalletClientAuthentication::new(
        request.request_id(),
        request.purpose(),
        request.client_id(),
        request.audience(),
        request.endpoint(),
        "e30.e30.YXR0ZXN0YXRpb24",
        &format!("e30.e30.{signature}"),
    )
}

fn field<'a>(body: &'a str, name: &str) -> &'a str {
    body.split('&')
        .find_map(|pair| pair.strip_prefix(&format!("{name}=")))
        .unwrap()
}

fn percent_encode(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut output = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            output.push(char::from(byte));
        } else {
            output.push('%');
            output.push(char::from(HEX[(byte >> 4) as usize]));
            output.push(char::from(HEX[(byte & 0x0f) as usize]));
        }
    }
    output
}

struct FlowAtPar {
    flow: AuthorizationFlow,
    request_id: CorrelationId,
    state: String,
}

fn flow_at_par(random: &SequenceRandom) -> FlowAtPar {
    let env = environment(random, 1_700_000_000);
    let (mut flow, effect) = AuthorizationFlow::begin(config(), &env).unwrap();
    let request = take_client_auth_effect(effect);
    assert_eq!(request.purpose(), EndpointPurpose::Par);
    let effects = flow
        .step(
            AuthorizationInput::WalletClientAuthentication(client_auth(&request, 1)),
            &env,
        )
        .unwrap();
    let par = match effects.into_iter().next().unwrap() {
        AuthorizationEffect::SendPar(request) => request,
        other => panic!("expected PAR, got {other:?}"),
    };
    let body = core::str::from_utf8(par.body()).unwrap();
    let state = field(body, "state").to_owned();
    FlowAtPar {
        flow,
        request_id: par.request_id(),
        state,
    }
}

struct FlowAtAuthorization {
    flow: AuthorizationFlow,
    state: String,
}

fn flow_at_authorization(random: &SequenceRandom, dpop_nonce: Vec<String>) -> FlowAtAuthorization {
    let env = environment(random, 1_700_000_000);
    let FlowAtPar {
        mut flow,
        request_id,
        state,
    } = flow_at_par(random);
    let body = br#"{"request_uri":"urn:ietf:params:oauth:request_uri:abc","expires_in":60}"#;
    let effects = flow
        .step(
            AuthorizationInput::ParResponse(par_response(
                request_id,
                201,
                "Application/JSON; Charset=\"UTF-8\"",
                true,
                dpop_nonce,
                body.to_vec(),
            )),
            &env,
        )
        .unwrap();
    let authorization = match effects.into_iter().next().unwrap() {
        AuthorizationEffect::OpenAuthorization(request) => request,
        other => panic!("expected authorization request, got {other:?}"),
    };
    assert_eq!(
        authorization.url(),
        "https://as.example/authorize?client_id=https%3A%2F%2Fwallet-provider.example%2Fwallet-type&request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Aabc"
    );
    assert_eq!(
        authorization.request_uri_expires_at_epoch_seconds(),
        1_700_000_060
    );
    FlowAtAuthorization { flow, state }
}

struct FlowAtTokenAuth {
    flow: AuthorizationFlow,
    request: WalletClientAuthenticationRequest,
}

fn flow_at_token_auth(random: &SequenceRandom, dpop_nonce: Vec<String>) -> FlowAtTokenAuth {
    let env = environment(random, 1_700_000_001);
    let FlowAtAuthorization { mut flow, state } = flow_at_authorization(random, dpop_nonce);
    let query = format!("code=AUTH-CODE&state={state}&iss={}", percent_encode(AS));
    let effects = flow
        .step(
            AuthorizationInput::AuthorizationRedirect(AuthorizationRedirect::new(
                REDIRECT,
                query.into_bytes(),
            )),
            &env,
        )
        .unwrap();
    let request = take_client_auth_effect(effects.into_iter().next().unwrap());
    assert_eq!(request.purpose(), EndpointPurpose::Token);
    FlowAtTokenAuth { flow, request }
}

struct FlowAtDpop {
    flow: AuthorizationFlow,
    request_id: CorrelationId,
    signing_input: Vec<u8>,
}

fn flow_at_dpop(random: &SequenceRandom, dpop_nonce: Vec<String>, marker: u8) -> FlowAtDpop {
    let env = environment(random, 1_700_000_002);
    let FlowAtTokenAuth { mut flow, request } = flow_at_token_auth(random, dpop_nonce);
    let effects = flow
        .step(
            AuthorizationInput::WalletClientAuthentication(client_auth(&request, marker)),
            &env,
        )
        .unwrap();
    let signing = match effects.into_iter().next().unwrap() {
        AuthorizationEffect::SignDpop(request) => request,
        other => panic!("expected DPoP signing, got {other:?}"),
    };
    assert_eq!(signing.algorithm(), crypto_traits::Alg::Es256);
    FlowAtDpop {
        flow,
        request_id: signing.request_id(),
        signing_input: signing.signing_input().to_vec(),
    }
}

struct FlowAtToken {
    flow: AuthorizationFlow,
    request_id: CorrelationId,
}

fn flow_at_token(random: &SequenceRandom, dpop_nonce: Vec<String>, marker: u8) -> FlowAtToken {
    let env = environment(random, 1_700_000_003);
    let FlowAtDpop {
        mut flow,
        request_id,
        signing_input,
    } = flow_at_dpop(random, dpop_nonce, marker);
    let effects = flow
        .step(
            AuthorizationInput::DpopSignature(DpopSignature::new(
                request_id,
                signing_input,
                vec![7; 64],
            )),
            &env,
        )
        .unwrap();
    let token = match effects.into_iter().next().unwrap() {
        AuthorizationEffect::SendToken(request) => request,
        other => panic!("expected token request, got {other:?}"),
    };
    let body = core::str::from_utf8(token.body()).unwrap();
    assert_eq!(field(body, "grant_type"), "authorization_code");
    assert_eq!(field(body, "code"), "AUTH-CODE");
    assert_eq!(field(body, "redirect_uri"), percent_encode(REDIRECT));
    assert_eq!(field(body, "code_verifier").len(), 43);
    assert_eq!(body.split('&').count(), 4);
    assert_eq!(token.dpop_proof().split('.').count(), 3);
    FlowAtToken {
        flow,
        request_id: token.request_id(),
    }
}

#[test]
fn happy_path_emits_exact_pkce_par_callback_dpop_and_token_contracts() {
    let random = SequenceRandom::new();
    let env = environment(&random, 1_700_000_004);
    let FlowAtToken {
        mut flow,
        request_id,
    } = flow_at_token(&random, Vec::new(), 2);
    let effects = flow
        .step(
            AuthorizationInput::TokenResponse(token_response(
                request_id,
                200,
                "application/json",
                true,
                vec!["next-token-nonce".to_owned()],
                br#"{"access_token":"ACCESS-TOKEN","token_type":"DPoP","expires_in":300,"scope":"pid"}"#.to_vec(),
            )),
            &env,
        )
        .unwrap();
    assert!(effects.is_empty());
    assert_eq!(flow.status(), FlowStatus::Complete);
    let grant = flow.into_token().unwrap();
    assert_eq!(grant.access_token(), "ACCESS-TOKEN");
    assert_eq!(grant.issued_at_epoch_seconds(), 1_700_000_004);
    assert_eq!(grant.expires_in_seconds(), Some(300));
    assert_eq!(grant.credential_identifiers().count(), 0);
    assert_eq!(grant.token_endpoint_dpop_nonce(), Some("next-token-nonce"));
    assert_eq!(grant.authorization_server(), AS);
    assert_eq!(grant.token_endpoint(), TOKEN);
    assert_eq!(grant.credential_issuer(), ISSUER);
    assert_eq!(grant.configuration_id(), "pid-sd-jwt");
    assert_eq!(
        grant.credential_endpoint(),
        "https://issuer.example/credential"
    );
    assert_eq!(grant.nonce_endpoint(), "https://issuer.example/nonce");
    assert_eq!(grant.dpop_key_ref().0, "hardware-key-reference");
}

#[test]
fn pkce_challenge_is_exact_s256_and_par_carries_only_profiled_fields() {
    let random = SequenceRandom::new();
    let env = environment(&random, 1_700_000_000);
    let (mut flow, effect) = AuthorizationFlow::begin(config(), &env).unwrap();
    let request = take_client_auth_effect(effect);
    let effects = flow
        .step(
            AuthorizationInput::WalletClientAuthentication(client_auth(&request, 1)),
            &env,
        )
        .unwrap();
    let par = match effects.into_iter().next().unwrap() {
        AuthorizationEffect::SendPar(request) => request,
        _ => unreachable!(),
    };
    let body = core::str::from_utf8(par.body()).unwrap();
    let verifier_entropy = [1u8; 32];
    let verifier = Base64UrlUnpadded::encode_string(&verifier_entropy);
    let challenge = Base64UrlUnpadded::encode_string(&AwsLc.sha256(verifier.as_bytes()));
    assert_eq!(field(body, "code_challenge"), challenge);
    assert_eq!(field(body, "code_challenge_method"), "S256");
    assert_eq!(field(body, "response_type"), "code");
    assert_eq!(field(body, "scope"), "pid");
    assert_eq!(field(body, "resource"), percent_encode(ISSUER));
    assert_eq!(field(body, "redirect_uri"), percent_encode(REDIRECT));
    assert_eq!(field(body, "state").len(), 43);
    assert_eq!(field(body, "dpop_jkt").len(), 43);
    assert_eq!(body.split('&').count(), 9);
    assert_eq!(par.oauth_client_attestation(), "e30.e30.YXR0ZXN0YXRpb24");
    assert!(par.oauth_client_attestation_pop().starts_with("e30.e30."));
    assert!(!body.contains("code_verifier"));
    assert!(!format!("{par:?}").contains("YXR0ZXN0YXRpb24"));
}

#[test]
fn wallet_attestation_pop_is_required_and_distinct_from_token_dpop() {
    let random = SequenceRandom::new();
    let env = environment(&random, 1_700_000_000);
    let (mut flow, first) = AuthorizationFlow::begin(config(), &env).unwrap();
    let par_auth = take_client_auth_effect(first);
    assert_eq!(par_auth.method(), "POST");
    assert_eq!(par_auth.endpoint(), PAR);
    assert_eq!(par_auth.audience(), AS);
    let effects = flow
        .step(
            AuthorizationInput::WalletClientAuthentication(client_auth(&par_auth, 1)),
            &env,
        )
        .unwrap();
    assert!(matches!(effects[0], AuthorizationEffect::SendPar(_)));

    let token_random = SequenceRandom::new();
    let FlowAtTokenAuth { mut flow, request } = flow_at_token_auth(&token_random, vec![]);
    assert_eq!(request.endpoint(), TOKEN);
    let effects = flow
        .step(
            AuthorizationInput::WalletClientAuthentication(client_auth(&request, 2)),
            &environment(&token_random, 1_700_000_002),
        )
        .unwrap();
    assert!(matches!(effects[0], AuthorizationEffect::SignDpop(_)));
}

#[test]
fn config_rejects_noncanonical_key_redirect_and_offer_plan_mismatch() {
    assert_eq!(
        Es256PublicJwk::parse("short", "short"),
        Err(AuthorizationError::InvalidConfiguration)
    );
    assert!(AuthorizationFlowConfig::from_plan_and_offer(
        &plan(),
        &offer(),
        CLIENT_ID,
        "http://wallet.example/callback",
        key(),
    )
    .is_err());
    let mut wrong_offer = offer();
    wrong_offer.credential_issuer = HttpsIdentifier::parse("https://other.example").unwrap();
    assert!(matches!(
        AuthorizationFlowConfig::from_plan_and_offer(
            &plan(),
            &wrong_offer,
            CLIENT_ID,
            REDIRECT,
            key(),
        ),
        Err(AuthorizationError::OfferPlanMismatch)
    ));

    let mut missing_configuration = offer();
    missing_configuration.credential_configuration_ids = vec!["other".to_owned()];
    assert!(matches!(
        AuthorizationFlowConfig::from_plan_and_offer(
            &plan(),
            &missing_configuration,
            CLIENT_ID,
            REDIRECT,
            key(),
        ),
        Err(AuthorizationError::OfferPlanMismatch)
    ));

    let mut query_endpoint = plan();
    query_endpoint.authorization_endpoint =
        HttpsEndpoint::parse("https://as.example/authorize?tenant=de").unwrap();
    assert!(matches!(
        AuthorizationFlowConfig::from_plan_and_offer(
            &query_endpoint,
            &offer(),
            CLIENT_ID,
            REDIRECT,
            key(),
        ),
        Err(AuthorizationError::InvalidConfiguration)
    ));
}

#[test]
fn broken_randomness_and_invalid_clock_fail_closed() {
    assert!(matches!(
        AuthorizationFlow::begin(config(), &environment(&FixedRandom(0), 1)),
        Err(AuthorizationError::RandomnessFailure)
    ));
    assert!(matches!(
        AuthorizationFlow::begin(config(), &environment(&FixedRandom(1), 1)),
        Err(AuthorizationError::RandomnessFailure)
    ));
    assert!(matches!(
        AuthorizationFlow::begin(config(), &environment(&SequenceRandom::new(), -1)),
        Err(AuthorizationError::InvalidClock)
    ));
    assert!(matches!(
        AuthorizationFlow::begin(config(), &environment(&SequenceRandom::new(), 0)),
        Err(AuthorizationError::InvalidClock)
    ));

    let random = SequenceRandom::new();
    let (mut flow, effect) =
        AuthorizationFlow::begin(config(), &environment(&random, 100)).unwrap();
    let request = take_client_auth_effect(effect);
    assert_eq!(
        flow.step(
            AuthorizationInput::WalletClientAuthentication(client_auth(&request, 1)),
            &environment(&random, 99),
        )
        .unwrap_err(),
        AuthorizationError::InvalidClock
    );
    assert_eq!(flow.status(), FlowStatus::Failed);
}

#[test]
fn issuer_state_is_returned_exactly_once_inside_par() {
    let parsed_offer = parse_credential_offer(
        br#"{
          "credential_issuer":"https://issuer.example/tenant",
          "credential_configuration_ids":["pid-sd-jwt"],
          "grants":{"authorization_code":{
            "issuer_state":"context a&b",
            "authorization_server":"https://as.example/tenant"
          }}
        }"#,
    )
    .unwrap();
    let config = AuthorizationFlowConfig::from_plan_and_offer(
        &plan(),
        &parsed_offer,
        CLIENT_ID,
        REDIRECT,
        key(),
    )
    .unwrap();
    let random = SequenceRandom::new();
    let env = environment(&random, 1_700_000_000);
    let (mut flow, effect) = AuthorizationFlow::begin(config, &env).unwrap();
    let request = take_client_auth_effect(effect);
    let effects = flow
        .step(
            AuthorizationInput::WalletClientAuthentication(client_auth(&request, 1)),
            &env,
        )
        .unwrap();
    let par = match effects.into_iter().next().unwrap() {
        AuthorizationEffect::SendPar(request) => request,
        _ => unreachable!(),
    };
    let body = core::str::from_utf8(par.body()).unwrap();
    assert_eq!(field(body, "issuer_state"), "context%20a%26b");
    assert_eq!(body.matches("issuer_state=").count(), 1);
}

#[test]
fn client_authentication_is_exactly_bound_and_pop_cannot_be_reused() {
    let random = SequenceRandom::new();
    let env = environment(&random, 1_700_000_000);
    let (mut flow, effect) = AuthorizationFlow::begin(config(), &env).unwrap();
    let request = take_client_auth_effect(effect);
    let bad = WalletClientAuthentication::new(
        request.request_id(),
        request.purpose(),
        request.client_id(),
        request.audience(),
        "https://as.example/wrong",
        "e30.e30.YXR0ZXN0YXRpb24",
        "e30.e30.cG9w",
    );
    assert_eq!(
        flow.step(AuthorizationInput::WalletClientAuthentication(bad), &env)
            .unwrap_err(),
        AuthorizationError::ClientAuthenticationBindingMismatch
    );
    assert_eq!(flow.status(), FlowStatus::Failed);

    let FlowAtTokenAuth { mut flow, request } = flow_at_token_auth(&random, vec![]);
    let reused = WalletClientAuthentication::new(
        request.request_id(),
        request.purpose(),
        request.client_id(),
        request.audience(),
        request.endpoint(),
        "e30.e30.YXR0ZXN0YXRpb24",
        // PAR used marker 1, whose encoded 8-byte signature is this value.
        &format!("e30.e30.{}", Base64UrlUnpadded::encode_string(&[1u8; 8])),
    );
    assert_eq!(
        flow.step(
            AuthorizationInput::WalletClientAuthentication(reused),
            &environment(&random, 1_700_000_002),
        )
        .unwrap_err(),
        AuthorizationError::ClientAuthenticationReused
    );
}

#[test]
fn malformed_wallet_attestation_never_reaches_transport() {
    let random = SequenceRandom::new();
    let env = environment(&random, 1_700_000_000);
    let (mut flow, effect) = AuthorizationFlow::begin(config(), &env).unwrap();
    let request = take_client_auth_effect(effect);
    let invalid = WalletClientAuthentication::new(
        request.request_id(),
        request.purpose(),
        request.client_id(),
        request.audience(),
        request.endpoint(),
        "not-a-jwt",
        "e30.e30.cG9w",
    );
    assert_eq!(
        flow.step(
            AuthorizationInput::WalletClientAuthentication(invalid),
            &env
        )
        .unwrap_err(),
        AuthorizationError::ClientAuthenticationInvalid
    );
}

#[test]
fn par_response_enforces_duplicate_aware_json_bounds_status_cache_and_fapi_expiry() {
    for (body, status, cache, expected) in [
        (
            format!(
                "{{\"request_uri\":\"urn:one\",\"expires_in\":{}}}",
                MAX_PAR_EXPIRES_IN_SECONDS
            ),
            201,
            true,
            None,
        ),
        (
            "{\"request_uri\":\"urn:one\",\"request_uri\":\"urn:two\",\"expires_in\":60}"
                .to_owned(),
            201,
            true,
            Some(AuthorizationError::InvalidParResponse),
        ),
        (
            "{\"request_uri\":\"urn:one\",\"expires_in\":600}".to_owned(),
            201,
            true,
            Some(AuthorizationError::InvalidParResponse),
        ),
        (
            "{\"request_uri\":\"urn:one\",\"expires_in\":0}".to_owned(),
            201,
            true,
            Some(AuthorizationError::InvalidParResponse),
        ),
        (
            "{\"request_uri\":\"urn:one\",\"expires_in\":60}".to_owned(),
            200,
            true,
            Some(AuthorizationError::InvalidParResponse),
        ),
        (
            "{\"request_uri\":\"urn:one\",\"expires_in\":60}".to_owned(),
            201,
            false,
            Some(AuthorizationError::CachePolicyMissing),
        ),
    ] {
        let random = SequenceRandom::new();
        let FlowAtPar {
            mut flow,
            request_id,
            ..
        } = flow_at_par(&random);
        let result = flow.step(
            AuthorizationInput::ParResponse(par_response(
                request_id,
                status,
                "application/json",
                cache,
                vec![],
                body.into_bytes(),
            )),
            &environment(&random, 1_700_000_001),
        );
        assert_eq!(result.err(), expected);
    }

    let random = SequenceRandom::new();
    let FlowAtPar {
        mut flow,
        request_id,
        ..
    } = flow_at_par(&random);
    assert_eq!(
        flow.step(
            AuthorizationInput::ParResponse(par_response(
                request_id,
                201,
                "application/json",
                true,
                vec![],
                vec![b' '; MAX_PAR_RESPONSE_BYTES + 1],
            )),
            &environment(&random, 1_700_000_001),
        )
        .unwrap_err(),
        AuthorizationError::InvalidParResponse
    );
}

#[test]
fn duplicate_dpop_nonce_headers_and_wrong_transport_binding_are_rejected() {
    let random = SequenceRandom::new();
    let FlowAtPar {
        mut flow,
        request_id,
        ..
    } = flow_at_par(&random);
    let body = br#"{"request_uri":"urn:one","expires_in":60}"#.to_vec();
    assert_eq!(
        flow.step(
            AuthorizationInput::ParResponse(par_response(
                request_id,
                201,
                "application/json",
                true,
                vec!["one".to_owned(), "two".to_owned()],
                body,
            )),
            &environment(&random, 1_700_000_001),
        )
        .unwrap_err(),
        AuthorizationError::DpopNonceInvalid
    );

    let random = SequenceRandom::new();
    let FlowAtPar { mut flow, .. } = flow_at_par(&random);
    let wrong_id = CorrelationId::from_bytes([99; 32]);
    assert_eq!(
        flow.step(
            AuthorizationInput::ParResponse(par_response(
                wrong_id,
                201,
                "application/json",
                true,
                vec![],
                br#"{"request_uri":"urn:one","expires_in":60}"#.to_vec(),
            )),
            &environment(&random, 1_700_000_001),
        )
        .unwrap_err(),
        AuthorizationError::TransportBindingMismatch
    );
}

#[test]
fn raw_response_metadata_is_parsed_in_core_and_bound_to_endpoint_and_method() {
    let body = br#"{"request_uri":"urn:one","expires_in":60}"#.to_vec();
    for (endpoint, method) in [("https://as.example/wrong", "POST"), (PAR, "GET")] {
        let random = SequenceRandom::new();
        let FlowAtPar {
            mut flow,
            request_id,
            ..
        } = flow_at_par(&random);
        assert_eq!(
            flow.step(
                AuthorizationInput::ParResponse(EndpointResponse::new(
                    request_id,
                    endpoint,
                    method,
                    201,
                    "application/json",
                    vec!["no-cache, no-store".to_owned()],
                    vec![],
                    vec![],
                    body.clone(),
                )),
                &environment(&random, 1_700_000_001),
            )
            .unwrap_err(),
            AuthorizationError::TransportBindingMismatch
        );
    }

    for (content_type, cache_control, expected) in [
        (
            "application/json; charset=iso-8859-1",
            vec!["no-cache, no-store".to_owned()],
            AuthorizationError::InvalidMediaType,
        ),
        (
            "application/json",
            vec!["no-store".to_owned()],
            AuthorizationError::CachePolicyMissing,
        ),
        (
            "application/json",
            vec!["no-cache, no-store\r\nInjected: value".to_owned()],
            AuthorizationError::CachePolicyMissing,
        ),
    ] {
        let random = SequenceRandom::new();
        let FlowAtPar {
            mut flow,
            request_id,
            ..
        } = flow_at_par(&random);
        let response = EndpointResponse::new(
            request_id,
            PAR,
            "POST",
            201,
            content_type,
            cache_control,
            vec![],
            vec![],
            body.clone(),
        );
        assert_eq!(
            flow.step(
                AuthorizationInput::ParResponse(response),
                &environment(&random, 1_700_000_001),
            )
            .unwrap_err(),
            expected
        );
    }

    let random = SequenceRandom::new();
    let FlowAtToken {
        mut flow,
        request_id,
    } = flow_at_token(&random, vec![], 2);
    let missing_pragma = EndpointResponse::new(
        request_id,
        TOKEN,
        "POST",
        200,
        "application/json;charset=UTF-8",
        vec!["NO-STORE".to_owned()],
        vec![],
        vec![],
        br#"{"access_token":"A","token_type":"DPoP"}"#.to_vec(),
    );
    assert_eq!(
        flow.step(
            AuthorizationInput::TokenResponse(missing_pragma),
            &environment(&random, 1_700_000_004),
        )
        .unwrap_err(),
        AuthorizationError::CachePolicyMissing
    );
}

#[test]
fn callback_requires_exact_redirect_constant_time_state_issuer_and_single_result() {
    let cases = [
        ("https://wallet.example/other", None),
        (REDIRECT, Some("code=ONE&code=TWO&state={state}&iss={iss}")),
        (REDIRECT, Some("code=ONE&error=no&state={state}&iss={iss}")),
        (REDIRECT, Some("code=ONE&state=wrong&iss={iss}")),
        (
            REDIRECT,
            Some("code=ONE&state={state}&iss=https%3A%2F%2Fevil.example"),
        ),
        (REDIRECT, Some("code=ONE&state={state}")),
    ];
    for (redirect_uri, template) in cases {
        let random = SequenceRandom::new();
        let FlowAtAuthorization { mut flow, state } = flow_at_authorization(&random, vec![]);
        let query = template
            .unwrap_or("code=ONE&state={state}&iss={iss}")
            .replace("{state}", &state)
            .replace("{iss}", &percent_encode(AS));
        assert!(flow
            .step(
                AuthorizationInput::AuthorizationRedirect(AuthorizationRedirect::new(
                    redirect_uri,
                    query.into_bytes(),
                )),
                &environment(&random, 1_700_000_002),
            )
            .is_err());
        assert_eq!(flow.status(), FlowStatus::Failed);
    }
}

#[test]
fn callback_bounds_and_error_response_are_fail_closed() {
    let random = SequenceRandom::new();
    let FlowAtAuthorization { mut flow, state } = flow_at_authorization(&random, vec![]);
    let query = format!(
        "error=access_denied&state={state}&iss={}",
        percent_encode(AS)
    );
    assert_eq!(
        flow.step(
            AuthorizationInput::AuthorizationRedirect(AuthorizationRedirect::new(
                REDIRECT,
                query.into_bytes(),
            )),
            &environment(&random, 1_700_000_002),
        )
        .unwrap_err(),
        AuthorizationError::AuthorizationDenied
    );

    let random = SequenceRandom::new();
    let FlowAtAuthorization { mut flow, .. } = flow_at_authorization(&random, vec![]);
    assert_eq!(
        flow.step(
            AuthorizationInput::AuthorizationRedirect(AuthorizationRedirect::new(
                REDIRECT,
                vec![b'a'; MAX_CALLBACK_QUERY_BYTES + 1],
            )),
            &environment(&random, 1_700_000_002),
        )
        .unwrap_err(),
        AuthorizationError::InvalidAuthorizationCallback
    );
}

#[test]
fn dpop_signing_input_binds_es256_public_key_method_uri_time_jti_and_nonce() {
    let random = SequenceRandom::new();
    let FlowAtDpop {
        flow: _,
        signing_input,
        ..
    } = flow_at_dpop(&random, vec!["par-seeded-nonce".to_owned()], 2);
    let compact = core::str::from_utf8(&signing_input).unwrap();
    let segments: Vec<_> = compact.split('.').collect();
    assert_eq!(segments.len(), 2);
    let header = Base64UrlUnpadded::decode_vec(segments[0]).unwrap();
    let payload = Base64UrlUnpadded::decode_vec(segments[1]).unwrap();
    let header: serde_json::Value = serde_json::from_slice(&header).unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    assert_eq!(header["typ"], "dpop+jwt");
    assert_eq!(header["alg"], "ES256");
    assert_eq!(header["jwk"]["kty"], "EC");
    assert_eq!(header["jwk"]["crv"], "P-256");
    assert!(header["jwk"].get("d").is_none());
    assert_eq!(payload["htm"], "POST");
    assert_eq!(payload["htu"], "https://as.example/token");
    assert_eq!(payload["iat"], 1_700_000_002i64);
    assert_eq!(payload["nonce"], "par-seeded-nonce");
    assert_eq!(payload["jti"].as_str().unwrap().len(), 43);
    assert!(payload.get("ath").is_none());
}

#[test]
fn stale_or_malformed_dpop_signing_results_never_emit_token_request() {
    for mutation in 0..3 {
        let random = SequenceRandom::new();
        let env = environment(&random, 1_700_000_003);
        let FlowAtDpop {
            mut flow,
            request_id,
            mut signing_input,
        } = flow_at_dpop(&random, vec![], 2);
        let mut signature = vec![7; 64];
        let request_id = if mutation == 0 {
            CorrelationId::from_bytes([88; 32])
        } else {
            request_id
        };
        if mutation == 1 {
            signing_input.push(b'x');
        }
        if mutation == 2 {
            signature.pop();
        }
        assert!(flow
            .step(
                AuthorizationInput::DpopSignature(DpopSignature::new(
                    request_id,
                    signing_input,
                    signature,
                )),
                &env,
            )
            .is_err());
        assert_eq!(flow.status(), FlowStatus::Failed);
    }
}

#[test]
fn token_dpop_nonce_challenge_reacquires_client_auth_and_uses_fresh_proof() {
    let random = SequenceRandom::new();
    let env = environment(&random, 1_700_000_004);
    let FlowAtToken {
        mut flow,
        request_id,
    } = flow_at_token(&random, vec![], 2);
    let effects = flow
        .step(
            AuthorizationInput::TokenResponse(token_response(
                request_id,
                400,
                "application/json",
                true,
                vec!["challenge-nonce".to_owned()],
                br#"{"error":"use_dpop_nonce"}"#.to_vec(),
            )),
            &env,
        )
        .unwrap();
    let auth = take_client_auth_effect(effects.into_iter().next().unwrap());
    assert_eq!(auth.purpose(), EndpointPurpose::Token);
    let effects = flow
        .step(
            AuthorizationInput::WalletClientAuthentication(client_auth(&auth, 3)),
            &environment(&random, 1_700_000_005),
        )
        .unwrap();
    let signing = match effects.into_iter().next().unwrap() {
        AuthorizationEffect::SignDpop(request) => request,
        _ => unreachable!(),
    };
    let payload_segment = core::str::from_utf8(signing.signing_input())
        .unwrap()
        .split('.')
        .nth(1)
        .unwrap();
    let payload: serde_json::Value =
        serde_json::from_slice(&Base64UrlUnpadded::decode_vec(payload_segment).unwrap()).unwrap();
    assert_eq!(payload["nonce"], "challenge-nonce");
}

#[test]
fn duplicate_stale_and_excessive_dpop_nonce_challenges_are_rejected() {
    let random = SequenceRandom::new();
    let FlowAtToken {
        mut flow,
        request_id,
    } = flow_at_token(&random, vec![], 2);
    assert_eq!(
        flow.step(
            AuthorizationInput::TokenResponse(token_response(
                request_id,
                400,
                "application/json",
                true,
                vec!["one".to_owned(), "two".to_owned()],
                br#"{"error":"use_dpop_nonce"}"#.to_vec(),
            )),
            &environment(&random, 1_700_000_004),
        )
        .unwrap_err(),
        AuthorizationError::DpopNonceInvalid
    );

    // Drive exactly the allowed number of rotations, then reject one more challenge.
    let random = SequenceRandom::new();
    let FlowAtToken {
        mut flow,
        mut request_id,
    } = flow_at_token(&random, vec![], 2);
    for retry in 0..=MAX_DPOP_NONCE_RETRIES {
        let now = 1_700_000_010 + i64::from(retry) * 10;
        let result = flow.step(
            AuthorizationInput::TokenResponse(token_response(
                request_id,
                400,
                "application/json",
                true,
                vec![format!("nonce-{retry}")],
                br#"{"error":"use_dpop_nonce"}"#.to_vec(),
            )),
            &environment(&random, now),
        );
        if retry == MAX_DPOP_NONCE_RETRIES {
            assert_eq!(result.unwrap_err(), AuthorizationError::DpopNonceRetryLimit);
            break;
        }
        let auth = take_client_auth_effect(result.unwrap().into_iter().next().unwrap());
        let effects = flow
            .step(
                AuthorizationInput::WalletClientAuthentication(client_auth(&auth, 10 + retry)),
                &environment(&random, now + 1),
            )
            .unwrap();
        let signing = match effects.into_iter().next().unwrap() {
            AuthorizationEffect::SignDpop(value) => value,
            _ => unreachable!(),
        };
        let signing_id = signing.request_id();
        let signing_input = signing.signing_input().to_vec();
        let effects = flow
            .step(
                AuthorizationInput::DpopSignature(DpopSignature::new(
                    signing_id,
                    signing_input,
                    vec![7; 64],
                )),
                &environment(&random, now + 2),
            )
            .unwrap();
        request_id = match effects.into_iter().next().unwrap() {
            AuthorizationEffect::SendToken(request) => request.request_id(),
            _ => unreachable!(),
        };
    }
}

#[test]
fn token_response_rejects_ambiguity_downgrade_bounds_scope_expiry_and_cache_failures() {
    let cases = [
        (
            br#"{"access_token":"A","access_token":"B","token_type":"DPoP"}"#.to_vec(),
            true,
            AuthorizationError::InvalidTokenResponse,
        ),
        (
            br#"{"access_token":"A","token_type":"Bearer"}"#.to_vec(),
            true,
            AuthorizationError::TokenTypeDowngrade,
        ),
        (
            br#"{"access_token":"A","token_type":"DPoP","expires_in":0}"#.to_vec(),
            true,
            AuthorizationError::InvalidTokenResponse,
        ),
        (
            br#"{"access_token":"A","token_type":"DPoP","scope":"other"}"#.to_vec(),
            true,
            AuthorizationError::InvalidTokenResponse,
        ),
        (
            br#"{"access_token":"A","token_type":"DPoP","scope":7}"#.to_vec(),
            true,
            AuthorizationError::InvalidTokenResponse,
        ),
        (
            br#"{"access_token":"A","token_type":"DPoP","refresh_token":"R"}"#.to_vec(),
            true,
            AuthorizationError::InvalidTokenResponse,
        ),
        (
            br#"{"access_token":"A","token_type":"DPoP"}"#.to_vec(),
            false,
            AuthorizationError::CachePolicyMissing,
        ),
        (
            vec![b' '; MAX_TOKEN_RESPONSE_BYTES + 1],
            true,
            AuthorizationError::InvalidTokenResponse,
        ),
        (
            format!(
                "{{\"access_token\":\"{}\",\"token_type\":\"DPoP\"}}",
                "A".repeat(MAX_ACCESS_TOKEN_BYTES + 1)
            )
            .into_bytes(),
            true,
            AuthorizationError::InvalidTokenResponse,
        ),
    ];
    for (body, cache, expected) in cases {
        let random = SequenceRandom::new();
        let FlowAtToken {
            mut flow,
            request_id,
        } = flow_at_token(&random, vec![], 2);
        assert_eq!(
            flow.step(
                AuthorizationInput::TokenResponse(token_response(
                    request_id,
                    200,
                    "application/json",
                    cache,
                    vec![],
                    body,
                )),
                &environment(&random, 1_700_000_004),
            )
            .unwrap_err(),
            expected
        );
    }
}

#[test]
fn final_token_parser_ignores_bounded_legacy_c_nonce_instead_of_requiring_it() {
    let random = SequenceRandom::new();
    let FlowAtToken {
        mut flow,
        request_id,
    } = flow_at_token(&random, vec![], 2);
    flow.step(
        AuthorizationInput::TokenResponse(token_response(
            request_id,
            200,
            "application/json",
            true,
            vec![],
            br#"{"access_token":"A","token_type":"DPoP","c_nonce":123}"#.to_vec(),
        )),
        &environment(&random, 1_700_000_004),
    )
    .unwrap();
    assert_eq!(flow.into_token().unwrap().access_token(), "A");
}

#[test]
fn token_response_carries_only_exact_selected_configuration_identifiers() {
    let random = SequenceRandom::new();
    let FlowAtToken {
        mut flow,
        request_id,
    } = flow_at_token(&random, vec![], 2);
    flow.step(
        AuthorizationInput::TokenResponse(token_response(
            request_id,
            200,
            "application/json",
            true,
            vec![],
            format!(
                r#"{{"access_token":"A","token_type":"DPoP","authorization_details":[{{"type":"openid_credential","credential_configuration_id":"pid-sd-jwt","locations":["{ISSUER}"],"credential_identifiers":["dataset-a","dataset-b"],"bounded_extension":true}}]}}"#
            )
            .into_bytes(),
        )),
        &environment(&random, 1_700_000_004),
    )
    .unwrap();
    let grant = flow.into_token().unwrap();
    assert_eq!(
        grant.credential_identifiers().collect::<Vec<_>>(),
        vec!["dataset-a", "dataset-b"]
    );

    for authorization_details in [
        r#"[{"type":"openid_credential","credential_configuration_id":"other","credential_identifiers":["dataset-a"]}]"#,
        r#"[{"type":"openid_credential","credential_configuration_id":"pid-sd-jwt","credential_identifiers":["same","same"]}]"#,
        r#"[{"type":"openid_credential","credential_configuration_id":"pid-sd-jwt","locations":["https://other.example"],"credential_identifiers":["dataset-a"]}]"#,
        r#"[{"type":"openid_credential","credential_configuration_id":"pid-sd-jwt","credential_identifiers":[]}]"#,
    ] {
        let random = SequenceRandom::new();
        let FlowAtToken {
            mut flow,
            request_id,
        } = flow_at_token(&random, vec![], 2);
        assert_eq!(
            flow.step(
                AuthorizationInput::TokenResponse(token_response(
                    request_id,
                    200,
                    "application/json",
                    true,
                    vec![],
                    format!(
                        r#"{{"access_token":"A","token_type":"DPoP","authorization_details":{authorization_details}}}"#
                    )
                    .into_bytes(),
                )),
                &environment(&random, 1_700_000_004),
            )
            .unwrap_err(),
            AuthorizationError::InvalidTokenResponse
        );
    }
}

#[test]
fn replay_concurrency_and_out_of_order_inputs_latch_closed() {
    let random = SequenceRandom::new();
    let env = environment(&random, 1_700_000_000);
    let (mut flow, _) = AuthorizationFlow::begin(config(), &env).unwrap();
    let wrong = par_response(
        CorrelationId::from_bytes([8; 32]),
        201,
        "application/json",
        true,
        vec![],
        br#"{"request_uri":"urn:one","expires_in":60}"#.to_vec(),
    );
    assert_eq!(
        flow.step(AuthorizationInput::ParResponse(wrong), &env)
            .unwrap_err(),
        AuthorizationError::UnexpectedInput
    );
    assert_eq!(flow.status(), FlowStatus::Failed);
    assert_eq!(
        flow.step(
            AuthorizationInput::AuthorizationRedirect(AuthorizationRedirect::new(
                REDIRECT,
                b"code=x".to_vec(),
            )),
            &env,
        )
        .unwrap_err(),
        AuthorizationError::AlreadyTerminal
    );

    let random = SequenceRandom::new();
    let FlowAtAuthorization { mut flow, state } = flow_at_authorization(&random, vec![]);
    let query = format!("code=A&state={state}&iss={}", percent_encode(AS));
    flow.step(
        AuthorizationInput::AuthorizationRedirect(AuthorizationRedirect::new(
            REDIRECT,
            query.clone().into_bytes(),
        )),
        &environment(&random, 1_700_000_002),
    )
    .unwrap();
    assert_eq!(
        flow.step(
            AuthorizationInput::AuthorizationRedirect(AuthorizationRedirect::new(
                REDIRECT,
                query.into_bytes(),
            )),
            &environment(&random, 1_700_000_003),
        )
        .unwrap_err(),
        AuthorizationError::UnexpectedInput
    );
    assert_eq!(flow.status(), FlowStatus::Failed);
}

#[test]
fn debug_outputs_never_disclose_verifier_code_tokens_assertions_proofs_or_nonces() {
    let random = SequenceRandom::new();
    let env = environment(&random, 1_700_000_000);
    let (flow, effect) = AuthorizationFlow::begin(config(), &env).unwrap();
    let diagnostics = format!("{flow:?} {effect:?}");
    for secret in [
        "hardware-key-reference",
        "AUTH-CODE",
        "ACCESS-TOKEN",
        "REFRESH",
        "par-seeded-nonce",
    ] {
        assert!(!diagnostics.contains(secret));
    }
    assert!(diagnostics.contains("[REDACTED]"));

    let response = token_response(
        CorrelationId::from_bytes([3; 32]),
        200,
        "application/json",
        true,
        vec!["TOP-SECRET-NONCE".to_owned()],
        br#"{"access_token":"TOP-SECRET-TOKEN"}"#.to_vec(),
    );
    let diagnostics = format!("{response:?}");
    assert!(!diagnostics.contains("TOP-SECRET"));
}

#[test]
fn par_body_and_callback_have_hard_resource_limits() {
    let random = SequenceRandom::new();
    let FlowAtPar {
        mut flow,
        request_id,
        ..
    } = flow_at_par(&random);
    assert_eq!(
        flow.step(
            AuthorizationInput::ParResponse(par_response(
                request_id,
                201,
                "application/json",
                true,
                vec![],
                vec![b'{'; MAX_PAR_RESPONSE_BYTES + 1],
            )),
            &environment(&random, 1_700_000_001),
        )
        .unwrap_err(),
        AuthorizationError::InvalidParResponse
    );
}
