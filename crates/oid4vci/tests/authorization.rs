use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use crypto_backend::{AwsLc, SoftwareSigner};
use crypto_traits::{Alg, CryptoError, Digest as _, KeyRef, Random, Signer, Verifier};
use oid4vci::authorization::{
    AuthorizationEffect, AuthorizationEnvironment, AuthorizationError, AuthorizationFlow,
    AuthorizationFlowConfig, AuthorizationInput, AuthorizationRedirect,
    ClientAttestationKeyBinding, ClientAttestationPopSignature, CorrelationId, DpopKeyBinding,
    DpopSignature, EndpointPurpose, EndpointResponse, Es256PublicJwk, FlowStatus,
    WalletAttestation, WalletAttestationRequest, WalletAttestationUsagePolicy,
    WalletAttestationUsageReservationResult, MAX_ACCESS_TOKEN_BYTES, MAX_CALLBACK_QUERY_BYTES,
    MAX_CLIENT_ATTESTATION_RETRIES, MAX_DPOP_NONCE_RETRIES, MAX_PAR_EXPIRES_IN_SECONDS,
    MAX_PAR_RESPONSE_BYTES, MAX_TOKEN_RESPONSE_BYTES, MAX_TOKEN_STATUS_LIST_INDEX,
    MAX_WALLET_ATTESTATION_LIFETIME_SECONDS, MAX_WALLET_NAME_BYTES,
    MAX_WALLET_SOLUTION_CERTIFICATION_INFORMATION_BYTES, MAX_WALLET_VERSION_BYTES,
    MIN_CLIENT_STATUS_MAINTENANCE_SECONDS,
};
use oid4vci::foundation::{
    parse_credential_offer, AuthorizationCodeGrant, CredentialOffer, CredentialSigningAlgorithm,
    GermanPidFormat, GermanPidIssuancePlan, HolderBindingMethod, HttpsEndpoint, HttpsIdentifier,
    OfferGrantSource, PidProviderTrust, MAX_PREFERRED_CLIENT_STATUS_PERIOD_SECONDS,
};
use std::cell::Cell;

const ISSUER: &str = "https://issuer.example/tenant";
const AS: &str = "https://as.example/tenant";
const REDIRECT: &str = "https://wallet.example/callback";
const CLIENT_ID: &str = "https://wallet-provider.example/wallet-type";
const PAR: &str = "https://as.example/par";
const TOKEN: &str = "https://as.example/token?tenant=de";
const CHALLENGE: &str = "https://as.example/challenge";
const OTHER_ISSUER: &str = "https://other-issuer.example/tenant";
const WALLET_ATTESTATION_SIGNER_CERTIFICATE: &[u8] =
    include_bytes!("../../x509/tests/vectors/rp.der");
const WALLET_ATTESTATION_SIGNER_PKCS8: &[u8] =
    include_bytes!("../../x509/tests/vectors/rp.pkcs8.der");

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

struct TestVerifier;

impl Verifier for TestVerifier {
    fn verify(
        &self,
        alg: Alg,
        public_key: &[u8],
        payload: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        let wallet_attestation_leaf = x509::parse_cert(WALLET_ATTESTATION_SIGNER_CERTIFICATE)
            .expect("wallet attestation signer certificate");
        if public_key == wallet_attestation_leaf.public_key_raw {
            AwsLc.verify(alg, public_key, payload, signature)
        } else if alg == Alg::Es256 && public_key.len() == 65 && signature.len() == 64 {
            Ok(())
        } else {
            Err(CryptoError::Backend("test verification failed".to_owned()))
        }
    }
}

static TEST_VERIFIER: TestVerifier = TestVerifier;

struct RejectingVerifier;

impl Verifier for RejectingVerifier {
    fn verify(
        &self,
        _alg: Alg,
        _public_key: &[u8],
        _payload: &[u8],
        _signature: &[u8],
    ) -> Result<(), CryptoError> {
        Err(CryptoError::Backend("rejected".to_owned()))
    }
}

static REJECTING_VERIFIER: RejectingVerifier = RejectingVerifier;

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
        preferred_client_status_period: None,
        preferred_key_storage_status_period: None,
        authorization_endpoint: HttpsEndpoint::parse("https://as.example/authorize").unwrap(),
        token_endpoint: HttpsEndpoint::parse(TOKEN).unwrap(),
        pushed_authorization_request_endpoint: HttpsEndpoint::parse(PAR).unwrap(),
        attestation_challenge_endpoint: None,
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

fn client_attestation_key() -> ClientAttestationKeyBinding {
    client_attestation_key_for(AS, ISSUER)
}

fn client_attestation_key_for(
    authorization_server: &str,
    credential_issuer: &str,
) -> ClientAttestationKeyBinding {
    let x = Base64UrlUnpadded::encode_string(&[3u8; 32]);
    let y = Base64UrlUnpadded::encode_string(&[4u8; 32]);
    ClientAttestationKeyBinding::new(
        authorization_server,
        credential_issuer,
        KeyRef("client-instance-key-reference".to_owned()),
        Es256PublicJwk::parse(&x, &y).unwrap(),
        WalletAttestationUsagePolicy::SingleIssuance,
    )
    .unwrap()
}

fn config() -> AuthorizationFlowConfig {
    AuthorizationFlowConfig::from_plan_and_offer(
        &plan(),
        &offer(),
        CLIENT_ID,
        REDIRECT,
        key(),
        client_attestation_key(),
    )
    .unwrap()
}

fn config_with_challenge() -> AuthorizationFlowConfig {
    let mut plan = plan();
    plan.attestation_challenge_endpoint = Some(HttpsEndpoint::parse(CHALLENGE).unwrap());
    AuthorizationFlowConfig::from_plan_and_offer(
        &plan,
        &offer(),
        CLIENT_ID,
        REDIRECT,
        key(),
        client_attestation_key(),
    )
    .unwrap()
}

fn config_with_preferred_client_status_period(period: u64) -> AuthorizationFlowConfig {
    let mut plan = plan();
    plan.preferred_client_status_period = Some(period);
    AuthorizationFlowConfig::from_plan_and_offer(
        &plan,
        &offer(),
        CLIENT_ID,
        REDIRECT,
        key(),
        client_attestation_key(),
    )
    .unwrap()
}

fn config_for_other_issuer() -> AuthorizationFlowConfig {
    let mut plan = plan();
    plan.credential_issuer = HttpsIdentifier::parse(OTHER_ISSUER).unwrap();
    plan.credential_endpoint =
        HttpsEndpoint::parse("https://other-issuer.example/credential").unwrap();
    plan.nonce_endpoint = HttpsEndpoint::parse("https://other-issuer.example/nonce").unwrap();
    let mut offer = offer();
    offer.credential_issuer = HttpsIdentifier::parse(OTHER_ISSUER).unwrap();
    AuthorizationFlowConfig::from_plan_and_offer(
        &plan,
        &offer,
        CLIENT_ID,
        REDIRECT,
        key(),
        client_attestation_key_for(AS, OTHER_ISSUER),
    )
    .unwrap()
}

fn environment<'a>(random: &'a dyn Random, now: i64) -> AuthorizationEnvironment<'a> {
    AuthorizationEnvironment {
        random,
        digest: &AwsLc,
        verifier: &TEST_VERIFIER,
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
        vec![content_type.to_owned()],
        if cache {
            vec!["no-cache, no-store".to_owned()]
        } else {
            vec!["no-cache".to_owned()]
        },
        vec![],
        vec![],
        dpop_nonce_headers,
        vec![],
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
        vec![content_type.to_owned()],
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
        vec![],
        dpop_nonce_headers,
        vec![],
        body,
    )
}

fn wallet_attestation_jwt(
    request: &WalletAttestationRequest,
    marker: u8,
    now_epoch_seconds: i64,
) -> String {
    let header = serde_json::json!({
        "alg": "ES256",
        "kid": format!("attester-{marker}"),
        "typ": "oauth-client-attestation+jwt",
        "x5c": [Base64::encode_string(WALLET_ATTESTATION_SIGNER_CERTIFICATE)],
    });
    let claims = serde_json::json!({
        "sub": request.client_id(),
        "wallet_name": "de.example.competitive-wallet",
        "wallet_version": "1.0.0",
        "wallet_solution_certification_information": {
            "certification": "DE-test-certificate-1"
        },
        "iat": now_epoch_seconds,
        "exp": now_epoch_seconds + 3_600,
        "client_status": {
            "status": {
                "status_list": {
                    "idx": u64::from(marker),
                    "uri": "https://wallet-provider.example/status/wia"
                }
            },
            "exp": now_epoch_seconds + 32 * 24 * 60 * 60
        },
        "cnf": {"jwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": request.public_jwk().x(),
            "y": request.public_jwk().y(),
        }},
    });
    signed_wallet_attestation(&header, &claims)
}

fn signed_wallet_attestation(header: &serde_json::Value, claims: &serde_json::Value) -> String {
    let signing_input = format!(
        "{}.{}",
        Base64UrlUnpadded::encode_string(&serde_json::to_vec(&header).unwrap()),
        Base64UrlUnpadded::encode_string(&serde_json::to_vec(&claims).unwrap()),
    );
    let signer = SoftwareSigner::from_pkcs8_der(WALLET_ATTESTATION_SIGNER_PKCS8).unwrap();
    let signature = signer
        .sign(
            &KeyRef("wallet-attestation-signer".to_owned()),
            Alg::Es256,
            signing_input.as_bytes(),
        )
        .unwrap();
    format!(
        "{signing_input}.{}",
        Base64UrlUnpadded::encode_string(&signature)
    )
}

fn decoded_wallet_attestation(jwt: &str) -> (serde_json::Value, serde_json::Value) {
    let segments: Vec<_> = jwt.split('.').collect();
    assert_eq!(segments.len(), 3);
    (
        serde_json::from_slice(&Base64UrlUnpadded::decode_vec(segments[0]).unwrap()).unwrap(),
        serde_json::from_slice(&Base64UrlUnpadded::decode_vec(segments[1]).unwrap()).unwrap(),
    )
}

fn assert_modified_wallet_attestation_rejected(
    now_epoch_seconds: i64,
    mutate: impl FnOnce(&mut serde_json::Value, &mut serde_json::Value),
    expected: AuthorizationError,
) {
    let random = SequenceRandom::new();
    let env = environment(&random, now_epoch_seconds);
    let (mut flow, effect) = AuthorizationFlow::begin(config(), &env).unwrap();
    let request = match effect {
        AuthorizationEffect::AcquireWalletAttestation(request) => request,
        other => panic!("expected Wallet Attestation acquisition, got {other:?}"),
    };
    let jwt = wallet_attestation_jwt(&request, 1, now_epoch_seconds);
    let (mut header, mut claims) = decoded_wallet_attestation(&jwt);
    mutate(&mut header, &mut claims);
    let jwt = signed_wallet_attestation(&header, &claims);
    assert_eq!(
        flow.step(
            AuthorizationInput::WalletAttestation(WalletAttestation::new(
                request.request_id(),
                &jwt,
            )),
            &env,
        )
        .unwrap_err(),
        expected
    );
    assert_eq!(flow.status(), FlowStatus::Failed);
}

/// Satisfy challenge retrieval, backend attestation acquisition, and local PoP signing until the
/// flow reaches its next network or DPoP effect.
fn drive_client_authentication(
    flow: &mut AuthorizationFlow,
    mut effect: AuthorizationEffect,
    environment: &AuthorizationEnvironment<'_>,
    marker: u8,
) -> Vec<AuthorizationEffect> {
    loop {
        match effect {
            AuthorizationEffect::FetchAttestationChallenge(request) => {
                assert_eq!(request.method(), "POST");
                assert_eq!(request.accept(), "application/json");
                assert_eq!(request.accept_encoding(), "identity");
                let response = EndpointResponse::new(
                    request.request_id(),
                    request.endpoint(),
                    "POST",
                    200,
                    vec!["application/json".to_owned()],
                    vec!["no-store".to_owned()],
                    vec![],
                    vec![],
                    vec![],
                    vec![],
                    format!(r#"{{"attestation_challenge":"challenge-{marker}"}}"#).into_bytes(),
                );
                effect = flow
                    .step(
                        AuthorizationInput::AttestationChallengeResponse(response),
                        environment,
                    )
                    .unwrap()
                    .into_iter()
                    .next()
                    .unwrap();
            }
            AuthorizationEffect::AcquireWalletAttestation(request) => {
                let jwt = wallet_attestation_jwt(&request, marker, environment.now_epoch_seconds);
                effect = flow
                    .step(
                        AuthorizationInput::WalletAttestation(WalletAttestation::new(
                            request.request_id(),
                            &jwt,
                        )),
                        environment,
                    )
                    .unwrap()
                    .into_iter()
                    .next()
                    .unwrap();
            }
            AuthorizationEffect::ReserveWalletAttestationUsage(request) => {
                assert_eq!(request.credential_issuer(), ISSUER);
                assert_eq!(request.authorization_server(), AS);
                assert_eq!(
                    request.policy(),
                    WalletAttestationUsagePolicy::SingleIssuance
                );
                let result = WalletAttestationUsageReservationResult::committed(&request);
                effect = flow
                    .step(
                        AuthorizationInput::WalletAttestationUsageReservation(result),
                        environment,
                    )
                    .unwrap()
                    .into_iter()
                    .next()
                    .unwrap();
            }
            AuthorizationEffect::SignClientAttestationPop(request) => {
                assert_eq!(request.key_ref().0, "client-instance-key-reference");
                assert_eq!(request.algorithm(), crypto_traits::Alg::Es256);
                return flow
                    .step(
                        AuthorizationInput::ClientAttestationPopSignature(
                            ClientAttestationPopSignature::new(
                                request.request_id(),
                                request.signing_input().to_vec(),
                                vec![marker; 64],
                            ),
                        ),
                        environment,
                    )
                    .unwrap();
            }
            other => return vec![other],
        }
    }
}

fn commit_wallet_attestation_usage(
    flow: &mut AuthorizationFlow,
    effect: AuthorizationEffect,
    environment: &AuthorizationEnvironment<'_>,
) -> AuthorizationEffect {
    let request = match effect {
        AuthorizationEffect::ReserveWalletAttestationUsage(request) => request,
        other => panic!("expected Wallet Attestation reservation, got {other:?}"),
    };
    let result = WalletAttestationUsageReservationResult::committed(&request);
    flow.step(
        AuthorizationInput::WalletAttestationUsageReservation(result),
        environment,
    )
    .unwrap()
    .into_iter()
    .next()
    .unwrap()
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
    let effects = drive_client_authentication(&mut flow, effect, &env, 1);
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
    assert_eq!(authorization.method(), "GET");
    assert_eq!(authorization.accept_encoding(), "identity");
    FlowAtAuthorization { flow, state }
}

struct FlowAtTokenAuth {
    flow: AuthorizationFlow,
    effect: AuthorizationEffect,
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
    let effect = effects.into_iter().next().unwrap();
    FlowAtTokenAuth { flow, effect }
}

struct FlowAtDpop {
    flow: AuthorizationFlow,
    request_id: CorrelationId,
    signing_input: Vec<u8>,
}

fn flow_at_dpop(random: &SequenceRandom, dpop_nonce: Vec<String>, marker: u8) -> FlowAtDpop {
    let env = environment(random, 1_700_000_002);
    let FlowAtTokenAuth { mut flow, effect } = flow_at_token_auth(random, dpop_nonce);
    let effects = drive_client_authentication(&mut flow, effect, &env, marker);
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
    assert_eq!(token.method(), "POST");
    assert_eq!(token.accept(), "application/json");
    assert_eq!(token.accept_encoding(), "identity");
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
    assert_eq!(
        grant.client_attestation_key_ref().0,
        "client-instance-key-reference"
    );
    assert_eq!(
        grant.client_attestation_public_jwk().x(),
        Base64UrlUnpadded::encode_string(&[3u8; 32])
    );
    assert_eq!(
        grant.client_attestation_public_jwk().y(),
        Base64UrlUnpadded::encode_string(&[4u8; 32])
    );
    let debug = format!("{grant:?}");
    assert!(!debug.contains("client-instance-key-reference"));
    assert!(!debug.contains(grant.client_attestation_public_jwk().x()));
}

#[test]
fn pkce_challenge_is_exact_s256_and_par_carries_only_profiled_fields() {
    let random = SequenceRandom::new();
    let env = environment(&random, 1_700_000_000);
    let (mut flow, effect) = AuthorizationFlow::begin(config(), &env).unwrap();
    let effects = drive_client_authentication(&mut flow, effect, &env, 1);
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
    assert_eq!(par.oauth_client_attestation().split('.').count(), 3);
    assert_eq!(par.oauth_client_attestation_pop().split('.').count(), 3);
    assert_eq!(par.method(), "POST");
    assert_eq!(par.accept(), "application/json");
    assert_eq!(par.accept_encoding(), "identity");
    assert!(!body.contains("code_verifier"));
    assert!(!format!("{par:?}").contains("YXR0ZXN0YXRpb24"));
}

#[test]
fn wallet_attestation_pop_is_required_and_distinct_from_token_dpop() {
    let random = SequenceRandom::new();
    let env = environment(&random, 1_700_000_000);
    let (mut flow, first) = AuthorizationFlow::begin(config(), &env).unwrap();
    let attestation = match first {
        AuthorizationEffect::AcquireWalletAttestation(request) => request,
        other => panic!("expected Wallet Attestation acquisition, got {other:?}"),
    };
    assert!(!format!("{attestation:?}").contains(AS));
    assert!(!format!("{attestation:?}").contains(PAR));
    let jwt = wallet_attestation_jwt(&attestation, 1, env.now_epoch_seconds);
    let effect = flow
        .step(
            AuthorizationInput::WalletAttestation(WalletAttestation::new(
                attestation.request_id(),
                &jwt,
            )),
            &env,
        )
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    let effect = commit_wallet_attestation_usage(&mut flow, effect, &env);
    let pop = match effect {
        AuthorizationEffect::SignClientAttestationPop(request) => request,
        other => panic!("expected local Client Attestation PoP signing, got {other:?}"),
    };
    let segments: Vec<_> = core::str::from_utf8(pop.signing_input())
        .unwrap()
        .split('.')
        .collect();
    let header: serde_json::Value =
        serde_json::from_slice(&Base64UrlUnpadded::decode_vec(segments[0]).unwrap()).unwrap();
    let payload: serde_json::Value =
        serde_json::from_slice(&Base64UrlUnpadded::decode_vec(segments[1]).unwrap()).unwrap();
    assert_eq!(header["typ"], "oauth-client-attestation-pop+jwt");
    assert_eq!(header["alg"], "ES256");
    assert_eq!(payload["iss"], CLIENT_ID);
    assert_eq!(payload["aud"], AS);
    assert_eq!(payload["iat"], env.now_epoch_seconds);
    assert_eq!(payload["jti"].as_str().unwrap().len(), 43);
    assert!(payload.get("challenge").is_none());
    let effects = flow
        .step(
            AuthorizationInput::ClientAttestationPopSignature(ClientAttestationPopSignature::new(
                pop.request_id(),
                pop.signing_input().to_vec(),
                vec![1; 64],
            )),
            &env,
        )
        .unwrap();
    assert!(matches!(effects[0], AuthorizationEffect::SendPar(_)));

    let token_random = SequenceRandom::new();
    let FlowAtTokenAuth { mut flow, effect } = flow_at_token_auth(&token_random, vec![]);
    assert!(matches!(
        effect,
        AuthorizationEffect::SignClientAttestationPop(_)
    ));
    let token_env = environment(&token_random, 1_700_000_002);
    let effects = drive_client_authentication(&mut flow, effect, &token_env, 2);
    assert!(matches!(effects[0], AuthorizationEffect::SignDpop(_)));
}

#[test]
fn durable_single_issuance_reservation_precedes_pop_and_blocks_cross_provider_reuse() {
    let random = SequenceRandom::new();
    let env = environment(&random, 1_700_000_000);
    let (mut first_flow, effect) = AuthorizationFlow::begin(config(), &env).unwrap();
    let first_acquisition = match effect {
        AuthorizationEffect::AcquireWalletAttestation(request) => request,
        _ => unreachable!(),
    };
    let acquisition_debug = format!("{first_acquisition:?}");
    assert!(!acquisition_debug.contains("client-instance-key-reference"));
    assert!(!acquisition_debug.contains(ISSUER));
    assert!(!acquisition_debug.contains(AS));
    let jwt = wallet_attestation_jwt(&first_acquisition, 1, env.now_epoch_seconds);
    let first_reservation = match first_flow
        .step(
            AuthorizationInput::WalletAttestation(WalletAttestation::new(
                first_acquisition.request_id(),
                &jwt,
            )),
            &env,
        )
        .unwrap()
        .into_iter()
        .next()
        .unwrap()
    {
        AuthorizationEffect::ReserveWalletAttestationUsage(request) => request,
        other => panic!("WIA escaped before durable reservation: {other:?}"),
    };
    assert_eq!(
        first_flow.status(),
        FlowStatus::AwaitingWalletAttestationUsageReservation(EndpointPurpose::Par)
    );
    assert_eq!(first_reservation.credential_issuer(), ISSUER);
    assert_eq!(first_reservation.authorization_server(), AS);
    assert!(first_reservation
        .wallet_attestation_hash()
        .iter()
        .any(|byte| *byte != 0));
    assert!(first_reservation
        .client_status_reference_hash()
        .iter()
        .any(|byte| *byte != 0));

    let (mut other_flow, effect) =
        AuthorizationFlow::begin(config_for_other_issuer(), &env).unwrap();
    let other_acquisition = match effect {
        AuthorizationEffect::AcquireWalletAttestation(request) => request,
        _ => unreachable!(),
    };
    let other_reservation = match other_flow
        .step(
            AuthorizationInput::WalletAttestation(WalletAttestation::new(
                other_acquisition.request_id(),
                &jwt,
            )),
            &env,
        )
        .unwrap()
        .into_iter()
        .next()
        .unwrap()
    {
        AuthorizationEffect::ReserveWalletAttestationUsage(request) => request,
        _ => unreachable!(),
    };
    assert_eq!(
        first_reservation.wallet_attestation_hash(),
        other_reservation.wallet_attestation_hash()
    );
    assert_eq!(
        first_reservation.client_status_reference_hash(),
        other_reservation.client_status_reference_hash()
    );
    assert_ne!(
        first_reservation.issuance_id().as_bytes(),
        other_reservation.issuance_id().as_bytes()
    );
    assert_eq!(other_reservation.credential_issuer(), OTHER_ISSUER);

    let committed = WalletAttestationUsageReservationResult::committed(&first_reservation);
    let effects = first_flow
        .step(
            AuthorizationInput::WalletAttestationUsageReservation(committed),
            &env,
        )
        .unwrap();
    assert!(matches!(
        effects[0],
        AuthorizationEffect::SignClientAttestationPop(_)
    ));

    // A durable ledger sees the duplicate WIA and status-entry hashes bound to another provider
    // and returns an exact rejection; the core latches closed before constructing a PoP or PAR.
    let rejected = WalletAttestationUsageReservationResult::rejected(&other_reservation);
    assert_eq!(
        other_flow
            .step(
                AuthorizationInput::WalletAttestationUsageReservation(rejected),
                &env,
            )
            .unwrap_err(),
        AuthorizationError::ClientAuthenticationReservationRejected
    );
    assert_eq!(other_flow.status(), FlowStatus::Failed);
}

#[test]
fn advertised_challenge_endpoint_and_response_header_drive_the_next_local_pop() {
    let random = SequenceRandom::new();
    let env = environment(&random, 1_700_000_000);
    let (mut flow, first) = AuthorizationFlow::begin(config_with_challenge(), &env).unwrap();
    let challenge_request = match first {
        AuthorizationEffect::FetchAttestationChallenge(request) => request,
        other => panic!("expected challenge retrieval, got {other:?}"),
    };
    assert_eq!(challenge_request.endpoint(), CHALLENGE);
    assert_eq!(challenge_request.accept_encoding(), "identity");
    let effect = flow
        .step(
            AuthorizationInput::AttestationChallengeResponse(EndpointResponse::new(
                challenge_request.request_id(),
                CHALLENGE,
                "POST",
                200,
                vec!["application/json".to_owned()],
                vec!["private, no-store".to_owned()],
                vec![],
                vec![],
                vec![],
                vec![],
                br#"{"attestation_challenge":"par-challenge"}"#.to_vec(),
            )),
            &env,
        )
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    let attestation = match effect {
        AuthorizationEffect::AcquireWalletAttestation(request) => request,
        _ => unreachable!(),
    };
    let jwt = wallet_attestation_jwt(&attestation, 1, env.now_epoch_seconds);
    let reservation = flow
        .step(
            AuthorizationInput::WalletAttestation(WalletAttestation::new(
                attestation.request_id(),
                &jwt,
            )),
            &env,
        )
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    let pop = match commit_wallet_attestation_usage(&mut flow, reservation, &env) {
        AuthorizationEffect::SignClientAttestationPop(request) => request,
        _ => unreachable!(),
    };
    let payload_segment = core::str::from_utf8(pop.signing_input())
        .unwrap()
        .split('.')
        .nth(1)
        .unwrap();
    let payload: serde_json::Value =
        serde_json::from_slice(&Base64UrlUnpadded::decode_vec(payload_segment).unwrap()).unwrap();
    assert_eq!(payload["challenge"], "par-challenge");
    let par = match flow
        .step(
            AuthorizationInput::ClientAttestationPopSignature(ClientAttestationPopSignature::new(
                pop.request_id(),
                pop.signing_input().to_vec(),
                vec![1; 64],
            )),
            &env,
        )
        .unwrap()
        .into_iter()
        .next()
        .unwrap()
    {
        AuthorizationEffect::SendPar(request) => request,
        _ => unreachable!(),
    };
    let state = field(core::str::from_utf8(par.body()).unwrap(), "state").to_owned();
    let response = par_response(
        par.request_id(),
        201,
        "application/json",
        false,
        vec![],
        br#"{"request_uri":"urn:next","expires_in":60}"#.to_vec(),
    )
    .with_attestation_challenge_headers(vec!["token-challenge".to_owned()]);
    flow.step(AuthorizationInput::ParResponse(response), &env)
        .unwrap();
    let query = format!("code=AUTH-CODE&state={state}&iss={}", percent_encode(AS));
    let effect = flow
        .step(
            AuthorizationInput::AuthorizationRedirect(AuthorizationRedirect::new(
                REDIRECT,
                query.into_bytes(),
            )),
            &environment(&random, 1_700_000_001),
        )
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    let token_pop = match effect {
        AuthorizationEffect::SignClientAttestationPop(request) => request,
        other => panic!("header challenge should avoid another fetch, got {other:?}"),
    };
    let payload_segment = core::str::from_utf8(token_pop.signing_input())
        .unwrap()
        .split('.')
        .nth(1)
        .unwrap();
    let payload: serde_json::Value =
        serde_json::from_slice(&Base64UrlUnpadded::decode_vec(payload_segment).unwrap()).unwrap();
    assert_eq!(payload["challenge"], "token-challenge");
}

#[test]
fn challenge_endpoint_rejects_cacheable_oversized_duplicate_and_dual_challenges() {
    for (cache, body, headers, expected) in [
        (
            vec!["private".to_owned()],
            br#"{"attestation_challenge":"one"}"#.to_vec(),
            vec![],
            AuthorizationError::AttestationChallengeInvalid,
        ),
        (
            vec!["no-store".to_owned()],
            vec![b' '; oid4vci::authorization::MAX_ATTESTATION_CHALLENGE_RESPONSE_BYTES + 1],
            vec![],
            AuthorizationError::AttestationChallengeInvalid,
        ),
        (
            vec!["no-store".to_owned()],
            br#"{"attestation_challenge":"one"}"#.to_vec(),
            vec!["one".to_owned(), "two".to_owned()],
            AuthorizationError::AttestationChallengeInvalid,
        ),
        (
            vec!["no-store".to_owned()],
            br#"{"attestation_challenge":"body"}"#.to_vec(),
            vec!["header".to_owned()],
            AuthorizationError::AttestationChallengeInvalid,
        ),
    ] {
        let random = SequenceRandom::new();
        let env = environment(&random, 1_700_000_000);
        let (mut flow, first) = AuthorizationFlow::begin(config_with_challenge(), &env).unwrap();
        let request = match first {
            AuthorizationEffect::FetchAttestationChallenge(request) => request,
            _ => unreachable!(),
        };
        let response = EndpointResponse::new(
            request.request_id(),
            CHALLENGE,
            "POST",
            200,
            vec!["application/json".to_owned()],
            cache,
            vec![],
            vec![],
            vec![],
            headers,
            body,
        );
        assert_eq!(
            flow.step(
                AuthorizationInput::AttestationChallengeResponse(response),
                &env,
            )
            .unwrap_err(),
            expected
        );
    }
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
        client_attestation_key(),
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
            client_attestation_key(),
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
            client_attestation_key(),
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
            client_attestation_key(),
        ),
        Err(AuthorizationError::InvalidConfiguration)
    ));

    let scoped_to_other_as = ClientAttestationKeyBinding::new(
        "https://other-as.example",
        ISSUER,
        KeyRef("other-client-instance-key".to_owned()),
        Es256PublicJwk::parse(
            &Base64UrlUnpadded::encode_string(&[3u8; 32]),
            &Base64UrlUnpadded::encode_string(&[4u8; 32]),
        )
        .unwrap(),
        WalletAttestationUsagePolicy::SingleIssuance,
    )
    .unwrap();
    assert!(matches!(
        AuthorizationFlowConfig::from_plan_and_offer(
            &plan(),
            &offer(),
            CLIENT_ID,
            REDIRECT,
            key(),
            scoped_to_other_as,
        ),
        Err(AuthorizationError::InvalidConfiguration)
    ));

    let scoped_to_other_provider = client_attestation_key_for(AS, OTHER_ISSUER);
    assert!(matches!(
        AuthorizationFlowConfig::from_plan_and_offer(
            &plan(),
            &offer(),
            CLIENT_ID,
            REDIRECT,
            key(),
            scoped_to_other_provider,
        ),
        Err(AuthorizationError::InvalidConfiguration)
    ));

    let mut excessive_status_period = plan();
    excessive_status_period.preferred_client_status_period =
        Some(MAX_PREFERRED_CLIENT_STATUS_PERIOD_SECONDS + 1);
    assert!(matches!(
        AuthorizationFlowConfig::from_plan_and_offer(
            &excessive_status_period,
            &offer(),
            CLIENT_ID,
            REDIRECT,
            key(),
            client_attestation_key(),
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
    let (mut flow, _) = AuthorizationFlow::begin(config(), &environment(&random, 100)).unwrap();
    assert_eq!(
        flow.step(
            AuthorizationInput::WalletAttestation(WalletAttestation::new(
                CorrelationId::from_bytes([9; 32]),
                "not-used",
            )),
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
        client_attestation_key(),
    )
    .unwrap();
    let random = SequenceRandom::new();
    let env = environment(&random, 1_700_000_000);
    let (mut flow, effect) = AuthorizationFlow::begin(config, &env).unwrap();
    let effects = drive_client_authentication(&mut flow, effect, &env, 1);
    let par = match effects.into_iter().next().unwrap() {
        AuthorizationEffect::SendPar(request) => request,
        _ => unreachable!(),
    };
    let body = core::str::from_utf8(par.body()).unwrap();
    assert_eq!(field(body, "issuer_state"), "context%20a%26b");
    assert_eq!(body.matches("issuer_state=").count(), 1);
}

#[test]
fn client_attestation_is_cnf_bound_and_local_pop_result_is_correlated() {
    let random = SequenceRandom::new();
    let env = environment(&random, 1_700_000_000);
    let (mut flow, effect) = AuthorizationFlow::begin(config(), &env).unwrap();
    let request = match effect {
        AuthorizationEffect::AcquireWalletAttestation(request) => request,
        other => panic!("expected attestation request, got {other:?}"),
    };
    let jwt = wallet_attestation_jwt(&request, 1, env.now_epoch_seconds);
    let segments: Vec<_> = jwt.split('.').collect();
    let header: serde_json::Value =
        serde_json::from_slice(&Base64UrlUnpadded::decode_vec(segments[0]).unwrap()).unwrap();
    let mut claims: serde_json::Value =
        serde_json::from_slice(&Base64UrlUnpadded::decode_vec(segments[1]).unwrap()).unwrap();
    claims["cnf"]["jwk"]["x"] = serde_json::json!(Base64UrlUnpadded::encode_string(&[9; 32]));
    let bad = signed_wallet_attestation(&header, &claims);
    assert_eq!(
        flow.step(
            AuthorizationInput::WalletAttestation(WalletAttestation::new(
                request.request_id(),
                &bad,
            )),
            &env,
        )
        .unwrap_err(),
        AuthorizationError::ClientAuthenticationBindingMismatch
    );
    assert_eq!(flow.status(), FlowStatus::Failed);

    let random = SequenceRandom::new();
    let env = environment(&random, 1_700_000_000);
    let (mut flow, effect) = AuthorizationFlow::begin(config(), &env).unwrap();
    let request = match effect {
        AuthorizationEffect::AcquireWalletAttestation(request) => request,
        _ => unreachable!(),
    };
    let jwt = wallet_attestation_jwt(&request, 2, env.now_epoch_seconds);
    let reservation = flow
        .step(
            AuthorizationInput::WalletAttestation(WalletAttestation::new(
                request.request_id(),
                &jwt,
            )),
            &env,
        )
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    let pop = match commit_wallet_attestation_usage(&mut flow, reservation, &env) {
        AuthorizationEffect::SignClientAttestationPop(request) => request,
        _ => unreachable!(),
    };
    assert_eq!(
        flow.step(
            AuthorizationInput::ClientAttestationPopSignature(ClientAttestationPopSignature::new(
                CorrelationId::from_bytes([77; 32]),
                pop.signing_input().to_vec(),
                vec![2; 64],
            ),),
            &env,
        )
        .unwrap_err(),
        AuthorizationError::ClientAttestationPopSigningResultMismatch
    );
}

#[test]
fn local_client_attestation_pop_signature_is_cryptographically_verified() {
    let random = SequenceRandom::new();
    let env = environment(&random, 1_700_000_000);
    let (mut flow, effect) = AuthorizationFlow::begin(config(), &env).unwrap();
    let request = match effect {
        AuthorizationEffect::AcquireWalletAttestation(request) => request,
        _ => unreachable!(),
    };
    let jwt = wallet_attestation_jwt(&request, 1, env.now_epoch_seconds);
    let reservation = flow
        .step(
            AuthorizationInput::WalletAttestation(WalletAttestation::new(
                request.request_id(),
                &jwt,
            )),
            &env,
        )
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    let pop = match commit_wallet_attestation_usage(&mut flow, reservation, &env) {
        AuthorizationEffect::SignClientAttestationPop(request) => request,
        _ => unreachable!(),
    };
    let rejecting_environment = AuthorizationEnvironment {
        random: &random,
        digest: &AwsLc,
        verifier: &REJECTING_VERIFIER,
        now_epoch_seconds: env.now_epoch_seconds,
    };
    assert_eq!(
        flow.step(
            AuthorizationInput::ClientAttestationPopSignature(ClientAttestationPopSignature::new(
                pop.request_id(),
                pop.signing_input().to_vec(),
                vec![1; 64],
            ),),
            &rejecting_environment,
        )
        .unwrap_err(),
        AuthorizationError::ClientAttestationPopSignatureInvalid
    );
}

#[test]
fn malformed_wallet_attestation_never_reaches_transport() {
    let random = SequenceRandom::new();
    let env = environment(&random, 1_700_000_000);
    let (mut flow, effect) = AuthorizationFlow::begin(config(), &env).unwrap();
    let request = match effect {
        AuthorizationEffect::AcquireWalletAttestation(request) => request,
        _ => unreachable!(),
    };
    assert_eq!(
        flow.step(
            AuthorizationInput::WalletAttestation(WalletAttestation::new(
                request.request_id(),
                "not-a-jwt",
            )),
            &env
        )
        .unwrap_err(),
        AuthorizationError::ClientAuthenticationInvalid
    );
}

#[test]
fn wallet_attestation_requires_a_canonical_parseable_x5c_chain_and_valid_leaf_signature() {
    let now = 1_700_000_000;
    assert_modified_wallet_attestation_rejected(
        now,
        |header, _| {
            header.as_object_mut().unwrap().remove("x5c");
        },
        AuthorizationError::ClientAuthenticationInvalid,
    );
    assert_modified_wallet_attestation_rejected(
        now,
        |header, _| header["x5c"] = serde_json::json!([]),
        AuthorizationError::ClientAuthenticationInvalid,
    );
    assert_modified_wallet_attestation_rejected(
        now,
        |header, _| header["x5c"] = serde_json::json!(["%%%"]),
        AuthorizationError::ClientAuthenticationInvalid,
    );
    assert_modified_wallet_attestation_rejected(
        now,
        |header, _| {
            let canonical = Base64::encode_string(WALLET_ATTESTATION_SIGNER_CERTIFICATE);
            header["x5c"] = serde_json::json!([canonical.trim_end_matches('=')]);
        },
        AuthorizationError::ClientAuthenticationInvalid,
    );
    assert_modified_wallet_attestation_rejected(
        now,
        |header, _| {
            header["x5c"] = serde_json::json!([
                Base64::encode_string(WALLET_ATTESTATION_SIGNER_CERTIFICATE),
                "AQ=="
            ]);
        },
        AuthorizationError::ClientAuthenticationInvalid,
    );
    assert_modified_wallet_attestation_rejected(
        now,
        |header, _| {
            let certificate = Base64::encode_string(WALLET_ATTESTATION_SIGNER_CERTIFICATE);
            header["x5c"] = serde_json::json!([certificate, certificate]);
        },
        AuthorizationError::ClientAuthenticationInvalid,
    );

    let random = SequenceRandom::new();
    let env = environment(&random, now);
    let (mut flow, effect) = AuthorizationFlow::begin(config(), &env).unwrap();
    let request = match effect {
        AuthorizationEffect::AcquireWalletAttestation(request) => request,
        _ => unreachable!(),
    };
    let jwt = wallet_attestation_jwt(&request, 1, now);
    let segments: Vec<_> = jwt.split('.').collect();
    let mut signature = Base64UrlUnpadded::decode_vec(segments[2]).unwrap();
    signature[0] ^= 1;
    let wrong_signature = format!(
        "{}.{}.{}",
        segments[0],
        segments[1],
        Base64UrlUnpadded::encode_string(&signature)
    );
    assert_eq!(
        flow.step(
            AuthorizationInput::WalletAttestation(WalletAttestation::new(
                request.request_id(),
                &wrong_signature,
            )),
            &env,
        )
        .unwrap_err(),
        AuthorizationError::ClientAuthenticationInvalid
    );
}

#[test]
fn ts3_wallet_identity_and_client_status_claims_are_required_and_bounded() {
    let now = 1_700_000_000;
    for field in [
        "wallet_name",
        "wallet_version",
        "wallet_solution_certification_information",
        "client_status",
    ] {
        assert_modified_wallet_attestation_rejected(
            now,
            |_, claims| {
                claims.as_object_mut().unwrap().remove(field);
            },
            AuthorizationError::ClientAuthenticationInvalid,
        );
    }

    for (field, value) in [
        ("wallet_name", serde_json::json!("")),
        (
            "wallet_name",
            serde_json::json!("w".repeat(MAX_WALLET_NAME_BYTES + 1)),
        ),
        ("wallet_version", serde_json::json!("")),
        (
            "wallet_version",
            serde_json::json!("v".repeat(MAX_WALLET_VERSION_BYTES + 1)),
        ),
        (
            "wallet_solution_certification_information",
            serde_json::json!(""),
        ),
        (
            "wallet_solution_certification_information",
            serde_json::json!("c".repeat(MAX_WALLET_SOLUTION_CERTIFICATION_INFORMATION_BYTES + 1)),
        ),
    ] {
        assert_modified_wallet_attestation_rejected(
            now,
            |_, claims| claims[field] = value,
            AuthorizationError::ClientAuthenticationInvalid,
        );
    }

    let malformed_status_values = [
        serde_json::json!({"exp": now + 32 * 24 * 60 * 60}),
        serde_json::json!({"status": {}, "exp": now + 32 * 24 * 60 * 60}),
        serde_json::json!({
            "status": {"status_list": {
                "idx": -1,
                "uri": "https://wallet-provider.example/status/wia"
            }},
            "exp": now + 32 * 24 * 60 * 60
        }),
        serde_json::json!({
            "status": {"status_list": {
                "idx": MAX_TOKEN_STATUS_LIST_INDEX + 1,
                "uri": "https://wallet-provider.example/status/wia"
            }},
            "exp": now + 32 * 24 * 60 * 60
        }),
        serde_json::json!({
            "status": {"status_list": {
                "idx": 1,
                "uri": "http://wallet-provider.example/status/wia"
            }},
            "exp": now + 32 * 24 * 60 * 60
        }),
        serde_json::json!({
            "status": {"status_list": {
                "idx": 1,
                "uri": "https://wallet-provider.example/status/wia"
            }},
            "exp": "later"
        }),
    ];
    for client_status in malformed_status_values {
        assert_modified_wallet_attestation_rejected(
            now,
            |_, claims| claims["client_status"] = client_status,
            AuthorizationError::ClientAuthenticationInvalid,
        );
    }
}

#[test]
fn ts3_wia_time_bounds_allow_optional_iat_and_keep_status_exp_independent() {
    let now = 1_700_000_000;
    let random = SequenceRandom::new();
    let env = environment(&random, now);
    let (mut flow, effect) = AuthorizationFlow::begin(config(), &env).unwrap();
    let request = match effect {
        AuthorizationEffect::AcquireWalletAttestation(request) => request,
        _ => unreachable!(),
    };
    assert!(request.force_fresh_attestation());
    assert_eq!(
        request.required_client_status_period_seconds(),
        MIN_CLIENT_STATUS_MAINTENANCE_SECONDS
    );
    assert_eq!(
        request.lifetime_must_be_less_than_seconds(),
        MAX_WALLET_ATTESTATION_LIFETIME_SECONDS as u64
    );
    let jwt = wallet_attestation_jwt(&request, 1, now);
    let (header, mut claims) = decoded_wallet_attestation(&jwt);
    claims.as_object_mut().unwrap().remove("iat");
    claims["client_status"]["exp"] =
        serde_json::json!(now + MIN_CLIENT_STATUS_MAINTENANCE_SECONDS as i64);
    let jwt = signed_wallet_attestation(&header, &claims);
    let effects = flow
        .step(
            AuthorizationInput::WalletAttestation(WalletAttestation::new(
                request.request_id(),
                &jwt,
            )),
            &env,
        )
        .unwrap();
    assert!(matches!(
        effects[0],
        AuthorizationEffect::ReserveWalletAttestationUsage(_)
    ));

    assert_modified_wallet_attestation_rejected(
        now,
        |_, claims| {
            claims["exp"] = serde_json::json!(now + MAX_WALLET_ATTESTATION_LIFETIME_SECONDS);
            claims.as_object_mut().unwrap().remove("iat");
        },
        AuthorizationError::ClientAuthenticationInvalid,
    );
    assert_modified_wallet_attestation_rejected(
        now,
        |_, claims| {
            claims["iat"] = serde_json::json!(now);
            claims["exp"] = serde_json::json!(now + MAX_WALLET_ATTESTATION_LIFETIME_SECONDS);
        },
        AuthorizationError::ClientAuthenticationInvalid,
    );
    assert_modified_wallet_attestation_rejected(
        now,
        |_, claims| {
            claims["client_status"]["exp"] =
                serde_json::json!(now + MIN_CLIENT_STATUS_MAINTENANCE_SECONDS as i64 - 1);
        },
        AuthorizationError::ClientAuthenticationInvalid,
    );
}

#[test]
fn metadata_preference_raises_but_never_lowers_the_client_status_floor() {
    let now = 1_700_000_000;
    let random = SequenceRandom::new();
    let env = environment(&random, now);
    let (mut flow, effect) = AuthorizationFlow::begin(
        config_with_preferred_client_status_period(45 * 24 * 60 * 60),
        &env,
    )
    .unwrap();
    let request = match effect {
        AuthorizationEffect::AcquireWalletAttestation(request) => request,
        _ => unreachable!(),
    };
    assert_eq!(
        request.required_client_status_period_seconds(),
        45 * 24 * 60 * 60
    );
    let too_short = wallet_attestation_jwt(&request, 1, now);
    assert_eq!(
        flow.step(
            AuthorizationInput::WalletAttestation(WalletAttestation::new(
                request.request_id(),
                &too_short,
            )),
            &env,
        )
        .unwrap_err(),
        AuthorizationError::ClientAuthenticationInvalid
    );

    let random = SequenceRandom::new();
    let env = environment(&random, now);
    let (mut flow, effect) = AuthorizationFlow::begin(
        config_with_preferred_client_status_period(45 * 24 * 60 * 60),
        &env,
    )
    .unwrap();
    let request = match effect {
        AuthorizationEffect::AcquireWalletAttestation(request) => request,
        _ => unreachable!(),
    };
    let jwt = wallet_attestation_jwt(&request, 2, now);
    let (header, mut claims) = decoded_wallet_attestation(&jwt);
    claims["client_status"]["exp"] = serde_json::json!(now + 45 * 24 * 60 * 60);
    let exact = signed_wallet_attestation(&header, &claims);
    assert!(matches!(
        flow.step(
            AuthorizationInput::WalletAttestation(WalletAttestation::new(
                request.request_id(),
                &exact,
            )),
            &env,
        )
        .unwrap()[0],
        AuthorizationEffect::ReserveWalletAttestationUsage(_)
    ));

    let random = SequenceRandom::new();
    let env = environment(&random, now);
    let (_, effect) =
        AuthorizationFlow::begin(config_with_preferred_client_status_period(0), &env).unwrap();
    let request = match effect {
        AuthorizationEffect::AcquireWalletAttestation(request) => request,
        _ => unreachable!(),
    };
    assert_eq!(
        request.required_client_status_period_seconds(),
        MIN_CLIENT_STATUS_MAINTENANCE_SECONDS
    );
}

#[test]
fn attestation_challenge_errors_require_a_fresh_header_and_have_a_finite_retry_budget() {
    let random = SequenceRandom::new();
    let FlowAtPar {
        mut flow,
        request_id,
        ..
    } = flow_at_par(&random);
    let missing = par_response(
        request_id,
        400,
        "application/json",
        false,
        vec![],
        br#"{"error":"use_attestation_challenge"}"#.to_vec(),
    );
    assert_eq!(
        flow.step(
            AuthorizationInput::ParResponse(missing),
            &environment(&random, 1_700_000_001),
        )
        .unwrap_err(),
        AuthorizationError::AttestationChallengeInvalid
    );

    let random = SequenceRandom::new();
    let FlowAtPar {
        mut flow,
        request_id,
        ..
    } = flow_at_par(&random);
    let response = par_response(
        request_id,
        400,
        "application/json",
        false,
        vec![],
        br#"{"error":"use_attestation_challenge"}"#.to_vec(),
    )
    .with_attestation_challenge_headers(vec!["replayed-challenge".to_owned()]);
    let effect = flow
        .step(
            AuthorizationInput::ParResponse(response),
            &environment(&random, 1_700_000_001),
        )
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    let retried =
        drive_client_authentication(&mut flow, effect, &environment(&random, 1_700_000_002), 2);
    let retried_request_id = match retried.into_iter().next().unwrap() {
        AuthorizationEffect::SendPar(request) => request.request_id(),
        _ => unreachable!(),
    };
    let replay = par_response(
        retried_request_id,
        400,
        "application/json",
        false,
        vec![],
        br#"{"error":"use_attestation_challenge"}"#.to_vec(),
    )
    .with_attestation_challenge_headers(vec!["replayed-challenge".to_owned()]);
    assert_eq!(
        flow.step(
            AuthorizationInput::ParResponse(replay),
            &environment(&random, 1_700_000_003),
        )
        .unwrap_err(),
        AuthorizationError::AttestationChallengeStale
    );

    let random = SequenceRandom::new();
    let FlowAtPar {
        mut flow,
        request_id,
        ..
    } = flow_at_par(&random);
    let mut next_request_id = request_id;
    for retry in 0..=MAX_CLIENT_ATTESTATION_RETRIES {
        let now = 1_700_000_010 + i64::from(retry) * 3;
        let response = par_response(
            next_request_id,
            400,
            "application/json",
            false,
            vec![],
            br#"{"error":"use_attestation_challenge"}"#.to_vec(),
        )
        .with_attestation_challenge_headers(vec![format!("challenge-retry-{retry}")]);
        let result = flow.step(
            AuthorizationInput::ParResponse(response),
            &environment(&random, now),
        );
        if retry == MAX_CLIENT_ATTESTATION_RETRIES {
            assert_eq!(
                result.unwrap_err(),
                AuthorizationError::AttestationChallengeRetryLimit
            );
            break;
        }
        let retry_env = environment(&random, now + 1);
        let effects = drive_client_authentication(
            &mut flow,
            result.unwrap().into_iter().next().unwrap(),
            &retry_env,
            10 + retry,
        );
        next_request_id = match effects.into_iter().next().unwrap() {
            AuthorizationEffect::SendPar(request) => request.request_id(),
            other => panic!("expected retried PAR, got {other:?}"),
        };
    }
}

#[test]
fn use_fresh_attestation_reacquires_backend_jwt_and_rejects_identical_reuse() {
    let random = SequenceRandom::new();
    let FlowAtPar {
        mut flow,
        request_id,
        ..
    } = flow_at_par(&random);
    let effects = flow
        .step(
            AuthorizationInput::ParResponse(par_response(
                request_id,
                400,
                "application/json",
                false,
                vec![],
                br#"{"error":"use_fresh_attestation"}"#.to_vec(),
            )),
            &environment(&random, 1_700_000_001),
        )
        .unwrap();
    let request = match effects.into_iter().next().unwrap() {
        AuthorizationEffect::AcquireWalletAttestation(request) => request,
        other => panic!("expected forced backend reacquisition, got {other:?}"),
    };
    assert!(request.force_fresh_attestation());
    let reused = wallet_attestation_jwt(&request, 1, 1_700_000_000);
    assert_eq!(
        flow.step(
            AuthorizationInput::WalletAttestation(WalletAttestation::new(
                request.request_id(),
                &reused,
            )),
            &environment(&random, 1_700_000_002),
        )
        .unwrap_err(),
        AuthorizationError::ClientAuthenticationReused
    );

    let random = SequenceRandom::new();
    let FlowAtPar {
        mut flow,
        request_id,
        ..
    } = flow_at_par(&random);
    let effect = flow
        .step(
            AuthorizationInput::ParResponse(par_response(
                request_id,
                401,
                "application/json",
                false,
                vec![],
                br#"{"error":"use_fresh_attestation"}"#.to_vec(),
            )),
            &environment(&random, 1_700_000_001),
        )
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    let effects =
        drive_client_authentication(&mut flow, effect, &environment(&random, 1_700_000_002), 2);
    assert!(matches!(effects[0], AuthorizationEffect::SendPar(_)));
}

#[test]
fn par_response_enforces_duplicate_aware_json_bounds_status_and_fapi_expiry() {
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
            None,
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
                    vec!["application/json".to_owned()],
                    vec!["no-cache, no-store".to_owned()],
                    vec![],
                    vec![],
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
        vec!["application/json; charset=iso-8859-1".to_owned()],
        vec!["no-cache, no-store".to_owned()],
        vec![],
        vec![],
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
        AuthorizationError::InvalidMediaType
    );

    for (content_types, content_encodings, expected) in [
        (
            vec!["application/json".to_owned(), "application/json".to_owned()],
            vec![],
            AuthorizationError::InvalidMediaType,
        ),
        (
            vec!["application/json".to_owned()],
            vec!["gzip".to_owned()],
            AuthorizationError::InvalidContentEncoding,
        ),
        (
            vec!["application/json".to_owned()],
            vec!["identity".to_owned(), "identity".to_owned()],
            AuthorizationError::InvalidContentEncoding,
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
            content_types,
            vec!["no-store".to_owned()],
            vec![],
            content_encodings,
            vec![],
            vec![],
            b"not-json-and-must-not-be-parsed".to_vec(),
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
        vec!["application/json;charset=UTF-8".to_owned()],
        vec!["NO-STORE".to_owned()],
        vec![],
        vec![],
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
    let retry_env = environment(&random, 1_700_000_005);
    let effects = drive_client_authentication(
        &mut flow,
        effects.into_iter().next().unwrap(),
        &retry_env,
        3,
    );
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
        let retry_env = environment(&random, now + 1);
        let effects = drive_client_authentication(
            &mut flow,
            result.unwrap().into_iter().next().unwrap(),
            &retry_env,
            10 + retry,
        );
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
fn dpop_token_type_is_matched_case_insensitively_as_required_by_oauth() {
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
            br#"{"access_token":"A","token_type":"dPoP"}"#.to_vec(),
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
    let bare_public_jwk = Es256PublicJwk::parse(
        &Base64UrlUnpadded::encode_string(&[1u8; 32]),
        &Base64UrlUnpadded::encode_string(&[2u8; 32]),
    )
    .unwrap();
    let diagnostics = format!("{flow:?} {effect:?} {bare_public_jwk:?}");
    for secret in [
        "hardware-key-reference",
        "client-instance-key-reference",
        "AUTH-CODE",
        "ACCESS-TOKEN",
        "REFRESH",
        "par-seeded-nonce",
    ] {
        assert!(!diagnostics.contains(secret));
    }
    for stable_coordinate in [
        Base64UrlUnpadded::encode_string(&[1u8; 32]),
        Base64UrlUnpadded::encode_string(&[2u8; 32]),
        Base64UrlUnpadded::encode_string(&[3u8; 32]),
        Base64UrlUnpadded::encode_string(&[4u8; 32]),
    ] {
        assert!(!diagnostics.contains(&stable_coordinate));
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
