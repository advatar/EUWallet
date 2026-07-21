use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use crypto_backend::AwsLc;
use crypto_traits::{Alg, CryptoError, Digest as _, KeyRef, Random, Signer, Verifier};
use oid4vci::authorization::{
    AuthorizationEffect, AuthorizationEnvironment, AuthorizationFlow, AuthorizationFlowConfig,
    AuthorizationInput, AuthorizationRedirect, ClientAttestationKeyBinding,
    ClientAttestationPopSignature, CorrelationId, DpopKeyBinding, DpopSignature,
    EndpointResponse as AuthorizationEndpointResponse, Es256PublicJwk, WalletAttestation,
    WalletAttestationRequest, WalletAttestationUsagePolicy,
    WalletAttestationUsageReservationResult,
};
use oid4vci::credential::{
    CNonceReservationOutcome, CNonceReservationRequest, CNonceReservationResult, CredentialEffect,
    CredentialEnvironment, CredentialError, CredentialFlow, CredentialFlowConfig, CredentialInput,
    CredentialKeyBinding, CredentialKeyReservationOutcome, CredentialKeyReservationRequest,
    CredentialKeyReservationResult, CredentialSelection, EndpointResponse, FlowStatus,
    KeyAttestation, KeyAttestationRequest, KeyAttestationReservationOutcome,
    KeyAttestationReservationRequest, KeyAttestationReservationResult, SignatureResult,
    MAX_CREDENTIAL_RESPONSE_BYTES, MAX_KEY_ATTESTATION_CLOCK_SKEW_SECONDS,
    MAX_NONCE_RESPONSE_BYTES, MIN_KEY_STORAGE_STATUS_REMAINING_SECONDS,
};
use oid4vci::foundation::{
    AuthorizationCodeGrant, CredentialOffer, CredentialSigningAlgorithm, GermanPidFormat,
    GermanPidIssuancePlan, HolderBindingMethod, HttpsEndpoint, HttpsIdentifier, OfferGrantSource,
    PidProviderTrust, MAX_PREFERRED_KEY_STORAGE_STATUS_PERIOD_SECONDS, MDOC_PID_DOCTYPE,
};
use serde_json::Value;
use std::cell::Cell;
use std::collections::BTreeMap;

const ISSUER: &str = "https://issuer.example/tenant";
const AS: &str = "https://as.example/tenant";
const CLIENT_ID: &str = "https://wallet-provider.example/wallet-type";
const REDIRECT: &str = "https://wallet.example/callback";
const PAR: &str = "https://as.example/par";
const TOKEN: &str = "https://as.example/token?tenant=de";
const NONCE: &str = "https://issuer.example/nonce";
const CREDENTIAL: &str = "https://issuer.example/credential?tenant=de";
const NOW: i64 = 1_700_000_004;
const KEY_ATTESTATION_SIGNER_CERTIFICATE: &[u8] = include_bytes!("../../x509/tests/vectors/rp.der");
// The subject and issuer names are identical, but the certificate contains the RP public key and
// is signed by the distinct test CA key. It is self-issued, not self-signed.
const SELF_ISSUED_NOT_SELF_SIGNED_B64: &str = "MIIBdDCCARugAwIBAgIDBnkyMAoGCCqGSM49BAMCMCExHzAdBgNVBAMMFkVVREkgVGVzdCBSUC1BY2Nlc3MgQ0EwHhcNMjYwNzIwMTc0MTE2WhcNMzYwNzE3MTc0MTE2WjAhMR8wHQYDVQQDDBZFVURJIFRlc3QgUlAtQWNjZXNzIENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEu6l8GEhe0KUU2vBA7lRp0Br1rMtnoRvm0/kS9FEdftAlnMQQmJ/inKO1Yl5T2jiiL3KB+qxttGwcW8JlJImCwqNCMEAwHQYDVR0OBBYEFDMg3Hkisj3Tma9EbJXExUb5WvqPMB8GA1UdIwQYMBaAFD3lIpm8a+/OjwYFG0ITZ7l8IizzMAoGCCqGSM49BAMCA0cAMEQCICTkPCUCo3DVvwiAJXBEIJR3uIfINf7VWb4ryFwlKwiCAiAvigrRK4cDEdvMeeK9G10pFbA0/8qdOKPtaz3fIzoiEg==";

struct SequenceRandom(Cell<u8>);

impl SequenceRandom {
    fn new() -> Self {
        Self(Cell::new(1))
    }
}

impl Random for SequenceRandom {
    fn fill(&self, output: &mut [u8]) {
        let marker = self.0.get();
        output.fill(marker);
        self.0.set(marker.wrapping_add(1));
    }
}

struct ZeroRandom;

impl Random for ZeroRandom {
    fn fill(&self, output: &mut [u8]) {
        output.fill(0);
    }
}

struct TestVerifier;

impl Verifier for TestVerifier {
    fn verify(
        &self,
        _alg: Alg,
        _public_key: &[u8],
        _payload: &[u8],
        _signature: &[u8],
    ) -> Result<(), CryptoError> {
        Ok(())
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
        Err(CryptoError::Backend("test rejection".to_owned()))
    }
}

static REJECTING_VERIFIER: RejectingVerifier = RejectingVerifier;

fn plan(format: GermanPidFormat) -> GermanPidIssuancePlan {
    let (configuration_id, holder_binding, credential_signing_algorithm) = match format {
        GermanPidFormat::DcSdJwt => (
            "pid-sd-jwt",
            HolderBindingMethod::Jwk,
            CredentialSigningAlgorithm::JoseEs256,
        ),
        GermanPidFormat::MsoMdoc => (
            "pid-mdoc",
            HolderBindingMethod::CoseKey,
            CredentialSigningAlgorithm::CoseEs256,
        ),
    };
    GermanPidIssuancePlan {
        credential_issuer: HttpsIdentifier::parse(ISSUER).unwrap(),
        authorization_server: HttpsIdentifier::parse(AS).unwrap(),
        configuration_id: configuration_id.to_owned(),
        format,
        scope: "pid".to_owned(),
        holder_binding,
        credential_signing_algorithm,
        proof_signing_algorithm: "ES256".to_owned(),
        credential_endpoint: HttpsEndpoint::parse(CREDENTIAL).unwrap(),
        nonce_endpoint: HttpsEndpoint::parse(NONCE).unwrap(),
        preferred_client_status_period: None,
        preferred_key_storage_status_period: None,
        authorization_endpoint: HttpsEndpoint::parse("https://as.example/authorize").unwrap(),
        token_endpoint: HttpsEndpoint::parse(TOKEN).unwrap(),
        pushed_authorization_request_endpoint: HttpsEndpoint::parse(PAR).unwrap(),
        attestation_challenge_endpoint: None,
        pid_provider_trust: PidProviderTrust::Unresolved,
    }
}

fn offer(plan: &GermanPidIssuancePlan) -> CredentialOffer {
    CredentialOffer {
        credential_issuer: plan.credential_issuer.clone(),
        credential_configuration_ids: vec![plan.configuration_id.clone()],
        authorization_code: Some(AuthorizationCodeGrant {
            issuer_state: None,
            authorization_server: Some(HttpsIdentifier::parse(AS).unwrap()),
        }),
        pre_authorized_code: None,
        grant_source: OfferGrantSource::Explicit,
    }
}

fn public_jwk() -> Es256PublicJwk {
    Es256PublicJwk::parse(
        &Base64UrlUnpadded::encode_string(&[1u8; 32]),
        &Base64UrlUnpadded::encode_string(&[2u8; 32]),
    )
    .unwrap()
}

fn credential_key() -> CredentialKeyBinding {
    CredentialKeyBinding::new(
        KeyRef("credential-holder-key-reference".to_owned()),
        Es256PublicJwk::parse(
            &Base64UrlUnpadded::encode_string(&[3u8; 32]),
            &Base64UrlUnpadded::encode_string(&[4u8; 32]),
        )
        .unwrap(),
    )
    .unwrap()
}

fn client_attestation_key(credential_issuer: &str) -> ClientAttestationKeyBinding {
    ClientAttestationKeyBinding::new(
        AS,
        credential_issuer,
        KeyRef("client-instance-key-reference".to_owned()),
        Es256PublicJwk::parse(
            &Base64UrlUnpadded::encode_string(&[5u8; 32]),
            &Base64UrlUnpadded::encode_string(&[6u8; 32]),
        )
        .unwrap(),
        WalletAttestationUsagePolicy::SingleIssuance,
    )
    .unwrap()
}

fn auth_environment<'a>(
    random: &'a dyn Random,
    now_epoch_seconds: i64,
) -> AuthorizationEnvironment<'a> {
    AuthorizationEnvironment {
        random,
        digest: &AwsLc,
        verifier: &TEST_VERIFIER,
        now_epoch_seconds,
    }
}

fn credential_environment<'a>(
    random: &'a dyn Random,
    now_epoch_seconds: i64,
) -> CredentialEnvironment<'a> {
    credential_environment_with_verifier(random, now_epoch_seconds, &TEST_VERIFIER)
}

fn credential_environment_with_verifier<'a>(
    random: &'a dyn Random,
    now_epoch_seconds: i64,
    verifier: &'a dyn Verifier,
) -> CredentialEnvironment<'a> {
    CredentialEnvironment {
        random,
        digest: &AwsLc,
        verifier,
        now_epoch_seconds,
    }
}

fn wallet_attestation_jwt(request: &WalletAttestationRequest, marker: u8) -> String {
    let header = serde_json::json!({
        "alg": "ES256",
        "kid": format!("attester-{marker}"),
        "typ": "oauth-client-attestation+jwt",
        "x5c": [Base64::encode_string(KEY_ATTESTATION_SIGNER_CERTIFICATE)],
    });
    let claims = serde_json::json!({
        "sub": request.client_id(),
        "wallet_name": "de.example.competitive-wallet",
        "wallet_version": "1.0.0",
        "wallet_solution_certification_information": {
            "certification": "DE-test-certificate-1"
        },
        "iat": NOW - 4,
        "exp": NOW + 3_596,
        "client_status": {
            "status": {
                "status_list": {
                    "idx": u64::from(marker),
                    "uri": "https://wallet-provider.example/status/wia"
                }
            },
            "exp": NOW + 32 * 24 * 60 * 60
        },
        "cnf": {"jwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": request.public_jwk().x(),
            "y": request.public_jwk().y(),
        }},
    });
    format!(
        "{}.{}.{}",
        Base64UrlUnpadded::encode_string(&serde_json::to_vec(&header).unwrap()),
        Base64UrlUnpadded::encode_string(&serde_json::to_vec(&claims).unwrap()),
        Base64UrlUnpadded::encode_string(&[marker; 64]),
    )
}

fn drive_client_authentication(
    flow: &mut AuthorizationFlow,
    mut effect: AuthorizationEffect,
    environment: &AuthorizationEnvironment<'_>,
    marker: u8,
) -> Vec<AuthorizationEffect> {
    loop {
        match effect {
            AuthorizationEffect::AcquireWalletAttestation(request) => {
                let jwt = wallet_attestation_jwt(&request, marker);
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
                effect = flow
                    .step(
                        AuthorizationInput::WalletAttestationUsageReservation(
                            WalletAttestationUsageReservationResult::committed(&request),
                        ),
                        environment,
                    )
                    .unwrap()
                    .into_iter()
                    .next()
                    .unwrap();
            }
            AuthorizationEffect::SignClientAttestationPop(request) => {
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

fn auth_response(
    request_id: CorrelationId,
    endpoint: &str,
    status: u16,
    dpop_nonce: Vec<String>,
    body: Vec<u8>,
) -> AuthorizationEndpointResponse {
    AuthorizationEndpointResponse::new(
        request_id,
        endpoint,
        "POST",
        status,
        vec!["application/json".to_owned()],
        vec!["no-cache, no-store".to_owned()],
        if endpoint == TOKEN {
            vec!["no-cache".to_owned()]
        } else {
            vec![]
        },
        vec!["identity".to_owned()],
        dpop_nonce,
        vec![],
        body,
    )
}

fn form_field<'a>(body: &'a str, field: &str) -> &'a str {
    body.split('&')
        .find_map(|pair| pair.strip_prefix(&format!("{field}=")))
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

fn authorized_grant(
    random: &SequenceRandom,
    plan: &GermanPidIssuancePlan,
    identifiers: &[&str],
) -> oid4vci::authorization::AccessTokenGrant {
    let config = AuthorizationFlowConfig::from_plan_and_offer(
        plan,
        &offer(plan),
        CLIENT_ID,
        REDIRECT,
        DpopKeyBinding::new(KeyRef("hardware-key-reference".to_owned()), public_jwk()).unwrap(),
        client_attestation_key(plan.credential_issuer.as_str()),
    )
    .unwrap();
    let (mut flow, effect) =
        AuthorizationFlow::begin(config, &auth_environment(random, NOW - 4)).unwrap();
    let par_environment = auth_environment(random, NOW - 4);
    let effects = drive_client_authentication(&mut flow, effect, &par_environment, 1);
    let par = match effects.into_iter().next().unwrap() {
        AuthorizationEffect::SendPar(request) => request,
        other => panic!("expected PAR, got {other:?}"),
    };
    let state = form_field(core::str::from_utf8(par.body()).unwrap(), "state").to_owned();
    let effects = flow
        .step(
            AuthorizationInput::ParResponse(auth_response(
                par.request_id(),
                PAR,
                201,
                vec![],
                br#"{"request_uri":"urn:ietf:params:oauth:request_uri:pid","expires_in":60}"#
                    .to_vec(),
            )),
            &auth_environment(random, NOW - 3),
        )
        .unwrap();
    assert!(matches!(
        effects[0],
        AuthorizationEffect::OpenAuthorization(_)
    ));
    let callback = format!("code=AUTH-CODE&state={state}&iss={}", percent_encode(AS));
    let effects = flow
        .step(
            AuthorizationInput::AuthorizationRedirect(AuthorizationRedirect::new(
                REDIRECT,
                callback.into_bytes(),
            )),
            &auth_environment(random, NOW - 2),
        )
        .unwrap();
    let token_environment = auth_environment(random, NOW - 2);
    let effects = drive_client_authentication(
        &mut flow,
        effects.into_iter().next().unwrap(),
        &token_environment,
        2,
    );
    let signing = match effects.into_iter().next().unwrap() {
        AuthorizationEffect::SignDpop(request) => request,
        other => panic!("expected token DPoP, got {other:?}"),
    };
    let effects = flow
        .step(
            AuthorizationInput::DpopSignature(DpopSignature::new(
                signing.request_id(),
                signing.signing_input().to_vec(),
                vec![7; 64],
            )),
            &auth_environment(random, NOW - 1),
        )
        .unwrap();
    let token = match effects.into_iter().next().unwrap() {
        AuthorizationEffect::SendToken(request) => request,
        other => panic!("expected token request, got {other:?}"),
    };
    let authorization_details = if identifiers.is_empty() {
        String::new()
    } else {
        format!(
            ",\"authorization_details\":[{{\"type\":\"openid_credential\",\"credential_configuration_id\":{},\"credential_identifiers\":{}}}]",
            serde_json::to_string(&plan.configuration_id).unwrap(),
            serde_json::to_string(identifiers).unwrap(),
        )
    };
    let body = format!(
        "{{\"access_token\":\"ACCESS-TOKEN\",\"token_type\":\"DPoP\",\"expires_in\":300{authorization_details}}}"
    );
    flow.step(
        AuthorizationInput::TokenResponse(auth_response(
            token.request_id(),
            TOKEN,
            200,
            vec![],
            body.into_bytes(),
        )),
        &auth_environment(random, NOW),
    )
    .unwrap();
    flow.into_token().unwrap()
}

fn endpoint_response(
    request_id: CorrelationId,
    endpoint: &str,
    status: u16,
    dpop_nonce_headers: Vec<String>,
    www_authenticate_headers: Vec<String>,
    body: Vec<u8>,
) -> EndpointResponse {
    EndpointResponse::new(
        request_id,
        endpoint,
        "POST",
        status,
        vec!["application/json; charset=utf-8".to_owned()],
        vec!["private, no-store".to_owned()],
        vec!["no-cache".to_owned()],
        vec!["identity".to_owned()],
        dpop_nonce_headers,
        www_authenticate_headers,
        body,
    )
}

fn decode_jwt_input(input: &[u8]) -> (Value, Value) {
    let input = core::str::from_utf8(input).unwrap();
    let mut parts = input.split('.');
    let header = Base64UrlUnpadded::decode_vec(parts.next().unwrap()).unwrap();
    let payload = Base64UrlUnpadded::decode_vec(parts.next().unwrap()).unwrap();
    assert!(parts.next().is_none());
    (
        serde_json::from_slice(&header).unwrap(),
        serde_json::from_slice(&payload).unwrap(),
    )
}

fn key_attestation_jwt(request: &KeyAttestationRequest, now: i64) -> String {
    let header = serde_json::json!({
        "alg": "ES256",
        "typ": "key-attestation+jwt",
        "x5c": [Base64::encode_string(KEY_ATTESTATION_SIGNER_CERTIFICATE)],
    });
    let payload = serde_json::json!({
        "iat": now - 1,
        "exp": now + 300,
        "certification": "https://wallet-provider.example/certification/iso-18045-high",
        "key_storage_status": {
            "status": {
                "status_list": {
                    "idx": 7,
                    "uri": "https://wallet-provider.example/status/key-storage",
                }
            },
            "exp": now + MIN_KEY_STORAGE_STATUS_REMAINING_SECONDS as i64,
        },
        "key_storage": ["iso_18045_high"],
        "user_authentication": ["iso_18045_high"],
        "attested_keys": [{
            "kty": "EC",
            "crv": "P-256",
            "x": request.public_jwk().x(),
            "y": request.public_jwk().y(),
        }],
    });
    format!(
        "{}.{}.{}",
        Base64UrlUnpadded::encode_string(&serde_json::to_vec(&header).unwrap()),
        Base64UrlUnpadded::encode_string(&serde_json::to_vec(&payload).unwrap()),
        Base64UrlUnpadded::encode_string(&[9; 64]),
    )
}

fn rewrite_key_attestation(
    compact: &str,
    mutate_header: impl FnOnce(&mut serde_json::Map<String, Value>),
    mutate_payload: impl FnOnce(&mut serde_json::Map<String, Value>),
) -> String {
    let parts: Vec<&str> = compact.split('.').collect();
    assert_eq!(parts.len(), 3);
    let mut header: Value = serde_json::from_slice(
        &Base64UrlUnpadded::decode_vec(parts[0]).expect("valid test header"),
    )
    .unwrap();
    let mut payload: Value = serde_json::from_slice(
        &Base64UrlUnpadded::decode_vec(parts[1]).expect("valid test payload"),
    )
    .unwrap();
    mutate_header(header.as_object_mut().unwrap());
    mutate_payload(payload.as_object_mut().unwrap());
    format!(
        "{}.{}.{}",
        Base64UrlUnpadded::encode_string(&serde_json::to_vec(&header).unwrap()),
        Base64UrlUnpadded::encode_string(&serde_json::to_vec(&payload).unwrap()),
        parts[2],
    )
}

fn key_attestation(request: &KeyAttestationRequest, now: i64, jwt: Option<&str>) -> KeyAttestation {
    let generated;
    let jwt = match jwt {
        Some(value) => value,
        None => {
            generated = key_attestation_jwt(request, now);
            &generated
        }
    };
    KeyAttestation::new(request.request_id(), jwt)
}

struct AtKeyAttestation {
    flow: CredentialFlow,
    request: KeyAttestationRequest,
}

struct AtCredentialKeyReservation {
    flow: CredentialFlow,
    request: CredentialKeyReservationRequest,
}

struct AtKeyAttestationReservation {
    flow: CredentialFlow,
    request: KeyAttestationReservationRequest,
}

struct AtCNonceReservation {
    flow: CredentialFlow,
    request: CNonceReservationRequest,
}

fn credential_key_reservation_result(
    request: &CredentialKeyReservationRequest,
    outcome: CredentialKeyReservationOutcome,
) -> CredentialKeyReservationResult {
    CredentialKeyReservationResult::new(
        request.request_id(),
        request.credential_issuer(),
        *request.public_key_thumbprint(),
        request.reserved_at_epoch_seconds(),
        outcome,
    )
}

fn key_attestation_reservation_result(
    request: &KeyAttestationReservationRequest,
    outcome: KeyAttestationReservationOutcome,
) -> KeyAttestationReservationResult {
    KeyAttestationReservationResult::new(
        request.request_id(),
        request.credential_issuer(),
        *request.public_key_thumbprint(),
        *request.key_attestation_hash(),
        request.key_attestation_expires_at_epoch_seconds(),
        request.reserved_at_epoch_seconds(),
        outcome,
    )
}

fn flow_at_c_nonce_reservation(
    random: &SequenceRandom,
    plan: &GermanPidIssuancePlan,
    selection: CredentialSelection,
    identifiers: &[&str],
    dpop_nonce: Vec<String>,
    c_nonce: &str,
) -> Result<AtCNonceReservation, CredentialError> {
    let grant = authorized_grant(random, plan, identifiers);
    let config =
        CredentialFlowConfig::from_authorization(grant, plan, selection, credential_key())?;
    let (mut flow, effect) = CredentialFlow::begin(config, &credential_environment(random, NOW))?;
    let nonce = match effect {
        CredentialEffect::SendNonce(request) => request,
        other => panic!("expected nonce request, got {other:?}"),
    };
    assert_eq!(nonce.endpoint(), NONCE);
    assert_eq!(nonce.method(), "POST");
    assert!(nonce.body().is_empty());
    assert_eq!(nonce.authorization(), None);
    assert_eq!(nonce.dpop_proof(), None);
    let effects = flow.step(
        CredentialInput::NonceResponse(endpoint_response(
            nonce.request_id(),
            NONCE,
            200,
            dpop_nonce,
            vec![],
            serde_json::to_vec(&serde_json::json!({"c_nonce": c_nonce})).unwrap(),
        )),
        &credential_environment(random, NOW + 1),
    )?;
    let reservation = match effects.into_iter().next().unwrap() {
        CredentialEffect::ReserveCNonce(request) => request,
        other => panic!("expected c_nonce reservation, got {other:?}"),
    };
    assert_eq!(
        reservation.credential_issuer(),
        plan.credential_issuer.as_str()
    );
    assert_eq!(
        reservation.c_nonce_hash(),
        &AwsLc.sha256(c_nonce.as_bytes())
    );
    assert_eq!(reservation.reserved_at_epoch_seconds(), NOW + 1);
    assert!(reservation.requires_atomic_compare_and_insert());
    assert!(reservation.requires_durable_commit_before_acknowledgement());
    assert!(reservation.requires_bounded_per_issuer_ledger());
    assert!(reservation.requires_issuer_authoritative_retention_policy());
    Ok(AtCNonceReservation {
        flow,
        request: reservation,
    })
}

fn flow_at_credential_key_reservation(
    random: &SequenceRandom,
    plan: &GermanPidIssuancePlan,
    selection: CredentialSelection,
    identifiers: &[&str],
    dpop_nonce: Vec<String>,
) -> Result<AtCredentialKeyReservation, CredentialError> {
    let AtCNonceReservation {
        mut flow,
        request: reservation,
    } = flow_at_c_nonce_reservation(
        random,
        plan,
        selection,
        identifiers,
        dpop_nonce,
        "CREDENTIAL-NONCE",
    )?;
    let effects = flow.step(
        CredentialInput::CNonceReservation(CNonceReservationResult::new(
            reservation.request_id(),
            reservation.credential_issuer(),
            *reservation.c_nonce_hash(),
            reservation.reserved_at_epoch_seconds(),
            CNonceReservationOutcome::Reserved,
        )),
        &credential_environment(random, NOW + 1),
    )?;
    let key_reservation = match effects.into_iter().next().unwrap() {
        CredentialEffect::ReserveCredentialKey(request) => request,
        other => panic!("expected credential-key reservation, got {other:?}"),
    };
    assert!(key_reservation.requires_atomic_compare_and_insert());
    assert!(key_reservation.requires_durable_commit_before_acknowledgement());
    assert!(key_reservation.requires_idempotent_request_replay());
    assert!(key_reservation.requires_verified_key_destruction_before_pruning());
    assert!(key_reservation.uniqueness_scope_is_global_across_issuers());
    Ok(AtCredentialKeyReservation {
        flow,
        request: key_reservation,
    })
}

fn flow_at_key_attestation(
    random: &SequenceRandom,
    plan: &GermanPidIssuancePlan,
    selection: CredentialSelection,
    identifiers: &[&str],
    dpop_nonce: Vec<String>,
) -> Result<AtKeyAttestation, CredentialError> {
    let AtCredentialKeyReservation {
        mut flow,
        request: key_reservation,
    } = flow_at_credential_key_reservation(random, plan, selection, identifiers, dpop_nonce)?;
    let effects = flow.step(
        CredentialInput::CredentialKeyReservation(credential_key_reservation_result(
            &key_reservation,
            CredentialKeyReservationOutcome::Reserved,
        )),
        &credential_environment(random, NOW + 1),
    )?;
    let request = match effects.into_iter().next().unwrap() {
        CredentialEffect::AcquireKeyAttestation(request) => request,
        other => panic!("expected key attestation, got {other:?}"),
    };
    assert_eq!(request.algorithm(), Alg::Es256);
    assert_eq!(request.jwt_type(), "key-attestation+jwt");
    assert_eq!(request.key_storage_requirement(), "iso_18045_high");
    assert_eq!(request.user_authentication_requirement(), "iso_18045_high");
    assert_eq!(
        request.minimum_key_storage_status_period(),
        plan.preferred_key_storage_status_period
            .unwrap_or_default()
            .max(MIN_KEY_STORAGE_STATUS_REMAINING_SECONDS)
    );
    assert!(request.certification_required());
    assert!(request.key_storage_status_required());
    assert!(request.require_x5c_without_trust_anchor());
    assert!(request.must_not_retry_after_dispatch());
    assert!(request.unknown_completion_requires_new_credential_key());
    let attestation_diagnostics = format!("{request:?}");
    assert!(!attestation_diagnostics.contains(ISSUER));
    assert!(!attestation_diagnostics.contains(CREDENTIAL));
    assert!(!attestation_diagnostics.contains("credential-holder-key-reference"));
    assert!(!attestation_diagnostics.contains("CREDENTIAL-NONCE"));
    Ok(AtKeyAttestation { flow, request })
}

fn flow_at_key_attestation_reservation(
    random: &SequenceRandom,
    plan: &GermanPidIssuancePlan,
    selection: CredentialSelection,
    identifiers: &[&str],
    dpop_nonce: Vec<String>,
) -> AtKeyAttestationReservation {
    let AtKeyAttestation { mut flow, request } =
        flow_at_key_attestation(random, plan, selection, identifiers, dpop_nonce).unwrap();
    let effects = flow
        .step(
            CredentialInput::KeyAttestation(key_attestation(&request, NOW + 2, None)),
            &credential_environment(random, NOW + 2),
        )
        .unwrap();
    let reservation = match effects.into_iter().next().unwrap() {
        CredentialEffect::ReserveKeyAttestation(request) => request,
        other => panic!("expected key-attestation reservation, got {other:?}"),
    };
    assert!(reservation.requires_atomic_key_binding_and_compare_insert());
    assert!(reservation.requires_durable_commit_before_acknowledgement());
    assert!(reservation.requires_idempotent_request_replay());
    assert!(reservation.uniqueness_scope_is_global_across_issuers());
    AtKeyAttestationReservation {
        flow,
        request: reservation,
    }
}

struct AtCredentialProof {
    flow: CredentialFlow,
    request_id: CorrelationId,
    signing_input: Vec<u8>,
}

fn flow_at_credential_proof(
    random: &SequenceRandom,
    plan: &GermanPidIssuancePlan,
    selection: CredentialSelection,
    identifiers: &[&str],
    dpop_nonce: Vec<String>,
) -> AtCredentialProof {
    let AtKeyAttestationReservation {
        mut flow,
        request: reservation,
    } = flow_at_key_attestation_reservation(random, plan, selection, identifiers, dpop_nonce);
    let effects = flow
        .step(
            CredentialInput::KeyAttestationReservation(key_attestation_reservation_result(
                &reservation,
                KeyAttestationReservationOutcome::Reserved,
            )),
            &credential_environment(random, NOW + 2),
        )
        .unwrap();
    let signing = match effects.into_iter().next().unwrap() {
        CredentialEffect::SignCredentialProof(request) => request,
        other => panic!("expected credential-proof signing, got {other:?}"),
    };
    AtCredentialProof {
        flow,
        request_id: signing.request_id(),
        signing_input: signing.signing_input().to_vec(),
    }
}

struct AtDpop {
    flow: CredentialFlow,
    request_id: CorrelationId,
    signing_input: Vec<u8>,
}

fn flow_at_dpop(
    random: &SequenceRandom,
    plan: &GermanPidIssuancePlan,
    selection: CredentialSelection,
    identifiers: &[&str],
    dpop_nonce: Vec<String>,
) -> AtDpop {
    let AtCredentialProof {
        mut flow,
        request_id,
        signing_input,
    } = flow_at_credential_proof(random, plan, selection, identifiers, dpop_nonce);
    let effects = flow
        .step(
            CredentialInput::CredentialProofSignature(SignatureResult::new(
                request_id,
                signing_input,
                vec![8; 64],
            )),
            &credential_environment(random, NOW + 3),
        )
        .unwrap();
    let signing = match effects.into_iter().next().unwrap() {
        CredentialEffect::SignDpop(request) => request,
        other => panic!("expected DPoP signing, got {other:?}"),
    };
    AtDpop {
        flow,
        request_id: signing.request_id(),
        signing_input: signing.signing_input().to_vec(),
    }
}

struct AtCredentialRequest {
    flow: CredentialFlow,
    request_id: CorrelationId,
    body: Vec<u8>,
    dpop_proof: String,
}

fn flow_at_credential_request(
    random: &SequenceRandom,
    plan: &GermanPidIssuancePlan,
    selection: CredentialSelection,
    identifiers: &[&str],
    dpop_nonce: Vec<String>,
) -> AtCredentialRequest {
    let AtDpop {
        mut flow,
        request_id,
        signing_input,
    } = flow_at_dpop(random, plan, selection, identifiers, dpop_nonce);
    let effects = flow
        .step(
            CredentialInput::DpopSignature(SignatureResult::new(
                request_id,
                signing_input,
                vec![7; 64],
            )),
            &credential_environment(random, NOW + 4),
        )
        .unwrap();
    let request = match effects.into_iter().next().unwrap() {
        CredentialEffect::SendCredential(request) => request,
        other => panic!("expected credential request, got {other:?}"),
    };
    assert_eq!(request.endpoint(), CREDENTIAL);
    assert_eq!(request.method(), "POST");
    assert_eq!(request.content_type(), "application/json");
    assert_eq!(request.accept_encoding(), "identity");
    assert_eq!(request.authorization(), "DPoP ACCESS-TOKEN");
    assert!(request.must_not_retry_after_dispatch());
    assert!(request.unknown_completion_requires_new_credential_key());
    AtCredentialRequest {
        flow,
        request_id: request.request_id(),
        body: request.body().to_vec(),
        dpop_proof: request.dpop_proof().to_owned(),
    }
}

fn sd_jwt(issuer: &str, vct: &str, typ: &str, alg: &str) -> String {
    let header = serde_json::json!({"alg": alg, "typ": typ});
    let payload = serde_json::json!({"iss": issuer, "vct": vct});
    format!(
        "{}.{}.{}~",
        Base64UrlUnpadded::encode_string(&serde_json::to_vec(&header).unwrap()),
        Base64UrlUnpadded::encode_string(&serde_json::to_vec(&payload).unwrap()),
        Base64UrlUnpadded::encode_string(&[5; 64]),
    )
}

fn sd_jwt_without_issuer(vct: &str, typ: &str, alg: &str) -> String {
    let header = serde_json::json!({"alg": alg, "typ": typ, "x5c": ["transport-only"]});
    let payload = serde_json::json!({"vct": vct});
    format!(
        "{}.{}.{}~",
        Base64UrlUnpadded::encode_string(&serde_json::to_vec(&header).unwrap()),
        Base64UrlUnpadded::encode_string(&serde_json::to_vec(&payload).unwrap()),
        Base64UrlUnpadded::encode_string(&[5; 64]),
    )
}

fn immediate_response(credential: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "credentials": [{"credential": credential}],
    }))
    .unwrap()
}

#[test]
fn happy_path_binds_nonce_key_attestation_proof_dpop_and_raw_sd_jwt() {
    let random = SequenceRandom::new();
    let selected = plan(GermanPidFormat::DcSdJwt);
    let AtCredentialProof {
        flow: _,
        request_id: _,
        signing_input,
    } = flow_at_credential_proof(
        &random,
        &selected,
        CredentialSelection::ConfigurationId,
        &[],
        vec!["resource-seed".to_owned()],
    );
    let (proof_header, proof_payload) = decode_jwt_input(&signing_input);
    assert_eq!(proof_header.as_object().unwrap().len(), 3);
    assert_eq!(proof_header["alg"], "ES256");
    assert_eq!(proof_header["typ"], "openid4vci-proof+jwt");
    assert!(proof_header.get("jwk").is_none());
    assert!(proof_header.get("kid").is_none());
    assert!(proof_header["key_attestation"]
        .as_str()
        .unwrap()
        .contains('.'));
    let encoded_header = core::str::from_utf8(&signing_input)
        .unwrap()
        .split('.')
        .next()
        .unwrap();
    let exact_header = format!(
        "{{\"alg\":\"ES256\",\"key_attestation\":{},\"typ\":\"openid4vci-proof+jwt\"}}",
        serde_json::to_string(proof_header["key_attestation"].as_str().unwrap()).unwrap()
    );
    assert_eq!(
        encoded_header,
        Base64UrlUnpadded::encode_string(exact_header.as_bytes())
    );
    assert_eq!(proof_payload["aud"], ISSUER);
    assert_eq!(proof_payload["nonce"], "CREDENTIAL-NONCE");

    let random = SequenceRandom::new();
    let AtDpop {
        flow: _,
        request_id: _,
        signing_input,
    } = flow_at_dpop(
        &random,
        &selected,
        CredentialSelection::ConfigurationId,
        &[],
        vec!["resource-seed".to_owned()],
    );
    let (dpop_header, dpop_payload) = decode_jwt_input(&signing_input);
    assert_eq!(dpop_header["typ"], "dpop+jwt");
    assert_eq!(
        dpop_header["jwk"]["x"],
        Base64UrlUnpadded::encode_string(&[1u8; 32])
    );
    assert_eq!(dpop_payload["htm"], "POST");
    assert_eq!(dpop_payload["htu"], "https://issuer.example/credential");
    assert_eq!(dpop_payload["nonce"], "resource-seed");
    assert_eq!(
        dpop_payload["ath"],
        Base64UrlUnpadded::encode_string(&AwsLc.sha256(b"ACCESS-TOKEN"))
    );

    let random = SequenceRandom::new();
    let AtCredentialRequest {
        mut flow,
        request_id,
        body,
        dpop_proof,
    } = flow_at_credential_request(
        &random,
        &selected,
        CredentialSelection::ConfigurationId,
        &[],
        vec!["resource-seed".to_owned()],
    );
    let request: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(request["credential_configuration_id"], "pid-sd-jwt");
    assert!(request.get("credential_identifier").is_none());
    assert_eq!(request["proofs"]["jwt"].as_array().unwrap().len(), 1);
    assert_eq!(dpop_proof.split('.').count(), 3);

    let raw = sd_jwt(ISSUER, "urn:eudi:pid:1", "dc+sd-jwt", "ES256");
    let effects = flow
        .step(
            CredentialInput::CredentialResponse(endpoint_response(
                request_id,
                CREDENTIAL,
                200,
                vec!["next-resource-nonce".to_owned()],
                vec![],
                immediate_response(&raw),
            )),
            &credential_environment(&random, NOW + 5),
        )
        .unwrap();
    assert!(effects.is_empty());
    assert_eq!(flow.status(), FlowStatus::Complete);
    let issued = flow.into_unverified_credential().unwrap();
    assert_eq!(issued.format(), GermanPidFormat::DcSdJwt);
    assert_eq!(issued.raw(), raw.as_bytes());
    assert_eq!(issued.c_nonce_hash(), &AwsLc.sha256(b"CREDENTIAL-NONCE"));
    assert_eq!(issued.notification_id(), None);
    assert!(issued.requires_verified_ingestion());
    assert!(format!("{issued:?}").contains("verified_ingestion"));
    assert!(!format!("{issued:?}").contains(&raw));
}

#[test]
fn authorized_credential_identifier_is_exclusive_and_exact() {
    let selected = plan(GermanPidFormat::DcSdJwt);
    let random = SequenceRandom::new();
    let grant = authorized_grant(&random, &selected, &["dataset-a", "dataset-b"]);
    assert!(matches!(
        CredentialFlowConfig::from_authorization(
            grant,
            &selected,
            CredentialSelection::ConfigurationId,
            credential_key(),
        ),
        Err(CredentialError::InvalidSelection)
    ));

    let random = SequenceRandom::new();
    let grant = authorized_grant(&random, &selected, &["dataset-a", "dataset-b"]);
    assert!(matches!(
        CredentialFlowConfig::from_authorization(
            grant,
            &selected,
            CredentialSelection::CredentialIdentifier("not-authorized".to_owned()),
            credential_key(),
        ),
        Err(CredentialError::InvalidSelection)
    ));

    let random = SequenceRandom::new();
    let AtCredentialRequest { body, .. } = flow_at_credential_request(
        &random,
        &selected,
        CredentialSelection::CredentialIdentifier("dataset-b".to_owned()),
        &["dataset-a", "dataset-b"],
        vec![],
    );
    let request: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(request["credential_identifier"], "dataset-b");
    assert!(request.get("credential_configuration_id").is_none());
    assert_eq!(request.as_object().unwrap().len(), 2);
}

#[test]
fn credential_holder_key_must_differ_from_dpop_and_client_instance_keys() {
    let selected = plan(GermanPidFormat::DcSdJwt);

    let random = SequenceRandom::new();
    let grant = authorized_grant(&random, &selected, &[]);
    let same_handle = CredentialKeyBinding::new(
        KeyRef("hardware-key-reference".to_owned()),
        Es256PublicJwk::parse(
            &Base64UrlUnpadded::encode_string(&[3u8; 32]),
            &Base64UrlUnpadded::encode_string(&[4u8; 32]),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(matches!(
        CredentialFlowConfig::from_authorization(
            grant,
            &selected,
            CredentialSelection::ConfigurationId,
            same_handle,
        ),
        Err(CredentialError::KeySeparationViolation)
    ));

    let random = SequenceRandom::new();
    let grant = authorized_grant(&random, &selected, &[]);
    let same_public_key =
        CredentialKeyBinding::new(KeyRef("different-hardware-handle".to_owned()), public_jwk())
            .unwrap();
    assert!(matches!(
        CredentialFlowConfig::from_authorization(
            grant,
            &selected,
            CredentialSelection::ConfigurationId,
            same_public_key,
        ),
        Err(CredentialError::KeySeparationViolation)
    ));

    let random = SequenceRandom::new();
    let grant = authorized_grant(&random, &selected, &[]);
    let same_client_handle = CredentialKeyBinding::new(
        KeyRef("client-instance-key-reference".to_owned()),
        Es256PublicJwk::parse(
            &Base64UrlUnpadded::encode_string(&[3u8; 32]),
            &Base64UrlUnpadded::encode_string(&[4u8; 32]),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(matches!(
        CredentialFlowConfig::from_authorization(
            grant,
            &selected,
            CredentialSelection::ConfigurationId,
            same_client_handle,
        ),
        Err(CredentialError::KeySeparationViolation)
    ));

    let random = SequenceRandom::new();
    let grant = authorized_grant(&random, &selected, &[]);
    let same_client_public_key = CredentialKeyBinding::new(
        KeyRef("client-key-alias".to_owned()),
        Es256PublicJwk::parse(
            &Base64UrlUnpadded::encode_string(&[5u8; 32]),
            &Base64UrlUnpadded::encode_string(&[6u8; 32]),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(matches!(
        CredentialFlowConfig::from_authorization(
            grant,
            &selected,
            CredentialSelection::ConfigurationId,
            same_client_public_key,
        ),
        Err(CredentialError::KeySeparationViolation)
    ));
}

#[test]
fn nonce_endpoint_is_strict_unprotected_uncacheable_and_replay_checked() {
    let selected = plan(GermanPidFormat::DcSdJwt);
    let random = SequenceRandom::new();
    let grant = authorized_grant(&random, &selected, &[]);
    let config = CredentialFlowConfig::from_authorization(
        grant,
        &selected,
        CredentialSelection::ConfigurationId,
        credential_key(),
    )
    .unwrap();
    let (mut flow, effect) =
        CredentialFlow::begin(config, &credential_environment(&random, NOW)).unwrap();
    let nonce = match effect {
        CredentialEffect::SendNonce(request) => request,
        _ => unreachable!(),
    };
    let effects = flow
        .step(
            CredentialInput::NonceResponse(endpoint_response(
                nonce.request_id(),
                NONCE,
                200,
                vec![],
                vec![],
                br#"{"c_nonce":"CREDENTIAL-NONCE"}"#.to_vec(),
            )),
            &credential_environment(&random, NOW + 1),
        )
        .unwrap();
    let reservation = match effects.into_iter().next().unwrap() {
        CredentialEffect::ReserveCNonce(request) => request,
        other => panic!("expected c_nonce reservation, got {other:?}"),
    };
    assert_eq!(
        flow.step(
            CredentialInput::CNonceReservation(CNonceReservationResult::new(
                reservation.request_id(),
                reservation.credential_issuer(),
                *reservation.c_nonce_hash(),
                reservation.reserved_at_epoch_seconds(),
                CNonceReservationOutcome::AlreadyReserved,
            )),
            &credential_environment(&random, NOW + 1),
        )
        .unwrap_err(),
        CredentialError::CNonceReplayed
    );

    for (status, content_types, cache, dpop, body, expected) in [
        (
            401,
            vec!["application/json".to_owned()],
            vec!["no-store".to_owned()],
            vec![],
            br#"{"c_nonce":"N"}"#.to_vec(),
            CredentialError::InvalidStatus,
        ),
        (
            200,
            vec!["text/json".to_owned()],
            vec!["no-store".to_owned()],
            vec![],
            br#"{"c_nonce":"N"}"#.to_vec(),
            CredentialError::InvalidMediaType,
        ),
        (
            200,
            vec!["application/json".to_owned()],
            vec!["private".to_owned()],
            vec![],
            br#"{"c_nonce":"N"}"#.to_vec(),
            CredentialError::CachePolicyMissing,
        ),
        (
            200,
            vec!["application/json".to_owned()],
            vec!["no-store".to_owned()],
            vec!["one".to_owned(), "two".to_owned()],
            br#"{"c_nonce":"N"}"#.to_vec(),
            CredentialError::DpopNonceInvalid,
        ),
        (
            200,
            vec!["application/json".to_owned()],
            vec!["no-store".to_owned()],
            vec![],
            br#"{"c_nonce":"A","c_nonce":"B"}"#.to_vec(),
            CredentialError::InvalidNonceResponse,
        ),
        (
            200,
            vec!["application/json".to_owned()],
            vec!["no-store".to_owned()],
            vec![],
            vec![b' '; MAX_NONCE_RESPONSE_BYTES + 1],
            CredentialError::InvalidNonceResponse,
        ),
    ] {
        let random = SequenceRandom::new();
        let grant = authorized_grant(&random, &selected, &[]);
        let config = CredentialFlowConfig::from_authorization(
            grant,
            &selected,
            CredentialSelection::ConfigurationId,
            credential_key(),
        )
        .unwrap();
        let (mut flow, effect) =
            CredentialFlow::begin(config, &credential_environment(&random, NOW)).unwrap();
        let request = match effect {
            CredentialEffect::SendNonce(request) => request,
            _ => unreachable!(),
        };
        let response = EndpointResponse::new(
            request.request_id(),
            NONCE,
            "POST",
            status,
            content_types,
            cache,
            vec![],
            vec![],
            dpop,
            vec![],
            body,
        );
        assert_eq!(
            flow.step(
                CredentialInput::NonceResponse(response),
                &credential_environment(&random, NOW + 1),
            )
            .unwrap_err(),
            expected
        );
    }
}

#[test]
fn nonce_reservation_is_bound_fail_closed_and_models_atomic_concurrency() {
    let selected = plan(GermanPidFormat::DcSdJwt);

    let random = SequenceRandom::new();
    let AtCNonceReservation { mut flow, request } = flow_at_c_nonce_reservation(
        &random,
        &selected,
        CredentialSelection::ConfigurationId,
        &[],
        vec![],
        "RACING-C-NONCE",
    )
    .unwrap();
    assert_eq!(flow.status(), FlowStatus::AwaitingCNonceReservation);
    assert_eq!(
        flow.step(
            CredentialInput::CNonceReservation(CNonceReservationResult::new(
                CorrelationId::from_bytes([99; 32]),
                request.credential_issuer(),
                *request.c_nonce_hash(),
                request.reserved_at_epoch_seconds(),
                CNonceReservationOutcome::Reserved,
            )),
            &credential_environment(&random, NOW + 1),
        )
        .unwrap_err(),
        CredentialError::CNonceReservationMismatch
    );

    let random = SequenceRandom::new();
    let AtCNonceReservation { mut flow, request } = flow_at_c_nonce_reservation(
        &random,
        &selected,
        CredentialSelection::ConfigurationId,
        &[],
        vec![],
        "RACING-C-NONCE",
    )
    .unwrap();
    assert_eq!(
        flow.step(
            CredentialInput::CNonceReservation(CNonceReservationResult::new(
                request.request_id(),
                request.credential_issuer(),
                *request.c_nonce_hash(),
                request.reserved_at_epoch_seconds(),
                CNonceReservationOutcome::StorageFailure,
            )),
            &credential_environment(&random, NOW + 1),
        )
        .unwrap_err(),
        CredentialError::CNonceReservationFailed
    );

    // Two flows can observe the same issuer nonce, but the durable store's atomic operation can
    // acknowledge only one. The loser never reaches attestation or proof signing.
    let first_random = SequenceRandom::new();
    let second_random = SequenceRandom::new();
    let AtCNonceReservation {
        flow: mut first,
        request: first_request,
    } = flow_at_c_nonce_reservation(
        &first_random,
        &selected,
        CredentialSelection::ConfigurationId,
        &[],
        vec![],
        "RACING-C-NONCE",
    )
    .unwrap();
    let AtCNonceReservation {
        flow: mut second,
        request: second_request,
    } = flow_at_c_nonce_reservation(
        &second_random,
        &selected,
        CredentialSelection::ConfigurationId,
        &[],
        vec![],
        "RACING-C-NONCE",
    )
    .unwrap();
    assert_eq!(first_request.c_nonce_hash(), second_request.c_nonce_hash());
    assert!(matches!(
        first
            .step(
                CredentialInput::CNonceReservation(CNonceReservationResult::new(
                    first_request.request_id(),
                    first_request.credential_issuer(),
                    *first_request.c_nonce_hash(),
                    first_request.reserved_at_epoch_seconds(),
                    CNonceReservationOutcome::Reserved,
                )),
                &credential_environment(&first_random, NOW + 1),
            )
            .unwrap()
            .as_slice(),
        [CredentialEffect::ReserveCredentialKey(_)]
    ));
    assert_eq!(
        second
            .step(
                CredentialInput::CNonceReservation(CNonceReservationResult::new(
                    second_request.request_id(),
                    second_request.credential_issuer(),
                    *second_request.c_nonce_hash(),
                    second_request.reserved_at_epoch_seconds(),
                    CNonceReservationOutcome::AlreadyReserved,
                )),
                &credential_environment(&second_random, NOW + 1),
            )
            .unwrap_err(),
        CredentialError::CNonceReplayed
    );
}

#[test]
fn attestation_public_key_and_compact_jwt_are_durably_burned_at_both_crash_boundaries() {
    let first_plan = plan(GermanPidFormat::DcSdJwt);
    let mut second_plan = first_plan.clone();
    second_plan.credential_issuer = HttpsIdentifier::parse("https://other-issuer.example").unwrap();
    let first_random = SequenceRandom::new();
    let second_random = SequenceRandom::new();
    let AtCredentialKeyReservation {
        flow: mut first,
        request: first_request,
    } = flow_at_credential_key_reservation(
        &first_random,
        &first_plan,
        CredentialSelection::ConfigurationId,
        &[],
        vec![],
    )
    .unwrap();
    let AtCredentialKeyReservation {
        flow: mut second,
        request: second_request,
    } = flow_at_credential_key_reservation(
        &second_random,
        &second_plan,
        CredentialSelection::ConfigurationId,
        &[],
        vec![],
    )
    .unwrap();
    assert_ne!(
        first_request.credential_issuer(),
        second_request.credential_issuer()
    );
    assert_eq!(
        first_request.public_key_thumbprint(),
        second_request.public_key_thumbprint()
    );

    // The shell's transaction key is the thumbprint alone, so the second issuer collides globally.
    let mut global_key_ledger = BTreeMap::new();
    assert!(global_key_ledger
        .insert(
            *first_request.public_key_thumbprint(),
            first_request.request_id()
        )
        .is_none());
    assert!(global_key_ledger
        .insert(
            *second_request.public_key_thumbprint(),
            second_request.request_id()
        )
        .is_some());
    assert!(matches!(
        first
            .step(
                CredentialInput::CredentialKeyReservation(credential_key_reservation_result(
                    &first_request,
                    CredentialKeyReservationOutcome::Reserved,
                )),
                &credential_environment(&first_random, NOW + 1),
            )
            .unwrap()
            .as_slice(),
        [CredentialEffect::AcquireKeyAttestation(_)]
    ));
    assert_eq!(
        second
            .step(
                CredentialInput::CredentialKeyReservation(credential_key_reservation_result(
                    &second_request,
                    CredentialKeyReservationOutcome::AlreadyReserved,
                )),
                &credential_environment(&second_random, NOW + 1),
            )
            .unwrap_err(),
        CredentialError::CredentialKeyAlreadyAttested
    );

    let random = SequenceRandom::new();
    let AtCredentialKeyReservation { mut flow, request } = flow_at_credential_key_reservation(
        &random,
        &first_plan,
        CredentialSelection::ConfigurationId,
        &[],
        vec![],
    )
    .unwrap();
    assert_eq!(
        flow.step(
            CredentialInput::CredentialKeyReservation(CredentialKeyReservationResult::new(
                CorrelationId::from_bytes([99; 32]),
                request.credential_issuer(),
                *request.public_key_thumbprint(),
                request.reserved_at_epoch_seconds(),
                CredentialKeyReservationOutcome::Reserved,
            )),
            &credential_environment(&random, NOW + 1),
        )
        .unwrap_err(),
        CredentialError::CredentialKeyReservationMismatch
    );
    let random = SequenceRandom::new();
    let AtCredentialKeyReservation { mut flow, request } = flow_at_credential_key_reservation(
        &random,
        &first_plan,
        CredentialSelection::ConfigurationId,
        &[],
        vec![],
    )
    .unwrap();
    assert_eq!(
        flow.step(
            CredentialInput::CredentialKeyReservation(credential_key_reservation_result(
                &request,
                CredentialKeyReservationOutcome::StorageFailure,
            )),
            &credential_environment(&random, NOW + 1),
        )
        .unwrap_err(),
        CredentialError::CredentialKeyReservationFailed
    );

    // After acquisition, no proof signing occurs until the exact KA hash has also committed.
    let random = SequenceRandom::new();
    let AtKeyAttestationReservation { mut flow, request } = flow_at_key_attestation_reservation(
        &random,
        &first_plan,
        CredentialSelection::ConfigurationId,
        &[],
        vec![],
    );
    assert_eq!(flow.status(), FlowStatus::AwaitingKeyAttestationReservation);
    assert!(matches!(
        flow.step(
            CredentialInput::KeyAttestationReservation(key_attestation_reservation_result(
                &request,
                KeyAttestationReservationOutcome::Reserved,
            )),
            &credential_environment(&random, NOW + 2),
        )
        .unwrap()
        .as_slice(),
        [CredentialEffect::SignCredentialProof(_)]
    ));

    let random = SequenceRandom::new();
    let AtKeyAttestationReservation { mut flow, request } = flow_at_key_attestation_reservation(
        &random,
        &first_plan,
        CredentialSelection::ConfigurationId,
        &[],
        vec![],
    );
    let mut wrong_hash = *request.key_attestation_hash();
    wrong_hash[0] ^= 0xff;
    assert_eq!(
        flow.step(
            CredentialInput::KeyAttestationReservation(KeyAttestationReservationResult::new(
                request.request_id(),
                request.credential_issuer(),
                *request.public_key_thumbprint(),
                wrong_hash,
                request.key_attestation_expires_at_epoch_seconds(),
                request.reserved_at_epoch_seconds(),
                KeyAttestationReservationOutcome::Reserved,
            )),
            &credential_environment(&random, NOW + 2),
        )
        .unwrap_err(),
        CredentialError::KeyAttestationReservationMismatch
    );

    for (outcome, expected) in [
        (
            KeyAttestationReservationOutcome::AlreadyReserved,
            CredentialError::KeyAttestationReplayed,
        ),
        (
            KeyAttestationReservationOutcome::CredentialKeyNotReserved,
            CredentialError::KeyAttestationReservationFailed,
        ),
        (
            KeyAttestationReservationOutcome::StorageFailure,
            CredentialError::KeyAttestationReservationFailed,
        ),
    ] {
        let random = SequenceRandom::new();
        let AtKeyAttestationReservation { mut flow, request } = flow_at_key_attestation_reservation(
            &random,
            &first_plan,
            CredentialSelection::ConfigurationId,
            &[],
            vec![],
        );
        assert_eq!(
            flow.step(
                CredentialInput::KeyAttestationReservation(key_attestation_reservation_result(
                    &request, outcome,
                )),
                &credential_environment(&random, NOW + 2),
            )
            .unwrap_err(),
            expected
        );
    }
}

#[test]
fn key_attestation_is_mandatory_exactly_bound_and_shape_checked_without_claiming_trust() {
    let selected = plan(GermanPidFormat::DcSdJwt);
    let random = SequenceRandom::new();
    let AtKeyAttestation { mut flow, request } = flow_at_key_attestation(
        &random,
        &selected,
        CredentialSelection::ConfigurationId,
        &[],
        vec![],
    )
    .unwrap();
    let valid = key_attestation_jwt(&request, NOW + 2);
    let wrong = KeyAttestation::new(CorrelationId::from_bytes([99; 32]), &valid);
    assert_eq!(
        flow.step(
            CredentialInput::KeyAttestation(wrong),
            &credential_environment(&random, NOW + 2),
        )
        .unwrap_err(),
        CredentialError::KeyAttestationBindingMismatch
    );

    // Appendix D does not require `iss`; x5c is the HAIP trust mechanism. Do not reject an
    // otherwise valid, exactly bound attestation solely because that optional claim is absent.
    let without_issuer = rewrite_key_attestation(
        &valid,
        |_| {},
        |payload| {
            payload.remove("iss");
        },
    );
    let random = SequenceRandom::new();
    let AtKeyAttestation { mut flow, request } = flow_at_key_attestation(
        &random,
        &selected,
        CredentialSelection::ConfigurationId,
        &[],
        vec![],
    )
    .unwrap();
    assert!(matches!(
        flow.step(
            CredentialInput::KeyAttestation(key_attestation(
                &request,
                NOW + 2,
                Some(&without_issuer),
            )),
            &credential_environment(&random, NOW + 2),
        )
        .unwrap()
        .as_slice(),
        [CredentialEffect::ReserveKeyAttestation(_)]
    ));

    // Public JWKs are extensible under RFC 7517. Optional public metadata must not break the
    // attested-key binding, while private key members remain forbidden below.
    let public_jwk_extensions = rewrite_key_attestation(
        &valid,
        |_| {},
        |payload| {
            let key = payload["attested_keys"][0].as_object_mut().unwrap();
            key.insert("alg".to_owned(), Value::String("ES256".to_owned()));
            key.insert(
                "kid".to_owned(),
                Value::String("provider-key-label".to_owned()),
            );
        },
    );
    let random = SequenceRandom::new();
    let AtKeyAttestation { mut flow, request } = flow_at_key_attestation(
        &random,
        &selected,
        CredentialSelection::ConfigurationId,
        &[],
        vec![],
    )
    .unwrap();
    assert!(matches!(
        flow.step(
            CredentialInput::KeyAttestation(key_attestation(
                &request,
                NOW + 2,
                Some(&public_jwk_extensions),
            )),
            &credential_environment(&random, NOW + 2),
        )
        .unwrap()
        .as_slice(),
        [CredentialEffect::ReserveKeyAttestation(_)]
    ));

    let wrong_type = rewrite_key_attestation(
        &valid,
        |header| {
            header.insert("typ".to_owned(), Value::String("other".to_owned()));
        },
        |_| {},
    );
    let missing_x5c = rewrite_key_attestation(
        &valid,
        |header| {
            header.remove("x5c");
        },
        |_| {},
    );
    let malformed_x5c = rewrite_key_attestation(
        &valid,
        |header| {
            header["x5c"] = serde_json::json!(["%%%"]);
        },
        |_| {},
    );
    let duplicate_x5c = rewrite_key_attestation(
        &valid,
        |header| {
            let certificate = Base64::encode_string(KEY_ATTESTATION_SIGNER_CERTIFICATE);
            header["x5c"] = serde_json::json!([certificate, certificate]);
        },
        |_| {},
    );
    let wrong_nonce = rewrite_key_attestation(
        &valid,
        |_| {},
        |payload| {
            payload.insert("nonce".to_owned(), Value::String("other".to_owned()));
        },
    );
    let insufficient_security = rewrite_key_attestation(
        &valid,
        |_| {},
        |payload| {
            payload.insert(
                "key_storage".to_owned(),
                serde_json::json!(["iso_18045_moderate"]),
            );
        },
    );
    let wrong_key = rewrite_key_attestation(
        &valid,
        |_| {},
        |payload| {
            payload["attested_keys"][0]["x"] =
                Value::String(Base64UrlUnpadded::encode_string(&[88; 32]));
        },
    );
    let private_key_material = rewrite_key_attestation(
        &valid,
        |_| {},
        |payload| {
            payload["attested_keys"][0]["d"] =
                Value::String(Base64UrlUnpadded::encode_string(&[77; 32]));
        },
    );
    let expired = rewrite_key_attestation(
        &valid,
        |_| {},
        |payload| {
            payload.insert("exp".to_owned(), Value::from(NOW + 1));
        },
    );
    let missing_certification = rewrite_key_attestation(
        &valid,
        |_| {},
        |payload| {
            payload.remove("certification");
        },
    );
    let insecure_certification = rewrite_key_attestation(
        &valid,
        |_| {},
        |payload| {
            payload["certification"] = Value::String("http://wallet-provider.example/cert".into());
        },
    );
    let missing_key_storage_status = rewrite_key_attestation(
        &valid,
        |_| {},
        |payload| {
            payload.remove("key_storage_status");
        },
    );
    let missing_status_reference = rewrite_key_attestation(
        &valid,
        |_| {},
        |payload| {
            payload["key_storage_status"]
                .as_object_mut()
                .unwrap()
                .remove("status");
        },
    );
    let missing_status_list = rewrite_key_attestation(
        &valid,
        |_| {},
        |payload| {
            payload["key_storage_status"]["status"]
                .as_object_mut()
                .unwrap()
                .remove("status_list");
        },
    );
    let insecure_status_uri = rewrite_key_attestation(
        &valid,
        |_| {},
        |payload| {
            payload["key_storage_status"]["status"]["status_list"]["uri"] =
                Value::String("http://wallet-provider.example/status".into());
        },
    );
    let negative_status_index = rewrite_key_attestation(
        &valid,
        |_| {},
        |payload| {
            payload["key_storage_status"]["status"]["status_list"]["idx"] = Value::from(-1);
        },
    );
    let overflowing_status_index = rewrite_key_attestation(
        &valid,
        |_| {},
        |payload| {
            payload["key_storage_status"]["status"]["status_list"]["idx"] =
                Value::from(u64::from(u32::MAX) + 1);
        },
    );
    let non_i64_status_expiry = rewrite_key_attestation(
        &valid,
        |_| {},
        |payload| {
            payload["key_storage_status"]["exp"] = Value::from(u64::MAX);
        },
    );
    let short_status_period = rewrite_key_attestation(
        &valid,
        |_| {},
        |payload| {
            payload["key_storage_status"]["exp"] =
                Value::from(NOW + 2 + MIN_KEY_STORAGE_STATUS_REMAINING_SECONDS as i64 - 1);
        },
    );
    let self_issued_not_self_signed = rewrite_key_attestation(
        &valid,
        |header| {
            header.insert(
                "x5c".to_owned(),
                serde_json::json!([SELF_ISSUED_NOT_SELF_SIGNED_B64]),
            );
        },
        |_| {},
    );
    // HAIP prohibits a self-signed signing certificate, not a merely self-issued certificate.
    // The transport boundary cannot prove self-signature without a verifier, so it must not use
    // subject == issuer as a substitute. External trust validation remains mandatory.
    let random = SequenceRandom::new();
    let AtKeyAttestation { mut flow, request } = flow_at_key_attestation(
        &random,
        &selected,
        CredentialSelection::ConfigurationId,
        &[],
        vec![],
    )
    .unwrap();
    assert!(matches!(
        flow.step(
            CredentialInput::KeyAttestation(key_attestation(
                &request,
                NOW + 2,
                Some(&self_issued_not_self_signed),
            )),
            &credential_environment(&random, NOW + 2),
        )
        .unwrap()
        .as_slice(),
        [CredentialEffect::ReserveKeyAttestation(_)]
    ));

    let future_iat = rewrite_key_attestation(
        &valid,
        |_| {},
        |payload| {
            payload.insert(
                "iat".to_owned(),
                Value::from(NOW + 2 + MAX_KEY_ATTESTATION_CLOCK_SKEW_SECONDS + 1),
            );
        },
    );
    for jwt in [
        "e30.e30.AQ".to_owned(),
        wrong_type,
        missing_x5c,
        malformed_x5c,
        duplicate_x5c,
        wrong_nonce,
        insufficient_security,
        wrong_key,
        private_key_material,
        expired,
        future_iat,
        missing_certification,
        insecure_certification,
        missing_key_storage_status,
        missing_status_reference,
        missing_status_list,
        insecure_status_uri,
        negative_status_index,
        overflowing_status_index,
        non_i64_status_expiry,
        short_status_period,
    ] {
        let random = SequenceRandom::new();
        let AtKeyAttestation { mut flow, request } = flow_at_key_attestation(
            &random,
            &selected,
            CredentialSelection::ConfigurationId,
            &[],
            vec![],
        )
        .unwrap();
        assert_eq!(
            flow.step(
                CredentialInput::KeyAttestation(key_attestation(&request, NOW + 2, Some(&jwt))),
                &credential_environment(&random, NOW + 2),
            )
            .unwrap_err(),
            CredentialError::KeyAttestationInvalid
        );
    }

    // Pre-issued attestations and technical lifetimes beyond the old process-local 10-minute
    // window are valid while their independent token and key-storage status expiries remain live.
    let pre_issued = rewrite_key_attestation(
        &valid,
        |_| {},
        |payload| {
            payload.insert("iat".to_owned(), Value::from(NOW - 86_400));
            payload.insert("exp".to_owned(), Value::from(NOW + 86_400));
        },
    );
    let random = SequenceRandom::new();
    let AtKeyAttestation { mut flow, request } = flow_at_key_attestation(
        &random,
        &selected,
        CredentialSelection::ConfigurationId,
        &[],
        vec![],
    )
    .unwrap();
    assert!(matches!(
        flow.step(
            CredentialInput::KeyAttestation(key_attestation(&request, NOW + 2, Some(&pre_issued),)),
            &credential_environment(&random, NOW + 2),
        )
        .unwrap()
        .as_slice(),
        [CredentialEffect::ReserveKeyAttestation(_)]
    ));

    let random = SequenceRandom::new();
    let AtKeyAttestation { mut flow, request } = flow_at_key_attestation(
        &random,
        &selected,
        CredentialSelection::ConfigurationId,
        &[],
        vec![],
    )
    .unwrap();
    let header = Base64UrlUnpadded::encode_string(
        serde_json::to_string(&serde_json::json!({
            "alg": "ES256",
            "typ": "key-attestation+jwt",
            "x5c": [Base64::encode_string(KEY_ATTESTATION_SIGNER_CERTIFICATE)],
        }))
        .unwrap()
        .as_bytes(),
    );
    let payload = format!(
        "{{\"iss\":\"https://wallet-provider.example\",\"iat\":{},\"exp\":{},\"key_storage\":[\"iso_18045_high\"],\"user_authentication\":[\"iso_18045_high\"],\"attested_keys\":[{{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"{}\",\"y\":\"{}\"}}],\"nonce\":\"A\",\"nonce\":\"B\"}}",
        NOW + 1,
        NOW + 300,
        request.public_jwk().x(),
        request.public_jwk().y(),
    );
    let duplicate = format!(
        "{header}.{}.{}",
        Base64UrlUnpadded::encode_string(payload.as_bytes()),
        Base64UrlUnpadded::encode_string(&[9; 64]),
    );
    assert_eq!(
        flow.step(
            CredentialInput::KeyAttestation(key_attestation(&request, NOW + 2, Some(&duplicate),)),
            &credential_environment(&random, NOW + 2),
        )
        .unwrap_err(),
        CredentialError::KeyAttestationInvalid
    );
}

#[test]
fn key_attestation_status_preference_is_effective_bounded_and_signature_verified() {
    let mut lower_than_floor = plan(GermanPidFormat::DcSdJwt);
    lower_than_floor.preferred_key_storage_status_period = Some(86_400);
    let random = SequenceRandom::new();
    let AtKeyAttestation { request, .. } = flow_at_key_attestation(
        &random,
        &lower_than_floor,
        CredentialSelection::ConfigurationId,
        &[],
        vec![],
    )
    .unwrap();
    assert_eq!(
        request.minimum_key_storage_status_period(),
        MIN_KEY_STORAGE_STATUS_REMAINING_SECONDS
    );

    let preferred = MIN_KEY_STORAGE_STATUS_REMAINING_SECONDS + 86_400;
    let mut selected = plan(GermanPidFormat::DcSdJwt);
    selected.preferred_key_storage_status_period = Some(preferred);
    let random = SequenceRandom::new();
    let AtKeyAttestation { mut flow, request } = flow_at_key_attestation(
        &random,
        &selected,
        CredentialSelection::ConfigurationId,
        &[],
        vec![],
    )
    .unwrap();
    assert_eq!(request.minimum_key_storage_status_period(), preferred);
    let short = key_attestation_jwt(&request, NOW + 2);
    assert_eq!(
        flow.step(
            CredentialInput::KeyAttestation(KeyAttestation::new(request.request_id(), &short)),
            &credential_environment(&random, NOW + 2),
        )
        .unwrap_err(),
        CredentialError::KeyAttestationInvalid
    );

    let random = SequenceRandom::new();
    let AtKeyAttestation { mut flow, request } = flow_at_key_attestation(
        &random,
        &selected,
        CredentialSelection::ConfigurationId,
        &[],
        vec![],
    )
    .unwrap();
    let exact = rewrite_key_attestation(
        &key_attestation_jwt(&request, NOW + 2),
        |_| {},
        |payload| {
            payload["key_storage_status"]["exp"] = Value::from(NOW + 2 + preferred as i64);
        },
    );
    assert!(matches!(
        flow.step(
            CredentialInput::KeyAttestation(KeyAttestation::new(request.request_id(), &exact)),
            &credential_environment(&random, NOW + 2),
        )
        .unwrap()
        .as_slice(),
        [CredentialEffect::ReserveKeyAttestation(_)]
    ));

    let random = SequenceRandom::new();
    let normal = plan(GermanPidFormat::DcSdJwt);
    let grant = authorized_grant(&random, &normal, &[]);
    let mut absurd = normal.clone();
    absurd.preferred_key_storage_status_period =
        Some(MAX_PREFERRED_KEY_STORAGE_STATUS_PERIOD_SECONDS + 1);
    assert!(matches!(
        CredentialFlowConfig::from_authorization(
            grant,
            &absurd,
            CredentialSelection::ConfigurationId,
            credential_key(),
        ),
        Err(CredentialError::PlanGrantMismatch)
    ));

    let random = SequenceRandom::new();
    let AtKeyAttestation { mut flow, request } = flow_at_key_attestation(
        &random,
        &normal,
        CredentialSelection::ConfigurationId,
        &[],
        vec![],
    )
    .unwrap();
    assert_eq!(
        flow.step(
            CredentialInput::KeyAttestation(key_attestation(&request, NOW + 2, None)),
            &credential_environment_with_verifier(&random, NOW + 2, &REJECTING_VERIFIER),
        )
        .unwrap_err(),
        CredentialError::KeyAttestationInvalid
    );
}

#[test]
fn proof_and_dpop_signatures_reject_mismatched_wrong_length_and_unverified_results() {
    let selected = plan(GermanPidFormat::DcSdJwt);
    let random = SequenceRandom::new();
    let AtCredentialProof {
        mut flow,
        request_id: _,
        signing_input,
    } = flow_at_credential_proof(
        &random,
        &selected,
        CredentialSelection::ConfigurationId,
        &[],
        vec![],
    );
    assert_eq!(
        flow.step(
            CredentialInput::CredentialProofSignature(SignatureResult::new(
                CorrelationId::from_bytes([88; 32]),
                signing_input,
                vec![8; 64],
            )),
            &credential_environment(&random, NOW + 3),
        )
        .unwrap_err(),
        CredentialError::CredentialProofSigningMismatch
    );

    let random = SequenceRandom::new();
    let AtCredentialProof {
        mut flow,
        request_id,
        signing_input,
    } = flow_at_credential_proof(
        &random,
        &selected,
        CredentialSelection::ConfigurationId,
        &[],
        vec![],
    );
    assert_eq!(
        flow.step(
            CredentialInput::CredentialProofSignature(SignatureResult::new(
                request_id,
                signing_input,
                vec![8; 64],
            )),
            &credential_environment_with_verifier(&random, NOW + 3, &REJECTING_VERIFIER,),
        )
        .unwrap_err(),
        CredentialError::CredentialProofSignatureInvalid
    );

    let random = SequenceRandom::new();
    let AtDpop {
        mut flow,
        request_id,
        signing_input,
    } = flow_at_dpop(
        &random,
        &selected,
        CredentialSelection::ConfigurationId,
        &[],
        vec![],
    );
    assert_eq!(
        flow.step(
            CredentialInput::DpopSignature(SignatureResult::new(
                request_id,
                signing_input,
                vec![7; 63],
            )),
            &credential_environment(&random, NOW + 4),
        )
        .unwrap_err(),
        CredentialError::DpopSignatureInvalid
    );

    let random = SequenceRandom::new();
    let AtDpop {
        mut flow,
        request_id,
        signing_input,
    } = flow_at_dpop(
        &random,
        &selected,
        CredentialSelection::ConfigurationId,
        &[],
        vec![],
    );
    assert_eq!(
        flow.step(
            CredentialInput::DpopSignature(SignatureResult::new(
                request_id,
                signing_input,
                vec![7; 64],
            )),
            &credential_environment_with_verifier(&random, NOW + 4, &REJECTING_VERIFIER,),
        )
        .unwrap_err(),
        CredentialError::DpopSignatureInvalid
    );
}

#[test]
fn resource_nonce_challenge_requires_rotation_and_never_redispatches_the_same_attestation() {
    let selected = plan(GermanPidFormat::DcSdJwt);
    let random = SequenceRandom::new();
    let AtCredentialRequest {
        mut flow,
        request_id,
        body,
        ..
    } = flow_at_credential_request(
        &random,
        &selected,
        CredentialSelection::ConfigurationId,
        &[],
        vec![],
    );
    let first: Value = serde_json::from_slice(&body).unwrap();
    let first_proof = first["proofs"]["jwt"][0].as_str().unwrap();
    let proof_header: Value = serde_json::from_slice(
        &Base64UrlUnpadded::decode_vec(first_proof.split('.').next().unwrap()).unwrap(),
    )
    .unwrap();
    assert!(proof_header["key_attestation"].as_str().is_some());
    assert_eq!(
        flow.step(
            CredentialInput::CredentialResponse(EndpointResponse::new(
                request_id,
                CREDENTIAL,
                "POST",
                401,
                vec![],
                vec![],
                vec![],
                vec![],
                vec!["resource-nonce-1".to_owned()],
                vec![
                    "Bearer realm=\"api\", DPoP realm=\"pid\", error=\"use_dpop_nonce\", scope=\"pid\""
                        .to_owned(),
                    "Basic realm=\"legacy\"".to_owned(),
                ],
                vec![],
            )),
            &credential_environment(&random, NOW + 5),
        )
        .unwrap_err(),
        CredentialError::CredentialKeyRotationRequired
    );
    assert_eq!(flow.status(), FlowStatus::Failed);
    assert_eq!(
        flow.step(
            CredentialInput::DpopSignature(SignatureResult::new(
                CorrelationId::from_bytes([90; 32]),
                vec![1],
                vec![2; 64],
            )),
            &credential_environment(&random, NOW + 6),
        )
        .unwrap_err(),
        CredentialError::AlreadyTerminal
    );
}

#[test]
fn invalid_c_nonce_requires_new_holder_key_instead_of_reacquiring_for_the_burned_key() {
    let selected = plan(GermanPidFormat::DcSdJwt);
    let random = SequenceRandom::new();
    let AtCredentialRequest {
        mut flow,
        request_id,
        ..
    } = flow_at_credential_request(
        &random,
        &selected,
        CredentialSelection::ConfigurationId,
        &[],
        vec![],
    );
    assert_eq!(
        flow.step(
            CredentialInput::CredentialResponse(endpoint_response(
                request_id,
                CREDENTIAL,
                400,
                vec![],
                vec![],
                br#"{"error":"invalid_nonce"}"#.to_vec(),
            )),
            &credential_environment(&random, NOW + 5),
        )
        .unwrap_err(),
        CredentialError::CredentialKeyRotationRequired
    );
    assert_eq!(flow.status(), FlowStatus::Failed);
}

#[test]
fn reused_seeded_resource_nonce_and_ambiguous_challenges_fail_closed() {
    let selected = plan(GermanPidFormat::DcSdJwt);
    let random = SequenceRandom::new();
    let AtCredentialRequest {
        mut flow,
        request_id,
        ..
    } = flow_at_credential_request(
        &random,
        &selected,
        CredentialSelection::ConfigurationId,
        &[],
        vec!["seed".to_owned()],
    );
    assert_eq!(
        flow.step(
            CredentialInput::CredentialResponse(endpoint_response(
                request_id,
                CREDENTIAL,
                401,
                vec!["seed".to_owned()],
                vec!["DPoP error=\"use_dpop_nonce\"".to_owned()],
                br#"{"error":"use_dpop_nonce"}"#.to_vec(),
            )),
            &credential_environment(&random, NOW + 5),
        )
        .unwrap_err(),
        CredentialError::DpopNonceStale
    );

    for challenges in [
        vec!["Bearer error=\"use_dpop_nonce\"".to_owned()],
        vec![
            "DPoP error=\"use_dpop_nonce\"".to_owned(),
            "DPoP error=\"use_dpop_nonce\"".to_owned(),
        ],
        vec!["DPoP error=\"invalid_dpop_proof\", DPoP error=\"use_dpop_nonce\"".to_owned()],
        vec!["DPoP error=\"use_dpop_nonce\", error=\"other\"".to_owned()],
    ] {
        let random = SequenceRandom::new();
        let AtCredentialRequest {
            mut flow,
            request_id,
            ..
        } = flow_at_credential_request(
            &random,
            &selected,
            CredentialSelection::ConfigurationId,
            &[],
            vec![],
        );
        assert!(flow
            .step(
                CredentialInput::CredentialResponse(endpoint_response(
                    request_id,
                    CREDENTIAL,
                    401,
                    vec!["fresh".to_owned()],
                    challenges,
                    br#"{"error":"use_dpop_nonce"}"#.to_vec(),
                )),
                &credential_environment(&random, NOW + 5),
            )
            .is_err());
    }
}

#[test]
fn immediate_response_rejects_deferred_batch_reissuance_and_wrong_pid_shape() {
    let selected = plan(GermanPidFormat::DcSdJwt);
    let good = sd_jwt(ISSUER, "urn:eudi:pid:1", "dc+sd-jwt", "ES256");
    let issuer_supplied_key_binding = format!(
        "{good}{}",
        sd_jwt(ISSUER, "urn:eudi:pid:1", "kb+jwt", "ES256").trim_end_matches('~')
    );
    let excessive_disclosures = format!("{good}{}", "e30~".repeat(258));
    let cases = [
        (
            202,
            br#"{"transaction_id":"later","interval":10}"#.to_vec(),
            CredentialError::DeferredIssuanceUnsupported,
        ),
        (
            200,
            serde_json::to_vec(&serde_json::json!({
                "credentials": [{"credential": good}, {"credential": good}]
            }))
            .unwrap(),
            CredentialError::BatchIssuanceUnsupported,
        ),
        (
            200,
            br#"{"acceptance_token":"legacy"}"#.to_vec(),
            CredentialError::DeferredIssuanceUnsupported,
        ),
        (
            200,
            serde_json::to_vec(&serde_json::json!({
                "credentials": [{"credential": good}], "refresh_token": "secret"
            }))
            .unwrap(),
            CredentialError::ReissuanceUnsupported,
        ),
        (
            200,
            serde_json::to_vec(&serde_json::json!({
                "credentials": [{"credential": good}],
                "credential_response_encryption": {"alg": "ECDH-ES", "enc": "A256GCM"}
            }))
            .unwrap(),
            CredentialError::ResponseEncryptionUnsupported,
        ),
        (
            200,
            immediate_response(&sd_jwt(ISSUER, "urn:eudi:other:1", "dc+sd-jwt", "ES256")),
            CredentialError::CredentialFormatMismatch,
        ),
        (
            200,
            serde_json::to_vec(&serde_json::json!({
                "credentials": [{"credential": good}], "notification_id": 7
            }))
            .unwrap(),
            CredentialError::InvalidCredentialResponse,
        ),
        (
            200,
            immediate_response(&sd_jwt(ISSUER, "urn:eudi:pid:1", "JWT", "ES256")),
            CredentialError::CredentialFormatMismatch,
        ),
        (
            200,
            immediate_response(&sd_jwt(ISSUER, "urn:eudi:pid:1", "dc+sd-jwt", "ES384")),
            CredentialError::CredentialFormatMismatch,
        ),
        (
            200,
            immediate_response(&issuer_supplied_key_binding),
            CredentialError::CredentialFormatMismatch,
        ),
        (
            200,
            immediate_response(&excessive_disclosures),
            CredentialError::CredentialFormatMismatch,
        ),
        (
            200,
            br#"{"credentials":[],"credentials":[]}"#.to_vec(),
            CredentialError::InvalidCredentialResponse,
        ),
    ];
    for (status, body, expected) in cases {
        let random = SequenceRandom::new();
        let AtCredentialRequest {
            mut flow,
            request_id,
            ..
        } = flow_at_credential_request(
            &random,
            &selected,
            CredentialSelection::ConfigurationId,
            &[],
            vec![],
        );
        assert_eq!(
            flow.step(
                CredentialInput::CredentialResponse(endpoint_response(
                    request_id,
                    CREDENTIAL,
                    status,
                    vec![],
                    vec![],
                    body,
                )),
                &credential_environment(&random, NOW + 5),
            )
            .unwrap_err(),
            expected
        );
    }
}

#[test]
fn sd_jwt_transport_defers_issuer_authentication_and_retains_notification_id() {
    let selected = plan(GermanPidFormat::DcSdJwt);
    let candidates = [
        sd_jwt(
            "https://untrusted-but-structurally-valid.example",
            "urn:eudi:pid:1",
            "dc+sd-jwt",
            "ES256",
        ),
        sd_jwt_without_issuer("urn:eudi:pid:1", "dc+sd-jwt", "ES256"),
    ];
    for raw in candidates {
        let random = SequenceRandom::new();
        let AtCredentialRequest {
            mut flow,
            request_id,
            ..
        } = flow_at_credential_request(
            &random,
            &selected,
            CredentialSelection::ConfigurationId,
            &[],
            vec![],
        );
        let body = serde_json::to_vec(&serde_json::json!({
            "credentials": [{"credential": raw}],
            "notification_id": "notify-after-verified-ingestion"
        }))
        .unwrap();
        flow.step(
            CredentialInput::CredentialResponse(endpoint_response(
                request_id,
                CREDENTIAL,
                200,
                vec![],
                vec![],
                body,
            )),
            &credential_environment(&random, NOW + 5),
        )
        .unwrap();
        let unverified = flow.into_unverified_credential().unwrap();
        assert_eq!(unverified.raw(), raw.as_bytes());
        assert_eq!(
            unverified.notification_id(),
            Some("notify-after-verified-ingestion")
        );
        assert!(unverified.requires_verified_ingestion());
        assert!(format!("{unverified:?}").contains("verified_ingestion"));
        assert!(!format!("{unverified:?}").contains("notify-after"));
    }
}

#[test]
fn credential_response_does_not_require_non_normative_cache_directives() {
    let selected = plan(GermanPidFormat::DcSdJwt);
    let random = SequenceRandom::new();
    let AtCredentialRequest {
        mut flow,
        request_id,
        ..
    } = flow_at_credential_request(
        &random,
        &selected,
        CredentialSelection::ConfigurationId,
        &[],
        vec![],
    );
    let raw = sd_jwt(ISSUER, "urn:eudi:pid:1", "dc+sd-jwt", "ES256");
    flow.step(
        CredentialInput::CredentialResponse(EndpointResponse::new(
            request_id,
            CREDENTIAL,
            "POST",
            200,
            vec!["application/json".to_owned()],
            vec![],
            vec![],
            vec!["identity".to_owned()],
            vec![],
            vec![],
            immediate_response(&raw),
        )),
        &credential_environment(&random, NOW + 5),
    )
    .unwrap();
    assert_eq!(
        flow.into_unverified_credential().unwrap().raw(),
        raw.as_bytes()
    );
}

struct MdocStub;

impl Signer for MdocStub {
    fn sign(&self, _key: &KeyRef, _alg: Alg, _payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Ok(vec![6; 64])
    }
}

impl crypto_traits::Digest for MdocStub {
    fn sha256(&self, input: &[u8]) -> [u8; 32] {
        AwsLc.sha256(input)
    }
}

fn mdoc_pid(doc_type: &str) -> Vec<u8> {
    let mut namespaces = BTreeMap::new();
    namespaces.insert(
        "eu.europa.ec.eudi.pid.1".to_owned(),
        vec![mdoc::IssuerSignedItem {
            digest_id: 0,
            random: vec![3; 16],
            element_id: "family_name".to_owned(),
            element_value: mdoc::cbor::Value::Text("Mustermann".to_owned()),
        }],
    );
    mdoc::build_and_sign(
        namespaces,
        doc_type,
        mdoc::cbor::Value::Null,
        mdoc::ValidityInfo {
            signed: "2026-01-01T00:00:00Z".to_owned(),
            valid_from: "2026-01-01T00:00:00Z".to_owned(),
            valid_until: "2027-01-01T00:00:00Z".to_owned(),
        },
        &MdocStub,
        &MdocStub,
        &KeyRef("issuer".to_owned()),
        Alg::Es256,
    )
    .unwrap()
    .to_value()
    .to_canonical()
}

#[test]
fn mdoc_response_decodes_canonical_issuer_signed_and_requires_pid_doctype() {
    let selected = plan(GermanPidFormat::MsoMdoc);
    let random = SequenceRandom::new();
    let AtCredentialRequest {
        mut flow,
        request_id,
        ..
    } = flow_at_credential_request(
        &random,
        &selected,
        CredentialSelection::ConfigurationId,
        &[],
        vec![],
    );
    let raw = mdoc_pid(MDOC_PID_DOCTYPE);
    let encoded = Base64UrlUnpadded::encode_string(&raw);
    flow.step(
        CredentialInput::CredentialResponse(endpoint_response(
            request_id,
            CREDENTIAL,
            200,
            vec![],
            vec![],
            immediate_response(&encoded),
        )),
        &credential_environment(&random, NOW + 5),
    )
    .unwrap();
    let issued = flow.into_unverified_credential().unwrap();
    assert_eq!(issued.format(), GermanPidFormat::MsoMdoc);
    assert_eq!(issued.raw(), raw);

    let random = SequenceRandom::new();
    let AtCredentialRequest {
        mut flow,
        request_id,
        ..
    } = flow_at_credential_request(
        &random,
        &selected,
        CredentialSelection::ConfigurationId,
        &[],
        vec![],
    );
    let wrong = Base64UrlUnpadded::encode_string(&mdoc_pid("org.iso.18013.5.1.mDL"));
    assert_eq!(
        flow.step(
            CredentialInput::CredentialResponse(endpoint_response(
                request_id,
                CREDENTIAL,
                200,
                vec![],
                vec![],
                immediate_response(&wrong),
            )),
            &credential_environment(&random, NOW + 5),
        )
        .unwrap_err(),
        CredentialError::CredentialFormatMismatch
    );
}

#[test]
fn transport_binding_out_of_order_replay_clock_token_expiry_and_size_fail_closed() {
    let selected = plan(GermanPidFormat::DcSdJwt);
    let random = SequenceRandom::new();
    let grant = authorized_grant(&random, &selected, &[]);
    let config = CredentialFlowConfig::from_authorization(
        grant,
        &selected,
        CredentialSelection::ConfigurationId,
        credential_key(),
    )
    .unwrap();
    assert!(matches!(
        CredentialFlow::begin(config, &credential_environment(&random, NOW + 300)),
        Err(CredentialError::TokenExpired)
    ));

    let random = SequenceRandom::new();
    let grant = authorized_grant(&random, &selected, &[]);
    let config = CredentialFlowConfig::from_authorization(
        grant,
        &selected,
        CredentialSelection::ConfigurationId,
        credential_key(),
    )
    .unwrap();
    assert!(matches!(
        CredentialFlow::begin(config, &credential_environment(&ZeroRandom, NOW)),
        Err(CredentialError::RandomnessFailure)
    ));

    let random = SequenceRandom::new();
    let grant = authorized_grant(&random, &selected, &[]);
    let config = CredentialFlowConfig::from_authorization(
        grant,
        &selected,
        CredentialSelection::ConfigurationId,
        credential_key(),
    )
    .unwrap();
    let (mut flow, _) =
        CredentialFlow::begin(config, &credential_environment(&random, NOW)).unwrap();
    assert_eq!(
        flow.step(
            CredentialInput::DpopSignature(SignatureResult::new(
                CorrelationId::from_bytes([7; 32]),
                b"wrong".to_vec(),
                vec![7; 64],
            )),
            &credential_environment(&random, NOW + 1),
        )
        .unwrap_err(),
        CredentialError::UnexpectedInput
    );
    assert_eq!(flow.status(), FlowStatus::Failed);
    assert_eq!(
        flow.step(
            CredentialInput::DpopSignature(SignatureResult::new(
                CorrelationId::from_bytes([7; 32]),
                b"wrong".to_vec(),
                vec![7; 64],
            )),
            &credential_environment(&random, NOW + 2),
        )
        .unwrap_err(),
        CredentialError::AlreadyTerminal
    );

    let random = SequenceRandom::new();
    let AtCredentialRequest {
        mut flow,
        request_id,
        ..
    } = flow_at_credential_request(
        &random,
        &selected,
        CredentialSelection::ConfigurationId,
        &[],
        vec![],
    );
    assert_eq!(
        flow.step(
            CredentialInput::CredentialResponse(endpoint_response(
                request_id,
                "https://issuer.example/other",
                200,
                vec![],
                vec![],
                vec![b' '; MAX_CREDENTIAL_RESPONSE_BYTES + 1],
            )),
            &credential_environment(&random, NOW + 5),
        )
        .unwrap_err(),
        CredentialError::TransportBindingMismatch
    );

    let random = SequenceRandom::new();
    let AtCredentialRequest {
        mut flow,
        request_id,
        ..
    } = flow_at_credential_request(
        &random,
        &selected,
        CredentialSelection::ConfigurationId,
        &[],
        vec![],
    );
    assert_eq!(
        flow.step(
            CredentialInput::CredentialResponse(endpoint_response(
                request_id,
                CREDENTIAL,
                200,
                vec![],
                vec![],
                vec![b' '; MAX_CREDENTIAL_RESPONSE_BYTES + 1],
            )),
            &credential_environment(&random, NOW + 5),
        )
        .unwrap_err(),
        CredentialError::InvalidCredentialResponse
    );
}

#[test]
fn diagnostics_redact_access_token_nonces_attestation_proofs_credentials_and_key_handles() {
    let selected = plan(GermanPidFormat::DcSdJwt);
    let random = SequenceRandom::new();
    let AtKeyAttestation { flow, request } = flow_at_key_attestation(
        &random,
        &selected,
        CredentialSelection::ConfigurationId,
        &[],
        vec!["SECRET-DPOP-NONCE".to_owned()],
    )
    .unwrap();
    let diagnostics = format!("{flow:?} {request:?}");
    for secret in [
        "ACCESS-TOKEN",
        "CREDENTIAL-NONCE",
        "SECRET-DPOP-NONCE",
        "hardware-key-reference",
        &Base64UrlUnpadded::encode_string(&[1u8; 32]),
        &Base64UrlUnpadded::encode_string(&[2u8; 32]),
        &Base64UrlUnpadded::encode_string(&[3u8; 32]),
        &Base64UrlUnpadded::encode_string(&[4u8; 32]),
    ] {
        assert!(!diagnostics.contains(secret));
    }
    assert!(diagnostics.contains("UNRESOLVED"));
    assert!(diagnostics.contains("[REDACTED]"));

    let random = SequenceRandom::new();
    let grant = authorized_grant(&random, &selected, &[]);
    let config = CredentialFlowConfig::from_authorization(
        grant,
        &selected,
        CredentialSelection::ConfigurationId,
        credential_key(),
    )
    .unwrap();
    let diagnostics = format!("{config:?} {:?}", credential_key());
    for coordinate in [
        Base64UrlUnpadded::encode_string(&[1u8; 32]),
        Base64UrlUnpadded::encode_string(&[2u8; 32]),
        Base64UrlUnpadded::encode_string(&[3u8; 32]),
        Base64UrlUnpadded::encode_string(&[4u8; 32]),
    ] {
        assert!(!diagnostics.contains(&coordinate));
    }

    let response = endpoint_response(
        CorrelationId::from_bytes([4; 32]),
        CREDENTIAL,
        200,
        vec!["SECRET-DPOP-NONCE".to_owned()],
        vec![],
        br#"{"credentials":[{"credential":"SECRET-CREDENTIAL"}]}"#.to_vec(),
    );
    let diagnostics = format!("{response:?}");
    assert!(!diagnostics.contains("SECRET"));
}
