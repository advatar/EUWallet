use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use crypto_backend::AwsLc;
use crypto_traits::{Alg, CryptoError, Digest as _, KeyRef, Random, Signer};
use oid4vci::authorization::{
    AuthorizationEffect, AuthorizationEnvironment, AuthorizationFlow, AuthorizationFlowConfig,
    AuthorizationInput, AuthorizationRedirect, CorrelationId, DpopKeyBinding, DpopSignature,
    EndpointResponse as AuthorizationEndpointResponse, Es256PublicJwk, WalletClientAuthentication,
    WalletClientAuthenticationRequest,
};
use oid4vci::credential::{
    CredentialEffect, CredentialEnvironment, CredentialError, CredentialFlow, CredentialFlowConfig,
    CredentialInput, CredentialKeyBinding, CredentialSelection, EndpointResponse, FlowStatus,
    KeyAttestation, KeyAttestationRequest, SignatureResult, MAX_CREDENTIAL_RESPONSE_BYTES,
    MAX_NONCE_RESPONSE_BYTES, MAX_RESOURCE_DPOP_NONCE_RETRIES,
};
use oid4vci::foundation::{
    AuthorizationCodeGrant, CredentialOffer, CredentialSigningAlgorithm, GermanPidFormat,
    GermanPidIssuancePlan, HolderBindingMethod, HttpsEndpoint, HttpsIdentifier, OfferGrantSource,
    PidProviderTrust, MDOC_PID_DOCTYPE,
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
const SELF_SIGNED_TRUST_ANCHOR: &[u8] = include_bytes!("../../x509/tests/vectors/ca.der");

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
        authorization_endpoint: HttpsEndpoint::parse("https://as.example/authorize").unwrap(),
        token_endpoint: HttpsEndpoint::parse(TOKEN).unwrap(),
        pushed_authorization_request_endpoint: HttpsEndpoint::parse(PAR).unwrap(),
        pid_provider_trust: PidProviderTrust::Unresolved,
    }
}

fn offer(plan: &GermanPidIssuancePlan) -> CredentialOffer {
    CredentialOffer {
        credential_issuer: HttpsIdentifier::parse(ISSUER).unwrap(),
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

fn auth_environment<'a>(
    random: &'a dyn Random,
    now_epoch_seconds: i64,
) -> AuthorizationEnvironment<'a> {
    AuthorizationEnvironment {
        random,
        digest: &AwsLc,
        now_epoch_seconds,
    }
}

fn credential_environment<'a>(
    random: &'a dyn Random,
    now_epoch_seconds: i64,
    seen_c_nonce_hashes: &'a [[u8; 32]],
) -> CredentialEnvironment<'a> {
    CredentialEnvironment {
        random,
        digest: &AwsLc,
        now_epoch_seconds,
        seen_c_nonce_hashes,
    }
}

fn take_client_auth(effect: AuthorizationEffect) -> WalletClientAuthenticationRequest {
    match effect {
        AuthorizationEffect::AcquireWalletClientAuthentication(request) => request,
        other => panic!("expected client authentication, got {other:?}"),
    }
}

fn client_auth(
    request: &WalletClientAuthenticationRequest,
    marker: u8,
) -> WalletClientAuthentication {
    WalletClientAuthentication::new(
        request.request_id(),
        request.purpose(),
        request.client_id(),
        request.audience(),
        request.endpoint(),
        "e30.e30.YXR0ZXN0YXRpb24",
        &format!("e30.e30.{}", Base64UrlUnpadded::encode_string(&[marker; 8])),
    )
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
        "application/json",
        vec!["no-cache, no-store".to_owned()],
        if endpoint == TOKEN {
            vec!["no-cache".to_owned()]
        } else {
            vec![]
        },
        dpop_nonce,
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
    )
    .unwrap();
    let (mut flow, effect) =
        AuthorizationFlow::begin(config, &auth_environment(random, NOW - 4)).unwrap();
    let par_auth = take_client_auth(effect);
    let effects = flow
        .step(
            AuthorizationInput::WalletClientAuthentication(client_auth(&par_auth, 1)),
            &auth_environment(random, NOW - 4),
        )
        .unwrap();
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
    let token_auth = take_client_auth(effects.into_iter().next().unwrap());
    let effects = flow
        .step(
            AuthorizationInput::WalletClientAuthentication(client_auth(&token_auth, 2)),
            &auth_environment(random, NOW - 2),
        )
        .unwrap();
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
        "iss": "https://wallet-provider.example",
        "iat": now - 1,
        "exp": now + 300,
        "key_storage": ["iso_18045_high"],
        "user_authentication": ["iso_18045_high"],
        "attested_keys": [{
            "kty": "EC",
            "crv": "P-256",
            "x": request.public_jwk().x(),
            "y": request.public_jwk().y(),
        }],
        "nonce": request.c_nonce(),
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
    KeyAttestation::new(
        request.request_id(),
        request.credential_issuer(),
        request.credential_endpoint(),
        request.key_ref().clone(),
        request.public_jwk().clone(),
        request.c_nonce(),
        jwt,
    )
}

struct AtKeyAttestation {
    flow: CredentialFlow,
    request: KeyAttestationRequest,
}

fn flow_at_key_attestation(
    random: &SequenceRandom,
    plan: &GermanPidIssuancePlan,
    selection: CredentialSelection,
    identifiers: &[&str],
    dpop_nonce: Vec<String>,
    seen: &[[u8; 32]],
) -> Result<AtKeyAttestation, CredentialError> {
    let grant = authorized_grant(random, plan, identifiers);
    let config =
        CredentialFlowConfig::from_authorization(grant, plan, selection, credential_key())?;
    let (mut flow, effect) =
        CredentialFlow::begin(config, &credential_environment(random, NOW, seen))?;
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
            br#"{"c_nonce":"CREDENTIAL-NONCE"}"#.to_vec(),
        )),
        &credential_environment(random, NOW + 1, seen),
    )?;
    let request = match effects.into_iter().next().unwrap() {
        CredentialEffect::AcquireKeyAttestation(request) => request,
        other => panic!("expected key attestation, got {other:?}"),
    };
    Ok(AtKeyAttestation { flow, request })
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
    let AtKeyAttestation { mut flow, request } =
        flow_at_key_attestation(random, plan, selection, identifiers, dpop_nonce, &[]).unwrap();
    assert_eq!(request.algorithm(), Alg::Es256);
    assert_eq!(request.jwt_type(), "key-attestation+jwt");
    assert_eq!(request.key_storage_requirement(), "iso_18045_high");
    assert_eq!(request.user_authentication_requirement(), "iso_18045_high");
    assert!(request.require_x5c_without_trust_anchor());
    let effects = flow
        .step(
            CredentialInput::KeyAttestation(key_attestation(&request, NOW + 2, None)),
            &credential_environment(random, NOW + 2, &[]),
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
            &credential_environment(random, NOW + 3, &[]),
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
            &credential_environment(random, NOW + 4, &[]),
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
    assert_eq!(proof_header["alg"], "ES256");
    assert_eq!(proof_header["typ"], "openid4vci-proof+jwt");
    assert_eq!(proof_header["jwk"]["crv"], "P-256");
    assert_eq!(
        proof_header["jwk"]["x"],
        Base64UrlUnpadded::encode_string(&[3u8; 32])
    );
    assert!(proof_header["key_attestation"]
        .as_str()
        .unwrap()
        .contains('.'));
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
            &credential_environment(&random, NOW + 5, &[]),
        )
        .unwrap();
    assert!(effects.is_empty());
    assert_eq!(flow.status(), FlowStatus::Complete);
    let issued = flow.into_credential().unwrap();
    assert_eq!(issued.format(), GermanPidFormat::DcSdJwt);
    assert_eq!(issued.raw(), raw.as_bytes());
    assert_eq!(issued.c_nonce_hash(), &AwsLc.sha256(b"CREDENTIAL-NONCE"));
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
        CredentialFlow::begin(config, &credential_environment(&random, NOW, &[])).unwrap();
    let nonce = match effect {
        CredentialEffect::SendNonce(request) => request,
        _ => unreachable!(),
    };
    let replay_hash = AwsLc.sha256(b"CREDENTIAL-NONCE");
    assert_eq!(
        flow.step(
            CredentialInput::NonceResponse(endpoint_response(
                nonce.request_id(),
                NONCE,
                200,
                vec![],
                vec![],
                br#"{"c_nonce":"CREDENTIAL-NONCE"}"#.to_vec(),
            )),
            &credential_environment(&random, NOW + 1, &[replay_hash]),
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
            CredentialFlow::begin(config, &credential_environment(&random, NOW, &[])).unwrap();
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
                &credential_environment(&random, NOW + 1, &[]),
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
        &[],
    )
    .unwrap();
    let valid = key_attestation_jwt(&request, NOW + 2);
    let wrong = KeyAttestation::new(
        CorrelationId::from_bytes([99; 32]),
        request.credential_issuer(),
        request.credential_endpoint(),
        request.key_ref().clone(),
        request.public_jwk().clone(),
        request.c_nonce(),
        &valid,
    );
    assert_eq!(
        flow.step(
            CredentialInput::KeyAttestation(wrong),
            &credential_environment(&random, NOW + 2, &[]),
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
        &[],
    )
    .unwrap();
    assert!(matches!(
        flow.step(
            CredentialInput::KeyAttestation(key_attestation(
                &request,
                NOW + 2,
                Some(&without_issuer),
            )),
            &credential_environment(&random, NOW + 2, &[]),
        )
        .unwrap()
        .as_slice(),
        [CredentialEffect::SignCredentialProof(_)]
    ));

    let wrong_type = rewrite_key_attestation(
        &valid,
        |header| {
            header.insert("typ".to_owned(), Value::String("other".to_owned()));
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
    let expired = rewrite_key_attestation(
        &valid,
        |_| {},
        |payload| {
            payload.insert("exp".to_owned(), Value::from(NOW + 1));
        },
    );
    let self_signed_signer = rewrite_key_attestation(
        &valid,
        |header| {
            header.insert(
                "x5c".to_owned(),
                serde_json::json!([Base64::encode_string(SELF_SIGNED_TRUST_ANCHOR)]),
            );
        },
        |_| {},
    );
    for jwt in [
        "e30.e30.AQ".to_owned(),
        wrong_type,
        wrong_nonce,
        insufficient_security,
        wrong_key,
        expired,
        self_signed_signer,
    ] {
        let random = SequenceRandom::new();
        let AtKeyAttestation { mut flow, request } = flow_at_key_attestation(
            &random,
            &selected,
            CredentialSelection::ConfigurationId,
            &[],
            vec![],
            &[],
        )
        .unwrap();
        assert_eq!(
            flow.step(
                CredentialInput::KeyAttestation(key_attestation(&request, NOW + 2, Some(&jwt))),
                &credential_environment(&random, NOW + 2, &[]),
            )
            .unwrap_err(),
            CredentialError::KeyAttestationInvalid
        );
    }

    let random = SequenceRandom::new();
    let AtKeyAttestation { mut flow, request } = flow_at_key_attestation(
        &random,
        &selected,
        CredentialSelection::ConfigurationId,
        &[],
        vec![],
        &[],
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
            &credential_environment(&random, NOW + 2, &[]),
        )
        .unwrap_err(),
        CredentialError::KeyAttestationInvalid
    );
}

#[test]
fn proof_and_dpop_signatures_reject_stale_cross_request_and_wrong_length_results() {
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
            &credential_environment(&random, NOW + 3, &[]),
        )
        .unwrap_err(),
        CredentialError::CredentialProofSigningMismatch
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
            &credential_environment(&random, NOW + 4, &[]),
        )
        .unwrap_err(),
        CredentialError::DpopSignatureInvalid
    );
}

#[test]
fn resource_nonce_challenge_retries_once_with_fresh_jti_and_same_credential_proof() {
    assert_eq!(MAX_RESOURCE_DPOP_NONCE_RETRIES, 1);
    let selected = plan(GermanPidFormat::DcSdJwt);
    let random = SequenceRandom::new();
    let AtCredentialRequest {
        mut flow,
        request_id,
        body: first_body,
        dpop_proof: first_dpop,
    } = flow_at_credential_request(
        &random,
        &selected,
        CredentialSelection::ConfigurationId,
        &[],
        vec![],
    );
    let effects = flow
        .step(
            CredentialInput::CredentialResponse(endpoint_response(
                request_id,
                CREDENTIAL,
                401,
                vec!["resource-nonce-1".to_owned()],
                vec!["DPoP realm=\"pid\", error=\"use_dpop_nonce\", scope=\"pid\"".to_owned()],
                br#"{"error":"use_dpop_nonce"}"#.to_vec(),
            )),
            &credential_environment(&random, NOW + 5, &[]),
        )
        .unwrap();
    let signing = match effects.into_iter().next().unwrap() {
        CredentialEffect::SignDpop(request) => request,
        other => panic!("expected retry DPoP, got {other:?}"),
    };
    let (_, retry_payload) = decode_jwt_input(signing.signing_input());
    assert_eq!(retry_payload["nonce"], "resource-nonce-1");
    let retry_id = signing.request_id();
    let retry_input = signing.signing_input().to_vec();
    let effects = flow
        .step(
            CredentialInput::DpopSignature(SignatureResult::new(
                retry_id,
                retry_input,
                vec![7; 64],
            )),
            &credential_environment(&random, NOW + 6, &[]),
        )
        .unwrap();
    let request = match effects.into_iter().next().unwrap() {
        CredentialEffect::SendCredential(request) => request,
        _ => unreachable!(),
    };
    assert_eq!(request.body(), first_body);
    assert_ne!(request.dpop_proof(), first_dpop);
    assert_eq!(
        flow.step(
            CredentialInput::CredentialResponse(endpoint_response(
                request.request_id(),
                CREDENTIAL,
                401,
                vec!["resource-nonce-2".to_owned()],
                vec!["DPoP error=\"use_dpop_nonce\"".to_owned()],
                br#"{"error":"use_dpop_nonce"}"#.to_vec(),
            )),
            &credential_environment(&random, NOW + 7, &[]),
        )
        .unwrap_err(),
        CredentialError::DpopNonceRetryLimit
    );
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
            &credential_environment(&random, NOW + 5, &[]),
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
                &credential_environment(&random, NOW + 5, &[]),
            )
            .is_err());
    }
}

#[test]
fn immediate_response_rejects_deferred_batch_notification_reissuance_and_wrong_pid() {
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
            serde_json::to_vec(&serde_json::json!({
                "credentials": [{"credential": good}], "notification_id": "notify"
            }))
            .unwrap(),
            CredentialError::NotificationUnsupported,
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
            immediate_response(&sd_jwt(
                "https://other.example",
                "urn:eudi:pid:1",
                "dc+sd-jwt",
                "ES256",
            )),
            CredentialError::CredentialFormatMismatch,
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
                &credential_environment(&random, NOW + 5, &[]),
            )
            .unwrap_err(),
            expected
        );
    }
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
        &credential_environment(&random, NOW + 5, &[]),
    )
    .unwrap();
    let issued = flow.into_credential().unwrap();
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
            &credential_environment(&random, NOW + 5, &[]),
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
        CredentialFlow::begin(config, &credential_environment(&random, NOW + 300, &[])),
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
        CredentialFlow::begin(config, &credential_environment(&ZeroRandom, NOW, &[])),
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
        CredentialFlow::begin(config, &credential_environment(&random, NOW, &[])).unwrap();
    assert_eq!(
        flow.step(
            CredentialInput::DpopSignature(SignatureResult::new(
                CorrelationId::from_bytes([7; 32]),
                b"wrong".to_vec(),
                vec![7; 64],
            )),
            &credential_environment(&random, NOW + 1, &[]),
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
            &credential_environment(&random, NOW + 2, &[]),
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
            &credential_environment(&random, NOW + 5, &[]),
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
            &credential_environment(&random, NOW + 5, &[]),
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
        &[],
    )
    .unwrap();
    let diagnostics = format!("{flow:?} {request:?}");
    for secret in [
        "ACCESS-TOKEN",
        "CREDENTIAL-NONCE",
        "SECRET-DPOP-NONCE",
        "hardware-key-reference",
    ] {
        assert!(!diagnostics.contains(secret));
    }
    assert!(diagnostics.contains("UNRESOLVED"));
    assert!(diagnostics.contains("[REDACTED]"));

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
