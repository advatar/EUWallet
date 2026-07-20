//! Bounded OpenID4VCI 1.0 Final authorization-code transport for the HAIP profile.
//!
//! This module is sans-I/O. It emits typed requests for a native shell and does not establish
//! PID-provider trust, mint Wallet Attestations, or perform signing. HAIP client authentication
//! and RFC 9449 DPoP are deliberately separate: PAR and token requests both require fresh
//! `OAuth-Client-Attestation` / `OAuth-Client-Attestation-PoP` material, while only the token
//! request carries a DPoP proof. The future WIA/KA integration must satisfy the attestation
//! acquisition effect; accepting an untrusted or self-asserted Wallet Attestation is not part of
//! this boundary.

use crate::bounded_json::{self, JsonBoundaryError, JsonLimits};
use crate::foundation::{
    CredentialOffer, GermanPidIssuancePlan, HttpsEndpoint, HttpsIdentifier, OpaqueValue,
};
use base64ct::{Base64UrlUnpadded, Encoding};
use crypto_traits::{Alg, Digest, KeyRef, Random};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::fmt;

pub const PKCE_VERIFIER_BYTES: usize = 32;
pub const PKCE_VERIFIER_CHARS: usize = 43;
pub const STATE_BYTES: usize = 32;
pub const STATE_CHARS: usize = 43;
pub const DPOP_JTI_BYTES: usize = 32;
pub const MAX_CLIENT_ID_BYTES: usize = 2_048;
pub const MAX_ISSUER_STATE_BYTES: usize = 2_048;
pub const MAX_REQUEST_URI_BYTES: usize = 2_048;
pub const MAX_AUTHORIZATION_CODE_BYTES: usize = 4_096;
pub const MAX_WALLET_ATTESTATION_BYTES: usize = 32 * 1024;
pub const MAX_WALLET_ATTESTATION_POP_BYTES: usize = 16 * 1024;
pub const MAX_DPOP_NONCE_BYTES: usize = 2_048;
pub const MAX_DPOP_SIGNING_INPUT_BYTES: usize = 16 * 1024;
pub const MAX_ACCESS_TOKEN_BYTES: usize = 8 * 1024;
pub const MAX_CREDENTIAL_IDENTIFIERS: usize = 32;
pub const MAX_CREDENTIAL_IDENTIFIER_BYTES: usize = 2_048;
pub const MAX_TOKEN_RESPONSE_BYTES: usize = 64 * 1024;
pub const MAX_PAR_RESPONSE_BYTES: usize = 16 * 1024;
pub const MAX_CALLBACK_QUERY_BYTES: usize = 16 * 1024;
pub const MAX_PAR_EXPIRES_IN_SECONDS: u64 = 599;
pub const MAX_DPOP_NONCE_RETRIES: u8 = 2;

const PAR_JSON_LIMITS: JsonLimits = JsonLimits {
    max_bytes: MAX_PAR_RESPONSE_BYTES,
    max_depth: 4,
    max_container_entries: 32,
    max_string_bytes: 8 * 1024,
};

const TOKEN_JSON_LIMITS: JsonLimits = JsonLimits {
    max_bytes: MAX_TOKEN_RESPONSE_BYTES,
    max_depth: 12,
    max_container_entries: 128,
    max_string_bytes: 8 * 1024,
};

/// Stable, non-secret diagnostics. Attacker-controlled values and protocol secrets never appear in
/// an error variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorizationError {
    InvalidConfiguration,
    OfferPlanMismatch,
    InvalidClock,
    RandomnessFailure,
    UnexpectedInput,
    CorrelationMismatch,
    ClientAuthenticationBindingMismatch,
    ClientAuthenticationInvalid,
    ClientAuthenticationReused,
    DpopSigningResultMismatch,
    DpopSignatureInvalid,
    DpopNonceInvalid,
    DpopNonceStale,
    DpopNonceRetryLimit,
    TransportBindingMismatch,
    InvalidMediaType,
    CachePolicyMissing,
    InvalidParResponse,
    ParRejected,
    RedirectMismatch,
    InvalidAuthorizationCallback,
    StateMismatch,
    AuthorizationIssuerMismatch,
    AuthorizationDenied,
    InvalidTokenResponse,
    TokenTypeDowngrade,
    TokenRejected,
    AlreadyTerminal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndpointPurpose {
    Par,
    Token,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowStatus {
    AwaitingClientAuthentication(EndpointPurpose),
    AwaitingDpopSignature,
    AwaitingParResponse,
    AwaitingAuthorization,
    AwaitingTokenResponse,
    Complete,
    Failed,
}

/// Opaque correlation material. It is copyable for response binding but redacted from diagnostics.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CorrelationId([u8; 32]);

impl fmt::Debug for CorrelationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CorrelationId([REDACTED])")
    }
}

impl CorrelationId {
    /// Reconstruct a correlation identifier at a transport/FFI boundary.
    pub fn from_bytes(value: [u8; 32]) -> Self {
        Self(value)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A secret byte buffer that clears its owned bytes on drop and never prints its contents.
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    fn new(value: Vec<u8>) -> Self {
        Self(value)
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretBytes([REDACTED])")
    }
}

/// An owned protocol secret with explicit access and redacted diagnostics.
pub struct SecretString(Vec<u8>);

impl SecretString {
    fn from_str(value: &str) -> Self {
        Self(value.as_bytes().to_vec())
    }

    fn from_string(value: String) -> Self {
        Self(value.into_bytes())
    }

    fn duplicate(&self) -> Self {
        Self(self.0.clone())
    }

    pub fn expose(&self) -> &str {
        // Every constructor receives an already-valid Rust string.
        core::str::from_utf8(&self.0).unwrap_or("")
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretString([REDACTED])")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Es256PublicJwk {
    x: String,
    y: String,
}

impl Es256PublicJwk {
    pub fn parse(x: &str, y: &str) -> Result<Self, AuthorizationError> {
        validate_coordinate(x)?;
        validate_coordinate(y)?;
        Ok(Self {
            x: x.to_owned(),
            y: y.to_owned(),
        })
    }

    pub fn x(&self) -> &str {
        &self.x
    }

    pub fn y(&self) -> &str {
        &self.y
    }

    fn thumbprint(&self, digest: &dyn Digest) -> String {
        // RFC 7638 member ordering and member set for an EC JWK.
        let canonical = format!(
            "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}",
            self.x, self.y
        );
        base64url(&digest.sha256(canonical.as_bytes()))
    }
}

fn validate_coordinate(value: &str) -> Result<(), AuthorizationError> {
    if value.len() != 43 || !is_base64url_unpadded(value.as_bytes()) {
        return Err(AuthorizationError::InvalidConfiguration);
    }
    let decoded = Base64UrlUnpadded::decode_vec(value)
        .map_err(|_| AuthorizationError::InvalidConfiguration)?;
    if decoded.len() != 32 || Base64UrlUnpadded::encode_string(&decoded) != value {
        return Err(AuthorizationError::InvalidConfiguration);
    }
    Ok(())
}

/// A public JWK and opaque hardware-key handle supplied as one shell-validated binding.
pub struct DpopKeyBinding {
    key_ref: KeyRef,
    public_jwk: Es256PublicJwk,
}

impl DpopKeyBinding {
    pub fn new(key_ref: KeyRef, public_jwk: Es256PublicJwk) -> Result<Self, AuthorizationError> {
        if !valid_bounded_text(&key_ref.0, 1_024, false) {
            return Err(AuthorizationError::InvalidConfiguration);
        }
        Ok(Self {
            key_ref,
            public_jwk,
        })
    }

    fn duplicate(&self) -> Self {
        Self {
            key_ref: self.key_ref.clone(),
            public_jwk: self.public_jwk.clone(),
        }
    }
}

impl fmt::Debug for DpopKeyBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DpopKeyBinding")
            .field("key_ref", &"[REDACTED]")
            .field("public_jwk", &self.public_jwk)
            .finish()
    }
}

/// Configuration selected from the already-bounded foundation types. Constructing this value does
/// not make [`GermanPidIssuancePlan::pid_provider_trust`] trusted.
pub struct AuthorizationFlowConfig {
    authorization_server: HttpsIdentifier,
    credential_issuer: HttpsIdentifier,
    configuration_id: String,
    credential_endpoint: HttpsEndpoint,
    nonce_endpoint: HttpsEndpoint,
    authorization_endpoint: HttpsEndpoint,
    token_endpoint: HttpsEndpoint,
    par_endpoint: HttpsEndpoint,
    scope: String,
    client_id: String,
    redirect_uri: HttpsIdentifier,
    issuer_state: Option<SecretString>,
    dpop_key: DpopKeyBinding,
}

impl fmt::Debug for AuthorizationFlowConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizationFlowConfig")
            .field("authorization_server", &self.authorization_server)
            .field("credential_issuer", &self.credential_issuer)
            .field("configuration_id", &self.configuration_id)
            .field("credential_endpoint", &self.credential_endpoint)
            .field("nonce_endpoint", &self.nonce_endpoint)
            .field("authorization_endpoint", &self.authorization_endpoint)
            .field("token_endpoint", &self.token_endpoint)
            .field("par_endpoint", &self.par_endpoint)
            .field("scope", &self.scope)
            .field("client_id", &self.client_id)
            .field("redirect_uri", &self.redirect_uri)
            .field("issuer_state", &"[REDACTED]")
            .field("dpop_key", &self.dpop_key)
            .finish()
    }
}

impl AuthorizationFlowConfig {
    pub fn from_plan_and_offer(
        plan: &GermanPidIssuancePlan,
        offer: &CredentialOffer,
        client_id: &str,
        redirect_uri: &str,
        dpop_key: DpopKeyBinding,
    ) -> Result<Self, AuthorizationError> {
        if offer.credential_issuer != plan.credential_issuer
            || !offer.authorization_code_eligible()
            || !offer
                .credential_configuration_ids
                .iter()
                .any(|identifier| identifier == &plan.configuration_id)
            || offer
                .authorization_code
                .as_ref()
                .and_then(|grant| grant.authorization_server.as_ref())
                .is_some_and(|server| server != &plan.authorization_server)
        {
            return Err(AuthorizationError::OfferPlanMismatch);
        }
        Self::new(
            plan,
            offer
                .authorization_code
                .as_ref()
                .and_then(|grant| grant.issuer_state.as_ref()),
            client_id,
            redirect_uri,
            dpop_key,
        )
    }

    pub fn new(
        plan: &GermanPidIssuancePlan,
        issuer_state: Option<&OpaqueValue>,
        client_id: &str,
        redirect_uri: &str,
        dpop_key: DpopKeyBinding,
    ) -> Result<Self, AuthorizationError> {
        if !valid_bounded_text(client_id, MAX_CLIENT_ID_BYTES, false) || !valid_scope(&plan.scope) {
            return Err(AuthorizationError::InvalidConfiguration);
        }
        let redirect_uri = HttpsIdentifier::parse(redirect_uri)
            .map_err(|_| AuthorizationError::InvalidConfiguration)?;
        if !redirect_uri.as_str()["https://".len()..].contains('/') {
            return Err(AuthorizationError::InvalidConfiguration);
        }
        if plan.authorization_endpoint.as_str().contains('?') {
            // The browser request is deliberately restricted to exactly client_id + request_uri.
            return Err(AuthorizationError::InvalidConfiguration);
        }
        let issuer_state = issuer_state
            .map(OpaqueValue::as_str)
            .map(|value| {
                if valid_bounded_text(value, MAX_ISSUER_STATE_BYTES, true) {
                    Ok(SecretString::from_str(value))
                } else {
                    Err(AuthorizationError::InvalidConfiguration)
                }
            })
            .transpose()?;
        Ok(Self {
            authorization_server: plan.authorization_server.clone(),
            credential_issuer: plan.credential_issuer.clone(),
            configuration_id: plan.configuration_id.clone(),
            credential_endpoint: plan.credential_endpoint.clone(),
            nonce_endpoint: plan.nonce_endpoint.clone(),
            authorization_endpoint: plan.authorization_endpoint.clone(),
            token_endpoint: plan.token_endpoint.clone(),
            par_endpoint: plan.pushed_authorization_request_endpoint.clone(),
            scope: plan.scope.clone(),
            client_id: client_id.to_owned(),
            redirect_uri,
            issuer_state,
            dpop_key,
        })
    }
}

/// The shell must obtain fresh Wallet Attestation client-auth material for this exact request.
/// `audience` is the selected Authorization Server identifier; `endpoint` and method bind the PoP
/// JWT request. The WIA slice is responsible for producing and validating these JWTs.
pub struct WalletClientAuthenticationRequest {
    request_id: CorrelationId,
    purpose: EndpointPurpose,
    client_id: String,
    audience: String,
    endpoint: String,
}

impl WalletClientAuthenticationRequest {
    pub fn request_id(&self) -> CorrelationId {
        self.request_id
    }
    pub fn purpose(&self) -> EndpointPurpose {
        self.purpose
    }
    pub fn client_id(&self) -> &str {
        &self.client_id
    }
    pub fn audience(&self) -> &str {
        &self.audience
    }
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
    pub fn method(&self) -> &'static str {
        "POST"
    }
}

impl fmt::Debug for WalletClientAuthenticationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WalletClientAuthenticationRequest")
            .field("request_id", &self.request_id)
            .field("purpose", &self.purpose)
            .field("client_id", &self.client_id)
            .field("audience", &self.audience)
            .field("endpoint", &self.endpoint)
            .field("method", &"POST")
            .finish()
    }
}

/// Fresh, externally minted Wallet Attestation client authentication. Binding fields are repeated
/// so stale results from another flow or endpoint are rejected before a request is emitted.
pub struct WalletClientAuthentication {
    request_id: CorrelationId,
    purpose: EndpointPurpose,
    client_id: String,
    audience: String,
    endpoint: String,
    attestation: SecretString,
    proof_of_possession: SecretString,
}

impl WalletClientAuthentication {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request_id: CorrelationId,
        purpose: EndpointPurpose,
        client_id: &str,
        audience: &str,
        endpoint: &str,
        attestation: &str,
        proof_of_possession: &str,
    ) -> Self {
        Self {
            request_id,
            purpose,
            client_id: client_id.to_owned(),
            audience: audience.to_owned(),
            endpoint: endpoint.to_owned(),
            attestation: SecretString::from_str(attestation),
            proof_of_possession: SecretString::from_str(proof_of_possession),
        }
    }
}

impl fmt::Debug for WalletClientAuthentication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WalletClientAuthentication")
            .field("request_id", &self.request_id)
            .field("purpose", &self.purpose)
            .field("client_id", &"[REDACTED]")
            .field("audience", &"[REDACTED]")
            .field("endpoint", &"[REDACTED]")
            .field("attestation", &"[REDACTED]")
            .field("proof_of_possession", &"[REDACTED]")
            .finish()
    }
}

pub struct DpopSigningRequest {
    request_id: CorrelationId,
    key_ref: KeyRef,
    signing_input: SecretBytes,
}

impl DpopSigningRequest {
    pub fn request_id(&self) -> CorrelationId {
        self.request_id
    }
    pub fn key_ref(&self) -> &KeyRef {
        &self.key_ref
    }
    pub fn algorithm(&self) -> Alg {
        Alg::Es256
    }
    pub fn signing_input(&self) -> &[u8] {
        self.signing_input.expose()
    }
}

impl fmt::Debug for DpopSigningRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DpopSigningRequest")
            .field("request_id", &self.request_id)
            .field("key_ref", &"[REDACTED]")
            .field("algorithm", &Alg::Es256)
            .field("signing_input", &"[REDACTED]")
            .finish()
    }
}

pub struct DpopSignature {
    request_id: CorrelationId,
    signing_input: SecretBytes,
    signature: SecretBytes,
}

impl DpopSignature {
    pub fn new(request_id: CorrelationId, signing_input: Vec<u8>, signature: Vec<u8>) -> Self {
        Self {
            request_id,
            signing_input: SecretBytes::new(signing_input),
            signature: SecretBytes::new(signature),
        }
    }
}

impl fmt::Debug for DpopSignature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DpopSignature([REDACTED])")
    }
}

pub struct ParRequest {
    request_id: CorrelationId,
    endpoint: String,
    body: SecretBytes,
    client_attestation: SecretString,
    client_attestation_pop: SecretString,
}

impl ParRequest {
    pub fn request_id(&self) -> CorrelationId {
        self.request_id
    }
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
    pub fn content_type(&self) -> &'static str {
        "application/x-www-form-urlencoded"
    }
    pub fn body(&self) -> &[u8] {
        self.body.expose()
    }
    pub fn oauth_client_attestation(&self) -> &str {
        self.client_attestation.expose()
    }
    pub fn oauth_client_attestation_pop(&self) -> &str {
        self.client_attestation_pop.expose()
    }
}

impl fmt::Debug for ParRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ParRequest")
            .field("request_id", &self.request_id)
            .field("endpoint", &self.endpoint)
            .field("content_type", &self.content_type())
            .field("body", &"[REDACTED]")
            .field("oauth_client_attestation", &"[REDACTED]")
            .field("oauth_client_attestation_pop", &"[REDACTED]")
            .finish()
    }
}

pub struct AuthorizationRequest {
    url: String,
    request_uri_expires_at_epoch_seconds: i64,
}

impl AuthorizationRequest {
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The shell must dispatch the browser request no later than this time. The deadline applies
    /// to dereferencing the PAR handle, not to completion of the interactive authorization.
    pub fn request_uri_expires_at_epoch_seconds(&self) -> i64 {
        self.request_uri_expires_at_epoch_seconds
    }
}

impl fmt::Debug for AuthorizationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizationRequest")
            .field("url", &"[REDACTED]")
            .field(
                "request_uri_expires_at_epoch_seconds",
                &self.request_uri_expires_at_epoch_seconds,
            )
            .finish()
    }
}

pub struct TokenRequest {
    request_id: CorrelationId,
    endpoint: String,
    body: SecretBytes,
    client_attestation: SecretString,
    client_attestation_pop: SecretString,
    dpop_proof: SecretString,
}

impl TokenRequest {
    pub fn request_id(&self) -> CorrelationId {
        self.request_id
    }
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
    pub fn content_type(&self) -> &'static str {
        "application/x-www-form-urlencoded"
    }
    pub fn body(&self) -> &[u8] {
        self.body.expose()
    }
    pub fn oauth_client_attestation(&self) -> &str {
        self.client_attestation.expose()
    }
    pub fn oauth_client_attestation_pop(&self) -> &str {
        self.client_attestation_pop.expose()
    }
    pub fn dpop_proof(&self) -> &str {
        self.dpop_proof.expose()
    }
}

impl fmt::Debug for TokenRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TokenRequest")
            .field("request_id", &self.request_id)
            .field("endpoint", &self.endpoint)
            .field("content_type", &self.content_type())
            .field("body", &"[REDACTED]")
            .field("oauth_client_attestation", &"[REDACTED]")
            .field("oauth_client_attestation_pop", &"[REDACTED]")
            .field("dpop_proof", &"[REDACTED]")
            .finish()
    }
}

pub enum AuthorizationEffect {
    AcquireWalletClientAuthentication(WalletClientAuthenticationRequest),
    SignDpop(DpopSigningRequest),
    SendPar(ParRequest),
    OpenAuthorization(AuthorizationRequest),
    SendToken(TokenRequest),
}

impl fmt::Debug for AuthorizationEffect {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AcquireWalletClientAuthentication(value) => value.fmt(formatter),
            Self::SignDpop(value) => value.fmt(formatter),
            Self::SendPar(value) => value.fmt(formatter),
            Self::OpenAuthorization(value) => value.fmt(formatter),
            Self::SendToken(value) => value.fmt(formatter),
        }
    }
}

pub struct EndpointResponse {
    request_id: CorrelationId,
    endpoint: String,
    method: String,
    status: u16,
    content_type: String,
    cache_control_headers: Vec<String>,
    pragma_headers: Vec<String>,
    dpop_nonce_headers: Vec<String>,
    body: SecretBytes,
}

impl EndpointResponse {
    /// Preserve raw singleton/bag header values for in-core validation. Keeping these arguments
    /// explicit makes it difficult for a shell adapter to silently collapse duplicate headers.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request_id: CorrelationId,
        endpoint: &str,
        method: &str,
        status: u16,
        content_type: &str,
        cache_control_headers: Vec<String>,
        pragma_headers: Vec<String>,
        dpop_nonce_headers: Vec<String>,
        body: Vec<u8>,
    ) -> Self {
        Self {
            request_id,
            endpoint: endpoint.to_owned(),
            method: method.to_owned(),
            status,
            content_type: content_type.to_owned(),
            cache_control_headers,
            pragma_headers,
            dpop_nonce_headers,
            body: SecretBytes::new(body),
        }
    }
}

impl fmt::Debug for EndpointResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EndpointResponse")
            .field("request_id", &self.request_id)
            .field("endpoint", &"[REDACTED]")
            .field("method", &"[REDACTED]")
            .field("status", &self.status)
            .field("content_type", &"[REDACTED]")
            .field("cache_control_headers", &"[REDACTED]")
            .field("pragma_headers", &"[REDACTED]")
            .field("dpop_nonce_headers", &"[REDACTED]")
            .field("body", &"[REDACTED]")
            .finish()
    }
}

pub struct AuthorizationRedirect {
    redirect_uri: String,
    query: SecretBytes,
}

impl AuthorizationRedirect {
    pub fn new(redirect_uri: &str, query: Vec<u8>) -> Self {
        Self {
            redirect_uri: redirect_uri.to_owned(),
            query: SecretBytes::new(query),
        }
    }
}

impl fmt::Debug for AuthorizationRedirect {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizationRedirect")
            .field("redirect_uri", &"[REDACTED]")
            .field("query", &"[REDACTED]")
            .finish()
    }
}

pub enum AuthorizationInput {
    WalletClientAuthentication(WalletClientAuthentication),
    DpopSignature(DpopSignature),
    ParResponse(EndpointResponse),
    AuthorizationRedirect(AuthorizationRedirect),
    TokenResponse(EndpointResponse),
}

impl fmt::Debug for AuthorizationInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::WalletClientAuthentication(_) => "WalletClientAuthentication([REDACTED])",
            Self::DpopSignature(_) => "DpopSignature([REDACTED])",
            Self::ParResponse(_) => "ParResponse([REDACTED])",
            Self::AuthorizationRedirect(_) => "AuthorizationRedirect([REDACTED])",
            Self::TokenResponse(_) => "TokenResponse([REDACTED])",
        })
    }
}

pub struct AccessTokenGrant {
    access_token: SecretString,
    issued_at_epoch_seconds: i64,
    expires_in_seconds: Option<u32>,
    credential_identifiers: Vec<SecretString>,
    token_endpoint_dpop_nonce: Option<SecretString>,
    authorization_server: HttpsIdentifier,
    token_endpoint: HttpsEndpoint,
    credential_issuer: HttpsIdentifier,
    configuration_id: String,
    credential_endpoint: HttpsEndpoint,
    nonce_endpoint: HttpsEndpoint,
    dpop_key: DpopKeyBinding,
}

impl AccessTokenGrant {
    pub fn access_token(&self) -> &str {
        self.access_token.expose()
    }
    pub fn issued_at_epoch_seconds(&self) -> i64 {
        self.issued_at_epoch_seconds
    }
    pub fn expires_in_seconds(&self) -> Option<u32> {
        self.expires_in_seconds
    }
    pub fn token_endpoint_dpop_nonce(&self) -> Option<&str> {
        self.token_endpoint_dpop_nonce
            .as_ref()
            .map(SecretString::expose)
    }
    pub fn credential_identifiers(&self) -> impl ExactSizeIterator<Item = &str> {
        self.credential_identifiers.iter().map(SecretString::expose)
    }
    pub fn credential_issuer(&self) -> &str {
        self.credential_issuer.as_str()
    }
    pub fn authorization_server(&self) -> &str {
        self.authorization_server.as_str()
    }
    pub fn token_endpoint(&self) -> &str {
        self.token_endpoint.as_str()
    }
    pub fn configuration_id(&self) -> &str {
        &self.configuration_id
    }
    pub fn credential_endpoint(&self) -> &str {
        self.credential_endpoint.as_str()
    }
    pub fn nonce_endpoint(&self) -> &str {
        self.nonce_endpoint.as_str()
    }
    pub fn dpop_key_ref(&self) -> &KeyRef {
        &self.dpop_key.key_ref
    }
    pub fn dpop_public_jwk(&self) -> &Es256PublicJwk {
        &self.dpop_key.public_jwk
    }
}

impl fmt::Debug for AccessTokenGrant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccessTokenGrant")
            .field("access_token", &"[REDACTED]")
            .field("issued_at_epoch_seconds", &self.issued_at_epoch_seconds)
            .field("expires_in_seconds", &self.expires_in_seconds)
            .field(
                "credential_identifiers",
                &self
                    .credential_identifiers
                    .iter()
                    .map(|_| "[REDACTED]")
                    .collect::<Vec<_>>(),
            )
            .field(
                "token_endpoint_dpop_nonce",
                &self
                    .token_endpoint_dpop_nonce
                    .as_ref()
                    .map(|_| "[REDACTED]"),
            )
            .field("authorization_server", &self.authorization_server)
            .field("token_endpoint", &self.token_endpoint)
            .field("credential_issuer", &self.credential_issuer)
            .field("configuration_id", &self.configuration_id)
            .field("credential_endpoint", &self.credential_endpoint)
            .field("nonce_endpoint", &self.nonce_endpoint)
            .field("dpop_key", &self.dpop_key)
            .finish()
    }
}

struct Context {
    authorization_server: HttpsIdentifier,
    credential_issuer: HttpsIdentifier,
    configuration_id: String,
    credential_endpoint: HttpsEndpoint,
    nonce_endpoint: HttpsEndpoint,
    authorization_endpoint: HttpsEndpoint,
    token_endpoint: HttpsEndpoint,
    par_endpoint: HttpsEndpoint,
    scope: String,
    client_id: String,
    redirect_uri: HttpsIdentifier,
    issuer_state: Option<SecretString>,
    dpop_key: DpopKeyBinding,
    pkce_verifier: SecretString,
    pkce_challenge: String,
    state: SecretString,
    dpop_jkt: String,
    token_endpoint_nonce: Option<SecretString>,
    retired_token_endpoint_nonces: Vec<SecretString>,
    used_client_auth_pop_hashes: Vec<[u8; 32]>,
    used_random_values: Vec<[u8; 32]>,
    last_now_epoch_seconds: i64,
}

impl Drop for Context {
    fn drop(&mut self) {
        for value in &mut self.used_random_values {
            value.fill(0);
        }
        for value in &mut self.used_client_auth_pop_hashes {
            value.fill(0);
        }
    }
}

enum Stage {
    AwaitingClientAuthentication {
        purpose: EndpointPurpose,
        request_id: CorrelationId,
        authorization_code: Option<SecretString>,
        nonce_retry_count: u8,
    },
    SigningDpop {
        request_id: CorrelationId,
        signing_input: SecretBytes,
        client_auth: WalletClientAuthentication,
        authorization_code: SecretString,
        nonce_retry_count: u8,
    },
    AwaitingParResponse {
        request_id: CorrelationId,
    },
    AwaitingAuthorization,
    AwaitingTokenResponse {
        request_id: CorrelationId,
        authorization_code: SecretString,
        nonce_retry_count: u8,
    },
    Complete(AccessTokenGrant),
    Failed(AuthorizationError),
}

pub struct AuthorizationFlow {
    context: Context,
    stage: Stage,
}

impl fmt::Debug for AuthorizationFlow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizationFlow")
            .field("status", &self.status())
            .field("authorization_server", &self.context.authorization_server)
            .field("credential_issuer", &self.context.credential_issuer)
            .field("secrets", &"[REDACTED]")
            .finish()
    }
}

pub struct AuthorizationEnvironment<'a> {
    pub random: &'a dyn Random,
    pub digest: &'a dyn Digest,
    pub now_epoch_seconds: i64,
}

impl AuthorizationFlow {
    pub fn begin(
        config: AuthorizationFlowConfig,
        environment: &AuthorizationEnvironment<'_>,
    ) -> Result<(Self, AuthorizationEffect), AuthorizationError> {
        validate_clock(environment.now_epoch_seconds)?;
        let mut used_random_values = Vec::new();
        let verifier_entropy = fresh_random(environment.random, &mut used_random_values)?;
        let state_entropy = fresh_random(environment.random, &mut used_random_values)?;
        let pkce_verifier = base64url(&verifier_entropy);
        let state = base64url(&state_entropy);
        if pkce_verifier.len() != PKCE_VERIFIER_CHARS || state.len() != STATE_CHARS {
            return Err(AuthorizationError::RandomnessFailure);
        }
        let pkce_challenge = base64url(&environment.digest.sha256(pkce_verifier.as_bytes()));
        let dpop_jkt = config.dpop_key.public_jwk.thumbprint(environment.digest);
        let context = Context {
            authorization_server: config.authorization_server,
            credential_issuer: config.credential_issuer,
            configuration_id: config.configuration_id,
            credential_endpoint: config.credential_endpoint,
            nonce_endpoint: config.nonce_endpoint,
            authorization_endpoint: config.authorization_endpoint,
            token_endpoint: config.token_endpoint,
            par_endpoint: config.par_endpoint,
            scope: config.scope,
            client_id: config.client_id,
            redirect_uri: config.redirect_uri,
            issuer_state: config.issuer_state,
            dpop_key: config.dpop_key,
            pkce_verifier: SecretString::from_string(pkce_verifier),
            pkce_challenge,
            state: SecretString::from_string(state),
            dpop_jkt,
            token_endpoint_nonce: None,
            retired_token_endpoint_nonces: Vec::new(),
            used_client_auth_pop_hashes: Vec::new(),
            used_random_values,
            last_now_epoch_seconds: environment.now_epoch_seconds,
        };
        let placeholder = Stage::Failed(AuthorizationError::UnexpectedInput);
        let mut flow = Self {
            context,
            stage: placeholder,
        };
        let (stage, effect) =
            flow.client_auth_stage(EndpointPurpose::Par, None, 0, environment.random)?;
        flow.stage = stage;
        Ok((flow, effect))
    }

    pub fn status(&self) -> FlowStatus {
        match self.stage {
            Stage::AwaitingClientAuthentication { purpose, .. } => {
                FlowStatus::AwaitingClientAuthentication(purpose)
            }
            Stage::SigningDpop { .. } => FlowStatus::AwaitingDpopSignature,
            Stage::AwaitingParResponse { .. } => FlowStatus::AwaitingParResponse,
            Stage::AwaitingAuthorization => FlowStatus::AwaitingAuthorization,
            Stage::AwaitingTokenResponse { .. } => FlowStatus::AwaitingTokenResponse,
            Stage::Complete(_) => FlowStatus::Complete,
            Stage::Failed(_) => FlowStatus::Failed,
        }
    }

    pub fn failure(&self) -> Option<AuthorizationError> {
        match self.stage {
            Stage::Failed(error) => Some(error),
            _ => None,
        }
    }

    pub fn into_token(self) -> Result<AccessTokenGrant, AuthorizationError> {
        match self.stage {
            Stage::Complete(grant) => Ok(grant),
            Stage::Failed(error) => Err(error),
            _ => Err(AuthorizationError::UnexpectedInput),
        }
    }

    pub fn step(
        &mut self,
        input: AuthorizationInput,
        environment: &AuthorizationEnvironment<'_>,
    ) -> Result<Vec<AuthorizationEffect>, AuthorizationError> {
        validate_clock(environment.now_epoch_seconds).map_err(|error| self.latch(error))?;
        if environment.now_epoch_seconds < self.context.last_now_epoch_seconds {
            return Err(self.latch(AuthorizationError::InvalidClock));
        }
        self.context.last_now_epoch_seconds = environment.now_epoch_seconds;
        if matches!(self.stage, Stage::Complete(_) | Stage::Failed(_)) {
            return Err(AuthorizationError::AlreadyTerminal);
        }
        let previous = core::mem::replace(
            &mut self.stage,
            Stage::Failed(AuthorizationError::UnexpectedInput),
        );
        match self.transition(previous, input, environment) {
            Ok((stage, effects)) => {
                self.stage = stage;
                Ok(effects)
            }
            Err(error) => {
                self.stage = Stage::Failed(error);
                Err(error)
            }
        }
    }

    fn latch(&mut self, error: AuthorizationError) -> AuthorizationError {
        self.stage = Stage::Failed(error);
        error
    }

    fn transition(
        &mut self,
        stage: Stage,
        input: AuthorizationInput,
        environment: &AuthorizationEnvironment<'_>,
    ) -> Result<(Stage, Vec<AuthorizationEffect>), AuthorizationError> {
        match (stage, input) {
            (
                Stage::AwaitingClientAuthentication {
                    purpose,
                    request_id,
                    authorization_code,
                    nonce_retry_count,
                },
                AuthorizationInput::WalletClientAuthentication(client_auth),
            ) => self.accept_client_authentication(
                purpose,
                request_id,
                authorization_code,
                nonce_retry_count,
                client_auth,
                environment,
            ),
            (
                Stage::SigningDpop {
                    request_id,
                    signing_input,
                    client_auth,
                    authorization_code,
                    nonce_retry_count,
                },
                AuthorizationInput::DpopSignature(signature),
            ) => self.accept_dpop_signature(
                request_id,
                signing_input,
                client_auth,
                authorization_code,
                nonce_retry_count,
                signature,
                environment.random,
            ),
            (
                Stage::AwaitingParResponse { request_id },
                AuthorizationInput::ParResponse(response),
            ) => self.accept_par_response(request_id, response, environment.now_epoch_seconds),
            (Stage::AwaitingAuthorization, AuthorizationInput::AuthorizationRedirect(redirect)) => {
                self.accept_authorization_redirect(redirect, environment.random)
            }
            (
                Stage::AwaitingTokenResponse {
                    request_id,
                    authorization_code,
                    nonce_retry_count,
                },
                AuthorizationInput::TokenResponse(response),
            ) => self.accept_token_response(
                request_id,
                authorization_code,
                nonce_retry_count,
                response,
                environment,
            ),
            _ => Err(AuthorizationError::UnexpectedInput),
        }
    }

    fn client_auth_stage(
        &mut self,
        purpose: EndpointPurpose,
        authorization_code: Option<SecretString>,
        nonce_retry_count: u8,
        random: &dyn Random,
    ) -> Result<(Stage, AuthorizationEffect), AuthorizationError> {
        let request_id = CorrelationId(fresh_random(random, &mut self.context.used_random_values)?);
        let endpoint = self.endpoint(purpose).to_owned();
        let request = WalletClientAuthenticationRequest {
            request_id,
            purpose,
            client_id: self.context.client_id.clone(),
            audience: self.context.authorization_server.as_str().to_owned(),
            endpoint,
        };
        Ok((
            Stage::AwaitingClientAuthentication {
                purpose,
                request_id,
                authorization_code,
                nonce_retry_count,
            },
            AuthorizationEffect::AcquireWalletClientAuthentication(request),
        ))
    }

    fn endpoint(&self, purpose: EndpointPurpose) -> &str {
        match purpose {
            EndpointPurpose::Par => self.context.par_endpoint.as_str(),
            EndpointPurpose::Token => self.context.token_endpoint.as_str(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn accept_client_authentication(
        &mut self,
        purpose: EndpointPurpose,
        request_id: CorrelationId,
        authorization_code: Option<SecretString>,
        nonce_retry_count: u8,
        client_auth: WalletClientAuthentication,
        environment: &AuthorizationEnvironment<'_>,
    ) -> Result<(Stage, Vec<AuthorizationEffect>), AuthorizationError> {
        if !ct_eq(&request_id.0, &client_auth.request_id.0) {
            return Err(AuthorizationError::CorrelationMismatch);
        }
        if client_auth.purpose != purpose
            || client_auth.client_id != self.context.client_id
            || client_auth.audience != self.context.authorization_server.as_str()
            || client_auth.endpoint != self.endpoint(purpose)
        {
            return Err(AuthorizationError::ClientAuthenticationBindingMismatch);
        }
        validate_compact_jwt(
            client_auth.attestation.expose(),
            MAX_WALLET_ATTESTATION_BYTES,
        )?;
        validate_compact_jwt(
            client_auth.proof_of_possession.expose(),
            MAX_WALLET_ATTESTATION_POP_BYTES,
        )?;
        let pop_hash = environment
            .digest
            .sha256(client_auth.proof_of_possession.expose().as_bytes());
        if self
            .context
            .used_client_auth_pop_hashes
            .iter()
            .any(|seen| ct_eq(seen, &pop_hash))
        {
            return Err(AuthorizationError::ClientAuthenticationReused);
        }
        self.context.used_client_auth_pop_hashes.push(pop_hash);

        match purpose {
            EndpointPurpose::Par => {
                if authorization_code.is_some() || nonce_retry_count != 0 {
                    return Err(AuthorizationError::UnexpectedInput);
                }
                let request_id = CorrelationId(fresh_random(
                    environment.random,
                    &mut self.context.used_random_values,
                )?);
                let request = self.build_par_request(request_id, client_auth)?;
                Ok((
                    Stage::AwaitingParResponse { request_id },
                    vec![AuthorizationEffect::SendPar(request)],
                ))
            }
            EndpointPurpose::Token => {
                let authorization_code =
                    authorization_code.ok_or(AuthorizationError::UnexpectedInput)?;
                let request_id = CorrelationId(fresh_random(
                    environment.random,
                    &mut self.context.used_random_values,
                )?);
                let jti = base64url(&fresh_random(
                    environment.random,
                    &mut self.context.used_random_values,
                )?);
                let signing_input = self.build_dpop_signing_input(
                    &jti,
                    environment.now_epoch_seconds,
                    self.context.token_endpoint_nonce.as_ref(),
                )?;
                let effect = DpopSigningRequest {
                    request_id,
                    key_ref: self.context.dpop_key.key_ref.clone(),
                    signing_input: SecretBytes::new(signing_input.expose().to_vec()),
                };
                Ok((
                    Stage::SigningDpop {
                        request_id,
                        signing_input,
                        client_auth,
                        authorization_code,
                        nonce_retry_count,
                    },
                    vec![AuthorizationEffect::SignDpop(effect)],
                ))
            }
        }
    }

    fn build_par_request(
        &self,
        request_id: CorrelationId,
        client_auth: WalletClientAuthentication,
    ) -> Result<ParRequest, AuthorizationError> {
        let mut fields = vec![
            ("response_type", "code"),
            ("client_id", self.context.client_id.as_str()),
            ("redirect_uri", self.context.redirect_uri.as_str()),
            ("scope", self.context.scope.as_str()),
            ("resource", self.context.credential_issuer.as_str()),
            ("state", self.context.state.expose()),
            ("code_challenge", self.context.pkce_challenge.as_str()),
            ("code_challenge_method", "S256"),
            ("dpop_jkt", self.context.dpop_jkt.as_str()),
        ];
        if let Some(issuer_state) = &self.context.issuer_state {
            fields.push(("issuer_state", issuer_state.expose()));
        }
        let body = encode_form(&fields)?;
        Ok(ParRequest {
            request_id,
            endpoint: self.context.par_endpoint.as_str().to_owned(),
            body: SecretBytes::new(body),
            client_attestation: client_auth.attestation,
            client_attestation_pop: client_auth.proof_of_possession,
        })
    }

    fn build_dpop_signing_input(
        &self,
        jti: &str,
        iat: i64,
        nonce: Option<&SecretString>,
    ) -> Result<SecretBytes, AuthorizationError> {
        let header = format!(
            "{{\"alg\":\"ES256\",\"jwk\":{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}},\"typ\":\"dpop+jwt\"}}",
            self.context.dpop_key.public_jwk.x, self.context.dpop_key.public_jwk.y
        );
        let htu = dpop_htu(self.context.token_endpoint.as_str());
        let payload = match nonce {
            Some(nonce) => serde_json::json!({
                "htm": "POST",
                "htu": htu,
                "iat": iat,
                "jti": jti,
                "nonce": nonce.expose(),
            }),
            None => serde_json::json!({
                "htm": "POST",
                "htu": htu,
                "iat": iat,
                "jti": jti,
            }),
        };
        let payload =
            serde_json::to_vec(&payload).map_err(|_| AuthorizationError::InvalidConfiguration)?;
        let signing_input = format!("{}.{}", base64url(header.as_bytes()), base64url(&payload));
        if signing_input.len() > MAX_DPOP_SIGNING_INPUT_BYTES {
            return Err(AuthorizationError::InvalidConfiguration);
        }
        Ok(SecretBytes::new(signing_input.into_bytes()))
    }

    #[allow(clippy::too_many_arguments)]
    fn accept_dpop_signature(
        &mut self,
        request_id: CorrelationId,
        signing_input: SecretBytes,
        client_auth: WalletClientAuthentication,
        authorization_code: SecretString,
        nonce_retry_count: u8,
        signature: DpopSignature,
        random: &dyn Random,
    ) -> Result<(Stage, Vec<AuthorizationEffect>), AuthorizationError> {
        if !ct_eq(&request_id.0, &signature.request_id.0)
            || !ct_eq(signing_input.expose(), signature.signing_input.expose())
        {
            return Err(AuthorizationError::DpopSigningResultMismatch);
        }
        if signature.signature.expose().len() != 64 {
            return Err(AuthorizationError::DpopSignatureInvalid);
        }
        let mut proof = signing_input.expose().to_vec();
        proof.push(b'.');
        proof.extend_from_slice(base64url(signature.signature.expose()).as_bytes());
        let proof =
            String::from_utf8(proof).map_err(|_| AuthorizationError::DpopSignatureInvalid)?;
        let request_id = CorrelationId(fresh_random(random, &mut self.context.used_random_values)?);
        let request = self.build_token_request(
            request_id,
            &authorization_code,
            client_auth,
            SecretString::from_string(proof),
        )?;
        Ok((
            Stage::AwaitingTokenResponse {
                request_id,
                authorization_code,
                nonce_retry_count,
            },
            vec![AuthorizationEffect::SendToken(request)],
        ))
    }

    fn build_token_request(
        &self,
        request_id: CorrelationId,
        authorization_code: &SecretString,
        client_auth: WalletClientAuthentication,
        dpop_proof: SecretString,
    ) -> Result<TokenRequest, AuthorizationError> {
        let fields = [
            ("grant_type", "authorization_code"),
            ("code", authorization_code.expose()),
            ("redirect_uri", self.context.redirect_uri.as_str()),
            ("code_verifier", self.context.pkce_verifier.expose()),
        ];
        Ok(TokenRequest {
            request_id,
            endpoint: self.context.token_endpoint.as_str().to_owned(),
            body: SecretBytes::new(encode_form(&fields)?),
            client_attestation: client_auth.attestation,
            client_attestation_pop: client_auth.proof_of_possession,
            dpop_proof,
        })
    }

    fn accept_par_response(
        &mut self,
        request_id: CorrelationId,
        response: EndpointResponse,
        now_epoch_seconds: i64,
    ) -> Result<(Stage, Vec<AuthorizationEffect>), AuthorizationError> {
        validate_transport_binding(
            request_id,
            self.context.par_endpoint.as_str(),
            "POST",
            &response,
        )?;
        validate_json_transport(&response)?;
        let nonce = parse_single_dpop_nonce(&response.dpop_nonce_headers)?;
        if response.status != 201 {
            parse_oauth_error(response.body.expose(), PAR_JSON_LIMITS)
                .map_err(|_| AuthorizationError::InvalidParResponse)?;
            return Err(AuthorizationError::ParRejected);
        }
        if !cache_control_has(&response.cache_control_headers, "no-store")?
            || !cache_control_has(&response.cache_control_headers, "no-cache")?
        {
            return Err(AuthorizationError::CachePolicyMissing);
        }
        let par = parse_par_response(response.body.expose())?;
        if let Some(nonce) = nonce {
            self.rotate_token_endpoint_nonce(nonce)?;
        }
        let authorization_url = build_authorization_url(
            self.context.authorization_endpoint.as_str(),
            &self.context.client_id,
            &par.request_uri,
        );
        let request_uri_expires_at_epoch_seconds = now_epoch_seconds
            .checked_add(i64::from(par.expires_in))
            .ok_or(AuthorizationError::InvalidParResponse)?;
        Ok((
            Stage::AwaitingAuthorization,
            vec![AuthorizationEffect::OpenAuthorization(
                AuthorizationRequest {
                    url: authorization_url,
                    request_uri_expires_at_epoch_seconds,
                },
            )],
        ))
    }

    fn accept_authorization_redirect(
        &mut self,
        redirect: AuthorizationRedirect,
        random: &dyn Random,
    ) -> Result<(Stage, Vec<AuthorizationEffect>), AuthorizationError> {
        if redirect.redirect_uri != self.context.redirect_uri.as_str() {
            return Err(AuthorizationError::RedirectMismatch);
        }
        let callback = parse_authorization_callback(redirect.query.expose())?;
        if !ct_eq(
            callback.state.as_bytes(),
            self.context.state.expose().as_bytes(),
        ) {
            return Err(AuthorizationError::StateMismatch);
        }
        if callback.issuer != self.context.authorization_server.as_str() {
            return Err(AuthorizationError::AuthorizationIssuerMismatch);
        }
        let authorization_code = match callback.result {
            CallbackResult::Code(code) => SecretString::from_string(code),
            CallbackResult::Error => return Err(AuthorizationError::AuthorizationDenied),
        };
        let (stage, effect) =
            self.client_auth_stage(EndpointPurpose::Token, Some(authorization_code), 0, random)?;
        Ok((stage, vec![effect]))
    }

    fn accept_token_response(
        &mut self,
        request_id: CorrelationId,
        authorization_code: SecretString,
        nonce_retry_count: u8,
        response: EndpointResponse,
        environment: &AuthorizationEnvironment<'_>,
    ) -> Result<(Stage, Vec<AuthorizationEffect>), AuthorizationError> {
        validate_transport_binding(
            request_id,
            self.context.token_endpoint.as_str(),
            "POST",
            &response,
        )?;
        validate_json_transport(&response)?;
        let nonce = parse_single_dpop_nonce(&response.dpop_nonce_headers)?;
        if response.status == 400 {
            let error = parse_oauth_error(response.body.expose(), TOKEN_JSON_LIMITS)
                .map_err(|_| AuthorizationError::InvalidTokenResponse)?;
            if error == OAuthError::UseDpopNonce {
                let nonce = nonce.ok_or(AuthorizationError::DpopNonceInvalid)?;
                if nonce_retry_count >= MAX_DPOP_NONCE_RETRIES {
                    return Err(AuthorizationError::DpopNonceRetryLimit);
                }
                self.rotate_token_endpoint_nonce(nonce)?;
                let (stage, effect) = self.client_auth_stage(
                    EndpointPurpose::Token,
                    Some(authorization_code),
                    nonce_retry_count + 1,
                    environment.random,
                )?;
                return Ok((stage, vec![effect]));
            }
            return Err(AuthorizationError::TokenRejected);
        }
        if response.status != 200 {
            return Err(AuthorizationError::TokenRejected);
        }
        if !cache_control_has(&response.cache_control_headers, "no-store")?
            || !pragma_has_no_cache(&response.pragma_headers)?
        {
            return Err(AuthorizationError::CachePolicyMissing);
        }
        if let Some(nonce) = nonce {
            self.rotate_token_endpoint_nonce(nonce)?;
        }
        let parsed = parse_access_token_response(
            response.body.expose(),
            &self.context.scope,
            &self.context.configuration_id,
            self.context.credential_issuer.as_str(),
        )?;
        let grant = AccessTokenGrant {
            access_token: parsed.access_token,
            issued_at_epoch_seconds: environment.now_epoch_seconds,
            expires_in_seconds: parsed.expires_in_seconds,
            credential_identifiers: parsed.credential_identifiers,
            token_endpoint_dpop_nonce: self
                .context
                .token_endpoint_nonce
                .as_ref()
                .map(SecretString::duplicate),
            authorization_server: self.context.authorization_server.clone(),
            token_endpoint: self.context.token_endpoint.clone(),
            credential_issuer: self.context.credential_issuer.clone(),
            configuration_id: self.context.configuration_id.clone(),
            credential_endpoint: self.context.credential_endpoint.clone(),
            nonce_endpoint: self.context.nonce_endpoint.clone(),
            dpop_key: self.context.dpop_key.duplicate(),
        };
        Ok((Stage::Complete(grant), Vec::new()))
    }

    fn rotate_token_endpoint_nonce(
        &mut self,
        nonce: SecretString,
    ) -> Result<(), AuthorizationError> {
        if self
            .context
            .retired_token_endpoint_nonces
            .iter()
            .any(|value| ct_eq(value.expose().as_bytes(), nonce.expose().as_bytes()))
        {
            return Err(AuthorizationError::DpopNonceStale);
        }
        if self
            .context
            .token_endpoint_nonce
            .as_ref()
            .is_some_and(|current| ct_eq(current.expose().as_bytes(), nonce.expose().as_bytes()))
        {
            return Err(AuthorizationError::DpopNonceStale);
        }
        if let Some(previous) = self.context.token_endpoint_nonce.replace(nonce) {
            self.context.retired_token_endpoint_nonces.push(previous);
        }
        Ok(())
    }
}

struct ParResponse {
    request_uri: String,
    #[allow(dead_code)]
    expires_in: u16,
}

fn parse_par_response(input: &[u8]) -> Result<ParResponse, AuthorizationError> {
    let mut object = bounded_json::parse_object(input, PAR_JSON_LIMITS)
        .map_err(|_| AuthorizationError::InvalidParResponse)?;
    if object.contains_key("error") {
        return Err(AuthorizationError::InvalidParResponse);
    }
    let request_uri = take_required_string(&mut object, "request_uri", MAX_REQUEST_URI_BYTES)
        .map_err(|_| AuthorizationError::InvalidParResponse)?;
    if !valid_uri_reference(&request_uri) {
        return Err(AuthorizationError::InvalidParResponse);
    }
    let expires_in = object
        .remove("expires_in")
        .and_then(|value| value.as_u64())
        .filter(|value| (1..=MAX_PAR_EXPIRES_IN_SECONDS).contains(value))
        .ok_or(AuthorizationError::InvalidParResponse)? as u16;
    Ok(ParResponse {
        request_uri,
        expires_in,
    })
}

enum CallbackResult {
    Code(String),
    Error,
}

struct AuthorizationCallback {
    state: String,
    issuer: String,
    result: CallbackResult,
}

fn parse_authorization_callback(input: &[u8]) -> Result<AuthorizationCallback, AuthorizationError> {
    let mut fields = parse_form(input, MAX_CALLBACK_QUERY_BYTES, 16, 8 * 1024)?;
    let state = fields
        .remove("state")
        .filter(|value| value.len() == STATE_CHARS && is_base64url_unpadded(value.as_bytes()))
        .ok_or(AuthorizationError::InvalidAuthorizationCallback)?;
    let issuer = fields
        .remove("iss")
        .filter(|value| valid_bounded_text(value, 2_048, false))
        .ok_or(AuthorizationError::InvalidAuthorizationCallback)?;
    let code = fields.remove("code");
    let error = fields.remove("error");
    let result = match (code, error) {
        (Some(code), None)
            if valid_bounded_text(&code, MAX_AUTHORIZATION_CODE_BYTES, false)
                && code.bytes().all(is_nqchar) =>
        {
            if fields.contains_key("error_description") || fields.contains_key("error_uri") {
                return Err(AuthorizationError::InvalidAuthorizationCallback);
            }
            CallbackResult::Code(code)
        }
        (None, Some(error)) if valid_oauth_error_code(&error) => CallbackResult::Error,
        _ => return Err(AuthorizationError::InvalidAuthorizationCallback),
    };
    Ok(AuthorizationCallback {
        state,
        issuer,
        result,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OAuthError {
    UseDpopNonce,
    Other,
}

fn parse_oauth_error(input: &[u8], limits: JsonLimits) -> Result<OAuthError, JsonBoundaryError> {
    let object = bounded_json::parse_object(input, limits)?;
    let error = object
        .get("error")
        .and_then(Value::as_str)
        .filter(|value| valid_oauth_error_code(value))
        .ok_or(JsonBoundaryError::InvalidJson)?;
    if object.contains_key("access_token") || object.contains_key("request_uri") {
        return Err(JsonBoundaryError::InvalidJson);
    }
    Ok(if error == "use_dpop_nonce" {
        OAuthError::UseDpopNonce
    } else {
        OAuthError::Other
    })
}

struct ParsedAccessTokenGrant {
    access_token: SecretString,
    expires_in_seconds: Option<u32>,
    credential_identifiers: Vec<SecretString>,
}

fn parse_access_token_response(
    input: &[u8],
    expected_scope: &str,
    expected_configuration_id: &str,
    expected_credential_issuer: &str,
) -> Result<ParsedAccessTokenGrant, AuthorizationError> {
    let mut object = bounded_json::parse_object(input, TOKEN_JSON_LIMITS)
        .map_err(|_| AuthorizationError::InvalidTokenResponse)?;
    if object.contains_key("error") {
        return Err(AuthorizationError::InvalidTokenResponse);
    }
    let access_token = take_required_string(&mut object, "access_token", MAX_ACCESS_TOKEN_BYTES)
        .map_err(|_| AuthorizationError::InvalidTokenResponse)?;
    if !valid_token_value(&access_token) {
        return Err(AuthorizationError::InvalidTokenResponse);
    }
    let token_type = take_required_string(&mut object, "token_type", 16)
        .map_err(|_| AuthorizationError::InvalidTokenResponse)?;
    if token_type != "DPoP" {
        return Err(AuthorizationError::TokenTypeDowngrade);
    }
    let expires_in_seconds = match object.remove("expires_in") {
        Some(value) => Some(
            value
                .as_u64()
                .filter(|value| *value > 0 && *value <= u32::MAX.into())
                .ok_or(AuthorizationError::InvalidTokenResponse)? as u32,
        ),
        None => None,
    };
    // Refresh/reissuance is not implemented in this first-enrolment slice. Retaining a refresh
    // token without a complete rotation/revocation lifecycle would create a dormant bearer secret.
    if object.contains_key("refresh_token") {
        return Err(AuthorizationError::InvalidTokenResponse);
    }
    match object.remove("scope") {
        Some(Value::String(scope)) if scope == expected_scope => {}
        Some(_) => return Err(AuthorizationError::InvalidTokenResponse),
        None => {}
    }
    let credential_identifiers = parse_credential_identifiers(
        object.remove("authorization_details"),
        expected_configuration_id,
        expected_credential_issuer,
    )?;
    // OpenID4VCI 1.0 Final obtains c_nonce from the separate Nonce Endpoint. Any bounded unknown
    // token-response member (including legacy c_nonce deployments) is ignored as required by the
    // final specification and is never promoted into credential-proof state here.
    Ok(ParsedAccessTokenGrant {
        access_token: SecretString::from_string(access_token),
        expires_in_seconds,
        credential_identifiers,
    })
}

fn parse_credential_identifiers(
    authorization_details: Option<Value>,
    expected_configuration_id: &str,
    expected_credential_issuer: &str,
) -> Result<Vec<SecretString>, AuthorizationError> {
    let Some(Value::Array(details)) = authorization_details else {
        return if authorization_details.is_none() {
            Ok(Vec::new())
        } else {
            Err(AuthorizationError::InvalidTokenResponse)
        };
    };
    if details.is_empty() || details.len() > MAX_CREDENTIAL_IDENTIFIERS {
        return Err(AuthorizationError::InvalidTokenResponse);
    }

    let mut result = None;
    for detail in details {
        let detail = detail
            .as_object()
            .ok_or(AuthorizationError::InvalidTokenResponse)?;
        let detail_type = detail
            .get("type")
            .and_then(Value::as_str)
            .filter(|value| valid_bounded_text(value, 128, false))
            .ok_or(AuthorizationError::InvalidTokenResponse)?;
        if detail_type != "openid_credential" {
            continue;
        }
        if result.is_some()
            || detail
                .get("credential_configuration_id")
                .and_then(Value::as_str)
                != Some(expected_configuration_id)
        {
            return Err(AuthorizationError::InvalidTokenResponse);
        }
        if let Some(locations) = detail.get("locations") {
            let locations = locations
                .as_array()
                .filter(|values| values.len() == 1)
                .ok_or(AuthorizationError::InvalidTokenResponse)?;
            if locations[0].as_str() != Some(expected_credential_issuer) {
                return Err(AuthorizationError::InvalidTokenResponse);
            }
        }
        let identifiers = detail
            .get("credential_identifiers")
            .and_then(Value::as_array)
            .filter(|values| !values.is_empty() && values.len() <= MAX_CREDENTIAL_IDENTIFIERS)
            .ok_or(AuthorizationError::InvalidTokenResponse)?;
        let mut parsed = Vec::with_capacity(identifiers.len());
        for identifier in identifiers {
            let identifier = identifier
                .as_str()
                .filter(|value| valid_bounded_text(value, MAX_CREDENTIAL_IDENTIFIER_BYTES, false))
                .ok_or(AuthorizationError::InvalidTokenResponse)?;
            if parsed
                .iter()
                .any(|seen: &SecretString| ct_eq(seen.expose().as_bytes(), identifier.as_bytes()))
            {
                return Err(AuthorizationError::InvalidTokenResponse);
            }
            parsed.push(SecretString::from_str(identifier));
        }
        result = Some(parsed);
    }
    result.ok_or(AuthorizationError::InvalidTokenResponse)
}

fn take_required_string(
    object: &mut Map<String, Value>,
    field: &'static str,
    max: usize,
) -> Result<String, AuthorizationError> {
    match object.remove(field) {
        Some(Value::String(value)) if valid_bounded_text(&value, max, false) => Ok(value),
        _ => Err(AuthorizationError::InvalidTokenResponse),
    }
}

fn validate_transport_binding(
    expected: CorrelationId,
    expected_endpoint: &str,
    expected_method: &str,
    response: &EndpointResponse,
) -> Result<(), AuthorizationError> {
    if ct_eq(&expected.0, &response.request_id.0)
        && response.endpoint == expected_endpoint
        && response.method == expected_method
    {
        Ok(())
    } else {
        Err(AuthorizationError::TransportBindingMismatch)
    }
}

fn validate_json_transport(response: &EndpointResponse) -> Result<(), AuthorizationError> {
    if valid_json_content_type(&response.content_type) {
        Ok(())
    } else {
        Err(AuthorizationError::InvalidMediaType)
    }
}

fn valid_json_content_type(value: &str) -> bool {
    if value.is_empty()
        || value.len() > 128
        || !value.is_ascii()
        || value.chars().any(char::is_control)
    {
        return false;
    }
    let mut parts = value.split(';');
    if !parts
        .next()
        .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("application/json"))
    {
        return false;
    }
    let mut saw_charset = false;
    for parameter in parts {
        let Some((name, parameter_value)) = parameter.trim().split_once('=') else {
            return false;
        };
        if saw_charset || !name.trim().eq_ignore_ascii_case("charset") {
            return false;
        }
        let parameter_value = parameter_value.trim();
        if !parameter_value.eq_ignore_ascii_case("utf-8")
            && !parameter_value.eq_ignore_ascii_case("\"utf-8\"")
        {
            return false;
        }
        saw_charset = true;
    }
    true
}

fn cache_control_has(
    header_values: &[String],
    required_directive: &str,
) -> Result<bool, AuthorizationError> {
    validate_raw_header_values(header_values)?;
    Ok(header_values.iter().any(|value| {
        value
            .split(',')
            .map(str::trim)
            .any(|directive| directive.eq_ignore_ascii_case(required_directive))
    }))
}

fn pragma_has_no_cache(header_values: &[String]) -> Result<bool, AuthorizationError> {
    validate_raw_header_values(header_values)?;
    Ok(header_values.iter().any(|value| {
        value
            .split(',')
            .map(str::trim)
            .any(|directive| directive.eq_ignore_ascii_case("no-cache"))
    }))
}

fn validate_raw_header_values(values: &[String]) -> Result<(), AuthorizationError> {
    if values.is_empty()
        || values.len() > 8
        || values.iter().any(|value| {
            value.is_empty()
                || value.len() > 1_024
                || !value.is_ascii()
                || value
                    .bytes()
                    .any(|byte| byte != b'\t' && !(0x20..=0x7e).contains(&byte))
        })
    {
        return Err(AuthorizationError::CachePolicyMissing);
    }
    Ok(())
}

fn parse_single_dpop_nonce(values: &[String]) -> Result<Option<SecretString>, AuthorizationError> {
    match values {
        [] => Ok(None),
        [value]
            if !value.is_empty()
                && value.len() <= MAX_DPOP_NONCE_BYTES
                && value.bytes().all(is_nqchar) =>
        {
            Ok(Some(SecretString::from_str(value)))
        }
        _ => Err(AuthorizationError::DpopNonceInvalid),
    }
}

fn build_authorization_url(endpoint: &str, client_id: &str, request_uri: &str) -> String {
    let separator = if endpoint.contains('?') { '&' } else { '?' };
    format!(
        "{endpoint}{separator}client_id={}&request_uri={}",
        percent_encode(client_id),
        percent_encode(request_uri)
    )
}

fn encode_form(fields: &[(&str, &str)]) -> Result<Vec<u8>, AuthorizationError> {
    if fields.is_empty() || fields.len() > 16 {
        return Err(AuthorizationError::InvalidConfiguration);
    }
    let mut output = Vec::new();
    for (index, (name, value)) in fields.iter().enumerate() {
        if index != 0 {
            output.push(b'&');
        }
        append_percent_encoded(&mut output, name);
        output.push(b'=');
        append_percent_encoded(&mut output, value);
    }
    if output.len() > 64 * 1024 {
        return Err(AuthorizationError::InvalidConfiguration);
    }
    Ok(output)
}

fn append_percent_encoded(output: &mut Vec<u8>, value: &str) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in value.bytes() {
        if is_unreserved(byte) {
            output.push(byte);
        } else {
            output.push(b'%');
            output.push(HEX[(byte >> 4) as usize]);
            output.push(HEX[(byte & 0x0f) as usize]);
        }
    }
}

fn percent_encode(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut output = String::with_capacity(value.len());
    for byte in value.bytes() {
        if is_unreserved(byte) {
            output.push(char::from(byte));
        } else {
            output.push('%');
            output.push(char::from(HEX[(byte >> 4) as usize]));
            output.push(char::from(HEX[(byte & 0x0f) as usize]));
        }
    }
    output
}

fn parse_form(
    input: &[u8],
    max_bytes: usize,
    max_fields: usize,
    max_value_bytes: usize,
) -> Result<BTreeMap<String, String>, AuthorizationError> {
    if input.is_empty() || input.len() > max_bytes {
        return Err(AuthorizationError::InvalidAuthorizationCallback);
    }
    let mut result = BTreeMap::new();
    for pair in input.split(|byte| *byte == b'&') {
        if pair.is_empty() || result.len() >= max_fields {
            return Err(AuthorizationError::InvalidAuthorizationCallback);
        }
        let separator = pair
            .iter()
            .position(|byte| *byte == b'=')
            .ok_or(AuthorizationError::InvalidAuthorizationCallback)?;
        let (name, value_with_separator) = pair.split_at(separator);
        let value = &value_with_separator[1..];
        let name = percent_decode(name, 128)?;
        let value = percent_decode(value, max_value_bytes)?;
        if name.is_empty()
            || !name.is_ascii()
            || name.chars().any(char::is_control)
            || result.insert(name, value).is_some()
        {
            return Err(AuthorizationError::InvalidAuthorizationCallback);
        }
    }
    Ok(result)
}

fn percent_decode(input: &[u8], max: usize) -> Result<String, AuthorizationError> {
    let mut output = Vec::with_capacity(input.len().min(max));
    let mut index = 0;
    while index < input.len() {
        if output.len() >= max {
            return Err(AuthorizationError::InvalidAuthorizationCallback);
        }
        match input[index] {
            b'+' => {
                output.push(b' ');
                index += 1;
            }
            b'%' => {
                let high = input
                    .get(index + 1)
                    .and_then(|value| from_hex(*value))
                    .ok_or(AuthorizationError::InvalidAuthorizationCallback)?;
                let low = input
                    .get(index + 2)
                    .and_then(|value| from_hex(*value))
                    .ok_or(AuthorizationError::InvalidAuthorizationCallback)?;
                output.push((high << 4) | low);
                index += 3;
            }
            byte => {
                output.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(output).map_err(|_| AuthorizationError::InvalidAuthorizationCallback)
}

fn from_hex(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn validate_compact_jwt(value: &str, max: usize) -> Result<(), AuthorizationError> {
    if value.is_empty() || value.len() > max {
        return Err(AuthorizationError::ClientAuthenticationInvalid);
    }
    let mut segments = value.split('.');
    for _ in 0..3 {
        let segment = segments
            .next()
            .filter(|segment| !segment.is_empty() && is_base64url_unpadded(segment.as_bytes()))
            .ok_or(AuthorizationError::ClientAuthenticationInvalid)?;
        if segment.len() > max {
            return Err(AuthorizationError::ClientAuthenticationInvalid);
        }
        let decoded = Base64UrlUnpadded::decode_vec(segment)
            .map_err(|_| AuthorizationError::ClientAuthenticationInvalid)?;
        if decoded.is_empty() || Base64UrlUnpadded::encode_string(&decoded) != segment {
            return Err(AuthorizationError::ClientAuthenticationInvalid);
        }
    }
    if segments.next().is_some() {
        return Err(AuthorizationError::ClientAuthenticationInvalid);
    }
    Ok(())
}

fn valid_uri_reference(value: &str) -> bool {
    if !valid_bounded_text(value, MAX_REQUEST_URI_BYTES, false)
        || !value.is_ascii()
        || value.contains('#')
        || value.bytes().any(|byte| byte == b' ' || byte == b'\\')
    {
        return false;
    }
    let Some((scheme, remainder)) = value.split_once(':') else {
        return false;
    };
    if remainder.is_empty()
        || !scheme
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic())
    {
        return false;
    }
    if !scheme
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
    {
        return false;
    }
    let bytes = remainder.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if bytes
                .get(index + 1)
                .and_then(|value| from_hex(*value))
                .is_none()
                || bytes
                    .get(index + 2)
                    .and_then(|value| from_hex(*value))
                    .is_none()
            {
                return false;
            }
            index += 3;
            continue;
        }
        if !is_uri_character(bytes[index]) {
            return false;
        }
        index += 1;
    }
    true
}

fn is_uri_character(byte: u8) -> bool {
    is_unreserved(byte)
        || matches!(
            byte,
            b':' | b'/'
                | b'?'
                | b'@'
                | b'!'
                | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
        )
}

fn valid_scope(value: &str) -> bool {
    valid_bounded_text(value, 512, false)
        && value
            .bytes()
            .all(|byte| matches!(byte, 0x21 | 0x23..=0x5b | 0x5d..=0x7e))
}

fn valid_token_value(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(is_nqchar)
}

fn valid_oauth_error_code(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| matches!(byte, 0x20..=0x21 | 0x23..=0x5b | 0x5d..=0x7e))
}

fn valid_bounded_text(value: &str, max: usize, allow_empty: bool) -> bool {
    (allow_empty || !value.is_empty()) && value.len() <= max && !value.chars().any(char::is_control)
}

fn is_nqchar(byte: u8) -> bool {
    matches!(byte, 0x21..=0x7e)
}

fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

fn is_base64url_unpadded(value: &[u8]) -> bool {
    !value.is_empty()
        && value
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn dpop_htu(endpoint: &str) -> &str {
    endpoint.split_once('?').map_or(endpoint, |(base, _)| base)
}

fn validate_clock(now_epoch_seconds: i64) -> Result<(), AuthorizationError> {
    if now_epoch_seconds <= 0 {
        Err(AuthorizationError::InvalidClock)
    } else {
        Ok(())
    }
}

fn fresh_random(
    random: &dyn Random,
    used: &mut Vec<[u8; 32]>,
) -> Result<[u8; 32], AuthorizationError> {
    if used.len() >= 32 {
        return Err(AuthorizationError::RandomnessFailure);
    }
    let mut value = [0u8; 32];
    random.fill(&mut value);
    if value.iter().all(|byte| *byte == 0) || used.iter().any(|seen| ct_eq(seen, &value)) {
        value.fill(0);
        return Err(AuthorizationError::RandomnessFailure);
    }
    used.push(value);
    Ok(value)
}

fn ct_eq(left: &[u8], right: &[u8]) -> bool {
    let max = left.len().max(right.len());
    let mut difference = left.len() ^ right.len();
    for index in 0..max {
        let left = left.get(index).copied().unwrap_or(0);
        let right = right.get(index).copied().unwrap_or(0);
        difference |= usize::from(left ^ right);
    }
    difference == 0
}

fn base64url(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}
