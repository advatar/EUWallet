//! OpenID4VCI 1.0 Final Nonce and immediate Credential Endpoint transport for German PID.
//!
//! This is a sans-I/O continuation of [`crate::authorization`]. It consumes that machine's
//! DPoP-bound access-token grant, obtains `c_nonce` from the unprotected Nonce Endpoint, requests
//! a fresh key attestation for the exact holder key and nonce, builds both ES256 signing inputs in
//! Rust, and emits one DPoP-protected Credential request. Only one immediate, unencrypted PID
//! credential is admitted.
//!
//! A structurally valid key-attestation JWT is not treated as trusted here. The selected German
//! ecosystem/TS3 certificate and Wallet Provider trust profile is still unresolved. The mandatory
//! [`KeyAttestationRequest`] effect carries the exact binding and assurance requirements; its
//! result is structurally checked and passed to the PID Provider, which must validate its signature
//! and trust chain. Likewise, [`IssuedCredential`] is only transport/profile checked. Its exact raw
//! bytes must still cross the existing verified-ingestion boundary before durable storage.

use crate::authorization::{AccessTokenGrant, CorrelationId, Es256PublicJwk};
use crate::bounded_json::{self, JsonLimits};
use crate::foundation::{
    CredentialSigningAlgorithm, GermanPidFormat, GermanPidIssuancePlan, HolderBindingMethod,
    HttpsEndpoint, HttpsIdentifier, MDOC_PID_DOCTYPE, SD_JWT_PID_VCT,
};
use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use crypto_traits::{Alg, Digest, KeyRef, Random};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::fmt;

pub const MAX_C_NONCE_BYTES: usize = 2_048;
pub const MAX_DPOP_NONCE_BYTES: usize = 2_048;
pub const MAX_NONCE_RESPONSE_BYTES: usize = 16 * 1024;
pub const MAX_CREDENTIAL_RESPONSE_BYTES: usize = 256 * 1024;
pub const MAX_CREDENTIAL_BYTES: usize = 224 * 1024;
pub const MAX_KEY_ATTESTATION_BYTES: usize = 64 * 1024;
pub const MAX_KEY_ATTESTATION_SEGMENT_BYTES: usize = 32 * 1024;
pub const MAX_SIGNING_INPUT_BYTES: usize = 128 * 1024;
pub const MAX_CREDENTIAL_REQUEST_BYTES: usize = 160 * 1024;
pub const MAX_RESOURCE_DPOP_NONCE_RETRIES: u8 = 1;
const MAX_SD_JWT_COMPONENT_SEPARATORS: usize = 257;

const NONCE_JSON_LIMITS: JsonLimits = JsonLimits {
    max_bytes: MAX_NONCE_RESPONSE_BYTES,
    max_depth: 4,
    max_container_entries: 16,
    max_string_bytes: 8 * 1024,
};

const CREDENTIAL_JSON_LIMITS: JsonLimits = JsonLimits {
    max_bytes: MAX_CREDENTIAL_RESPONSE_BYTES,
    max_depth: 6,
    max_container_entries: 16,
    max_string_bytes: MAX_CREDENTIAL_BYTES,
};

const JWT_JSON_LIMITS: JsonLimits = JsonLimits {
    max_bytes: MAX_KEY_ATTESTATION_SEGMENT_BYTES,
    max_depth: 8,
    max_container_entries: 32,
    max_string_bytes: 16 * 1024,
};

/// Stable diagnostics. No variant includes attacker-controlled or secret material.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialError {
    InvalidConfiguration,
    PlanGrantMismatch,
    InvalidSelection,
    InvalidClock,
    TokenExpired,
    RandomnessFailure,
    UnexpectedInput,
    AlreadyTerminal,
    CorrelationMismatch,
    TransportBindingMismatch,
    InvalidStatus,
    InvalidMediaType,
    CachePolicyMissing,
    InvalidContentEncoding,
    InvalidNonceResponse,
    CNonceReplayed,
    DpopNonceInvalid,
    DpopNonceStale,
    DpopNonceRetryLimit,
    KeyAttestationBindingMismatch,
    KeyAttestationInvalid,
    CredentialProofSigningMismatch,
    CredentialProofSignatureInvalid,
    DpopSigningMismatch,
    DpopSignatureInvalid,
    CredentialRejected,
    DeferredIssuanceUnsupported,
    BatchIssuanceUnsupported,
    NotificationUnsupported,
    ReissuanceUnsupported,
    ResponseEncryptionUnsupported,
    InvalidCredentialResponse,
    CredentialFormatMismatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowStatus {
    AwaitingNonceResponse,
    AwaitingKeyAttestation,
    AwaitingCredentialProofSignature,
    AwaitingDpopSignature,
    AwaitingCredentialResponse,
    Complete,
    Failed,
}

/// Which final-spec selector the Credential request must use. Construction validates this against
/// the authorization grant: identifiers returned in `authorization_details` are mandatory when
/// present; otherwise the selected configuration ID is mandatory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CredentialSelection {
    ConfigurationId,
    CredentialIdentifier(String),
}

struct SecretBytes(Vec<u8>);

impl SecretBytes {
    fn new(value: Vec<u8>) -> Self {
        Self(value)
    }

    fn expose(&self) -> &[u8] {
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

struct SecretString(Vec<u8>);

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

    fn expose(&self) -> &str {
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

enum SelectedRequestTarget {
    ConfigurationId(String),
    CredentialIdentifier(SecretString),
}

/// The holder-binding key for the new Credential. It is intentionally distinct from the DPoP key
/// carried by [`AccessTokenGrant`]: callers can allocate a fresh WSCD key without coupling the
/// long-lived Credential identifier to OAuth sender-constraining traffic.
pub struct CredentialKeyBinding {
    key_ref: KeyRef,
    public_jwk: Es256PublicJwk,
}

impl CredentialKeyBinding {
    pub fn new(key_ref: KeyRef, public_jwk: Es256PublicJwk) -> Result<Self, CredentialError> {
        if !valid_bounded_text(&key_ref.0, 1_024) {
            return Err(CredentialError::InvalidConfiguration);
        }
        Ok(Self {
            key_ref,
            public_jwk,
        })
    }
}

impl fmt::Debug for CredentialKeyBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialKeyBinding")
            .field("key_ref", &"[REDACTED]")
            .field("public_jwk", &self.public_jwk)
            .finish()
    }
}

/// Checked handoff from the authorization transport and the exact selected German PID plan.
pub struct CredentialFlowConfig {
    access_token: SecretString,
    token_issued_at_epoch_seconds: i64,
    token_expires_in_seconds: Option<u32>,
    credential_issuer: HttpsIdentifier,
    configuration_id: String,
    format: GermanPidFormat,
    credential_endpoint: HttpsEndpoint,
    nonce_endpoint: HttpsEndpoint,
    request_target: SelectedRequestTarget,
    dpop_key_ref: KeyRef,
    dpop_public_jwk: Es256PublicJwk,
    credential_key_ref: KeyRef,
    credential_public_jwk: Es256PublicJwk,
}

impl fmt::Debug for CredentialFlowConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialFlowConfig")
            .field("access_token", &"[REDACTED]")
            .field(
                "token_issued_at_epoch_seconds",
                &self.token_issued_at_epoch_seconds,
            )
            .field("token_expires_in_seconds", &self.token_expires_in_seconds)
            .field("credential_issuer", &self.credential_issuer)
            .field("configuration_id", &self.configuration_id)
            .field("format", &self.format)
            .field("credential_endpoint", &self.credential_endpoint)
            .field("nonce_endpoint", &self.nonce_endpoint)
            .field("request_target", &"[REDACTED]")
            .field("dpop_key_ref", &"[REDACTED]")
            .field("dpop_public_jwk", &self.dpop_public_jwk)
            .field("credential_key_ref", &"[REDACTED]")
            .field("credential_public_jwk", &self.credential_public_jwk)
            .finish()
    }
}

impl CredentialFlowConfig {
    pub fn from_authorization(
        grant: AccessTokenGrant,
        plan: &GermanPidIssuancePlan,
        selection: CredentialSelection,
        credential_key: CredentialKeyBinding,
    ) -> Result<Self, CredentialError> {
        if grant.credential_issuer() != plan.credential_issuer.as_str()
            || grant.authorization_server() != plan.authorization_server.as_str()
            || grant.token_endpoint() != plan.token_endpoint.as_str()
            || grant.configuration_id() != plan.configuration_id
            || grant.credential_endpoint() != plan.credential_endpoint.as_str()
            || grant.nonce_endpoint() != plan.nonce_endpoint.as_str()
            || plan.proof_signing_algorithm != "ES256"
            || !valid_pid_plan(plan)
        {
            return Err(CredentialError::PlanGrantMismatch);
        }
        let authorized_identifiers: Vec<String> =
            grant.credential_identifiers().map(str::to_owned).collect();
        let request_target = match (authorized_identifiers.as_slice(), selection) {
            ([], CredentialSelection::ConfigurationId) => {
                SelectedRequestTarget::ConfigurationId(plan.configuration_id.clone())
            }
            ([], CredentialSelection::CredentialIdentifier(_))
            | ([_, ..], CredentialSelection::ConfigurationId) => {
                return Err(CredentialError::InvalidSelection);
            }
            (identifiers, CredentialSelection::CredentialIdentifier(identifier))
                if valid_bounded_text(&identifier, 2_048)
                    && identifiers
                        .iter()
                        .any(|allowed| ct_eq(allowed.as_bytes(), identifier.as_bytes())) =>
            {
                SelectedRequestTarget::CredentialIdentifier(SecretString::from_string(identifier))
            }
            _ => return Err(CredentialError::InvalidSelection),
        };
        Ok(Self {
            access_token: SecretString::from_str(grant.access_token()),
            token_issued_at_epoch_seconds: grant.issued_at_epoch_seconds(),
            token_expires_in_seconds: grant.expires_in_seconds(),
            credential_issuer: plan.credential_issuer.clone(),
            configuration_id: plan.configuration_id.clone(),
            format: plan.format,
            credential_endpoint: plan.credential_endpoint.clone(),
            nonce_endpoint: plan.nonce_endpoint.clone(),
            request_target,
            dpop_key_ref: grant.dpop_key_ref().clone(),
            dpop_public_jwk: grant.dpop_public_jwk().clone(),
            credential_key_ref: credential_key.key_ref,
            credential_public_jwk: credential_key.public_jwk,
        })
    }
}

fn valid_pid_plan(plan: &GermanPidIssuancePlan) -> bool {
    match plan.format {
        GermanPidFormat::MsoMdoc => {
            plan.holder_binding == HolderBindingMethod::CoseKey
                && plan.credential_signing_algorithm == CredentialSigningAlgorithm::CoseEs256
        }
        GermanPidFormat::DcSdJwt => {
            plan.holder_binding == HolderBindingMethod::Jwk
                && plan.credential_signing_algorithm == CredentialSigningAlgorithm::JoseEs256
        }
    }
}

pub struct NonceRequest {
    request_id: CorrelationId,
    endpoint: String,
}

impl NonceRequest {
    pub fn request_id(&self) -> CorrelationId {
        self.request_id
    }
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
    pub fn method(&self) -> &'static str {
        "POST"
    }
    pub fn body(&self) -> &[u8] {
        &[]
    }
    pub fn authorization(&self) -> Option<&str> {
        None
    }
    pub fn dpop_proof(&self) -> Option<&str> {
        None
    }
    pub fn accept(&self) -> &'static str {
        "application/json"
    }
    pub fn accept_encoding(&self) -> &'static str {
        "identity"
    }
}

impl fmt::Debug for NonceRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NonceRequest")
            .field("request_id", &self.request_id)
            .field("endpoint", &self.endpoint)
            .field("method", &"POST")
            .field("body", &"empty")
            .finish()
    }
}

/// Mandatory external acquisition request for an Appendix-D JWT key attestation. The external
/// provider must authenticate the platform evidence and sign with an ecosystem-trusted key; this
/// module only checks the returned JWT's bounded shape and exact public binding.
pub struct KeyAttestationRequest {
    request_id: CorrelationId,
    credential_issuer: String,
    credential_endpoint: String,
    key_ref: KeyRef,
    public_jwk: Es256PublicJwk,
    c_nonce: SecretString,
}

impl KeyAttestationRequest {
    pub fn request_id(&self) -> CorrelationId {
        self.request_id
    }
    pub fn credential_issuer(&self) -> &str {
        &self.credential_issuer
    }
    pub fn credential_endpoint(&self) -> &str {
        &self.credential_endpoint
    }
    pub fn method(&self) -> &'static str {
        "POST"
    }
    pub fn key_ref(&self) -> &KeyRef {
        &self.key_ref
    }
    pub fn public_jwk(&self) -> &Es256PublicJwk {
        &self.public_jwk
    }
    pub fn c_nonce(&self) -> &str {
        self.c_nonce.expose()
    }
    pub fn algorithm(&self) -> Alg {
        Alg::Es256
    }
    pub fn key_storage_requirement(&self) -> &'static str {
        "iso_18045_high"
    }
    pub fn user_authentication_requirement(&self) -> &'static str {
        "iso_18045_high"
    }
    pub fn jwt_type(&self) -> &'static str {
        "key-attestation+jwt"
    }
    pub fn require_x5c_without_trust_anchor(&self) -> bool {
        true
    }
}

impl fmt::Debug for KeyAttestationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KeyAttestationRequest")
            .field("request_id", &self.request_id)
            .field("credential_issuer", &self.credential_issuer)
            .field("credential_endpoint", &self.credential_endpoint)
            .field("key_ref", &"[REDACTED]")
            .field("public_jwk", &self.public_jwk)
            .field("c_nonce", &"[REDACTED]")
            .field("algorithm", &Alg::Es256)
            .field("key_storage", &"iso_18045_high")
            .field("user_authentication", &"iso_18045_high")
            .field("trust_profile", &"UNRESOLVED")
            .finish()
    }
}

pub struct KeyAttestation {
    request_id: CorrelationId,
    credential_issuer: String,
    credential_endpoint: String,
    key_ref: KeyRef,
    public_jwk: Es256PublicJwk,
    c_nonce: SecretString,
    jwt: SecretString,
}

impl KeyAttestation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request_id: CorrelationId,
        credential_issuer: &str,
        credential_endpoint: &str,
        key_ref: KeyRef,
        public_jwk: Es256PublicJwk,
        c_nonce: &str,
        jwt: &str,
    ) -> Self {
        Self {
            request_id,
            credential_issuer: credential_issuer.to_owned(),
            credential_endpoint: credential_endpoint.to_owned(),
            key_ref,
            public_jwk,
            c_nonce: SecretString::from_str(c_nonce),
            jwt: SecretString::from_str(jwt),
        }
    }
}

impl fmt::Debug for KeyAttestation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KeyAttestation([REDACTED])")
    }
}

pub struct SigningRequest {
    request_id: CorrelationId,
    key_ref: KeyRef,
    signing_input: SecretBytes,
}

impl SigningRequest {
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

impl fmt::Debug for SigningRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SigningRequest")
            .field("request_id", &self.request_id)
            .field("key_ref", &"[REDACTED]")
            .field("algorithm", &Alg::Es256)
            .field("signing_input", &"[REDACTED]")
            .finish()
    }
}

pub struct SignatureResult {
    request_id: CorrelationId,
    signing_input: SecretBytes,
    signature: SecretBytes,
}

impl SignatureResult {
    pub fn new(request_id: CorrelationId, signing_input: Vec<u8>, signature: Vec<u8>) -> Self {
        Self {
            request_id,
            signing_input: SecretBytes::new(signing_input),
            signature: SecretBytes::new(signature),
        }
    }
}

impl fmt::Debug for SignatureResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SignatureResult([REDACTED])")
    }
}

pub struct CredentialRequest {
    request_id: CorrelationId,
    endpoint: String,
    authorization: SecretString,
    dpop_proof: SecretString,
    body: SecretBytes,
}

impl CredentialRequest {
    pub fn request_id(&self) -> CorrelationId {
        self.request_id
    }
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
    pub fn method(&self) -> &'static str {
        "POST"
    }
    pub fn content_type(&self) -> &'static str {
        "application/json"
    }
    pub fn accept(&self) -> &'static str {
        "application/json"
    }
    pub fn accept_encoding(&self) -> &'static str {
        "identity"
    }
    pub fn authorization(&self) -> &str {
        self.authorization.expose()
    }
    pub fn dpop_proof(&self) -> &str {
        self.dpop_proof.expose()
    }
    pub fn body(&self) -> &[u8] {
        self.body.expose()
    }
}

impl fmt::Debug for CredentialRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialRequest")
            .field("request_id", &self.request_id)
            .field("endpoint", &self.endpoint)
            .field("method", &"POST")
            .field("content_type", &"application/json")
            .field("authorization", &"[REDACTED]")
            .field("dpop_proof", &"[REDACTED]")
            .field("body", &"[REDACTED]")
            .finish()
    }
}

pub enum CredentialEffect {
    SendNonce(NonceRequest),
    AcquireKeyAttestation(KeyAttestationRequest),
    SignCredentialProof(SigningRequest),
    SignDpop(SigningRequest),
    SendCredential(CredentialRequest),
}

impl fmt::Debug for CredentialEffect {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SendNonce(value) => value.fmt(formatter),
            Self::AcquireKeyAttestation(value) => value.fmt(formatter),
            Self::SignCredentialProof(value) | Self::SignDpop(value) => value.fmt(formatter),
            Self::SendCredential(value) => value.fmt(formatter),
        }
    }
}

/// Raw multi-value response headers are retained instead of being collapsed by a shell adapter.
pub struct EndpointResponse {
    request_id: CorrelationId,
    endpoint: String,
    method: String,
    status: u16,
    content_type_headers: Vec<String>,
    cache_control_headers: Vec<String>,
    pragma_headers: Vec<String>,
    content_encoding_headers: Vec<String>,
    dpop_nonce_headers: Vec<String>,
    www_authenticate_headers: Vec<String>,
    body: SecretBytes,
}

impl EndpointResponse {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request_id: CorrelationId,
        endpoint: &str,
        method: &str,
        status: u16,
        content_type_headers: Vec<String>,
        cache_control_headers: Vec<String>,
        pragma_headers: Vec<String>,
        content_encoding_headers: Vec<String>,
        dpop_nonce_headers: Vec<String>,
        www_authenticate_headers: Vec<String>,
        body: Vec<u8>,
    ) -> Self {
        Self {
            request_id,
            endpoint: endpoint.to_owned(),
            method: method.to_owned(),
            status,
            content_type_headers,
            cache_control_headers,
            pragma_headers,
            content_encoding_headers,
            dpop_nonce_headers,
            www_authenticate_headers,
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
            .field("headers", &"[REDACTED]")
            .field("body", &"[REDACTED]")
            .finish()
    }
}

pub enum CredentialInput {
    NonceResponse(EndpointResponse),
    KeyAttestation(KeyAttestation),
    CredentialProofSignature(SignatureResult),
    DpopSignature(SignatureResult),
    CredentialResponse(EndpointResponse),
}

impl fmt::Debug for CredentialInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NonceResponse(_) => "NonceResponse([REDACTED])",
            Self::KeyAttestation(_) => "KeyAttestation([REDACTED])",
            Self::CredentialProofSignature(_) => "CredentialProofSignature([REDACTED])",
            Self::DpopSignature(_) => "DpopSignature([REDACTED])",
            Self::CredentialResponse(_) => "CredentialResponse([REDACTED])",
        })
    }
}

/// Transport/profile-checked credential bytes. Signature, trust, status, validity and device-key
/// binding are deliberately still the responsibility of the verified-ingestion boundary.
pub struct IssuedCredential {
    format: GermanPidFormat,
    raw: Vec<u8>,
    c_nonce_hash: [u8; 32],
}

impl IssuedCredential {
    pub fn format(&self) -> GermanPidFormat {
        self.format
    }
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }
    pub fn c_nonce_hash(&self) -> &[u8; 32] {
        &self.c_nonce_hash
    }
    pub fn into_raw(mut self) -> Vec<u8> {
        core::mem::take(&mut self.raw)
    }
}

impl Drop for IssuedCredential {
    fn drop(&mut self) {
        self.raw.fill(0);
        self.c_nonce_hash.fill(0);
    }
}

impl fmt::Debug for IssuedCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuedCredential")
            .field("format", &self.format)
            .field("raw", &"[REDACTED]")
            .field("c_nonce_hash", &"[REDACTED]")
            .field("verified_ingestion", &"REQUIRED")
            .finish()
    }
}

pub struct CredentialEnvironment<'a> {
    pub random: &'a dyn Random,
    pub digest: &'a dyn Digest,
    pub now_epoch_seconds: i64,
    /// SHA-256 values of previously consumed `c_nonce` strings. The caller persists this replay
    /// state only after verified ingestion succeeds.
    pub seen_c_nonce_hashes: &'a [[u8; 32]],
}

struct Context {
    access_token: SecretString,
    token_issued_at_epoch_seconds: i64,
    token_expires_in_seconds: Option<u32>,
    credential_issuer: HttpsIdentifier,
    format: GermanPidFormat,
    credential_endpoint: HttpsEndpoint,
    nonce_endpoint: HttpsEndpoint,
    request_target: SelectedRequestTarget,
    dpop_key_ref: KeyRef,
    dpop_public_jwk: Es256PublicJwk,
    credential_key_ref: KeyRef,
    credential_public_jwk: Es256PublicJwk,
    credential_endpoint_nonce: Option<SecretString>,
    retired_credential_endpoint_nonces: Vec<SecretString>,
    used_random_values: Vec<[u8; 32]>,
    last_now_epoch_seconds: i64,
}

impl Drop for Context {
    fn drop(&mut self) {
        for value in &mut self.used_random_values {
            value.fill(0);
        }
    }
}

enum Stage {
    AwaitingNonceResponse {
        request_id: CorrelationId,
    },
    AwaitingKeyAttestation {
        request_id: CorrelationId,
        c_nonce: SecretString,
        c_nonce_hash: [u8; 32],
    },
    SigningCredentialProof {
        request_id: CorrelationId,
        c_nonce_hash: [u8; 32],
        signing_input: SecretBytes,
    },
    SigningDpop {
        request_id: CorrelationId,
        c_nonce_hash: [u8; 32],
        credential_proof: SecretString,
        signing_input: SecretBytes,
        nonce_retry_count: u8,
    },
    AwaitingCredentialResponse {
        request_id: CorrelationId,
        c_nonce_hash: [u8; 32],
        credential_proof: SecretString,
        nonce_retry_count: u8,
    },
    Complete(IssuedCredential),
    Failed(CredentialError),
}

pub struct CredentialFlow {
    context: Context,
    stage: Stage,
}

impl fmt::Debug for CredentialFlow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialFlow")
            .field("status", &self.status())
            .field("credential_issuer", &self.context.credential_issuer)
            .field("format", &self.context.format)
            .field("secrets", &"[REDACTED]")
            .finish()
    }
}

impl CredentialFlow {
    pub fn begin(
        config: CredentialFlowConfig,
        environment: &CredentialEnvironment<'_>,
    ) -> Result<(Self, CredentialEffect), CredentialError> {
        validate_clock(environment.now_epoch_seconds)?;
        validate_token_lifetime(
            config.token_issued_at_epoch_seconds,
            config.token_expires_in_seconds,
            environment.now_epoch_seconds,
        )?;
        let mut used_random_values = Vec::new();
        let request_id =
            CorrelationId::from_bytes(fresh_random(environment.random, &mut used_random_values)?);
        let nonce_request = NonceRequest {
            request_id,
            endpoint: config.nonce_endpoint.as_str().to_owned(),
        };
        let context = Context {
            access_token: config.access_token,
            token_issued_at_epoch_seconds: config.token_issued_at_epoch_seconds,
            token_expires_in_seconds: config.token_expires_in_seconds,
            credential_issuer: config.credential_issuer,
            format: config.format,
            credential_endpoint: config.credential_endpoint,
            nonce_endpoint: config.nonce_endpoint,
            request_target: config.request_target,
            dpop_key_ref: config.dpop_key_ref,
            dpop_public_jwk: config.dpop_public_jwk,
            credential_key_ref: config.credential_key_ref,
            credential_public_jwk: config.credential_public_jwk,
            credential_endpoint_nonce: None,
            retired_credential_endpoint_nonces: Vec::new(),
            used_random_values,
            last_now_epoch_seconds: environment.now_epoch_seconds,
        };
        Ok((
            Self {
                context,
                stage: Stage::AwaitingNonceResponse { request_id },
            },
            CredentialEffect::SendNonce(nonce_request),
        ))
    }

    pub fn status(&self) -> FlowStatus {
        match self.stage {
            Stage::AwaitingNonceResponse { .. } => FlowStatus::AwaitingNonceResponse,
            Stage::AwaitingKeyAttestation { .. } => FlowStatus::AwaitingKeyAttestation,
            Stage::SigningCredentialProof { .. } => FlowStatus::AwaitingCredentialProofSignature,
            Stage::SigningDpop { .. } => FlowStatus::AwaitingDpopSignature,
            Stage::AwaitingCredentialResponse { .. } => FlowStatus::AwaitingCredentialResponse,
            Stage::Complete(_) => FlowStatus::Complete,
            Stage::Failed(_) => FlowStatus::Failed,
        }
    }

    pub fn failure(&self) -> Option<CredentialError> {
        match self.stage {
            Stage::Failed(error) => Some(error),
            _ => None,
        }
    }

    pub fn into_credential(self) -> Result<IssuedCredential, CredentialError> {
        match self.stage {
            Stage::Complete(credential) => Ok(credential),
            Stage::Failed(error) => Err(error),
            _ => Err(CredentialError::UnexpectedInput),
        }
    }

    pub fn step(
        &mut self,
        input: CredentialInput,
        environment: &CredentialEnvironment<'_>,
    ) -> Result<Vec<CredentialEffect>, CredentialError> {
        validate_clock(environment.now_epoch_seconds).map_err(|error| self.latch(error))?;
        if environment.now_epoch_seconds < self.context.last_now_epoch_seconds {
            return Err(self.latch(CredentialError::InvalidClock));
        }
        validate_token_lifetime(
            self.context.token_issued_at_epoch_seconds,
            self.context.token_expires_in_seconds,
            environment.now_epoch_seconds,
        )
        .map_err(|error| self.latch(error))?;
        self.context.last_now_epoch_seconds = environment.now_epoch_seconds;
        if matches!(self.stage, Stage::Complete(_) | Stage::Failed(_)) {
            return Err(CredentialError::AlreadyTerminal);
        }
        let previous = core::mem::replace(
            &mut self.stage,
            Stage::Failed(CredentialError::UnexpectedInput),
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

    fn latch(&mut self, error: CredentialError) -> CredentialError {
        self.stage = Stage::Failed(error);
        error
    }

    fn transition(
        &mut self,
        stage: Stage,
        input: CredentialInput,
        environment: &CredentialEnvironment<'_>,
    ) -> Result<(Stage, Vec<CredentialEffect>), CredentialError> {
        match (stage, input) {
            (
                Stage::AwaitingNonceResponse { request_id },
                CredentialInput::NonceResponse(response),
            ) => self.accept_nonce_response(request_id, response, environment),
            (
                Stage::AwaitingKeyAttestation {
                    request_id,
                    c_nonce,
                    c_nonce_hash,
                },
                CredentialInput::KeyAttestation(attestation),
            ) => self.accept_key_attestation(
                request_id,
                c_nonce,
                c_nonce_hash,
                attestation,
                environment,
            ),
            (
                Stage::SigningCredentialProof {
                    request_id,
                    c_nonce_hash,
                    signing_input,
                },
                CredentialInput::CredentialProofSignature(signature),
            ) => self.accept_credential_proof_signature(
                request_id,
                c_nonce_hash,
                signing_input,
                signature,
                environment,
            ),
            (
                Stage::SigningDpop {
                    request_id,
                    c_nonce_hash,
                    credential_proof,
                    signing_input,
                    nonce_retry_count,
                },
                CredentialInput::DpopSignature(signature),
            ) => self.accept_dpop_signature(
                request_id,
                c_nonce_hash,
                credential_proof,
                signing_input,
                nonce_retry_count,
                signature,
                environment.random,
            ),
            (
                Stage::AwaitingCredentialResponse {
                    request_id,
                    c_nonce_hash,
                    credential_proof,
                    nonce_retry_count,
                },
                CredentialInput::CredentialResponse(response),
            ) => self.accept_credential_response(
                request_id,
                c_nonce_hash,
                credential_proof,
                nonce_retry_count,
                response,
                environment,
            ),
            _ => Err(CredentialError::UnexpectedInput),
        }
    }

    fn accept_nonce_response(
        &mut self,
        request_id: CorrelationId,
        response: EndpointResponse,
        environment: &CredentialEnvironment<'_>,
    ) -> Result<(Stage, Vec<CredentialEffect>), CredentialError> {
        validate_transport_binding(
            request_id,
            self.context.nonce_endpoint.as_str(),
            "POST",
            &response,
        )?;
        if response.body.expose().len() > MAX_NONCE_RESPONSE_BYTES {
            return Err(CredentialError::InvalidNonceResponse);
        }
        validate_common_response_headers(&response, true)?;
        if !(200..=299).contains(&response.status) {
            return Err(CredentialError::InvalidStatus);
        }
        if !response.www_authenticate_headers.is_empty() {
            return Err(CredentialError::InvalidNonceResponse);
        }
        if let Some(nonce) = parse_single_dpop_nonce(&response.dpop_nonce_headers)? {
            self.rotate_credential_endpoint_nonce(nonce)?;
        }
        let c_nonce = parse_nonce_response(response.body.expose())?;
        let c_nonce_hash = environment.digest.sha256(c_nonce.as_bytes());
        if environment
            .seen_c_nonce_hashes
            .iter()
            .any(|seen| ct_eq(seen, &c_nonce_hash))
        {
            return Err(CredentialError::CNonceReplayed);
        }
        let c_nonce = SecretString::from_string(c_nonce);
        let attestation_request_id = CorrelationId::from_bytes(fresh_random(
            environment.random,
            &mut self.context.used_random_values,
        )?);
        let request = KeyAttestationRequest {
            request_id: attestation_request_id,
            credential_issuer: self.context.credential_issuer.as_str().to_owned(),
            credential_endpoint: self.context.credential_endpoint.as_str().to_owned(),
            key_ref: self.context.credential_key_ref.clone(),
            public_jwk: self.context.credential_public_jwk.clone(),
            c_nonce: c_nonce.duplicate(),
        };
        Ok((
            Stage::AwaitingKeyAttestation {
                request_id: attestation_request_id,
                c_nonce,
                c_nonce_hash,
            },
            vec![CredentialEffect::AcquireKeyAttestation(request)],
        ))
    }

    fn accept_key_attestation(
        &mut self,
        request_id: CorrelationId,
        c_nonce: SecretString,
        c_nonce_hash: [u8; 32],
        attestation: KeyAttestation,
        environment: &CredentialEnvironment<'_>,
    ) -> Result<(Stage, Vec<CredentialEffect>), CredentialError> {
        if !ct_eq(request_id.as_bytes(), attestation.request_id.as_bytes())
            || attestation.credential_issuer != self.context.credential_issuer.as_str()
            || attestation.credential_endpoint != self.context.credential_endpoint.as_str()
            || attestation.key_ref != self.context.credential_key_ref
            || attestation.public_jwk != self.context.credential_public_jwk
            || !ct_eq(
                attestation.c_nonce.expose().as_bytes(),
                c_nonce.expose().as_bytes(),
            )
        {
            return Err(CredentialError::KeyAttestationBindingMismatch);
        }
        validate_key_attestation(
            attestation.jwt.expose(),
            c_nonce.expose(),
            &self.context.credential_public_jwk,
            environment.now_epoch_seconds,
        )?;
        let signing_input = build_credential_proof_signing_input(
            self.context.credential_issuer.as_str(),
            c_nonce.expose(),
            &self.context.credential_public_jwk,
            attestation.jwt.expose(),
            environment.now_epoch_seconds,
        )?;
        let signing_request_id = CorrelationId::from_bytes(fresh_random(
            environment.random,
            &mut self.context.used_random_values,
        )?);
        let effect = SigningRequest {
            request_id: signing_request_id,
            key_ref: self.context.credential_key_ref.clone(),
            signing_input: SecretBytes::new(signing_input.expose().to_vec()),
        };
        Ok((
            Stage::SigningCredentialProof {
                request_id: signing_request_id,
                c_nonce_hash,
                signing_input,
            },
            vec![CredentialEffect::SignCredentialProof(effect)],
        ))
    }

    fn accept_credential_proof_signature(
        &mut self,
        request_id: CorrelationId,
        c_nonce_hash: [u8; 32],
        signing_input: SecretBytes,
        signature: SignatureResult,
        environment: &CredentialEnvironment<'_>,
    ) -> Result<(Stage, Vec<CredentialEffect>), CredentialError> {
        if !ct_eq(request_id.as_bytes(), signature.request_id.as_bytes())
            || signing_input.expose().len() != signature.signing_input.expose().len()
            || !ct_eq(signing_input.expose(), signature.signing_input.expose())
        {
            return Err(CredentialError::CredentialProofSigningMismatch);
        }
        if signature.signature.expose().len() != 64 {
            return Err(CredentialError::CredentialProofSignatureInvalid);
        }
        let credential_proof = assemble_compact_jwt(&signing_input, &signature.signature)?;
        let (stage, effect) = self.dpop_signing_stage(
            c_nonce_hash,
            SecretString::from_string(credential_proof),
            0,
            environment,
        )?;
        Ok((stage, vec![effect]))
    }

    fn dpop_signing_stage(
        &mut self,
        c_nonce_hash: [u8; 32],
        credential_proof: SecretString,
        nonce_retry_count: u8,
        environment: &CredentialEnvironment<'_>,
    ) -> Result<(Stage, CredentialEffect), CredentialError> {
        let jti = base64url(&fresh_random(
            environment.random,
            &mut self.context.used_random_values,
        )?);
        let signing_input = build_dpop_signing_input(
            self.context.credential_endpoint.as_str(),
            &self.context.dpop_public_jwk,
            self.context.access_token.expose(),
            &jti,
            environment.now_epoch_seconds,
            self.context.credential_endpoint_nonce.as_ref(),
            environment.digest,
        )?;
        let request_id = CorrelationId::from_bytes(fresh_random(
            environment.random,
            &mut self.context.used_random_values,
        )?);
        let effect = SigningRequest {
            request_id,
            key_ref: self.context.dpop_key_ref.clone(),
            signing_input: SecretBytes::new(signing_input.expose().to_vec()),
        };
        Ok((
            Stage::SigningDpop {
                request_id,
                c_nonce_hash,
                credential_proof,
                signing_input,
                nonce_retry_count,
            },
            CredentialEffect::SignDpop(effect),
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn accept_dpop_signature(
        &mut self,
        request_id: CorrelationId,
        c_nonce_hash: [u8; 32],
        credential_proof: SecretString,
        signing_input: SecretBytes,
        nonce_retry_count: u8,
        signature: SignatureResult,
        random: &dyn Random,
    ) -> Result<(Stage, Vec<CredentialEffect>), CredentialError> {
        if !ct_eq(request_id.as_bytes(), signature.request_id.as_bytes())
            || signing_input.expose().len() != signature.signing_input.expose().len()
            || !ct_eq(signing_input.expose(), signature.signing_input.expose())
        {
            return Err(CredentialError::DpopSigningMismatch);
        }
        if signature.signature.expose().len() != 64 {
            return Err(CredentialError::DpopSignatureInvalid);
        }
        let dpop_proof = assemble_compact_jwt(&signing_input, &signature.signature)
            .map_err(|_| CredentialError::DpopSignatureInvalid)?;
        let body = build_credential_request_body(&self.context.request_target, &credential_proof)?;
        let request_id =
            CorrelationId::from_bytes(fresh_random(random, &mut self.context.used_random_values)?);
        let request = CredentialRequest {
            request_id,
            endpoint: self.context.credential_endpoint.as_str().to_owned(),
            authorization: SecretString::from_string(format!(
                "DPoP {}",
                self.context.access_token.expose()
            )),
            dpop_proof: SecretString::from_string(dpop_proof),
            body,
        };
        Ok((
            Stage::AwaitingCredentialResponse {
                request_id,
                c_nonce_hash,
                credential_proof,
                nonce_retry_count,
            },
            vec![CredentialEffect::SendCredential(request)],
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn accept_credential_response(
        &mut self,
        request_id: CorrelationId,
        c_nonce_hash: [u8; 32],
        credential_proof: SecretString,
        nonce_retry_count: u8,
        response: EndpointResponse,
        environment: &CredentialEnvironment<'_>,
    ) -> Result<(Stage, Vec<CredentialEffect>), CredentialError> {
        validate_transport_binding(
            request_id,
            self.context.credential_endpoint.as_str(),
            "POST",
            &response,
        )?;
        if response.body.expose().len() > MAX_CREDENTIAL_RESPONSE_BYTES {
            return Err(CredentialError::InvalidCredentialResponse);
        }
        validate_common_response_headers(&response, true)?;
        let nonce = parse_single_dpop_nonce(&response.dpop_nonce_headers)?;
        if response.status == 401
            && is_use_dpop_nonce_challenge(&response.www_authenticate_headers)?
        {
            let nonce = nonce.ok_or(CredentialError::DpopNonceInvalid)?;
            parse_use_dpop_nonce_body(response.body.expose())?;
            if nonce_retry_count >= MAX_RESOURCE_DPOP_NONCE_RETRIES {
                return Err(CredentialError::DpopNonceRetryLimit);
            }
            self.rotate_credential_endpoint_nonce(nonce)?;
            let (stage, effect) = self.dpop_signing_stage(
                c_nonce_hash,
                credential_proof,
                nonce_retry_count + 1,
                environment,
            )?;
            return Ok((stage, vec![effect]));
        }
        if !response.www_authenticate_headers.is_empty() {
            return Err(CredentialError::CredentialRejected);
        }
        if let Some(nonce) = nonce {
            self.rotate_credential_endpoint_nonce(nonce)?;
        }
        if response.status == 202 {
            return Err(CredentialError::DeferredIssuanceUnsupported);
        }
        if response.status != 200 {
            return Err(CredentialError::CredentialRejected);
        }
        let raw = parse_immediate_credential(
            response.body.expose(),
            self.context.format,
            self.context.credential_issuer.as_str(),
        )?;
        Ok((
            Stage::Complete(IssuedCredential {
                format: self.context.format,
                raw,
                c_nonce_hash,
            }),
            Vec::new(),
        ))
    }

    fn rotate_credential_endpoint_nonce(
        &mut self,
        nonce: SecretString,
    ) -> Result<(), CredentialError> {
        if self
            .context
            .credential_endpoint_nonce
            .as_ref()
            .is_some_and(|current| ct_eq(current.expose().as_bytes(), nonce.expose().as_bytes()))
            || self
                .context
                .retired_credential_endpoint_nonces
                .iter()
                .any(|retired| ct_eq(retired.expose().as_bytes(), nonce.expose().as_bytes()))
        {
            return Err(CredentialError::DpopNonceStale);
        }
        if let Some(previous) = self.context.credential_endpoint_nonce.replace(nonce) {
            self.context
                .retired_credential_endpoint_nonces
                .push(previous);
        }
        Ok(())
    }
}

fn validate_token_lifetime(
    issued_at: i64,
    expires_in: Option<u32>,
    now: i64,
) -> Result<(), CredentialError> {
    if issued_at <= 0 || now < issued_at {
        return Err(CredentialError::InvalidClock);
    }
    if let Some(expires_in) = expires_in {
        let deadline = issued_at
            .checked_add(i64::from(expires_in))
            .ok_or(CredentialError::TokenExpired)?;
        if now >= deadline {
            return Err(CredentialError::TokenExpired);
        }
    }
    Ok(())
}

fn validate_transport_binding(
    expected_request_id: CorrelationId,
    expected_endpoint: &str,
    expected_method: &str,
    response: &EndpointResponse,
) -> Result<(), CredentialError> {
    if ct_eq(
        expected_request_id.as_bytes(),
        response.request_id.as_bytes(),
    ) && response.endpoint == expected_endpoint
        && response.method == expected_method
    {
        Ok(())
    } else {
        Err(CredentialError::TransportBindingMismatch)
    }
}

fn validate_common_response_headers(
    response: &EndpointResponse,
    require_no_store: bool,
) -> Result<(), CredentialError> {
    let content_type = parse_single_header(&response.content_type_headers)
        .ok_or(CredentialError::InvalidMediaType)?;
    if !valid_json_content_type(content_type) {
        return Err(CredentialError::InvalidMediaType);
    }
    validate_header_values(&response.cache_control_headers)?;
    if require_no_store
        && !response.cache_control_headers.iter().any(|value| {
            value
                .split(',')
                .map(str::trim)
                .any(|directive| directive.eq_ignore_ascii_case("no-store"))
        })
    {
        return Err(CredentialError::CachePolicyMissing);
    }
    if response.cache_control_headers.iter().any(|value| {
        value.split(',').map(str::trim).any(|directive| {
            let name = directive
                .split_once('=')
                .map_or(directive, |(name, _)| name)
                .trim();
            name.eq_ignore_ascii_case("public")
                || name.eq_ignore_ascii_case("max-age")
                || name.eq_ignore_ascii_case("s-maxage")
                || name.eq_ignore_ascii_case("immutable")
        })
    }) {
        return Err(CredentialError::CachePolicyMissing);
    }
    if !response.pragma_headers.is_empty() {
        validate_header_values(&response.pragma_headers)?;
        if !response.pragma_headers.iter().all(|value| {
            value
                .split(',')
                .map(str::trim)
                .all(|directive| directive.eq_ignore_ascii_case("no-cache"))
        }) {
            return Err(CredentialError::CachePolicyMissing);
        }
    }
    match response.content_encoding_headers.as_slice() {
        [] => {}
        [value] if valid_header_value(value) && value.eq_ignore_ascii_case("identity") => {}
        _ => return Err(CredentialError::InvalidContentEncoding),
    }
    Ok(())
}

fn parse_single_header(values: &[String]) -> Option<&str> {
    match values {
        [value] if valid_header_value(value) => Some(value),
        _ => None,
    }
}

fn validate_header_values(values: &[String]) -> Result<(), CredentialError> {
    if values.is_empty()
        || values.len() > 8
        || values.iter().any(|value| !valid_header_value(value))
    {
        Err(CredentialError::CachePolicyMissing)
    } else {
        Ok(())
    }
}

fn valid_header_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 4_096
        && value.is_ascii()
        && value
            .bytes()
            .all(|byte| byte == b'\t' || (0x20..=0x7e).contains(&byte))
}

fn valid_json_content_type(value: &str) -> bool {
    if !valid_header_value(value) || value.contains(',') {
        return false;
    }
    let mut parts = value.split(';');
    if !parts
        .next()
        .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json"))
    {
        return false;
    }
    let mut charset = false;
    for parameter in parts {
        let Some((name, value)) = parameter.trim().split_once('=') else {
            return false;
        };
        if charset || !name.trim().eq_ignore_ascii_case("charset") {
            return false;
        }
        let value = value.trim();
        if !value.eq_ignore_ascii_case("utf-8") && !value.eq_ignore_ascii_case("\"utf-8\"") {
            return false;
        }
        charset = true;
    }
    true
}

fn parse_single_dpop_nonce(values: &[String]) -> Result<Option<SecretString>, CredentialError> {
    match values {
        [] => Ok(None),
        [value]
            if value.len() <= MAX_DPOP_NONCE_BYTES
                && valid_header_value(value)
                && value.bytes().all(is_nqchar) =>
        {
            Ok(Some(SecretString::from_str(value)))
        }
        _ => Err(CredentialError::DpopNonceInvalid),
    }
}

fn parse_nonce_response(input: &[u8]) -> Result<String, CredentialError> {
    let mut object = bounded_json::parse_object(input, NONCE_JSON_LIMITS)
        .map_err(|_| CredentialError::InvalidNonceResponse)?;
    if object.contains_key("error") {
        return Err(CredentialError::InvalidNonceResponse);
    }
    match object.remove("c_nonce") {
        Some(Value::String(value))
            if valid_bounded_text(&value, MAX_C_NONCE_BYTES) && value.bytes().all(is_nqchar) =>
        {
            Ok(value)
        }
        _ => Err(CredentialError::InvalidNonceResponse),
    }
}

fn validate_key_attestation(
    compact: &str,
    expected_nonce: &str,
    expected_jwk: &Es256PublicJwk,
    now: i64,
) -> Result<(), CredentialError> {
    let DecodedCompactJwt {
        header: header_bytes,
        payload: payload_bytes,
        signature,
    } = split_compact_jwt(
        compact,
        MAX_KEY_ATTESTATION_BYTES,
        MAX_KEY_ATTESTATION_SEGMENT_BYTES,
    )
    .map_err(|_| CredentialError::KeyAttestationInvalid)?;
    if signature.len() != 64 {
        return Err(CredentialError::KeyAttestationInvalid);
    }
    let header = bounded_json::parse_object(&header_bytes, JWT_JSON_LIMITS)
        .map_err(|_| CredentialError::KeyAttestationInvalid)?;
    if header.get("alg").and_then(Value::as_str) != Some("ES256")
        || header.get("typ").and_then(Value::as_str) != Some("key-attestation+jwt")
    {
        return Err(CredentialError::KeyAttestationInvalid);
    }
    let certificates = header
        .get("x5c")
        .and_then(Value::as_array)
        .filter(|certificates| !certificates.is_empty() && certificates.len() <= 8)
        .ok_or(CredentialError::KeyAttestationInvalid)?;
    let mut parsed_certificates = Vec::with_capacity(certificates.len());
    for certificate in certificates {
        let certificate = certificate
            .as_str()
            .filter(|value| value.len() <= 16 * 1024)
            .ok_or(CredentialError::KeyAttestationInvalid)?;
        let decoded =
            Base64::decode_vec(certificate).map_err(|_| CredentialError::KeyAttestationInvalid)?;
        if decoded.is_empty() || Base64::encode_string(&decoded) != certificate {
            return Err(CredentialError::KeyAttestationInvalid);
        }
        parsed_certificates
            .push(x509::parse_cert(&decoded).map_err(|_| CredentialError::KeyAttestationInvalid)?);
    }
    // HAIP forbids a self-signed signing certificate and forbids carrying the trust anchor. A
    // self-issued certificate anywhere in this bounded x5c list is therefore rejected. Full path,
    // EKU/policy and anchor authorization remain the explicitly unresolved ecosystem trust step.
    if parsed_certificates
        .iter()
        .any(|certificate| certificate.subject == certificate.issuer)
    {
        return Err(CredentialError::KeyAttestationInvalid);
    }

    let payload = bounded_json::parse_object(&payload_bytes, JWT_JSON_LIMITS)
        .map_err(|_| CredentialError::KeyAttestationInvalid)?;
    // Appendix D does not require `iss`. If a Wallet Provider includes it, keep the JWT claim
    // type and attacker-controlled size strict without inventing an interoperability requirement.
    if payload.get("iss").is_some_and(|value| {
        !value
            .as_str()
            .is_some_and(|value| valid_bounded_text(value, 2_048))
    }) {
        return Err(CredentialError::KeyAttestationInvalid);
    }
    let issued_at = payload
        .get("iat")
        .and_then(Value::as_i64)
        .ok_or(CredentialError::KeyAttestationInvalid)?;
    let expires_at = payload
        .get("exp")
        .and_then(Value::as_i64)
        .ok_or(CredentialError::KeyAttestationInvalid)?;
    if issued_at <= 0 || issued_at > now || expires_at <= now || expires_at <= issued_at {
        return Err(CredentialError::KeyAttestationInvalid);
    }
    if !payload
        .get("nonce")
        .and_then(Value::as_str)
        .is_some_and(|nonce| ct_eq(nonce.as_bytes(), expected_nonce.as_bytes()))
        || !string_array_contains(&payload, "key_storage", "iso_18045_high")
        || !string_array_contains(&payload, "user_authentication", "iso_18045_high")
    {
        return Err(CredentialError::KeyAttestationInvalid);
    }
    let keys = payload
        .get("attested_keys")
        .and_then(Value::as_array)
        .filter(|keys| keys.len() == 1)
        .ok_or(CredentialError::KeyAttestationInvalid)?;
    let key = keys[0]
        .as_object()
        .ok_or(CredentialError::KeyAttestationInvalid)?;
    if key.get("kty").and_then(Value::as_str) != Some("EC")
        || key.get("crv").and_then(Value::as_str) != Some("P-256")
        || key.get("x").and_then(Value::as_str) != Some(expected_jwk.x())
        || key.get("y").and_then(Value::as_str) != Some(expected_jwk.y())
    {
        return Err(CredentialError::KeyAttestationInvalid);
    }
    Ok(())
}

fn string_array_contains(object: &Map<String, Value>, field: &str, expected: &str) -> bool {
    object
        .get(field)
        .and_then(Value::as_array)
        .filter(|values| !values.is_empty() && values.len() <= 16)
        .is_some_and(|values| {
            values.iter().all(|value| {
                value
                    .as_str()
                    .is_some_and(|value| valid_bounded_text(value, 256))
            }) && values.iter().any(|value| value.as_str() == Some(expected))
        })
}

fn build_credential_proof_signing_input(
    credential_issuer: &str,
    c_nonce: &str,
    jwk: &Es256PublicJwk,
    key_attestation: &str,
    iat: i64,
) -> Result<SecretBytes, CredentialError> {
    let header = serde_json::json!({
        "alg": "ES256",
        "jwk": {
            "crv": "P-256",
            "kty": "EC",
            "x": jwk.x(),
            "y": jwk.y(),
        },
        "key_attestation": key_attestation,
        "typ": "openid4vci-proof+jwt",
    });
    let payload = serde_json::json!({
        "aud": credential_issuer,
        "iat": iat,
        "nonce": c_nonce,
    });
    let signing_input = format!(
        "{}.{}",
        base64url(&serde_json::to_vec(&header).map_err(|_| CredentialError::InvalidConfiguration)?),
        base64url(
            &serde_json::to_vec(&payload).map_err(|_| CredentialError::InvalidConfiguration)?
        ),
    );
    if signing_input.len() > MAX_SIGNING_INPUT_BYTES {
        return Err(CredentialError::InvalidConfiguration);
    }
    Ok(SecretBytes::new(signing_input.into_bytes()))
}

#[allow(clippy::too_many_arguments)]
fn build_dpop_signing_input(
    endpoint: &str,
    jwk: &Es256PublicJwk,
    access_token: &str,
    jti: &str,
    iat: i64,
    nonce: Option<&SecretString>,
    digest: &dyn Digest,
) -> Result<SecretBytes, CredentialError> {
    let header = serde_json::json!({
        "alg": "ES256",
        "jwk": {
            "crv": "P-256",
            "kty": "EC",
            "x": jwk.x(),
            "y": jwk.y(),
        },
        "typ": "dpop+jwt",
    });
    let ath = base64url(&digest.sha256(access_token.as_bytes()));
    let mut payload = serde_json::json!({
        "ath": ath,
        "htm": "POST",
        "htu": dpop_htu(endpoint),
        "iat": iat,
        "jti": jti,
    });
    if let Some(nonce) = nonce {
        payload
            .as_object_mut()
            .ok_or(CredentialError::InvalidConfiguration)?
            .insert("nonce".to_owned(), Value::String(nonce.expose().to_owned()));
    }
    let signing_input = format!(
        "{}.{}",
        base64url(&serde_json::to_vec(&header).map_err(|_| CredentialError::InvalidConfiguration)?),
        base64url(
            &serde_json::to_vec(&payload).map_err(|_| CredentialError::InvalidConfiguration)?
        ),
    );
    if signing_input.len() > MAX_SIGNING_INPUT_BYTES {
        return Err(CredentialError::InvalidConfiguration);
    }
    Ok(SecretBytes::new(signing_input.into_bytes()))
}

fn build_credential_request_body(
    target: &SelectedRequestTarget,
    proof: &SecretString,
) -> Result<SecretBytes, CredentialError> {
    let mut object = Map::new();
    match target {
        SelectedRequestTarget::ConfigurationId(identifier) => {
            object.insert(
                "credential_configuration_id".to_owned(),
                Value::String(identifier.clone()),
            );
        }
        SelectedRequestTarget::CredentialIdentifier(identifier) => {
            object.insert(
                "credential_identifier".to_owned(),
                Value::String(identifier.expose().to_owned()),
            );
        }
    }
    object.insert(
        "proofs".to_owned(),
        serde_json::json!({ "jwt": [proof.expose()] }),
    );
    let body = serde_json::to_vec(&object).map_err(|_| CredentialError::InvalidConfiguration)?;
    if body.len() > MAX_CREDENTIAL_REQUEST_BYTES {
        return Err(CredentialError::InvalidConfiguration);
    }
    Ok(SecretBytes::new(body))
}

fn assemble_compact_jwt(
    signing_input: &SecretBytes,
    signature: &SecretBytes,
) -> Result<String, CredentialError> {
    let mut compact = signing_input.expose().to_vec();
    compact.push(b'.');
    compact.extend_from_slice(base64url(signature.expose()).as_bytes());
    String::from_utf8(compact).map_err(|_| CredentialError::InvalidConfiguration)
}

fn is_use_dpop_nonce_challenge(values: &[String]) -> Result<bool, CredentialError> {
    let challenge = match values {
        [value] if valid_header_value(value) => value,
        [] => return Ok(false),
        _ => return Err(CredentialError::DpopNonceInvalid),
    };
    let (scheme, parameters) = challenge
        .split_once(char::is_whitespace)
        .ok_or(CredentialError::DpopNonceInvalid)?;
    if !scheme.eq_ignore_ascii_case("DPoP") {
        return Ok(false);
    }
    let parameters = parse_auth_parameters(parameters)?;
    Ok(parameters.get("error").map(String::as_str) == Some("use_dpop_nonce"))
}

fn parse_auth_parameters(input: &str) -> Result<BTreeMap<String, String>, CredentialError> {
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut quoted = false;
    let mut escaped = false;
    for (index, byte) in input.bytes().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        match byte {
            b'\\' if quoted => escaped = true,
            b'"' => quoted = !quoted,
            b',' if !quoted => {
                parts.push(&input[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    if quoted || escaped {
        return Err(CredentialError::DpopNonceInvalid);
    }
    parts.push(&input[start..]);
    if parts.is_empty() || parts.len() > 16 {
        return Err(CredentialError::DpopNonceInvalid);
    }
    let mut result = BTreeMap::new();
    for part in parts {
        let (name, value) = part
            .trim()
            .split_once('=')
            .ok_or(CredentialError::DpopNonceInvalid)?;
        let name = name.trim().to_ascii_lowercase();
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            || result.contains_key(&name)
        {
            return Err(CredentialError::DpopNonceInvalid);
        }
        let value = parse_auth_parameter_value(value.trim())?;
        result.insert(name, value);
    }
    Ok(result)
}

fn parse_auth_parameter_value(value: &str) -> Result<String, CredentialError> {
    if let Some(inner) = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
    {
        let mut output = String::new();
        let mut escaped = false;
        for character in inner.chars() {
            if escaped {
                if character != '"' && character != '\\' {
                    return Err(CredentialError::DpopNonceInvalid);
                }
                output.push(character);
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' || character.is_control() {
                return Err(CredentialError::DpopNonceInvalid);
            } else {
                output.push(character);
            }
        }
        if escaped || output.len() > 2_048 {
            return Err(CredentialError::DpopNonceInvalid);
        }
        Ok(output)
    } else if !value.is_empty()
        && value.len() <= 2_048
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        ..=b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
                )
        })
    {
        Ok(value.to_owned())
    } else {
        Err(CredentialError::DpopNonceInvalid)
    }
}

fn parse_use_dpop_nonce_body(input: &[u8]) -> Result<(), CredentialError> {
    let object = bounded_json::parse_object(input, NONCE_JSON_LIMITS)
        .map_err(|_| CredentialError::DpopNonceInvalid)?;
    if object.get("error").and_then(Value::as_str) == Some("use_dpop_nonce") {
        Ok(())
    } else {
        Err(CredentialError::DpopNonceInvalid)
    }
}

fn parse_immediate_credential(
    input: &[u8],
    format: GermanPidFormat,
    expected_issuer: &str,
) -> Result<Vec<u8>, CredentialError> {
    let object = bounded_json::parse_object(input, CREDENTIAL_JSON_LIMITS)
        .map_err(|_| CredentialError::InvalidCredentialResponse)?;
    if object.contains_key("transaction_id")
        || object.contains_key("interval")
        || object.contains_key("acceptance_token")
    {
        return Err(CredentialError::DeferredIssuanceUnsupported);
    }
    if object.contains_key("notification_id") {
        return Err(CredentialError::NotificationUnsupported);
    }
    if object.contains_key("refresh_token") || object.contains_key("reissuance") {
        return Err(CredentialError::ReissuanceUnsupported);
    }
    if object.contains_key("credential_response_encryption") {
        return Err(CredentialError::ResponseEncryptionUnsupported);
    }
    let credentials = object
        .get("credentials")
        .and_then(Value::as_array)
        .ok_or(CredentialError::InvalidCredentialResponse)?;
    if credentials.len() > 1 {
        return Err(CredentialError::BatchIssuanceUnsupported);
    }
    if credentials.len() != 1 {
        return Err(CredentialError::InvalidCredentialResponse);
    }
    let credential = credentials[0]
        .as_object()
        .and_then(|object| object.get("credential"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= MAX_CREDENTIAL_BYTES)
        .ok_or(CredentialError::InvalidCredentialResponse)?;
    match format {
        GermanPidFormat::DcSdJwt => validate_sd_jwt_pid(credential, expected_issuer),
        GermanPidFormat::MsoMdoc => validate_mdoc_pid(credential),
    }
}

fn validate_sd_jwt_pid(compact: &str, expected_issuer: &str) -> Result<Vec<u8>, CredentialError> {
    let separators = compact.bytes().filter(|byte| *byte == b'~').count();
    if !(1..=MAX_SD_JWT_COMPONENT_SEPARATORS).contains(&separators) {
        return Err(CredentialError::CredentialFormatMismatch);
    }
    let parsed =
        sdjwt::SdJwtVc::parse(compact).map_err(|_| CredentialError::CredentialFormatMismatch)?;
    if parsed.key_binding_jwt.is_some() {
        return Err(CredentialError::CredentialFormatMismatch);
    }
    let DecodedCompactJwt {
        header,
        payload,
        signature,
    } = split_compact_jwt(
        &parsed.issuer_jwt,
        MAX_CREDENTIAL_BYTES,
        MAX_CREDENTIAL_BYTES,
    )
    .map_err(|_| CredentialError::CredentialFormatMismatch)?;
    if signature.len() != 64 {
        return Err(CredentialError::CredentialFormatMismatch);
    }
    let header = bounded_json::parse_object(&header, CREDENTIAL_JSON_LIMITS)
        .map_err(|_| CredentialError::CredentialFormatMismatch)?;
    let payload = bounded_json::parse_object(&payload, CREDENTIAL_JSON_LIMITS)
        .map_err(|_| CredentialError::CredentialFormatMismatch)?;
    if header.get("alg").and_then(Value::as_str) != Some("ES256")
        || header.get("typ").and_then(Value::as_str) != Some("dc+sd-jwt")
        || payload.get("vct").and_then(Value::as_str) != Some(SD_JWT_PID_VCT)
        || payload.get("iss").and_then(Value::as_str) != Some(expected_issuer)
    {
        return Err(CredentialError::CredentialFormatMismatch);
    }
    Ok(compact.as_bytes().to_vec())
}

fn validate_mdoc_pid(encoded: &str) -> Result<Vec<u8>, CredentialError> {
    if !is_base64url_unpadded(encoded.as_bytes()) {
        return Err(CredentialError::CredentialFormatMismatch);
    }
    let decoded = Base64UrlUnpadded::decode_vec(encoded)
        .map_err(|_| CredentialError::CredentialFormatMismatch)?;
    if decoded.is_empty() || decoded.len() > MAX_CREDENTIAL_BYTES || base64url(&decoded) != encoded
    {
        return Err(CredentialError::CredentialFormatMismatch);
    }
    let issued = mdoc::IssuerSigned::parse(&decoded)
        .map_err(|_| CredentialError::CredentialFormatMismatch)?;
    if issued.doc_type().as_deref() != Ok(MDOC_PID_DOCTYPE)
        || issued.issuer_auth.signature.len() != 64
        || !cose_alg_is_es256(&issued.issuer_auth.protected)
    {
        return Err(CredentialError::CredentialFormatMismatch);
    }
    Ok(decoded)
}

fn cose_alg_is_es256(protected: &[u8]) -> bool {
    let Ok(mdoc::cbor::Value::Map(entries)) = mdoc::cbor::from_canonical_slice(protected) else {
        return false;
    };
    entries.iter().any(|(key, value)| {
        key == &mdoc::cbor::Value::Uint(1) && value == &mdoc::cbor::Value::Nint(6)
    })
}

struct DecodedCompactJwt {
    header: Vec<u8>,
    payload: Vec<u8>,
    signature: Vec<u8>,
}

fn split_compact_jwt(
    compact: &str,
    max_compact: usize,
    max_segment_bytes: usize,
) -> Result<DecodedCompactJwt, ()> {
    if compact.is_empty() || compact.len() > max_compact {
        return Err(());
    }
    let segments: Vec<&str> = compact.split('.').collect();
    if segments.len() != 3 {
        return Err(());
    }
    let mut decoded = Vec::with_capacity(3);
    for segment in segments {
        if segment.is_empty() || !is_base64url_unpadded(segment.as_bytes()) {
            return Err(());
        }
        let value = Base64UrlUnpadded::decode_vec(segment).map_err(|_| ())?;
        if value.is_empty() || value.len() > max_segment_bytes || base64url(&value) != segment {
            return Err(());
        }
        decoded.push(value);
    }
    Ok(DecodedCompactJwt {
        header: decoded.remove(0),
        payload: decoded.remove(0),
        signature: decoded.remove(0),
    })
}

fn dpop_htu(endpoint: &str) -> &str {
    endpoint.split_once('?').map_or(endpoint, |(base, _)| base)
}

fn validate_clock(now: i64) -> Result<(), CredentialError> {
    if now > 0 {
        Ok(())
    } else {
        Err(CredentialError::InvalidClock)
    }
}

fn fresh_random(
    random: &dyn Random,
    used: &mut Vec<[u8; 32]>,
) -> Result<[u8; 32], CredentialError> {
    if used.len() >= 32 {
        return Err(CredentialError::RandomnessFailure);
    }
    let mut value = [0u8; 32];
    random.fill(&mut value);
    if value.iter().all(|byte| *byte == 0) || used.iter().any(|seen| ct_eq(seen, &value)) {
        value.fill(0);
        return Err(CredentialError::RandomnessFailure);
    }
    used.push(value);
    Ok(value)
}

fn valid_bounded_text(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}

fn is_nqchar(byte: u8) -> bool {
    matches!(byte, 0x21..=0x7e)
}

fn is_base64url_unpadded(value: &[u8]) -> bool {
    !value.is_empty()
        && value
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn ct_eq(left: &[u8], right: &[u8]) -> bool {
    let max = left.len().max(right.len());
    let mut difference = left.len() ^ right.len();
    for index in 0..max {
        difference |= usize::from(
            left.get(index).copied().unwrap_or(0) ^ right.get(index).copied().unwrap_or(0),
        );
    }
    difference == 0
}

fn base64url(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}
