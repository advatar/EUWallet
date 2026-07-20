//! OpenID4VCI 1.0 discovery and German PID first-enrolment profile selection.
//!
//! This is an isolated protocol boundary.  It does not drive the legacy issuance state machine and
//! it deliberately does not turn successful HTTPS retrieval or metadata parsing into PID-provider
//! trust.  A successful [`GermanPidIssuancePlan`] remains explicitly trust-unresolved.

use crate::bounded_json::{self, JsonBoundaryError, JsonLimits, DEFAULT_JSON_LIMITS};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, Ipv6Addr};

pub const MAX_IDENTIFIER_BYTES: usize = 2_048;
pub const MAX_ENDPOINT_BYTES: usize = 4_096;
pub const MAX_CONFIGURATION_IDS: usize = 32;
pub const MAX_CONFIGURATION_ID_BYTES: usize = 256;
pub const MAX_AUTHORIZATION_SERVERS: usize = 8;
pub const MAX_CONFIGURATIONS: usize = 32;
pub const MAX_LIST_VALUES: usize = 32;
pub const MAX_PROOF_TYPES: usize = 8;
pub const MAX_SCOPE_BYTES: usize = 512;
pub const MAX_OPAQUE_VALUE_BYTES: usize = 2_048;
pub const MAX_TRANSACTION_CODE_LENGTH: u64 = 64;
pub const MAX_BATCH_SIZE: u64 = 64;

pub const AUTHORIZATION_CODE_GRANT: &str = "authorization_code";
pub const PRE_AUTHORIZED_CODE_GRANT: &str = "urn:ietf:params:oauth:grant-type:pre-authorized_code";
pub const MDOC_PID_DOCTYPE: &str = "eu.europa.ec.eudi.pid.1";
pub const SD_JWT_PID_VCT: &str = "urn:eudi:pid:1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UrlSyntaxError {
    Empty,
    TooLong,
    NotHttps,
    CredentialsForbidden,
    QueryForbidden,
    FragmentForbidden,
    InvalidAuthority,
    InvalidHost,
    InvalidPort,
    InvalidPath,
    InvalidQuery,
    NonCanonical,
}

/// A case-sensitive, already-canonical HTTPS issuer identifier.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct HttpsIdentifier(String);

impl HttpsIdentifier {
    pub fn parse(value: &str) -> Result<Self, UrlSyntaxError> {
        validate_https_url(value, UrlKind::Identifier)?;
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// OpenID4VCI 1.0 pathful well-known construction (insertion before the issuer path).
    pub fn credential_issuer_metadata_url(&self) -> String {
        well_known_url(self.as_str(), "openid-credential-issuer", false)
    }

    /// RFC 8414 pathful well-known construction (insertion before the issuer path).
    pub fn authorization_server_metadata_url(&self) -> String {
        well_known_url(self.as_str(), "oauth-authorization-server", true)
    }
}

/// A strict HTTPS endpoint URL. Queries are allowed; fragments and credentials are not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpsEndpoint(String);

impl HttpsEndpoint {
    pub fn parse(value: &str) -> Result<Self, UrlSyntaxError> {
        validate_https_url(value, UrlKind::Endpoint)?;
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy)]
enum UrlKind {
    Identifier,
    Endpoint,
}

fn validate_https_url(value: &str, kind: UrlKind) -> Result<(), UrlSyntaxError> {
    if value.is_empty() {
        return Err(UrlSyntaxError::Empty);
    }
    let max = match kind {
        UrlKind::Identifier => MAX_IDENTIFIER_BYTES,
        UrlKind::Endpoint => MAX_ENDPOINT_BYTES,
    };
    if value.len() > max {
        return Err(UrlSyntaxError::TooLong);
    }
    if !value.is_ascii() {
        return Err(UrlSyntaxError::NonCanonical);
    }
    let remainder = value
        .strip_prefix("https://")
        .ok_or(UrlSyntaxError::NotHttps)?;
    if value.contains('#') {
        return Err(UrlSyntaxError::FragmentForbidden);
    }
    if matches!(kind, UrlKind::Identifier) && value.contains('?') {
        return Err(UrlSyntaxError::QueryForbidden);
    }

    let authority_end = remainder.find(['/', '?']).unwrap_or(remainder.len());
    let authority = &remainder[..authority_end];
    if authority.is_empty() {
        return Err(UrlSyntaxError::InvalidAuthority);
    }
    if authority.contains('@') {
        return Err(UrlSyntaxError::CredentialsForbidden);
    }
    validate_authority(authority)?;

    let suffix = &remainder[authority_end..];
    let (path, query) = match suffix.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (suffix, None),
    };
    if !path.is_empty() && !path.starts_with('/') {
        return Err(UrlSyntaxError::InvalidPath);
    }
    validate_uri_component(path, false)?;
    if path
        .split('/')
        .any(|segment| segment == "." || segment == "..")
    {
        return Err(UrlSyntaxError::NonCanonical);
    }
    if let Some(query) = query {
        if matches!(kind, UrlKind::Identifier) {
            return Err(UrlSyntaxError::QueryForbidden);
        }
        if query.is_empty() {
            return Err(UrlSyntaxError::NonCanonical);
        }
        validate_uri_component(query, true)?;
    }
    Ok(())
}

fn validate_authority(authority: &str) -> Result<(), UrlSyntaxError> {
    if let Some(ip_literal) = authority.strip_prefix('[') {
        let closing = ip_literal.find(']').ok_or(UrlSyntaxError::InvalidHost)?;
        let host = &ip_literal[..closing];
        let rest = &ip_literal[closing + 1..];
        let parsed = host
            .parse::<Ipv6Addr>()
            .map_err(|_| UrlSyntaxError::InvalidHost)?;
        if parsed.to_string() != host {
            return Err(UrlSyntaxError::NonCanonical);
        }
        if !rest.is_empty() {
            let port = rest
                .strip_prefix(':')
                .ok_or(UrlSyntaxError::InvalidAuthority)?;
            validate_port(port)?;
        }
        return Ok(());
    }

    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => {
            if host.contains(':') {
                return Err(UrlSyntaxError::InvalidHost);
            }
            (host, Some(port))
        }
        None => (authority, None),
    };
    if host.is_empty() {
        return Err(UrlSyntaxError::InvalidHost);
    }
    if let Some(port) = port {
        validate_port(port)?;
    }
    validate_reg_name(host)
}

fn validate_port(port: &str) -> Result<(), UrlSyntaxError> {
    if port.is_empty()
        || !port.bytes().all(|byte| byte.is_ascii_digit())
        || (port.len() > 1 && port.starts_with('0'))
    {
        return Err(UrlSyntaxError::InvalidPort);
    }
    let port = port
        .parse::<u16>()
        .map_err(|_| UrlSyntaxError::InvalidPort)?;
    if port == 0 {
        return Err(UrlSyntaxError::InvalidPort);
    }
    if port == 443 {
        return Err(UrlSyntaxError::NonCanonical);
    }
    Ok(())
}

fn validate_reg_name(host: &str) -> Result<(), UrlSyntaxError> {
    if host.len() > 253 || host.ends_with('.') || host.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return Err(UrlSyntaxError::NonCanonical);
    }
    if host
        .bytes()
        .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        let address = host
            .parse::<Ipv4Addr>()
            .map_err(|_| UrlSyntaxError::InvalidHost)?;
        return if address.to_string() == host {
            Ok(())
        } else {
            Err(UrlSyntaxError::NonCanonical)
        };
    }
    for label in host.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(UrlSyntaxError::InvalidHost);
        }
    }
    Ok(())
}

fn validate_uri_component(component: &str, query: bool) -> Result<(), UrlSyntaxError> {
    let bytes = component.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' {
            let high = *bytes.get(index + 1).ok_or(if query {
                UrlSyntaxError::InvalidQuery
            } else {
                UrlSyntaxError::InvalidPath
            })?;
            let low = *bytes.get(index + 2).ok_or(if query {
                UrlSyntaxError::InvalidQuery
            } else {
                UrlSyntaxError::InvalidPath
            })?;
            if !is_upper_hex(high) || !is_upper_hex(low) {
                return Err(UrlSyntaxError::NonCanonical);
            }
            let decoded = (hex(high) << 4) | hex(low);
            if is_unreserved(decoded)
                || decoded < 0x20
                || decoded == 0x7f
                || matches!(decoded, b'/' | b'\\' | b'?' | b'#')
            {
                return Err(UrlSyntaxError::NonCanonical);
            }
            index += 3;
            continue;
        }
        let allowed = is_unreserved(byte)
            || matches!(
                byte,
                b'!' | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
                    | b':'
                    | b'@'
            )
            || byte == b'/'
            || (query && byte == b'?');
        if !allowed {
            return Err(if query {
                UrlSyntaxError::InvalidQuery
            } else {
                UrlSyntaxError::InvalidPath
            });
        }
        index += 1;
    }
    Ok(())
}

fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

fn is_upper_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || matches!(byte, b'A'..=b'F')
}

fn hex(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'A'..=b'F' => byte - b'A' + 10,
        _ => 0,
    }
}

fn well_known_url(identifier: &str, suffix: &str, remove_terminating_slash: bool) -> String {
    let after_scheme = &identifier["https://".len()..];
    let authority_end = after_scheme.find('/').unwrap_or(after_scheme.len());
    let origin_end = "https://".len() + authority_end;
    let origin = &identifier[..origin_end];
    let path = &identifier[origin_end..];
    let path = if remove_terminating_slash {
        path.strip_suffix('/').unwrap_or(path)
    } else {
        path
    };
    if path.is_empty() {
        format!("{origin}/.well-known/{suffix}")
    } else {
        format!("{origin}/.well-known/{suffix}{path}")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpaqueValue(String);

impl OpaqueValue {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransactionCodeInputMode {
    Numeric,
    Text,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionCode {
    pub input_mode: TransactionCodeInputMode,
    pub length: Option<u64>,
    pub description: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizationCodeGrant {
    pub issuer_state: Option<OpaqueValue>,
    pub authorization_server: Option<HttpsIdentifier>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreAuthorizedCodeGrant {
    pub pre_authorized_code: OpaqueValue,
    pub transaction_code: Option<TransactionCode>,
    pub authorization_server: Option<HttpsIdentifier>,
}

/// Whether the offer explicitly named grants or delegates grant determination to AS metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OfferGrantSource {
    Explicit,
    AuthorizationServerMetadata,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialOffer {
    pub credential_issuer: HttpsIdentifier,
    pub credential_configuration_ids: Vec<String>,
    pub authorization_code: Option<AuthorizationCodeGrant>,
    pub pre_authorized_code: Option<PreAuthorizedCodeGrant>,
    pub grant_source: OfferGrantSource,
}

impl CredentialOffer {
    pub fn authorization_code_eligible(&self) -> bool {
        self.authorization_code.is_some()
            || self.grant_source == OfferGrantSource::AuthorizationServerMetadata
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OfferError {
    Json(JsonBoundaryError),
    MissingField(&'static str),
    InvalidField(&'static str),
    EmptyCollection(&'static str),
    TooManyValues(&'static str),
    DuplicateValue(&'static str),
    ValueTooLong(&'static str),
    InvalidIssuer(UrlSyntaxError),
}

impl From<JsonBoundaryError> for OfferError {
    fn from(value: JsonBoundaryError) -> Self {
        Self::Json(value)
    }
}

pub fn parse_credential_offer(input: &[u8]) -> Result<CredentialOffer, OfferError> {
    parse_credential_offer_with_limits(input, DEFAULT_JSON_LIMITS)
}

pub fn parse_credential_offer_with_limits(
    input: &[u8],
    limits: JsonLimits,
) -> Result<CredentialOffer, OfferError> {
    let object = bounded_json::parse_object(input, limits)?;
    let issuer_text = offer_required_string(&object, "credential_issuer")?;
    let credential_issuer =
        HttpsIdentifier::parse(issuer_text).map_err(OfferError::InvalidIssuer)?;

    let configuration_values = object
        .get("credential_configuration_ids")
        .ok_or(OfferError::MissingField("credential_configuration_ids"))?
        .as_array()
        .ok_or(OfferError::InvalidField("credential_configuration_ids"))?;
    if configuration_values.is_empty() {
        return Err(OfferError::EmptyCollection("credential_configuration_ids"));
    }
    if configuration_values.len() > MAX_CONFIGURATION_IDS {
        return Err(OfferError::TooManyValues("credential_configuration_ids"));
    }
    let mut credential_configuration_ids = Vec::with_capacity(configuration_values.len());
    for value in configuration_values {
        let id = value
            .as_str()
            .ok_or(OfferError::InvalidField("credential_configuration_ids"))?;
        validate_bounded_text(id, MAX_CONFIGURATION_ID_BYTES, false)
            .map_err(|issue| offer_text_error("credential_configuration_ids", issue))?;
        if credential_configuration_ids
            .iter()
            .any(|existing| existing == id)
        {
            return Err(OfferError::DuplicateValue("credential_configuration_ids"));
        }
        credential_configuration_ids.push(id.to_owned());
    }

    let mut authorization_code = None;
    let mut pre_authorized_code = None;
    let mut grant_source = OfferGrantSource::AuthorizationServerMetadata;
    if let Some(grants) = object.get("grants") {
        let grants = grants
            .as_object()
            .ok_or(OfferError::InvalidField("grants"))?;
        if !grants.is_empty() {
            grant_source = OfferGrantSource::Explicit;
        }
        if let Some(grant) = grants.get(AUTHORIZATION_CODE_GRANT) {
            authorization_code = Some(parse_authorization_code_grant(grant)?);
        }
        if let Some(grant) = grants.get(PRE_AUTHORIZED_CODE_GRANT) {
            pre_authorized_code = Some(parse_pre_authorized_code_grant(grant)?);
        }
    }

    Ok(CredentialOffer {
        credential_issuer,
        credential_configuration_ids,
        authorization_code,
        pre_authorized_code,
        grant_source,
    })
}

fn parse_authorization_code_grant(value: &Value) -> Result<AuthorizationCodeGrant, OfferError> {
    let object = value
        .as_object()
        .ok_or(OfferError::InvalidField("authorization_code"))?;
    let issuer_state = object
        .get("issuer_state")
        .map(|value| offer_opaque(value, "issuer_state", true))
        .transpose()?;
    let authorization_server = object
        .get("authorization_server")
        .map(|value| offer_identifier(value, "authorization_server"))
        .transpose()?;
    Ok(AuthorizationCodeGrant {
        issuer_state,
        authorization_server,
    })
}

fn parse_pre_authorized_code_grant(value: &Value) -> Result<PreAuthorizedCodeGrant, OfferError> {
    let object = value
        .as_object()
        .ok_or(OfferError::InvalidField("pre-authorized_code_grant"))?;
    let pre_authorized_code = offer_opaque(
        object
            .get("pre-authorized_code")
            .ok_or(OfferError::MissingField("pre-authorized_code"))?,
        "pre-authorized_code",
        false,
    )?;
    let transaction_code = object
        .get("tx_code")
        .map(parse_transaction_code)
        .transpose()?;
    let authorization_server = object
        .get("authorization_server")
        .map(|value| offer_identifier(value, "authorization_server"))
        .transpose()?;
    Ok(PreAuthorizedCodeGrant {
        pre_authorized_code,
        transaction_code,
        authorization_server,
    })
}

fn parse_transaction_code(value: &Value) -> Result<TransactionCode, OfferError> {
    let object = value
        .as_object()
        .ok_or(OfferError::InvalidField("tx_code"))?;
    let input_mode = match object.get("input_mode") {
        None => TransactionCodeInputMode::Numeric,
        Some(Value::String(value)) if value == "numeric" => TransactionCodeInputMode::Numeric,
        Some(Value::String(value)) if value == "text" => TransactionCodeInputMode::Text,
        _ => return Err(OfferError::InvalidField("tx_code.input_mode")),
    };
    let length = object
        .get("length")
        .map(|value| {
            let value = value
                .as_u64()
                .ok_or(OfferError::InvalidField("tx_code.length"))?;
            if value == 0 || value > MAX_TRANSACTION_CODE_LENGTH {
                return Err(OfferError::InvalidField("tx_code.length"));
            }
            Ok(value)
        })
        .transpose()?;
    let description = object
        .get("description")
        .map(|value| {
            let value = value
                .as_str()
                .ok_or(OfferError::InvalidField("tx_code.description"))?;
            if value.chars().count() > 300 {
                return Err(OfferError::ValueTooLong("tx_code.description"));
            }
            validate_bounded_text(value, MAX_OPAQUE_VALUE_BYTES, true)
                .map_err(|issue| offer_text_error("tx_code.description", issue))?;
            Ok(value.to_owned())
        })
        .transpose()?;
    Ok(TransactionCode {
        input_mode,
        length,
        description,
    })
}

fn offer_required_string<'a>(
    object: &'a Map<String, Value>,
    field: &'static str,
) -> Result<&'a str, OfferError> {
    object
        .get(field)
        .ok_or(OfferError::MissingField(field))?
        .as_str()
        .ok_or(OfferError::InvalidField(field))
}

fn offer_opaque(
    value: &Value,
    field: &'static str,
    allow_empty: bool,
) -> Result<OpaqueValue, OfferError> {
    let value = value.as_str().ok_or(OfferError::InvalidField(field))?;
    validate_bounded_text(value, MAX_OPAQUE_VALUE_BYTES, allow_empty)
        .map_err(|issue| offer_text_error(field, issue))?;
    Ok(OpaqueValue(value.to_owned()))
}

fn offer_identifier(value: &Value, field: &'static str) -> Result<HttpsIdentifier, OfferError> {
    let value = value.as_str().ok_or(OfferError::InvalidField(field))?;
    HttpsIdentifier::parse(value).map_err(OfferError::InvalidIssuer)
}

#[derive(Clone, Copy)]
enum TextIssue {
    Empty,
    TooLong,
    Control,
}

fn validate_bounded_text(value: &str, max: usize, allow_empty: bool) -> Result<(), TextIssue> {
    if value.is_empty() && !allow_empty {
        return Err(TextIssue::Empty);
    }
    if value.len() > max {
        return Err(TextIssue::TooLong);
    }
    if value.chars().any(char::is_control) {
        return Err(TextIssue::Control);
    }
    Ok(())
}

fn offer_text_error(field: &'static str, issue: TextIssue) -> OfferError {
    match issue {
        TextIssue::TooLong => OfferError::ValueTooLong(field),
        TextIssue::Empty | TextIssue::Control => OfferError::InvalidField(field),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AlgorithmIdentifier {
    Jose(String),
    Cose(i64),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyAttestationRequirement {
    pub key_storage: Option<Vec<String>>,
    pub user_authentication: Option<Vec<String>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofTypeMetadata {
    pub signing_algorithms: Vec<AlgorithmIdentifier>,
    pub key_attestations_required: Option<KeyAttestationRequirement>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialConfiguration {
    pub format: String,
    pub scope: Option<String>,
    pub cryptographic_binding_methods_supported: Option<Vec<String>>,
    pub credential_signing_algorithms: Option<Vec<AlgorithmIdentifier>>,
    pub proof_types_supported: Option<BTreeMap<String, ProofTypeMetadata>>,
    pub doctype: Option<String>,
    pub vct: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IssuerFeatureFlags {
    pub nonce_endpoint: bool,
    pub deferred_credential_endpoint: bool,
    pub notification_endpoint: bool,
    pub batch_credential_issuance: bool,
    pub credential_request_encryption_required: bool,
    pub credential_response_encryption_required: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialIssuerMetadata {
    pub credential_issuer: HttpsIdentifier,
    pub authorization_servers: Vec<HttpsIdentifier>,
    pub credential_endpoint: HttpsEndpoint,
    pub nonce_endpoint: Option<HttpsEndpoint>,
    pub deferred_credential_endpoint: Option<HttpsEndpoint>,
    pub notification_endpoint: Option<HttpsEndpoint>,
    pub credential_configurations_supported: BTreeMap<String, CredentialConfiguration>,
    pub features: IssuerFeatureFlags,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MetadataError {
    Json(JsonBoundaryError),
    MissingField(&'static str),
    InvalidField(&'static str),
    EmptyCollection(&'static str),
    TooManyValues(&'static str),
    DuplicateValue(&'static str),
    ValueTooLong(&'static str),
    InvalidUrl(&'static str, UrlSyntaxError),
    IdentifierMismatch,
}

impl From<JsonBoundaryError> for MetadataError {
    fn from(value: JsonBoundaryError) -> Self {
        Self::Json(value)
    }
}

pub fn parse_credential_issuer_metadata(
    input: &[u8],
    expected_issuer: &str,
) -> Result<CredentialIssuerMetadata, MetadataError> {
    parse_credential_issuer_metadata_with_limits(input, expected_issuer, DEFAULT_JSON_LIMITS)
}

pub fn parse_credential_issuer_metadata_with_limits(
    input: &[u8],
    expected_issuer: &str,
    limits: JsonLimits,
) -> Result<CredentialIssuerMetadata, MetadataError> {
    let expected = HttpsIdentifier::parse(expected_issuer)
        .map_err(|error| MetadataError::InvalidUrl("expected_issuer", error))?;
    let object = bounded_json::parse_object(input, limits)?;
    let issuer_text = metadata_required_string(&object, "credential_issuer")?;
    let credential_issuer = HttpsIdentifier::parse(issuer_text)
        .map_err(|error| MetadataError::InvalidUrl("credential_issuer", error))?;
    if credential_issuer.as_str() != expected.as_str() {
        return Err(MetadataError::IdentifierMismatch);
    }

    let authorization_servers = match object.get("authorization_servers") {
        Some(value) => {
            parse_identifier_list(value, "authorization_servers", MAX_AUTHORIZATION_SERVERS)?
        }
        None => vec![credential_issuer.clone()],
    };
    let credential_endpoint = metadata_endpoint(&object, "credential_endpoint", true)?
        .ok_or(MetadataError::MissingField("credential_endpoint"))?;
    let nonce_endpoint = metadata_endpoint(&object, "nonce_endpoint", false)?;
    let deferred_credential_endpoint =
        metadata_endpoint(&object, "deferred_credential_endpoint", false)?;
    let notification_endpoint = metadata_endpoint(&object, "notification_endpoint", false)?;

    let request_encryption_required = object
        .get("credential_request_encryption")
        .map(validate_request_encryption)
        .transpose()?
        .unwrap_or(false);
    let response_encryption_required = object
        .get("credential_response_encryption")
        .map(validate_response_encryption)
        .transpose()?
        .unwrap_or(false);
    let batch_credential_issuance = object
        .get("batch_credential_issuance")
        .map(validate_batch_issuance)
        .transpose()?
        .is_some();
    if let Some(display) = object.get("display") {
        validate_nonempty_object_array(display, "display")?;
    }

    let configurations_value =
        object
            .get("credential_configurations_supported")
            .ok_or(MetadataError::MissingField(
                "credential_configurations_supported",
            ))?;
    let configurations_object =
        configurations_value
            .as_object()
            .ok_or(MetadataError::InvalidField(
                "credential_configurations_supported",
            ))?;
    if configurations_object.is_empty() {
        return Err(MetadataError::EmptyCollection(
            "credential_configurations_supported",
        ));
    }
    if configurations_object.len() > MAX_CONFIGURATIONS {
        return Err(MetadataError::TooManyValues(
            "credential_configurations_supported",
        ));
    }
    let mut credential_configurations_supported = BTreeMap::new();
    for (id, value) in configurations_object {
        validate_bounded_text(id, MAX_CONFIGURATION_ID_BYTES, false)
            .map_err(|issue| metadata_text_error("credential_configuration_id", issue))?;
        credential_configurations_supported
            .insert(id.clone(), parse_credential_configuration(value)?);
    }

    let features = IssuerFeatureFlags {
        nonce_endpoint: nonce_endpoint.is_some(),
        deferred_credential_endpoint: deferred_credential_endpoint.is_some(),
        notification_endpoint: notification_endpoint.is_some(),
        batch_credential_issuance,
        credential_request_encryption_required: request_encryption_required,
        credential_response_encryption_required: response_encryption_required,
    };
    Ok(CredentialIssuerMetadata {
        credential_issuer,
        authorization_servers,
        credential_endpoint,
        nonce_endpoint,
        deferred_credential_endpoint,
        notification_endpoint,
        credential_configurations_supported,
        features,
    })
}

fn parse_credential_configuration(value: &Value) -> Result<CredentialConfiguration, MetadataError> {
    let object = value
        .as_object()
        .ok_or(MetadataError::InvalidField("credential_configuration"))?;
    let format = metadata_required_string(object, "format")?;
    validate_bounded_text(format, 64, false)
        .map_err(|issue| metadata_text_error("format", issue))?;
    let scope = object
        .get("scope")
        .map(|value| metadata_bounded_string(value, "scope", MAX_SCOPE_BYTES))
        .transpose()?;
    if let Some(scope) = &scope {
        validate_scope_token(scope, "scope")?;
    }
    let cryptographic_binding_methods_supported = object
        .get("cryptographic_binding_methods_supported")
        .map(|value| {
            parse_string_list(
                value,
                "cryptographic_binding_methods_supported",
                MAX_LIST_VALUES,
                128,
            )
        })
        .transpose()?;
    let credential_signing_algorithms = object
        .get("credential_signing_alg_values_supported")
        .map(|value| {
            parse_algorithm_list(
                value,
                "credential_signing_alg_values_supported",
                MAX_LIST_VALUES,
            )
        })
        .transpose()?;
    let proof_types_supported = object
        .get("proof_types_supported")
        .map(parse_proof_types)
        .transpose()?;
    // OpenID4VCI requires proof metadata exactly when cryptographic key binding is advertised.
    if cryptographic_binding_methods_supported.is_some() != proof_types_supported.is_some() {
        return Err(MetadataError::InvalidField("proof_types_supported"));
    }
    let doctype = object
        .get("doctype")
        .map(|value| metadata_bounded_string(value, "doctype", MAX_CONFIGURATION_ID_BYTES))
        .transpose()?;
    let vct = object
        .get("vct")
        .map(|value| metadata_bounded_string(value, "vct", MAX_CONFIGURATION_ID_BYTES))
        .transpose()?;
    Ok(CredentialConfiguration {
        format: format.to_owned(),
        scope,
        cryptographic_binding_methods_supported,
        credential_signing_algorithms,
        proof_types_supported,
        doctype,
        vct,
    })
}

fn parse_proof_types(value: &Value) -> Result<BTreeMap<String, ProofTypeMetadata>, MetadataError> {
    let object = value
        .as_object()
        .ok_or(MetadataError::InvalidField("proof_types_supported"))?;
    if object.is_empty() {
        return Err(MetadataError::EmptyCollection("proof_types_supported"));
    }
    if object.len() > MAX_PROOF_TYPES {
        return Err(MetadataError::TooManyValues("proof_types_supported"));
    }
    let mut result = BTreeMap::new();
    for (proof_type, value) in object {
        validate_bounded_text(proof_type, 64, false)
            .map_err(|issue| metadata_text_error("proof_type", issue))?;
        let proof = value
            .as_object()
            .ok_or(MetadataError::InvalidField("proof_type"))?;
        let signing_algorithms =
            parse_algorithm_list(
                proof.get("proof_signing_alg_values_supported").ok_or(
                    MetadataError::MissingField("proof_signing_alg_values_supported"),
                )?,
                "proof_signing_alg_values_supported",
                MAX_LIST_VALUES,
            )?;
        let key_attestations_required = proof
            .get("key_attestations_required")
            .map(parse_key_attestation_requirement)
            .transpose()?;
        result.insert(
            proof_type.clone(),
            ProofTypeMetadata {
                signing_algorithms,
                key_attestations_required,
            },
        );
    }
    Ok(result)
}

fn parse_key_attestation_requirement(
    value: &Value,
) -> Result<KeyAttestationRequirement, MetadataError> {
    let object = value
        .as_object()
        .ok_or(MetadataError::InvalidField("key_attestations_required"))?;
    let key_storage = object
        .get("key_storage")
        .map(|value| parse_string_list(value, "key_storage", MAX_LIST_VALUES, 128))
        .transpose()?;
    let user_authentication = object
        .get("user_authentication")
        .map(|value| parse_string_list(value, "user_authentication", MAX_LIST_VALUES, 128))
        .transpose()?;
    if let Some(period) = object.get("preferred_key_storage_status_period") {
        if period.as_u64().is_none() {
            return Err(MetadataError::InvalidField(
                "preferred_key_storage_status_period",
            ));
        }
    }
    Ok(KeyAttestationRequirement {
        key_storage,
        user_authentication,
    })
}

fn validate_request_encryption(value: &Value) -> Result<bool, MetadataError> {
    let object = value
        .as_object()
        .ok_or(MetadataError::InvalidField("credential_request_encryption"))?;
    let jwks = object
        .get("jwks")
        .and_then(Value::as_object)
        .ok_or(MetadataError::MissingField(
            "credential_request_encryption.jwks",
        ))?;
    let keys = jwks
        .get("keys")
        .and_then(Value::as_array)
        .ok_or(MetadataError::MissingField(
            "credential_request_encryption.jwks.keys",
        ))?;
    if keys.is_empty() {
        return Err(MetadataError::EmptyCollection(
            "credential_request_encryption.jwks.keys",
        ));
    }
    if keys.len() > MAX_LIST_VALUES {
        return Err(MetadataError::TooManyValues(
            "credential_request_encryption.jwks.keys",
        ));
    }
    let mut kids = BTreeSet::new();
    for key in keys {
        let key = key.as_object().ok_or(MetadataError::InvalidField(
            "credential_request_encryption.jwks.keys",
        ))?;
        let kid = metadata_required_string(key, "kid")?;
        validate_bounded_text(kid, 256, false)
            .map_err(|issue| metadata_text_error("kid", issue))?;
        if !kids.insert(kid) {
            return Err(MetadataError::DuplicateValue("kid"));
        }
    }
    parse_string_list(
        object
            .get("enc_values_supported")
            .ok_or(MetadataError::MissingField("enc_values_supported"))?,
        "enc_values_supported",
        MAX_LIST_VALUES,
        128,
    )?;
    if let Some(zip) = object.get("zip_values_supported") {
        parse_string_list(zip, "zip_values_supported", MAX_LIST_VALUES, 128)?;
    }
    object
        .get("encryption_required")
        .and_then(Value::as_bool)
        .ok_or(MetadataError::MissingField("encryption_required"))
}

fn validate_response_encryption(value: &Value) -> Result<bool, MetadataError> {
    let object = value.as_object().ok_or(MetadataError::InvalidField(
        "credential_response_encryption",
    ))?;
    for field in ["alg_values_supported", "enc_values_supported"] {
        parse_string_list(
            object
                .get(field)
                .ok_or(MetadataError::MissingField(field))?,
            field,
            MAX_LIST_VALUES,
            128,
        )?;
    }
    if let Some(zip) = object.get("zip_values_supported") {
        parse_string_list(zip, "zip_values_supported", MAX_LIST_VALUES, 128)?;
    }
    object
        .get("encryption_required")
        .and_then(Value::as_bool)
        .ok_or(MetadataError::MissingField("encryption_required"))
}

fn validate_batch_issuance(value: &Value) -> Result<u64, MetadataError> {
    let object = value
        .as_object()
        .ok_or(MetadataError::InvalidField("batch_credential_issuance"))?;
    let size = object
        .get("batch_size")
        .and_then(Value::as_u64)
        .ok_or(MetadataError::MissingField("batch_size"))?;
    if !(2..=MAX_BATCH_SIZE).contains(&size) {
        return Err(MetadataError::InvalidField("batch_size"));
    }
    Ok(size)
}

fn validate_nonempty_object_array(value: &Value, field: &'static str) -> Result<(), MetadataError> {
    let values = value.as_array().ok_or(MetadataError::InvalidField(field))?;
    if values.is_empty() {
        return Err(MetadataError::EmptyCollection(field));
    }
    if values.len() > MAX_LIST_VALUES {
        return Err(MetadataError::TooManyValues(field));
    }
    if values.iter().any(|value| !value.is_object()) {
        return Err(MetadataError::InvalidField(field));
    }
    Ok(())
}

fn parse_identifier_list(
    value: &Value,
    field: &'static str,
    max: usize,
) -> Result<Vec<HttpsIdentifier>, MetadataError> {
    let values = value.as_array().ok_or(MetadataError::InvalidField(field))?;
    if values.is_empty() {
        return Err(MetadataError::EmptyCollection(field));
    }
    if values.len() > max {
        return Err(MetadataError::TooManyValues(field));
    }
    let mut result = Vec::with_capacity(values.len());
    for value in values {
        let value = value.as_str().ok_or(MetadataError::InvalidField(field))?;
        let identifier = HttpsIdentifier::parse(value)
            .map_err(|error| MetadataError::InvalidUrl(field, error))?;
        if result.iter().any(|existing| existing == &identifier) {
            return Err(MetadataError::DuplicateValue(field));
        }
        result.push(identifier);
    }
    Ok(result)
}

fn parse_string_list(
    value: &Value,
    field: &'static str,
    max_values: usize,
    max_value_bytes: usize,
) -> Result<Vec<String>, MetadataError> {
    let values = value.as_array().ok_or(MetadataError::InvalidField(field))?;
    if values.is_empty() {
        return Err(MetadataError::EmptyCollection(field));
    }
    if values.len() > max_values {
        return Err(MetadataError::TooManyValues(field));
    }
    let mut result = Vec::with_capacity(values.len());
    for value in values {
        let value = value.as_str().ok_or(MetadataError::InvalidField(field))?;
        validate_bounded_text(value, max_value_bytes, false)
            .map_err(|issue| metadata_text_error(field, issue))?;
        if result.iter().any(|existing| existing == value) {
            return Err(MetadataError::DuplicateValue(field));
        }
        result.push(value.to_owned());
    }
    Ok(result)
}

fn parse_algorithm_list(
    value: &Value,
    field: &'static str,
    max_values: usize,
) -> Result<Vec<AlgorithmIdentifier>, MetadataError> {
    let values = value.as_array().ok_or(MetadataError::InvalidField(field))?;
    if values.is_empty() {
        return Err(MetadataError::EmptyCollection(field));
    }
    if values.len() > max_values {
        return Err(MetadataError::TooManyValues(field));
    }
    let mut result = Vec::with_capacity(values.len());
    for value in values {
        let algorithm = if let Some(value) = value.as_str() {
            validate_bounded_text(value, 128, false)
                .map_err(|issue| metadata_text_error(field, issue))?;
            AlgorithmIdentifier::Jose(value.to_owned())
        } else if let Some(value) = value.as_i64() {
            AlgorithmIdentifier::Cose(value)
        } else {
            return Err(MetadataError::InvalidField(field));
        };
        if result.contains(&algorithm) {
            return Err(MetadataError::DuplicateValue(field));
        }
        result.push(algorithm);
    }
    Ok(result)
}

fn metadata_required_string<'a>(
    object: &'a Map<String, Value>,
    field: &'static str,
) -> Result<&'a str, MetadataError> {
    object
        .get(field)
        .ok_or(MetadataError::MissingField(field))?
        .as_str()
        .ok_or(MetadataError::InvalidField(field))
}

fn metadata_bounded_string(
    value: &Value,
    field: &'static str,
    max: usize,
) -> Result<String, MetadataError> {
    let value = value.as_str().ok_or(MetadataError::InvalidField(field))?;
    validate_bounded_text(value, max, false).map_err(|issue| metadata_text_error(field, issue))?;
    Ok(value.to_owned())
}

fn metadata_endpoint(
    object: &Map<String, Value>,
    field: &'static str,
    required: bool,
) -> Result<Option<HttpsEndpoint>, MetadataError> {
    let Some(value) = object.get(field) else {
        if required {
            return Err(MetadataError::MissingField(field));
        }
        return Ok(None);
    };
    let value = value.as_str().ok_or(MetadataError::InvalidField(field))?;
    HttpsEndpoint::parse(value)
        .map(Some)
        .map_err(|error| MetadataError::InvalidUrl(field, error))
}

fn metadata_text_error(field: &'static str, issue: TextIssue) -> MetadataError {
    match issue {
        TextIssue::TooLong => MetadataError::ValueTooLong(field),
        TextIssue::Empty | TextIssue::Control => MetadataError::InvalidField(field),
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AuthorizationServerFeatureFlags {
    pub authorization_code: bool,
    pub response_type_code: bool,
    pub par: bool,
    pub par_required: bool,
    pub pkce_s256: bool,
    pub dpop_es256: bool,
    pub authorization_response_issuer: bool,
}

impl AuthorizationServerFeatureFlags {
    fn supports_auto_selected_authorization_code(self) -> bool {
        self.authorization_code
            && self.response_type_code
            && self.par
            && self.pkce_s256
            && self.dpop_es256
            && self.authorization_response_issuer
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizationServerMetadata {
    pub issuer: HttpsIdentifier,
    pub authorization_endpoint: Option<HttpsEndpoint>,
    pub token_endpoint: Option<HttpsEndpoint>,
    pub pushed_authorization_request_endpoint: Option<HttpsEndpoint>,
    pub jwks_uri: Option<HttpsEndpoint>,
    pub scopes_supported: Option<Vec<String>>,
    pub grant_types_supported: Vec<String>,
    pub response_types_supported: Vec<String>,
    pub code_challenge_methods_supported: Vec<String>,
    pub dpop_signing_alg_values_supported: Vec<String>,
    pub features: AuthorizationServerFeatureFlags,
}

pub fn parse_authorization_server_metadata(
    input: &[u8],
    expected_issuer: &str,
) -> Result<AuthorizationServerMetadata, MetadataError> {
    parse_authorization_server_metadata_with_limits(input, expected_issuer, DEFAULT_JSON_LIMITS)
}

pub fn parse_authorization_server_metadata_with_limits(
    input: &[u8],
    expected_issuer: &str,
    limits: JsonLimits,
) -> Result<AuthorizationServerMetadata, MetadataError> {
    let expected = HttpsIdentifier::parse(expected_issuer)
        .map_err(|error| MetadataError::InvalidUrl("expected_issuer", error))?;
    let object = bounded_json::parse_object(input, limits)?;
    let issuer_value = metadata_required_string(&object, "issuer")?;
    let issuer = HttpsIdentifier::parse(issuer_value)
        .map_err(|error| MetadataError::InvalidUrl("issuer", error))?;
    if issuer.as_str() != expected.as_str() {
        return Err(MetadataError::IdentifierMismatch);
    }

    let authorization_endpoint = metadata_endpoint(&object, "authorization_endpoint", false)?;
    let token_endpoint = metadata_endpoint(&object, "token_endpoint", false)?;
    let pushed_authorization_request_endpoint =
        metadata_endpoint(&object, "pushed_authorization_request_endpoint", false)?;
    let jwks_uri = metadata_endpoint(&object, "jwks_uri", false)?;
    let response_types_supported = parse_string_list(
        object
            .get("response_types_supported")
            .ok_or(MetadataError::MissingField("response_types_supported"))?,
        "response_types_supported",
        MAX_LIST_VALUES,
        128,
    )?;
    let grant_types_supported = match object.get("grant_types_supported") {
        Some(value) => parse_string_list(value, "grant_types_supported", MAX_LIST_VALUES, 128)?,
        None => vec!["authorization_code".to_owned(), "implicit".to_owned()],
    };
    let scopes_supported = object
        .get("scopes_supported")
        .map(|value| -> Result<Vec<String>, MetadataError> {
            let scopes =
                parse_string_list(value, "scopes_supported", MAX_LIST_VALUES, MAX_SCOPE_BYTES)?;
            for scope in &scopes {
                validate_scope_token(scope, "scopes_supported")?;
            }
            Ok(scopes)
        })
        .transpose()?;
    let code_challenge_methods_supported = object
        .get("code_challenge_methods_supported")
        .map(|value| {
            parse_string_list(
                value,
                "code_challenge_methods_supported",
                MAX_LIST_VALUES,
                128,
            )
        })
        .transpose()?
        .unwrap_or_default();
    let dpop_signing_alg_values_supported = object
        .get("dpop_signing_alg_values_supported")
        .map(|value| {
            parse_string_list(
                value,
                "dpop_signing_alg_values_supported",
                MAX_LIST_VALUES,
                128,
            )
        })
        .transpose()?
        .unwrap_or_default();
    let par_required = object
        .get("require_pushed_authorization_requests")
        .map(|value| {
            value.as_bool().ok_or(MetadataError::InvalidField(
                "require_pushed_authorization_requests",
            ))
        })
        .transpose()?
        .unwrap_or(false);
    let authorization_response_issuer = object
        .get("authorization_response_iss_parameter_supported")
        .map(|value| {
            value.as_bool().ok_or(MetadataError::InvalidField(
                "authorization_response_iss_parameter_supported",
            ))
        })
        .transpose()?
        .unwrap_or(false);

    let features = AuthorizationServerFeatureFlags {
        authorization_code: grant_types_supported
            .iter()
            .any(|grant| grant == AUTHORIZATION_CODE_GRANT),
        response_type_code: response_types_supported
            .iter()
            .any(|response| response == "code"),
        par: pushed_authorization_request_endpoint.is_some(),
        par_required,
        pkce_s256: code_challenge_methods_supported
            .iter()
            .any(|method| method == "S256"),
        dpop_es256: dpop_signing_alg_values_supported
            .iter()
            .any(|algorithm| algorithm == "ES256"),
        authorization_response_issuer,
    };
    Ok(AuthorizationServerMetadata {
        issuer,
        authorization_endpoint,
        token_endpoint,
        pushed_authorization_request_endpoint,
        jwks_uri,
        scopes_supported,
        grant_types_supported,
        response_types_supported,
        code_challenge_methods_supported,
        dpop_signing_alg_values_supported,
        features,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GermanPidFormat {
    MsoMdoc,
    DcSdJwt,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HolderBindingMethod {
    CoseKey,
    Jwk,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialSigningAlgorithm {
    CoseEs256,
    JoseEs256,
}

/// Parsing and WebPKI transport do not establish authorization to issue a German PID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PidProviderTrust {
    Unresolved,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GermanPidIssuancePlan {
    pub credential_issuer: HttpsIdentifier,
    pub authorization_server: HttpsIdentifier,
    pub configuration_id: String,
    pub format: GermanPidFormat,
    pub scope: String,
    pub holder_binding: HolderBindingMethod,
    pub credential_signing_algorithm: CredentialSigningAlgorithm,
    pub proof_signing_algorithm: String,
    pub credential_endpoint: HttpsEndpoint,
    pub nonce_endpoint: HttpsEndpoint,
    pub authorization_endpoint: HttpsEndpoint,
    pub token_endpoint: HttpsEndpoint,
    pub pushed_authorization_request_endpoint: HttpsEndpoint,
    pub pid_provider_trust: PidProviderTrust,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProfileSelectionError {
    OfferIssuerMismatch,
    AuthorizationCodeRequired,
    ConfigurationNotOffered,
    ConfigurationUnknown,
    UnsupportedPidConfiguration,
    MixedAlgorithmIdentifiers,
    ScopeMissing,
    BindingMethodMissing,
    CredentialSigningAlgorithmMissing,
    JwtProofMissing,
    ProofAlgorithmMissing,
    KeyAttestationMissing,
    HighKeyStorageMissing,
    HighUserAuthenticationMissing,
    NonceEndpointMissing,
    CredentialRequestEncryptionRequired,
    CredentialResponseEncryptionRequired,
    AuthorizationServerHintNotAllowed,
    AuthorizationServerHintMismatch,
    AuthorizationServerNotAdvertised,
    AuthorizationServerMetadataMissing,
    AmbiguousAuthorizationServer,
    AuthorizationCodeUnsupported,
    ResponseTypeCodeUnsupported,
    AuthorizationEndpointMissing,
    TokenEndpointMissing,
    ParUnsupported,
    PkceS256Unsupported,
    DpopEs256Unsupported,
    AuthorizationResponseIssuerUnsupported,
    ScopeUnsupportedByAuthorizationServer,
}

pub fn select_authorization_server<'a>(
    offer: &CredentialOffer,
    issuer: &CredentialIssuerMetadata,
    servers: &'a [AuthorizationServerMetadata],
    required_scope: Option<&str>,
) -> Result<&'a AuthorizationServerMetadata, ProfileSelectionError> {
    if offer.credential_issuer != issuer.credential_issuer {
        return Err(ProfileSelectionError::OfferIssuerMismatch);
    }
    if !offer.authorization_code_eligible() {
        return Err(ProfileSelectionError::AuthorizationCodeRequired);
    }
    let grant = offer.authorization_code.as_ref();
    let advertised: BTreeSet<&str> = issuer
        .authorization_servers
        .iter()
        .map(HttpsIdentifier::as_str)
        .collect();
    let mut seen = BTreeSet::new();
    for server in servers {
        if !advertised.contains(server.issuer.as_str()) {
            return Err(ProfileSelectionError::AuthorizationServerNotAdvertised);
        }
        if !seen.insert(server.issuer.as_str()) {
            return Err(ProfileSelectionError::AmbiguousAuthorizationServer);
        }
    }

    let target = if let Some(hint) = grant.and_then(|grant| grant.authorization_server.as_ref()) {
        if issuer.authorization_servers.len() <= 1 {
            return Err(ProfileSelectionError::AuthorizationServerHintNotAllowed);
        }
        if !advertised.contains(hint.as_str()) {
            return Err(ProfileSelectionError::AuthorizationServerHintMismatch);
        }
        hint.as_str()
    } else if issuer.authorization_servers.len() == 1 {
        issuer.authorization_servers[0].as_str()
    } else {
        if servers.len() != issuer.authorization_servers.len()
            || issuer
                .authorization_servers
                .iter()
                .any(|advertised| !servers.iter().any(|server| server.issuer == *advertised))
        {
            return Err(ProfileSelectionError::AuthorizationServerMetadataMissing);
        }
        let mut candidates = servers.iter().filter(|server| {
            server.features.supports_auto_selected_authorization_code()
                && server.authorization_endpoint.is_some()
                && server.token_endpoint.is_some()
                && authorization_server_supports_scope(server, required_scope)
        });
        let candidate = candidates
            .next()
            .ok_or(ProfileSelectionError::AmbiguousAuthorizationServer)?;
        if candidates.next().is_some() {
            return Err(ProfileSelectionError::AmbiguousAuthorizationServer);
        }
        candidate.issuer.as_str()
    };
    let selected = servers
        .iter()
        .find(|server| server.issuer.as_str() == target)
        .ok_or(ProfileSelectionError::AuthorizationServerMetadataMissing)?;
    if !authorization_server_supports_scope(selected, required_scope) {
        return Err(ProfileSelectionError::ScopeUnsupportedByAuthorizationServer);
    }
    Ok(selected)
}

/// Select one explicitly chosen, offered PID configuration for German first enrolment.
///
/// Pre-authorized-only offers are rejected. `selected_configuration_id` is an exact, opaque match;
/// the API never silently chooses between two offered PID formats.
pub fn select_german_first_enrolment(
    offer: &CredentialOffer,
    issuer: &CredentialIssuerMetadata,
    authorization_servers: &[AuthorizationServerMetadata],
    selected_configuration_id: &str,
) -> Result<GermanPidIssuancePlan, ProfileSelectionError> {
    if !offer.authorization_code_eligible() {
        return Err(ProfileSelectionError::AuthorizationCodeRequired);
    }
    if offer.credential_issuer != issuer.credential_issuer {
        return Err(ProfileSelectionError::OfferIssuerMismatch);
    }
    if !offer
        .credential_configuration_ids
        .iter()
        .any(|id| id == selected_configuration_id)
    {
        return Err(ProfileSelectionError::ConfigurationNotOffered);
    }
    let configuration = issuer
        .credential_configurations_supported
        .get(selected_configuration_id)
        .ok_or(ProfileSelectionError::ConfigurationUnknown)?;
    if issuer.features.credential_request_encryption_required {
        return Err(ProfileSelectionError::CredentialRequestEncryptionRequired);
    }
    if issuer.features.credential_response_encryption_required {
        return Err(ProfileSelectionError::CredentialResponseEncryptionRequired);
    }
    let nonce_endpoint = issuer
        .nonce_endpoint
        .clone()
        .ok_or(ProfileSelectionError::NonceEndpointMissing)?;

    let scope = configuration
        .scope
        .clone()
        .filter(|scope| !scope.is_empty())
        .ok_or(ProfileSelectionError::ScopeMissing)?;
    let bindings = configuration
        .cryptographic_binding_methods_supported
        .as_ref()
        .ok_or(ProfileSelectionError::BindingMethodMissing)?;
    let credential_algorithms = configuration
        .credential_signing_algorithms
        .as_ref()
        .ok_or(ProfileSelectionError::CredentialSigningAlgorithmMissing)?;
    let proof_types = configuration
        .proof_types_supported
        .as_ref()
        .ok_or(ProfileSelectionError::JwtProofMissing)?;
    let jwt = proof_types
        .get("jwt")
        .ok_or(ProfileSelectionError::JwtProofMissing)?;
    if !jwt
        .signing_algorithms
        .iter()
        .any(|algorithm| matches!(algorithm, AlgorithmIdentifier::Jose(value) if value == "ES256"))
    {
        return Err(ProfileSelectionError::ProofAlgorithmMissing);
    }
    if jwt
        .signing_algorithms
        .iter()
        .any(|algorithm| matches!(algorithm, AlgorithmIdentifier::Cose(_)))
    {
        return Err(ProfileSelectionError::MixedAlgorithmIdentifiers);
    }
    let key_attestation = jwt
        .key_attestations_required
        .as_ref()
        .ok_or(ProfileSelectionError::KeyAttestationMissing)?;
    if !contains_value(key_attestation.key_storage.as_deref(), "iso_18045_high") {
        return Err(ProfileSelectionError::HighKeyStorageMissing);
    }
    if !contains_value(
        key_attestation.user_authentication.as_deref(),
        "iso_18045_high",
    ) {
        return Err(ProfileSelectionError::HighUserAuthenticationMissing);
    }

    let (format, holder_binding, credential_signing_algorithm) = match configuration.format.as_str()
    {
        "mso_mdoc"
            if configuration.doctype.as_deref() == Some(MDOC_PID_DOCTYPE)
                && configuration.vct.is_none() =>
        {
            if !bindings.iter().any(|binding| binding == "cose_key") {
                return Err(ProfileSelectionError::BindingMethodMissing);
            }
            if credential_algorithms
                .iter()
                .any(|algorithm| matches!(algorithm, AlgorithmIdentifier::Jose(_)))
            {
                return Err(ProfileSelectionError::MixedAlgorithmIdentifiers);
            }
            if !credential_algorithms.contains(&AlgorithmIdentifier::Cose(-7)) {
                return Err(ProfileSelectionError::CredentialSigningAlgorithmMissing);
            }
            (
                GermanPidFormat::MsoMdoc,
                HolderBindingMethod::CoseKey,
                CredentialSigningAlgorithm::CoseEs256,
            )
        }
        "dc+sd-jwt"
            if configuration.vct.as_deref() == Some(SD_JWT_PID_VCT)
                && configuration.doctype.is_none() =>
        {
            if !bindings.iter().any(|binding| binding == "jwk") {
                return Err(ProfileSelectionError::BindingMethodMissing);
            }
            if credential_algorithms
                .iter()
                .any(|algorithm| matches!(algorithm, AlgorithmIdentifier::Cose(_)))
            {
                return Err(ProfileSelectionError::MixedAlgorithmIdentifiers);
            }
            if !credential_algorithms.iter().any(
                |algorithm| matches!(algorithm, AlgorithmIdentifier::Jose(value) if value == "ES256"),
            ) {
                return Err(ProfileSelectionError::CredentialSigningAlgorithmMissing);
            }
            (
                GermanPidFormat::DcSdJwt,
                HolderBindingMethod::Jwk,
                CredentialSigningAlgorithm::JoseEs256,
            )
        }
        _ => return Err(ProfileSelectionError::UnsupportedPidConfiguration),
    };

    let authorization_server =
        select_authorization_server(offer, issuer, authorization_servers, Some(&scope))?;
    if !authorization_server.features.authorization_code {
        return Err(ProfileSelectionError::AuthorizationCodeUnsupported);
    }
    if !authorization_server.features.response_type_code {
        return Err(ProfileSelectionError::ResponseTypeCodeUnsupported);
    }
    let authorization_endpoint = authorization_server
        .authorization_endpoint
        .clone()
        .ok_or(ProfileSelectionError::AuthorizationEndpointMissing)?;
    let token_endpoint = authorization_server
        .token_endpoint
        .clone()
        .ok_or(ProfileSelectionError::TokenEndpointMissing)?;
    let pushed_authorization_request_endpoint = authorization_server
        .pushed_authorization_request_endpoint
        .clone()
        .ok_or(ProfileSelectionError::ParUnsupported)?;
    if !authorization_server.features.pkce_s256 {
        return Err(ProfileSelectionError::PkceS256Unsupported);
    }
    if !authorization_server.features.dpop_es256 {
        return Err(ProfileSelectionError::DpopEs256Unsupported);
    }
    if !authorization_server.features.authorization_response_issuer {
        return Err(ProfileSelectionError::AuthorizationResponseIssuerUnsupported);
    }

    Ok(GermanPidIssuancePlan {
        credential_issuer: issuer.credential_issuer.clone(),
        authorization_server: authorization_server.issuer.clone(),
        configuration_id: selected_configuration_id.to_owned(),
        format,
        scope,
        holder_binding,
        credential_signing_algorithm,
        proof_signing_algorithm: "ES256".to_owned(),
        credential_endpoint: issuer.credential_endpoint.clone(),
        nonce_endpoint,
        authorization_endpoint,
        token_endpoint,
        pushed_authorization_request_endpoint,
        pid_provider_trust: PidProviderTrust::Unresolved,
    })
}

fn contains_value(values: Option<&[String]>, expected: &str) -> bool {
    values
        .unwrap_or_default()
        .iter()
        .any(|value| value == expected)
}

fn authorization_server_supports_scope(
    server: &AuthorizationServerMetadata,
    required_scope: Option<&str>,
) -> bool {
    let Some(required_scope) = required_scope else {
        return true;
    };
    match &server.scopes_supported {
        None => true,
        Some(scopes) => scopes.iter().any(|scope| scope == required_scope),
    }
}

fn validate_scope_token(value: &str, field: &'static str) -> Result<(), MetadataError> {
    if value
        .bytes()
        .all(|byte| byte == 0x21 || (0x23..=0x5b).contains(&byte) || (0x5d..=0x7e).contains(&byte))
    {
        Ok(())
    } else {
        Err(MetadataError::InvalidField(field))
    }
}
