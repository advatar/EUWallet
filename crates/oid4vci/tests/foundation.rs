use oid4vci::bounded_json::{
    parse_object, JsonBoundaryError, JsonLimits, ABSOLUTE_MAX_CONTAINER_ENTRIES,
    ABSOLUTE_MAX_JSON_BYTES, ABSOLUTE_MAX_JSON_DEPTH, ABSOLUTE_MAX_STRING_BYTES,
};
use oid4vci::foundation::{
    parse_authorization_server_metadata, parse_credential_issuer_metadata, parse_credential_offer,
    select_authorization_server, select_german_first_enrolment, CredentialSigningAlgorithm,
    GermanPidFormat, HolderBindingMethod, HttpsEndpoint, HttpsIdentifier, MetadataError,
    OfferError, OfferGrantSource, PidProviderTrust, ProfileSelectionError,
    TransactionCodeInputMode, UrlSyntaxError, MAX_AUTHORIZATION_SERVERS, MAX_CONFIGURATIONS,
    MAX_CONFIGURATION_IDS, MAX_CONFIGURATION_ID_BYTES, MAX_ENDPOINT_BYTES, MAX_OPAQUE_VALUE_BYTES,
    MAX_SCOPE_BYTES, MDOC_PID_DOCTYPE, SD_JWT_PID_VCT,
};
use serde_json::{json, Value};

const ISSUER: &str = "https://issuer.example/tenant";
const AS_ONE: &str = "https://as-one.example/tenant";
const AS_TWO: &str = "https://as-two.example";

fn limits(
    max_bytes: usize,
    max_depth: usize,
    max_container_entries: usize,
    max_string_bytes: usize,
) -> JsonLimits {
    JsonLimits {
        max_bytes,
        max_depth,
        max_container_entries,
        max_string_bytes,
    }
}

#[test]
fn bounded_json_rejects_decoded_duplicates_at_every_depth() {
    for input in [
        br#"{"a":1,"\u0061":2}"#.as_slice(),
        br#"{"outer":{"a":1,"\u0061":2}}"#.as_slice(),
        "{\"😀\":1,\"\\uD83D\\uDE00\":2}".as_bytes(),
        br#"{"a/b":1,"a\u002fb":2}"#.as_slice(),
    ] {
        assert_eq!(
            parse_object(input, limits(512, 8, 8, 64)),
            Err(JsonBoundaryError::DuplicateMember)
        );
    }

    // JSON compares decoded Unicode scalar sequences, not Unicode normalization forms.
    let distinct = "{\"é\":1,\"e\\u0301\":2}";
    assert_eq!(
        parse_object(distinct.as_bytes(), limits(512, 8, 8, 64))
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn bounded_json_rejects_invalid_surrogates_and_accepts_a_valid_pair() {
    assert!(parse_object(br#"{"value":"\uD83D\uDE00"}"#, limits(128, 4, 4, 8)).is_ok());
    for input in [
        br#"{"value":"\uD83D"}"#.as_slice(),
        br#"{"value":"\uDE00"}"#.as_slice(),
        br#"{"value":"\uD83D\u0041"}"#.as_slice(),
        br#"{"value":"\uD83Dx"}"#.as_slice(),
    ] {
        assert_eq!(
            parse_object(input, limits(128, 4, 4, 16)),
            Err(JsonBoundaryError::InvalidJson)
        );
    }
}

#[test]
fn bounded_json_enforces_exact_byte_depth_container_and_string_boundaries() {
    let input = br#"{"a":1}"#;
    assert!(parse_object(input, limits(input.len(), 1, 1, 1)).is_ok());
    assert_eq!(
        parse_object(input, limits(input.len() - 1, 1, 1, 1)),
        Err(JsonBoundaryError::InputTooLarge)
    );

    let nested = br#"{"a":{"b":1}}"#;
    assert!(parse_object(nested, limits(nested.len(), 2, 1, 1)).is_ok());
    assert_eq!(
        parse_object(nested, limits(nested.len(), 1, 1, 1)),
        Err(JsonBoundaryError::DepthExceeded)
    );

    let entries = br#"{"a":1,"b":2}"#;
    assert!(parse_object(entries, limits(entries.len(), 1, 2, 1)).is_ok());
    assert_eq!(
        parse_object(entries, limits(entries.len(), 1, 1, 1)),
        Err(JsonBoundaryError::ContainerEntriesExceeded)
    );
    let array_entries = br#"{"a":[1,2]}"#;
    assert_eq!(
        parse_object(array_entries, limits(array_entries.len(), 2, 1, 1)),
        Err(JsonBoundaryError::ContainerEntriesExceeded)
    );

    let unicode = "{\"k\":\"é\"}";
    assert!(parse_object(unicode.as_bytes(), limits(32, 1, 1, 2)).is_ok());
    assert_eq!(
        parse_object(unicode.as_bytes(), limits(32, 1, 1, 1)),
        Err(JsonBoundaryError::StringTooLong)
    );
}

#[test]
fn bounded_json_hard_ceilings_cannot_be_raised_by_callers() {
    let base = JsonLimits {
        max_bytes: ABSOLUTE_MAX_JSON_BYTES,
        max_depth: ABSOLUTE_MAX_JSON_DEPTH,
        max_container_entries: ABSOLUTE_MAX_CONTAINER_ENTRIES,
        max_string_bytes: ABSOLUTE_MAX_STRING_BYTES,
    };
    for raised in [
        JsonLimits {
            max_bytes: base.max_bytes + 1,
            ..base
        },
        JsonLimits {
            max_depth: base.max_depth + 1,
            ..base
        },
        JsonLimits {
            max_container_entries: base.max_container_entries + 1,
            ..base
        },
        JsonLimits {
            max_string_bytes: base.max_string_bytes + 1,
            ..base
        },
    ] {
        assert_eq!(
            parse_object(b"{}", raised),
            Err(JsonBoundaryError::LimitsExceedHardMaximum)
        );
    }
}

#[test]
fn bounded_json_uses_strict_json_number_grammar_and_rejects_trailing_data() {
    for number in ["0", "-0", "1", "-12", "1.0", "1e3", "1E-3"] {
        let input = format!("{{\"n\":{number}}}");
        assert!(parse_object(input.as_bytes(), limits(64, 2, 4, 8)).is_ok());
    }
    for number in ["01", "-", ".1", "1.", "1e", "+1", "NaN", "Infinity"] {
        let input = format!("{{\"n\":{number}}}");
        assert_eq!(
            parse_object(input.as_bytes(), limits(64, 2, 4, 16)),
            Err(JsonBoundaryError::InvalidJson),
            "number {number}"
        );
    }
    assert_eq!(
        parse_object(b"{} trailing", limits(32, 2, 2, 8)),
        Err(JsonBoundaryError::InvalidJson)
    );
    assert_eq!(
        parse_object(b"[]", limits(8, 2, 2, 8)),
        Err(JsonBoundaryError::NonObjectRoot)
    );
}

#[test]
fn strict_https_identifiers_and_endpoints_do_not_normalize_attacker_input() {
    let identifier = HttpsIdentifier::parse("https://issuer.example/tenant/").unwrap();
    assert_eq!(identifier.as_str(), "https://issuer.example/tenant/");
    assert_eq!(
        identifier.credential_issuer_metadata_url(),
        "https://issuer.example/.well-known/openid-credential-issuer/tenant/"
    );
    assert_eq!(
        identifier.authorization_server_metadata_url(),
        "https://issuer.example/.well-known/oauth-authorization-server/tenant"
    );
    assert_eq!(
        HttpsIdentifier::parse("https://issuer.example/")
            .unwrap()
            .credential_issuer_metadata_url(),
        "https://issuer.example/.well-known/openid-credential-issuer/"
    );
    assert_eq!(
        HttpsIdentifier::parse("https://issuer.example")
            .unwrap()
            .credential_issuer_metadata_url(),
        "https://issuer.example/.well-known/openid-credential-issuer"
    );

    for (input, error) in [
        ("http://issuer.example", UrlSyntaxError::NotHttps),
        ("HTTPS://issuer.example", UrlSyntaxError::NotHttps),
        (
            "https://user@issuer.example",
            UrlSyntaxError::CredentialsForbidden,
        ),
        (
            "https://issuer.example?tenant=1",
            UrlSyntaxError::QueryForbidden,
        ),
        (
            "https://issuer.example#fragment",
            UrlSyntaxError::FragmentForbidden,
        ),
        ("https://Issuer.example", UrlSyntaxError::NonCanonical),
        ("https://issuer.example:0", UrlSyntaxError::InvalidPort),
        ("https://issuer.example:0443", UrlSyntaxError::InvalidPort),
        ("https://issuer.example:443", UrlSyntaxError::NonCanonical),
        (
            "https://issuer.example/a/../b",
            UrlSyntaxError::NonCanonical,
        ),
        ("https://issuer.example/%61", UrlSyntaxError::NonCanonical),
        ("https://issuer.example/%2f", UrlSyntaxError::NonCanonical),
        ("https://[2001:0db8::1]", UrlSyntaxError::NonCanonical),
    ] {
        assert_eq!(HttpsIdentifier::parse(input), Err(error), "{input}");
    }

    assert!(HttpsEndpoint::parse("https://issuer.example/credential?tenant=one").is_ok());
    assert_eq!(
        HttpsEndpoint::parse("https://user@issuer.example/token"),
        Err(UrlSyntaxError::CredentialsForbidden)
    );
    assert_eq!(
        HttpsEndpoint::parse("https://issuer.example/token#fragment"),
        Err(UrlSyntaxError::FragmentForbidden)
    );
    assert_eq!(
        HttpsEndpoint::parse(&format!(
            "https://issuer.example/{}",
            "a".repeat(MAX_ENDPOINT_BYTES)
        )),
        Err(UrlSyntaxError::TooLong)
    );
}

fn authorization_offer(issuer: &str, configuration_id: &str) -> Value {
    json!({
        "credential_issuer": issuer,
        "credential_configuration_ids": [configuration_id],
        "grants": { "authorization_code": { "issuer_state": "opaque-state" } }
    })
}

fn pre_authorized_offer(issuer: &str, configuration_id: &str) -> Value {
    json!({
        "credential_issuer": issuer,
        "credential_configuration_ids": [configuration_id],
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": "opaque-code",
                "tx_code": {"input_mode":"text", "length":8, "description":"Separate channel"}
            }
        }
    })
}

fn parse_offer(value: &Value) -> oid4vci::foundation::CredentialOffer {
    parse_credential_offer(&serde_json::to_vec(value).unwrap()).unwrap()
}

#[test]
fn final_credential_offer_preserves_opaque_grants_and_ignores_bounded_extensions() {
    let mut value = authorization_offer(ISSUER, "pid-sd");
    value["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"] = json!({
        "pre-authorized_code": "opaque-code",
        "tx_code": {},
        "authorization_server": AS_ONE,
        "extension": {"bounded": [1,2,3]}
    });
    value["extension"] = json!({"ignored": true});
    let offer = parse_offer(&value);
    assert_eq!(offer.credential_issuer.as_str(), ISSUER);
    assert_eq!(
        offer
            .authorization_code
            .unwrap()
            .issuer_state
            .unwrap()
            .as_str(),
        "opaque-state"
    );
    let pre_authorized = offer.pre_authorized_code.unwrap();
    assert_eq!(pre_authorized.pre_authorized_code.as_str(), "opaque-code");
    assert_eq!(
        pre_authorized.transaction_code.unwrap().input_mode,
        TransactionCodeInputMode::Numeric
    );
    assert_eq!(
        pre_authorized.authorization_server.unwrap().as_str(),
        AS_ONE
    );
}

#[test]
fn offer_rejects_legacy_shape_duplicate_empty_and_over_budget_ids() {
    assert_eq!(
        parse_credential_offer(br#"{"format":"dc+sd-jwt","grant":"authorization_code"}"#),
        Err(OfferError::MissingField("credential_issuer"))
    );
    assert!(matches!(
        parse_credential_offer(
            br#"{"credential_issuer":"https://issuer.example","credential_configuration_ids":["pid"],"grants":{},"gr\u0061nts":{}}"#
        ),
        Err(OfferError::Json(JsonBoundaryError::DuplicateMember))
    ));

    let mut empty = authorization_offer(ISSUER, "pid");
    empty["credential_configuration_ids"] = json!([]);
    assert_eq!(
        parse_credential_offer(&serde_json::to_vec(&empty).unwrap()),
        Err(OfferError::EmptyCollection("credential_configuration_ids"))
    );
    empty["credential_configuration_ids"] = json!(["pid", "pid"]);
    assert_eq!(
        parse_credential_offer(&serde_json::to_vec(&empty).unwrap()),
        Err(OfferError::DuplicateValue("credential_configuration_ids"))
    );
    empty["credential_configuration_ids"] = Value::Array(
        (0..=MAX_CONFIGURATION_IDS)
            .map(|index| Value::String(format!("pid-{index}")))
            .collect(),
    );
    assert_eq!(
        parse_credential_offer(&serde_json::to_vec(&empty).unwrap()),
        Err(OfferError::TooManyValues("credential_configuration_ids"))
    );
    empty["credential_configuration_ids"] = json!(["x".repeat(MAX_CONFIGURATION_ID_BYTES + 1)]);
    assert_eq!(
        parse_credential_offer(&serde_json::to_vec(&empty).unwrap()),
        Err(OfferError::ValueTooLong("credential_configuration_ids"))
    );
}

#[test]
fn offer_opaque_values_have_an_exact_hard_bound() {
    let mut value = authorization_offer(ISSUER, "pid");
    value["grants"]["authorization_code"]["issuer_state"] =
        Value::String("x".repeat(MAX_OPAQUE_VALUE_BYTES));
    assert!(parse_credential_offer(&serde_json::to_vec(&value).unwrap()).is_ok());
    value["grants"]["authorization_code"]["issuer_state"] =
        Value::String("x".repeat(MAX_OPAQUE_VALUE_BYTES + 1));
    assert_eq!(
        parse_credential_offer(&serde_json::to_vec(&value).unwrap()),
        Err(OfferError::ValueTooLong("issuer_state"))
    );
}

fn sd_configuration() -> Value {
    json!({
        "format": "dc+sd-jwt",
        "scope": "pid_sd",
        "vct": SD_JWT_PID_VCT,
        "cryptographic_binding_methods_supported": ["jwk"],
        "credential_signing_alg_values_supported": ["ES256"],
        "proof_types_supported": {
            "jwt": {
                "proof_signing_alg_values_supported": ["ES256"],
                "key_attestations_required": {
                    "key_storage": ["iso_18045_high"],
                    "user_authentication": ["iso_18045_high", "iso_18045_moderate"]
                }
            },
            "attestation": {
                "proof_signing_alg_values_supported": ["ES256"],
                "key_attestations_required": {
                    "key_storage": ["iso_18045_high"],
                    "user_authentication": ["iso_18045_high"]
                }
            }
        }
    })
}

fn mdoc_configuration() -> Value {
    json!({
        "format": "mso_mdoc",
        "scope": "pid_mdoc",
        "doctype": MDOC_PID_DOCTYPE,
        "cryptographic_binding_methods_supported": ["cose_key"],
        "credential_signing_alg_values_supported": [-7],
        "proof_types_supported": {
            "jwt": {
                "proof_signing_alg_values_supported": ["ES256"],
                "key_attestations_required": {
                    "key_storage": ["iso_18045_high"],
                    "user_authentication": ["iso_18045_high"]
                }
            }
        }
    })
}

fn issuer_metadata(configuration_id: &str, configuration: Value) -> Value {
    json!({
        "credential_issuer": ISSUER,
        "authorization_servers": [AS_ONE],
        "credential_endpoint": "https://issuer.example/tenant/credential?version=1",
        "nonce_endpoint": "https://issuer.example/tenant/nonce",
        "deferred_credential_endpoint": "https://issuer.example/tenant/deferred",
        "credential_configurations_supported": {
            configuration_id: configuration
        },
        "extension": {"ignored": [1, 2, 3]}
    })
}

fn authorization_server_metadata(issuer: &str) -> Value {
    json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "pushed_authorization_request_endpoint": format!("{issuer}/par"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "scopes_supported": ["pid_sd", "pid_mdoc"],
        "code_challenge_methods_supported": ["S256"],
        "dpop_signing_alg_values_supported": ["ES256"],
        "authorization_response_iss_parameter_supported": true,
        "require_pushed_authorization_requests": true
    })
}

fn parse_issuer(value: &Value) -> oid4vci::foundation::CredentialIssuerMetadata {
    parse_credential_issuer_metadata(&serde_json::to_vec(value).unwrap(), ISSUER).unwrap()
}

fn parse_as(value: &Value, expected: &str) -> oid4vci::foundation::AuthorizationServerMetadata {
    parse_authorization_server_metadata(&serde_json::to_vec(value).unwrap(), expected).unwrap()
}

#[test]
fn issuer_and_as_metadata_parse_exact_identifiers_endpoints_and_features() {
    let issuer = parse_issuer(&issuer_metadata("pid-sd", sd_configuration()));
    assert_eq!(issuer.credential_issuer.as_str(), ISSUER);
    assert_eq!(issuer.authorization_servers[0].as_str(), AS_ONE);
    assert!(issuer.features.nonce_endpoint);
    assert!(issuer.features.deferred_credential_endpoint);
    assert!(!issuer.features.credential_request_encryption_required);
    assert_eq!(
        issuer.credential_endpoint.as_str(),
        "https://issuer.example/tenant/credential?version=1"
    );

    let server = parse_as(&authorization_server_metadata(AS_ONE), AS_ONE);
    assert!(server.features.authorization_code);
    assert!(server.features.response_type_code);
    assert!(server.features.par);
    assert!(server.features.par_required);
    assert!(server.features.pkce_s256);
    assert!(server.features.dpop_es256);
    assert!(server.features.authorization_response_issuer);
}

#[test]
fn metadata_rejects_identifier_mismatch_bad_endpoints_and_empty_collections() {
    let value = issuer_metadata("pid", sd_configuration());
    assert_eq!(
        parse_credential_issuer_metadata(
            &serde_json::to_vec(&value).unwrap(),
            "https://other.example"
        ),
        Err(MetadataError::IdentifierMismatch)
    );
    let mut bad = value.clone();
    bad["credential_endpoint"] = json!("https://user@issuer.example/credential");
    assert!(matches!(
        parse_credential_issuer_metadata(&serde_json::to_vec(&bad).unwrap(), ISSUER),
        Err(MetadataError::InvalidUrl(
            "credential_endpoint",
            UrlSyntaxError::CredentialsForbidden
        ))
    ));
    bad = value.clone();
    bad["authorization_servers"] = json!([]);
    assert_eq!(
        parse_credential_issuer_metadata(&serde_json::to_vec(&bad).unwrap(), ISSUER),
        Err(MetadataError::EmptyCollection("authorization_servers"))
    );
    bad = value.clone();
    bad["credential_configurations_supported"] = json!({});
    assert_eq!(
        parse_credential_issuer_metadata(&serde_json::to_vec(&bad).unwrap(), ISSUER),
        Err(MetadataError::EmptyCollection(
            "credential_configurations_supported"
        ))
    );

    let server = authorization_server_metadata(AS_ONE);
    assert_eq!(
        parse_authorization_server_metadata(&serde_json::to_vec(&server).unwrap(), AS_TWO),
        Err(MetadataError::IdentifierMismatch)
    );
    let mut server = server;
    server["response_types_supported"] = json!([]);
    assert_eq!(
        parse_authorization_server_metadata(&serde_json::to_vec(&server).unwrap(), AS_ONE),
        Err(MetadataError::EmptyCollection("response_types_supported"))
    );
}

#[test]
fn metadata_semantic_collection_and_text_caps_are_hard() {
    let mut value = issuer_metadata("pid", sd_configuration());
    value["authorization_servers"] = Value::Array(
        (0..=MAX_AUTHORIZATION_SERVERS)
            .map(|index| Value::String(format!("https://as-{index}.example")))
            .collect(),
    );
    assert_eq!(
        parse_credential_issuer_metadata(&serde_json::to_vec(&value).unwrap(), ISSUER),
        Err(MetadataError::TooManyValues("authorization_servers"))
    );

    let mut configurations = serde_json::Map::new();
    for index in 0..=MAX_CONFIGURATIONS {
        configurations.insert(format!("pid-{index}"), sd_configuration());
    }
    value = issuer_metadata("pid", sd_configuration());
    value["credential_configurations_supported"] = Value::Object(configurations);
    assert_eq!(
        parse_credential_issuer_metadata(&serde_json::to_vec(&value).unwrap(), ISSUER),
        Err(MetadataError::TooManyValues(
            "credential_configurations_supported"
        ))
    );

    value = issuer_metadata("pid", sd_configuration());
    value["credential_configurations_supported"]["pid"]["scope"] =
        Value::String("s".repeat(MAX_SCOPE_BYTES));
    assert!(parse_credential_issuer_metadata(&serde_json::to_vec(&value).unwrap(), ISSUER).is_ok());
    value["credential_configurations_supported"]["pid"]["scope"] =
        Value::String("s".repeat(MAX_SCOPE_BYTES + 1));
    assert_eq!(
        parse_credential_issuer_metadata(&serde_json::to_vec(&value).unwrap(), ISSUER),
        Err(MetadataError::ValueTooLong("scope"))
    );

    value = issuer_metadata("pid", sd_configuration());
    value["credential_configurations_supported"]["pid"]["scope"] = json!("pid other");
    assert_eq!(
        parse_credential_issuer_metadata(&serde_json::to_vec(&value).unwrap(), ISSUER),
        Err(MetadataError::InvalidField("scope"))
    );
}

fn valid_setup(
    configuration_id: &str,
    configuration: Value,
) -> (
    oid4vci::foundation::CredentialOffer,
    oid4vci::foundation::CredentialIssuerMetadata,
    oid4vci::foundation::AuthorizationServerMetadata,
) {
    (
        parse_offer(&authorization_offer(ISSUER, configuration_id)),
        parse_issuer(&issuer_metadata(configuration_id, configuration)),
        parse_as(&authorization_server_metadata(AS_ONE), AS_ONE),
    )
}

#[test]
fn german_first_enrolment_selects_only_exact_current_pid_profiles() {
    let (offer, issuer, server) = valid_setup("pid-sd", sd_configuration());
    let plan = select_german_first_enrolment(&offer, &issuer, &[server], "pid-sd").unwrap();
    assert_eq!(plan.format, GermanPidFormat::DcSdJwt);
    assert_eq!(plan.holder_binding, HolderBindingMethod::Jwk);
    assert_eq!(
        plan.credential_signing_algorithm,
        CredentialSigningAlgorithm::JoseEs256
    );
    assert_eq!(plan.scope, "pid_sd");
    assert_eq!(plan.pid_provider_trust, PidProviderTrust::Unresolved);
    assert_eq!(
        plan.deferred_credential_endpoint
            .as_ref()
            .map(|endpoint| endpoint.as_str()),
        Some("https://issuer.example/tenant/deferred")
    );

    let (offer, issuer, server) = valid_setup("pid-mdoc", mdoc_configuration());
    let plan = select_german_first_enrolment(&offer, &issuer, &[server], "pid-mdoc").unwrap();
    assert_eq!(plan.format, GermanPidFormat::MsoMdoc);
    assert_eq!(plan.holder_binding, HolderBindingMethod::CoseKey);
    assert_eq!(
        plan.credential_signing_algorithm,
        CredentialSigningAlgorithm::CoseEs256
    );
    assert_eq!(plan.proof_signing_algorithm, "ES256");
}

#[test]
fn german_first_enrolment_rejects_pre_authorized_and_unoffered_choices() {
    let offer = parse_offer(&pre_authorized_offer(ISSUER, "pid-sd"));
    let issuer = parse_issuer(&issuer_metadata("pid-sd", sd_configuration()));
    let server = parse_as(&authorization_server_metadata(AS_ONE), AS_ONE);
    assert_eq!(
        select_german_first_enrolment(&offer, &issuer, &[server], "pid-sd"),
        Err(ProfileSelectionError::AuthorizationCodeRequired)
    );

    let (offer, issuer, server) = valid_setup("pid-sd", sd_configuration());
    assert_eq!(
        select_german_first_enrolment(&offer, &issuer, &[server], "pid-mdoc"),
        Err(ProfileSelectionError::ConfigurationNotOffered)
    );
}

#[test]
fn absent_or_empty_grants_defer_authorization_code_to_as_metadata() {
    let issuer = parse_issuer(&issuer_metadata("pid-sd", sd_configuration()));
    let server = parse_as(&authorization_server_metadata(AS_ONE), AS_ONE);

    let mut absent = authorization_offer(ISSUER, "pid-sd");
    absent.as_object_mut().unwrap().remove("grants");
    let absent = parse_offer(&absent);
    assert_eq!(
        absent.grant_source,
        OfferGrantSource::AuthorizationServerMetadata
    );
    assert!(select_german_first_enrolment(
        &absent,
        &issuer,
        std::slice::from_ref(&server),
        "pid-sd"
    )
    .is_ok());

    let mut empty = authorization_offer(ISSUER, "pid-sd");
    empty["grants"] = json!({});
    let empty = parse_offer(&empty);
    assert_eq!(
        empty.grant_source,
        OfferGrantSource::AuthorizationServerMetadata
    );
    assert!(select_german_first_enrolment(&empty, &issuer, &[server], "pid-sd").is_ok());
}

#[test]
fn pid_configuration_type_and_algorithm_confusion_fails_closed() {
    let cases = [
        (
            {
                let mut value = sd_configuration();
                value["format"] = json!("vc+sd-jwt");
                value
            },
            ProfileSelectionError::UnsupportedPidConfiguration,
        ),
        (
            {
                let mut value = sd_configuration();
                value["vct"] = json!("urn:example:not-pid");
                value
            },
            ProfileSelectionError::UnsupportedPidConfiguration,
        ),
        (
            {
                let mut value = mdoc_configuration();
                value["vct"] = json!(SD_JWT_PID_VCT);
                value
            },
            ProfileSelectionError::UnsupportedPidConfiguration,
        ),
        (
            {
                let mut value = sd_configuration();
                value["credential_signing_alg_values_supported"] = json!(["ES256", -7]);
                value
            },
            ProfileSelectionError::MixedAlgorithmIdentifiers,
        ),
        (
            {
                let mut value = mdoc_configuration();
                value["credential_signing_alg_values_supported"] = json!([-7, "ES256"]);
                value
            },
            ProfileSelectionError::MixedAlgorithmIdentifiers,
        ),
        (
            {
                let mut value = sd_configuration();
                value["proof_types_supported"]["jwt"]["proof_signing_alg_values_supported"] =
                    json!(["ES256", -7]);
                value
            },
            ProfileSelectionError::MixedAlgorithmIdentifiers,
        ),
    ];
    for (configuration, expected) in cases {
        let (offer, issuer, server) = valid_setup("pid", configuration);
        assert_eq!(
            select_german_first_enrolment(&offer, &issuer, &[server], "pid"),
            Err(expected)
        );
    }
}

#[test]
fn pid_configuration_capability_matrix_is_typed_and_fail_closed() {
    let cases = [
        (
            {
                let mut value = sd_configuration();
                value.as_object_mut().unwrap().remove("scope");
                value
            },
            ProfileSelectionError::ScopeMissing,
        ),
        (
            {
                let mut value = sd_configuration();
                value["cryptographic_binding_methods_supported"] = json!(["cose_key"]);
                value
            },
            ProfileSelectionError::BindingMethodMissing,
        ),
        (
            {
                let mut value = sd_configuration();
                value["credential_signing_alg_values_supported"] = json!(["ES384"]);
                value
            },
            ProfileSelectionError::CredentialSigningAlgorithmMissing,
        ),
        (
            {
                let mut value = sd_configuration();
                value["proof_types_supported"]
                    .as_object_mut()
                    .unwrap()
                    .remove("jwt");
                value
            },
            ProfileSelectionError::JwtProofMissing,
        ),
        (
            {
                let mut value = sd_configuration();
                value["proof_types_supported"]["jwt"]["proof_signing_alg_values_supported"] =
                    json!(["ES384"]);
                value
            },
            ProfileSelectionError::ProofAlgorithmMissing,
        ),
        (
            {
                let mut value = sd_configuration();
                value["proof_types_supported"]["jwt"]
                    .as_object_mut()
                    .unwrap()
                    .remove("key_attestations_required");
                value
            },
            ProfileSelectionError::KeyAttestationMissing,
        ),
        (
            {
                let mut value = sd_configuration();
                value["proof_types_supported"]["jwt"]["key_attestations_required"]["key_storage"] =
                    json!(["iso_18045_moderate"]);
                value
            },
            ProfileSelectionError::HighKeyStorageMissing,
        ),
        (
            {
                let mut value = sd_configuration();
                value["proof_types_supported"]["jwt"]["key_attestations_required"]
                    ["user_authentication"] = json!(["iso_18045_moderate"]);
                value
            },
            ProfileSelectionError::HighUserAuthenticationMissing,
        ),
    ];
    for (configuration, expected) in cases {
        let (offer, issuer, server) = valid_setup("pid", configuration);
        assert_eq!(
            select_german_first_enrolment(&offer, &issuer, &[server], "pid"),
            Err(expected)
        );
    }
}

#[test]
fn issuer_required_nonce_and_encryption_capabilities_fail_closed() {
    let offer = parse_offer(&authorization_offer(ISSUER, "pid"));
    let server = parse_as(&authorization_server_metadata(AS_ONE), AS_ONE);

    let mut value = issuer_metadata("pid", sd_configuration());
    value.as_object_mut().unwrap().remove("nonce_endpoint");
    let issuer = parse_issuer(&value);
    assert_eq!(
        select_german_first_enrolment(&offer, &issuer, std::slice::from_ref(&server), "pid"),
        Err(ProfileSelectionError::NonceEndpointMissing)
    );

    let mut value = issuer_metadata("pid", sd_configuration());
    value["credential_request_encryption"] = json!({
        "jwks": {"keys": [{"kty":"EC", "kid":"encryption-key"}]},
        "enc_values_supported": ["A256GCM"],
        "encryption_required": true
    });
    let issuer = parse_issuer(&value);
    assert_eq!(
        select_german_first_enrolment(&offer, &issuer, std::slice::from_ref(&server), "pid"),
        Err(ProfileSelectionError::CredentialRequestEncryptionRequired)
    );

    let mut value = issuer_metadata("pid", sd_configuration());
    value["credential_response_encryption"] = json!({
        "alg_values_supported": ["ECDH-ES"],
        "enc_values_supported": ["A256GCM"],
        "encryption_required": true
    });
    let issuer = parse_issuer(&value);
    assert_eq!(
        select_german_first_enrolment(&offer, &issuer, &[server], "pid"),
        Err(ProfileSelectionError::CredentialResponseEncryptionRequired)
    );
}

#[test]
fn authorization_server_capability_matrix_is_typed_and_fail_closed() {
    let (offer, issuer, _) = valid_setup("pid", sd_configuration());
    let cases: [(&str, Option<Value>, ProfileSelectionError); 9] = [
        (
            "grant_types_supported",
            Some(json!(["client_credentials"])),
            ProfileSelectionError::AuthorizationCodeUnsupported,
        ),
        (
            "response_types_supported",
            Some(json!(["code token"])),
            ProfileSelectionError::ResponseTypeCodeUnsupported,
        ),
        (
            "authorization_endpoint",
            None,
            ProfileSelectionError::AuthorizationEndpointMissing,
        ),
        (
            "token_endpoint",
            None,
            ProfileSelectionError::TokenEndpointMissing,
        ),
        (
            "pushed_authorization_request_endpoint",
            None,
            ProfileSelectionError::ParUnsupported,
        ),
        (
            "code_challenge_methods_supported",
            Some(json!(["plain"])),
            ProfileSelectionError::PkceS256Unsupported,
        ),
        (
            "dpop_signing_alg_values_supported",
            Some(json!(["ES384"])),
            ProfileSelectionError::DpopEs256Unsupported,
        ),
        (
            "authorization_response_iss_parameter_supported",
            Some(json!(false)),
            ProfileSelectionError::AuthorizationResponseIssuerUnsupported,
        ),
        (
            "scopes_supported",
            Some(json!(["other_scope"])),
            ProfileSelectionError::ScopeUnsupportedByAuthorizationServer,
        ),
    ];
    for (field, replacement, expected) in cases {
        let mut value = authorization_server_metadata(AS_ONE);
        match replacement {
            Some(replacement) => value[field] = replacement,
            None => {
                value.as_object_mut().unwrap().remove(field);
            }
        }
        let server = parse_as(&value, AS_ONE);
        assert_eq!(
            select_german_first_enrolment(&offer, &issuer, &[server], "pid"),
            Err(expected),
            "field {field}"
        );
    }
}

fn metadata_with_servers(servers: &[&str]) -> oid4vci::foundation::CredentialIssuerMetadata {
    let mut value = issuer_metadata("pid", sd_configuration());
    value["authorization_servers"] =
        Value::Array(servers.iter().map(|value| json!(value)).collect());
    parse_issuer(&value)
}

fn offer_with_hint(hint: Option<&str>) -> oid4vci::foundation::CredentialOffer {
    let mut value = authorization_offer(ISSUER, "pid");
    if let Some(hint) = hint {
        value["grants"]["authorization_code"]["authorization_server"] = json!(hint);
    }
    parse_offer(&value)
}

#[test]
fn authorization_server_hint_rules_and_multi_server_selection_are_exact() {
    let single = metadata_with_servers(&[AS_ONE]);
    let hinted = offer_with_hint(Some(AS_ONE));
    let one = parse_as(&authorization_server_metadata(AS_ONE), AS_ONE);
    assert_eq!(
        select_authorization_server(&hinted, &single, std::slice::from_ref(&one), None),
        Err(ProfileSelectionError::AuthorizationServerHintNotAllowed)
    );

    let multiple = metadata_with_servers(&[AS_ONE, AS_TWO]);
    let bad_hint = offer_with_hint(Some("https://not-advertised.example"));
    assert_eq!(
        select_authorization_server(&bad_hint, &multiple, std::slice::from_ref(&one), None),
        Err(ProfileSelectionError::AuthorizationServerHintMismatch)
    );
    assert_eq!(
        select_authorization_server(
            &offer_with_hint(None),
            &multiple,
            std::slice::from_ref(&one),
            None
        ),
        Err(ProfileSelectionError::AuthorizationServerMetadataMissing)
    );

    let two = parse_as(&authorization_server_metadata(AS_TWO), AS_TWO);
    let hinted_servers = [one.clone(), two.clone()];
    let selected = select_authorization_server(
        &offer_with_hint(Some(AS_TWO)),
        &multiple,
        &hinted_servers,
        None,
    )
    .unwrap();
    assert_eq!(selected.issuer.as_str(), AS_TWO);

    assert_eq!(
        select_authorization_server(
            &offer_with_hint(None),
            &multiple,
            &[one.clone(), two.clone()],
            None
        ),
        Err(ProfileSelectionError::AmbiguousAuthorizationServer)
    );
    let mut not_ready = authorization_server_metadata(AS_TWO);
    not_ready["dpop_signing_alg_values_supported"] = json!(["ES384"]);
    let not_ready = parse_as(&not_ready, AS_TWO);
    let one_ready_server = [one, not_ready];
    let selected =
        select_authorization_server(&offer_with_hint(None), &multiple, &one_ready_server, None)
            .unwrap();
    assert_eq!(selected.issuer.as_str(), AS_ONE);
}

#[test]
fn offer_and_metadata_issuer_mix_up_is_rejected_before_profile_selection() {
    let offer = parse_offer(&authorization_offer("https://other.example", "pid"));
    let issuer = parse_issuer(&issuer_metadata("pid", sd_configuration()));
    let server = parse_as(&authorization_server_metadata(AS_ONE), AS_ONE);
    assert_eq!(
        select_german_first_enrolment(&offer, &issuer, &[server], "pid"),
        Err(ProfileSelectionError::OfferIssuerMismatch)
    );
}
