//! Regression tests for the authentication-to-storage boundary. A credential can be structurally
//! valid and still must not enter holdings unless issuer trust, signature, type policy, validity,
//! mandatory claims and device binding all succeed.

use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use crypto_backend::{AwsLc, SoftwareSigner};
use crypto_traits::{Alg, KeyRef, Signer};
use mdoc::cbor::Value;
use mdoc::{IssuerSignedItem, ValidityInfo};
use serde_json::json;
use std::collections::BTreeMap;
use wallet_core::{Core, CredentialIngestionError, DemoWallet, IssuanceScenario, WalletEngine};

const ISSUER_PKCS8: &[u8] = include_bytes!("../../x509/tests/vectors/rp.pkcs8.der");
const OTHER_ISSUER_B64: &str = include_str!("../../x509/tests/vectors/other-issuer.der.b64");
const RP_LEAF: &[u8] = include_bytes!("../../x509/tests/vectors/rp.der");
const ROOT_A_B64: &str = include_str!("vectors/mdoc-x5chain/root-a.der.b64");
const ROOT_B_B64: &str = include_str!("vectors/mdoc-x5chain/root-b.der.b64");
const BRIDGE_A_B64: &str = include_str!("vectors/mdoc-x5chain/bridge-a.der.b64");
const BRIDGE_B_B64: &str = include_str!("vectors/mdoc-x5chain/bridge-b.der.b64");
const EXPIRED_CERTIFICATE_EPOCH: i64 = 2_100_000_000;

fn decode_cert(encoded: &str) -> Vec<u8> {
    Base64::decode_vec(encoded.trim()).expect("valid test certificate base64")
}

fn ready_core(scenario: &IssuanceScenario) -> Core {
    let mut core = Core::new("wallet.example", "device-key");
    core.handle_event(wallet_core::Event::SetClock {
        epoch: scenario.epoch,
    });
    core.load_device_key(scenario.device_public_key.clone());
    core.load_trust_list(&scenario.trust_list, &scenario.operator_public_key)
        .expect("demo trust list verifies");
    core
}

fn ready_core_with_anchors(
    scenario: &IssuanceScenario,
    now: i64,
    anchors: &[(Vec<u8>, &'static str)],
) -> Core {
    let operator = SoftwareSigner::generate_p256().expect("trust-list operator key");
    let encoded_anchors = anchors
        .iter()
        .map(|(certificate, service)| {
            json!({
                "cert": Base64UrlUnpadded::encode_string(certificate),
                "service": service,
                "status": "granted",
            })
        })
        .collect::<Vec<_>>();
    let header = Base64UrlUnpadded::encode_string(br#"{"alg":"ES256"}"#);
    let payload = Base64UrlUnpadded::encode_string(
        json!({
            "seq": 1,
            "valid_from": 0,
            "valid_until": 4_000_000_000i64,
            "anchors": encoded_anchors,
        })
        .to_string()
        .as_bytes(),
    );
    let signing_input = format!("{header}.{payload}");
    let signature = operator
        .sign(
            &KeyRef("trust-list".into()),
            Alg::Es256,
            signing_input.as_bytes(),
        )
        .expect("sign custom trust list");
    let trust_list = format!(
        "{signing_input}.{}",
        Base64UrlUnpadded::encode_string(&signature)
    );

    let mut core = Core::new("wallet.example", "device-key");
    core.handle_event(wallet_core::Event::SetClock { epoch: now });
    core.load_device_key(scenario.device_public_key.clone());
    core.load_trust_list(trust_list.as_bytes(), operator.public_key_raw())
        .expect("custom trust list verifies");
    core
}

fn cose_key(public_key: &[u8]) -> Value {
    Value::Map(vec![
        (Value::Uint(1), Value::Uint(2)),
        (Value::Nint(0), Value::Uint(1)),
        (Value::Nint(1), Value::Bytes(public_key[1..33].to_vec())),
        (Value::Nint(2), Value::Bytes(public_key[33..65].to_vec())),
    ])
}

fn issued_mdoc(
    scenario: &IssuanceScenario,
    namespace: &str,
    x5chain: Option<cose::X5Chain>,
) -> mdoc::IssuerSigned {
    let issuer = SoftwareSigner::from_pkcs8_der(ISSUER_PKCS8).expect("issuer key");
    let mut name_spaces = BTreeMap::new();
    name_spaces.insert(
        namespace.to_string(),
        vec![
            IssuerSignedItem {
                digest_id: 0,
                random: vec![0x11; 16],
                element_id: "family_name".into(),
                element_value: Value::Text("Andersson".into()),
            },
            IssuerSignedItem {
                digest_id: 1,
                random: vec![0x22; 16],
                element_id: "given_name".into(),
                element_value: Value::Text("Astrid".into()),
            },
        ],
    );
    let mut issued = mdoc::build_and_sign(
        name_spaces,
        "org.iso.18013.5.1.mDL",
        cose_key(&scenario.device_public_key),
        ValidityInfo {
            signed: "2026-07-19T02:00:00.125+02:00".into(),
            valid_from: "2026-07-19T00:00:00Z".into(),
            valid_until: "2035-01-01T00:00:00Z".into(),
        },
        &AwsLc,
        &issuer,
        &KeyRef("issuer".into()),
        Alg::Es256,
    )
    .expect("sign mdoc");
    issued.issuer_auth.unprotected.x5chain = x5chain.map(Box::new);
    issued
}

fn encoded_mdoc(issued: &mdoc::IssuerSigned) -> Vec<u8> {
    Base64UrlUnpadded::encode_string(&issued.to_value().to_canonical()).into_bytes()
}

fn signed_mdoc(scenario: &IssuanceScenario, namespace: &str) -> Vec<u8> {
    encoded_mdoc(&issued_mdoc(
        scenario,
        namespace,
        Some(cose::X5Chain::Single(scenario.issuer_cert_chain[0].clone())),
    ))
}

fn issued_pid_mdoc(scenario: &IssuanceScenario, portrait: Option<Vec<u8>>) -> mdoc::IssuerSigned {
    let issuer = SoftwareSigner::from_pkcs8_der(ISSUER_PKCS8).expect("issuer key");
    let mut items = vec![
        IssuerSignedItem {
            digest_id: 0,
            random: vec![0x11; 16],
            element_id: "family_name".into(),
            element_value: Value::Text("Andersson".into()),
        },
        IssuerSignedItem {
            digest_id: 1,
            random: vec![0x22; 16],
            element_id: "given_name".into(),
            element_value: Value::Text("Astrid".into()),
        },
        IssuerSignedItem {
            digest_id: 2,
            random: vec![0x33; 16],
            element_id: "birth_date".into(),
            element_value: Value::Tag(1004, Box::new(Value::Text("1988-04-12".into()))),
        },
    ];
    if let Some(portrait) = portrait {
        items.push(IssuerSignedItem {
            digest_id: 3,
            random: vec![0x44; 16],
            element_id: "portrait".into(),
            element_value: Value::Bytes(portrait),
        });
    }
    let mut name_spaces = BTreeMap::new();
    name_spaces.insert("eu.europa.ec.eudi.pid.1".into(), items);
    let mut issued = mdoc::build_and_sign(
        name_spaces,
        "eu.europa.ec.eudi.pid.1",
        cose_key(&scenario.device_public_key),
        ValidityInfo {
            signed: "2026-07-19T00:00:00Z".into(),
            valid_from: "2026-07-19T00:00:00Z".into(),
            valid_until: "2035-01-01T00:00:00Z".into(),
        },
        &AwsLc,
        &issuer,
        &KeyRef("issuer".into()),
        Alg::Es256,
    )
    .expect("sign PID mdoc");
    issued.issuer_auth.unprotected.x5chain = Some(Box::new(cose::X5Chain::Single(
        scenario.issuer_cert_chain[0].clone(),
    )));
    issued
}

fn remove_sd_jwt_disclosure(compact: &str, claim: &str) -> String {
    let mut components = compact.split('~');
    let issuer_jwt = components.next().expect("issuer JWT");
    let disclosures = components
        .filter(|component| !component.is_empty())
        .filter(|component| {
            let decoded = Base64UrlUnpadded::decode_vec(component).expect("disclosure base64");
            let disclosure: serde_json::Value =
                serde_json::from_slice(&decoded).expect("disclosure JSON");
            disclosure.get(1).and_then(serde_json::Value::as_str) != Some(claim)
        })
        .collect::<Vec<_>>();
    format!("{issuer_jwt}~{}~", disclosures.join("~"))
}

#[test]
fn authenticated_sdjwt_and_mdoc_cross_the_storage_boundary() {
    let wallet = DemoWallet::new();
    let scenario = wallet.issuance_scenario();
    let mut core = ready_core(&scenario);

    core.ingest_credential(
        "dc+sd-jwt",
        scenario.pid_credential_compact.as_bytes(),
        &scenario.issuer_cert_chain,
        &scenario.issuer_id,
    )
    .expect("issuer-authenticated, device-bound PID is accepted");
    core.ingest_credential(
        "mso_mdoc",
        scenario.mdl_mdoc_credential.as_bytes(),
        &scenario.issuer_cert_chain,
        &scenario.issuer_id,
    )
    .expect("issuer-authenticated, device-bound mdoc is accepted");

    let held = core.held_credentials_json();
    assert!(held.contains("urn:eudi:pid:1"));
    assert!(held.contains("org.iso.18013.5.1.mDL"));
}

#[test]
fn pid_portrait_profile_is_enforced_at_authenticated_storage_boundary() {
    let wallet = DemoWallet::new();
    let scenario = wallet.issuance_scenario();

    let missing_picture = remove_sd_jwt_disclosure(&scenario.pid_credential_compact, "picture");
    let mut sd_core = ready_core(&scenario);
    assert_eq!(
        sd_core.ingest_credential(
            "dc+sd-jwt",
            missing_picture.as_bytes(),
            &scenario.issuer_cert_chain,
            &scenario.issuer_id,
        ),
        Err(CredentialIngestionError::PidPortraitInvalid)
    );
    assert_eq!(sd_core.held_credentials_json(), "[]");

    for portrait in [vec![0xff, 0xd8, 0xff, 0xd9], vec![]] {
        let mut mdoc_core = ready_core(&scenario);
        let credential = encoded_mdoc(&issued_pid_mdoc(&scenario, Some(portrait)));
        mdoc_core
            .ingest_credential(
                "mso_mdoc",
                &credential,
                &scenario.issuer_cert_chain,
                &scenario.issuer_id,
            )
            .expect("JPEG and explicit empty opt-out PID portraits are accepted");
        assert!(mdoc_core
            .held_credentials_json()
            .contains("eu.europa.ec.eudi.pid.1"));
    }

    let mut missing_mdoc_core = ready_core(&scenario);
    let missing = encoded_mdoc(&issued_pid_mdoc(&scenario, None));
    assert_eq!(
        missing_mdoc_core.ingest_credential(
            "mso_mdoc",
            &missing,
            &scenario.issuer_cert_chain,
            &scenario.issuer_id,
        ),
        Err(CredentialIngestionError::PidPortraitInvalid)
    );
}

#[test]
fn mdoc_tagged_offset_date_is_accepted_but_a_lookalike_namespace_is_not() {
    let wallet = DemoWallet::new();
    let scenario = wallet.issuance_scenario();

    let mut exact_core = ready_core(&scenario);
    exact_core
        .ingest_credential(
            "mso_mdoc",
            &signed_mdoc(&scenario, "org.iso.18013.5.1"),
            &scenario.issuer_cert_chain,
            &scenario.issuer_id,
        )
        .expect("tagged fractional offset tdate and exact catalogue path are accepted");

    let mut wrong_namespace_core = ready_core(&scenario);
    assert_eq!(
        wrong_namespace_core.ingest_credential(
            "mso_mdoc",
            &signed_mdoc(&scenario, "org.example.lookalike"),
            &scenario.issuer_cert_chain,
            &scenario.issuer_id,
        ),
        Err(CredentialIngestionError::MandatoryClaimsMissing)
    );
    assert_eq!(wrong_namespace_core.held_credentials_json(), "[]");
}

#[test]
fn mdoc_embedded_x5chain_accepts_unordered_cross_signed_intermediates() {
    let wallet = DemoWallet::new();
    let scenario = wallet.issuance_scenario();
    let root_a = decode_cert(ROOT_A_B64);
    let bridge_a = decode_cert(BRIDGE_A_B64);
    let bridge_b = decode_cert(BRIDGE_B_B64);
    let mut core = ready_core_with_anchors(&scenario, scenario.epoch, &[(root_a, "attestation")]);
    let credential = encoded_mdoc(&issued_mdoc(
        &scenario,
        "org.iso.18013.5.1",
        Some(cose::X5Chain::Chain(vec![
            scenario.issuer_cert_chain[0].clone(),
            bridge_b,
            bridge_a,
        ])),
    ));

    core.ingest_credential("mso_mdoc", &credential, &[], &scenario.issuer_id)
        .expect("the one path reaching Root A is built independently of input order");
    assert!(core
        .held_credentials_json()
        .contains("org.iso.18013.5.1.mDL"));
}

#[test]
fn mdoc_rejects_untrusted_ambiguous_and_expired_embedded_paths() {
    let wallet = DemoWallet::new();
    let scenario = wallet.issuance_scenario();
    let root_a = decode_cert(ROOT_A_B64);
    let root_b = decode_cert(ROOT_B_B64);
    let bridge_a = decode_cert(BRIDGE_A_B64);
    let bridge_b = decode_cert(BRIDGE_B_B64);
    let issuer = scenario.issuer_cert_chain[0].clone();

    let single_path_credential = encoded_mdoc(&issued_mdoc(
        &scenario,
        "org.iso.18013.5.1",
        Some(cose::X5Chain::Chain(vec![issuer.clone(), bridge_a.clone()])),
    ));
    let mut untrusted = ready_core_with_anchors(
        &scenario,
        scenario.epoch,
        &[(root_b.clone(), "attestation")],
    );
    assert_eq!(
        untrusted.ingest_credential(
            "mso_mdoc",
            &single_path_credential,
            &scenario.issuer_cert_chain,
            &scenario.issuer_id,
        ),
        Err(CredentialIngestionError::UntrustedIssuer)
    );

    let ambiguous_credential = encoded_mdoc(&issued_mdoc(
        &scenario,
        "org.iso.18013.5.1",
        Some(cose::X5Chain::Chain(vec![issuer, bridge_b, bridge_a])),
    ));
    let mut ambiguous = ready_core_with_anchors(
        &scenario,
        scenario.epoch,
        &[(root_a.clone(), "attestation"), (root_b, "attestation")],
    );
    assert_eq!(
        ambiguous.ingest_credential("mso_mdoc", &ambiguous_credential, &[], &scenario.issuer_id,),
        Err(CredentialIngestionError::UntrustedIssuer)
    );

    let mut expired = ready_core_with_anchors(
        &scenario,
        EXPIRED_CERTIFICATE_EPOCH,
        &[(root_a, "attestation")],
    );
    assert_eq!(
        expired.ingest_credential(
            "mso_mdoc",
            &single_path_credential,
            &scenario.issuer_cert_chain,
            &scenario.issuer_id,
        ),
        Err(CredentialIngestionError::UntrustedIssuer)
    );
    assert_eq!(untrusted.held_credentials_json(), "[]");
    assert_eq!(ambiguous.held_credentials_json(), "[]");
    assert_eq!(expired.held_credentials_json(), "[]");
}

#[test]
fn mdoc_issuer_signed_item_tampering_is_rejected_after_path_authentication() {
    let wallet = DemoWallet::new();
    let scenario = wallet.issuance_scenario();
    let mut issued = issued_mdoc(
        &scenario,
        "org.iso.18013.5.1",
        Some(cose::X5Chain::Single(scenario.issuer_cert_chain[0].clone())),
    );
    issued
        .name_spaces
        .get_mut("org.iso.18013.5.1")
        .expect("namespace")
        .first_mut()
        .expect("issuer-signed item")
        .element_value = Value::Text("Mallory".into());
    let tampered = encoded_mdoc(&issued);
    let mut core = ready_core(&scenario);

    assert_eq!(
        core.ingest_credential("mso_mdoc", &tampered, &[], &scenario.issuer_id),
        Err(CredentialIngestionError::SignatureInvalid)
    );
    assert_eq!(core.held_credentials_json(), "[]");
}

#[test]
fn mdoc_caller_path_and_identity_cannot_override_embedded_evidence() {
    let wallet = DemoWallet::new();
    let scenario = wallet.issuance_scenario();

    // A valid embedded path needs no caller reconstruction at the storage boundary.
    let mut no_caller_path = ready_core(&scenario);
    no_caller_path
        .ingest_credential(
            "mso_mdoc",
            scenario.mdl_mdoc_credential.as_bytes(),
            &[],
            &scenario.issuer_id,
        )
        .expect("embedded x5chain is authoritative");

    // Conversely, a trusted caller path cannot rescue issuerAuth evidence that carries the RP
    // leaf. The leaf shares the signing key and chains to the same CA, but lacks issuer identity.
    let rp_evidence = encoded_mdoc(&issued_mdoc(
        &scenario,
        "org.iso.18013.5.1",
        Some(cose::X5Chain::Single(RP_LEAF.to_vec())),
    ));
    let mut path_override = ready_core(&scenario);
    assert_eq!(
        path_override.ingest_credential(
            "mso_mdoc",
            &rp_evidence,
            &scenario.issuer_cert_chain,
            &scenario.issuer_id,
        ),
        Err(CredentialIngestionError::UntrustedIssuer)
    );

    let mut identity_override = ready_core(&scenario);
    assert_eq!(
        identity_override.ingest_credential(
            "mso_mdoc",
            scenario.mdl_mdoc_credential.as_bytes(),
            &scenario.issuer_cert_chain,
            "https://other-issuer.example",
        ),
        Err(CredentialIngestionError::IssuerMismatch)
    );
    assert_eq!(path_override.held_credentials_json(), "[]");
    assert_eq!(identity_override.held_credentials_json(), "[]");
}

#[test]
fn mdoc_without_embedded_x5chain_is_not_issuer_authenticated() {
    let wallet = DemoWallet::new();
    let scenario = wallet.issuance_scenario();
    let credential = encoded_mdoc(&issued_mdoc(&scenario, "org.iso.18013.5.1", None));
    let mut core = ready_core(&scenario);

    assert_eq!(
        core.ingest_credential(
            "mso_mdoc",
            &credential,
            &scenario.issuer_cert_chain,
            &scenario.issuer_id,
        ),
        Err(CredentialIngestionError::UntrustedIssuer)
    );
    assert_eq!(core.held_credentials_json(), "[]");
}

#[test]
fn forged_signature_never_reaches_holdings() {
    let wallet = DemoWallet::new();
    let scenario = wallet.issuance_scenario();
    let mut core = ready_core(&scenario);
    let compact = scenario.pid_credential_compact;
    let issuer_end = compact.find('~').expect("combined SD-JWT has a separator");
    let mut parts = compact[..issuer_end].split('.');
    let header = parts.next().unwrap();
    let payload = parts.next().unwrap();
    let mut signature = Base64UrlUnpadded::decode_vec(parts.next().unwrap()).unwrap();
    signature[0] ^= 1;
    let forged = format!(
        "{header}.{payload}.{}{}",
        Base64UrlUnpadded::encode_string(&signature),
        &compact[issuer_end..]
    )
    .into_bytes();

    assert_eq!(
        core.ingest_credential(
            "dc+sd-jwt",
            &forged,
            &scenario.issuer_cert_chain,
            &scenario.issuer_id,
        ),
        Err(CredentialIngestionError::SignatureInvalid)
    );
    assert_eq!(core.held_credentials_json(), "[]");
}

#[test]
fn credential_bound_to_another_device_is_rejected() {
    let wallet = DemoWallet::new();
    let scenario = wallet.issuance_scenario();
    let mut core = ready_core(&scenario);
    let other_device = SoftwareSigner::generate_p256().expect("test key");
    core.load_device_key(other_device.public_key_raw().to_vec());

    assert_eq!(
        core.ingest_credential(
            "dc+sd-jwt",
            scenario.pid_credential_compact.as_bytes(),
            &scenario.issuer_cert_chain,
            &scenario.issuer_id,
        ),
        Err(CredentialIngestionError::DeviceBindingMismatch)
    );
    assert_eq!(core.held_credentials_json(), "[]");
}

#[test]
fn a_valid_signature_without_a_trusted_path_is_rejected() {
    let wallet = DemoWallet::new();
    let scenario = wallet.issuance_scenario();
    let mut core = Core::new("wallet.example", "device-key");
    core.handle_event(wallet_core::Event::SetClock {
        epoch: scenario.epoch,
    });
    core.load_device_key(scenario.device_public_key.clone());

    assert_eq!(
        core.ingest_credential(
            "dc+sd-jwt",
            scenario.pid_credential_compact.as_bytes(),
            &scenario.issuer_cert_chain,
            &scenario.issuer_id,
        ),
        Err(CredentialIngestionError::UntrustedIssuer)
    );
    assert_eq!(core.held_credentials_json(), "[]");
}

#[test]
fn trusted_issuer_cannot_claim_another_catalogue_identity() {
    let wallet = DemoWallet::new();
    let scenario = wallet.issuance_scenario();
    let mut core = ready_core(&scenario);
    let other_issuer = decode_cert(OTHER_ISSUER_B64);

    // The alternate certificate chains to the same trusted CA and deliberately carries the same
    // signing key, but its authenticated URI is `other-issuer.example`. Signature/path validity
    // therefore cannot authorize its claim to be `issuer.example`.
    assert_eq!(
        core.ingest_credential(
            "dc+sd-jwt",
            scenario.pid_credential_compact.as_bytes(),
            &[other_issuer],
            &scenario.issuer_id,
        ),
        Err(CredentialIngestionError::IssuerMismatch)
    );
    assert_eq!(core.held_credentials_json(), "[]");
}

#[test]
fn shell_issuer_assertion_cannot_override_authenticated_identity() {
    let wallet = DemoWallet::new();
    let scenario = wallet.issuance_scenario();
    let mut core = ready_core(&scenario);

    assert_eq!(
        core.ingest_credential(
            "dc+sd-jwt",
            scenario.pid_credential_compact.as_bytes(),
            &scenario.issuer_cert_chain,
            "https://other-issuer.example",
        ),
        Err(CredentialIngestionError::IssuerMismatch)
    );
    assert_eq!(core.held_credentials_json(), "[]");
}

#[test]
fn credential_type_cannot_cross_trusted_list_service_domains() {
    let wallet = DemoWallet::new();
    let scenario = wallet.issuance_scenario();
    let mut core = Core::new("wallet.example", "device-key");
    core.handle_event(wallet_core::Event::SetClock {
        epoch: scenario.epoch,
    });
    core.load_device_key(scenario.device_public_key.clone());
    core.load_trust_list(
        &wallet.signed_trust_list_with_pid_anchor(),
        &scenario.operator_public_key,
    )
    .expect("PID-only trust list verifies");

    assert_eq!(
        core.ingest_credential(
            "mso_mdoc",
            scenario.mdl_mdoc_credential.as_bytes(),
            &scenario.issuer_cert_chain,
            &scenario.issuer_id,
        ),
        Err(CredentialIngestionError::IssuerServiceMismatch)
    );
    assert_eq!(core.held_credentials_json(), "[]");
}

#[test]
fn reader_leaf_cannot_be_repurposed_as_a_credential_issuer() {
    let wallet = DemoWallet::new();
    let scenario = wallet.issuance_scenario();
    let mut core = ready_core(&scenario);

    // This certificate has a valid path and the same signing key, but carries the RP profile and
    // no credential-issuer URI SAN.
    assert_eq!(
        core.ingest_credential(
            "dc+sd-jwt",
            scenario.pid_credential_compact.as_bytes(),
            &[RP_LEAF.to_vec()],
            &scenario.issuer_id,
        ),
        Err(CredentialIngestionError::UntrustedIssuer)
    );
    assert_eq!(core.held_credentials_json(), "[]");
}

#[test]
fn legacy_ffi_loader_cannot_inject_an_unverified_holding() {
    let wallet = DemoWallet::new();
    let scenario = wallet.scenario();
    let engine = WalletEngine::new("wallet.example".into(), "device-key".into());

    engine.load_credential(
        scenario.issuer_jwt,
        scenario.disclosures_by_claim_json,
        None,
    );

    assert_eq!(engine.held_credentials_json(), "[]");
}
