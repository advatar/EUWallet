//! Regression tests for the authentication-to-storage boundary. A credential can be structurally
//! valid and still must not enter holdings unless issuer trust, signature, type policy, validity,
//! mandatory claims and device binding all succeed.

use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use crypto_backend::{AwsLc, SoftwareSigner};
use crypto_traits::{Alg, KeyRef};
use mdoc::cbor::Value;
use mdoc::{IssuerSignedItem, ValidityInfo};
use std::collections::BTreeMap;
use wallet_core::{Core, CredentialIngestionError, DemoWallet, IssuanceScenario, WalletEngine};

const ISSUER_PKCS8: &[u8] = include_bytes!("../../x509/tests/vectors/rp.pkcs8.der");
const OTHER_ISSUER_B64: &str = include_str!("../../x509/tests/vectors/other-issuer.der.b64");
const RP_LEAF: &[u8] = include_bytes!("../../x509/tests/vectors/rp.der");

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

fn cose_key(public_key: &[u8]) -> Value {
    Value::Map(vec![
        (Value::Uint(1), Value::Uint(2)),
        (Value::Nint(0), Value::Uint(1)),
        (Value::Nint(1), Value::Bytes(public_key[1..33].to_vec())),
        (Value::Nint(2), Value::Bytes(public_key[33..65].to_vec())),
    ])
}

fn signed_mdoc(scenario: &IssuanceScenario, namespace: &str) -> Vec<u8> {
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
    let issued = mdoc::build_and_sign(
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
    Base64UrlUnpadded::encode_string(&issued.to_value().to_canonical()).into_bytes()
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
