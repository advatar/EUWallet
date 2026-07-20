//! Regression tests for the authentication-to-storage boundary. A credential can be structurally
//! valid and still must not enter holdings unless issuer trust, signature, type policy, validity,
//! mandatory claims and device binding all succeed.

use base64ct::{Base64UrlUnpadded, Encoding};
use crypto_backend::SoftwareSigner;
use wallet_core::{Core, CredentialIngestionError, DemoWallet, IssuanceScenario, WalletEngine};

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
