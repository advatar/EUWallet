//! Wallet-to-wallet receive (TS09) driven through wallet-core, proving BOTH accept decisions are
//! made IN-CORE, never as shell booleans:
//!
//! - issuer_valid: the transferred credential's issuer chain is trusted AND signs the credential;
//! - peer_bound: the sender's transfer authorization is bound to THIS wallet's key + this exact
//!   credential.
//!
//! Real aws-lc-rs crypto throughout. Mirrors the proven receiver machine (formal/lean/W2wModel).

use base64ct::{Base64UrlUnpadded, Encoding};
use crypto_backend::SoftwareSigner;
use crypto_traits::{Alg, KeyRef, Signer};
use serde_json::json;
use wallet_core::{Core, Effect, Event};

// The issuer leaf `rp.der` chains to the trusted CA `ca.der`; `rp.pkcs8.der` is the leaf's key, so
// a credential signed with it verifies against the leaf cert's public key.
const CA_DER: &[u8] = include_bytes!("../../x509/tests/vectors/ca.der");
const ISSUER_LEAF: &[u8] = include_bytes!("../../x509/tests/vectors/rp.der");
const ISSUER_PKCS8: &[u8] = include_bytes!("../../x509/tests/vectors/rp.pkcs8.der");
const NOW: i64 = 1_790_000_000;

fn b64(b: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(b)
}

fn signed_trust_list(operator: &SoftwareSigner) -> Vec<u8> {
    let header = b64(br#"{"alg":"ES256"}"#);
    let payload = b64(json!({
        "seq": 1, "valid_from": 0, "valid_until": 4_000_000_000i64,
        "anchors": [{ "cert": b64(CA_DER), "service": "pid", "status": "granted" }]
    })
    .to_string()
    .as_bytes());
    let si = format!("{header}.{payload}");
    let sig = operator
        .sign(&KeyRef("op".into()), Alg::Es256, si.as_bytes())
        .unwrap();
    format!("{si}.{}", b64(&sig)).into_bytes()
}

/// An SD-JWT VC signed by the issuer whose key matches `ISSUER_LEAF`.
fn issued_credential(issuer: &SoftwareSigner) -> Vec<u8> {
    let header = b64(br#"{"alg":"ES256","typ":"dc+sd-jwt"}"#);
    let payload = b64(
        json!({"iss":"https://issuer.example","vct":"urn:eudi:pid:1"})
            .to_string()
            .as_bytes(),
    );
    let si = format!("{header}.{payload}");
    let sig = issuer
        .sign(&KeyRef("i".into()), Alg::Es256, si.as_bytes())
        .unwrap();
    format!("{si}.{}~", b64(&sig)).into_bytes()
}

/// Set up a receiver core with a device key, clock, and (optionally) the trust list loaded.
fn receiver(device: &SoftwareSigner, load_trust: bool, operator: &SoftwareSigner) -> Core {
    let mut core = Core::new("wallet.example", "device-key");
    core.handle_event(Event::SetClock { epoch: NOW });
    core.load_device_key(device.public_key_raw().to_vec());
    if load_trust {
        core.load_trust_list(&signed_trust_list(operator), operator.public_key_raw())
            .unwrap();
    }
    core
}

/// The sender signs a transfer authorization bound to `bound_key` (the key it believes it is
/// sending to) + the credential.
fn sender_transfer(
    sender: &SoftwareSigner,
    bound_key: &[u8],
    credential: &[u8],
    consent_hash: &[u8; 32],
    nonce: u64,
) -> Vec<u8> {
    let binding = w2w::transfer_authorization_binding(
        "wallet.example",
        bound_key,
        credential,
        consent_hash,
        nonce,
    );
    sender
        .sign(&KeyRef("s".into()), Alg::Es256, &binding)
        .unwrap()
}

#[test]
fn accepts_a_trusted_peer_bound_transfer_in_core() {
    let device = SoftwareSigner::generate_p256().unwrap();
    let operator = SoftwareSigner::generate_p256().unwrap();
    let sender = SoftwareSigner::generate_p256().unwrap();
    let issuer = SoftwareSigner::from_pkcs8_der(ISSUER_PKCS8).unwrap();

    let mut core = receiver(&device, true, &operator);
    let cred = issued_credential(&issuer);
    let consent = [7u8; 32];
    let sig = sender_transfer(&sender, device.public_key_raw(), &cred, &consent, 1);

    core.handle_event(Event::WalletTransferOfferCreated);
    core.handle_event(Event::WalletTransferReceived {
        credential: cred.clone(),
        issuer_cert_chain: vec![ISSUER_LEAF.to_vec()],
        sender_public_key: sender.public_key_raw().to_vec(),
        sender_signature: sig,
        sender_consent_hash: consent.to_vec(),
        nonce: 1,
    });

    assert_eq!(
        core.received_transfer_credential(),
        Some(cred),
        "accepted the transfer in-core"
    );
    // A privacy-preserving Transfer entry is logged.
    assert!(core.transaction_report_json().contains(r#""transfers":1"#));
}

#[test]
fn rejects_an_untrusted_issuer_in_core() {
    let device = SoftwareSigner::generate_p256().unwrap();
    let operator = SoftwareSigner::generate_p256().unwrap();
    let sender = SoftwareSigner::generate_p256().unwrap();
    let issuer = SoftwareSigner::from_pkcs8_der(ISSUER_PKCS8).unwrap();

    // No trust list loaded → issuer_valid is false in-core.
    let mut core = receiver(&device, false, &operator);
    let cred = issued_credential(&issuer);
    let consent = [7u8; 32];
    let sig = sender_transfer(&sender, device.public_key_raw(), &cred, &consent, 2);

    core.handle_event(Event::WalletTransferReceived {
        credential: cred,
        issuer_cert_chain: vec![ISSUER_LEAF.to_vec()],
        sender_public_key: sender.public_key_raw().to_vec(),
        sender_signature: sig,
        sender_consent_hash: consent.to_vec(),
        nonce: 2,
    });
    assert_eq!(
        core.received_transfer_credential(),
        None,
        "untrusted issuer → rejected"
    );
}

#[test]
fn rejects_a_misdirected_transfer_in_core() {
    let device = SoftwareSigner::generate_p256().unwrap();
    let operator = SoftwareSigner::generate_p256().unwrap();
    let sender = SoftwareSigner::generate_p256().unwrap();
    let issuer = SoftwareSigner::from_pkcs8_der(ISSUER_PKCS8).unwrap();

    let mut core = receiver(&device, true, &operator);
    let cred = issued_credential(&issuer);
    let consent = [7u8; 32];
    // The sender bound the transfer to a DIFFERENT wallet's key → peer_bound is false here.
    let other_key = SoftwareSigner::generate_p256()
        .unwrap()
        .public_key_raw()
        .to_vec();
    let sig = sender_transfer(&sender, &other_key, &cred, &consent, 3);

    core.handle_event(Event::WalletTransferReceived {
        credential: cred,
        issuer_cert_chain: vec![ISSUER_LEAF.to_vec()],
        sender_public_key: sender.public_key_raw().to_vec(),
        sender_signature: sig,
        sender_consent_hash: consent.to_vec(),
        nonce: 3,
    });
    assert_eq!(
        core.received_transfer_credential(),
        None,
        "misdirected transfer → rejected"
    );
}

#[test]
fn offer_publishes_this_wallets_key() {
    let device = SoftwareSigner::generate_p256().unwrap();
    let operator = SoftwareSigner::generate_p256().unwrap();
    let mut core = receiver(&device, true, &operator);
    let fx = core.handle_event(Event::WalletTransferOfferCreated);
    let offered = fx.iter().find_map(|e| match e {
        Effect::PublishTransferOffer { offered_key } => Some(offered_key.clone()),
        _ => None,
    });
    assert_eq!(
        offered.as_deref(),
        Some(device.public_key_raw()),
        "offer carries this wallet's key"
    );
}
