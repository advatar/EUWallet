//! Self-contained demo fixtures for the iOS simulator app.
//!
//! These let the SwiftUI app drive a REAL end-to-end flow — real aws-lc-rs crypto, real data
//! minimisation, real trusted-list validation — with no live issuer/RP/PSP and no network.
//!
//! Everything here is DEMO scaffolding, not production. A real wallet receives its credential
//! from an issuer over OID4VCI, its device key from the Secure Enclave, and its trusted list from
//! the scheme operator. The demo generates equivalents in-process so the exact same core flow is
//! exercisable offline on the simulator, where the Secure Enclave is unavailable. The keys are
//! ephemeral (regenerated per `DemoWallet`), so nothing here is a credential of value.
//!
//! The device key lives in Rust ([`DemoWallet::sign_device`]) precisely so the shell's `Sign`
//! effect resolves to a real ES256 signature over the key the core validates against — the
//! simulator stand-in for the Secure Enclave signer used on device.

use std::collections::BTreeMap;
use std::sync::Arc;

use base64ct::{Base64UrlUnpadded, Encoding};
use crypto_backend::{AwsLc, SoftwareSigner};
use crypto_traits::{Alg, Digest, KeyRef, Signer};
use serde_json::json;

// Real openssl-generated RP chain, reused from the x509 crate's conformance vectors: `rp.der`
// (leaf reader cert) is issued by `ca.der`; `rp.pkcs8.der` is the leaf's private key. The demo
// trusted list anchors `ca.der`, so in-core RP registration validates against a real chain.
const CA_DER: &[u8] = include_bytes!("../../x509/tests/vectors/ca.der");
const RP_DER: &[u8] = include_bytes!("../../x509/tests/vectors/rp.der");
const RP_PKCS8: &[u8] = include_bytes!("../../x509/tests/vectors/rp.pkcs8.der");

/// A fixed clock inside the demo credential/trust-list validity windows.
const DEMO_EPOCH: i64 = 1_790_000_000;
/// The nonce the RP's request is bound to (echoed in the key-binding JWT).
const DEMO_NONCE: u64 = 424_242;

/// A self-contained payment request (PSD2/TS12 shape). Static because it needs no signing —
/// the SCA binding the user authorises is computed and signed in-core at approval time.
const PAYMENT_REQUEST_JSON: &[u8] = br#"{"creditor_name":"Acme Store","creditor_account":"DE89370400440532013000","amount_minor":1299,"currency":"EUR","transaction_id":"txn-1","nonce":7,"response_uri":"https://psp.example/authorize"}"#;

fn b64(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

/// Everything the shell must load/feed to drive the demo flows against the real core.
#[derive(uniffi::Record, Clone)]
pub struct DemoScenario {
    /// Wall-clock (Unix seconds) to give the core via `setClock`.
    pub epoch: i64,

    // --- Presentation (OpenID4VP) ---
    /// Issuer-signed SD-JWT VC (a PID with `family_name` + `age_over_18`).
    pub issuer_jwt: String,
    /// JSON object mapping claim name → base64url disclosure, for `loadCredential`.
    pub disclosures_by_claim_json: String,
    /// Operator-signed trusted list anchoring the RP-access CA.
    pub trust_list: Vec<u8>,
    /// Raw public key that signed `trust_list`.
    pub operator_public_key: Vec<u8>,
    /// Raw device public key to load into the core (`loadDeviceKey`).
    pub device_public_key: Vec<u8>,
    /// RP certificate chain (DER, leaf-first) the shell supplies on `resolveRpTrust`.
    pub rp_cert_chain: Vec<Vec<u8>>,
    /// Redirect URIs registered for the RP (empty for the demo).
    pub registered_redirect_uris: Vec<String>,
    /// RP-signed authorization request (compact JWS) requesting only `age_over_18`.
    pub presentation_request: Vec<u8>,

    // --- Payment (PSD2/TS12 SCA) ---
    /// A payment authorization request the shell feeds via `paymentAuthorizationRequestReceived`.
    pub payment_request: Vec<u8>,
}

/// Holds the demo's ephemeral keys and mints [`DemoScenario`]s. Also acts as the device signer for
/// the simulator, where no Secure Enclave exists.
#[derive(uniffi::Object)]
pub struct DemoWallet {
    device: SoftwareSigner,
    issuer: SoftwareSigner,
    operator: SoftwareSigner,
    rp: SoftwareSigner,
    wallet_provider: SoftwareSigner,
}

#[uniffi::export]
impl DemoWallet {
    /// Generate a fresh set of demo keys. The RP key is the one matching the real `rp.der` cert.
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            device: SoftwareSigner::generate_p256().expect("device keygen"),
            issuer: SoftwareSigner::generate_p256().expect("issuer keygen"),
            operator: SoftwareSigner::generate_p256().expect("operator keygen"),
            rp: SoftwareSigner::from_pkcs8_der(RP_PKCS8).expect("rp key"),
            wallet_provider: SoftwareSigner::generate_p256().expect("wp keygen"),
        })
    }

    /// Build the full demo scenario (credential, trusted list, signed request, payment request).
    pub fn scenario(&self) -> DemoScenario {
        let (issuer_jwt, by_claim) = self.issue(&[
            ("family_name", json!("Andersson")),
            ("age_over_18", json!(true)),
        ]);
        DemoScenario {
            epoch: DEMO_EPOCH,
            issuer_jwt,
            disclosures_by_claim_json: serde_json::to_string(&by_claim)
                .expect("serialize disclosures"),
            trust_list: self.signed_trust_list(),
            operator_public_key: self.operator.public_key_raw().to_vec(),
            device_public_key: self.device.public_key_raw().to_vec(),
            rp_cert_chain: vec![RP_DER.to_vec()],
            registered_redirect_uris: vec![],
            presentation_request: self.sign_request(DEMO_NONCE, &["age_over_18"]),
            payment_request: PAYMENT_REQUEST_JSON.to_vec(),
        }
    }

    /// Sign as the demo device key — the simulator stand-in for the Secure Enclave. The shell
    /// routes its `Sign` effect here; the resulting ES256 signature validates against
    /// [`DemoScenario::device_public_key`].
    pub fn sign_device(&self, payload: Vec<u8>) -> Vec<u8> {
        self.device
            .sign(&KeyRef("device-key".into()), Alg::Es256, &payload)
            .expect("device sign")
    }
}

impl DemoWallet {
    /// Like [`DemoWallet::scenario`], but the presentation request targets `response_uri` and
    /// carries a real DCQL query (OpenID4VP 1.0 §6) instead of the legacy `claims` array. Used by
    /// the live-I/O reference shell tests to point the wallet at a real local RP endpoint. Plain
    /// Rust only (not FFI-exported), so the generated bindings are unaffected.
    pub fn scenario_with_response_uri(&self, response_uri: &str) -> DemoScenario {
        let mut s = self.scenario();
        s.presentation_request = self.sign_request_dcql(DEMO_NONCE, response_uri);
        s
    }

    /// The demo issuer's raw public key — what an RP uses to verify the issuer signature of a
    /// presented SD-JWT VC. Plain Rust only (not FFI-exported).
    pub fn issuer_public_key(&self) -> Vec<u8> {
        self.issuer.public_key_raw().to_vec()
    }

    /// The nonce the demo presentation request is bound to (the RP checks it in the KB-JWT).
    pub fn demo_nonce(&self) -> u64 {
        DEMO_NONCE
    }

    /// A signed trusted list anchoring the demo CA for BOTH RP access and PID issuance, so one
    /// core can run the full lifecycle (issuance needs a `pid` anchor; presentation needs
    /// `rp-access-ca`). Plain Rust only (not FFI-exported).
    pub fn signed_trust_list_with_pid_anchor(&self) -> Vec<u8> {
        let header = b64(br#"{"alg":"ES256"}"#);
        let payload = b64(json!({
            "seq": 1,
            "valid_from": 0,
            "valid_until": 4_000_000_000i64,
            "anchors": [
                { "cert": b64(CA_DER), "service": "rp-access-ca", "status": "granted" },
                { "cert": b64(CA_DER), "service": "pid", "status": "granted" },
            ],
        })
        .to_string()
        .as_bytes());
        let signing_input = format!("{header}.{payload}");
        let sig = self
            .operator
            .sign(&KeyRef("op".into()), Alg::Es256, signing_input.as_bytes())
            .expect("operator sign");
        format!("{signing_input}.{}", b64(&sig)).into_bytes()
    }

    /// A Wallet Unit Attestation binding the demo device key at High assurance, signed by the demo
    /// wallet provider. The core verifies it in-core before proving possession during issuance.
    pub fn wua_jwt(&self) -> Vec<u8> {
        let header = b64(br#"{"alg":"ES256","typ":"wallet-unit-attestation+jwt"}"#);
        let payload = b64(json!({
            "iss": "https://wp.example",
            "exp": 4_000_000_000i64,
            "aal": "high",
            "cnf": { "jwk_raw": b64(self.device.public_key_raw()) },
        })
        .to_string()
        .as_bytes());
        let signing_input = format!("{header}.{payload}");
        let sig = self
            .wallet_provider
            .sign(&KeyRef("wp".into()), Alg::Es256, signing_input.as_bytes())
            .expect("wp sign");
        format!("{signing_input}.{}", b64(&sig)).into_bytes()
    }

    /// The demo wallet provider's raw public key (verifies [`DemoWallet::wua_jwt`]).
    pub fn wallet_provider_public_key(&self) -> Vec<u8> {
        self.wallet_provider.public_key_raw().to_vec()
    }

    /// An RP-signed OpenID4VP authorization request carrying a DCQL query for `age_over_18`,
    /// bound to `nonce`, answering to `response_uri`.
    fn sign_request_dcql(&self, nonce: u64, response_uri: &str) -> Vec<u8> {
        let header = b64(br#"{"alg":"ES256","typ":"oauth-authz-req+jwt"}"#);
        let payload = b64(serde_json::to_string(&json!({
            "client_id": "rp.example",
            "nonce": nonce,
            "aud": "wallet.example",
            "response_uri": response_uri,
            "purpose": "Prove you are over 18",
            "dcql_query": {
                "credentials": [{
                    "id": "pid",
                    "format": "dc+sd-jwt",
                    "meta": { "vct_values": ["urn:eudi:pid:1"] },
                    "claims": [{ "path": ["age_over_18"] }]
                }]
            },
        }))
        .expect("serialize request")
        .as_bytes());
        let signing_input = format!("{header}.{payload}");
        let sig = self
            .rp
            .sign(&KeyRef("r".into()), Alg::Es256, signing_input.as_bytes())
            .expect("rp sign");
        format!("{signing_input}.{}", b64(&sig)).into_bytes()
    }

    /// Issue an SD-JWT VC; return (issuer_jwt, disclosures_by_claim). Mirrors the issuance the
    /// wallet-core e2e tests perform, so the credential is byte-compatible with the core.
    fn issue(&self, claims: &[(&str, serde_json::Value)]) -> (String, BTreeMap<String, String>) {
        let mut by_claim = BTreeMap::new();
        let mut sd = Vec::new();
        for (i, (name, value)) in claims.iter().enumerate() {
            let raw = b64(
                serde_json::to_string(&json!([format!("s{i}"), name, value]))
                    .expect("serialize disclosure")
                    .as_bytes(),
            );
            sd.push(json!(b64(&self.digest_of(raw.as_bytes()))));
            by_claim.insert((*name).to_string(), raw);
        }
        let header = b64(br#"{"alg":"ES256","typ":"dc+sd-jwt"}"#);
        let payload = b64(serde_json::to_string(&json!({
            "iss": "https://issuer.example",
            "vct": "urn:eudi:pid:1",
            "_sd_alg": "sha-256",
            "_sd": sd,
        }))
        .expect("serialize issuer payload")
        .as_bytes());
        let signing_input = format!("{header}.{payload}");
        let sig = self
            .issuer
            .sign(&KeyRef("i".into()), Alg::Es256, signing_input.as_bytes())
            .expect("issuer sign");
        (format!("{signing_input}.{}", b64(&sig)), by_claim)
    }

    /// A signed trusted list granting the demo CA as an RP-access CA.
    fn signed_trust_list(&self) -> Vec<u8> {
        let header = b64(br#"{"alg":"ES256"}"#);
        let payload = b64(json!({
            "seq": 1,
            "valid_from": 0,
            "valid_until": 4_000_000_000i64,
            "anchors": [{ "cert": b64(CA_DER), "service": "rp-access-ca", "status": "granted" }],
        })
        .to_string()
        .as_bytes());
        let signing_input = format!("{header}.{payload}");
        let sig = self
            .operator
            .sign(&KeyRef("op".into()), Alg::Es256, signing_input.as_bytes())
            .expect("operator sign");
        format!("{signing_input}.{}", b64(&sig)).into_bytes()
    }

    /// An RP-signed OpenID4VP authorization request bound to `nonce`, requesting `requested`.
    fn sign_request(&self, nonce: u64, requested: &[&str]) -> Vec<u8> {
        let header = b64(br#"{"alg":"ES256","typ":"oauth-authz-req+jwt"}"#);
        let payload = b64(serde_json::to_string(&json!({
            "client_id": "rp.example",
            "nonce": nonce,
            "aud": "wallet.example",
            "response_uri": "https://rp.example/response",
            "purpose": "Prove you are over 18",
            "claims": requested,
        }))
        .expect("serialize request")
        .as_bytes());
        let signing_input = format!("{header}.{payload}");
        let sig = self
            .rp
            .sign(&KeyRef("r".into()), Alg::Es256, signing_input.as_bytes())
            .expect("rp sign");
        format!("{signing_input}.{}", b64(&sig)).into_bytes()
    }

    fn digest_of(&self, data: &[u8]) -> [u8; 32] {
        AwsLc.sha256(data)
    }
}
