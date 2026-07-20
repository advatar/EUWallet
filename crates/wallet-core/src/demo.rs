//! Self-contained demo fixtures for the iOS simulator app.
//!
//! These let the SwiftUI app drive a REAL end-to-end flow — real aws-lc-rs crypto, real data
//! minimisation, real trusted-list validation — with no live issuer/RP/PSP and no network.
//!
//! Everything here is DEMO scaffolding, not production. A real wallet receives its credential
//! from an issuer over OID4VCI, its device key from the Secure Enclave, and its trusted list from
//! the scheme operator. The demo generates equivalents in-process so the exact same core flow is
//! exercisable offline on the simulator, where the Secure Enclave is unavailable. The keys are
//! demo-only or fixed conformance keys, so nothing here is a credential of value.
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
/// The authenticated direct-post endpoint carried by the demo RP registration.
const DEMO_RESPONSE_URI: &str = "https://rp.example/response";

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
    /// Authenticated delivery endpoints registered for the RP. The field keeps its legacy name for
    /// compatibility with the native FFI contract.
    pub registered_redirect_uris: Vec<String>,
    /// RP-signed authorization request (compact JWS) requesting only `age_over_18`.
    pub presentation_request: Vec<u8>,

    // --- Payment (PSD2/TS12 SCA) ---
    /// A payment authorization request the shell feeds via `paymentAuthorizationRequestReceived`.
    pub payment_request: Vec<u8>,
}

/// Everything the shell must load/feed to drive a REAL OpenID4VCI issuance against the core: the
/// trusted list (anchoring the issuer), the device key + Wallet Unit Attestation (so the in-core
/// key-attestation gate passes), the pre-authorized offer, the issuer's certificate chain, and the
/// issuer-signed credential the (stub) `/credential` endpoint returns for each offered type. The
/// core runs the full issuance machine — trust decision, WUA gate, device-signed proof — exactly
/// as in `shell-io`'s live-TCP lifecycle test; only the transport is stubbed.
#[derive(uniffi::Record, Clone)]
pub struct IssuanceScenario {
    /// Wall-clock (Unix seconds) for `setClock`.
    pub epoch: i64,
    /// Operator-signed trusted list anchoring the demo CA for issuance (pid + attestation) AND
    /// RP access, so one engine can both add credentials and present them.
    pub trust_list: Vec<u8>,
    /// Raw public key that signed `trust_list`.
    pub operator_public_key: Vec<u8>,
    /// Raw device public key to load (`loadDeviceKey`) — the key the WUA attests.
    pub device_public_key: Vec<u8>,
    /// Wallet Unit Attestation JWT (`loadWua`): binds the device key at High assurance.
    pub wua_jwt: Vec<u8>,
    /// Raw public key that signed the WUA (the wallet provider).
    pub wallet_provider_public_key: Vec<u8>,
    /// The issuer's certificate chain (DER, leaf-first) for the `CredentialOfferReceived` event —
    /// it chains to the trusted CA, so in-core issuer trust validates against a real chain.
    pub issuer_cert_chain: Vec<Vec<u8>>,
    /// The issuer identity recorded in the audit log.
    pub issuer_id: String,
    /// A pre-authorized credential offer (no PAR / browser / tx-code), fed via
    /// `credentialOfferReceived`.
    pub offer: Vec<u8>,
    /// The issuer-signed PID compact the stub `/credential` endpoint returns.
    pub pid_credential_compact: String,
    /// The issuer-signed mDL compact the stub `/credential` endpoint returns.
    pub mdl_credential_compact: String,
    /// The issuer-signed passport compact.
    pub passport_credential_compact: String,
    /// The issuer-signed national ID card compact.
    pub nid_credential_compact: String,
    /// The issuer-signed German ID card (Personalausweis) compact.
    pub german_id_credential_compact: String,
    /// An issuer-signed mDL in the ISO 18013-5 `mso_mdoc` format, base64url(IssuerSigned CBOR) —
    /// what an mso_mdoc `/credential` endpoint returns. Presented over OpenID4VP as a DeviceResponse.
    pub mdl_mdoc_credential: String,
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
            // The issuer must sign with the key authenticated by `RP_DER`; a random unrelated key
            // would make the demo credential structurally parseable but cryptographically false.
            issuer: SoftwareSigner::from_pkcs8_der(RP_PKCS8).expect("issuer key"),
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
            registered_redirect_uris: vec![DEMO_RESPONSE_URI.into()],
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

    /// An RP-signed OpenID4VP presentation request for `age_over_18`, bound to a caller-chosen
    /// `nonce`. A persistent wallet engine records used nonces (replay protection), so each new
    /// presentation must carry a fresh one — this lets the shell mint one per run.
    pub fn presentation_request(&self, nonce: u64) -> Vec<u8> {
        self.sign_request(nonce, &["age_over_18"])
    }

    /// An RP-signed OpenID4VP request carrying a DCQL `mso_mdoc` query for the mDL's `age_over_18`,
    /// bound to a caller-chosen `nonce`. Feeding this drives the wallet's mdoc-over-OpenID4VP path:
    /// the core selects the held mDL by doctype and answers with a signed ISO `DeviceResponse`.
    pub fn mdoc_presentation_request(&self, nonce: u64) -> Vec<u8> {
        let header = b64(br#"{"alg":"ES256","typ":"oauth-authz-req+jwt"}"#);
        let payload = b64(serde_json::to_string(&json!({
            "client_id": "rp.example",
            "nonce": nonce,
            "aud": "wallet.example",
            "response_uri": DEMO_RESPONSE_URI,
            "response_mode": "direct_post",
            "purpose": "Prove you are over 18 (mDL)",
            "dcql_query": {
                "credentials": [{
                    "id": "mdl",
                    "format": "mso_mdoc",
                    "meta": { "doctype_value": "org.iso.18013.5.1.mDL" },
                    "claims": [{ "path": ["org.iso.18013.5.1", "age_over_18"] }]
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

    /// A PSD2/TS12 payment authorization request bound to a caller-chosen `nonce` (and a matching
    /// unique transaction id), for the same fresh-per-run reason as [`Self::presentation_request`].
    pub fn payment_request(&self, nonce: u64) -> Vec<u8> {
        format!(
            r#"{{"creditor_name":"Acme Store","creditor_account":"DE89370400440532013000","amount_minor":1299,"currency":"EUR","transaction_id":"txn-{nonce}","nonce":{nonce},"response_uri":"https://psp.example/authorize"}}"#
        )
        .into_bytes()
    }

    /// The full issuance setup + the issuer-signed credentials the stub endpoint returns per type.
    /// Everything the shell needs to run a REAL OpenID4VCI issuance through the core (see
    /// [`IssuanceScenario`]).
    pub fn issuance_scenario(&self) -> IssuanceScenario {
        let (pid_jwt, pid_claims) = self.issue_as(
            "urn:eudi:pid:1",
            &[
                ("family_name", json!("Andersson")),
                ("given_name", json!("Astrid")),
                ("birthdate", json!("1988-04-12")),
                ("age_over_18", json!(true)),
            ],
        );
        let (mdl_jwt, mdl_claims) = self.issue_as(
            "urn:eudi:mdl:1",
            &[
                ("family_name", json!("Andersson")),
                ("given_name", json!("Astrid")),
                ("driving_privileges", json!("A, B, BE")),
                ("issuing_country", json!("SE")),
                ("age_over_18", json!(true)),
            ],
        );
        let (passport_jwt, passport_claims) = self.issue_as(
            "urn:eudi:passport:1",
            &[
                ("family_name", json!("Andersson")),
                ("given_name", json!("Astrid")),
                ("document_number", json!("P1234567")),
                ("nationality", json!("SE")),
                ("expiry_date", json!("2032-05-01")),
                ("age_over_18", json!(true)),
            ],
        );
        let (nid_jwt, nid_claims) = self.issue_as(
            "urn:eudi:nid:1",
            &[
                ("family_name", json!("Andersson")),
                ("given_name", json!("Astrid")),
                ("document_number", json!("ID987654")),
                ("issuing_country", json!("SE")),
                ("expiry_date", json!("2031-03-15")),
                ("age_over_18", json!(true)),
            ],
        );
        let (german_jwt, german_claims) = self.issue_as(
            "urn:eudi:pid:de:1",
            &[
                ("family_name", json!("Andersson")),
                ("given_name", json!("Astrid")),
                ("birthdate", json!("1988-04-12")),
                ("place_of_birth", json!("Berlin")),
                ("resident_address", json!("Alexanderplatz 1, 10178 Berlin")),
                ("issuing_country", json!("DE")),
                ("age_over_18", json!(true)),
            ],
        );
        IssuanceScenario {
            epoch: DEMO_EPOCH,
            trust_list: self.signed_trust_list_all_services(),
            operator_public_key: self.operator.public_key_raw().to_vec(),
            device_public_key: self.device.public_key_raw().to_vec(),
            wua_jwt: self.wua_jwt(),
            wallet_provider_public_key: self.wallet_provider.public_key_raw().to_vec(),
            issuer_cert_chain: vec![RP_DER.to_vec()],
            issuer_id: "https://issuer.example".into(),
            offer: br#"{"format":"dc+sd-jwt","grant":"pre-authorized","tx_code_required":false}"#
                .to_vec(),
            pid_credential_compact: Self::compact(&pid_jwt, &pid_claims),
            mdl_credential_compact: Self::compact(&mdl_jwt, &mdl_claims),
            passport_credential_compact: Self::compact(&passport_jwt, &passport_claims),
            nid_credential_compact: Self::compact(&nid_jwt, &nid_claims),
            german_id_credential_compact: Self::compact(&german_jwt, &german_claims),
            mdl_mdoc_credential: self.mdl_mdoc_credential(),
        }
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
        s.registered_redirect_uris = vec![response_uri.into()];
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
    /// A signed trusted list anchoring the demo CA for EVERY service the wallet needs in one
    /// engine: RP access (presentation), and PID + attestation issuance (add-a-credential). Plain
    /// Rust only (not FFI-exported).
    fn signed_trust_list_all_services(&self) -> Vec<u8> {
        let header = b64(br#"{"alg":"ES256"}"#);
        let payload = b64(json!({
            "seq": 1,
            "valid_from": 0,
            "valid_until": 4_000_000_000i64,
            "anchors": [
                { "cert": b64(CA_DER), "service": "rp-access-ca", "status": "granted" },
                { "cert": b64(CA_DER), "service": "pid", "status": "granted" },
                { "cert": b64(CA_DER), "service": "attestation", "status": "granted" },
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
            "response_mode": "direct_post",
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

    /// Issue a real ISO 18013-5 mDL in the `mso_mdoc` format, binding the demo device key, and
    /// return it as base64url(IssuerSigned CBOR) — the shape an `mso_mdoc` `/credential` endpoint
    /// returns and the wallet presents over OpenID4VP as a signed `DeviceResponse`.
    fn mdl_mdoc_credential(&self) -> String {
        use mdoc::cbor::Value;
        use mdoc::{build_and_sign, IssuerSignedItem, ValidityInfo};

        let items = vec![
            IssuerSignedItem {
                digest_id: 0,
                random: vec![0x1a; 16],
                element_id: "family_name".into(),
                element_value: Value::Text("Andersson".into()),
            },
            IssuerSignedItem {
                digest_id: 1,
                random: vec![0x2b; 16],
                element_id: "given_name".into(),
                element_value: Value::Text("Astrid".into()),
            },
            IssuerSignedItem {
                digest_id: 2,
                random: vec![0x3c; 16],
                element_id: "age_over_18".into(),
                element_value: Value::Bool(true),
            },
        ];
        let mut name_spaces = BTreeMap::new();
        name_spaces.insert("org.iso.18013.5.1".to_string(), items);
        let issued = build_and_sign(
            name_spaces,
            "org.iso.18013.5.1.mDL",
            Self::cose_key(self.device.public_key_raw()),
            ValidityInfo {
                signed: "2026-07-19T00:00:00Z".into(),
                valid_from: "2026-07-19T00:00:00Z".into(),
                valid_until: "2035-01-01T00:00:00Z".into(),
            },
            &AwsLc,
            &self.issuer,
            &KeyRef("i".into()),
            Alg::Es256,
        )
        .expect("issue demo mdoc");
        Base64UrlUnpadded::encode_string(&issued.to_value().to_canonical())
    }

    /// A COSE_Key (EC2 / P-256) for an uncompressed SEC1 public key `0x04 || X(32) || Y(32)`:
    /// `{1: 2 (EC2), -1: 1 (P-256), -2: X, -3: Y}`.
    fn cose_key(pubkey: &[u8]) -> mdoc::cbor::Value {
        use mdoc::cbor::Value;
        Value::Map(vec![
            (Value::Uint(1), Value::Uint(2)),
            (Value::Nint(0), Value::Uint(1)),
            (Value::Nint(1), Value::Bytes(pubkey[1..33].to_vec())),
            (Value::Nint(2), Value::Bytes(pubkey[33..65].to_vec())),
        ])
    }

    /// RFC 7800 confirmation JWK for an uncompressed P-256 public point.
    fn confirmation_jwk(pubkey: &[u8]) -> serde_json::Value {
        json!({
            "kty": "EC",
            "crv": "P-256",
            "x": b64(&pubkey[1..33]),
            "y": b64(&pubkey[33..65]),
        })
    }

    /// Issue an SD-JWT VC of type `vct`; return (issuer_jwt, disclosures_by_claim). Mirrors the
    /// issuance the wallet-core e2e tests perform, so the credential is byte-compatible with the
    /// core.
    fn issue_as(
        &self,
        vct: &str,
        claims: &[(&str, serde_json::Value)],
    ) -> (String, BTreeMap<String, String>) {
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
            "iat": DEMO_EPOCH,
            "exp": 4_000_000_000i64,
            "vct": vct,
            "_sd_alg": "sha-256",
            "_sd": sd,
            "cnf": { "jwk": Self::confirmation_jwk(self.device.public_key_raw()) },
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

    /// Issue a PID (`urn:eudi:pid:1`).
    fn issue(&self, claims: &[(&str, serde_json::Value)]) -> (String, BTreeMap<String, String>) {
        self.issue_as("urn:eudi:pid:1", claims)
    }

    /// The compact SD-JWT serialization (`<issuer-jwt>~<disclosure>~…~`) a pre-authorized issuer
    /// hands back at the `/credential` endpoint — exactly what the live-I/O lifecycle test feeds.
    fn compact(issuer_jwt: &str, by_claim: &BTreeMap<String, String>) -> String {
        let disclosures = by_claim.values().cloned().collect::<Vec<_>>().join("~");
        format!("{issuer_jwt}~{disclosures}~")
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
            "response_uri": DEMO_RESPONSE_URI,
            "response_mode": "direct_post",
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
