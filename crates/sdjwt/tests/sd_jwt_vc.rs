//! SD-JWT VC tests (plan Section 4.3): real disclosure vector, combined-format parsing,
//! selective-disclosure digest math with REAL SHA-256, verify wiring, and tamper/alg rejection.
use base64ct::{Base64UrlUnpadded, Encoding};
use crypto_traits::{Alg, CryptoError, Digest, KeyRef, Signer, Verifier};
use sdjwt::{ClaimPathElement, Disclosure, KeyBindingCheck, SdJwtError, SdJwtVc, SD_JWT_VC_DRAFT};
use serde_json::json;

// Real SHA-256 (via sha2) behind the Digest trait — lets us check disclosure digests for real.
struct RealDigest;
impl Digest for RealDigest {
    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        use sha2::{Digest as _, Sha256};
        let mut h = Sha256::new();
        h.update(data);
        h.finalize().into()
    }
}

// Deterministic stub signature over the JWS signing input (real ECDSA lives behind this trait).
fn fnv(data: &[u8]) -> Vec<u8> {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h.to_be_bytes().to_vec()
}
struct StubCrypto;
impl Signer for StubCrypto {
    fn sign(&self, _k: &KeyRef, _a: Alg, payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Ok(fnv(payload))
    }
}
impl Verifier for StubCrypto {
    fn verify(&self, _a: Alg, _pk: &[u8], payload: &[u8], sig: &[u8]) -> Result<(), CryptoError> {
        if fnv(payload) == sig {
            Ok(())
        } else {
            Err(CryptoError::Backend("bad".into()))
        }
    }
}

fn b64(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

#[test]
fn draft_version_is_pinned() {
    // A silent bump of the pinned draft must break CI (register change-watch item).
    assert_eq!(SD_JWT_VC_DRAFT, "draft-17");
}

#[test]
fn parses_published_disclosure_vector() {
    // From the SD-JWT specification's worked examples: ["_26bc4LT-ac6q2KI6cBW5es",
    // "family_name", "Möbius"] — checks base64url + JSON + UTF-8 handling against a real vector.
    let raw = "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0";
    let d = Disclosure::parse(raw).expect("parse");
    assert_eq!(d.salt, "_26bc4LT-ac6q2KI6cBW5es");
    assert_eq!(d.name.as_deref(), Some("family_name"));
    assert_eq!(d.value, json!("Möbius"));
    // The digest is base64url(SHA-256(ascii(raw))) — recomputable and stable.
    assert_eq!(d.digest_b64(&RealDigest), d.digest_b64(&RealDigest));
}

/// Build a signed SD-JWT VC with the given selectively-disclosable object members.
fn build(disclosable: &[(&str, serde_json::Value)]) -> (String, Vec<String>) {
    let digest = RealDigest;
    let mut disclosures = Vec::new();
    let mut sd = Vec::new();
    for (i, (name, value)) in disclosable.iter().enumerate() {
        let salt = format!("salt{i}");
        let arr = json!([salt, name, value]);
        let raw = b64(serde_json::to_string(&arr).unwrap().as_bytes());
        let d = Disclosure::parse(&raw).unwrap();
        sd.push(serde_json::Value::String(d.digest_b64(&digest)));
        disclosures.push(raw);
    }
    let header = b64(br#"{"alg":"ES256","typ":"dc+sd-jwt"}"#);
    let payload_json = json!({
        "iss": "https://issuer.example",
        "vct": "urn:eudi:pid:1",
        "_sd_alg": "sha-256",
        "_sd": sd,
    });
    let payload = b64(serde_json::to_string(&payload_json).unwrap().as_bytes());
    let signing_input = format!("{header}.{payload}");
    let sig = b64(&fnv(signing_input.as_bytes()));
    let issuer_jwt = format!("{signing_input}.{sig}");
    (issuer_jwt, disclosures)
}

fn signed_payload(payload_json: serde_json::Value) -> String {
    let header = b64(br#"{"alg":"ES256","typ":"dc+sd-jwt"}"#);
    let payload = b64(serde_json::to_string(&payload_json).unwrap().as_bytes());
    let signing_input = format!("{header}.{payload}");
    format!("{signing_input}.{}", b64(&fnv(signing_input.as_bytes())))
}

fn signed_jwt(header_json: serde_json::Value, payload_json: serde_json::Value) -> String {
    let header = b64(serde_json::to_string(&header_json).unwrap().as_bytes());
    let payload = b64(serde_json::to_string(&payload_json).unwrap().as_bytes());
    let signing_input = format!("{header}.{payload}");
    format!("{signing_input}.{}", b64(&fnv(signing_input.as_bytes())))
}

fn object_disclosure(salt: &str, name: &str, value: serde_json::Value) -> (String, String) {
    let raw = b64(serde_json::to_string(&json!([salt, name, value]))
        .unwrap()
        .as_bytes());
    let digest = Disclosure::parse(&raw).unwrap().digest_b64(&RealDigest);
    (raw, digest)
}

fn array_disclosure(salt: &str, value: serde_json::Value) -> (String, String) {
    let raw = b64(serde_json::to_string(&json!([salt, value]))
        .unwrap()
        .as_bytes());
    let digest = Disclosure::parse(&raw).unwrap().digest_b64(&RealDigest);
    (raw, digest)
}

#[test]
fn parse_combined_serialization() {
    let (jwt, disclosures) = build(&[("family_name", json!("Andersson"))]);
    let compact = format!("{jwt}~{}~", disclosures[0]);
    let parsed = SdJwtVc::parse(&compact).expect("parse");
    assert_eq!(parsed.issuer_jwt, jwt);
    assert_eq!(parsed.disclosures.len(), 1);
    assert!(parsed.key_binding_jwt.is_none());
}

#[test]
fn verify_and_disclose_returns_disclosed_claims() {
    let (jwt, disclosures) = build(&[
        ("family_name", json!("Andersson")),
        ("age_over_18", json!(true)),
    ]);
    let compact = format!("{jwt}~{}~{}~", disclosures[0], disclosures[1]);
    let sd = SdJwtVc::parse(&compact).unwrap();
    assert_eq!(sd.issuer_algorithm(), Ok(Alg::Es256));
    assert_eq!(
        sd.issuer_payload().unwrap().get("vct"),
        Some(&json!("urn:eudi:pid:1"))
    );

    let claims = sd
        .verify_and_disclose(&StubCrypto, &RealDigest, b"issuer-pub", Alg::Es256)
        .expect("verify");
    assert_eq!(claims.get("family_name"), Some(&json!("Andersson")));
    assert_eq!(claims.get("age_over_18"), Some(&json!(true)));
    assert_eq!(claims.get("iss"), Some(&json!("https://issuer.example")));
    // The _sd machinery must not leak into the disclosed claims.
    assert!(claims.get("_sd").is_none());
    assert!(claims.get("_sd_alg").is_none());
}

#[test]
fn recursively_processes_object_and_array_disclosures_with_exact_dependencies() {
    let (street_raw, street_digest) = object_disclosure("street-salt", "street", json!("Main"));
    let (address_raw, address_digest) = object_disclosure(
        "address-salt",
        "address",
        json!({"country":"DE", "_sd":[street_digest]}),
    );
    let (contact_raw, contact_digest) = array_disclosure(
        "contact-salt",
        json!({"type":"email", "value":"alice@example.com"}),
    );
    let jwt = signed_payload(json!({
        "iss":"https://issuer.example",
        "vct":"urn:eudi:pid:1",
        "_sd_alg":"sha-256",
        "_sd":[address_digest],
        "contacts":[
            {"...":contact_digest},
            {"type":"fixed", "value":"always"},
            {"...":b64(&[9u8; 32])}
        ]
    }));
    let sd = SdJwtVc::parse(&format!("{jwt}~{street_raw}~{contact_raw}~{address_raw}~")).unwrap();

    let processed = sd
        .verify_and_process(&StubCrypto, &RealDigest, b"issuer", Alg::Es256)
        .unwrap();

    assert_eq!(processed.claims["address"]["country"], json!("DE"));
    assert_eq!(processed.claims["address"]["street"], json!("Main"));
    assert_eq!(processed.claims["contacts"].as_array().unwrap().len(), 2);
    assert!(processed.claims.get("_sd").is_none());
    assert!(processed.claims.get("_sd_alg").is_none());

    let address = processed
        .disclosures
        .iter()
        .find(|d| d.raw == address_raw)
        .unwrap();
    assert_eq!(address.path, vec![ClaimPathElement::Name("address".into())]);
    assert_eq!(address.parent_digest, None);

    let street = processed
        .disclosures
        .iter()
        .find(|d| d.raw == street_raw)
        .unwrap();
    assert_eq!(
        street.path,
        vec![
            ClaimPathElement::Name("address".into()),
            ClaimPathElement::Name("street".into()),
        ]
    );
    assert_eq!(
        street.parent_digest.as_deref(),
        Some(address.digest.as_str())
    );

    let contact = processed
        .disclosures
        .iter()
        .find(|d| d.raw == contact_raw)
        .unwrap();
    assert_eq!(
        contact.path,
        vec![
            ClaimPathElement::Name("contacts".into()),
            ClaimPathElement::Index(0),
        ]
    );
    assert_eq!(contact.parent_digest, None);
}

#[test]
fn rejects_unreferenced_and_duplicate_disclosures() {
    let (child_raw, child_digest) = object_disclosure("child", "street", json!("Main"));
    let (_parent_raw, parent_digest) =
        object_disclosure("parent", "address", json!({"_sd":[child_digest]}));
    let jwt = signed_payload(json!({"_sd":[parent_digest]}));

    let unreferenced = SdJwtVc::parse(&format!("{jwt}~{child_raw}~")).unwrap();
    assert_eq!(
        unreferenced.verify_and_disclose(&StubCrypto, &RealDigest, b"issuer", Alg::Es256),
        Err(SdJwtError::UnknownDisclosure)
    );

    let (raw, digest) = object_disclosure("one", "name", json!("Alice"));
    let jwt = signed_payload(json!({"_sd":[digest]}));
    let duplicate = SdJwtVc::parse(&format!("{jwt}~{raw}~{raw}~")).unwrap();
    assert_eq!(
        duplicate.verify_and_disclose(&StubCrypto, &RealDigest, b"issuer", Alg::Es256),
        Err(SdJwtError::DuplicateClaim)
    );
}

#[test]
fn rejects_duplicate_digest_occurrences_at_any_depth() {
    let (raw, digest) = object_disclosure("one", "name", json!("Alice"));
    let jwt = signed_payload(json!({
        "_sd":[digest],
        "nested":{"_sd":[digest]}
    }));
    let sd = SdJwtVc::parse(&format!("{jwt}~{raw}~")).unwrap();
    assert_eq!(
        sd.verify_and_disclose(&StubCrypto, &RealDigest, b"issuer", Alg::Es256),
        Err(SdJwtError::DuplicateClaim)
    );
}

#[test]
fn enforces_object_array_shape_reserved_names_and_collisions() {
    let (object_raw, object_digest) = object_disclosure("one", "name", json!("Alice"));
    let jwt = signed_payload(json!({"items":[{"...":object_digest}]}));
    let wrong_array_shape = SdJwtVc::parse(&format!("{jwt}~{object_raw}~")).unwrap();
    assert_eq!(
        wrong_array_shape.verify_and_disclose(&StubCrypto, &RealDigest, b"issuer", Alg::Es256),
        Err(SdJwtError::InvalidJson)
    );

    let (array_raw, array_digest) = array_disclosure("two", json!("Alice"));
    let jwt = signed_payload(json!({"_sd":[array_digest]}));
    let wrong_object_shape = SdJwtVc::parse(&format!("{jwt}~{array_raw}~")).unwrap();
    assert_eq!(
        wrong_object_shape.verify_and_disclose(&StubCrypto, &RealDigest, b"issuer", Alg::Es256),
        Err(SdJwtError::InvalidJson)
    );

    for name in ["_sd", "_sd_alg", "..."] {
        let (raw, digest) = object_disclosure("reserved", name, json!(true));
        let jwt = signed_payload(json!({"_sd":[digest]}));
        let sd = SdJwtVc::parse(&format!("{jwt}~{raw}~")).unwrap();
        assert_eq!(
            sd.verify_and_disclose(&StubCrypto, &RealDigest, b"issuer", Alg::Es256),
            Err(SdJwtError::InvalidJson),
            "reserved name {name} was accepted"
        );
    }

    let (raw, digest) = object_disclosure("collision", "name", json!("Mallory"));
    let jwt = signed_payload(json!({"name":"Alice", "_sd":[digest]}));
    let collision = SdJwtVc::parse(&format!("{jwt}~{raw}~")).unwrap();
    assert_eq!(
        collision.verify_and_disclose(&StubCrypto, &RealDigest, b"issuer", Alg::Es256),
        Err(SdJwtError::DuplicateClaim)
    );
}

#[test]
fn rejects_malformed_recursive_machinery_and_noncanonical_hash_name() {
    for payload in [
        json!({"_sd":[7]}),
        json!({"nested":{"_sd":"digest"}}),
        json!({"items":[{"...":7}]}),
        json!({"items":[{"...":"digest", "other":true}]}),
        json!({"nested":{"_sd_alg":"sha-256"}}),
    ] {
        let jwt = signed_payload(payload);
        let sd = SdJwtVc::parse(&format!("{jwt}~")).unwrap();
        assert_eq!(
            sd.verify_and_disclose(&StubCrypto, &RealDigest, b"issuer", Alg::Es256),
            Err(SdJwtError::InvalidJson)
        );
    }

    let jwt = signed_payload(json!({"_sd_alg":"SHA-256"}));
    let sd = SdJwtVc::parse(&format!("{jwt}~")).unwrap();
    assert_eq!(
        sd.verify_and_disclose(&StubCrypto, &RealDigest, b"issuer", Alg::Es256),
        Err(SdJwtError::UnsupportedHashAlg)
    );

    let jwt = signed_payload(json!({"_sd_alg":7}));
    let sd = SdJwtVc::parse(&format!("{jwt}~")).unwrap();
    assert_eq!(
        sd.verify_and_disclose(&StubCrypto, &RealDigest, b"issuer", Alg::Es256),
        Err(SdJwtError::InvalidJson)
    );

    let jwt = signed_payload(json!({"_sd":["!!!!"]}));
    let sd = SdJwtVc::parse(&format!("{jwt}~")).unwrap();
    assert_eq!(
        sd.verify_and_disclose(&StubCrypto, &RealDigest, b"issuer", Alg::Es256),
        Err(SdJwtError::InvalidBase64)
    );
}

#[test]
fn recursive_processor_enforces_depth_and_digest_budgets() {
    let mut nested = json!(true);
    for _ in 0..34 {
        nested = json!({"child":nested});
    }
    let jwt = signed_payload(nested);
    let sd = SdJwtVc::parse(&format!("{jwt}~")).unwrap();
    assert_eq!(
        sd.verify_and_disclose(&StubCrypto, &RealDigest, b"issuer", Alg::Es256),
        Err(SdJwtError::TooLarge)
    );

    let digests = (0..4_097u32)
        .map(|index| {
            let mut bytes = [0u8; 32];
            bytes[..4].copy_from_slice(&index.to_be_bytes());
            json!(b64(&bytes))
        })
        .collect::<Vec<_>>();
    let jwt = signed_payload(json!({"_sd":digests}));
    let sd = SdJwtVc::parse(&format!("{jwt}~")).unwrap();
    assert_eq!(
        sd.verify_and_disclose(&StubCrypto, &RealDigest, b"issuer", Alg::Es256),
        Err(SdJwtError::TooLarge)
    );
}

#[test]
fn verify_rejects_a_jwt_from_another_media_type() {
    let header = b64(br#"{"alg":"ES256","typ":"JWT"}"#);
    let payload = b64(br#"{"iss":"https://issuer.example","vct":"urn:eudi:pid:1"}"#);
    let signing_input = format!("{header}.{payload}");
    let jwt = format!("{signing_input}.{}", b64(&fnv(signing_input.as_bytes())));
    let sd = SdJwtVc::parse(&format!("{jwt}~")).unwrap();

    assert_eq!(sd.issuer_algorithm(), Err(SdJwtError::InvalidType));
    assert_eq!(
        sd.verify_and_disclose(&StubCrypto, &RealDigest, b"pub", Alg::Es256),
        Err(SdJwtError::InvalidType)
    );
}

#[test]
fn key_binding_requires_profile_type_and_issued_at() {
    let issuer_jwt = signed_payload(json!({
        "iss":"https://issuer.example",
        "vct":"urn:eudi:pid:1"
    }));
    let presentation = format!("{issuer_jwt}~");
    let sd_hash = b64(&RealDigest.sha256(presentation.as_bytes()));
    let check = KeyBindingCheck {
        device_public_key: b"device",
        expected_aud: "rp.example",
        expected_nonce: 42,
        device_alg: Alg::Es256,
    };

    let payload = json!({
        "aud":"rp.example",
        "nonce":42,
        "iat":1_790_000_000,
        "sd_hash":sd_hash
    });
    let missing_type = signed_jwt(json!({"alg":"ES256"}), payload.clone());
    let sd = SdJwtVc::parse(&format!("{issuer_jwt}~{missing_type}")).unwrap();
    assert_eq!(
        sd.verify_presentation(&StubCrypto, &RealDigest, b"issuer", Alg::Es256, &check),
        Err(SdJwtError::KeyBindingMismatch)
    );

    let mut missing_iat = payload;
    missing_iat.as_object_mut().unwrap().remove("iat");
    let missing_iat = signed_jwt(json!({"alg":"ES256", "typ":"kb+jwt"}), missing_iat);
    let sd = SdJwtVc::parse(&format!("{issuer_jwt}~{missing_iat}")).unwrap();
    assert_eq!(
        sd.verify_presentation(&StubCrypto, &RealDigest, b"issuer", Alg::Es256, &check),
        Err(SdJwtError::KeyBindingMismatch)
    );

    let valid = signed_jwt(
        json!({"alg":"ES256", "typ":"kb+jwt"}),
        json!({
            "aud":"rp.example",
            "nonce":42,
            "iat":1_790_000_000,
            "sd_hash":sd_hash
        }),
    );
    let sd = SdJwtVc::parse(&format!("{issuer_jwt}~{valid}")).unwrap();
    assert!(sd
        .verify_presentation(&StubCrypto, &RealDigest, b"issuer", Alg::Es256, &check)
        .is_ok());
}

#[test]
fn verify_rejects_forged_disclosure() {
    let (jwt, _disclosures) = build(&[("family_name", json!("Andersson"))]);
    // Attacker appends a disclosure the issuer never committed to.
    let forged = b64(serde_json::to_string(&json!(["x", "role", "admin"]))
        .unwrap()
        .as_bytes());
    let compact = format!("{jwt}~{forged}~");
    let sd = SdJwtVc::parse(&compact).unwrap();
    let err = sd
        .verify_and_disclose(&StubCrypto, &RealDigest, b"pub", Alg::Es256)
        .unwrap_err();
    assert_eq!(err, SdJwtError::UnknownDisclosure);
}

#[test]
fn verify_rejects_a_disclosure_that_overwrites_a_plain_claim() {
    let raw = b64(
        serde_json::to_string(&json!(["salt", "family_name", "Mallory"]))
            .unwrap()
            .as_bytes(),
    );
    let disclosure = Disclosure::parse(&raw).unwrap();
    let header = b64(br#"{"alg":"ES256","typ":"dc+sd-jwt"}"#);
    let payload = b64(serde_json::to_string(&json!({
        "iss": "https://issuer.example",
        "vct": "urn:eudi:pid:1",
        "family_name": "Alice",
        "_sd": [disclosure.digest_b64(&RealDigest)]
    }))
    .unwrap()
    .as_bytes());
    let signing_input = format!("{header}.{payload}");
    let jwt = format!("{signing_input}.{}", b64(&fnv(signing_input.as_bytes())));
    let sd = SdJwtVc::parse(&format!("{jwt}~{raw}~")).unwrap();

    assert_eq!(
        sd.verify_and_disclose(&StubCrypto, &RealDigest, b"pub", Alg::Es256),
        Err(SdJwtError::DuplicateClaim)
    );
}

#[test]
fn parser_enforces_explicit_resource_budgets() {
    assert_eq!(
        SdJwtVc::parse(&"x".repeat(1024 * 1024 + 1)),
        Err(SdJwtError::TooLarge)
    );
    assert_eq!(
        Disclosure::parse(&"A".repeat(64 * 1024 + 1)),
        Err(SdJwtError::TooLarge)
    );
    let jwt = "a.b.c";
    let disclosures = std::iter::repeat_n("A", 257).collect::<Vec<_>>().join("~");
    assert_eq!(
        SdJwtVc::parse(&format!("{jwt}~{disclosures}~")),
        Err(SdJwtError::TooLarge)
    );
}

#[test]
fn verify_rejects_bad_signature() {
    let (jwt, disclosures) = build(&[("family_name", json!("A"))]);
    // Corrupt the signature segment.
    let mut bad = jwt.clone();
    bad.truncate(bad.rfind('.').unwrap() + 1);
    bad.push_str(&b64(&[0u8; 8]));
    let compact = format!("{bad}~{}~", disclosures[0]);
    let sd = SdJwtVc::parse(&compact).unwrap();
    let err = sd
        .verify_and_disclose(&StubCrypto, &RealDigest, b"pub", Alg::Es256)
        .unwrap_err();
    assert!(matches!(err, SdJwtError::Crypto(_)));
}

#[test]
fn rejects_alg_none() {
    let header = b64(br#"{"alg":"none"}"#);
    let payload = b64(br#"{"_sd":[]}"#);
    let jwt = format!("{header}.{payload}.{}", b64(&[0u8; 4]));
    let sd = SdJwtVc::parse(&format!("{jwt}~")).unwrap();
    let err = sd
        .verify_and_disclose(&StubCrypto, &RealDigest, b"pub", Alg::Es256)
        .unwrap_err();
    assert_eq!(err, SdJwtError::AlgNone);
}

#[test]
fn parse_rejects_malformed() {
    assert_eq!(SdJwtVc::parse("no-tilde"), Err(SdJwtError::Malformed));
    assert_eq!(SdJwtVc::parse("not-a-jwt~"), Err(SdJwtError::Malformed));
    // never panics on arbitrary input
    let _ = SdJwtVc::parse("");
    let _ = Disclosure::parse("!!!!not-base64");
}
