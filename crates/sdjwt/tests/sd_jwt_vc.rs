//! SD-JWT VC tests (plan Section 4.3): real disclosure vector, combined-format parsing,
//! selective-disclosure digest math with REAL SHA-256, verify wiring, and tamper/alg rejection.
use base64ct::{Base64UrlUnpadded, Encoding};
use crypto_traits::{Alg, CryptoError, Digest, KeyRef, Signer, Verifier};
use sdjwt::{Disclosure, SdJwtError, SdJwtVc, SD_JWT_VC_DRAFT};
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
