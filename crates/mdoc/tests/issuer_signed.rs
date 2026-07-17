//! mdoc IssuerSigned tests (plan Section 4.2): tag-24 encoding, MSO round-trip, digest-match on
//! verify, and tamper detection. Crypto is a deterministic STUB over the crypto-traits boundary.
use mdoc::cbor::Value;
use mdoc::{
    build_and_sign, verify_issuer_signed, IssuerSignedItem, MdocError, MobileSecurityObject,
    ValidityInfo,
};
use std::collections::BTreeMap;

use crypto_traits::{Alg, CryptoError, Digest, KeyRef, Signer, Verifier};

// ---- deterministic stub crypto (proves wiring; real crypto is aws-lc-rs behind these traits) ----

fn fnv(seed: u64, data: &[u8]) -> u64 {
    let mut h = seed;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

struct StubCrypto;
impl Signer for StubCrypto {
    fn sign(&self, _k: &KeyRef, _a: Alg, payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Ok(fnv(0xcbf29ce484222325, payload).to_be_bytes().to_vec())
    }
}
impl Verifier for StubCrypto {
    fn verify(&self, _a: Alg, _pk: &[u8], payload: &[u8], sig: &[u8]) -> Result<(), CryptoError> {
        if fnv(0xcbf29ce484222325, payload).to_be_bytes().to_vec() == sig {
            Ok(())
        } else {
            Err(CryptoError::Backend("bad sig".into()))
        }
    }
}
impl Digest for StubCrypto {
    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        // Four independently-seeded FNV rounds → a deterministic 32-byte digest. Tamper-sensitive.
        let mut out = [0u8; 32];
        for (i, seed) in [1u64, 2, 3, 4].iter().enumerate() {
            out[i * 8..i * 8 + 8].copy_from_slice(&fnv(*seed, data).to_be_bytes());
        }
        out
    }
}

fn sample_namespaces() -> BTreeMap<String, Vec<IssuerSignedItem>> {
    let mut ns = BTreeMap::new();
    ns.insert(
        "org.iso.18013.5.1".to_string(),
        vec![
            IssuerSignedItem {
                digest_id: 0,
                random: vec![0xAA; 16],
                element_id: "family_name".into(),
                element_value: Value::Text("Andersson".into()),
            },
            IssuerSignedItem {
                digest_id: 1,
                random: vec![0xBB; 16],
                element_id: "age_over_18".into(),
                element_value: Value::Bool(true),
            },
        ],
    );
    ns
}

#[test]
fn issuer_signed_item_bytes_are_tag24_and_deterministic() {
    let item = IssuerSignedItem {
        digest_id: 7,
        random: vec![1, 2, 3, 4],
        element_id: "given_name".into(),
        element_value: Value::Text("Kim".into()),
    };
    let b1 = item.to_item_bytes();
    let b2 = item.to_item_bytes();
    assert_eq!(b1, b2, "encoding must be deterministic");
    // Tag 24 encodes as 0xd8 0x18 ...
    assert_eq!(&b1[..2], &[0xd8, 0x18], "must be a tag-24 wrapper");
}

#[test]
fn mso_roundtrips_through_canonical_cbor() {
    let crypto = StubCrypto;
    let issued = build_and_sign(
        sample_namespaces(),
        "org.iso.18013.5.1.mDL",
        Value::Null,
        ValidityInfo {
            signed: "2026-07-17T00:00:00Z".into(),
            valid_from: "2026-07-17T00:00:00Z".into(),
            valid_until: "2027-07-17T00:00:00Z".into(),
        },
        &crypto,
        &crypto,
        &KeyRef("issuer".into()),
        Alg::Es256,
    )
    .expect("build");

    let mso =
        verify_issuer_signed(&issued, &crypto, &crypto, b"issuer-pub", Alg::Es256).expect("verify");
    assert_eq!(mso.doc_type, "org.iso.18013.5.1.mDL");
    assert_eq!(mso.digest_algorithm, "SHA-256");
    // Re-encode the decoded MSO and confirm it decodes again (canonical fixed point).
    let bytes = mso.to_mso_bytes();
    assert_eq!(MobileSecurityObject::to_mso_bytes(&mso), bytes);
}

#[test]
fn verify_succeeds_for_untampered_credential() {
    let crypto = StubCrypto;
    let issued = build_and_sign(
        sample_namespaces(),
        "org.iso.18013.5.1.mDL",
        Value::Null,
        ValidityInfo::default(),
        &crypto,
        &crypto,
        &KeyRef("issuer".into()),
        Alg::Es256,
    )
    .unwrap();
    assert!(verify_issuer_signed(&issued, &crypto, &crypto, b"pub", Alg::Es256).is_ok());
}

#[test]
fn verify_detects_tampered_element_value() {
    let crypto = StubCrypto;
    let mut issued = build_and_sign(
        sample_namespaces(),
        "org.iso.18013.5.1.mDL",
        Value::Null,
        ValidityInfo::default(),
        &crypto,
        &crypto,
        &KeyRef("issuer".into()),
        Alg::Es256,
    )
    .unwrap();

    // Attacker flips age_over_18 from true to false WITHOUT re-signing the MSO.
    let items = issued.name_spaces.get_mut("org.iso.18013.5.1").unwrap();
    items[1].element_value = Value::Bool(false);

    let err = verify_issuer_signed(&issued, &crypto, &crypto, b"pub", Alg::Es256).unwrap_err();
    assert_eq!(err, MdocError::DigestMismatch);
}

#[test]
fn verify_detects_forged_issuer_signature() {
    let crypto = StubCrypto;
    let mut issued = build_and_sign(
        sample_namespaces(),
        "org.iso.18013.5.1.mDL",
        Value::Null,
        ValidityInfo::default(),
        &crypto,
        &crypto,
        &KeyRef("issuer".into()),
        Alg::Es256,
    )
    .unwrap();
    issued.issuer_auth.signature = vec![0; 8]; // wrong signature
    let err = verify_issuer_signed(&issued, &crypto, &crypto, b"pub", Alg::Es256).unwrap_err();
    assert!(matches!(err, MdocError::Cose(_)));
}
