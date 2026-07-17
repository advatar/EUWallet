//! The payoff: exercise the real aws-lc-rs backend through the actual codecs — COSE_Sign1, mdoc
//! issuer signing/verification, and X.509 chain validation with real ECDSA. This is what the
//! stub-crypto codec tests were standing in for.
use crypto_backend::{AwsLc, SoftwareSigner};
use crypto_traits::{Alg, KeyRef};

#[test]
fn cose_sign1_real_es256_roundtrip() {
    let issuer = SoftwareSigner::generate_p256().unwrap();
    let payload = b"mobile security object bytes";
    let msg = cose::CoseSign1::sign(
        &issuer,
        &KeyRef("issuer".into()),
        Alg::Es256,
        payload,
        &[],
        cose::UnprotectedHeader::default(),
    )
    .expect("sign");

    // Verify with the real backend against the issuer's raw public key.
    assert!(msg
        .verify(&AwsLc, Alg::Es256, issuer.public_key_raw(), &[], None)
        .is_ok());

    // Tamper the payload → verification fails.
    let mut tampered = msg.clone();
    tampered.payload = Some(b"forged".to_vec());
    assert!(tampered
        .verify(&AwsLc, Alg::Es256, issuer.public_key_raw(), &[], None)
        .is_err());
}

#[test]
fn mdoc_issuer_signed_real_crypto() {
    use mdoc::cbor::Value;
    use std::collections::BTreeMap;

    let issuer = SoftwareSigner::generate_p256().unwrap();
    let mut ns = BTreeMap::new();
    ns.insert(
        "org.iso.18013.5.1".to_string(),
        vec![
            mdoc::IssuerSignedItem {
                digest_id: 0,
                random: vec![0xAA; 16],
                element_id: "family_name".into(),
                element_value: Value::Text("Andersson".into()),
            },
            mdoc::IssuerSignedItem {
                digest_id: 1,
                random: vec![0xBB; 16],
                element_id: "age_over_18".into(),
                element_value: Value::Bool(true),
            },
        ],
    );

    let issued = mdoc::build_and_sign(
        ns,
        "org.iso.18013.5.1.mDL",
        Value::Null,
        mdoc::ValidityInfo::default(),
        &AwsLc,  // real SHA-256 digests
        &issuer, // real ES256 issuer signature
        &KeyRef("issuer".into()),
        Alg::Es256,
    )
    .expect("build");

    // Full verification with real crypto: issuer signature + per-item digest match.
    let mso =
        mdoc::verify_issuer_signed(&issued, &AwsLc, &AwsLc, issuer.public_key_raw(), Alg::Es256)
            .expect("verify");
    assert_eq!(mso.doc_type, "org.iso.18013.5.1.mDL");

    // Tamper a disclosed element → digest mismatch under real SHA-256.
    let mut tampered = issued.clone();
    tampered.name_spaces.get_mut("org.iso.18013.5.1").unwrap()[1].element_value =
        Value::Bool(false);
    assert_eq!(
        mdoc::verify_issuer_signed(
            &tampered,
            &AwsLc,
            &AwsLc,
            issuer.public_key_raw(),
            Alg::Es256
        ),
        Err(mdoc::MdocError::DigestMismatch)
    );
}

#[test]
fn x509_real_chain_verification() {
    // Verify the openssl-generated RP leaf's ECDSA (ASN.1 DER) signature against the CA, for real.
    const CA: &[u8] = include_bytes!("../../x509/tests/vectors/ca.der");
    const RP: &[u8] = include_bytes!("../../x509/tests/vectors/rp.der");
    const NOW: i64 = 1_790_000_000; // within the certs' validity window

    let ca = x509::parse_cert(CA).expect("parse CA");
    let path = x509::validate_path(&[RP.to_vec()], &[ca], NOW, &AwsLc)
        .expect("real ECDSA chain verification must succeed");
    assert_eq!(path.len(), 2); // leaf + anchor

    // And the full RP profile check passes with real crypto.
    let ca = x509::parse_cert(CA).unwrap();
    let profile = x509::check_relying_party(&[RP.to_vec()], &[ca], NOW, &AwsLc).unwrap();
    assert!(profile.registered);
}
