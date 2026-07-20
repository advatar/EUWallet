//! The EUDI reference (eudiw.dev) **development** trust anchors parse with our in-core x509 parser,
//! so they can be loaded into the trusted list as issuer / reader-auth anchors for interop testing
//! against issuer.eudiw.dev / verifier.eudiw.dev.
//!
//! Fetched from the reference iOS wallet
//! (eu-digital-identity-wallet/eudi-app-ios-wallet-ui, `Wallet/Certificate/`). These are DEVELOPMENT
//! certificates — they MUST be replaced with the production PKI before any real deployment.

use x509::parse_cert;

// PID issuer CAs (the issuer-trust anchors). `_ut` is the reference/Utopia test issuer, `_eu` the
// EU-level one. Both are self-signed ECDSA roots.
const PID_CA_UT: &[u8] = include_bytes!("vectors/eudiw/pidissuerca02_ut.der");
const PID_CA_EU: &[u8] = include_bytes!("vectors/eudiw/pidissuerca02_eu.der");
// Reader-authentication (verifier) CA for the staging verifier — GlobalSign R45 AATL (RSA).
const READER_CA: &[u8] = include_bytes!("vectors/eudiw/r45_staging.der");

#[test]
fn eudiw_pid_issuer_cas_are_ingestible_anchors() {
    for (label, der) in [("UT", PID_CA_UT), ("EU", PID_CA_EU)] {
        let c =
            parse_cert(der).unwrap_or_else(|e| panic!("{label} PID issuer CA must parse: {e:?}"));
        assert!(c.is_ca, "{label} PID issuer CA has the CA basic-constraint");
        assert!(
            c.subject.contains("PID Issuer CA"),
            "{label} subject is the reference PID issuer CA, got {}",
            c.subject
        );
        // A usable trust anchor exposes a verification key (EUDI reference issuer CAs are ECDSA).
        assert!(
            !c.public_key_raw.is_empty(),
            "{label} anchor exposes a public key"
        );
    }
}

#[test]
fn eudiw_reader_ca_is_an_ingestible_profiled_rsa_anchor() {
    // RSA exists only in the certificate-signature boundary. JOSE/COSE `Alg` remains unchanged,
    // so interoperability with this development anchor does not broaden protocol algorithms.
    let c =
        parse_cert(READER_CA).expect("GlobalSign R45 reader CA must satisfy the RSA SPKI policy");
    assert!(
        c.subject.contains("GlobalSign") || c.subject.contains("R45"),
        "unexpected reader CA subject: {}",
        c.subject
    );
    assert!(c.is_ca);
    assert!(!c.public_key_raw.is_empty());
}
