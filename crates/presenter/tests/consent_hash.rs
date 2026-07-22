//! presenter tests (plan Section 7): canonical/stable ScreenDescription encoding, consent hashing
//! (what-you-see-is-what-you-sign), and data minimization.
use cose::cbor::from_canonical_slice;
use crypto_traits::Digest;
use presenter::{
    canonical_bytes, consent_hash, minimum_claim_set, present, ConsentScreen, ScreenDescription,
    ScreenKind, Snapshot,
};

struct RealDigest;
impl Digest for RealDigest {
    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        use sha2::{Digest as _, Sha256};
        let mut h = Sha256::new();
        h.update(data);
        h.finalize().into()
    }
}

fn consent(claims: &[&str]) -> ScreenDescription {
    ScreenDescription::Consent(ConsentScreen {
        rp_display_name: "Example RP".into(),
        purpose: "age verification".into(),
        requested_claims: claims.iter().map(|s| s.to_string()).collect(),
        not_shared_claims: vec!["family_name".into()],
    })
}

#[test]
fn present_maps_snapshot_to_screen() {
    let snap = Snapshot {
        screen: Some(ScreenKind::Consent),
        consent: ConsentScreen {
            rp_display_name: "RP".into(),
            purpose: "p".into(),
            requested_claims: vec!["age_over_18".into()],
            not_shared_claims: vec!["family_name".into()],
        },
        error: None,
    };
    assert!(matches!(present(&snap), ScreenDescription::Consent(_)));
    assert_eq!(present(&Snapshot::default()), ScreenDescription::Loading);
}

#[test]
fn canonical_bytes_are_valid_cbor_and_deterministic() {
    let s = consent(&["age_over_18"]);
    let a = canonical_bytes(&s);
    let b = canonical_bytes(&s);
    assert_eq!(a, b, "must be deterministic");
    // It is valid canonical CBOR: decoding then re-encoding is a fixed point.
    let decoded = from_canonical_slice(&a).expect("valid canonical CBOR");
    assert_eq!(decoded.to_canonical(), a);
    // Shape: array(5) whose first element is the text tag "consent".
    assert_eq!(a[0], 0x85);
    assert_eq!(&a[1..9], &[0x67, b'c', b'o', b'n', b's', b'e', b'n', b't']);
}

#[test]
fn consent_hash_is_stable_and_tamper_evident() {
    let base = consent(&["age_over_18"]);
    let h1 = consent_hash(&RealDigest, &base);
    let h2 = consent_hash(&RealDigest, &base);
    assert_eq!(h1, h2, "same screen -> same hash");

    // Any change to what the user sees changes the hash (what-you-see-is-what-you-sign).
    let more = consent(&["age_over_18", "family_name"]);
    assert_ne!(consent_hash(&RealDigest, &more), h1);

    let mut different_complement = base;
    let ScreenDescription::Consent(ref mut screen) = different_complement else {
        unreachable!()
    };
    screen.not_shared_claims = vec!["birth_date".into()];
    assert_ne!(consent_hash(&RealDigest, &different_complement), h1);
}

#[test]
fn minimum_claim_set_is_intersection_deterministic() {
    let requested = vec![
        "family_name".to_string(),
        "age_over_18".to_string(),
        "age_over_18".to_string(), // duplicate
        "portrait".to_string(),    // requested but not held
    ];
    let held = vec!["age_over_18".to_string(), "family_name".to_string()];
    let min = minimum_claim_set(&requested, &held);
    // Only held claims, deduped, sorted.
    assert_eq!(
        min,
        vec!["age_over_18".to_string(), "family_name".to_string()]
    );
}
