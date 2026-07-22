//! presenter tests (plan Section 7): canonical/stable ScreenDescription encoding, consent hashing
//! (what-you-see-is-what-you-sign), and data minimization.
use cose::cbor::from_canonical_slice;
use crypto_traits::Digest;
use presenter::{
    canonical_bytes, consent_hash, minimum_claim_set, present, ConsentScreen, CredentialFormat,
    DocumentStatus, DocumentSummary, IssuanceRecovery, IssuanceRecoveryScreen, NfcReadState,
    ScreenDescription, ScreenKind, Snapshot,
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

fn pid_summary(status: DocumentStatus) -> DocumentSummary {
    DocumentSummary {
        document_id: "pid-1".into(),
        document_name: "National ID".into(),
        issuer_name: "Federal identity authority".into(),
        format: CredentialFormat::DcSdJwt,
        status,
        portrait_required: true,
    }
}

fn consent(claims: &[&str]) -> ScreenDescription {
    ScreenDescription::Consent(ConsentScreen {
        rp_display_name: "Example RP".into(),
        purpose: "age verification".into(),
        requested_claims: claims.iter().map(|s| s.to_string()).collect(),
        not_shared_claims: vec!["family_name".into()],
        verifier_registration: presenter::VerifierRegistration::Registered,
        trust_mark: Some(presenter::VerifierTrustMark::EudiWallet),
        retention: presenter::RetentionDisclosure::NotStored,
        over_ask: presenter::OverAskResult::WithinRegisteredScope,
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
            ..ConsentScreen::default()
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
    // Shape: array(9) whose first element is the text tag "consent".
    assert_eq!(a[0], 0x89);
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

    let mut different_policy = consent(&["age_over_18"]);
    let ScreenDescription::Consent(ref mut screen) = different_policy else {
        unreachable!()
    };
    screen.retention = presenter::RetentionDisclosure::Days { days: 30 };
    assert_ne!(consent_hash(&RealDigest, &different_policy), h1);

    let mut over_ask = consent(&["age_over_18"]);
    let ScreenDescription::Consent(ref mut screen) = over_ask else {
        unreachable!()
    };
    screen.over_ask = presenter::OverAskResult::ExceedsRegisteredScope {
        claims: vec!["age_over_18".into()],
    };
    assert_ne!(consent_hash(&RealDigest, &over_ask), h1);
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

#[test]
fn complete_issuance_journey_has_canonical_closed_screens() {
    let screens = [
        ScreenDescription::PinPreparation {
            document_name: "National ID".into(),
        },
        ScreenDescription::PinHelp,
        ScreenDescription::NfcReady {
            document_name: "National ID".into(),
        },
        ScreenDescription::NfcReading {
            state: NfcReadState::Reading,
        },
        ScreenDescription::IssuancePreparing(pid_summary(DocumentStatus::Preparing)),
        ScreenDescription::IssuanceReady(pid_summary(DocumentStatus::Ready)),
        ScreenDescription::IssuanceNeedsAttention {
            document: pid_summary(DocumentStatus::NeedsAttention),
            recovery: IssuanceRecovery::SessionInterrupted,
        },
        ScreenDescription::IssuanceRecovery(IssuanceRecoveryScreen {
            reason: IssuanceRecovery::WrongPin,
            document_name: "National ID".into(),
            attempts_remaining: Some(2),
            can_resume: true,
        }),
    ];

    for screen in screens {
        let bytes = canonical_bytes(&screen);
        let decoded = from_canonical_slice(&bytes).expect("valid canonical issuance screen");
        assert_eq!(decoded.to_canonical(), bytes);
    }
}

#[test]
fn issuance_recovery_and_status_change_the_canonical_contract() {
    let preparing = ScreenDescription::IssuancePreparing(pid_summary(DocumentStatus::Preparing));
    let ready = ScreenDescription::IssuanceReady(pid_summary(DocumentStatus::Ready));
    assert_ne!(canonical_bytes(&preparing), canonical_bytes(&ready));

    let wrong_pin = ScreenDescription::IssuanceRecovery(IssuanceRecoveryScreen {
        reason: IssuanceRecovery::WrongPin,
        document_name: "National ID".into(),
        attempts_remaining: Some(2),
        can_resume: true,
    });
    let blocked = ScreenDescription::IssuanceRecovery(IssuanceRecoveryScreen {
        reason: IssuanceRecovery::PinBlocked,
        document_name: "National ID".into(),
        attempts_remaining: None,
        can_resume: false,
    });
    assert_ne!(canonical_bytes(&wrong_pin), canonical_bytes(&blocked));
}
