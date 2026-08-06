//! End-to-end proof that the wallet exercises a REAL, issuer-minted mandate — not a hand-built
//! look-alike. The golden `mandate.sdjwt` was produced by VCIssuer's own `mandate_sd_jwt_payload`
//! encoder and signed with ES256 (see VCIssuer `mint_mandate_golden_for_wallet_agent`); its issuer
//! public key and the agent's `cnf` key are vendored alongside it.
//!
//! `delegation::verify_and_hold_mandate` verifies the issuer's ES256 signature, the disclosure/`_sd`
//! binding, and the signed validity window (`nbf`/`exp`) before the mandate is held — so a tampered
//! signature, a swapped disclosure, the wrong issuer key, or an expired/not-yet-valid mandate is
//! rejected, none of which the old hand-built fixture could offer.
//!
//! Honest scope: the golden is signed with VCIssuer's real ENCODER but a fixed DEV key ([42;32]), not
//! the production Keychain issuing key; and this verifies the ISSUER's attestation — the AGENT's
//! proof-of-possession of the `cnf` key is a presentation-layer concern, not exercised here.

use std::collections::BTreeSet;

use base64ct::{Base64UrlUnpadded, Encoding};
use crypto_backend::AwsLc;
use serde_json::{json, Value};
use wallet_core::delegation::{self, DelegationError};

const GOLDEN: &str = include_str!("../../testagent/testdata/mandate.sdjwt");
const ISSUER_JWK: &str = include_str!("../../testagent/testdata/issuer_jwk.json");
const AGENT_JWK: &str = include_str!("../../testagent/testdata/agent_jwk.json");

// The golden's issuer-signed validity window (a real 15-minute mandate). Keep in sync with the mint.
const MINTED_AT: u64 = 1_700_000_000;
const VALID_AT: u64 = MINTED_AT + 450; // inside [nbf, exp)
const EXP: u64 = MINTED_AT + 900;

/// The delegate (agent) key the golden is bound to — the vendored real P-256 key.
fn agent_jwk() -> Value {
    serde_json::from_str(AGENT_JWK).expect("vendored agent jwk parses")
}

/// Issuer P-256 public key in SEC1 uncompressed form (`0x04 || X || Y`) from the vendored JWK.
fn issuer_pk_sec1() -> Vec<u8> {
    let jwk: Value = serde_json::from_str(ISSUER_JWK).expect("issuer jwk parses");
    let x = Base64UrlUnpadded::decode_vec(jwk["x"].as_str().unwrap()).unwrap();
    let y = Base64UrlUnpadded::decode_vec(jwk["y"].as_str().unwrap()).unwrap();
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    sec1
}

fn urn(short: &str) -> String {
    format!("urn:eudi:mandate:power:{short}")
}

fn required(powers: &[&str]) -> BTreeSet<String> {
    powers.iter().map(|p| urn(p)).collect()
}

#[test]
fn real_minted_mandate_verifies_and_backs_a_delegated_presentation() {
    let pk = issuer_pk_sec1();
    let held = delegation::verify_and_hold_mandate(GOLDEN.trim(), &pk, VALID_AT, &AwsLc, &AwsLc)
        .expect("the real minted mandate must verify (ES256 + _sd binding + within window)");

    // Drift guard: the disclosed claim set is EXACTLY what VCIssuer's encoder granted. If the encoder
    // wire structure changes, this pinned expectation forces a deliberate re-vendor of the golden.
    let mandate = delegation::parse_mandate(&held).expect("verified mandate parses");
    assert_eq!(mandate.mandator, "urn:eudi:subject:erika-mustermann");
    assert_eq!(mandate.mandate_jti.as_deref(), Some("mandamus:cap:7f3a"));
    let expected_scope: BTreeSet<String> = [
        "present-identity",
        "sign-document",
        "authorise-payment",
        "manage-subscription",
        "access-records",
    ]
    .iter()
    .map(|p| urn(p))
    .collect();
    assert_eq!(
        mandate.scope, expected_scope,
        "golden grants exactly 5 of 6 powers"
    );
    assert!(
        !mandate.scope.contains(&urn("administer-account")),
        "administer-account was withheld at mint — a real out-of-scope power"
    );

    // In-scope: a delegated presentation plan is produced, never wider than the grant.
    let plan = delegation::select_delegated_presentation(
        std::slice::from_ref(&held).iter(),
        &agent_jwk(),
        &required(&["present-identity"]),
    )
    .expect("in-scope power selects the mandate");
    assert!(plan.plan.exercised_scope.is_subset(&mandate.scope));

    // Out-of-scope: administer-account was not granted → refused (real monotonic narrowing).
    let refused = delegation::select_delegated_presentation(
        std::slice::from_ref(&held).iter(),
        &agent_jwk(),
        &required(&["administer-account"]),
    );
    assert_eq!(refused.err(), Some(DelegationError::ScopeInsufficient));
}

#[test]
fn a_mandate_bound_to_a_different_agent_key_is_not_selected() {
    let held = delegation::verify_and_hold_mandate(
        GOLDEN.trim(),
        &issuer_pk_sec1(),
        VALID_AT,
        &AwsLc,
        &AwsLc,
    )
    .expect("golden verifies");
    // A different agent key (perturb the vendored x coordinate) must not key-bind this mandate.
    let mut other = agent_jwk();
    other["x"] = json!("Zm9yZ2VkX2FnZW50X3hfY29vcmRpbmF0ZV9ub3RfdGhlX3JlYWw");
    let err = delegation::select_delegated_presentation(
        std::slice::from_ref(&held).iter(),
        &other,
        &required(&["present-identity"]),
    )
    .expect_err("a mandate bound to another agent key must not be selected");
    assert_eq!(err, DelegationError::AgentKeyMismatch);
}

#[test]
fn an_expired_mandate_is_rejected() {
    // Same good signature, but the verification instant is past `exp`.
    let err =
        delegation::verify_and_hold_mandate(GOLDEN.trim(), &issuer_pk_sec1(), EXP, &AwsLc, &AwsLc)
            .expect_err("an expired mandate must be rejected even with a valid signature");
    assert_eq!(err, DelegationError::Expired);
}

#[test]
fn a_not_yet_valid_mandate_is_rejected() {
    let err = delegation::verify_and_hold_mandate(
        GOLDEN.trim(),
        &issuer_pk_sec1(),
        MINTED_AT - 1,
        &AwsLc,
        &AwsLc,
    )
    .expect_err("a not-yet-valid mandate must be rejected");
    assert_eq!(err, DelegationError::NotYetValid);
}

#[test]
fn a_tampered_signature_is_rejected() {
    // Flip the last base64url char of the issuer signature segment (the 3rd JWT part).
    let (jwt, disclosures) = GOLDEN.trim().split_once('~').unwrap();
    let mut parts: Vec<&str> = jwt.split('.').collect();
    let sig = parts[2];
    let last = sig.chars().last().unwrap();
    let flipped_last = if last == 'A' { 'B' } else { 'A' };
    let tampered_sig = format!("{}{}", &sig[..sig.len() - 1], flipped_last);
    parts[2] = &tampered_sig;
    let tampered = format!("{}~{}", parts.join("."), disclosures);

    let err =
        delegation::verify_and_hold_mandate(&tampered, &issuer_pk_sec1(), VALID_AT, &AwsLc, &AwsLc)
            .expect_err("a tampered signature must be rejected");
    // Depending on which byte flips, the sig fails to verify or fails to decode — both are rejections.
    assert!(matches!(
        err,
        DelegationError::SignatureInvalid | DelegationError::Malformed
    ));
}

#[test]
fn a_swapped_disclosure_value_is_rejected() {
    // Re-encode the `scope` disclosure with an escalated power — its digest no longer matches `_sd`.
    let forged = Base64UrlUnpadded::encode_string(
        &serde_json::to_vec(&json!(["forgedsalt", "scope", [urn("administer-account")]])).unwrap(),
    );
    let (jwt, _) = GOLDEN.trim().split_once('~').unwrap();
    let forged_compact = format!("{jwt}~{forged}~");

    let err = delegation::verify_and_hold_mandate(
        &forged_compact,
        &issuer_pk_sec1(),
        VALID_AT,
        &AwsLc,
        &AwsLc,
    )
    .expect_err("a disclosure not matching a signed _sd digest must be rejected");
    assert!(matches!(
        err,
        DelegationError::Malformed | DelegationError::SignatureInvalid
    ));
}

#[test]
fn the_wrong_issuer_key_is_rejected() {
    // A different, valid P-256 public key (not the issuer's) must not verify the golden.
    let wrong = {
        let mut k = issuer_pk_sec1();
        k[1] ^= 0xFF; // perturb the X coordinate
        k
    };
    let err = delegation::verify_and_hold_mandate(GOLDEN.trim(), &wrong, VALID_AT, &AwsLc, &AwsLc)
        .expect_err("the wrong issuer key must be rejected");
    assert!(matches!(
        err,
        DelegationError::SignatureInvalid | DelegationError::Malformed
    ));
}
