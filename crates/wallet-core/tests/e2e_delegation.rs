//! D8 — end-to-end power-of-representation (delegation) flow across the stack, exercised through
//! wallet-core's public API.
//!
//! Chain under test: a mandate SD-JWT VC shaped exactly as the VCIssuer encoder emits it (D4:
//! `vct = urn:eudi:mandate:1`, agent key in `cnf`, selectively-disclosed `scope`/`mandator`/
//! `mandate_jti`) → the wallet recognises and selects it for a required scope (D6) → the headless
//! agent signs the presentation and appends a hash-chained receipt (D7) → the produced delegation
//! evidence satisfies the VCVerifier acceptance contract (D5): bound to the presenting agent key,
//! and the relying party's required powers are within the mandate's grant.
//!
//! issuer-core and verifier-core live in sibling repos, so the issuer's mandate SHAPE and the
//! verifier's ACCEPTANCE RULE are reproduced faithfully here; the real cross-repo wiring is the
//! deployed services. The one aligned property — a delegate can only ever exercise a subset of the
//! granted powers, bound to its own key — is what this test pins together.

use std::collections::BTreeSet;

use base64ct::{Base64UrlUnpadded, Encoding};
use crypto_backend::AwsLc;
use serde_json::{json, Value};
use wallet_core::agent::{
    ActionRequest, AgentSession, AgentUnitAttestation, AssuranceTier, AttestedSigner, HappEvidence,
    KeyProtection,
};
use wallet_core::delegation::{self, HeldMandate};
use wallet_core::HeldCredential;

const PRESENT_IDENTITY: &str = "urn:eudi:mandate:power:present-identity";
const SIGN_DOCUMENT: &str = "urn:eudi:mandate:power:sign-document";
const AUTHORISE_PAYMENT: &str = "urn:eudi:mandate:power:authorise-payment";

fn b64(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

fn agent_jwk() -> Value {
    json!({"kty": "EC", "crv": "P-256", "x": "AGENT_X", "y": "AGENT_Y"})
}

fn disclosure(name: &str, value: Value) -> String {
    b64(&serde_json::to_vec(&json!(["c2FsdA", name, value])).unwrap())
}

/// A mandate SD-JWT VC as the VCIssuer D4 encoder emits it: mandate `vct`, agent key in `cnf`,
/// delegator PID binding, and selectively-disclosed `mandator` / `scope` / `mandate_jti`.
fn issued_mandate(scope: &[&str]) -> HeldCredential {
    let payload = json!({
        "iss": "https://issuer.advatar.systems",
        "vct": delegation::MANDATE_VCT,
        "cnf": {"jwk": agent_jwk()},
        "cryptographically_bound_to": "eu.europa.ec.eudi.pid.1"
    });
    let issuer_jwt = format!(
        "{}.{}.{}",
        b64(b"{\"alg\":\"ES256\",\"typ\":\"dc+sd-jwt\"}"),
        b64(&serde_json::to_vec(&payload).unwrap()),
        "issuer-signature"
    );
    let mut disclosures_by_claim = std::collections::BTreeMap::new();
    disclosures_by_claim.insert(
        "mandator".to_owned(),
        disclosure("mandator", json!("urn:eudi:subject:erika-mustermann")),
    );
    disclosures_by_claim.insert("scope".to_owned(), disclosure("scope", json!(scope)));
    disclosures_by_claim.insert(
        "mandate_jti".to_owned(),
        disclosure("mandate_jti", json!("mandamus:cap:7f3a")),
    );
    HeldCredential {
        issuer_jwt,
        disclosures_by_claim,
        status: None,
    }
}

/// A device (Secure Enclave) agent key.
struct EnclaveSigner;
impl AttestedSigner for EnclaveSigner {
    fn agent_jwk(&self) -> Value {
        agent_jwk()
    }
    fn attestation(&self) -> AgentUnitAttestation {
        AgentUnitAttestation {
            protection: KeyProtection::SecureElement,
            remotely_attested: false,
        }
    }
    fn sign(&self, payload: &[u8]) -> Vec<u8> {
        let mut signature = b"enclave-es256:".to_vec();
        signature.extend_from_slice(payload);
        signature
    }
}

fn powers(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| (*s).to_owned()).collect()
}

/// Faithful mirror of VCVerifier `verifier-core::authorize_accept`'s delegation gate: a relying
/// party accepts iff the mandate is bound to the presenting agent key and its granted powers cover
/// what the RP requires. (Signature/status/revocation are the verifier's other, orthogonal gates.)
fn verifier_accepts(
    mandate: &HeldMandate,
    presenting_agent: &Value,
    rp_required: &BTreeSet<String>,
) -> bool {
    mandate.is_bound_to(presenting_agent) && rp_required.is_subset(&mandate.scope)
}

#[test]
fn issue_hold_present_verify_within_granted_scope() {
    // 1. VCIssuer emits a mandate granting present-identity + sign-document to the agent.
    let mandate_vc = issued_mandate(&[PRESENT_IDENTITY, SIGN_DOCUMENT]);
    let pid_vc = {
        // An ordinary PID the agent also holds (proves the agent key at presentation).
        let payload = json!({"vct": "eu.europa.ec.eudi.pid.1", "cnf": {"jwk": agent_jwk()}});
        HeldCredential {
            issuer_jwt: format!(
                "{}.{}.sig",
                b64(b"{}"),
                b64(&serde_json::to_vec(&payload).unwrap())
            ),
            disclosures_by_claim: std::collections::BTreeMap::new(),
            status: None,
        }
    };
    let holdings = [pid_vc, mandate_vc];

    // 2. A relying party asks for a presentation exercising `present-identity`.
    let rp_required = powers(&[PRESENT_IDENTITY]);

    // 3. The wallet selects the mandate that backs it, bound to the agent key (D6).
    let chosen =
        delegation::select_delegated_presentation(holdings.iter(), &agent_jwk(), &rp_required)
            .expect("a held mandate covers the request");
    assert_eq!(
        chosen.consent().on_behalf_of,
        "urn:eudi:subject:erika-mustermann"
    );
    assert_eq!(
        chosen.plan.mandate_jti.as_deref(),
        Some("mandamus:cap:7f3a")
    );

    // 4. The headless agent signs the presentation and appends a hash-chained receipt (D7).
    let mut session = AgentSession::new(EnclaveSigner);
    let request = ActionRequest {
        required_powers: rp_required.clone(),
        required_tier: AssuranceTier::T1,
        payload: b"openid4vp direct_post vp_token".to_vec(),
    };
    let action = session
        .act(&chosen.plan, &request, None, &AwsLc)
        .expect("action is within scope and assurance");
    assert!(action.signature.starts_with(b"enclave-es256:"));
    assert_eq!(
        action.receipt.on_behalf_of,
        "urn:eudi:subject:erika-mustermann"
    );
    assert_eq!(
        action.receipt.mandate_jti.as_deref(),
        Some("mandamus:cap:7f3a")
    );
    assert!(
        session.log().verify(&AwsLc),
        "receipt chain is tamper-evident"
    );

    // 5. The verifier accepts: bound to the presenting agent key and within the granted scope (D5).
    assert!(verifier_accepts(
        &chosen.mandate,
        &agent_jwk(),
        &rp_required
    ));

    // The aligned safety property, end to end: the exercised scope never exceeds the grant.
    assert!(chosen.plan.exercised_scope.is_subset(&chosen.mandate.scope));
}

#[test]
fn a_payment_beyond_the_grant_is_stopped_at_the_wallet() {
    // The mandate grants only present-identity; a payment is never delegated.
    let holdings = [issued_mandate(&[PRESENT_IDENTITY])];
    let rp_required = powers(&[AUTHORISE_PAYMENT]);

    // The wallet refuses to even select a presentation — it cannot over-claim (D6).
    let selected =
        delegation::select_delegated_presentation(holdings.iter(), &agent_jwk(), &rp_required);
    assert_eq!(
        selected,
        Err(delegation::DelegationError::ScopeInsufficient)
    );

    // And the verifier would reject it too (D5) — the property holds on both sides.
    let mandate = delegation::parse_mandate(&issued_mandate(&[PRESENT_IDENTITY])).unwrap();
    assert!(!verifier_accepts(&mandate, &agent_jwk(), &rp_required));
}

#[test]
fn a_payment_within_grant_needs_a_fresh_human_approval() {
    // This mandate DOES grant payments; a payment is a high-assurance (T2) action.
    let holdings = [issued_mandate(&[PRESENT_IDENTITY, AUTHORISE_PAYMENT])];
    let rp_required = powers(&[AUTHORISE_PAYMENT]);
    let chosen =
        delegation::select_delegated_presentation(holdings.iter(), &agent_jwk(), &rp_required)
            .expect("mandate grants payment");

    let mut session = AgentSession::new(EnclaveSigner);
    let request = ActionRequest {
        required_powers: rp_required,
        required_tier: AssuranceTier::T2, // a payment demands human step-up
        payload: b"authorise EUR 42.00 to Payee GmbH".to_vec(),
    };

    // No fresh HAPP → the agent refuses (D7 / the wallet's approval-before-signing gate).
    assert!(session.act(&chosen.plan, &request, None, &AwsLc).is_err());

    // A fresh iProov step-up at the required tier authorizes exactly this action.
    let approved = HappEvidence {
        fresh: true,
        tier: AssuranceTier::T2,
    };
    let action = session
        .act(&chosen.plan, &request, Some(approved), &AwsLc)
        .expect("fresh HAPP authorizes the payment");
    assert_eq!(action.receipt.seq, 0);
    assert!(session.log().verify(&AwsLc));
}
