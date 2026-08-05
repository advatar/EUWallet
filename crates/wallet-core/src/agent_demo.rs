//! TestAgent demo surface (FFI): exercise a delegated mandate end to end, entirely in-core.
//!
//! This is the AUTHORITY layer of the TestAgent. A model (Apple Foundation Models, on the iOS side)
//! PROPOSES which powers an action needs; [`exercise_mandate`] is the wallet DECIDING whether the
//! agent may exercise them — `select_delegated_presentation` → `AgentSession::act` — and returning a
//! JSON report the UI renders. The model never holds keys or authority; it only proposes. (DEL.md:
//! "do not make the agent equal the model".)

use std::collections::{BTreeMap, BTreeSet};

use base64ct::{Base64UrlUnpadded, Encoding};
use crypto_backend::AwsLc;
use serde_json::{json, Value};

use crate::agent::{
    ActionRequest, AgentSession, AgentUnitAttestation, AssuranceTier, AttestedSigner, HappEvidence,
    KeyProtection,
};
use crate::delegation::{self, DelegationError};
use crate::HeldCredential;

const AUTHORISE_PAYMENT: &str = "urn:eudi:mandate:power:authorise-payment";
const ADMINISTER_ACCOUNT: &str = "urn:eudi:mandate:power:administer-account";

fn b64(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

/// The agent's own key — the mandate's `cnf`. Whoever holds this key can exercise the mandate.
fn agent_jwk() -> Value {
    json!({"kty": "EC", "crv": "P-256", "x": "AGENT_X", "y": "AGENT_Y"})
}

fn disclosure(name: &str, value: Value) -> String {
    b64(&serde_json::to_vec(&json!(["c2FsdA", name, value])).unwrap_or_default())
}

/// A mandate SD-JWT VC shaped as the VCIssuer encoder emits it (mandate `vct`, agent key in `cnf`,
/// selectively-disclosed `scope`/`mandator`/`mandate_jti`).
fn fixture_mandate(scope: &[String]) -> HeldCredential {
    let payload = json!({
        "iss": "https://issuer.advatar.systems",
        "vct": delegation::MANDATE_VCT,
        "cnf": {"jwk": agent_jwk()},
        "cryptographically_bound_to": "eu.europa.ec.eudi.pid.1"
    });
    let issuer_jwt = format!(
        "{}.{}.{}",
        b64(b"{\"alg\":\"ES256\",\"typ\":\"dc+sd-jwt\"}"),
        b64(&serde_json::to_vec(&payload).unwrap_or_default()),
        "issuer-signature"
    );
    let mut disclosures_by_claim = BTreeMap::new();
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

/// In-core Secure-Enclave-class signer for the demo. The point is the AUTHORITY gate, not key
/// custody, so the signature is a deterministic stand-in.
struct DemoSigner;
impl AttestedSigner for DemoSigner {
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
        let mut sig = b"demo-es256:".to_vec();
        sig.extend_from_slice(payload);
        sig
    }
}

/// The tier a request demands: payment steps up to T2, account admin to T3, else T1.
fn tier_for(required: &BTreeSet<String>) -> AssuranceTier {
    if required.iter().any(|p| p == ADMINISTER_ACCOUNT) {
        AssuranceTier::T3
    } else if required.iter().any(|p| p == AUTHORISE_PAYMENT) {
        AssuranceTier::T2
    } else {
        AssuranceTier::T1
    }
}

fn tier_name(t: AssuranceTier) -> &'static str {
    match t {
        AssuranceTier::T0 => "T0",
        AssuranceTier::T1 => "T1",
        AssuranceTier::T2 => "T2",
        AssuranceTier::T3 => "T3",
    }
}

fn report(v: &Value) -> String {
    serde_json::to_string(v).unwrap_or_else(|_| "{\"decision\":\"error\"}".to_owned())
}

/// Exercise a delegated mandate and return a JSON report the TestAgent UI renders.
///
/// `mandate_powers` / `requested_powers` are full power URNs (`urn:eudi:mandate:power:*`).
/// `requested_powers` is what the on-device model proposed; the wallet decides here.
/// `human_approved` supplies a fresh HAPP at the required tier for consequential actions.
#[uniffi::export]
#[must_use]
pub fn exercise_mandate(
    mandate_powers: Vec<String>,
    requested_powers: Vec<String>,
    human_approved: bool,
) -> String {
    let required: BTreeSet<String> = requested_powers.iter().cloned().collect();
    let tier = tier_for(&required);
    let holdings = [fixture_mandate(&mandate_powers)];

    let chosen = match delegation::select_delegated_presentation(
        holdings.iter(),
        &agent_jwk(),
        &required,
    ) {
        Ok(c) => c,
        Err(DelegationError::ScopeInsufficient) => {
            return report(&json!({
                "decision": "refused",
                "stage": "selection",
                "requiredTier": tier_name(tier),
                "reason": "The mandate does not grant these powers — the wallet cannot over-claim.",
            }));
        }
        Err(e) => {
            return report(&json!({
                "decision": "refused",
                "stage": "selection",
                "requiredTier": tier_name(tier),
                "reason": format!("{e:?}"),
            }));
        }
    };

    let needs_stepup = matches!(tier, AssuranceTier::T2 | AssuranceTier::T3);
    let mut session = AgentSession::new(DemoSigner);
    let action_request = ActionRequest {
        required_powers: required,
        required_tier: tier,
        payload: b"openid4vp presentation".to_vec(),
    };

    // Surface the "held for step-up" state: a consequential action with no fresh approval refuses.
    let held = needs_stepup
        && session
            .act(&chosen.plan, &action_request, None, &AwsLc)
            .is_err();
    let happ = needs_stepup.then_some(HappEvidence {
        fresh: human_approved,
        tier,
    });
    match session.act(&chosen.plan, &action_request, happ, &AwsLc) {
        Ok(action) => report(&json!({
            "decision": "signed",
            "requiredTier": tier_name(tier),
            "steppedUp": needs_stepup,
            "heldForApproval": held,
            "onBehalfOf": action.receipt.on_behalf_of,
            "mandateJti": action.receipt.mandate_jti,
            "receiptSeq": action.receipt.seq,
            "exercisedScope": chosen.plan.exercised_scope.iter().cloned().collect::<Vec<_>>(),
            "grantedScope": chosen.mandate.scope.iter().cloned().collect::<Vec<_>>(),
            "withinGrant": chosen.plan.exercised_scope.is_subset(&chosen.mandate.scope),
            "receiptChainVerified": session.log().verify(&AwsLc),
        })),
        Err(e) => report(&json!({
            "decision": "refused",
            "stage": "signing",
            "requiredTier": tier_name(tier),
            "heldForApproval": held,
            "reason": format!("{e:?}"),
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRESENT: &str = "urn:eudi:mandate:power:present-identity";
    const SIGN: &str = "urn:eudi:mandate:power:sign-document";

    #[test]
    fn in_scope_signs_and_chain_verifies() {
        let out = exercise_mandate(
            vec![PRESENT.to_owned(), SIGN.to_owned()],
            vec![PRESENT.to_owned()],
            false,
        );
        assert!(out.contains("\"decision\":\"signed\""));
        assert!(out.contains("\"receiptChainVerified\":true"));
        assert!(out.contains("\"withinGrant\":true"));
    }

    #[test]
    fn out_of_scope_refused_at_selection() {
        let out = exercise_mandate(
            vec![PRESENT.to_owned()],
            vec![AUTHORISE_PAYMENT.to_owned()],
            false,
        );
        assert!(out.contains("\"decision\":\"refused\""));
        assert!(out.contains("\"stage\":\"selection\""));
    }

    #[test]
    fn payment_within_grant_needs_fresh_approval() {
        let denied = exercise_mandate(
            vec![PRESENT.to_owned(), AUTHORISE_PAYMENT.to_owned()],
            vec![AUTHORISE_PAYMENT.to_owned()],
            false,
        );
        assert!(denied.contains("\"decision\":\"refused\""));
        assert!(denied.contains("\"stage\":\"signing\""));

        let approved = exercise_mandate(
            vec![PRESENT.to_owned(), AUTHORISE_PAYMENT.to_owned()],
            vec![AUTHORISE_PAYMENT.to_owned()],
            true,
        );
        assert!(approved.contains("\"decision\":\"signed\""));
        assert!(approved.contains("\"steppedUp\":true"));
    }
}
