//! TestAgent — a headless CLI to *play with* delegation against the shipped `wallet-core` engine.
//!
//! It exercises the real Epic D1–D3 modules — `delegation::select_delegated_presentation` and
//! `agent::AgentSession::act` — the same code paths `tests/e2e_delegation.rs` pins, but as a runnable
//! demo you can point at different powers. It shows a mandate being selected and exercised within
//! scope, refused out of scope, and gated behind a fresh human approval, always with a tamper-evident
//! receipt chain.
//!
//! Run the canonical scenarios:            cargo run -p testagent
//! Try your own required powers:           cargo run -p testagent -- authorise-payment present-identity
//! (Short names map to `urn:eudi:mandate:power:*`. Payment is T2, account admin is T3 — both need a
//! fresh HAPP; everything else is T1.)

use std::collections::{BTreeMap, BTreeSet};

use base64ct::{Base64UrlUnpadded, Encoding};
use crypto_backend::AwsLc;
use serde_json::{json, Value};
use wallet_core::agent::{
    ActionRequest, AgentSession, AgentUnitAttestation, AssuranceTier, AttestedSigner, HappEvidence,
    KeyProtection,
};
use wallet_core::delegation::{self, DelegationError};
use wallet_core::HeldCredential;

/// The six delegated powers (short name → pinned URN), mirroring `POWER_TAXONOMY` in issuer-core.
const POWERS: &[(&str, &str)] = &[
    (
        "present-identity",
        "urn:eudi:mandate:power:present-identity",
    ),
    ("sign-document", "urn:eudi:mandate:power:sign-document"),
    (
        "authorise-payment",
        "urn:eudi:mandate:power:authorise-payment",
    ),
    (
        "manage-subscription",
        "urn:eudi:mandate:power:manage-subscription",
    ),
    ("access-records", "urn:eudi:mandate:power:access-records"),
    (
        "administer-account",
        "urn:eudi:mandate:power:administer-account",
    ),
];

fn urn(short: &str) -> Option<&'static str> {
    POWERS.iter().find(|(s, _)| *s == short).map(|(_, u)| *u)
}

fn b64(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

/// The agent's own key — the mandate's `cnf`. Whoever holds this key can exercise the mandate.
fn agent_jwk() -> Value {
    json!({"kty": "EC", "crv": "P-256", "x": "AGENT_X", "y": "AGENT_Y"})
}

fn disclosure(name: &str, value: Value) -> String {
    b64(&serde_json::to_vec(&json!(["c2FsdA", name, value])).unwrap())
}

/// A mandate SD-JWT VC exactly as the VCIssuer D4 encoder emits it: mandate `vct`, agent key in
/// `cnf`, and selectively-disclosed `mandator` / `scope` / `mandate_jti`.
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

/// A device (Secure Enclave) agent key. `sign` is a stand-in; the point is the *authority* gate.
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
        let mut sig = b"enclave-es256:".to_vec();
        sig.extend_from_slice(payload);
        sig
    }
}

fn powers(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| (*s).to_owned()).collect()
}

/// The assurance tier a power demands: payment steps up to T2, account admin to T3, else T1.
fn tier_for(required: &BTreeSet<String>) -> AssuranceTier {
    if required.contains(urn("administer-account").unwrap()) {
        AssuranceTier::T3
    } else if required.contains(urn("authorise-payment").unwrap()) {
        AssuranceTier::T2
    } else {
        AssuranceTier::T1
    }
}

/// Exercise one delegated action end to end and print what the wallet decided.
fn run(label: &str, granted: &[&str], required: &[&str]) {
    println!("\n── {label} ──");
    println!("   mandate grants : {}", granted.join(", "));
    println!("   RP requires    : {}", required.join(", "));

    let granted_urns: Vec<&str> = granted.iter().filter_map(|s| urn(s)).collect();
    let required_urns: Vec<&str> = required.iter().filter_map(|s| urn(s)).collect();
    let holdings = [issued_mandate(&granted_urns)];
    let rp_required = powers(&required_urns);

    // 1. The wallet selects a held mandate that is bound to the agent key and covers the request.
    let chosen = match delegation::select_delegated_presentation(
        holdings.iter(),
        &agent_jwk(),
        &rp_required,
    ) {
        Ok(c) => c,
        Err(DelegationError::ScopeInsufficient) => {
            println!("   ✗ REFUSED at selection: the mandate does not grant these powers.");
            println!("     (the wallet cannot over-claim — monotonic narrowing holds)");
            return;
        }
        Err(e) => {
            println!("   ✗ REFUSED at selection: {e:?}");
            return;
        }
    };

    // 2. The headless agent tries to act. Payment/admin need a fresh human approval (HAPP).
    let tier = tier_for(&rp_required);
    let request = ActionRequest {
        required_powers: rp_required.clone(),
        required_tier: tier,
        payload: format!("openid4vp presentation for {}", required.join("+")).into_bytes(),
    };
    let mut session = AgentSession::new(EnclaveSigner);

    let needs_stepup = matches!(tier, AssuranceTier::T2 | AssuranceTier::T3);
    if needs_stepup {
        // First without approval — must be refused.
        if session.act(&chosen.plan, &request, None, &AwsLc).is_err() {
            println!("   ⏸ HELD (tier {tier:?}): needs a fresh human approval before signing.");
        }
    }
    let happ = needs_stepup.then_some(HappEvidence { fresh: true, tier });
    match session.act(&chosen.plan, &request, happ, &AwsLc) {
        Ok(action) => {
            let r = &action.receipt;
            println!(
                "   ✓ SIGNED on behalf of {} (mandate {}, receipt #{}){}",
                r.on_behalf_of,
                r.mandate_jti.as_deref().unwrap_or("-"),
                r.seq,
                if needs_stepup { " after step-up" } else { "" }
            );
            // The load-bearing safety property, checked live.
            assert!(
                chosen.plan.exercised_scope.is_subset(&chosen.mandate.scope),
                "invariant violated: exercised scope exceeded the grant"
            );
            assert!(
                session.log().verify(&AwsLc),
                "receipt chain is not tamper-evident"
            );
            println!("   ✓ exercised scope ⊆ granted scope, and the receipt chain verifies.");
        }
        Err(e) => println!("   ✗ REFUSED at signing: {e:?}"),
    }
}

fn main() {
    println!("TestAgent — delegation playground (wallet-core delegation + agent)");

    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        // The three canonical scenarios.
        run(
            "In scope — present an identity",
            &["present-identity", "sign-document"],
            &["present-identity"],
        );
        run(
            "Out of scope — a payment that was never delegated",
            &["present-identity"],
            &["authorise-payment"],
        );
        run(
            "In scope but consequential — a delegated payment",
            &["present-identity", "authorise-payment"],
            &["authorise-payment"],
        );
        println!("\nTry your own:  cargo run -p testagent -- <power> [power…]");
        println!(
            "Powers: {}",
            POWERS
                .iter()
                .map(|(s, _)| *s)
                .collect::<Vec<_>>()
                .join(", ")
        );
        return;
    }

    // Custom run: the args are the RP-required powers; grant the agent a broad mandate to show the
    // gate deciding on scope + tier (an unknown power name is reported and ignored).
    for a in &args {
        if urn(a).is_none() {
            eprintln!(
                "unknown power '{a}' — known: {}",
                POWERS
                    .iter()
                    .map(|(s, _)| *s)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }
    let required: Vec<&str> = args
        .iter()
        .map(String::as_str)
        .filter(|a| urn(a).is_some())
        .collect();
    if required.is_empty() {
        std::process::exit(2);
    }
    let granted: Vec<&str> = POWERS.iter().map(|(s, _)| *s).collect(); // a full-taxonomy mandate
    run("Custom request", &granted, &required);
}
