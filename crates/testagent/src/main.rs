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

/// Accept either a short name (`present-identity`) or the full pinned URN and return the short form,
/// so the HTTP bridge can be fed whatever the caller has. An unknown token is passed through and later
/// rejected by `urn`.
fn short_of(s: &str) -> String {
    s.rsplit(':').next().unwrap_or(s).to_owned()
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

/// Exercise one delegated action end to end and return a STRUCTURED verdict (the same real gate the
/// CLI `run` prints, but as JSON for the HTTP bridge). `granted`/`required` are short power names.
fn exercise(granted: &[&str], required: &[&str], happ_fresh: bool) -> Value {
    let granted_urns: Vec<&str> = granted.iter().filter_map(|s| urn(s)).collect();
    let required_urns: Vec<&str> = required.iter().filter_map(|s| urn(s)).collect();
    if required_urns.is_empty() {
        return json!({"decision": "refused", "reason": "no known required power"});
    }
    let holdings = [issued_mandate(&granted_urns)];
    let rp_required = powers(&required_urns);

    // 1. Select a held mandate bound to the agent key that covers the request (monotonic narrowing).
    let chosen = match delegation::select_delegated_presentation(
        holdings.iter(),
        &agent_jwk(),
        &rp_required,
    ) {
        Ok(c) => c,
        Err(DelegationError::ScopeInsufficient) => {
            return json!({
                "decision": "refused",
                "reason": "scope_insufficient",
                "detail": "the mandate does not grant these powers (monotonic narrowing forbids widening)",
            });
        }
        Err(e) => return json!({"decision": "refused", "reason": format!("{e:?}")}),
    };

    // 2. Act. Payment (T2) / account admin (T3) need a fresh human approval before signing.
    let tier = tier_for(&rp_required);
    let tier_str = match tier {
        AssuranceTier::T0 => "T0",
        AssuranceTier::T1 => "T1",
        AssuranceTier::T2 => "T2",
        AssuranceTier::T3 => "T3",
    };
    let needs_stepup = matches!(tier, AssuranceTier::T2 | AssuranceTier::T3);
    if needs_stepup && !happ_fresh {
        return json!({
            "decision": "step_up",
            "tier": tier_str,
            "reason": "needs a fresh genuinely-present human approval (passkey + iProov) before signing",
        });
    }
    let request = ActionRequest {
        required_powers: rp_required.clone(),
        required_tier: tier,
        payload: format!("openid4vp presentation for {}", required.join("+")).into_bytes(),
    };
    let mut session = AgentSession::new(EnclaveSigner);
    let happ = needs_stepup.then_some(HappEvidence { fresh: true, tier });
    match session.act(&chosen.plan, &request, happ, &AwsLc) {
        Ok(action) => {
            let r = &action.receipt;
            json!({
                "decision": "signed",
                "tier": tier_str,
                "on_behalf_of": r.on_behalf_of,
                "mandate_jti": r.mandate_jti,
                "seq": r.seq,
                "exercised_scope": chosen.plan.exercised_scope.iter().collect::<Vec<_>>(),
                "narrowing_ok": chosen.plan.exercised_scope.is_subset(&chosen.mandate.scope),
                "chain_verified": session.log().verify(&AwsLc),
                "stepped_up": needs_stepup,
            })
        }
        Err(e) => json!({"decision": "refused", "reason": format!("{e:?}")}),
    }
}

/// The default mandate the local wallet-agent holds for the demo agent — the full pinned taxonomy.
fn default_granted() -> Vec<&'static str> {
    POWERS.iter().map(|(s, _)| *s).collect()
}

/// Pull an array-of-power-names field from a JSON body, normalising each to its short form.
fn body_powers(body: &Value, key: &str) -> Vec<String> {
    body.get(key)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|e| e.as_str().map(short_of))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

/// Route one HTTP request to a JSON reply. Read-only; the exercise gate is the real `wallet-core` one.
fn route(method: &str, path: &str, body: &[u8]) -> (&'static str, String) {
    let json_body = serde_json::from_slice::<Value>(body).unwrap_or(Value::Null);
    let path = path.split('?').next().unwrap_or(path);
    match (method, path) {
        ("GET", "/livez") => (
            "200 OK",
            json!({"ok": true, "service": "wallet-agent"}).to_string(),
        ),
        // Metadata only — the fixture mandate the wallet holds for this agent. Never the raw credential.
        ("GET", "/v1/mandates") => {
            let granted = default_granted();
            (
                "200 OK",
                json!({
                    "mandates": [{
                        "vct": delegation::MANDATE_VCT,
                        "mandate_jti": "mandamus:cap:7f3a",
                        "mandator": "urn:eudi:subject:erika-mustermann",
                        "granted_powers": granted,
                    }],
                })
                .to_string(),
            )
        }
        // Exercise a power against the real selection + agent gate; return the signed/step_up/refused verdict.
        ("POST", "/v1/present") => {
            let mut required = body_powers(&json_body, "required_powers");
            if let Some(p) = json_body.get("power").and_then(Value::as_str) {
                required.push(short_of(p));
            }
            let granted = {
                let g = body_powers(&json_body, "granted_powers");
                if g.is_empty() {
                    default_granted().iter().map(|s| (*s).to_owned()).collect()
                } else {
                    g
                }
            };
            let happ = json_body
                .get("happ_fresh")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let g: Vec<&str> = granted.iter().map(String::as_str).collect();
            let r: Vec<&str> = required.iter().map(String::as_str).collect();
            let mut verdict = exercise(&g, &r, happ);
            if let Some(rp) = json_body.get("relying_party").and_then(Value::as_str) {
                verdict["relying_party"] = json!(rp);
            }
            ("200 OK", verdict.to_string())
        }
        // Verify a narrowing sub-delegation (requested ⊆ granted) against the real selection gate.
        ("POST", "/v1/delegate") => {
            let granted = {
                let g = body_powers(&json_body, "granted_powers");
                if g.is_empty() {
                    default_granted().iter().map(|s| (*s).to_owned()).collect()
                } else {
                    g
                }
            };
            let requested = body_powers(&json_body, "requested_powers");
            let to_agent = json_body
                .get("to_agent")
                .and_then(Value::as_str)
                .unwrap_or("agent:sub");
            let granted_urns: Vec<&str> = granted.iter().filter_map(|s| urn(s)).collect();
            let requested_urns: Vec<&str> = requested.iter().filter_map(|s| urn(s)).collect();
            let holdings = [issued_mandate(&granted_urns)];
            let rp = powers(&requested_urns);
            let verdict = match delegation::select_delegated_presentation(
                holdings.iter(),
                &agent_jwk(),
                &rp,
            ) {
                Ok(_) => json!({
                    "decision": "narrowed",
                    "to_agent": to_agent,
                    "granted": granted,
                    "requested": requested,
                    "note": "narrowing verified against the real selection gate; a production sub-mandate is minted by the issuer/wallet",
                }),
                Err(DelegationError::ScopeInsufficient) => json!({
                    "decision": "refused",
                    "reason": "would_widen",
                    "granted": granted,
                    "requested": requested,
                }),
                Err(e) => json!({"decision": "refused", "reason": format!("{e:?}")}),
            };
            ("200 OK", verdict.to_string())
        }
        _ => ("404 Not Found", json!({"error": "not found"}).to_string()),
    }
}

/// A tiny, dependency-free HTTP/1.1 JSON server (blocking, one request at a time) exposing the
/// wallet-agent endpoints. This is the local-exercise backend `MANDAMUS_WALLET_URL` points the
/// `mandamus-eudi-wallet` plugin at, so `present`/`delegate` run against real `wallet-core` instead of
/// a deeplink hand-off. Dev/demo only — NOT a production service.
fn serve(addr: &str) -> std::io::Result<()> {
    use std::io::{BufRead, BufReader, Read, Write};
    let listener = std::net::TcpListener::bind(addr)?;
    eprintln!("wallet-agent listening on http://{addr}  (GET /v1/mandates · POST /v1/present · POST /v1/delegate)");
    for stream in listener.incoming() {
        let mut stream = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };
        let read_half = match stream.try_clone() {
            Ok(s) => s,
            Err(_) => continue,
        };
        let mut reader = BufReader::new(read_half);
        let mut request_line = String::new();
        if reader.read_line(&mut request_line).is_err() {
            continue;
        }
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or("").to_owned();
        let path = parts.next().unwrap_or("").to_owned();
        let mut content_length = 0usize;
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).is_err() {
                break;
            }
            if line == "\r\n" || line == "\n" || line.is_empty() {
                break;
            }
            let lower = line.to_ascii_lowercase();
            if let Some(v) = lower.strip_prefix("content-length:") {
                content_length = v.trim().parse().unwrap_or(0);
            }
        }
        let mut body = vec![0u8; content_length];
        if content_length > 0 && reader.read_exact(&mut body).is_err() {
            continue;
        }
        let (status, payload) = route(&method, &path, &body);
        let response = format!(
            "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{payload}",
            payload.len()
        );
        let _ = stream.write_all(response.as_bytes());
    }
    Ok(())
}

fn main() {
    // `serve [addr]` runs the local wallet-agent HTTP bridge instead of the CLI playground.
    let raw: Vec<String> = std::env::args().skip(1).collect();
    if raw.first().map(String::as_str) == Some("serve") {
        let addr = raw.get(1).map_or("127.0.0.1:8902", String::as_str);
        if let Err(e) = serve(addr) {
            eprintln!("wallet-agent failed to bind {addr}: {e}");
            std::process::exit(1);
        }
        return;
    }

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
