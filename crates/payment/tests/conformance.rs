//! Tier-2 conformance: replay the traces the Lean model produced (formal/lean/PaymentModel.lean)
//! and assert the Rust reference model matches the proven model exactly. See plan Section 10.
//!
//! Regenerate the fixture with:
//!   (cd ../../formal/lean && lake exe payment_traces) > tests/model_traces.json

use payment::model::{bound, run, state_name, Ev, Payment};
use serde_json::Value;

fn parse_event(v: &Value) -> Ev {
    match v["kind"].as_str().expect("event kind") {
        "request" => Ev::Request(Payment {
            payee: v["payee"].as_str().expect("payee").to_string(),
            amount: v["amount"].as_u64().expect("amount"),
            nonce: v["nonce"].as_u64().expect("nonce"),
        }),
        "approve" => Ev::Approve,
        "decline" => Ev::Decline,
        "sign" => Ev::Sign,
        other => panic!("unknown event kind: {other}"),
    }
}

#[test]
fn rust_model_matches_lean_oracle() {
    let traces: Value =
        serde_json::from_str(include_str!("model_traces.json")).expect("valid trace JSON");
    let arr = traces.as_array().expect("top-level array");
    assert!(!arr.is_empty(), "oracle produced no traces");

    for (i, trace) in arr.iter().enumerate() {
        let events: Vec<Ev> = trace["events"]
            .as_array()
            .expect("events array")
            .iter()
            .map(parse_event)
            .collect();
        let ctx = run(&events);
        let expect = &trace["expect"];

        assert_eq!(
            state_name(&ctx.st),
            expect["state"].as_str().unwrap(),
            "trace #{i}: state mismatch vs Lean oracle"
        );
        assert_eq!(
            ctx.approved,
            expect["approved"].as_bool().unwrap(),
            "trace #{i}: approved (SCA)"
        );
        assert_eq!(
            bound(&ctx),
            expect["bound"].as_bool().unwrap(),
            "trace #{i}: dynamic-linking bound"
        );
    }
}
