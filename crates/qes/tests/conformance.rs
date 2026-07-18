//! Tier-2 conformance: replay the traces the Lean model produced (formal/lean/QesModel.lean) and
//! assert the Rust reference model matches the proven model exactly. See plan Section 10.
//!
//! Regenerate the fixture with:
//!   (cd ../../formal/lean && lake exe qes_traces) > tests/model_traces.json

use qes::model::{bound, run, state_name, Doc, Ev};
use serde_json::Value;

fn parse_event(v: &Value) -> Ev {
    match v["kind"].as_str().expect("event kind") {
        "request" => Ev::Request(Doc {
            doc_id: v["docId"].as_u64().expect("docId"),
            nonce: v["nonce"].as_u64().expect("nonce"),
        }),
        "authorize" => Ev::Authorize,
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
            ctx.authorized,
            expect["authorized"].as_bool().unwrap(),
            "trace #{i}: authorized (SCA)"
        );
        assert_eq!(
            bound(&ctx),
            expect["bound"].as_bool().unwrap(),
            "trace #{i}: WYSIWYS bound"
        );
    }
}
