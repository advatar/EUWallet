//! Tier-2 conformance: replay the traces the Lean model produced (formal/lean/W2wModel.lean) and
//! assert the Rust reference model matches the proven model exactly. See plan Section 10.
//!
//! Regenerate the fixture with:
//!   (cd ../../formal/lean && lake exe w2w_traces) > tests/model_traces.json

use serde_json::Value;
use w2w::model::{run, state_name, Ev};

fn parse_event(v: &Value) -> Ev {
    match v["kind"].as_str().expect("event kind") {
        "createOffer" => Ev::CreateOffer,
        "transferReceived" => Ev::TransferReceived {
            issuer_valid: v["issuerValid"].as_bool().expect("issuerValid"),
            peer_bound: v["peerBound"].as_bool().expect("peerBound"),
        },
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
            ctx.issuer_valid,
            expect["issuerValid"].as_bool().unwrap(),
            "trace #{i}: issuerValid"
        );
        assert_eq!(
            ctx.peer_bound,
            expect["peerBound"].as_bool().unwrap(),
            "trace #{i}: peerBound"
        );
    }
}
