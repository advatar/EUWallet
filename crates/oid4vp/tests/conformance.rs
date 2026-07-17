//! Tier-2 conformance: replay the traces the Lean model produced (formal/lean) and assert
//! the Rust reference model matches the proven model exactly. See plan Section 10.
//!
//! Regenerate the fixture with:
//!   (cd ../../formal/lean && lake exe traces) > tests/model_traces.json

use oid4vp::model::{run, state_name, Ev};
use serde_json::Value;

fn parse_event(v: &Value) -> Ev {
    match v["kind"].as_str().expect("event kind") {
        "request" => Ev::Request(v["nonce"].as_u64().expect("nonce")),
        "validateSig" => Ev::ValidateSig,
        "consent" => Ev::Consent,
        "disclose" => Ev::Disclose,
        other => panic!("unknown event kind: {other}"),
    }
}

#[test]
fn rust_core_matches_lean_oracle() {
    let json = include_str!("model_traces.json");
    let traces: Value = serde_json::from_str(json).expect("valid trace JSON");
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
            state_name(ctx.st),
            expect["state"].as_str().unwrap(),
            "trace #{i}: state mismatch vs Lean oracle"
        );
        assert_eq!(
            ctx.disclosed,
            expect["disclosed"].as_bool().unwrap(),
            "trace #{i}: disclosed"
        );
        assert_eq!(
            ctx.sig_validated,
            expect["sigValidated"].as_bool().unwrap(),
            "trace #{i}: sigValidated"
        );
        assert_eq!(
            ctx.consented,
            expect["consented"].as_bool().unwrap(),
            "trace #{i}: consented"
        );
    }
}
