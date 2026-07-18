//! Tier-2 conformance: replay the traces the Lean model produced (formal/lean/ProximityModel.lean)
//! and assert the Rust reference model matches the proven model exactly. See plan Section 10.
//!
//! Regenerate the fixture with:
//!   (cd ../../formal/lean && lake exe proximity_traces) > tests/model_traces.json

use iso18013_5::model::{run, state_name, Ev};
use serde_json::Value;

fn parse_event(v: &Value) -> Ev {
    match v["kind"].as_str().expect("event kind") {
        "startEngagement" => Ev::StartEngagement,
        "readerEstablish" => Ev::ReaderEstablish(v["valid"].as_bool().expect("valid")),
        "consentGrant" => Ev::ConsentGrant,
        "consentDecline" => Ev::ConsentDecline,
        "deviceSign" => Ev::DeviceSign,
        "terminate" => Ev::Terminate,
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
            ctx.session_bound,
            expect["sessionBound"].as_bool().unwrap(),
            "trace #{i}: sessionBound"
        );
        assert_eq!(
            ctx.consented,
            expect["consented"].as_bool().unwrap(),
            "trace #{i}: consented"
        );
    }
}
