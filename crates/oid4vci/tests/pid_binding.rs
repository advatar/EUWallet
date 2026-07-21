use base64ct::{Base64UrlUnpadded, Encoding};
use oid4vci::binding::{
    assemble_pid_bound_credential_request, parse_pid_binding_policy,
    pid_binding_proof_signing_input, validate_issued_pid_binding, PidBindingError,
    PidBindingPolicy, PID_VCT,
};
use serde_json::{json, Value};

fn compact(payload: Value) -> String {
    format!(
        "e30.{}.c2ln~",
        Base64UrlUnpadded::encode_string(&serde_json::to_vec(&payload).unwrap())
    )
}

#[test]
fn bound_profile_builds_pid_key_signed_request() {
    let metadata = json!({"pid_binding":{"required":true,"pid_vct":PID_VCT,
        "presentation_format":"dc+sd-jwt","binding_proof_alg_values_supported":["ES256"]}});
    let policy = parse_pid_binding_policy(&metadata).unwrap();
    assert_eq!(
        policy,
        PidBindingPolicy::Required {
            pid_vct: PID_VCT.into()
        }
    );
    let input = pid_binding_proof_signing_input(
        "https://issuer.example",
        "nonce",
        "jti",
        42,
        "pid.jwt",
        "new-jkt",
    )
    .unwrap();
    let request = assemble_pid_bound_credential_request(
        "learning:pid-bound",
        "credential.proof.jwt",
        "pid.jwt~disclosure~",
        &input,
        &[7; 64],
    )
    .unwrap();
    let request: Value = serde_json::from_slice(&request).unwrap();
    let proof = request["pid_binding"]["proof_jwt"].as_str().unwrap();
    assert_eq!(proof.split('.').count(), 3);
    assert!(request["pid_binding"]["pid_vp"]
        .as_str()
        .unwrap()
        .ends_with(proof));
}

#[test]
fn binding_claim_is_required_exactly_for_bound_profile() {
    let bound = compact(json!({"cryptographically_bound_to":PID_VCT}));
    let plain = compact(json!({"vct":"learning"}));
    let required = PidBindingPolicy::Required {
        pid_vct: PID_VCT.into(),
    };
    assert_eq!(validate_issued_pid_binding(&bound, &required), Ok(()));
    assert_eq!(
        validate_issued_pid_binding(&plain, &required),
        Err(PidBindingError::MissingBinding)
    );
    assert_eq!(
        validate_issued_pid_binding(&bound, &PidBindingPolicy::NotRequired),
        Err(PidBindingError::UnexpectedBinding)
    );
    assert_eq!(
        validate_issued_pid_binding(&plain, &PidBindingPolicy::NotRequired),
        Ok(())
    );
}
