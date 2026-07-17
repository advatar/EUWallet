//! End-to-end OpenID4VCI issuance with REAL crypto: the wallet's device signs the
//! proof-of-possession over the issuer's c_nonce, a (simulated) issuer verifies that proof with
//! aws-lc-rs and issues an SD-JWT VC, and the machine reaches CredentialIssued. Complements the
//! presentation e2e — together they cover issue → hold → present.
use base64ct::{Base64UrlUnpadded, Encoding};
use crypto_backend::{AwsLc, SoftwareSigner};
use crypto_traits::{Alg, KeyRef, Signer, Verifier};
use oid4vci::{step, CredentialFormat, Env, Input, Output, State};
use serde_json::{json, Value};

fn b64(b: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(b)
}

/// The issuer verifies the wallet's proof JWT (real ECDSA) and, if valid, issues an SD-JWT VC.
fn issuer_verify_proof_and_issue(
    issuer: &SoftwareSigner,
    proof_jwt: &[u8],
    device_pub: &[u8],
    expected_aud: &str,
    expected_nonce: u64,
) -> Option<Vec<u8>> {
    let s = std::str::from_utf8(proof_jwt).ok()?;
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig = Base64UrlUnpadded::decode_vec(parts[2]).ok()?;
    // Real verification of the device's proof signature.
    AwsLc
        .verify(Alg::Es256, device_pub, signing_input.as_bytes(), &sig)
        .ok()?;
    // Check aud + nonce binding.
    let payload: Value =
        serde_json::from_slice(&Base64UrlUnpadded::decode_vec(parts[1]).ok()?).ok()?;
    if payload["aud"].as_str()? != expected_aud || payload["nonce"].as_u64()? != expected_nonce {
        return None;
    }
    // Issue a minimal SD-JWT VC signed by the issuer.
    let header = b64(br#"{"alg":"ES256","typ":"dc+sd-jwt"}"#);
    let body = b64(serde_json::to_string(
        &json!({"iss":"https://issuer.example","vct":"urn:eudi:pid:1"}),
    )
    .unwrap()
    .as_bytes());
    let si = format!("{header}.{body}");
    let isig = issuer
        .sign(&KeyRef("i".into()), Alg::Es256, si.as_bytes())
        .ok()?;
    Some(format!("{si}.{}~", b64(&isig)).into_bytes())
}

#[test]
fn full_issuance_with_real_proof_of_possession() {
    let device = SoftwareSigner::generate_p256().unwrap();
    let issuer = SoftwareSigner::generate_p256().unwrap();
    const C_NONCE: u64 = 55555;

    let seen: Vec<u64> = vec![];
    let env = Env {
        issuer_trusted: true,
        proof_key_attested: true,
        seen_c_nonces: &seen,
        device_key_ref: "device-key",
        issuer_id: "https://issuer.example",
        now_epoch: 1_790_000_000,
    };

    // Offer (pre-auth, no PIN) → token → SignProof.
    let offer =
        br#"{"format":"dc+sd-jwt","grant":"pre-authorized","tx_code_required":false}"#.to_vec();
    let (s, _) = step(&State::Idle, &Input::CredentialOffer(offer), &env);
    let (s, out) = step(
        &s,
        &Input::TokenResponse {
            bound: true,
            c_nonce: C_NONCE,
        },
        &env,
    );
    let signing_input = match out.as_slice() {
        [Output::SignProof { signing_input, .. }] => signing_input.clone(),
        other => panic!("expected SignProof, got {other:?}"),
    };

    // Device signs the proof (Secure Enclave in production).
    let proof_sig = device
        .sign(&KeyRef("device-key".into()), Alg::Es256, &signing_input)
        .unwrap();
    let (s, out) = step(&s, &Input::ProofSignatureProduced(proof_sig), &env);
    let proof_jwt = match out.as_slice() {
        [Output::RequestCredential { proof_jwt }] => proof_jwt.clone(),
        other => panic!("expected RequestCredential, got {other:?}"),
    };

    // The issuer verifies the proof with REAL crypto and issues the credential.
    let credential = issuer_verify_proof_and_issue(
        &issuer,
        &proof_jwt,
        device.public_key_raw(),
        "https://issuer.example",
        C_NONCE,
    )
    .expect("issuer must accept a valid key-bound proof");

    let (s, out) = step(
        &s,
        &Input::CredentialResponse {
            format: CredentialFormat::DcSdJwt,
            bytes: credential.clone(),
        },
        &env,
    );
    assert!(matches!(
        s,
        State::CredentialIssued {
            format: CredentialFormat::DcSdJwt,
            ..
        }
    ));
    assert_eq!(out, vec![Output::Close]);

    // The issued credential is a real, issuer-verifiable SD-JWT VC.
    let sd = sdjwt::SdJwtVc::parse(std::str::from_utf8(&credential).unwrap()).unwrap();
    assert!(sd
        .verify_and_disclose(&AwsLc, &AwsLc, issuer.public_key_raw(), Alg::Es256)
        .is_ok());
}

#[test]
fn issuer_rejects_proof_signed_by_wrong_key() {
    let device = SoftwareSigner::generate_p256().unwrap();
    let attacker = SoftwareSigner::generate_p256().unwrap();
    let issuer = SoftwareSigner::generate_p256().unwrap();
    const C_NONCE: u64 = 9;
    let seen: Vec<u64> = vec![];
    let env = Env {
        issuer_trusted: true,
        proof_key_attested: true,
        seen_c_nonces: &seen,
        device_key_ref: "device-key",
        issuer_id: "https://issuer.example",
        now_epoch: 1,
    };
    let offer =
        br#"{"format":"dc+sd-jwt","grant":"pre-authorized","tx_code_required":false}"#.to_vec();
    let (s, _) = step(&State::Idle, &Input::CredentialOffer(offer), &env);
    let (s, out) = step(
        &s,
        &Input::TokenResponse {
            bound: true,
            c_nonce: C_NONCE,
        },
        &env,
    );
    let signing_input = match out.as_slice() {
        [Output::SignProof { signing_input, .. }] => signing_input.clone(),
        _ => unreachable!(),
    };
    // Attacker signs the proof instead of the device.
    let bad_sig = attacker
        .sign(&KeyRef("x".into()), Alg::Es256, &signing_input)
        .unwrap();
    let (_s, out) = step(&s, &Input::ProofSignatureProduced(bad_sig), &env);
    let proof_jwt = match out.as_slice() {
        [Output::RequestCredential { proof_jwt }] => proof_jwt.clone(),
        _ => unreachable!(),
    };
    // Issuer checks against the DEVICE key → rejects.
    assert!(issuer_verify_proof_and_issue(
        &issuer,
        &proof_jwt,
        device.public_key_raw(),
        "https://issuer.example",
        C_NONCE
    )
    .is_none());
}
