//! Blocker-2 regression: an mso_mdoc credential carrying an IETF Token Status List reference in its
//! signed MSO is checked for revocation/suspension at presentation time, exactly like SD-JWT VC.
//! Before the fix the presentation status gate skipped every mdoc source, so a revoked mso_mdoc PID
//! was presented with no status check. Here the wallet holds an mDL whose MSO `status` points at a
//! verified status list; a revoked index must abort before any device signature, a valid index must
//! proceed to signing.
use base64ct::{Base64UrlUnpadded, Encoding};
use cose::cbor::Value;
use crypto_backend::{AwsLc, SoftwareSigner};
use crypto_traits::{Alg, KeyRef, Signer};
use mdoc::{build_and_sign_with_status, IssuerSignedItem, MsoStatus, ValidityInfo};
use serde_json::json;
use std::collections::BTreeMap;
use wallet_core::{Core, Effect, Event, MdocHolding};

const DOCTYPE: &str = "org.iso.18013.5.1.mDL";
const NS: &str = "org.iso.18013.5.1";
const CLIENT_ID: &str = "rp.example";
const RESPONSE_URI: &str = "https://rp.example/response";
const NONCE: u64 = 424_242;
const NOW: i64 = 1_790_000_000;
const STATUS_URI: &str = "https://status.example/lists/mdl-1";

const CA_DER: &[u8] = include_bytes!("../../x509/tests/vectors/ca.der");
const RP_DER: &[u8] = include_bytes!("../../x509/tests/vectors/rp.der");
const RP_PKCS8: &[u8] = include_bytes!("../../x509/tests/vectors/rp.pkcs8.der");

fn b64(b: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(b)
}

/// Trust list granting the CA for BOTH RP access (reader auth) and the status service.
fn signed_trust_list(op: &SoftwareSigner) -> Vec<u8> {
    let header = b64(br#"{"alg":"ES256"}"#);
    let payload = b64(json!({
        "seq":1,"valid_from":0,"valid_until":4_000_000_000i64,
        "anchors":[
            {"cert":b64(CA_DER),"service":"rp-access-ca","status":"granted"},
            {"cert":b64(CA_DER),"service":"status","status":"granted"}
        ]
    })
    .to_string()
    .as_bytes());
    let si = format!("{header}.{payload}");
    let sig = op
        .sign(&KeyRef("op".into()), Alg::Es256, si.as_bytes())
        .unwrap();
    format!("{si}.{}", b64(&sig)).into_bytes()
}

/// A status token where index 0 = valid, index 1 = revoked (bits=2, byte = 1<<2 = 0x04).
fn signed_status(provider: &SoftwareSigner) -> Vec<u8> {
    let compressed = miniz_oxide::deflate::compress_to_vec_zlib(&[0x04u8], 6);
    let header = b64(br#"{"alg":"ES256","typ":"statuslist+jwt"}"#);
    let payload = b64(json!({
        "sub": STATUS_URI,
        "iat": NOW,
        "exp": NOW + 3600,
        "ttl": 300,
        "status_list": { "bits": 2, "lst": b64(&compressed) }
    })
    .to_string()
    .as_bytes());
    let si = format!("{header}.{payload}");
    let sig = provider
        .sign(&KeyRef("s".into()), Alg::Es256, si.as_bytes())
        .unwrap();
    format!("{si}.{}", b64(&sig)).into_bytes()
}

/// A COSE_Key (EC2 / P-256) for an uncompressed SEC1 public key `0x04 || X(32) || Y(32)`.
fn cose_key(pubkey: &[u8]) -> Value {
    Value::Map(vec![
        (Value::Uint(1), Value::Uint(2)),
        (Value::Nint(0), Value::Uint(1)),
        (Value::Nint(1), Value::Bytes(pubkey[1..33].to_vec())),
        (Value::Nint(2), Value::Bytes(pubkey[33..65].to_vec())),
    ])
}

/// An RP-signed OpenID4VP request with a DCQL `mso_mdoc` query for `age_over_18`.
fn sign_mdoc_request(rp: &SoftwareSigner) -> Vec<u8> {
    let header = b64(br#"{"alg":"ES256","typ":"oauth-authz-req+jwt"}"#);
    let payload = b64(serde_json::to_string(&json!({
        "client_id": CLIENT_ID,
        "nonce": NONCE.to_string(),
        "aud": "wallet.example",
        "response_uri": RESPONSE_URI,
        "response_mode": "direct_post",
        "purpose": "Prove you are over 18",
        "dcql_query": {
            "credentials": [{
                "id": "mdl",
                "format": "mso_mdoc",
                "meta": { "doctype_value": DOCTYPE },
                "claims": [{ "path": [NS, "age_over_18"], "intent_to_retain": true }]
            }]
        },
    }))
    .unwrap()
    .as_bytes());
    let si = format!("{header}.{payload}");
    let sig = rp
        .sign(&KeyRef("r".into()), Alg::Es256, si.as_bytes())
        .unwrap();
    format!("{si}.{}", b64(&sig)).into_bytes()
}

/// Hold an mDL whose MSO carries a status reference at `status_index`, load a verified status list,
/// then drive the presentation up to (and including) user consent. Returns the consent effects.
fn drive_mdoc_presentation_to_consent(status_index: u64) -> Vec<Effect> {
    let issuer = SoftwareSigner::generate_p256().unwrap();
    let device = SoftwareSigner::generate_p256().unwrap();
    let rp = SoftwareSigner::from_pkcs8_der(RP_PKCS8).unwrap();
    let trust_op = SoftwareSigner::generate_p256().unwrap();

    let mut name_spaces = BTreeMap::new();
    name_spaces.insert(
        NS.to_string(),
        vec![IssuerSignedItem {
            digest_id: 0,
            random: vec![0x11; 16],
            element_id: "age_over_18".into(),
            element_value: Value::Bool(true),
        }],
    );
    let issuer_signed = build_and_sign_with_status(
        name_spaces,
        DOCTYPE,
        cose_key(device.public_key_raw()),
        ValidityInfo {
            signed: "2026-07-19T00:00:00Z".into(),
            valid_from: "2026-07-19T00:00:00Z".into(),
            valid_until: "2035-01-01T00:00:00Z".into(),
        },
        Some(MsoStatus {
            uri: STATUS_URI.into(),
            index: status_index,
        }),
        &AwsLc,
        &issuer,
        &KeyRef("issuer".into()),
        Alg::Es256,
    )
    .expect("issuer signs the mDL with a status reference");

    let mut core = Core::new("wallet.example", "device-key");
    core.handle_event(Event::SetClock { epoch: NOW });
    core.load_trust_list(&signed_trust_list(&trust_op), trust_op.public_key_raw())
        .expect("trust list loads");
    core.load_status_list(STATUS_URI, &signed_status(&rp), &[RP_DER.to_vec()])
        .expect("status list loads");
    core.load_unverified_mdoc_for_testing(MdocHolding {
        doctype: DOCTYPE.into(),
        issuer_signed,
    });

    core.handle_event(Event::AuthorizationRequestReceived {
        request: sign_mdoc_request(&rp),
    });
    core.handle_event(Event::RpCertChainResolved {
        rp_cert_chain: vec![RP_DER.to_vec()],
        registered_redirect_uris: vec![RESPONSE_URI.into()],
    });
    core.handle_event(Event::UserConsented)
}

#[test]
fn revoked_mdoc_is_not_presented() {
    // MSO status index 1 is revoked in the bound list → consent must produce an error, not a Sign.
    let fx = drive_mdoc_presentation_to_consent(1);
    assert!(
        fx.iter().any(|e| matches!(
            e,
            Effect::Render {
                screen: presenter::ScreenDescription::Error { code, .. }
            } if code == "credential_revoked"
        )),
        "a revoked mso_mdoc must surface a revocation error, got {fx:?}"
    );
    assert!(
        !fx.iter().any(|e| matches!(e, Effect::Sign { .. })),
        "a revoked mso_mdoc must never be device-signed/presented"
    );
}

#[test]
fn valid_mdoc_proceeds_to_signing() {
    // MSO status index 0 is valid → the presentation proceeds to a device-signing effect.
    let fx = drive_mdoc_presentation_to_consent(0);
    assert!(
        fx.iter().any(|e| matches!(e, Effect::Sign { .. })),
        "a valid mso_mdoc should proceed to signing, got {fx:?}"
    );
}
