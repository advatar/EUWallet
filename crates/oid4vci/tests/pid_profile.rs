use base64ct::{Base64, Encoding};
use mdoc::{cbor::Value, IssuerSigned, IssuerSignedItem};
use oid4vci::pid_profile::{
    validate_mdoc_pid_portrait, validate_sd_jwt_pid_portrait, PidPortraitError,
    MAX_PID_PORTRAIT_BYTES, PID_MDOC_NAMESPACE,
};
use serde_json::{json, Map};
use std::collections::BTreeMap;

const JPEG: &[u8] = &[0xff, 0xd8, 0xff, 0xdb, 0xff, 0xd9];

fn sd_claims(picture: serde_json::Value) -> Map<String, serde_json::Value> {
    let mut claims = Map::new();
    claims.insert("picture".into(), picture);
    claims
}

fn mdoc_with_portraits(values: Vec<Value>) -> IssuerSigned {
    let mut name_spaces = BTreeMap::new();
    name_spaces.insert(
        PID_MDOC_NAMESPACE.into(),
        values
            .into_iter()
            .enumerate()
            .map(|(digest_id, element_value)| IssuerSignedItem {
                digest_id: digest_id as u64,
                random: vec![digest_id as u8],
                element_id: "portrait".into(),
                element_value,
            })
            .collect(),
    );
    IssuerSigned {
        name_spaces,
        issuer_auth: Default::default(),
    }
}

#[test]
fn sd_jwt_accepts_jpeg_data_url_and_explicit_empty_opt_out() {
    let data_url = format!("data:image/jpeg;base64,{}", Base64::encode_string(JPEG));
    assert_eq!(
        validate_sd_jwt_pid_portrait(&sd_claims(json!(data_url))),
        Ok(())
    );
    assert_eq!(validate_sd_jwt_pid_portrait(&sd_claims(json!(""))), Ok(()));
}

#[test]
fn sd_jwt_rejects_missing_wrong_media_malformed_and_oversized_portraits() {
    assert_eq!(
        validate_sd_jwt_pid_portrait(&Map::new()),
        Err(PidPortraitError::Missing)
    );
    assert_eq!(
        validate_sd_jwt_pid_portrait(&sd_claims(json!(7))),
        Err(PidPortraitError::WrongType)
    );
    assert_eq!(
        validate_sd_jwt_pid_portrait(&sd_claims(json!("data:image/png;base64,/9j/2Q=="))),
        Err(PidPortraitError::InvalidDataUrl)
    );
    assert_eq!(
        validate_sd_jwt_pid_portrait(&sd_claims(json!("data:image/jpeg;base64,bm90LWpwZWc="))),
        Err(PidPortraitError::InvalidJpeg)
    );
    let oversized = vec![0xff; MAX_PID_PORTRAIT_BYTES + 1];
    let data_url = format!(
        "data:image/jpeg;base64,{}",
        Base64::encode_string(&oversized)
    );
    assert_eq!(
        validate_sd_jwt_pid_portrait(&sd_claims(json!(data_url))),
        Err(PidPortraitError::TooLarge)
    );
}

#[test]
fn mdoc_accepts_jpeg_bytes_and_explicit_empty_opt_out() {
    assert_eq!(
        validate_mdoc_pid_portrait(&mdoc_with_portraits(vec![Value::Bytes(JPEG.into())])),
        Ok(())
    );
    assert_eq!(
        validate_mdoc_pid_portrait(&mdoc_with_portraits(vec![Value::Bytes(vec![])])),
        Ok(())
    );
}

#[test]
fn mdoc_rejects_missing_duplicate_wrong_type_and_malformed_portraits() {
    assert_eq!(
        validate_mdoc_pid_portrait(&mdoc_with_portraits(vec![])),
        Err(PidPortraitError::Missing)
    );
    assert_eq!(
        validate_mdoc_pid_portrait(&mdoc_with_portraits(vec![
            Value::Bytes(JPEG.into()),
            Value::Bytes(JPEG.into())
        ])),
        Err(PidPortraitError::Duplicate)
    );
    assert_eq!(
        validate_mdoc_pid_portrait(&mdoc_with_portraits(vec![Value::Text("jpeg".into())])),
        Err(PidPortraitError::WrongType)
    );
    assert_eq!(
        validate_mdoc_pid_portrait(&mdoc_with_portraits(vec![Value::Bytes(
            b"not-jpeg".to_vec()
        )])),
        Err(PidPortraitError::InvalidJpeg)
    );
}
