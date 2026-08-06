//! OpenID4VP over the W3C **Digital Credentials API** (OpenID4VP 1.0 Appendix A/B.2.6.2) — the
//! browser-mediated presentation route (`navigator.credentials.get({digital: …})`).
//!
//! This module holds the pure, testable request/response shaping. The credential selection,
//! signing, and DeviceResponse assembly live in the wallet-core facade (mirroring the proximity
//! driver), binding to the byte-exact [`mdoc::oid4vp_dcapi_session_transcript`] handover.
//!
//! Honest scope: this first cut handles an unsigned (`openid4vp-v1-unsigned`) request with a single
//! `mso_mdoc` DCQL credential query and `response_mode=dc_api` (unencrypted). Signed requests
//! (`expected_origins`), `dc_api.jwt` (JWE) responses, and the SD-JWT VC path are tracked follow-ups.

use base64ct::{Base64UrlUnpadded, Encoding};
use serde_json::Value;

/// Failures parsing a DC-API request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DcApiError {
    /// The request was not valid JSON, or not an object.
    Malformed,
    /// `response_type` was not `vp_token`, or `response_mode` was not a `dc_api` variant.
    UnsupportedMode,
    /// No `mso_mdoc` credential query with a doctype was found in `dcql_query`.
    NoMdocQuery,
}

/// The parts of a DC-API OpenID4VP request the wallet needs to select + present an mdoc.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DcApiRequest {
    /// The request nonce (bound into the SessionTranscript handover).
    pub nonce: String,
    /// `dc_api` (unencrypted) or `dc_api.jwt` (encrypted). Only `dc_api` is handled for now.
    pub response_mode: String,
    /// The DCQL credential-query id — the key the response's `vp_token` object is keyed by.
    pub dcql_id: String,
    /// The requested mdoc doctype (from the query's `meta.doctype_value`).
    pub doctype: String,
    /// The requested `(namespace, element)` data elements (from the query's `claims[].path`).
    pub claims: Vec<(String, String)>,
}

/// Parse an unsigned OpenID4VP DC-API request:
/// ```json
/// { "response_type": "vp_token", "response_mode": "dc_api", "nonce": "...",
///   "dcql_query": { "credentials": [
///     { "id": "cred1", "format": "mso_mdoc",
///       "meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" },
///       "claims": [ { "path": ["eu.europa.ec.eudi.pid.1", "age_over_18"] } ] } ] } }
/// ```
/// `client_id` is intentionally ignored (unsigned DC-API requests omit it; the browser-authenticated
/// Origin is the anti-phishing anchor, supplied out-of-band by the OS).
pub fn parse_dcapi_request(request: &[u8]) -> Result<DcApiRequest, DcApiError> {
    let root: Value = serde_json::from_slice(request).map_err(|_| DcApiError::Malformed)?;
    let obj = root.as_object().ok_or(DcApiError::Malformed)?;

    if obj.get("response_type").and_then(Value::as_str) != Some("vp_token") {
        return Err(DcApiError::UnsupportedMode);
    }
    let response_mode = obj
        .get("response_mode")
        .and_then(Value::as_str)
        .filter(|m| *m == "dc_api" || *m == "dc_api.jwt")
        .ok_or(DcApiError::UnsupportedMode)?
        .to_string();
    let nonce = obj
        .get("nonce")
        .and_then(Value::as_str)
        .ok_or(DcApiError::Malformed)?
        .to_string();

    let credentials = obj
        .get("dcql_query")
        .and_then(|q| q.get("credentials"))
        .and_then(Value::as_array)
        .ok_or(DcApiError::Malformed)?;
    // First mso_mdoc credential query with a doctype.
    let query = credentials
        .iter()
        .find(|c| c.get("format").and_then(Value::as_str) == Some("mso_mdoc"))
        .ok_or(DcApiError::NoMdocQuery)?;
    let dcql_id = query
        .get("id")
        .and_then(Value::as_str)
        .ok_or(DcApiError::Malformed)?
        .to_string();
    let doctype = query
        .get("meta")
        .and_then(|m| m.get("doctype_value"))
        .and_then(Value::as_str)
        .ok_or(DcApiError::NoMdocQuery)?
        .to_string();

    let mut claims = Vec::new();
    if let Some(claim_list) = query.get("claims").and_then(Value::as_array) {
        for claim in claim_list {
            if let Some(path) = claim.get("path").and_then(Value::as_array) {
                if let (Some(ns), Some(el)) = (
                    path.first().and_then(Value::as_str),
                    path.get(1).and_then(Value::as_str),
                ) {
                    claims.push((ns.to_string(), el.to_string()));
                }
            }
        }
    }
    Ok(DcApiRequest {
        nonce,
        response_mode,
        dcql_id,
        doctype,
        claims,
    })
}

/// Build the DC-API response body the wallet hands back through `DigitalCredential.data` for an
/// unencrypted `dc_api` response: `{ "vp_token": { "<dcql_id>": [ "<base64url(DeviceResponse)>" ] } }`
/// (OpenID4VP 1.0 §8.1 — the `vp_token` is keyed by DCQL credential-query id).
#[must_use]
pub fn vp_token_response(dcql_id: &str, device_response: &[u8]) -> Vec<u8> {
    let body = serde_json::json!({
        "vp_token": { dcql_id: [Base64UrlUnpadded::encode_string(device_response)] }
    });
    serde_json::to_vec(&body).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request_json(doctype: &str, claims: &[[&str; 2]]) -> Vec<u8> {
        let claims: Vec<Value> = claims
            .iter()
            .map(|p| serde_json::json!({ "path": [p[0], p[1]] }))
            .collect();
        serde_json::to_vec(&serde_json::json!({
            "response_type": "vp_token",
            "response_mode": "dc_api",
            "nonce": "n-0S6_WzA2Mj",
            "dcql_query": { "credentials": [ {
                "id": "pid", "format": "mso_mdoc",
                "meta": { "doctype_value": doctype },
                "claims": claims
            } ] }
        }))
        .unwrap()
    }

    #[test]
    fn parses_an_unsigned_mdoc_dcapi_request() {
        let req = parse_dcapi_request(&request_json(
            "eu.europa.ec.eudi.pid.1",
            &[["eu.europa.ec.eudi.pid.1", "age_over_18"]],
        ))
        .expect("parse");
        assert_eq!(req.response_mode, "dc_api");
        assert_eq!(req.nonce, "n-0S6_WzA2Mj");
        assert_eq!(req.dcql_id, "pid");
        assert_eq!(req.doctype, "eu.europa.ec.eudi.pid.1");
        assert_eq!(
            req.claims,
            vec![("eu.europa.ec.eudi.pid.1".into(), "age_over_18".into())]
        );
    }

    #[test]
    fn rejects_non_vp_token_and_non_dcapi_mode() {
        let bad_type = serde_json::to_vec(&serde_json::json!({
            "response_type": "code", "response_mode": "dc_api", "nonce": "n",
            "dcql_query": {"credentials": []}
        }))
        .unwrap();
        assert_eq!(
            parse_dcapi_request(&bad_type),
            Err(DcApiError::UnsupportedMode)
        );

        let redirect = serde_json::to_vec(&serde_json::json!({
            "response_type": "vp_token", "response_mode": "direct_post", "nonce": "n",
            "dcql_query": {"credentials": []}
        }))
        .unwrap();
        assert_eq!(
            parse_dcapi_request(&redirect),
            Err(DcApiError::UnsupportedMode)
        );
    }

    #[test]
    fn requires_an_mdoc_query() {
        let sd_jwt_only = serde_json::to_vec(&serde_json::json!({
            "response_type": "vp_token", "response_mode": "dc_api", "nonce": "n",
            "dcql_query": {"credentials": [{"id": "x", "format": "dc+sd-jwt"}]}
        }))
        .unwrap();
        assert_eq!(
            parse_dcapi_request(&sd_jwt_only),
            Err(DcApiError::NoMdocQuery)
        );
    }

    #[test]
    fn vp_token_is_keyed_by_dcql_id() {
        let body = vp_token_response("pid", b"device-response-bytes");
        let parsed: Value = serde_json::from_slice(&body).unwrap();
        let arr = parsed["vp_token"]["pid"].as_array().expect("keyed array");
        assert_eq!(arr.len(), 1);
        assert_eq!(
            arr[0].as_str().unwrap(),
            Base64UrlUnpadded::encode_string(b"device-response-bytes")
        );
    }
}
