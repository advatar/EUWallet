//! DCQL — Digital Credentials Query Language (OpenID4VP 1.0, §6).
//!
//! The real query language an RP uses to say which credential(s) and which claims it wants,
//! replacing the earlier simplified `claims: [name,...]` stand-in. We parse the structured query
//! and flatten it to the claim *paths* the wallet's data-minimisation works on, plus expose the
//! requested credential formats and type values (vct / doctype) so the wallet can pick a matching
//! held credential.
//!
//! A claim `path` is a JSON array whose elements are: a string (object key), a non-negative
//! integer (array index), or null (all elements of an array) — see §6.4. We render it to a stable
//! identity string (`address.street_address`, `nationalities[0]`, `driving_privileges[]`).

use serde::Deserialize;

/// A full DCQL query: a set of credential queries (the RP wants all of them satisfied).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct DcqlQuery {
    pub credentials: Vec<CredentialQuery>,
}

/// One requested credential.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct CredentialQuery {
    /// RP-chosen identifier for this query entry.
    pub id: String,
    /// Credential format, e.g. `dc+sd-jwt` or `mso_mdoc`.
    pub format: String,
    #[serde(default)]
    pub meta: Option<Meta>,
    /// Requested claims. Absent/empty means "all claims" in DCQL; we surface that as an empty set.
    #[serde(default)]
    pub claims: Vec<ClaimQuery>,
}

/// Format-specific matching metadata.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
pub struct Meta {
    /// SD-JWT VC: acceptable `vct` values.
    #[serde(default)]
    pub vct_values: Vec<String>,
    /// mdoc: the doctype.
    #[serde(default)]
    pub doctype_value: Option<String>,
}

/// A single requested claim, identified by a path.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ClaimQuery {
    pub path: Vec<serde_json::Value>,
    /// Optional value constraints (the claim must be one of these). Not used for minimisation.
    #[serde(default)]
    pub values: Option<Vec<serde_json::Value>>,
}

impl ClaimQuery {
    /// Render the path to a stable identity string per DCQL element kinds.
    pub fn path_string(&self) -> String {
        let mut out = String::new();
        for elem in &self.path {
            match elem {
                serde_json::Value::String(s) => {
                    if !out.is_empty() {
                        out.push('.');
                    }
                    out.push_str(s);
                }
                serde_json::Value::Number(n) => {
                    out.push('[');
                    out.push_str(&n.to_string());
                    out.push(']');
                }
                serde_json::Value::Null => out.push_str("[]"), // all array elements
                _ => {}
            }
        }
        out
    }
}

impl DcqlQuery {
    /// Parse a DCQL query from JSON bytes; `None` if malformed.
    pub fn parse(bytes: &[u8]) -> Option<DcqlQuery> {
        serde_json::from_slice(bytes).ok()
    }

    /// Parse from a `serde_json::Value` (the request payload's `dcql_query` field); `None` if malformed.
    pub fn from_value(v: &serde_json::Value) -> Option<DcqlQuery> {
        serde_json::from_value(v.clone()).ok()
    }

    /// Every requested claim path across all credential queries, de-duplicated in first-seen order.
    /// This is what the wallet minimises against (discloses only requested-and-held claims).
    pub fn requested_claim_paths(&self) -> Vec<String> {
        let mut paths = Vec::new();
        for c in &self.credentials {
            for claim in &c.claims {
                let p = claim.path_string();
                if !p.is_empty() && !paths.contains(&p) {
                    paths.push(p);
                }
            }
        }
        paths
    }

    /// The id of the first credential query. The `vp_token` in an OpenID4VP 1.0 response is a JSON
    /// object keyed by these ids (§8.1); the flows we support present one credential per query.
    pub fn first_credential_id(&self) -> Option<String> {
        self.credentials.first().map(|c| c.id.clone())
    }

    /// Every acceptable SD-JWT VC type (`meta.vct_values`) across the query, de-duplicated. The
    /// wallet uses this to select a held credential of the requested TYPE, not merely one that
    /// happens to carry the requested claim names.
    pub fn requested_vcts(&self) -> Vec<String> {
        let mut out = Vec::new();
        for c in &self.credentials {
            if let Some(meta) = &c.meta {
                for v in &meta.vct_values {
                    if !out.contains(v) {
                        out.push(v.clone());
                    }
                }
            }
        }
        out
    }

    /// Every acceptable mdoc doctype (`meta.doctype_value`) across the query, de-duplicated.
    pub fn requested_doctypes(&self) -> Vec<String> {
        let mut out = Vec::new();
        for c in &self.credentials {
            if let Some(meta) = &c.meta {
                if let Some(dt) = &meta.doctype_value {
                    if !out.contains(dt) {
                        out.push(dt.clone());
                    }
                }
            }
        }
        out
    }

    /// The set of requested credential formats.
    pub fn formats(&self) -> Vec<String> {
        let mut fs = Vec::new();
        for c in &self.credentials {
            if !fs.contains(&c.format) {
                fs.push(c.format.clone());
            }
        }
        fs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A realistic DCQL query (OpenID4VP 1.0 §6 shape): a PID SD-JWT VC requesting three claims,
    // one of them nested.
    const PID_QUERY: &[u8] = br#"{
      "credentials": [
        {
          "id": "pid",
          "format": "dc+sd-jwt",
          "meta": { "vct_values": ["urn:eudi:pid:1"] },
          "claims": [
            { "path": ["age_over_18"] },
            { "path": ["family_name"] },
            { "path": ["address", "locality"] }
          ]
        }
      ]
    }"#;

    #[test]
    fn parses_pid_query_and_flattens_paths() {
        let q = DcqlQuery::parse(PID_QUERY).expect("valid DCQL");
        assert_eq!(q.credentials.len(), 1);
        let c = &q.credentials[0];
        assert_eq!(c.id, "pid");
        assert_eq!(c.format, "dc+sd-jwt");
        assert_eq!(c.meta.as_ref().unwrap().vct_values, vec!["urn:eudi:pid:1"]);
        assert_eq!(
            q.requested_claim_paths(),
            vec![
                "age_over_18".to_string(),
                "family_name".to_string(),
                "address.locality".to_string()
            ]
        );
        assert_eq!(q.formats(), vec!["dc+sd-jwt".to_string()]);
    }

    #[test]
    fn renders_array_and_wildcard_path_elements() {
        let q = DcqlQuery::parse(
            br#"{"credentials":[{"id":"mdl","format":"mso_mdoc","claims":[
                {"path":["driving_privileges", 0, "vehicle_category_code"]},
                {"path":["nationalities", null]}
            ]}]}"#,
        )
        .unwrap();
        assert_eq!(
            q.requested_claim_paths(),
            vec![
                "driving_privileges[0].vehicle_category_code".to_string(),
                "nationalities[]".to_string()
            ]
        );
    }

    #[test]
    fn rejects_malformed_query() {
        assert!(DcqlQuery::parse(b"{not json").is_none());
        assert!(DcqlQuery::parse(br#"{"credentials": "nope"}"#).is_none());
    }

    #[test]
    fn multiple_credentials_dedupe_paths() {
        let q = DcqlQuery::parse(
            br#"{"credentials":[
              {"id":"a","format":"dc+sd-jwt","claims":[{"path":["given_name"]}]},
              {"id":"b","format":"dc+sd-jwt","claims":[{"path":["given_name"]},{"path":["birthdate"]}]}
            ]}"#,
        )
        .unwrap();
        assert_eq!(q.requested_claim_paths(), vec!["given_name".to_string(), "birthdate".to_string()]);
    }
}
