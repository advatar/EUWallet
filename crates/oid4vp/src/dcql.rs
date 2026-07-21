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

use serde::{de, Deserialize, Deserializer};

// A signed request is attacker-controlled until RP trust is resolved. Keep selection work and all
// intermediate path/value clones within fixed, reviewable bounds before wallet-core sees a query.
const MAX_DCQL_BYTES: usize = 128 * 1024;
const MAX_CREDENTIAL_QUERIES: usize = 16;
const MAX_CREDENTIAL_SET_QUERIES: usize = 16;
const MAX_CREDENTIAL_SET_OPTIONS: usize = 16;
const MAX_CREDENTIAL_IDS_PER_OPTION: usize = MAX_CREDENTIAL_QUERIES;
const MAX_CLAIMS_PER_QUERY: usize = 64;
const MAX_CLAIM_SET_OPTIONS: usize = 32;
const MAX_CLAIM_IDS_PER_OPTION: usize = MAX_CLAIMS_PER_QUERY;
const MAX_PATH_DEPTH: usize = 16;
const MAX_VALUES_PER_CLAIM: usize = 64;
const MAX_META_VALUES: usize = 32;
const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_CLAIM_NAME_BYTES: usize = 256;
const MAX_JSON_STRING_OR_KEY_BYTES: usize = 512;
const MAX_JSON_VALUE_DEPTH: usize = 16;
const MAX_JSON_CONTAINER_ITEMS: usize = 128;

fn deserialize_non_empty_credentials<'de, D>(
    deserializer: D,
) -> Result<Vec<CredentialQuery>, D::Error>
where
    D: Deserializer<'de>,
{
    let credentials = Vec::<CredentialQuery>::deserialize(deserializer)?;
    if credentials.is_empty() {
        return Err(de::Error::custom("DCQL credentials must not be empty"));
    }
    Ok(credentials)
}

fn deserialize_present_claims<'de, D>(deserializer: D) -> Result<Vec<ClaimQuery>, D::Error>
where
    D: Deserializer<'de>,
{
    let claims = Vec::<ClaimQuery>::deserialize(deserializer)?;
    if claims.is_empty() {
        return Err(de::Error::custom(
            "DCQL claims must be omitted instead of explicitly empty",
        ));
    }
    Ok(claims)
}

/// A full DCQL query. Without `credential_sets` every Credential Query is required; with them,
/// required combinations determine the default presented subset and optional combinations await
/// explicit holder opt-in.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct DcqlQuery {
    #[serde(deserialize_with = "deserialize_non_empty_credentials")]
    pub credentials: Vec<CredentialQuery>,
    /// Alternative required/optional combinations of Credential Query identifiers.
    #[serde(default)]
    pub credential_sets: Option<Vec<CredentialSetQuery>>,
}

/// One non-empty alternative inside a [`CredentialSetQuery`].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(transparent)]
pub struct CredentialSetOption(pub Vec<String>);

/// A DCQL Credential Set Query (OpenID4VP 1.0 §6.2).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct CredentialSetQuery {
    /// Ordered alternatives; every identifier refers to a Credential Query.
    pub options: Vec<CredentialSetOption>,
    /// Required by default when omitted on the wire.
    #[serde(default = "required_by_default")]
    pub required: bool,
}

const fn required_by_default() -> bool {
    true
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
    /// Requested selectively-disclosable claims. Absent means none; an explicit empty array is
    /// invalid in OpenID4VP 1.0 and is rejected during deserialization.
    #[serde(default, deserialize_with = "deserialize_present_claims")]
    pub claims: Vec<ClaimQuery>,
    /// Preference-ordered alternative combinations of claim identifiers.
    #[serde(default)]
    pub claim_sets: Option<Vec<ClaimSet>>,
    /// These final-spec modifiers are parsed but rejected until the selector implements them.
    #[serde(default)]
    pub trusted_authorities: Option<serde_json::Value>,
    #[serde(default)]
    pub require_cryptographic_holder_binding: Option<bool>,
    #[serde(default)]
    pub multiple: Option<bool>,
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
    #[serde(default)]
    pub id: Option<String>,
    pub path: Vec<serde_json::Value>,
    /// Optional value constraints (the claim must be one of these). Not used for minimisation.
    #[serde(default)]
    pub values: Option<Vec<serde_json::Value>>,
    #[serde(default)]
    pub intent_to_retain: Option<bool>,
}

/// One non-empty alternative inside a Credential Query's `claim_sets` array.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(transparent)]
pub struct ClaimSet(pub Vec<String>);

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

impl CredentialQuery {
    /// Resolve claim-set identifiers into preference-ordered claim indices.
    ///
    /// Absent `claims` produces one empty option (mandatory claims only); absent `claim_sets`
    /// produces one option containing every claim. `None` means this value was constructed outside
    /// the bounded parser and contains a dangling or ambiguous identifier.
    pub fn claim_selection_options(&self) -> Option<Vec<Vec<usize>>> {
        match &self.claim_sets {
            None => Some(vec![(0..self.claims.len()).collect()]),
            Some(claim_sets) => claim_sets
                .iter()
                .map(|claim_set| {
                    claim_set
                        .0
                        .iter()
                        .map(|id| {
                            self.claims
                                .iter()
                                .position(|claim| claim.id.as_deref() == Some(id))
                        })
                        .collect()
                })
                .collect(),
        }
    }
}

impl DcqlQuery {
    /// Parse a DCQL query from JSON bytes; `None` if malformed.
    pub fn parse(bytes: &[u8]) -> Option<DcqlQuery> {
        if bytes.len() > MAX_DCQL_BYTES {
            return None;
        }
        let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
        Self::from_value(&value)
    }

    /// Parse from a `serde_json::Value` (the request payload's `dcql_query` field); `None` if malformed.
    pub fn from_value(v: &serde_json::Value) -> Option<DcqlQuery> {
        if !json_value_within_budget(v, 0)
            || !known_optional_arrays_are_non_empty(v)
            || contains_unsupported_selection_modifier(v)
        {
            return None;
        }
        let query: DcqlQuery = serde_json::from_value(v.clone()).ok()?;
        query.within_budget().then_some(query)
    }

    fn within_budget(&self) -> bool {
        !self.credentials.is_empty()
            && self.credentials.len() <= MAX_CREDENTIAL_QUERIES
            && self
                .credentials
                .iter()
                .enumerate()
                .all(|(index, credential)| {
                    valid_dcql_id(&credential.id)
                        && !self.credentials[..index]
                            .iter()
                            .any(|earlier| earlier.id == credential.id)
                        && !credential.format.is_empty()
                        && credential.format.len() <= MAX_IDENTIFIER_BYTES
                        && credential.claims.len() <= MAX_CLAIMS_PER_QUERY
                        && credential.trusted_authorities.is_none()
                        && credential.multiple != Some(true)
                        && credential.meta.is_some()
                        && credential.meta.as_ref().is_none_or(|meta| {
                            meta.vct_values.len() <= MAX_META_VALUES
                                && meta.vct_values.iter().all(|value| {
                                    !value.is_empty() && value.len() <= MAX_JSON_STRING_OR_KEY_BYTES
                                })
                                && meta.doctype_value.as_ref().is_none_or(|value| {
                                    !value.is_empty() && value.len() <= MAX_JSON_STRING_OR_KEY_BYTES
                                })
                        })
                        && match (credential.format.as_str(), credential.meta.as_ref()) {
                            ("dc+sd-jwt", Some(meta)) => !meta.vct_values.is_empty(),
                            ("mso_mdoc", Some(meta)) => meta
                                .doctype_value
                                .as_ref()
                                .is_some_and(|doctype| !doctype.is_empty()),
                            ("dc+sd-jwt" | "mso_mdoc", None) => false,
                            _ => true,
                        }
                        && credential.claims.iter().enumerate().all(|(index, claim)| {
                            claim.id.as_ref().is_none_or(|id| {
                                valid_dcql_id(id)
                                    && !credential.claims[..index]
                                        .iter()
                                        .filter_map(|earlier| earlier.id.as_ref())
                                        .any(|earlier| earlier == id)
                            }) && (credential.claim_sets.is_none() || claim.id.is_some())
                                && !claim.path.is_empty()
                                && claim.path.len() <= MAX_PATH_DEPTH
                                && claim.path.iter().all(|element| match element {
                                    serde_json::Value::String(name) => {
                                        !name.is_empty() && name.len() <= MAX_CLAIM_NAME_BYTES
                                    }
                                    serde_json::Value::Number(index) => index.as_u64().is_some(),
                                    serde_json::Value::Null => true,
                                    _ => false,
                                })
                                && claim.values.as_ref().is_none_or(|values| {
                                    !values.is_empty()
                                        && values.len() <= MAX_VALUES_PER_CLAIM
                                        && values.iter().all(|value| match value {
                                            serde_json::Value::String(_)
                                            | serde_json::Value::Bool(_) => true,
                                            serde_json::Value::Number(number) => {
                                                number.as_i64().is_some()
                                                    || number.as_u64().is_some()
                                            }
                                            _ => false,
                                        })
                                })
                                && !credential.claims[..index]
                                    .iter()
                                    .any(|earlier| earlier.path == claim.path)
                        })
                        && credential.claim_sets.as_ref().is_none_or(|claim_sets| {
                            !claim_sets.is_empty()
                                && claim_sets.len() <= MAX_CLAIM_SET_OPTIONS
                                && claim_sets.iter().enumerate().all(|(set_index, claim_set)| {
                                    !claim_set.0.is_empty()
                                        && claim_set.0.len() <= MAX_CLAIM_IDS_PER_OPTION
                                        && claim_set.0.iter().enumerate().all(|(id_index, id)| {
                                            valid_dcql_id(id)
                                                && !claim_set.0[..id_index].contains(id)
                                                && credential
                                                    .claims
                                                    .iter()
                                                    .any(|claim| claim.id.as_ref() == Some(id))
                                        })
                                        && !claim_sets[..set_index].iter().any(|earlier| {
                                            same_identifier_set(&earlier.0, &claim_set.0)
                                        })
                                })
                        })
                })
            && self.credential_sets.as_ref().is_none_or(|credential_sets| {
                !credential_sets.is_empty()
                    && credential_sets.len() <= MAX_CREDENTIAL_SET_QUERIES
                    && credential_sets.iter().all(|credential_set| {
                        !credential_set.options.is_empty()
                            && credential_set.options.len() <= MAX_CREDENTIAL_SET_OPTIONS
                            && credential_set.options.iter().enumerate().all(
                                |(option_index, option)| {
                                    !option.0.is_empty()
                                        && option.0.len() <= MAX_CREDENTIAL_IDS_PER_OPTION
                                        && option.0.iter().enumerate().all(|(id_index, id)| {
                                            valid_dcql_id(id)
                                                && !option.0[..id_index].contains(id)
                                                && self
                                                    .credentials
                                                    .iter()
                                                    .any(|credential| credential.id == *id)
                                        })
                                        && !credential_set.options[..option_index].iter().any(
                                            |earlier| same_identifier_set(&earlier.0, &option.0),
                                        )
                                },
                            )
                    })
            })
    }

    /// Compute a deterministic, atomic Credential Query plan from candidate availability.
    ///
    /// Without `credential_sets`, every Credential Query is required. With sets, the first
    /// satisfiable option of each required set is selected and any unavailable required set
    /// rejects the complete plan. Optional sets are omitted until an explicit holder opt-in
    /// contract exists. The returned indices always follow original `credentials` order, so
    /// signing, consent and response assembly remain stable.
    pub fn credential_selection_plan(&self, satisfiable: &[bool]) -> Option<Vec<usize>> {
        if satisfiable.len() != self.credentials.len() {
            return None;
        }
        let Some(credential_sets) = &self.credential_sets else {
            return satisfiable
                .iter()
                .all(|available| *available)
                .then(|| (0..self.credentials.len()).collect());
        };

        let mut selected = vec![false; self.credentials.len()];
        for credential_set in credential_sets {
            // `required=false` permits the wallet to return the set; it does not justify automatic
            // extra disclosure. A future holder-choice contract can explicitly opt into one of
            // these options. Until then, data minimisation requires omitting it unconditionally.
            if !credential_set.required {
                continue;
            }
            let option = credential_set.options.iter().find(|option| {
                option.0.iter().all(|id| {
                    self.credentials
                        .iter()
                        .position(|credential| credential.id == *id)
                        .is_some_and(|index| satisfiable[index])
                })
            });
            let option = option?;
            for id in &option.0 {
                let index = self
                    .credentials
                    .iter()
                    .position(|credential| credential.id == *id)?;
                selected[index] = true;
            }
        }
        Some(
            selected
                .iter()
                .enumerate()
                .filter_map(|(index, selected)| selected.then_some(index))
                .collect(),
        )
    }

    /// Every declared claim path across all queries and alternatives, de-duplicated in first-seen
    /// order. Actual disclosure and consent use the planner-selected claim and credential options.
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

fn valid_dcql_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_IDENTIFIER_BYTES
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn same_identifier_set(left: &[String], right: &[String]) -> bool {
    left.len() == right.len() && left.iter().all(|id| right.contains(id))
}

fn known_optional_arrays_are_non_empty(value: &serde_json::Value) -> bool {
    let Some(query) = value.as_object() else {
        return false;
    };
    if query
        .get("credential_sets")
        .is_some_and(|sets| !sets.as_array().is_some_and(|sets| !sets.is_empty()))
    {
        return false;
    }
    query
        .get("credentials")
        .and_then(serde_json::Value::as_array)
        .is_none_or(|credentials| {
            credentials.iter().all(|credential| {
                credential.as_object().is_none_or(|credential| {
                    !credential
                        .get("claim_sets")
                        .is_some_and(|sets| !sets.as_array().is_some_and(|sets| !sets.is_empty()))
                })
            })
        })
}

fn contains_unsupported_selection_modifier(value: &serde_json::Value) -> bool {
    let Some(query) = value.as_object() else {
        return false;
    };
    query
        .get("credentials")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|credentials| {
            credentials.iter().any(|credential| {
                credential.as_object().is_some_and(|credential| {
                    credential.contains_key("trusted_authorities")
                        || credential
                            .get("require_cryptographic_holder_binding")
                            .is_some_and(|value| !value.is_boolean())
                        || credential
                            .get("multiple")
                            .is_some_and(|value| !value.is_boolean())
                        || (credential.get("format").and_then(serde_json::Value::as_str)
                            == Some("mso_mdoc")
                            && credential
                                .get("claims")
                                .and_then(serde_json::Value::as_array)
                                .is_some_and(|claims| {
                                    claims.iter().any(|claim| {
                                        claim.as_object().is_some_and(|claim| {
                                            claim.contains_key("intent_to_retain")
                                        })
                                    })
                                }))
                })
            })
        })
}

fn json_value_within_budget(value: &serde_json::Value, depth: usize) -> bool {
    if depth > MAX_JSON_VALUE_DEPTH {
        return false;
    }
    match value {
        serde_json::Value::String(value) => value.len() <= MAX_JSON_STRING_OR_KEY_BYTES,
        serde_json::Value::Array(values) => {
            values.len() <= MAX_JSON_CONTAINER_ITEMS
                && values
                    .iter()
                    .all(|value| json_value_within_budget(value, depth + 1))
        }
        serde_json::Value::Object(object) => {
            object.len() <= MAX_JSON_CONTAINER_ITEMS
                && object.iter().all(|(key, value)| {
                    key.len() <= MAX_JSON_STRING_OR_KEY_BYTES
                        && json_value_within_budget(value, depth + 1)
                })
        }
        _ => true,
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
            br#"{"credentials":[{"id":"mdl","format":"mso_mdoc",
              "meta":{"doctype_value":"org.iso.18013.5.1.mDL"},"claims":[
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
    fn rejects_non_typed_mdoc_path_components_instead_of_flattening_them() {
        assert!(DcqlQuery::parse(
            br#"{"credentials":[{"id":"mdl","format":"mso_mdoc",
              "meta":{"doctype_value":"org.iso.18013.5.1.mDL"},"claims":[
                {"path":["org.iso.18013.5.1", {}, "age_over_18"]}
            ]}]}"#,
        )
        .is_none());
    }

    #[test]
    fn rejects_malformed_query() {
        assert!(DcqlQuery::parse(b"{not json").is_none());
        assert!(DcqlQuery::parse(br#"{"credentials": "nope"}"#).is_none());
        assert!(DcqlQuery::parse(br#"{"credentials":[]}"#).is_none());
        assert!(DcqlQuery::parse(
            br#"{"credentials":[{"id":"pid","format":"dc+sd-jwt","claims":[]}]}"#
        )
        .is_none());
    }

    #[test]
    fn absent_claims_means_no_selective_claims() {
        let query = DcqlQuery::parse(
            br#"{"credentials":[{"id":"pid","format":"dc+sd-jwt",
                "meta":{"vct_values":["urn:eudi:pid:1"]}}]}"#,
        )
        .expect("claims may be absent");
        assert!(query.credentials[0].claims.is_empty());
        assert!(query.requested_claim_paths().is_empty());
    }

    #[test]
    fn rejects_queries_over_selection_cardinality_budgets() {
        let credentials: Vec<serde_json::Value> = (0..=MAX_CREDENTIAL_QUERIES)
            .map(|index| {
                serde_json::json!({
                    "id": format!("pid-{index}"),
                    "format": "dc+sd-jwt",
                    "meta": {"vct_values":["urn:eudi:pid:1"]}
                })
            })
            .collect();
        assert!(DcqlQuery::from_value(&serde_json::json!({
            "credentials": credentials
        }))
        .is_none());

        let claims: Vec<serde_json::Value> = (0..=MAX_CLAIMS_PER_QUERY)
            .map(|index| serde_json::json!({ "path": [format!("claim-{index}")] }))
            .collect();
        assert!(DcqlQuery::from_value(&serde_json::json!({
            "credentials": [{"id":"pid", "format":"dc+sd-jwt",
                "meta":{"vct_values":["urn:eudi:pid:1"]}, "claims":claims}]
        }))
        .is_none());

        let values: Vec<serde_json::Value> = (0..=MAX_VALUES_PER_CLAIM)
            .map(serde_json::Value::from)
            .collect();
        assert!(DcqlQuery::from_value(&serde_json::json!({
            "credentials": [{"id":"pid", "format":"dc+sd-jwt",
                "meta":{"vct_values":["urn:eudi:pid:1"]}, "claims":[{
                "path":["age"], "values":values
            }]}]
        }))
        .is_none());
    }

    #[test]
    fn rejects_queries_over_path_and_string_budgets() {
        let path = vec![serde_json::Value::String("nested".into()); MAX_PATH_DEPTH + 1];
        assert!(DcqlQuery::from_value(&serde_json::json!({
            "credentials": [{"id":"pid", "format":"dc+sd-jwt",
                "meta":{"vct_values":["urn:eudi:pid:1"]}, "claims":[{"path":path}]}]
        }))
        .is_none());

        let oversized_claim = "x".repeat(MAX_CLAIM_NAME_BYTES + 1);
        assert!(DcqlQuery::from_value(&serde_json::json!({
            "credentials": [{"id":"pid", "format":"dc+sd-jwt",
                "meta":{"vct_values":["urn:eudi:pid:1"]}, "claims":[{
                "path":[oversized_claim]
            }]}]
        }))
        .is_none());

        let oversized_key = "k".repeat(MAX_JSON_STRING_OR_KEY_BYTES + 1);
        assert!(DcqlQuery::from_value(&serde_json::json!({
            "credentials": [{"id":"pid", "format":"dc+sd-jwt",
                "meta":{"vct_values":["urn:eudi:pid:1"]}, (oversized_key):true}]
        }))
        .is_none());
    }

    #[test]
    fn rejects_oversized_serialized_dcql() {
        assert!(DcqlQuery::parse(&vec![b' '; MAX_DCQL_BYTES + 1]).is_none());
    }

    #[test]
    fn rejects_unsupported_selection_and_trust_modifiers() {
        for query in [
            serde_json::json!({
                "credentials":[{"id":"pid", "format":"dc+sd-jwt"}],
                "credential_sets": null
            }),
            serde_json::json!({
                "credentials":[{"id":"pid", "format":"dc+sd-jwt", "claim_sets":[]}]
            }),
            serde_json::json!({
                "credentials":[{"id":"pid", "format":"dc+sd-jwt",
                    "trusted_authorities":[{"type":"aki", "values":["x"]}]}]
            }),
        ] {
            assert!(DcqlQuery::from_value(&query).is_none());
        }
        assert!(DcqlQuery::from_value(&serde_json::json!({
            "credentials":[{"id":"pid", "format":"dc+sd-jwt",
                "require_cryptographic_holder_binding":"false"}]
        }))
        .is_none());
        assert!(DcqlQuery::from_value(&serde_json::json!({
            "credentials":[{"id":"pid", "format":"dc+sd-jwt",
                "meta":{"vct_values":["urn:eudi:pid:1"]},
                "require_cryptographic_holder_binding":false}]
        }))
        .is_some());
    }

    #[test]
    fn parses_typed_sets_ignores_extensions_and_resolves_preference_order() {
        let query = DcqlQuery::from_value(&serde_json::json!({
            "credentials": [
                {
                    "id": "pid",
                    "format": "dc+sd-jwt",
                    "meta": {"vct_values": ["urn:eudi:pid:1"], "future_meta": true},
                    "claims": [
                        {"id": "age", "path": ["age_over_18"], "future_claim": 7},
                        {"id": "birth", "path": ["birthdate"]}
                    ],
                    "claim_sets": [["age"], ["birth"]],
                    "future_credential": {"ignored": true}
                },
                {
                    "id": "mdl",
                    "format": "mso_mdoc",
                    "meta": {"doctype_value": "org.iso.18013.5.1.mDL"}
                }
            ],
            "credential_sets": [{
                "options": [["pid"], ["mdl"]],
                "future_set_property": "ignored"
            }],
            "future_top_level": [1, 2, 3]
        }))
        .expect("unknown extension properties are ignored within global budgets");

        assert_eq!(
            query.credentials[0].claim_selection_options(),
            Some(vec![vec![0], vec![1]])
        );
        let sets = query.credential_sets.as_ref().expect("typed sets");
        assert!(sets[0].required, "required defaults to true");
        assert_eq!(sets[0].options[0].0, vec!["pid"]);
        assert_eq!(
            query.credential_selection_plan(&[true, false]),
            Some(vec![0])
        );
        assert_eq!(
            query.credential_selection_plan(&[false, true]),
            Some(vec![1])
        );
        assert_eq!(query.credential_selection_plan(&[false, false]), None);
    }

    #[test]
    fn credential_set_planner_is_atomic_deterministic_and_optional() {
        let query = DcqlQuery::from_value(&serde_json::json!({
            "credentials": [
                {"id":"a", "format":"dc+sd-jwt", "meta":{"vct_values":["a"]}},
                {"id":"b", "format":"dc+sd-jwt", "meta":{"vct_values":["b"]}},
                {"id":"c", "format":"dc+sd-jwt", "meta":{"vct_values":["c"]}},
                {"id":"d", "format":"dc+sd-jwt", "meta":{"vct_values":["d"]}}
            ],
            "credential_sets": [
                {"options": [["b", "a"], ["c"]]},
                {"options": [["c", "a"]]},
                {"required": false, "options": [["d"]]}
            ]
        }))
        .unwrap();

        // The first required option is incomplete, so its complete fallback wins; the second
        // required set adds `a`. Their union is de-duplicated in original Credential Query order.
        // Satisfiable optional `d` remains omitted without explicit holder opt-in.
        assert_eq!(
            query.credential_selection_plan(&[true, false, true, true]),
            Some(vec![0, 2])
        );
        // Both preferred required options are complete. Their stable union omits optional `d`.
        assert_eq!(
            query.credential_selection_plan(&[true, true, true, true]),
            Some(vec![0, 1, 2])
        );
        // The first required set could use `c`, but the second required set is incomplete: the
        // entire plan fails instead of returning the first set as a partial response.
        assert_eq!(
            query.credential_selection_plan(&[false, false, true, true]),
            None
        );
        assert_eq!(query.credential_selection_plan(&[true, true]), None);

        let optional_only = DcqlQuery::from_value(&serde_json::json!({
            "credentials": [
                {"id":"a", "format":"dc+sd-jwt", "meta":{"vct_values":["a"]}}
            ],
            "credential_sets": [{"required":false, "options":[["a"]]}]
        }))
        .unwrap();
        assert_eq!(
            optional_only.credential_selection_plan(&[false]),
            Some(vec![])
        );
        assert_eq!(
            optional_only.credential_selection_plan(&[true]),
            Some(vec![])
        );
    }

    #[test]
    fn rejects_empty_duplicate_and_dangling_set_identifiers() {
        for query in [
            serde_json::json!({
                "credentials":[{"id":"pid", "format":"dc+sd-jwt",
                    "meta":{"vct_values":["v1"]}, "claims":[
                        {"path":["age_over_18"]}
                    ], "claim_sets":[["age"]]}]
            }),
            serde_json::json!({
                "credentials":[{"id":"pid", "format":"dc+sd-jwt",
                    "meta":{"vct_values":["v1"]}, "claims":[
                        {"id":"age", "path":["age_over_18"]}
                    ], "claim_sets":[["missing"]]}]
            }),
            serde_json::json!({
                "credentials":[{"id":"pid", "format":"dc+sd-jwt",
                    "meta":{"vct_values":["v1"]}, "claims":[
                        {"id":"age", "path":["age_over_18"]}
                    ], "claim_sets":[["age", "age"]]}]
            }),
            serde_json::json!({
                "credentials":[{"id":"pid", "format":"dc+sd-jwt",
                    "meta":{"vct_values":["v1"]}, "claims":[
                        {"id":"age", "path":["age_over_18"]},
                        {"id":"birth", "path":["birthdate"]}
                    ], "claim_sets":[["age", "birth"], ["birth", "age"]]}]
            }),
            serde_json::json!({
                "credentials":[{"id":"pid", "format":"dc+sd-jwt",
                    "meta":{"vct_values":["v1"]}}],
                "credential_sets":[{"options":[["missing"]]}]
            }),
            serde_json::json!({
                "credentials":[{"id":"pid", "format":"dc+sd-jwt",
                    "meta":{"vct_values":["v1"]}}],
                "credential_sets":[{"options":[["pid", "pid"]]}]
            }),
            serde_json::json!({
                "credentials":[
                    {"id":"a", "format":"dc+sd-jwt", "meta":{"vct_values":["a"]}},
                    {"id":"b", "format":"dc+sd-jwt", "meta":{"vct_values":["b"]}}
                ],
                "credential_sets":[{"options":[["a", "b"], ["b", "a"]]}]
            }),
            serde_json::json!({
                "credentials":[{"id":"pid", "format":"dc+sd-jwt",
                    "meta":{"vct_values":["v1"]}}], "credential_sets":[]
            }),
            serde_json::json!({
                "credentials":[{"id":"pid", "format":"dc+sd-jwt",
                    "meta":{"vct_values":["v1"]}, "claims":[
                        {"id":"age", "path":["age_over_18"]}
                    ], "claim_sets":[[]]}]
            }),
        ] {
            assert!(DcqlQuery::from_value(&query).is_none(), "accepted {query}");
        }
    }

    #[test]
    fn bounds_claim_and_credential_set_planning_work() {
        let claim_sets: Vec<serde_json::Value> = (0..=MAX_CLAIM_SET_OPTIONS)
            .map(|_| serde_json::json!(["age"]))
            .collect();
        assert!(DcqlQuery::from_value(&serde_json::json!({
            "credentials":[{"id":"pid", "format":"dc+sd-jwt",
                "meta":{"vct_values":["v1"]},
                "claims":[{"id":"age", "path":["age_over_18"]}],
                "claim_sets":claim_sets
            }]
        }))
        .is_none());

        let credential_sets: Vec<serde_json::Value> = (0..=MAX_CREDENTIAL_SET_QUERIES)
            .map(|_| serde_json::json!({"required":false, "options":[["pid"]]}))
            .collect();
        assert!(DcqlQuery::from_value(&serde_json::json!({
            "credentials":[{"id":"pid", "format":"dc+sd-jwt",
                "meta":{"vct_values":["v1"]}}],
            "credential_sets":credential_sets
        }))
        .is_none());
    }

    #[test]
    fn enforces_unique_unambiguous_credential_and_claim_ids() {
        assert!(DcqlQuery::from_value(&serde_json::json!({
            "credentials":[
                {"id":"same", "format":"dc+sd-jwt", "meta":{"vct_values":["v1"]}},
                {"id":"same", "format":"dc+sd-jwt", "meta":{"vct_values":["v1"]}}
            ]
        }))
        .is_none());
        assert!(DcqlQuery::from_value(&serde_json::json!({
            "credentials":[{"id":"pid.dot", "format":"dc+sd-jwt",
                "meta":{"vct_values":["v1"]}}]
        }))
        .is_none());
        assert!(DcqlQuery::from_value(&serde_json::json!({
            "credentials":[{"id":"pid", "format":"dc+sd-jwt",
                "meta":{"vct_values":["v1"]}, "claims":[
                {"id":"name", "path":["given_name"]},
                {"id":"name", "path":["family_name"]}
            ]}]
        }))
        .is_none());
    }

    #[test]
    fn rejects_missing_meta_multiple_retention_and_ambiguous_values() {
        for query in [
            serde_json::json!({"credentials":[{"id":"pid", "format":"dc+sd-jwt"}]}),
            serde_json::json!({"credentials":[{"id":"pid", "format":"dc+sd-jwt",
                "meta":{"vct_values":[]}}]}),
            serde_json::json!({"credentials":[{"id":"mdl", "format":"mso_mdoc",
                "meta":{}}]}),
            serde_json::json!({"credentials":[{"id":"pid", "format":"dc+sd-jwt",
                "meta":{"vct_values":["v1"]}, "multiple":true}]}),
            serde_json::json!({"credentials":[{"id":"mdl", "format":"mso_mdoc",
            "meta":{"doctype_value":"org.iso.18013.5.1.mDL"}, "claims":[{
                "path":["org.iso.18013.5.1", "age_over_18"],
                "intent_to_retain":false
            }]}]}),
            serde_json::json!({"credentials":[{"id":"pid", "format":"dc+sd-jwt",
            "meta":{"vct_values":["v1"]}, "claims":[
                {"path":["age"], "values":[18]},
                {"path":["age"], "values":[21]}
            ]}]}),
        ] {
            assert!(DcqlQuery::from_value(&query).is_none(), "accepted {query}");
        }

        for invalid_value in [
            serde_json::Value::Null,
            serde_json::json!(1.5),
            serde_json::json!([]),
            serde_json::json!({}),
        ] {
            let query = serde_json::json!({"credentials":[{
                "id":"pid", "format":"dc+sd-jwt", "meta":{"vct_values":["v1"]},
                "claims":[{"path":["age"], "values":[invalid_value]}]
            }]});
            assert!(DcqlQuery::from_value(&query).is_none(), "accepted {query}");
        }
    }

    #[test]
    fn multiple_credentials_dedupe_paths() {
        let q = DcqlQuery::parse(
            br#"{"credentials":[
              {"id":"a","format":"dc+sd-jwt","meta":{"vct_values":["v1"]},
                "claims":[{"path":["given_name"]}]},
              {"id":"b","format":"dc+sd-jwt","meta":{"vct_values":["v1"]},
                "claims":[{"path":["given_name"]},{"path":["birthdate"]}]}
            ]}"#,
        )
        .unwrap();
        assert_eq!(
            q.requested_claim_paths(),
            vec!["given_name".to_string(), "birthdate".to_string()]
        );
    }

    #[test]
    fn selection_accessors_vct_doctype_and_id() {
        let pid = DcqlQuery::parse(PID_QUERY).unwrap();
        assert_eq!(pid.first_credential_id(), Some("pid".to_string()));
        assert_eq!(pid.requested_vcts(), vec!["urn:eudi:pid:1".to_string()]);
        assert!(pid.requested_doctypes().is_empty());

        let mdl = DcqlQuery::parse(
            br#"{"credentials":[{"id":"mdl","format":"mso_mdoc",
                "meta":{"doctype_value":"org.iso.18013.5.1.mDL"},"claims":[{"path":["age_over_18"]}]}]}"#,
        )
        .unwrap();
        assert_eq!(mdl.first_credential_id(), Some("mdl".to_string()));
        assert_eq!(
            mdl.requested_doctypes(),
            vec!["org.iso.18013.5.1.mDL".to_string()]
        );
        assert!(mdl.requested_vcts().is_empty());

        // from_value parses an equivalent serde_json::Value.
        assert!(DcqlQuery::from_value(&serde_json::json!({
            "credentials": [{ "id": "x", "format": "dc+sd-jwt",
                "meta":{"vct_values":["v1"]} }]
        }))
        .is_some());

        // Dedup across credential queries (the `if !out.contains(..)` guards).
        let dup = DcqlQuery::parse(
            br#"{"credentials":[
                {"id":"a","format":"dc+sd-jwt","meta":{"vct_values":["v1"]}},
                {"id":"b","format":"dc+sd-jwt","meta":{"vct_values":["v1"]}}]}"#,
        )
        .unwrap();
        assert_eq!(dup.requested_vcts(), vec!["v1".to_string()]);
    }
}
