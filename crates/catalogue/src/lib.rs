#![forbid(unsafe_code)]
//! `catalogue` — the wallet's attestation catalogue (P1 / TS11).
//!
//! A registry of the credential *types* the wallet understands: each type's stable id (SD-JWT VC
//! `vct` or mdoc doctype), display name, format, the claims it carries (with which are mandatory),
//! and the issuers trusted to issue it. This drives two things the wallet needs but that are not
//! protocol state machines:
//!
//!  * **"What can prove X?"** — given a requested attribute, which credential types offer it, and
//!    which held credential(s) could satisfy a whole requested set (data-minimisation planning).
//!  * **Policy** — is a given issuer allowed to issue a given type; does a held claim set satisfy a
//!    type's mandatory claims.
//!
//! Pure and sans-IO: the catalogue is a value the shell ships / updates; no I/O here.

/// One claim a credential type carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimSpec {
    /// Claim path/identity (e.g. `age_over_18`, `family_name`).
    pub path: String,
    pub display_name: String,
    /// Whether the type is invalid without this claim.
    pub mandatory: bool,
}

/// A credential type the wallet understands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttestationType {
    /// Stable type id: SD-JWT VC `vct` or mdoc doctype (e.g. `urn:eudi:pid:1`).
    pub id: String,
    pub display_name: String,
    /// Credential format: `dc+sd-jwt` or `mso_mdoc`.
    pub format: String,
    pub claims: Vec<ClaimSpec>,
    /// Issuer ids trusted to issue this type.
    pub trusted_issuers: Vec<String>,
}

impl AttestationType {
    /// The mandatory claim paths of this type.
    pub fn mandatory_claims(&self) -> Vec<&str> {
        self.claims
            .iter()
            .filter(|c| c.mandatory)
            .map(|c| c.path.as_str())
            .collect()
    }

    fn offers(&self, path: &str) -> bool {
        self.claims.iter().any(|c| c.path == path)
    }
}

/// The catalogue: a set of known attestation types, keyed by id.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Catalogue {
    types: Vec<AttestationType>,
}

impl Catalogue {
    pub fn new() -> Self {
        Catalogue { types: Vec::new() }
    }

    /// Register (or replace, by id) a type. Returns whether it replaced an existing entry.
    pub fn register(&mut self, t: AttestationType) -> bool {
        if let Some(existing) = self.types.iter_mut().find(|e| e.id == t.id) {
            *existing = t;
            true
        } else {
            self.types.push(t);
            false
        }
    }

    pub fn get(&self, id: &str) -> Option<&AttestationType> {
        self.types.iter().find(|t| t.id == id)
    }

    pub fn list(&self) -> &[AttestationType] {
        &self.types
    }

    pub fn len(&self) -> usize {
        self.types.len()
    }

    pub fn is_empty(&self) -> bool {
        self.types.is_empty()
    }

    /// Type ids that offer `path` — "which credentials can prove this attribute".
    pub fn types_offering(&self, path: &str) -> Vec<&str> {
        self.types
            .iter()
            .filter(|t| t.offers(path))
            .map(|t| t.id.as_str())
            .collect()
    }

    /// Type ids that offer EVERY requested claim (candidates to satisfy a presentation request).
    pub fn types_satisfying(&self, requested: &[String]) -> Vec<&str> {
        self.types
            .iter()
            .filter(|t| requested.iter().all(|r| t.offers(r)))
            .map(|t| t.id.as_str())
            .collect()
    }

    /// Is `issuer` trusted (by this catalogue's policy) to issue type `id`?
    pub fn issuer_allowed(&self, id: &str, issuer: &str) -> bool {
        self.get(id)
            .map(|t| t.trusted_issuers.iter().any(|i| i == issuer))
            .unwrap_or(false)
    }

    /// Does the set of `held` claim paths satisfy type `id`'s mandatory claims? False if unknown id.
    pub fn satisfies_mandatory(&self, id: &str, held: &[String]) -> bool {
        match self.get(id) {
            Some(t) => t
                .mandatory_claims()
                .iter()
                .all(|m| held.iter().any(|h| h == m)),
            None => false,
        }
    }
}

/// The default catalogue the wallet ships with: the Person Identification Data (PID) type.
pub fn default_catalogue() -> Catalogue {
    let mut c = Catalogue::new();
    c.register(AttestationType {
        id: "urn:eudi:pid:1".into(),
        display_name: "Person Identification Data".into(),
        format: "dc+sd-jwt".into(),
        claims: vec![
            ClaimSpec { path: "family_name".into(), display_name: "Family name".into(), mandatory: true },
            ClaimSpec { path: "given_name".into(), display_name: "Given name".into(), mandatory: true },
            ClaimSpec { path: "birthdate".into(), display_name: "Date of birth".into(), mandatory: true },
            ClaimSpec { path: "age_over_18".into(), display_name: "Over 18".into(), mandatory: false },
        ],
        trusted_issuers: vec!["https://issuer.example".into()],
    });
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_get_and_replace() {
        let mut c = Catalogue::new();
        assert!(c.is_empty());
        assert!(!c.register(AttestationType {
            id: "t1".into(),
            display_name: "One".into(),
            format: "dc+sd-jwt".into(),
            claims: vec![],
            trusted_issuers: vec![],
        }));
        assert_eq!(c.len(), 1);
        // Re-registering the same id replaces (returns true), doesn't duplicate.
        assert!(c.register(AttestationType {
            id: "t1".into(),
            display_name: "One v2".into(),
            format: "mso_mdoc".into(),
            claims: vec![],
            trusted_issuers: vec![],
        }));
        assert_eq!(c.len(), 1);
        assert_eq!(c.get("t1").unwrap().display_name, "One v2");
        assert!(c.get("missing").is_none());
    }

    #[test]
    fn matching_and_policy() {
        let c = default_catalogue();
        // Which types can prove age_over_18 / family_name.
        assert_eq!(c.types_offering("age_over_18"), vec!["urn:eudi:pid:1"]);
        assert!(c.types_offering("unknown_claim").is_empty());

        // A request for held-and-offered claims resolves to the PID type.
        assert_eq!(
            c.types_satisfying(&["family_name".into(), "age_over_18".into()]),
            vec!["urn:eudi:pid:1"]
        );
        // A request including a claim no type offers resolves to nothing.
        assert!(c.types_satisfying(&["family_name".into(), "passport_number".into()]).is_empty());

        // Issuer policy.
        assert!(c.issuer_allowed("urn:eudi:pid:1", "https://issuer.example"));
        assert!(!c.issuer_allowed("urn:eudi:pid:1", "https://evil.example"));
        assert!(!c.issuer_allowed("unknown", "https://issuer.example"));
    }

    #[test]
    fn mandatory_claims_gate() {
        let c = default_catalogue();
        // All three mandatory claims present → satisfied (age_over_18 is optional).
        assert!(c.satisfies_mandatory(
            "urn:eudi:pid:1",
            &["family_name".into(), "given_name".into(), "birthdate".into()]
        ));
        // Missing a mandatory claim → not satisfied.
        assert!(!c.satisfies_mandatory(
            "urn:eudi:pid:1",
            &["family_name".into(), "age_over_18".into()]
        ));
        assert!(!c.satisfies_mandatory("unknown", &[]));
    }
}
