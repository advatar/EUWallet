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

/// Trusted-list service domain authorised to issue a credential type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IssuerTrustDomain {
    /// Person Identification Data issuer service.
    Pid,
    /// Electronic attestation issuer service, including mdoc and (Q)EAA credentials.
    Attestation,
}

/// A credential type the wallet understands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttestationType {
    /// Stable type id: SD-JWT VC `vct` or mdoc doctype (e.g. `urn:eudi:pid:1`).
    pub id: String,
    pub display_name: String,
    /// Credential format: `dc+sd-jwt` or `mso_mdoc`.
    pub format: String,
    /// The exact trusted-list service whose anchors may authenticate issuers of this type.
    pub issuer_trust_domain: IssuerTrustDomain,
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

    /// The trusted-list service domain required for issuers of type `id`.
    pub fn issuer_trust_domain(&self, id: &str) -> Option<IssuerTrustDomain> {
        self.get(id).map(|t| t.issuer_trust_domain)
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

/// The default catalogue the wallet ships with: the Person Identification Data (PID) type and the
/// mobile Driving Licence (mDL) — the two attestations the demo wallet can be issued.
pub fn default_catalogue() -> Catalogue {
    let mut c = Catalogue::new();
    c.register(AttestationType {
        id: "urn:eudi:pid:1".into(),
        display_name: "Person Identification Data".into(),
        format: "dc+sd-jwt".into(),
        issuer_trust_domain: IssuerTrustDomain::Pid,
        claims: vec![
            ClaimSpec {
                path: "family_name".into(),
                display_name: "Family name".into(),
                mandatory: true,
            },
            ClaimSpec {
                path: "given_name".into(),
                display_name: "Given name".into(),
                mandatory: true,
            },
            ClaimSpec {
                path: "birthdate".into(),
                display_name: "Date of birth".into(),
                mandatory: true,
            },
            ClaimSpec {
                path: "age_over_18".into(),
                display_name: "Over 18".into(),
                mandatory: false,
            },
        ],
        trusted_issuers: vec!["https://issuer.example".into()],
    });
    c.register(AttestationType {
        // ISO/IEC 18013-5 mDL modelled as an SD-JWT VC for the demo (the same core path issues it).
        id: "urn:eudi:mdl:1".into(),
        display_name: "Mobile Driving Licence".into(),
        format: "dc+sd-jwt".into(),
        issuer_trust_domain: IssuerTrustDomain::Attestation,
        claims: vec![
            ClaimSpec {
                path: "family_name".into(),
                display_name: "Family name".into(),
                mandatory: true,
            },
            ClaimSpec {
                path: "given_name".into(),
                display_name: "Given name".into(),
                mandatory: true,
            },
            ClaimSpec {
                path: "driving_privileges".into(),
                display_name: "Driving categories".into(),
                mandatory: true,
            },
            ClaimSpec {
                path: "issuing_country".into(),
                display_name: "Issuing country".into(),
                mandatory: true,
            },
            ClaimSpec {
                path: "age_over_18".into(),
                display_name: "Over 18".into(),
                mandatory: false,
            },
        ],
        trusted_issuers: vec!["https://issuer.example".into()],
    });
    c.register(AttestationType {
        id: "org.iso.18013.5.1.mDL".into(),
        display_name: "Mobile Driving Licence (mdoc)".into(),
        format: "mso_mdoc".into(),
        issuer_trust_domain: IssuerTrustDomain::Attestation,
        claims: vec![
            ClaimSpec {
                path: "family_name".into(),
                display_name: "Family name".into(),
                mandatory: true,
            },
            ClaimSpec {
                path: "given_name".into(),
                display_name: "Given name".into(),
                mandatory: true,
            },
            ClaimSpec {
                path: "age_over_18".into(),
                display_name: "Over 18".into(),
                mandatory: false,
            },
        ],
        trusted_issuers: vec!["https://issuer.example".into()],
    });
    c.register(AttestationType {
        // ICAO 9303 / eMRTD electronic passport, modelled as an SD-JWT VC for the demo.
        id: "urn:eudi:passport:1".into(),
        display_name: "Passport".into(),
        format: "dc+sd-jwt".into(),
        issuer_trust_domain: IssuerTrustDomain::Attestation,
        claims: vec![
            ClaimSpec {
                path: "family_name".into(),
                display_name: "Family name".into(),
                mandatory: true,
            },
            ClaimSpec {
                path: "given_name".into(),
                display_name: "Given name".into(),
                mandatory: true,
            },
            ClaimSpec {
                path: "document_number".into(),
                display_name: "Passport number".into(),
                mandatory: true,
            },
            ClaimSpec {
                path: "nationality".into(),
                display_name: "Nationality".into(),
                mandatory: true,
            },
            ClaimSpec {
                path: "expiry_date".into(),
                display_name: "Expiry date".into(),
                mandatory: true,
            },
            ClaimSpec {
                path: "age_over_18".into(),
                display_name: "Over 18".into(),
                mandatory: false,
            },
        ],
        trusted_issuers: vec!["https://issuer.example".into()],
    });
    c.register(AttestationType {
        // A generic national identity card.
        id: "urn:eudi:nid:1".into(),
        display_name: "National ID Card".into(),
        format: "dc+sd-jwt".into(),
        issuer_trust_domain: IssuerTrustDomain::Attestation,
        claims: vec![
            ClaimSpec {
                path: "family_name".into(),
                display_name: "Family name".into(),
                mandatory: true,
            },
            ClaimSpec {
                path: "given_name".into(),
                display_name: "Given name".into(),
                mandatory: true,
            },
            ClaimSpec {
                path: "document_number".into(),
                display_name: "Document number".into(),
                mandatory: true,
            },
            ClaimSpec {
                path: "issuing_country".into(),
                display_name: "Issuing country".into(),
                mandatory: true,
            },
            ClaimSpec {
                path: "expiry_date".into(),
                display_name: "Expiry date".into(),
                mandatory: true,
            },
            ClaimSpec {
                path: "age_over_18".into(),
                display_name: "Over 18".into(),
                mandatory: false,
            },
        ],
        trusted_issuers: vec!["https://issuer.example".into()],
    });
    c.register(AttestationType {
        // The German national identity card (Personalausweis), as its eID PID profile.
        id: "urn:eudi:pid:de:1".into(),
        display_name: "German ID Card".into(),
        format: "dc+sd-jwt".into(),
        issuer_trust_domain: IssuerTrustDomain::Pid,
        claims: vec![
            ClaimSpec {
                path: "family_name".into(),
                display_name: "Family name".into(),
                mandatory: true,
            },
            ClaimSpec {
                path: "given_name".into(),
                display_name: "Given name".into(),
                mandatory: true,
            },
            ClaimSpec {
                path: "birthdate".into(),
                display_name: "Date of birth".into(),
                mandatory: true,
            },
            ClaimSpec {
                path: "place_of_birth".into(),
                display_name: "Place of birth".into(),
                mandatory: true,
            },
            ClaimSpec {
                path: "resident_address".into(),
                display_name: "Resident address".into(),
                mandatory: true,
            },
            ClaimSpec {
                path: "issuing_country".into(),
                display_name: "Issuing country".into(),
                mandatory: true,
            },
            ClaimSpec {
                path: "age_over_18".into(),
                display_name: "Over 18".into(),
                mandatory: false,
            },
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
            issuer_trust_domain: IssuerTrustDomain::Pid,
            claims: vec![],
            trusted_issuers: vec![],
        }));
        assert_eq!(c.len(), 1);
        // Re-registering the same id replaces (returns true), doesn't duplicate.
        assert!(c.register(AttestationType {
            id: "t1".into(),
            display_name: "One v2".into(),
            format: "mso_mdoc".into(),
            issuer_trust_domain: IssuerTrustDomain::Attestation,
            claims: vec![],
            trusted_issuers: vec![],
        }));
        assert_eq!(c.len(), 1);
        assert_eq!(c.get("t1").unwrap().display_name, "One v2");
        assert_eq!(
            c.issuer_trust_domain("t1"),
            Some(IssuerTrustDomain::Attestation)
        );
        assert!(c.get("missing").is_none());
    }

    #[test]
    fn matching_and_policy() {
        let c = default_catalogue();
        // Every identity document proves age_over_18; the discriminating claims narrow the type.
        assert_eq!(
            c.types_offering("age_over_18"),
            vec![
                "urn:eudi:pid:1",
                "urn:eudi:mdl:1",
                "org.iso.18013.5.1.mDL",
                "urn:eudi:passport:1",
                "urn:eudi:nid:1",
                "urn:eudi:pid:de:1"
            ]
        );
        assert_eq!(
            c.types_offering("driving_privileges"),
            vec!["urn:eudi:mdl:1"]
        );
        assert_eq!(c.types_offering("nationality"), vec!["urn:eudi:passport:1"]);
        assert_eq!(
            c.types_offering("place_of_birth"),
            vec!["urn:eudi:pid:de:1"]
        );
        // Date of birth is on both the PID and the German ID card.
        assert_eq!(
            c.types_offering("birthdate"),
            vec!["urn:eudi:pid:1", "urn:eudi:pid:de:1"]
        );
        assert!(c.types_offering("unknown_claim").is_empty());

        // A request for name + age is satisfiable by any document; discriminating claims narrow it.
        assert_eq!(
            c.types_satisfying(&["family_name".into(), "age_over_18".into()]),
            vec![
                "urn:eudi:pid:1",
                "urn:eudi:mdl:1",
                "org.iso.18013.5.1.mDL",
                "urn:eudi:passport:1",
                "urn:eudi:nid:1",
                "urn:eudi:pid:de:1"
            ]
        );
        assert_eq!(
            c.types_satisfying(&["family_name".into(), "birthdate".into()]),
            vec!["urn:eudi:pid:1", "urn:eudi:pid:de:1"]
        );
        assert_eq!(
            c.types_satisfying(&["given_name".into(), "driving_privileges".into()]),
            vec!["urn:eudi:mdl:1"]
        );
        assert_eq!(
            c.types_satisfying(&["given_name".into(), "nationality".into()]),
            vec!["urn:eudi:passport:1"]
        );
        // A request including a claim no type offers resolves to nothing.
        assert!(c
            .types_satisfying(&["family_name".into(), "iban".into()])
            .is_empty());

        // Issuer policy.
        assert!(c.issuer_allowed("urn:eudi:pid:1", "https://issuer.example"));
        assert!(c.issuer_allowed("urn:eudi:mdl:1", "https://issuer.example"));
        assert!(c.issuer_allowed("org.iso.18013.5.1.mDL", "https://issuer.example"));
        assert!(c.issuer_allowed("urn:eudi:passport:1", "https://issuer.example"));
        assert!(c.issuer_allowed("urn:eudi:pid:de:1", "https://issuer.example"));
        assert!(!c.issuer_allowed("urn:eudi:pid:1", "https://evil.example"));
        assert!(!c.issuer_allowed("unknown", "https://issuer.example"));
        assert_eq!(
            c.issuer_trust_domain("urn:eudi:pid:1"),
            Some(IssuerTrustDomain::Pid)
        );
        assert_eq!(
            c.issuer_trust_domain("org.iso.18013.5.1.mDL"),
            Some(IssuerTrustDomain::Attestation)
        );
    }

    #[test]
    fn mandatory_claims_gate() {
        let c = default_catalogue();
        // All three mandatory claims present → satisfied (age_over_18 is optional).
        assert!(c.satisfies_mandatory(
            "urn:eudi:pid:1",
            &[
                "family_name".into(),
                "given_name".into(),
                "birthdate".into()
            ]
        ));
        // Missing a mandatory claim → not satisfied.
        assert!(!c.satisfies_mandatory(
            "urn:eudi:pid:1",
            &["family_name".into(), "age_over_18".into()]
        ));
        assert!(!c.satisfies_mandatory("unknown", &[]));
    }
}
