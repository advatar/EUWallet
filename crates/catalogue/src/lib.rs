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

/// A format-aware claim identity. mdoc claims remain structurally bound to their namespace;
/// callers never have to infer that boundary by splitting a dotted string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClaimPath {
    Json(String),
    Mdoc { namespace: String, element: String },
}

impl ClaimPath {
    pub fn mdoc(namespace: impl Into<String>, element: impl Into<String>) -> Self {
        Self::Mdoc {
            namespace: namespace.into(),
            element: element.into(),
        }
    }

    /// External request/display spelling. Structural mdoc checks use the enum fields directly.
    pub fn request_path(&self) -> String {
        match self {
            Self::Json(path) => path.clone(),
            Self::Mdoc { namespace, element } => format!("{namespace}.{element}"),
        }
    }

    fn matches_request(&self, requested: &str) -> bool {
        match self {
            Self::Json(path) => path == requested,
            Self::Mdoc { namespace, element } => requested
                .strip_prefix(namespace)
                .and_then(|suffix| suffix.strip_prefix('.'))
                .is_some_and(|suffix| suffix == element),
        }
    }
}

impl From<&str> for ClaimPath {
    fn from(value: &str) -> Self {
        Self::Json(value.into())
    }
}

impl From<String> for ClaimPath {
    fn from(value: String) -> Self {
        Self::Json(value)
    }
}

/// One claim a credential type carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimSpec {
    /// Format-aware claim identity.
    pub path: ClaimPath,
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
    pub fn mandatory_claims(&self) -> Vec<&ClaimPath> {
        self.claims
            .iter()
            .filter(|c| c.mandatory)
            .map(|c| &c.path)
            .collect()
    }

    fn offers(&self, path: &str) -> bool {
        self.claims.iter().any(|c| c.path.matches_request(path))
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
                .all(|m| matches!(m, ClaimPath::Json(path) if held.iter().any(|h| h == path))),
            None => false,
        }
    }

    /// Does an mdoc with this exact signed document type and these exact namespace/element pairs
    /// contain every mandatory catalogue claim? JSON paths and bare element names never match.
    pub fn satisfies_mandatory_mdoc(&self, doc_type: &str, held: &[(String, String)]) -> bool {
        match self.get(doc_type) {
            Some(t) if t.format == "mso_mdoc" => t.mandatory_claims().iter().all(|claim| {
                matches!(claim,
                    ClaimPath::Mdoc { namespace, element }
                        if held.iter().any(|(held_namespace, held_element)|
                            held_namespace == namespace && held_element == element))
            }),
            _ => false,
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
                path: ClaimPath::mdoc("org.iso.18013.5.1", "family_name"),
                display_name: "Family name".into(),
                mandatory: true,
            },
            ClaimSpec {
                path: ClaimPath::mdoc("org.iso.18013.5.1", "given_name"),
                display_name: "Given name".into(),
                mandatory: true,
            },
            ClaimSpec {
                path: ClaimPath::mdoc("org.iso.18013.5.1", "age_over_18"),
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
                "urn:eudi:passport:1",
                "urn:eudi:nid:1",
                "urn:eudi:pid:de:1"
            ]
        );
        assert_eq!(
            c.types_offering("org.iso.18013.5.1.age_over_18"),
            vec!["org.iso.18013.5.1.mDL"]
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
                "urn:eudi:passport:1",
                "urn:eudi:nid:1",
                "urn:eudi:pid:de:1"
            ]
        );
        assert_eq!(
            c.types_satisfying(&[
                "org.iso.18013.5.1.family_name".into(),
                "org.iso.18013.5.1.age_over_18".into()
            ]),
            vec!["org.iso.18013.5.1.mDL"]
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

        let exact_mdoc_claims = vec![
            ("org.iso.18013.5.1".into(), "family_name".into()),
            ("org.iso.18013.5.1".into(), "given_name".into()),
        ];
        assert!(c.satisfies_mandatory_mdoc("org.iso.18013.5.1.mDL", &exact_mdoc_claims));
        assert!(!c.satisfies_mandatory_mdoc(
            "org.iso.18013.5.1.mDL",
            &[
                ("org.example.lookalike".into(), "family_name".into()),
                ("org.example.lookalike".into(), "given_name".into()),
            ]
        ));
        assert!(!c.satisfies_mandatory_mdoc("org.example.lookalike.mDL", &exact_mdoc_claims));
        assert!(!c.satisfies_mandatory(
            "org.iso.18013.5.1.mDL",
            &["family_name".into(), "given_name".into()]
        ));
    }
}
