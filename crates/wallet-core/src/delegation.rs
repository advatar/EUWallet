//! Power-of-representation (mandate) support for the holder wallet.
//!
//! An agent's authority to act for someone is a distinct SD-JWT VC — a *mandate* (`vct` =
//! [`MANDATE_VCT`]) — that the agent holds like any other credential. Its holder key (`cnf`) is the
//! agent's own key, and its selectively-disclosable `scope` claim lists the delegated power URNs.
//!
//! This module is the pure, sans-IO foundation the delegated-presentation assembly and the
//! "My Agents" journey build on: it recognises a held mandate, reads its delegated scope and
//! delegator, and decides whether the mandate can back a delegated presentation for a given agent
//! key and a required scope — i.e. that the mandate is bound to *this* agent and actually grants
//! (a superset of) what the relying party asks. The cryptographic proofs that the mandate is
//! authentic, live, and non-revoked are the issuer's (at mint) and the verifier's (at accept); the
//! wallet's job here is to pick the right mandate and never over-claim beyond its scope.
//!
//! The `scope` URN vocabulary and `vct` mirror the issuer's pinned power taxonomy
//! (`issuer_core::POWER_TAXONOMY` / `MANDATE_VCT`) and the verifier's mandate model. Scope is
//! carried as URNs (not the kernel's bitmask) because the wallet works directly with the wire
//! claim; set-containment here is the same relation the verifier decides.

use std::collections::{BTreeMap, BTreeSet};

use base64ct::{Base64UrlUnpadded, Encoding};
use serde_json::Value;

use crate::HeldCredential;

/// The pinned power-of-representation mandate credential type. Must stay byte-equal to the issuer's
/// `issuer_core::MANDATE_VCT` and the verifier's mandate `vct`.
pub const MANDATE_VCT: &str = "urn:eudi:mandate:1";

/// A power-of-representation mandate the wallet holds, parsed from a [`HeldCredential`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeldMandate {
    /// The delegator this mandate represents (the disclosed `mandator` claim).
    pub mandator: String,
    /// The delegated powers, as scope URNs (the disclosed `scope` claim).
    pub scope: BTreeSet<String>,
    /// Optional link to the governing Mandamus mandate (the disclosed `mandate_jti` claim).
    pub mandate_jti: Option<String>,
    /// The agent (delegate) public key the mandate is holder-bound to (`cnf.jwk`), if present.
    pub delegate_cnf_jwk: Option<Value>,
}

/// Why a held credential cannot back a delegated presentation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DelegationError {
    /// The credential's `vct` is not the mandate type.
    NotAMandate,
    /// The mandate discloses no non-empty `mandator` (delegator) claim — the load-bearing identity
    /// of a power-of-representation credential must never be absent or empty.
    MandatorMissing,
    /// The mandate discloses no non-empty `scope` claim.
    ScopeMissing,
    /// The mandate is not bound to the presenting agent key (`cnf` mismatch).
    AgentKeyMismatch,
    /// The mandate's scope does not cover every required power.
    ScopeInsufficient,
    /// The compact SD-JWT is not well-formed (bad structure, wrong `typ`/`alg`, or the disclosures
    /// do not match the issuer-signed `_sd` digests). Raised only by [`verify_and_hold_mandate`].
    Malformed,
    /// The issuer's ES256 signature over the mandate did not verify against the trusted issuer key.
    /// Raised only by [`verify_and_hold_mandate`].
    SignatureInvalid,
    /// The mandate is past its issuer-signed `exp` (or has no `exp`) at the verification instant.
    /// Raised only by [`verify_and_hold_mandate`].
    Expired,
    /// The verification instant is before the mandate's issuer-signed `nbf`. Raised only by
    /// [`verify_and_hold_mandate`].
    NotYetValid,
}

/// The plan for one delegated presentation: who the agent acts for, the exact powers exercised
/// (a subset of the mandate's grant — never wider), and the link to the governing mandate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DelegationPlan {
    pub mandator: String,
    pub exercised_scope: BTreeSet<String>,
    pub mandate_jti: Option<String>,
}

impl HeldMandate {
    /// True when this mandate's `cnf` public key is the given agent key. Compares the membership
    /// fields of the two JWKs (order-insensitively), so the wallet only presents a mandate it can
    /// actually key-bind at presentation time.
    #[must_use]
    pub fn is_bound_to(&self, agent_jwk: &Value) -> bool {
        match (
            self.delegate_cnf_jwk.as_ref().and_then(jwk_identity),
            jwk_identity(agent_jwk),
        ) {
            (Some(mandate_key), Some(agent_key)) => mandate_key == agent_key,
            _ => false,
        }
    }

    /// True when every power in `required` is granted by this mandate.
    #[must_use]
    pub fn covers(&self, required: &BTreeSet<String>) -> bool {
        required.is_subset(&self.scope)
    }
}

/// Recognise a held credential as a power-of-representation mandate and read its delegated scope.
///
/// # Errors
///
/// [`DelegationError::NotAMandate`] if the `vct` is not [`MANDATE_VCT`]; [`DelegationError::ScopeMissing`]
/// if no non-empty `scope` claim is disclosed.
pub fn parse_mandate(held: &HeldCredential) -> Result<HeldMandate, DelegationError> {
    let payload = jwt_payload(&held.issuer_jwt).ok_or(DelegationError::NotAMandate)?;
    if payload.get("vct").and_then(Value::as_str) != Some(MANDATE_VCT) {
        return Err(DelegationError::NotAMandate);
    }
    let scope = disclosed_claim(held, "scope")
        .and_then(|value| {
            let urns: BTreeSet<String> = value
                .as_array()?
                .iter()
                .filter_map(|entry| entry.as_str().map(str::to_owned))
                .collect();
            (!urns.is_empty()).then_some(urns)
        })
        .ok_or(DelegationError::ScopeMissing)?;
    let mandator = disclosed_claim(held, "mandator")
        .and_then(|value| value.as_str().map(str::to_owned))
        .filter(|delegator| !delegator.is_empty())
        .ok_or(DelegationError::MandatorMissing)?;
    let mandate_jti =
        disclosed_claim(held, "mandate_jti").and_then(|value| value.as_str().map(str::to_owned));
    let delegate_cnf_jwk = payload.get("cnf").and_then(|cnf| cnf.get("jwk")).cloned();
    Ok(HeldMandate {
        mandator,
        scope,
        mandate_jti,
        delegate_cnf_jwk,
    })
}

/// Cryptographically verify a mandate SD-JWT VC and return it as a [`HeldCredential`] ready for
/// [`parse_mandate`] / [`select_delegated_presentation`].
///
/// Unlike [`parse_mandate`] (which trusts the caller to have authenticated the credential and only
/// *reads* structure), this is the authenticated entry point a wallet uses when it receives a
/// mandate from the issuer: it verifies the issuer's **ES256 signature** over the issuer-signed JWT
/// **and** that every disclosure hashes into the signed `_sd` set (via the same
/// [`sdjwt::SdJwtVc::verify_and_process`] the rest of the wallet uses for SD-JWT VCs), enforces the
/// mandatory `typ: dc+sd-jwt`, and confirms the credential type is [`MANDATE_VCT`]. A tampered
/// signature, a swapped disclosure, or a wrong issuer key is rejected — so a mandate accepted here
/// is a real, issuer-minted one, not merely a well-shaped string.
///
/// `issuer_public_key_raw` is the issuer's P-256 public key in SEC1 uncompressed form
/// (`0x04 || X || Y`, 65 bytes), typically obtained from the issuer's trusted JWKS.
///
/// `issuer_public_key_raw` is the issuer's P-256 public key in SEC1 uncompressed form
/// (`0x04 || X || Y`, 65 bytes), typically obtained from the issuer's trusted JWKS.
///
/// `now_unix_secs` is the verification instant (seconds since the Unix epoch): the mandate's
/// issuer-signed validity window (`nbf`/`exp`) is enforced against it, so an expired or not-yet-valid
/// mandate is rejected even though its signature is intact. (What this does NOT do: verify the
/// AGENT's proof-of-possession of the `cnf` key — that holder binding is checked at presentation time
/// via a key-binding JWT, not here. This entry point authenticates the ISSUER's attestation.)
///
/// # Errors
///
/// [`DelegationError::Malformed`] if the compact form, header (`typ`/`alg`), or disclosure/`_sd`
/// binding is invalid, or the `vct` is not [`MANDATE_VCT`]; [`DelegationError::SignatureInvalid`]
/// if the issuer's ES256 signature does not verify against `issuer_public_key_raw`;
/// [`DelegationError::Expired`] / [`DelegationError::NotYetValid`] if `now_unix_secs` is outside the
/// signed `[nbf, exp)` window.
pub fn verify_and_hold_mandate(
    compact_sdjwt: &str,
    issuer_public_key_raw: &[u8],
    now_unix_secs: u64,
    verifier: &dyn crypto_traits::Verifier,
    digest: &dyn crypto_traits::Digest,
) -> Result<HeldCredential, DelegationError> {
    let sd = sdjwt::SdJwtVc::parse(compact_sdjwt).map_err(|_| DelegationError::Malformed)?;
    if sd
        .issuer_algorithm()
        .map_err(|_| DelegationError::Malformed)?
        != crypto_traits::Alg::Es256
    {
        return Err(DelegationError::Malformed);
    }
    // Verifies the ES256 issuer signature AND that every disclosure matches a signed `_sd` digest
    // AND the mandatory `typ: dc+sd-jwt`. A bad signature or a swapped disclosure fails here.
    let processed = sd
        .verify_and_process(
            verifier,
            digest,
            issuer_public_key_raw,
            crypto_traits::Alg::Es256,
        )
        .map_err(|_| DelegationError::SignatureInvalid)?;
    let held = crate::held_credential_from_verified_sd(&sd, &processed, None)
        .map_err(|_| DelegationError::Malformed)?;
    // Read the always-visible, now issuer-SIGNED claims (the signature was verified above).
    let payload = jwt_payload(&held.issuer_jwt).ok_or(DelegationError::Malformed)?;
    // Only vouch for it as a mandate if the issuer-signed payload actually says so.
    if payload.get("vct").and_then(Value::as_str) != Some(MANDATE_VCT) {
        return Err(DelegationError::Malformed);
    }
    // Temporal validity against the issuer-signed window. A mandate MUST carry an `exp`; `nbf` is
    // enforced when present. A short-lived mandate that has expired is rejected even with a good sig.
    let exp = payload
        .get("exp")
        .and_then(Value::as_u64)
        .ok_or(DelegationError::Expired)?;
    if now_unix_secs >= exp {
        return Err(DelegationError::Expired);
    }
    if let Some(nbf) = payload.get("nbf").and_then(Value::as_u64) {
        if now_unix_secs < nbf {
            return Err(DelegationError::NotYetValid);
        }
    }
    Ok(held)
}

/// Decide whether a held mandate can back a delegated presentation for `agent_jwk` covering the
/// `required` powers, and produce the plan (exercising exactly `required`, never wider).
///
/// # Errors
///
/// [`DelegationError::AgentKeyMismatch`] if the mandate is not bound to the agent key;
/// [`DelegationError::ScopeInsufficient`] if the mandate does not grant every required power.
pub fn plan_delegated_presentation(
    mandate: &HeldMandate,
    agent_jwk: &Value,
    required: &BTreeSet<String>,
) -> Result<DelegationPlan, DelegationError> {
    if !mandate.is_bound_to(agent_jwk) {
        return Err(DelegationError::AgentKeyMismatch);
    }
    if !mandate.covers(required) {
        return Err(DelegationError::ScopeInsufficient);
    }
    Ok(DelegationPlan {
        mandator: mandate.mandator.clone(),
        exercised_scope: required.clone(),
        mandate_jti: mandate.mandate_jti.clone(),
    })
}

/// A chosen delegated presentation: which held mandate backs it and the exercised plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DelegatedPresentation {
    pub mandate: HeldMandate,
    pub plan: DelegationPlan,
}

impl DelegatedPresentation {
    /// The consent context the shell surfaces before signing: on whose behalf, and exactly which
    /// powers this presentation exercises (never wider than the mandate's grant).
    #[must_use]
    pub fn consent(&self) -> DelegationConsent {
        DelegationConsent {
            on_behalf_of: self.plan.mandator.clone(),
            exercised_scope: self.plan.exercised_scope.clone(),
        }
    }
}

/// What the "acting on behalf of" consent step shows the holder for a delegated presentation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DelegationConsent {
    pub on_behalf_of: String,
    pub exercised_scope: BTreeSet<String>,
}

/// From the wallet's held credentials, pick a mandate that is bound to `agent_jwk` and grants the
/// `required` powers, and return the delegated-presentation plan. The holder credential proving the
/// agent key is presented alongside the mandate by the existing multi-credential OpenID4VP path.
///
/// # Errors
///
/// The most specific failure seen while scanning the holdings: [`DelegationError::NotAMandate`] if
/// none is a mandate, else [`DelegationError::AgentKeyMismatch`] / [`DelegationError::ScopeInsufficient`]
/// / [`DelegationError::ScopeMissing`] from the closest candidate.
pub fn select_delegated_presentation<'a, I>(
    held: I,
    agent_jwk: &Value,
    required: &BTreeSet<String>,
) -> Result<DelegatedPresentation, DelegationError>
where
    I: IntoIterator<Item = &'a HeldCredential>,
{
    let mut closest = DelegationError::NotAMandate;
    for credential in held {
        match parse_mandate(credential) {
            Ok(mandate) => match plan_delegated_presentation(&mandate, agent_jwk, required) {
                Ok(plan) => return Ok(DelegatedPresentation { mandate, plan }),
                Err(error) => closest = error,
            },
            Err(DelegationError::NotAMandate) => {}
            Err(error) => closest = error,
        }
    }
    Err(closest)
}

/// The base64url-encoded JWT payload as JSON (the always-visible issuer claims).
fn jwt_payload(issuer_jwt: &str) -> Option<Value> {
    let payload_b64 = issuer_jwt.split('.').nth(1)?;
    let bytes = Base64UrlUnpadded::decode_vec(payload_b64).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// The disclosed value of one selectively-disclosable claim: a disclosure is
/// `base64url(json [salt, name, value])`, so the value is element 2.
fn disclosed_claim(held: &HeldCredential, name: &str) -> Option<Value> {
    let disclosure = held.disclosures_by_claim.get(name)?;
    let bytes = Base64UrlUnpadded::decode_vec(disclosure).ok()?;
    let array: Value = serde_json::from_slice(&bytes).ok()?;
    array.as_array()?.get(2).cloned()
}

/// The identity-defining public-key fields of a JWK, order-normalised so two encodings of the same
/// key compare equal regardless of member order or extra (non-identity) members.
fn jwk_identity(jwk: &Value) -> Option<BTreeMap<String, String>> {
    let object = jwk.as_object()?;
    let mut identity = BTreeMap::new();
    for field in ["kty", "crv", "x", "y", "n", "e"] {
        if let Some(value) = object.get(field).and_then(Value::as_str) {
            identity.insert(field.to_owned(), value.to_owned());
        }
    }
    // A comparable key identity MUST carry discriminating public-key material — an EC/OKP `x` or an
    // RSA `n`. Two JWKs sharing only `{kty, crv}` are NOT the same key and must never compare bound.
    if identity.contains_key("x") || identity.contains_key("n") {
        Some(identity)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64(bytes: &[u8]) -> String {
        Base64UrlUnpadded::encode_string(bytes)
    }

    fn disclosure(name: &str, value: Value) -> String {
        b64(&serde_json::to_vec(&serde_json::json!(["c2FsdA", name, value])).unwrap())
    }

    fn agent_jwk() -> Value {
        serde_json::json!({"kty": "EC", "crv": "P-256", "x": "AGENT_X", "y": "AGENT_Y"})
    }

    /// A held mandate bound to the agent key, granting present-identity + sign-document.
    fn mandate_holding() -> HeldCredential {
        let payload = serde_json::json!({
            "iss": "https://issuer.example",
            "vct": MANDATE_VCT,
            "cnf": {"jwk": agent_jwk()},
            "cryptographically_bound_to": "eu.europa.ec.eudi.pid.1"
        });
        let issuer_jwt = format!(
            "{}.{}.{}",
            b64(b"{}"),
            b64(&serde_json::to_vec(&payload).unwrap()),
            "sig"
        );
        let mut disclosures_by_claim = BTreeMap::new();
        disclosures_by_claim.insert(
            "mandator".to_owned(),
            disclosure(
                "mandator",
                serde_json::json!("urn:eudi:subject:delegator-1"),
            ),
        );
        disclosures_by_claim.insert(
            "scope".to_owned(),
            disclosure(
                "scope",
                serde_json::json!([
                    "urn:eudi:mandate:power:present-identity",
                    "urn:eudi:mandate:power:sign-document"
                ]),
            ),
        );
        disclosures_by_claim.insert(
            "mandate_jti".to_owned(),
            disclosure("mandate_jti", serde_json::json!("mandate-jti-9")),
        );
        HeldCredential {
            issuer_jwt,
            disclosures_by_claim,
            status: None,
        }
    }

    #[test]
    fn parses_a_held_mandate_scope_and_delegator() {
        let mandate = parse_mandate(&mandate_holding()).expect("valid mandate");
        assert_eq!(mandate.mandator, "urn:eudi:subject:delegator-1");
        assert_eq!(mandate.mandate_jti.as_deref(), Some("mandate-jti-9"));
        assert!(mandate
            .scope
            .contains("urn:eudi:mandate:power:present-identity"));
        assert!(mandate
            .scope
            .contains("urn:eudi:mandate:power:sign-document"));
        assert_eq!(mandate.scope.len(), 2);
    }

    #[test]
    fn a_non_mandate_credential_is_not_a_mandate() {
        let mut holding = mandate_holding();
        let payload =
            serde_json::json!({"vct": "eu.europa.ec.eudi.pid.1", "cnf": {"jwk": agent_jwk()}});
        holding.issuer_jwt = format!(
            "{}.{}.{}",
            b64(b"{}"),
            b64(&serde_json::to_vec(&payload).unwrap()),
            "sig"
        );
        assert_eq!(parse_mandate(&holding), Err(DelegationError::NotAMandate));
    }

    #[test]
    fn a_mandate_without_a_scope_disclosure_is_rejected() {
        let mut holding = mandate_holding();
        holding.disclosures_by_claim.remove("scope");
        assert_eq!(parse_mandate(&holding), Err(DelegationError::ScopeMissing));
    }

    #[test]
    fn a_mandate_without_a_mandator_disclosure_is_rejected() {
        let mut holding = mandate_holding();
        holding.disclosures_by_claim.remove("mandator");
        // The delegator identity is load-bearing — an absent mandator must not parse as valid
        // (and must never render as the holder acting for themselves).
        assert_eq!(
            parse_mandate(&holding),
            Err(DelegationError::MandatorMissing)
        );
    }

    #[test]
    fn a_key_with_no_coordinate_material_is_never_bound() {
        let mandate = parse_mandate(&mandate_holding()).unwrap();
        // Sharing only {kty, crv} is not identity — must not compare bound.
        assert!(!mandate.is_bound_to(&serde_json::json!({"kty": "EC", "crv": "P-256"})));
    }

    #[test]
    fn plans_a_presentation_within_the_granted_scope() {
        let mandate = parse_mandate(&mandate_holding()).unwrap();
        let required: BTreeSet<String> =
            ["urn:eudi:mandate:power:present-identity".to_owned()].into();
        let plan = plan_delegated_presentation(&mandate, &agent_jwk(), &required).unwrap();
        assert_eq!(plan.mandator, "urn:eudi:subject:delegator-1");
        assert_eq!(plan.exercised_scope, required);
        assert_eq!(plan.mandate_jti.as_deref(), Some("mandate-jti-9"));
    }

    #[test]
    fn cannot_present_beyond_the_granted_scope() {
        let mandate = parse_mandate(&mandate_holding()).unwrap();
        let required: BTreeSet<String> =
            ["urn:eudi:mandate:power:authorise-payment".to_owned()].into();
        assert_eq!(
            plan_delegated_presentation(&mandate, &agent_jwk(), &required),
            Err(DelegationError::ScopeInsufficient)
        );
    }

    #[test]
    fn cannot_present_a_mandate_bound_to_a_different_agent_key() {
        let mandate = parse_mandate(&mandate_holding()).unwrap();
        let other_key =
            serde_json::json!({"kty": "EC", "crv": "P-256", "x": "OTHER_X", "y": "OTHER_Y"});
        let required: BTreeSet<String> =
            ["urn:eudi:mandate:power:present-identity".to_owned()].into();
        assert_eq!(
            plan_delegated_presentation(&mandate, &other_key, &required),
            Err(DelegationError::AgentKeyMismatch)
        );
    }

    #[test]
    fn jwk_identity_ignores_member_order_and_extra_members() {
        let mandate = parse_mandate(&mandate_holding()).unwrap();
        // Same key, different member order plus an extra non-identity member.
        let reordered = serde_json::json!({"y": "AGENT_Y", "use": "sig", "x": "AGENT_X", "crv": "P-256", "kty": "EC"});
        assert!(mandate.is_bound_to(&reordered));
    }

    /// A non-mandate holding (an ordinary PID) bound to the same agent key.
    fn pid_holding() -> HeldCredential {
        let payload = serde_json::json!({
            "iss": "https://issuer.example",
            "vct": "eu.europa.ec.eudi.pid.1",
            "cnf": {"jwk": agent_jwk()}
        });
        HeldCredential {
            issuer_jwt: format!(
                "{}.{}.{}",
                b64(b"{}"),
                b64(&serde_json::to_vec(&payload).unwrap()),
                "sig"
            ),
            disclosures_by_claim: BTreeMap::new(),
            status: None,
        }
    }

    #[test]
    fn selects_the_qualifying_mandate_from_mixed_holdings() {
        let holdings = [pid_holding(), mandate_holding()];
        let required: BTreeSet<String> =
            ["urn:eudi:mandate:power:present-identity".to_owned()].into();
        let chosen = select_delegated_presentation(holdings.iter(), &agent_jwk(), &required)
            .expect("a held mandate qualifies");
        let consent = chosen.consent();
        assert_eq!(consent.on_behalf_of, "urn:eudi:subject:delegator-1");
        assert_eq!(consent.exercised_scope, required);
    }

    #[test]
    fn selection_reports_scope_insufficient_when_no_mandate_covers_the_request() {
        let holdings = [pid_holding(), mandate_holding()];
        let required: BTreeSet<String> =
            ["urn:eudi:mandate:power:authorise-payment".to_owned()].into();
        assert_eq!(
            select_delegated_presentation(holdings.iter(), &agent_jwk(), &required),
            Err(DelegationError::ScopeInsufficient)
        );
    }

    #[test]
    fn selection_reports_not_a_mandate_when_no_mandate_is_held() {
        let holdings = [pid_holding()];
        let required: BTreeSet<String> =
            ["urn:eudi:mandate:power:present-identity".to_owned()].into();
        assert_eq!(
            select_delegated_presentation(holdings.iter(), &agent_jwk(), &required),
            Err(DelegationError::NotAMandate)
        );
    }
}
