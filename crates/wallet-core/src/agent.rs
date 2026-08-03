//! Headless AI-agent shell over the sans-IO wallet core.
//!
//! An *agent* is a [`crate`] holder driven programmatically rather than by a phone UI. It holds a
//! power-of-representation mandate (see [`crate::delegation`]), signs with an **attested** keystore
//! (Secure Enclave on device; KMS/HSM/TEE with remote attestation in the cloud), and — per the
//! Mandamus/WAUTH spine `Identity → Mandate → Capability → Action → Receipt` — for every action:
//!
//! 1. gates it on the mandate's granted scope (never wider than what was delegated),
//! 2. requires the signing key's *attested* assurance to meet the action's required tier,
//! 3. requires a fresh **HAPP** (human approval / iProov step-up) for high-assurance actions —
//!    reputation/tier may *raise* the bar but can never *widen* scope, and
//! 4. emits a hash-chained, tamper-evident **receipt** linked to the governing mandate
//!    (`mandate_jti`), the wallet-side twin of the Mandamus Ed25519 receipt.
//!
//! This module is the pure decision + audit core. The concrete attested signer, the OpenID4VP
//! transport, and the MandamusCo receipt sink are injected by the host behind [`AttestedSigner`]
//! and the returned [`Receipt`] values.

use std::collections::BTreeSet;

use crypto_traits::Digest;

use crate::delegation::DelegationPlan;

/// How the agent's signing key is protected. Ordered by assurance the environment can attest to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyProtection {
    /// No hardware isolation (development only).
    Software,
    /// Cloud KMS / HSM without a fresh remote-attestation quote.
    Kms,
    /// TEE or KMS/HSM with a verified remote-attestation quote.
    AttestedTee,
    /// On-device secure element (Secure Enclave / StrongBox).
    SecureElement,
}

/// The assurance level an action is performed at (WAUTH T0–T3). Ordered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AssuranceTier {
    T0,
    T1,
    T2,
    T3,
}

/// The agent's "Agent Unit Attestation" — the WUA analog asserting how its key is protected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AgentUnitAttestation {
    pub protection: KeyProtection,
    pub remotely_attested: bool,
}

impl AgentUnitAttestation {
    /// The highest assurance tier this key protection can back. A cloud key only reaches the higher
    /// tiers when its environment is remotely attested; the weakest link is the cloud TEE quote.
    #[must_use]
    pub const fn assurance_ceiling(self) -> AssuranceTier {
        match self.protection {
            KeyProtection::Software => AssuranceTier::T0,
            KeyProtection::Kms => AssuranceTier::T1,
            KeyProtection::AttestedTee => {
                if self.remotely_attested {
                    AssuranceTier::T3
                } else {
                    AssuranceTier::T1
                }
            }
            KeyProtection::SecureElement => AssuranceTier::T3,
        }
    }
}

/// A human-approval (HAPP / iProov step-up) result to bind into a high-assurance action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HappEvidence {
    /// The approval was captured fresh for this action (not replayed).
    pub fresh: bool,
    /// The assurance tier the step-up achieved.
    pub tier: AssuranceTier,
}

/// One action the agent is asked to perform on the delegator's behalf.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActionRequest {
    /// The powers this action exercises; must be within the mandate's granted (planned) scope.
    pub required_powers: BTreeSet<String>,
    /// The assurance tier this action demands (e.g. a payment demands T2+).
    pub required_tier: AssuranceTier,
    /// The exact bytes being authorized (the OpenID4VP response / WYSIWYS payload).
    pub payload: Vec<u8>,
}

impl ActionRequest {
    /// Actions at this tier or above require a fresh human approval (HAPP).
    const HAPP_REQUIRED_FROM: AssuranceTier = AssuranceTier::T2;

    const fn requires_happ(&self) -> bool {
        matches!(self.required_tier, AssuranceTier::T2 | AssuranceTier::T3)
    }
}

/// Why the agent refused to act. Fail-closed: no signature or receipt is produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentError {
    /// The action exercises a power outside the mandate's granted scope.
    ScopeExceeded,
    /// The attested key protection cannot reach the action's required assurance tier.
    InsufficientAssurance,
    /// A high-assurance action lacks a fresh HAPP approval at (or above) the required tier.
    ApprovalRequired,
}

/// A tamper-evident, hash-chained receipt for one agent action — the wallet-side twin of a
/// Mandamus Ed25519 receipt. `chain_hash = H(prev_hash ‖ action_hash ‖ seq ‖ mandate_jti)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub seq: u64,
    pub mandate_jti: Option<String>,
    pub on_behalf_of: String,
    pub action_hash: [u8; 32],
    pub prev_hash: [u8; 32],
    pub chain_hash: [u8; 32],
}

/// The append-only hash-chained log of an agent's actions.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReceiptLog {
    head: [u8; 32],
    next_seq: u64,
    entries: Vec<Receipt>,
}

impl ReceiptLog {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn head(&self) -> [u8; 32] {
        self.head
    }

    #[must_use]
    pub fn entries(&self) -> &[Receipt] {
        &self.entries
    }

    fn link(
        digest: &dyn Digest,
        prev_hash: [u8; 32],
        seq: u64,
        action_hash: &[u8; 32],
        mandate_jti: Option<&str>,
        on_behalf_of: &str,
    ) -> [u8; 32] {
        // Length-prefix the variable-length fields so no two distinct (jti, on_behalf_of) pairs can
        // produce the same pre-image — the delegator identity is bound into the tamper-evidence.
        let mut buffer = Vec::with_capacity(96);
        buffer.extend_from_slice(&prev_hash);
        buffer.extend_from_slice(action_hash);
        buffer.extend_from_slice(&seq.to_be_bytes());
        let jti = mandate_jti.unwrap_or("");
        buffer.extend_from_slice(&(jti.len() as u64).to_be_bytes());
        buffer.extend_from_slice(jti.as_bytes());
        buffer.extend_from_slice(&(on_behalf_of.len() as u64).to_be_bytes());
        buffer.extend_from_slice(on_behalf_of.as_bytes());
        digest.sha256(&buffer)
    }

    fn append(
        &mut self,
        digest: &dyn Digest,
        action_hash: [u8; 32],
        mandate_jti: Option<String>,
        on_behalf_of: String,
    ) -> Receipt {
        let seq = self.next_seq;
        let prev_hash = self.head;
        let chain_hash = Self::link(
            digest,
            prev_hash,
            seq,
            &action_hash,
            mandate_jti.as_deref(),
            &on_behalf_of,
        );
        let receipt = Receipt {
            seq,
            mandate_jti,
            on_behalf_of,
            action_hash,
            prev_hash,
            chain_hash,
        };
        self.head = chain_hash;
        self.next_seq += 1;
        self.entries.push(receipt.clone());
        receipt
    }

    /// Recompute the whole chain and confirm each link and the head — detects any tampering.
    #[must_use]
    pub fn verify(&self, digest: &dyn Digest) -> bool {
        let mut prev = [0u8; 32];
        for (index, receipt) in self.entries.iter().enumerate() {
            if receipt.seq != index as u64 || receipt.prev_hash != prev {
                return false;
            }
            let expected = Self::link(
                digest,
                receipt.prev_hash,
                receipt.seq,
                &receipt.action_hash,
                receipt.mandate_jti.as_deref(),
                &receipt.on_behalf_of,
            );
            if expected != receipt.chain_hash {
                return false;
            }
            prev = receipt.chain_hash;
        }
        prev == self.head
    }
}

/// An attested keystore the agent signs with. The private key never leaves the host; the core only
/// sees the public key, the attestation, and produced signatures.
pub trait AttestedSigner {
    /// The agent's public key as a JWK — the key a mandate's `cnf` must be bound to.
    fn agent_jwk(&self) -> serde_json::Value;
    /// The environment's attestation of how the key is protected.
    fn attestation(&self) -> AgentUnitAttestation;
    /// Produce a signature over `payload` with the attested key.
    fn sign(&self, payload: &[u8]) -> Vec<u8>;
}

/// The result of a successful, authorized agent action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentAction {
    /// The signature over the action payload (the OpenID4VP response / WYSIWYS bytes).
    pub signature: Vec<u8>,
    /// The receipt appended to the audit chain for this action.
    pub receipt: Receipt,
}

/// A headless agent session: an attested signer plus its append-only receipt log.
pub struct AgentSession<S: AttestedSigner> {
    signer: S,
    log: ReceiptLog,
}

impl<S: AttestedSigner> AgentSession<S> {
    #[must_use]
    pub fn new(signer: S) -> Self {
        Self {
            signer,
            log: ReceiptLog::new(),
        }
    }

    #[must_use]
    pub fn log(&self) -> &ReceiptLog {
        &self.log
    }

    /// Perform one action on the delegator's behalf under an already-selected mandate `plan`.
    ///
    /// Fail-closed order: the action must stay within the planned (granted) scope; the attested key
    /// must reach the required tier; a high-assurance action needs a fresh HAPP approval at that
    /// tier. Scope is checked first and independently — a higher HAPP tier can never widen it. On
    /// success the payload is signed and a hash-chained receipt (linked to `mandate_jti`) appended.
    ///
    /// # Errors
    ///
    /// [`AgentError::ScopeExceeded`], [`AgentError::InsufficientAssurance`], or
    /// [`AgentError::ApprovalRequired`] — in that precedence — with no signature or receipt emitted.
    pub fn act(
        &mut self,
        plan: &DelegationPlan,
        request: &ActionRequest,
        happ: Option<HappEvidence>,
        digest: &dyn Digest,
    ) -> Result<AgentAction, AgentError> {
        // 1. Scope — never wider than the mandate delegated (checked first, HAPP-independent).
        if !request.required_powers.is_subset(&plan.exercised_scope) {
            return Err(AgentError::ScopeExceeded);
        }
        // 2. The attested key must be able to reach the action's assurance tier.
        if self.signer.attestation().assurance_ceiling() < request.required_tier {
            return Err(AgentError::InsufficientAssurance);
        }
        // 3. High-assurance actions require a fresh human approval at (or above) the required tier.
        if request.requires_happ() {
            let approved = happ
                .is_some_and(|evidence| evidence.fresh && evidence.tier >= request.required_tier);
            if !approved {
                return Err(AgentError::ApprovalRequired);
            }
        }
        let signature = self.signer.sign(&request.payload);
        let action_hash = digest.sha256(&request.payload);
        let receipt = self.log.append(
            digest,
            action_hash,
            plan.mandate_jti.clone(),
            plan.mandator.clone(),
        );
        Ok(AgentAction { signature, receipt })
    }
}

/// Documented constant so the HAPP threshold is discoverable from the public surface.
pub const HAPP_REQUIRED_FROM: AssuranceTier = ActionRequest::HAPP_REQUIRED_FROM;

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_backend::AwsLc;

    struct FakeSigner {
        attestation: AgentUnitAttestation,
    }
    impl AttestedSigner for FakeSigner {
        fn agent_jwk(&self) -> serde_json::Value {
            serde_json::json!({"kty": "EC", "crv": "P-256", "x": "AGENT_X", "y": "AGENT_Y"})
        }
        fn attestation(&self) -> AgentUnitAttestation {
            self.attestation
        }
        fn sign(&self, payload: &[u8]) -> Vec<u8> {
            // A deterministic stand-in for the attested signature (the real key lives in the host).
            let mut signature = b"sig:".to_vec();
            signature.extend_from_slice(payload);
            signature
        }
    }

    fn enclave_session() -> AgentSession<FakeSigner> {
        AgentSession::new(FakeSigner {
            attestation: AgentUnitAttestation {
                protection: KeyProtection::SecureElement,
                remotely_attested: false,
            },
        })
    }

    fn plan(scope: &[&str]) -> DelegationPlan {
        DelegationPlan {
            mandator: "urn:eudi:subject:delegator-1".to_owned(),
            exercised_scope: scope.iter().map(|s| (*s).to_owned()).collect(),
            mandate_jti: Some("mandate-jti-9".to_owned()),
        }
    }

    fn request(powers: &[&str], tier: AssuranceTier) -> ActionRequest {
        ActionRequest {
            required_powers: powers.iter().map(|s| (*s).to_owned()).collect(),
            required_tier: tier,
            payload: b"openid4vp-response-bytes".to_vec(),
        }
    }

    #[test]
    fn low_tier_in_scope_action_signs_and_receipts_without_happ() {
        let mut session = enclave_session();
        let plan = plan(&["urn:eudi:mandate:power:present-identity"]);
        let request = request(
            &["urn:eudi:mandate:power:present-identity"],
            AssuranceTier::T1,
        );
        let action = session.act(&plan, &request, None, &AwsLc).unwrap();
        assert!(action.signature.starts_with(b"sig:"));
        assert_eq!(action.receipt.seq, 0);
        assert_eq!(action.receipt.on_behalf_of, "urn:eudi:subject:delegator-1");
        assert_eq!(action.receipt.mandate_jti.as_deref(), Some("mandate-jti-9"));
        assert_eq!(action.receipt.prev_hash, [0u8; 32]);
        assert!(session.log().verify(&AwsLc));
    }

    #[test]
    fn an_action_outside_the_planned_scope_is_refused() {
        let mut session = enclave_session();
        let plan = plan(&["urn:eudi:mandate:power:present-identity"]);
        let request = request(
            &["urn:eudi:mandate:power:authorise-payment"],
            AssuranceTier::T1,
        );
        assert_eq!(
            session.act(&plan, &request, None, &AwsLc),
            Err(AgentError::ScopeExceeded)
        );
        assert!(session.log().entries().is_empty());
    }

    #[test]
    fn a_high_tier_action_requires_a_fresh_happ_approval() {
        let mut session = enclave_session();
        let plan = plan(&["urn:eudi:mandate:power:authorise-payment"]);
        let request = request(
            &["urn:eudi:mandate:power:authorise-payment"],
            AssuranceTier::T2,
        );

        // No approval → refused.
        assert_eq!(
            session.act(&plan, &request, None, &AwsLc),
            Err(AgentError::ApprovalRequired)
        );
        // Stale approval → refused.
        let stale = HappEvidence {
            fresh: false,
            tier: AssuranceTier::T3,
        };
        assert_eq!(
            session.act(&plan, &request, Some(stale), &AwsLc),
            Err(AgentError::ApprovalRequired)
        );
        // Fresh approval below the required tier → refused (tier can raise, never lower, the bar).
        let weak = HappEvidence {
            fresh: true,
            tier: AssuranceTier::T1,
        };
        assert_eq!(
            session.act(&plan, &request, Some(weak), &AwsLc),
            Err(AgentError::ApprovalRequired)
        );
        // Fresh approval at the required tier → authorized.
        let approved = HappEvidence {
            fresh: true,
            tier: AssuranceTier::T2,
        };
        assert!(session.act(&plan, &request, Some(approved), &AwsLc).is_ok());
    }

    #[test]
    fn happ_can_never_widen_scope() {
        let mut session = enclave_session();
        let plan = plan(&["urn:eudi:mandate:power:present-identity"]);
        // Even a top-tier fresh approval cannot authorize a power the mandate never granted.
        let request = request(
            &["urn:eudi:mandate:power:authorise-payment"],
            AssuranceTier::T3,
        );
        let approved = HappEvidence {
            fresh: true,
            tier: AssuranceTier::T3,
        };
        assert_eq!(
            session.act(&plan, &request, Some(approved), &AwsLc),
            Err(AgentError::ScopeExceeded)
        );
    }

    #[test]
    fn a_cloud_key_without_attestation_cannot_reach_high_tiers() {
        let mut session = AgentSession::new(FakeSigner {
            attestation: AgentUnitAttestation {
                protection: KeyProtection::AttestedTee,
                remotely_attested: false,
            },
        });
        let plan = plan(&["urn:eudi:mandate:power:authorise-payment"]);
        let request = request(
            &["urn:eudi:mandate:power:authorise-payment"],
            AssuranceTier::T2,
        );
        let approved = HappEvidence {
            fresh: true,
            tier: AssuranceTier::T3,
        };
        assert_eq!(
            session.act(&plan, &request, Some(approved), &AwsLc),
            Err(AgentError::InsufficientAssurance)
        );
    }

    #[test]
    fn receipts_form_a_tamper_evident_chain() {
        let mut session = enclave_session();
        let plan = plan(&["urn:eudi:mandate:power:present-identity"]);
        let request = request(
            &["urn:eudi:mandate:power:present-identity"],
            AssuranceTier::T1,
        );
        let first = session.act(&plan, &request, None, &AwsLc).unwrap();
        let second = session.act(&plan, &request, None, &AwsLc).unwrap();
        // The second receipt chains onto the first.
        assert_eq!(second.receipt.prev_hash, first.receipt.chain_hash);
        assert_eq!(second.receipt.seq, 1);
        assert!(session.log().verify(&AwsLc));
    }

    #[test]
    fn tampering_the_delegator_identity_breaks_the_chain() {
        let mut session = enclave_session();
        let plan = plan(&["urn:eudi:mandate:power:present-identity"]);
        let request = request(
            &["urn:eudi:mandate:power:present-identity"],
            AssuranceTier::T1,
        );
        session.act(&plan, &request, None, &AwsLc).unwrap();
        assert!(session.log().verify(&AwsLc));
        // Forge WHO the agent acted for — the load-bearing claim of a delegation receipt.
        session.log.entries[0].on_behalf_of = "urn:eudi:subject:attacker".to_owned();
        assert!(
            !session.log().verify(&AwsLc),
            "on_behalf_of must be bound into the tamper-evident chain"
        );
    }
}
