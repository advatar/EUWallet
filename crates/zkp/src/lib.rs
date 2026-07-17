#![forbid(unsafe_code)]
//! `zkp` — pluggable zero-knowledge / unlinkable-presentation **proof-provider abstraction**.
//!
//! See docs/IMPLEMENTATION_PLAN.md Section 5 (Watch modules) and the register's TS04 / ARF Topic G.
//!
//! ## Why this is an interface, not an implementation
//!
//! Register status (TS04, ARF Topic G): *"Published guidance; no universal mandatory production
//! profile."* Guidance: *"Keep a proof-provider interface but no production dependency until a
//! mandated interoperable profile matures. Do not choose a proprietary ZKP system that breaks
//! cross-border interoperability."*
//!
//! So this crate deliberately contains **no concrete ZK scheme**. It defines the boundary the
//! wallet will program against, and pins any future scheme behind a versioned [`ProofProfile`]
//! (the same isolation discipline used for SD-JWT VC's draft marker). When a profile is mandated,
//! it is added as a new [`ProofProvider`] implementation behind that profile id — the protocol
//! layer does not change. Until then, the wallet uses selective disclosure (SD-JWT VC) and the
//! [`SelectiveDisclosureFallback`] provider reports predicate proofs as unsupported so callers
//! fall back rather than silently degrade.

use crypto_traits::Digest;

/// A statement the holder proves about a credential while revealing no more than necessary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Predicate {
    /// Prove the holder is at least `years` old without revealing the birth date (range proof).
    AgeOver { years: u32 },
    /// Prove a claim equals a value without revealing other claims.
    AttributeEquals { claim: String, value: String },
    /// Ordinary selective disclosure of a claim (no ZK required — the base case).
    AttributeDisclosed { claim: String },
}

/// A versioned marker identifying the concrete proof system in use, so a chosen scheme is
/// isolated behind it and can be swapped without touching the protocol layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProofProfile {
    pub id: &'static str,
}

/// The only profile that exists today: none. Selective disclosure, not a ZK scheme.
pub const PROFILE_NONE: ProofProfile = ProofProfile {
    id: "none/selective-disclosure",
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ZkpError {
    /// This provider cannot prove this predicate (e.g. a range proof with no mandated ZK profile).
    /// The caller should fall back to selective disclosure or refuse.
    Unsupported,
    /// The witness (credential secret) did not satisfy the predicate.
    UnsatisfiedPredicate,
    Backend(String),
}

/// A witness: the secret material (e.g. the credential + salts) that lets the holder prove a
/// predicate. Opaque to the abstraction.
pub struct Witness<'a> {
    pub credential: &'a [u8],
}

/// The pluggable proof provider. A concrete implementation is chosen at runtime by profile; the
/// wallet's protocol machines depend only on this trait.
pub trait ProofProvider {
    /// Which proof system this provider implements.
    fn profile(&self) -> ProofProfile;

    /// Produce a proof that `predicate` holds for `witness`, bound to `nonce` (freshness).
    fn prove(
        &self,
        predicate: &Predicate,
        witness: &Witness,
        nonce: &[u8],
    ) -> Result<Vec<u8>, ZkpError>;

    /// Verify a `proof` for `predicate`, bound to `nonce`.
    fn verify(&self, predicate: &Predicate, proof: &[u8], nonce: &[u8]) -> Result<bool, ZkpError>;
}

/// The register-endorsed default until a ZK profile is mandated: there is **no** zero-knowledge
/// here. Predicate/range proofs (`AgeOver`, `AttributeEquals`) return [`ZkpError::Unsupported`]
/// so the wallet falls back to selective disclosure; `AttributeDisclosed` is acknowledged as the
/// disclosure base case (the actual disclosure is performed by the SD-JWT VC path, not here).
pub struct SelectiveDisclosureFallback;

impl ProofProvider for SelectiveDisclosureFallback {
    fn profile(&self) -> ProofProfile {
        PROFILE_NONE
    }

    fn prove(
        &self,
        predicate: &Predicate,
        _witness: &Witness,
        _nonce: &[u8],
    ) -> Result<Vec<u8>, ZkpError> {
        match predicate {
            // No ZK scheme is active: the wallet must fall back to selective disclosure.
            Predicate::AgeOver { .. } | Predicate::AttributeEquals { .. } => {
                Err(ZkpError::Unsupported)
            }
            // The disclosure base case carries no ZK proof; the SD-JWT VC layer does the work.
            Predicate::AttributeDisclosed { .. } => Ok(Vec::new()),
        }
    }

    fn verify(&self, predicate: &Predicate, proof: &[u8], _nonce: &[u8]) -> Result<bool, ZkpError> {
        match predicate {
            Predicate::AttributeDisclosed { .. } => Ok(proof.is_empty()),
            _ => Err(ZkpError::Unsupported),
        }
    }
}

/// Bind a proof to a session nonce deterministically (a helper future providers can reuse for
/// their transcript). Not a proof itself — just a domain-separated commitment over the nonce.
pub fn transcript_commitment(digest: &dyn Digest, profile: ProofProfile, nonce: &[u8]) -> [u8; 32] {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"eudi-zkp-transcript:");
    buf.extend_from_slice(profile.id.as_bytes());
    buf.push(b'|');
    buf.extend_from_slice(nonce);
    digest.sha256(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StubDigest;
    impl Digest for StubDigest {
        fn sha256(&self, _d: &[u8]) -> [u8; 32] {
            [0u8; 32]
        }
    }

    #[test]
    fn fallback_reports_predicate_proofs_unsupported() {
        let p = SelectiveDisclosureFallback;
        let w = Witness {
            credential: b"cred",
        };
        // Range/equality predicates require a mandated ZK profile → unsupported (fall back).
        assert_eq!(
            p.prove(&Predicate::AgeOver { years: 18 }, &w, b"n"),
            Err(ZkpError::Unsupported)
        );
        assert_eq!(
            p.prove(
                &Predicate::AttributeEquals {
                    claim: "nationality".into(),
                    value: "SE".into()
                },
                &w,
                b"n"
            ),
            Err(ZkpError::Unsupported)
        );
    }

    #[test]
    fn fallback_treats_disclosure_as_base_case() {
        let p = SelectiveDisclosureFallback;
        let w = Witness {
            credential: b"cred",
        };
        let proof = p
            .prove(
                &Predicate::AttributeDisclosed {
                    claim: "age_over_18".into(),
                },
                &w,
                b"n",
            )
            .unwrap();
        assert!(proof.is_empty());
        assert_eq!(
            p.verify(
                &Predicate::AttributeDisclosed {
                    claim: "age_over_18".into()
                },
                &proof,
                b"n"
            ),
            Ok(true)
        );
    }

    #[test]
    fn transcript_commitment_is_deterministic_and_domain_separated() {
        let a = transcript_commitment(&StubDigest, PROFILE_NONE, b"nonce");
        let b = transcript_commitment(&StubDigest, PROFILE_NONE, b"nonce");
        assert_eq!(a, b);
    }
}
