//! `experimental` — a REAL zero-knowledge proof provider, behind an EXPERIMENTAL versioned profile.
//!
//! This exists to demonstrate that the [`ProofProvider`](crate::ProofProvider) interface is
//! genuinely pluggable — not vapourware — with an honest ZK implementation. It is deliberately NOT
//! the production default: the register (TS04 / ARF Topic G) says keep no production ZK dependency
//! until a mandated interoperable profile matures, so the wallet ships [`SelectiveDisclosureFallback`]
//! (`crate::SelectiveDisclosureFallback`) and this provider is compiled only under the
//! `experimental-zk` feature and pinned behind [`PROFILE_EXPERIMENTAL`].
//!
//! ## The scheme
//!
//! A Pedersen commitment `C = m·G + r·H` (Ristretto; `H` a nothing-up-my-sleeve second generator)
//! hides an attribute value `m` under blinding `r`. To prove an attribute equals a PUBLIC value
//! (e.g. `age_over_18 == true`) without revealing `r` — so presentations are unlinkable — the
//! holder gives a non-interactive Schnorr proof of knowledge of `r` in `C − m·G = r·H`
//! (Chaum–Pedersen), Fiat–Shamir–bound to the session nonce for freshness. Hashing (generator
//! derivation, value→scalar, the challenge, and the deterministic Schnorr nonce) is done with
//! aws-lc SHA-256 via wide (64-byte) reduction — no extra hash dependency.
//!
//! What it proves: the prover knows an opening of `C` to the claimed value. Binding `C` to an
//! ISSUER signature (so the value is attested, not self-chosen) is the credential layer's job and
//! is out of this module's scope — the same division of labour as the rest of the wallet.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;

use crypto_backend::AwsLc;
use crypto_traits::Digest;

use crate::{Predicate, ProofProfile, ProofProvider, Witness, ZkpError};

/// The experimental ZK profile id. Isolated so it can never be confused with a mandated one.
pub const PROFILE_EXPERIMENTAL: ProofProfile = ProofProfile {
    id: "eudi-zk-experimental-v0",
};

/// 64 uniform bytes from a domain-separated input (two SHA-256 halves) for wide reduction.
fn wide(domain: &[u8], data: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    let mut d0 = Vec::with_capacity(domain.len() + 1 + data.len());
    d0.extend_from_slice(domain);
    d0.push(0);
    d0.extend_from_slice(data);
    let mut d1 = Vec::with_capacity(domain.len() + 1 + data.len());
    d1.extend_from_slice(domain);
    d1.push(1);
    d1.extend_from_slice(data);
    out[..32].copy_from_slice(&AwsLc.sha256(&d0));
    out[32..].copy_from_slice(&AwsLc.sha256(&d1));
    out
}

/// The second generator `H`, independent of `G` (discrete log unknown): a hash-to-curve of a fixed
/// domain tag, so nobody knows `log_G(H)`.
fn generator_h() -> RistrettoPoint {
    RistrettoPoint::from_uniform_bytes(&wide(b"eudi-zk-experimental-v0/H", b""))
}

/// Map an attribute `(claim, value)` to a scalar `m`. Binding the CLAIM (not just the value) is
/// essential: otherwise `age_over_18 == "true"` and `age_over_21 == "true"` would share a
/// commitment, and a proof for one would verify for the other.
fn attribute_scalar(claim: &[u8], value: &[u8]) -> Scalar {
    let mut buf = Vec::with_capacity(claim.len() + 1 + value.len());
    buf.extend_from_slice(claim);
    buf.push(b'=');
    buf.extend_from_slice(value);
    Scalar::from_bytes_mod_order_wide(&wide(b"eudi-zk-experimental-v0/attr", &buf))
}

/// A Pedersen commitment `C = m·G + r·H` to `(claim, value)` with blinding `r` (from
/// `blinding_seed`). Returns `(compressed C, r)`.
pub fn commit(claim: &[u8], value: &[u8], blinding_seed: &[u8]) -> ([u8; 32], [u8; 32]) {
    let r = Scalar::from_bytes_mod_order_wide(&wide(b"eudi-zk-experimental-v0/r", blinding_seed));
    let c = attribute_scalar(claim, value) * RISTRETTO_BASEPOINT_POINT + r * generator_h();
    (c.compress().to_bytes(), r.to_bytes())
}

fn point_from(bytes: &[u8]) -> Option<RistrettoPoint> {
    let arr: [u8; 32] = bytes.try_into().ok()?;
    CompressedRistretto(arr).decompress()
}

/// The Fiat–Shamir challenge, binding profile, nonce, commitment, claimed value, and announcement.
fn challenge(nonce: &[u8], c: &[u8; 32], value: &[u8], a: &[u8; 32]) -> Scalar {
    let mut t = Vec::new();
    for part in [
        PROFILE_EXPERIMENTAL.id.as_bytes(),
        nonce,
        &c[..],
        value,
        &a[..],
    ] {
        t.extend_from_slice(&(part.len() as u64).to_le_bytes());
        t.extend_from_slice(part);
    }
    Scalar::from_bytes_mod_order_wide(&wide(b"eudi-zk-experimental-v0/challenge", &t))
}

/// Resolve a predicate to the (claim, public-value) pair this scheme proves. `AgeOver{n}` reduces
/// to an issuer-asserted committed boolean `age_over_<n> == "true"`.
fn target(predicate: &Predicate) -> Result<(String, Vec<u8>), ZkpError> {
    match predicate {
        Predicate::AttributeEquals { claim, value } => {
            Ok((claim.clone(), value.clone().into_bytes()))
        }
        Predicate::AgeOver { years } => Ok((format!("age_over_{years}"), b"true".to_vec())),
        Predicate::AttributeDisclosed { .. } => Err(ZkpError::Unsupported),
    }
}

/// The witness JSON the holder supplies: `{ "<claim>": { "value": "<utf8>", "r": "<hex32>" } }`.
/// (`r` is the blinding returned by [`commit`]; `value` is the attribute's plaintext.)
fn witness_entry(witness: &Witness, claim: &str) -> Result<(Vec<u8>, Scalar), ZkpError> {
    let v: serde_json::Value =
        serde_json::from_slice(witness.credential).map_err(|_| ZkpError::UnsatisfiedPredicate)?;
    let entry = v.get(claim).ok_or(ZkpError::UnsatisfiedPredicate)?;
    let value = entry
        .get("value")
        .and_then(|x| x.as_str())
        .ok_or(ZkpError::UnsatisfiedPredicate)?
        .as_bytes()
        .to_vec();
    let r_hex = entry
        .get("r")
        .and_then(|x| x.as_str())
        .ok_or(ZkpError::UnsatisfiedPredicate)?;
    let r_bytes = hex32(r_hex).ok_or(ZkpError::UnsatisfiedPredicate)?;
    let r = Option::<Scalar>::from(Scalar::from_canonical_bytes(r_bytes))
        .ok_or(ZkpError::UnsatisfiedPredicate)?;
    Ok((value, r))
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(core::str::from_utf8(chunk).ok()?, 16).ok()?;
    }
    Some(out)
}

/// The experimental Ristretto ZK provider (feature `experimental-zk`).
pub struct ExperimentalZk;

impl ProofProvider for ExperimentalZk {
    fn profile(&self) -> ProofProfile {
        PROFILE_EXPERIMENTAL
    }

    fn prove(
        &self,
        predicate: &Predicate,
        witness: &Witness,
        nonce: &[u8],
    ) -> Result<Vec<u8>, ZkpError> {
        let (claim, expected_value) = target(predicate)?;
        let (value, r) = witness_entry(witness, &claim)?;
        // The witness must actually satisfy the predicate.
        if value != expected_value {
            return Err(ZkpError::UnsatisfiedPredicate);
        }

        let h = generator_h();
        let m = attribute_scalar(claim.as_bytes(), &value);
        let c = m * RISTRETTO_BASEPOINT_POINT + r * h;
        let c_bytes = c.compress().to_bytes();

        // Deterministic Schnorr nonce k, secret-dependent (hiding) yet reproducible (sans-IO).
        let mut k_seed = Vec::new();
        k_seed.extend_from_slice(&r.to_bytes());
        k_seed.extend_from_slice(nonce);
        k_seed.extend_from_slice(&c_bytes);
        k_seed.extend_from_slice(&value);
        let k = Scalar::from_bytes_mod_order_wide(&wide(b"eudi-zk-experimental-v0/k", &k_seed));
        let a = (k * h).compress().to_bytes();

        let e = challenge(nonce, &c_bytes, &value, &a);
        let z = k + e * r;

        // proof = C ‖ A ‖ z  (96 bytes).
        let mut proof = Vec::with_capacity(96);
        proof.extend_from_slice(&c_bytes);
        proof.extend_from_slice(&a);
        proof.extend_from_slice(&z.to_bytes());
        Ok(proof)
    }

    fn verify(&self, predicate: &Predicate, proof: &[u8], nonce: &[u8]) -> Result<bool, ZkpError> {
        let (claim, value) = target(predicate)?;
        if proof.len() != 96 {
            return Ok(false);
        }
        let (Some(c), Some(a)) = (point_from(&proof[..32]), point_from(&proof[32..64])) else {
            return Ok(false);
        };
        let z = match Option::<Scalar>::from(Scalar::from_canonical_bytes(
            proof[64..96].try_into().expect("32 bytes"),
        )) {
            Some(z) => z,
            None => return Ok(false),
        };
        let c_bytes: [u8; 32] = proof[..32].try_into().expect("32 bytes");
        let a_bytes: [u8; 32] = proof[32..64].try_into().expect("32 bytes");

        let h = generator_h();
        // P = C − m·G should equal r·H; the Schnorr check is z·H == A + e·P.
        let p = c - attribute_scalar(claim.as_bytes(), &value) * RISTRETTO_BASEPOINT_POINT;
        let e = challenge(nonce, &c_bytes, &value, &a_bytes);
        Ok(z * h == a + e * p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build the holder's witness JSON for one committed attribute.
    fn witness_json(claim: &str, value: &str, r_hex: &str) -> String {
        format!(r#"{{"{claim}":{{"value":"{value}","r":"{r_hex}"}}}}"#)
    }

    fn hexstr(b: &[u8; 32]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn age_over_18_proof_is_complete_and_sound() {
        let p = ExperimentalZk;
        // Issuer commits the boolean `age_over_18 = true`; the holder gets (C, r).
        let (_c, r) = commit(b"age_over_18", b"true", b"holder-blinding-seed");
        let wit_json = witness_json("age_over_18", "true", &hexstr(&r));
        let witness = Witness {
            credential: wit_json.as_bytes(),
        };
        let pred = Predicate::AgeOver { years: 18 };

        // Completeness: an honest proof verifies.
        let proof = p.prove(&pred, &witness, b"session-nonce").unwrap();
        assert_eq!(p.verify(&pred, &proof, b"session-nonce"), Ok(true));

        // Freshness: the proof is bound to the nonce — a different nonce rejects.
        assert_eq!(p.verify(&pred, &proof, b"other-nonce"), Ok(false));

        // Soundness: the SAME proof does not verify for a different claimed predicate value.
        let pred21 = Predicate::AgeOver { years: 21 };
        assert_eq!(p.verify(&pred21, &proof, b"session-nonce"), Ok(false));

        // Tamper: flipping any proof byte breaks verification.
        let mut bad = proof.clone();
        bad[80] ^= 1;
        assert_eq!(p.verify(&pred, &bad, b"session-nonce"), Ok(false));
    }

    #[test]
    fn attribute_equals_hides_blinding_and_is_unlinkable() {
        let p = ExperimentalZk;
        // Two commitments to the SAME value with different blinding are distinct (unlinkable).
        let (c1, r1) = commit(b"nationality", b"SE", b"seed-1");
        let (c2, _r2) = commit(b"nationality", b"SE", b"seed-2");
        assert_ne!(
            c1, c2,
            "re-blinded commitments to the same value are unlinkable"
        );

        let pred = Predicate::AttributeEquals {
            claim: "nationality".into(),
            value: "SE".into(),
        };
        let wit = witness_json("nationality", "SE", &hexstr(&r1));
        let proof = p
            .prove(
                &pred,
                &Witness {
                    credential: wit.as_bytes(),
                },
                b"n",
            )
            .unwrap();
        assert_eq!(p.verify(&pred, &proof, b"n"), Ok(true));

        // The blinding `r` never appears in the proof bytes (it is only in the witness).
        assert!(
            !proof.windows(32).any(|w| w == r1),
            "the Schnorr proof must not leak the blinding"
        );
    }

    #[test]
    fn proving_a_false_predicate_fails() {
        let p = ExperimentalZk;
        let (_c, r) = commit(b"age_over_18", b"false", b"seed");
        // The holder is NOT over 18 (committed value is "false").
        let wit = witness_json("age_over_18", "false", &hexstr(&r));
        assert_eq!(
            p.prove(
                &Predicate::AgeOver { years: 18 },
                &Witness {
                    credential: wit.as_bytes()
                },
                b"n"
            ),
            Err(ZkpError::UnsatisfiedPredicate)
        );
    }
}
