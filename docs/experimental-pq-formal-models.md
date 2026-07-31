# Experimental hybrid-PQ formal models

Issue #92 (plan section 15) extends the formal tiers with models of the hybrid authenticity and
negotiation invariants.

## Tier-3 symbolic model

`formal/tamarin/hybrid_pq_and_verification.spthy` (tamarin-prover 1.12.0, all lemmas verified,
no wellformedness warnings) models `euwallet-hybrid-pq-v1` against a Dolev-Yao attacker who can
additionally reveal the classical long-term key alone — a cryptographically relevant quantum
computer. Registration binds both component keys and one generation atomically; signing emits both
component signatures over one domain-separated TBS `<'hybrid_v1', purpose, ctx, m>`.

| Lemma | Acceptance criterion |
|---|---|
| `and_verification_both_components_required` | Acceptance implies the identity's atomic signing of exactly that purpose/context/message unless both components were compromised |
| `classical_break_alone_is_insufficient` | One valid component is formally insufficient: a classical break alone cannot produce acceptance |
| `no_mixed_identity_or_generation` | Accepted key pairs were registered atomically under one identity and generation |
| `hybrid_required_session_cannot_downgrade` | A hybrid-required session is never completed by a classical-only acceptance |
| `no_cross_purpose_replay` | Domain separation: an honest signature for one purpose is never accepted for another |

Component removal and substitution are covered structurally (acceptance requires both signatures
verifying over the same TBS under one atomically registered key pair) and by the compromise-bound
lemmas above. Partial completion cannot accept because signing and acceptance are single atomic
rules requiring both components.

## Tier-2 state-machine model

`formal/lean/HybridPqModel.lean` (no mathlib; built by `lake build HybridPqModel` in Tier-2 CI)
models the fail-closed verifier decision mirrored by `crates/hybrid-pq`: a session negotiates a
profile (recording hybrid-required policy), then a component result carries the six checks —
classical validity, PQ validity, identity match, generation match, profile match, purpose match —
and acceptance requires all six; any failure rejects the whole result.

Machine-checked theorems:

- `accepted_requires_both_components` — AND verification; one valid component is insufficient.
- `accepted_requires_one_identity_and_generation` — mixed identities/generations cannot combine.
- `accepted_requires_negotiated_profile_and_purpose` — profile binding and cross-purpose
  rejection.
- `hybrid_required_never_downgrades` — a hybrid-required session can never end in classical-only
  acceptance; the explicit fallback event rejects instead.

Implementation-level correspondence for these properties is exercised by the Rust adversarial
matrix (`crates/crypto-backend/src/experimental_pq.rs` tests and
`docs/experimental-pq-adversarial-matrix.md`).
