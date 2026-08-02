# Delegating scoped authority to AI agents — cross-repo design brief

**Date:** 2026-08-03 · **Status:** design proposal for review (no code yet). Spans five repos:
`EUWallet` (holder), `../VCIssuer` (issuer), `../VCVerifier` (verifier), `~/dev/iproov/MandamusCo`
(Agentic Authority control plane), `~/dev/iproov/AAIF/WAUTH` (the Mandamus/WAUTH spec).

Claims are **[grounded]** (read from a repo or a cited source) or **[proposed]** (our design/inference).

---

## 0. The honest starting point

**The EU gives us the legal hook and a required attestation *shape*, but not a machine-agent model.** **[grounded]**
- Reg (EU) 2024/1183 makes "a natural person representing another natural person or a legal person" a
  first-class subject; **Annex VI(9): "Powers and mandates to represent natural or legal persons"** is a
  minimum attribute.
- ARF **Topic 29 "Representation paradigm" (RP_01/RP_02):** representation SHALL be a **distinct attestation
  type** naming its **validity period, nature, and the specific operations authorized (scope)**, and SHALL be
  **short-lived or revocable**. But Topic 29 is scoped to **natural-person→natural-person only**, legal-person
  delegation is deferred, and **no official Rulebook exists yet** (the catalog is only PID + mDL).
- Buildable data models today: the **EWC Large-Scale Pilot** rulebooks **Legal Person ID (LPID, rb001)** and
  **Signatory Rights (rb_004)** (SD-JWT VC) — which themselves **exclude delegation chains**.
- **There is no EU-recognised model for an AI agent as delegate.** An agent is not a "user"/holder under
  eIDAS; holder-binding assumes a human-controlled secure device; delegation chains + machine mandatees are
  unspecified. **This is the gap we are designing into — an explicit, honest extension, not a claim of
  EU-standard status.**

**Mandamus/WAUTH already fills the machine half.** **[grounded]** The WAUTH spec (`advatar/WAUTH`, Apache-2.0)
defines the spine `Identity → Mandate → Capability → Action → Receipt`, **HAPP** (human approval / iProov
liveness step-up), **hash-chained Ed25519 receipts**, and **delegation chains with monotonic narrowing**
(Agent A → narrower capability for Agent B via RFC 8693 `act` + `mandate_jti`) — already **Lean-proven**
(`formal/lean/Hamp/Delegation.lean`: narrow-not-widen, depth bound, "no permit without policy/revocation/
HAPP/receipt evidence"; "reputation only affects HAPP tier, not mandate scope"). It already cites
OpenID4VCI/VP and has a `link-agent-wallet-bridge` profile.

**Thesis:** make the **EUDI power-of-representation attestation the interoperable, government-trust, verifiable
face of a Mandamus mandate/capability.** Mandamus governs the agent's action at runtime (gate + HAPP +
receipt); the EUDI mandate VC lets *any* EUDI relying party verify the agent's delegated authority via
OpenID4VP/VCVerifier. Both worlds already carry Lean proofs, so we align one delegation-monotonicity
obligation across stacks.

## 1. Two-world mapping
| Mandamus / WAUTH (runtime authority + audit) | EUDI (portable, verifiable credential) |
|---|---|
| Mandate / WRIT-CAP capability (scope, `mandate_jti`) | Power-of-representation attestation (Topic 29 / EWC) |
| Agent identity + KMS/enclave key | mandate VC **holder binding** (`cnf` = agent key) |
| HAPP (iProov step-up, T0–T3 tier) | wallet **explicit-approval-before-signing** gate |
| Receipt (hash-chained Ed25519) | wallet **transaction log** / presentation audit |
| Gate allow/deny + revoke | **Token Status List** revocation (already in EUWallet `status`) |
| Monotonic-narrowing delegation chain (RFC 8693 `act`) | scope constraints + chain in the mandate VC |

## 2. The mandate attestation (data model) [proposed, grounded in Topic 29 + EWC + WAUTH]
A **distinct** SD-JWT VC (mdoc optional) attestation type, e.g. `vct: urn:eudi:mandate:1`, carrying:
- **mandator** (delegator) identity, cryptographically bound to a **presented PID / LPID+Signatory-Rights** at
  issuance;
- **mandatee = the agent**, bound by **`cnf` = the agent's holder key** (machine holder-binding — the explicit
  extension);
- **powers/scope** — the specific authorized operations, as **selectively-disclosable claims**, expressed to
  be **decidably subset-checkable** (so a verifier can prove requested ⊆ granted);
- **validity** (short-lived) + **status reference** (Token Status List) for revocation;
- optional **`mandate_jti`** linking to the Mandamus mandate/capability, and delegation-chain lineage (`act`)
  for agent-to-agent sub-delegation with **monotonic narrowing**;
- `cryptographically_bound_to` the delegator PID/LPID (reusing the issuer's existing binding claim).

## 3. The agent-holder ("where it keeps VCs, how it uses them") [proposed]
One **portable model**: a **headless `wallet-core` + a pluggable, *attested* keystore signer**. The
`crypto-traits::Signer` boundary already abstracts key location; the sans-IO core already separates the
security decision from IO and just emits a `Sign` effect.
- **Mac app / iPhone app:** **Secure Enclave** signer (as iOS already does) — highest assurance, local.
- **Cloud:** **KMS/HSM or TEE** signer (Mandamus uses Cloud-KMS Ed25519 / AWS-KMS P-256 — both in the wallet's
  alg allow-list) with **remote attestation** of the environment.
- The key's protection level is asserted by an **"Agent Unit Attestation"** — the WUA analog the wallet
  already has at LoA High. The mandate VC's `cnf` binds to this key; the verifier trusts it per its attested
  protection.
- **Use = headless OpenID4VP presentation:** the core authenticates the verifier, validates the request,
  minimises, and signs with the agent key **within the mandate's scope**; **HAPP** provides human step-up on
  consequential actions; each use writes an audit record (wallet txnlog ↔ Mandamus receipt).

## 4. Cross-repo build map (concrete, grounded extension points)

### VCIssuer — issue the mandate attestation [grounded hooks]
Template to mirror: the **existing PID-bound QEAA flow** (verify presented PID = delegator, bind holder key,
emit `cryptographically_bound_to`). New work: a **scope/powers type + revocation** (kernel has none today).
- `rust/issuer-core/src/lib.rs`: add a `Scope/Powers` type + delegator/mandate fields to Request/Session;
  add `may_issue` conjuncts (delegate-key possession, **powers ⊆ delegator grant**, `mandate_not_revoked`,
  delegator-evidence-usable); expose via `SignCommand` — mirror the hybrid-PQ AND-gate at `lib.rs:246-305`.
- `formal/lean/EudiIssuer/Model.lean`: mirror in `mayIssue`; prove FI-SAF-style theorems (scope-subset,
  delegate-key-binding, revocation-freshness) following `hybridAccept`/`authorizeHybridSign`.
- `formal/tamarin/eudi_issuance.spthy`: mandate lemma (issuance ⇒ prior delegator authorization agreeing on
  delegate key + scope).
- `rust/issuer-service/src/main.rs`: mandate `credential_configuration_id` + `vct` constants; `mandate_profile`
  in metadata (model on `learning_profile` pid_binding); route in `authorize_kernel`; **reuse
  `verify_pid_binding` as the delegator-authentication step**; `issue_sd_jwt` branch emitting mandate vct +
  delegate key in `cnf` + scope claims; keychain signer; `activechain_schema.rs` mapping.
- `schemas/credential-profile.schema.json` + `standards.lock.toml`: pin a concrete power-of-representation
  rulebook + vct/claim schema (replace the placeholder attestation slot).

### EUWallet — hold + present as the agent [grounded hooks]
- `crates/catalogue`: register the mandate type (mandatory claims per the pinned rulebook); note **portrait
  is already enforced for PID** — the mandate type has its own profile.
- `crates/status`: Token Status List revocation is **already implemented** — reuse for mandate revocation.
- `crates/wallet-core` + `crates/oid4vp`: present the **delegate's holder credential + the mandate attestation**
  together (multi-credential presentation already exists); bind the **agent key** as the device/holder key;
  surface **on-behalf-of** context in consent. `crates/w2w` (wallet-to-wallet) is the closest existing
  transport concept to reuse for delegate hand-off.
- New **"agent shell"**: a headless driver over `wallet-core` (KMS/enclave signer + programmatic OID4VP
  responder), instead of the phone UI.

### VCVerifier — verify the delegation chain [grounded hooks]
No delegation concept today — clean extension points:
- `rust/verifier-core/src/lib.rs`: add `DelegationEvidence` (delegator_subject, delegate_key, granted_power/
  scope, delegation trust_anchor, signature/status `TimedEvidence`, `delegation_not_revoked`, mandate binding);
  extend `VerificationPolicy` (`require_delegation`, allowed type/anchor, required scope, delegate-key-binding);
  add errors (`PowerNotGranted`/`ScopeExceeded`, `DelegateKeyBindingInvalid`, `DelegationRevoked`,
  `DelegationChainInvalid`); generalise the `credential_count==1` gate to allow holder-cred + mandate; add a
  **decidable scope-containment relation** (the opaque disclosure-set equality is insufficient for subset).
- New adapter crate `rust/delegation-verifier` (template `rust/hybrid-pq-verifier`) to parse/verify the
  attestation + resolve delegator anchor + delegate key.
- `formal/lean/EudiVerifier/Model.lean`: `mayAccept` conjuncts + theorems `delegate_key_binding_is_enforced`,
  `delegated_request_is_within_granted_scope`, `revoked_delegation_cannot_be_accepted`,
  `delegator_is_mandate_subject`; `eudi_presentation.spthy` two-party flow; `requirements/traceability.csv`
  DEL-* rows.

### Mandamus/WAUTH — the authority + audit bridge [grounded]
- Map **Mandamus capability scope ↔ EUDI powers claim 1:1** so both enforce the same monotonic narrowing;
  carry `mandate_jti` in the VC to link.
- **HAPP** is the human step-up for consequential agent actions (iProov First-Person portrait/liveness); its
  approval evidence binds into the presentation's authorization (see EUWallet "authenticated approval before
  signing" work).
- Every agent presentation → a **Mandamus receipt** (hash-chained Ed25519); align the wallet txnlog with it.
- Reuse/extend the WAUTH **`link-agent-wallet-bridge`** and **OAuth-token-exchange** profiles for the
  wallet↔agent and chain-narrowing paths; align the delegation-monotonicity obligation with
  `WAUTH/formal/lean/Hamp/Delegation.lean`.

## 5. Recommended answers to the four open decisions [proposed]
1. **Per-delegation, short-lived VC that references the Mandamus mandate** (`mandate_jti` + scope), status-list
   revocable (Topic 29 RP_02) — not a static long-lived credential.
2. **Issuer = VCIssuer as the mandate EAA issuer, with the delegator authenticated by PID (natural person) or
   LPID + Signatory-Rights (legal person) presentation** (reuse `verify_pid_binding`). A business wallet
   self-issuing is a later option; VCIssuer-as-EAA is the buildable path now.
3. **Yes — consequential (high-tier) actions require a fresh HAPP/iProov step-up whose receipt binds into the
   OpenID4VP authorization** (this is the wallet's authenticated-approval-before-signing gate). Tier from WAUTH
   T0–T3; reputation may raise the tier but **never widens scope** (their Lean proof).
4. **Scope = the EUDI Topic 29 "specific operations authorized" as selectively-disclosable power claims with a
   decidable subset relation in the verifier; Mandamus capability maps to it 1:1.**

## 6. Formal obligations (aligned across repos)
One property, proved on both sides: **a delegate can only ever exercise a subset of the granted powers, only
while the mandate is valid and non-revoked, only with the bound agent key, and (for high-tier actions) only
with fresh HAPP evidence.** Issuer proves it can't mint a widening mandate; verifier proves it can't accept an
out-of-scope / revoked / wrong-key / (where required) un-approved delegated request; WAUTH already proves
chain monotonicity + depth bounds. Serialization + Swift/Android decoder conformance for the new wallet types.

## 7. Core-first phased plan (per repo; each slice verified before the next)
1. **Schema + rulebook pin** (shared): fix the mandate `vct` + power/scope claim schema; pin in each
   `standards.lock.toml`.
2. **VCIssuer**: mandate attestation issuance (kernel scope/powers + revocation + `may_issue` conjuncts →
   Lean/Tamarin → service encoder), reusing the PID-bound-QEAA template. Tests green.
3. **VCVerifier**: `DelegationEvidence` + scope-containment + delegation gates + `delegation-verifier` adapter
   → Lean/Tamarin/traceability. Tests green.
4. **EUWallet**: hold the mandate + present holder-cred-plus-mandate as the delegate; agent key binding;
   on-behalf-of consent. Reuse `status` revocation + multi-credential presentation.
5. **Agent shell + Mandamus bridge**: headless `wallet-core` with KMS/enclave signer; HAPP step-up binding;
   receipt emission; `mandate_jti` linkage; agent-to-agent narrowing.
6. **End-to-end**: issue → hold (agent) → present → verify, across all repos, with the aligned scope/revocation
   proof.

## 8. Risks / open items
- Not an EU-standard model for agents — position as a **designed extension**; track the eventual EU
  power-of-representation Rulebook and converge when it lands.
- **Machine holder-binding + LoA** for a cloud agent key needs an attestation story (Agent Unit Attestation);
  cloud TEE remote-attestation trust is the weakest link.
- **Scope taxonomy** (what "powers" mean, how expressed for subset checks) must be pinned early — it drives
  the verifier's decidable relation and the Lean proof.
- Liability/legal: a machine mandatee acting under a natural/legal person's mandate is legally novel; keep the
  human accountable via HAPP + receipts.
