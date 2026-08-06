# The Agent Wallet Runtime — plan

**Status:** design plan for review · **Date:** 2026-08-06 · **Scope:** turn the shipped delegation
engine into a portable **Agent Wallet Runtime** exposed through several adapters — MCP, Agent
Plugins, REST, native SDK, local IPC — so any plugin-capable AI agent can hold its own cryptographic
identity and exercise delegated human/organizational authority **without ever receiving the
delegator's private credentials**.

Companion to [`agent-delegation-design.md`](agent-delegation-design.md) (the cross-repo delegation
model) and [`agent-wallet-custody-profiles.md`](agent-wallet-custody-profiles.md) (MAWP-1/2/3: where
each runtime's key + mandate live). Claims are **[grounded]** (read from this repo / a cited spec) or
**[proposed]**.

---

## 0. Thesis

> **Mandamus is not "an Agent Plugin." Mandamus is the authority runtime that *happens to be
> distributable as* an Agent Plugin.**

The product is the **Agent Wallet Runtime**. Agent Plugins, MCP, REST, native SDKs and desktop IPC
are **adapters** onto it. If Agent Plugins disappeared tomorrow, the runtime still works over the
others. The plugin contains **zero security logic** — it is an adapter that forwards intents to the
runtime, which decides.

This is also forced by the spec: Agent Plugins 1.0 defines **exactly two component types — skills and
MCP servers** — and states *"Agent Plugins v1 defines no OAuth configuration or portable
credential-reference fields. Authorization discovery, user interaction, and credential storage are
client-managed."* It even warns *"Plugins MUST NOT embed credentials or other secrets in `headers`."*
So the spec leaves exactly the hole the runtime fills, and forbids the plugin from being the wallet.
**[grounded — agent-plugins.org/specification]**

```
Agent Plugins ─┐
MCP ───────────┤
REST ──────────┤ adapters (thin)
Native SDK ────┤
CLI / IPC ─────┘
        ▼
  Mandamus Agent Wallet Runtime   ← identity · authority · policy · receipts · presentation
        ▼
  Key Broker  (MAWP-1/2/3)        ← the security boundary: the LLM never sees private keys
        ▼
  EU Wallet / Secure Enclave / KMS-HSM-TEE
```

---

## 1. What already exists (the runtime is largely built) [grounded]

The delegation **engine** is shipped and formally gated — the hard part is done:

- **Mandate credential**: power-of-representation SD-JWT VC, `vct = urn:eudi:mandate:1`, agent key in
  `cnf`, selectively-disclosed `scope`/`powers`/`mandator` ([`docs/delegation/mandate-schema.md`](mandate-schema.md)).
- **Issuer-side gate (Lean-proved)**: VCIssuer's `authorize_kernel` / `may_issue` monotonic-narrowing
  power-of-representation gate, mirrored + proved in `EudiIssuer/Model.lean` (D2/D3).
- **Wallet-side engine**: [`crates/wallet-core/src/delegation.rs`](../../crates/wallet-core/src/delegation.rs)
  — `parse_mandate`, `plan_delegated_presentation`, `select_delegated_presentation`, `DelegationPlan`
  (`is_bound_to` agent key, `covers(required)` narrowing check), `DelegatedPresentation` +
  `DelegationConsent`. And [`crates/wallet-core/src/agent.rs`](../../crates/wallet-core/src/agent.rs)
  — `AgentSession<S: AttestedSigner>::act(...)` (the **exercise primitive** → a `Receipt`),
  `ReceiptLog` (hash-chained, `head()` + `verify()`), `AgentUnitAttestation`, `AssuranceTier`,
  `KeyProtection`, `HappEvidence`. Exercised end-to-end by
  [`e2e_delegation.rs`](../../crates/wallet-core/tests/e2e_delegation.rs).
- **Control-plane seam**: Mandamus tiers T0–T3 + receipts; our integration point is
  `POST /v1/doorkeeper/eudi-wallet`.
- **Custody profiles**: MAWP-1/2/3 are specified (mobile / hosted / brokered-local).

**The gap (precise).** The delegation FFI surface is **read-only**: the only export is
`agent_mandates_json()` ([`crates/wallet-core/src/lib.rs:7246`](../../crates/wallet-core/src/lib.rs)).
`AgentSession::act`, `plan_delegated_presentation`, receipts, and revoke are **not** exposed over
uniffi/FFI, so no shell — and therefore no MCP server or plugin — can *exercise* a mandate yet. That
is the real work, and every adapter (Agent Plugins included) depends on it.

---

## 2. The stable surface: intent-level operations, not crypto primitives [proposed]

The runtime must expose **intents**, not `sign()/present()/verify()`. Intents keep the cryptography
behind a stable API and let the implementation evolve (e.g. swap the PQ scheme) without breaking
callers. The canonical surface:

```
identity()                      → the agent's DID / key thumbprint / runtime class (MAWP profile)
capabilities(context?)          → what this agent may do right now (mandates ∩ policy), read-only
credentials.list()              → delegated credentials held (never keys), read-only
authority.check(intent)         → would this be permitted? (dry-run the policy; no side effect)
execute(intent)                 → run an action within policy → ActionReceipt | Denied | StepUpRequired
present(request)                → produce a (mandate-narrowed) presentation for a verifier
requestAuthority(intent)        → ask the human/org for a (new/broader) mandate  → pairing/step-up
stepUp(intent)                  → escalate a denied intent to the delegator for one-time approval
delegate(sub_intent)            → sub-delegate a narrowed slice to another agent (monotonic)
revoke(mandateId)               → relinquish / revoke a mandate this agent holds
receipts.list() / verify()      → the hash-chained audit log (ReceiptLog) + verification
```

Split by privilege at the adapter boundary:

- **Information** (`identity`, `capabilities`, `credentials.list`, `authority.check`, `receipts.*`) —
  routine, no key use.
- **Privileged** (`execute`, `present`, `requestAuthority`, `stepUp`, `delegate`, `revoke`) — pass
  through the **policy-enforcing runtime + key broker**. `execute({purchase, €438})` is decided by
  Mandamus, **never by the model**. This is the property worth protecting, and it is exactly the
  shipped narrowing gate (`DelegationPlan::covers` + the Lean-proved kernel).

Each intent maps onto existing engine calls: `execute` → `AgentSession::act` + `ReceiptLog`;
`present` → `plan_delegated_presentation` / `select_delegated_presentation`; `capabilities` →
`agent_mandates_json` + `DelegationPlan`; `receipts` → `ReceiptLog`.

---

## 3. Adapters (thin) [proposed]

| Adapter | Role | Notes |
|---|---|---|
| **MCP server** | primary programmatic surface | one MCP tool per intent; privileged tools call the runtime broker |
| **Agent Plugin** | distribution/packaging | `skills/` (request-authority, prove-authority, step-up, show-receipts) + `mcp.json` pointing at the MCP server. Zero security logic. |
| **REST** | server-to-server / hosted agents (MAWP-2) | same intents over HTTP to the hosted runtime |
| **Native SDK** | in-app (MAWP-1) | Swift/Kotlin binding straight onto the uniffi exports |
| **Local IPC** | terminal/native agents (MAWP-3) | `mandamusd` Unix-socket/XPC; processes get short-lived session capabilities |

All five call the **same runtime**. The Agent Plugin is one row, not the product.

---

## 4. TestAgent — the client side (answering "can we make TestAgent implement the client side?")

**Yes.** There is no `TestAgent` today (only `ios/TestWallet`, a display-only holder), so this is a
new, small harness whose job is to be an **Agent-Plugins-compatible client/host**:

1. Load a plugin package (a directory with `skills/*/SKILL.md` + `mcp.json`) — the v1 format.
2. Launch/connect the declared **MCP server** (the Mandamus adapter).
3. Expose the skills to a model loop and let it call the intent tools.
4. Drive the demo: pair with the EU Wallet, receive a mandate, `execute`, hit a policy denial, request
   step-up, inspect a receipt.

**What's buildable now vs blocked:**
- **Now (read-only):** the client can install the plugin, connect to the MCP server, and call
  `identity()` / `capabilities()` / `credentials.list()` / `receipts.list()` — these map onto the
  existing read FFI (`agent_mandates_json`) + the parsed mandate.
- **Blocked on P1 (below):** `execute` / `present` / `delegate` / `revoke` / `stepUp` need the
  exercise FFI exports first. Until then the client can *display* authority and *dry-run*
  `authority.check`, but cannot perform a signed action.

Form factor: a small Rust or TypeScript CLI is the cheapest honest "arbitrary agent" (installs the
plugin, speaks MCP). It is deliberately **not** the wallet — it holds no keys; it talks to the runtime.

---

## 5. Phased plan

**P0 — Runtime API shape + read-only MCP + TestAgent skeleton** *(days)*
- Define the intent structs (`Intent`, `Decision = Permitted | Denied{reason} | StepUpRequired`,
  `ActionReceipt`) as the stable contract.
- Export the **read** intents over uniffi (`identity`, `capabilities`, `credentials.list`,
  `authority.check` dry-run, `receipts.list`).
- Ship a minimal **MCP server** (the Mandamus adapter) exposing those read tools.
- Ship the **TestAgent** client: installs a plugin dir, connects MCP, lists identity/capabilities.
- *Accept:* TestAgent installs the plugin and prints the agent's identity + current capabilities from
  a real held mandate. No key use yet.

**P1 — The exercise FFI (the real work)** *(the bulk of the effort)*
- Export `execute` (→ `AgentSession::act` + `ReceiptLog`), `present` (→ `plan_delegated_presentation`),
  `delegate` (monotonic narrowing), `revoke`, `stepUp` over uniffi — the privileged intents.
- Route every privileged intent through the **policy gate** (`DelegationPlan::covers` + the
  Lean-proved kernel) inside the runtime — the model's request is *evidence*, never the decision.
- WYSIWYS binding on `execute`/`present` (reuse the operationId + authorizationHash pattern).
- *Accept:* an `execute` within scope yields a signed `ActionReceipt`; an out-of-scope `execute` is
  `Denied` with the mandate delta; `receipts.verify()` validates the chain. All in `e2e_*` tests.

**P2 — Agent Plugin package + privileged MCP + TestAgent end-to-end** *(days)*
- Author the plugin: `skills/{request-authority,prove-authority,request-step-up,show-receipts}` +
  `mcp.json`.
- Expose the privileged intents as MCP tools (broker-gated).
- TestAgent drives the full loop against a real agent key (MAWP-3 brokered-local first).
- *Accept:* install → pair → delegate → act → exceed → deny → step-up → receipt, end to end.

**P3 — Custody + attestation per MAWP** *(parallelizable)*
- MAWP-1 Secure Enclave + App Attest (mobile); MAWP-2 KMS/HSM/TEE (hosted/web); MAWP-3 `mandamusd`
  local daemon + short-lived session capabilities (terminal).
- Bind the agent key's *location* as evidence (TPM/SE/TEE attestation) into the mandate context.

**P4 — Standardization (optional, larger bet)**
- Propose a **portable Agent Wallet interface** to the MCP/Agent-Plugins ecosystem — the gap the specs
  leave open. Prototype as the Mandamus MCP surface first; only then propose. **[proposed]**

---

## 6. The demo (P2 acceptance, one narrative)

```
Install plugin: mandamus          → "No agent identity exists. Create one?"
Agent provisions itself           → did:mandamus:7f92…  (non-exportable key, MAWP-3)
Pair with EU Wallet (QR)          → phone shows the exact agent + requested scope + limit + duration
Face ID → Delegate                → mandate bound to the agent key (cnf), narrowed
"Book a flight to Berlin…"        → execute(travel.booking) within €1,000 → ActionReceipt
"Also buy a €2,000 laptop"        → Denied: outside delegated authority (purchase €2,000 > travel ≤ €1,000)
"Request authority from Johan?"   → step-up on the phone → one-time approval or refusal
Inspect receipt                   → receipts.verify() over the hash chain
```

Communicates the whole system — *identity, delegated authority, policy enforcement below the model,
verifiable receipts* — in about 30 seconds, inside an existing agent client rather than a bespoke demo.

---

## 7. Risks / open questions

- **Key custody is the boundary** (MAWP): the LLM/plugin logic sits *above* the key broker; keys never
  cross into model context. Web agents (MAWP-2) especially must NOT hold reusable keys/VCs in
  browser-accessible storage.
- **Model ≠ agent**: bind the mandate to the agent installation + holder key, not the model provider;
  swapping models must not require reissuing the mandate. **[proposed]**
- **PQ note (carried from the mdoc work):** an ML-DSA public key that travels in an unauthenticated
  header is anti-downgrade, not issuer-authenticating — any PQ authority evidence must bind the PQ key
  to the delegator. See [[dc-api-and-dual-format-status]].
- **Standardization ambition (P4)** is a large, separate commitment — prototype the interface before
  proposing it.
