# Agent-wallet custody profiles (MAWP) — where the key and the mandate live

**Status:** design reference · **Date:** 2026-08-06 · **Scope:** how a Mandamus agent's
holder key and mandate credential are custodied across runtimes (mobile, web, laptop/native,
terminal, cloud), behind one authority abstraction.

Companion to [`agent-delegation-design.md`](agent-delegation-design.md) (the cross-repo delegation
model) and [`mandate-schema.md`](mandate-schema.md) (the `urn:eudi:mandate:1` claim model). Where
that brief answers *what a mandate is and how it is issued/narrowed*, this one answers *where the
sensitive material physically lives per runtime and what authority ceiling each runtime earns*.

Claims are **[grounded]** (read from this repo or a cited spec) or **[proposed]** (design/inference).

> **How this maps to shipped code.** Delegation is already implemented in `EUWallet`: the mandate
> SD-JWT VC (`vct: urn:eudi:mandate:1`), the Lean-proved narrowing gate, and
> [`crates/wallet-core/src/delegation.rs`](../../crates/wallet-core/src/delegation.rs) +
> [`crates/wallet-core/src/agent.rs`](../../crates/wallet-core/src/agent.rs) (exercised by
> [`e2e_delegation.rs`](../../crates/wallet-core/tests/e2e_delegation.rs)). The wallet is the
> **holder/creator** of delegations; Mandamus is the **authority plane**. The profiles below are the
> custody design for the *agent side* of that seam (`POST /v1/doorkeeper/eudi-wallet`), not yet
> wired end-to-end. **[grounded / proposed]**

---

## 0. The custody principle

The crucial distinction is between **where the mandate VC is stored** and **where the holder key
that can *exercise* it is stored**. **[grounded]**

A VC is a signed data object. The sensitive asset is the **private key** referenced by its
holder-binding claim (e.g. `cnf.jkt`). Whoever controls that key can exercise the mandate — so the
VC and the key need not, and often should not, live in the same place. Each agent runtime gets three
logical things:

```text
Agent identity key   +   Agent Mandate VC   +   Mandamus capability record
```

…but their custody differs by runtime, behind one `MandamusAuthority` interface (§4).

---

## 1. Mobile native app agents (MAWP-1)

Examples: an in-wallet assistant, a health/banking/travel app, a third-party iOS app integrated with
EUWallet.

**Key.** Device-bound, generated in the **Secure Enclave** where supported; Keychain holds encrypted
metadata/state; **App Attest** proves the request came from a legitimate app instance. The private
key stays hardware-protected rather than exported into app memory. **[grounded — Apple SE / App
Attest, see refs]**

```text
iPhone
┌────────────────────────────┐
│ Mobile agent app           │
│   VC metadata / database   │
│            │               │
│            ▼               │
│         Keychain           │
│            │               │
│            ▼               │
│  Secure Enclave private key│
└────────────────────────────┘
```

**VC.** Hybrid: the encrypted mandate VC + agent key + cached status + recent receipts live locally;
Mandamus remains authoritative for the registry, an encrypted backup/canonical copy, revocation,
usage counters, policy, and the receipt chain.

**Delegation handoff (same device).**

```text
Agent app creates key → registers key with Mandamus → opens EUWallet delegation request
→ user reviews & approves → Mandamus issuer binds the mandate to the agent key
→ agent app receives the encrypted mandate
```

Transports: app-to-app universal link, QR, OpenID4VCI credential offer, or an EUWallet system
handoff. OpenID4VCI defines the *issuance* protocol (and supports SD-JWT VC and mdoc) but does not
prescribe storage. **[grounded — OpenID4VCI, see refs]**

**Ceiling.** Highest — device-bound key + attestation + biometrics + secure local UI + direct wallet
handoff. Target **T2**, later **T3**.

---

## 2. Web app agents (MAWP-2)

Examples: an agent on `jeevesy.com`, a browser assistant, a Lovable web app, a third-party SaaS
agent.

> A normal web page should **not** store an exportable mandate key or a reusable mandate VC in
> JavaScript-accessible browser storage. **[proposed]**

Keep mandate credentials / bearer tokens **out of** `localStorage`, JS-readable cookies, IndexedDB
without a broker boundary, frontend state, and service-worker caches.

**Preferred architecture: a server-side Mandamus wallet.** The browser is the *interaction surface*,
not the credential holder.

```text
Browser (UI / conversation — no mandate key, no reusable raw VC)
        │  authenticated session
        ▼
Web application backend
        ▼
Mandamus Agent Vault
   ├─ encrypted mandate VC
   ├─ agent key in KMS / HSM / TEE (backend can request signatures, cannot export the key)
   └─ policy + counters
```

The web app holds only an opaque reference:

```json
{ "mandate_ref": "mdm_01K…", "capabilities": ["read_calendar", "propose_booking"],
  "expires_at": "2026-08-06T14:00:00Z" }
```

**WebAuthn / passkeys** authenticate the *human* operating the app (scoped to a relying-party origin,
stored by an authenticator) — they are not the agent's portable mandate holder key. **[grounded —
WebAuthn L2, see refs]** Use passkeys for human login / approval / reconnect-or-revoke; use the
Mandamus workload key for mandate proof-of-possession, action-envelope signing, and
sender-constrained API tokens.

The user must see the exact entity receiving the mandate (application, domain, operator, runtime,
session lifetime) — bind the mandate to the **registered server-side agent key**, and separately bind
the browser session to that agent. Do **not** bind a mandate to a browser cookie.

**Browser-only agents.** A truly browser-only agent may use WebCrypto (non-exportable key) +
IndexedDB, but this is lower-assurance and fragile (data deletion, origin changes, XSS invoking the
key, hard migration/recovery, limited attestation). Permit only for low-risk **T0/T1**; label it an
**Ephemeral Browser Agent**, not a wallet.

**Ceiling.** **T1–T2** by assurance.

---

## 3. Laptop / native-app and terminal agents (MAWP-3)

Examples: a terminal coding agent, a Rust CLI, a native macOS app, a local autonomous process, an MCP
server, a background launch agent.

These should **not** each implement their own wallet. Run one **Mandamus local daemon** (`mandamusd`)
per user/device that owns credentials and brokers access.

```text
Mac
┌─────────────────────────────────────────┐
│ CLI ─────────┐                           │
│ coding agent ┤                           │
│ native app ──┤  Unix socket / XPC        │
│ MCP server ──┤                           │
│ local agent ─┘                           │
│              ▼                            │
│          mandamusd                        │
│   ┌───────────────────────┐               │
│   │ credential vault      │               │
│   │ policy engine         │               │
│   │ approval router       │               │
│   │ receipt recorder      │               │
│   └──────────┬────────────┘               │
│              ▼                            │
│      Keychain / Secure Enclave            │
└─────────────────────────────────────────┘
```

**Key.** Secure Enclave where the algorithm/access pattern allows; Keychain-backed otherwise;
TPM/KMS-equivalent on other platforms; a separate key per installation / logical agent. **Never**
store keys in `~/.config/agent/private-key.pem`, `.env`, shell env vars, Git repos, or MCP config
files.

**VC.** `mandamusd` keeps encrypted VCs in a local vault (e.g.
`~/Library/Application Support/Mandamus/`) under a Keychain-managed root key; the decryption key stays
in Keychain / the Secure Enclave.

**Interaction.** The CLI talks to `mandamusd`, never directly to the VC:

```bash
mandamus capabilities list
mandamus propose --action calendar.create --input event.json
mandamus execute --plan plan_01K…
```

…or over MCP (`mandamus.list_capabilities`, `mandamus.propose_action`, `mandamus.execute_plan`,
`mandamus.request_approval`, `mandamus.get_receipt`). The daemon identifies the caller from a
combination of Unix user, executable identity / code signature, registered installation, local
socket credential, per-agent client key, optional runtime attestation, and process ancestry — **not**
the binary name alone (e.g. not just `codex`).

**Native app vs terminal process.** A signed native app can own its Secure Enclave key + vault. A
terminal process is hard to identify reliably (scripts/subprocesses churn), so it should receive a
**short-lived session capability** from `mandamusd` rather than own a long-lived VC:

```text
long-lived mandate VC (held by mandamusd)
        ▼
short-lived session capability (issued to the process)
        ▼
one or more bounded actions
```

This gives control over restarts, differing repos/shells/sessions, compromised plugins, revocation,
and per-project scope.

**Ceiling.** Native app **T2**; terminal agent **T0–T2**, policy-dependent.

---

## 4. The unifying custody matrix

| Agent type | Holder key | VC storage | Agent receives | Ceiling |
|---|---|---|---|---|
| Mobile native app | Secure Enclave / app key | Encrypted local vault + Mandamus registry | Local capability API | T2; later T3 |
| Web app + backend | KMS / HSM / TEE key | Mandamus cloud vault | Opaque mandate reference | T1–T2 by assurance |
| Browser-only agent | WebCrypto / WebAuthn-adjacent local key | IndexedDB or remote encrypted vault | Local browser capability | T0–T1 |
| Native laptop app | Secure Enclave / Keychain key | Local Mandamus vault | Local capability API | T2 |
| Terminal agent | `mandamusd` key; session key per process | Local daemon vault | Short-lived session capability | T0–T2, policy-dependent |
| Cloud autonomous agent | KMS / TEE workload key | Mandamus cloud vault | Workload capability | T0–T2 |
| Third-party model API | No credential key | Mandamus only | Tool calls / proposals | Set by the doorkeeper |

---

## 5. Do not conflate "the agent" with "the model"

Model and agent-holder stay separate in every runtime:

```text
Model            → produces proposed intentions + parameters
Agent runtime    → maintains conversation, tools, execution context
Mandamus wallet  → holds or resolves authority
Mandamus PDP     → decides whether an action is permitted
Executor         → performs the external side effect
```

One model (e.g. a hosted LLM) may back a mobile, a web, and a terminal Jeevesy — **three** agent
installations with three keys and potentially three mandates. Bind the mandate to the agent, not the
model:

```json
{ "agent_id": "urn:mandamus:agent:jeevesy", "installation_id": "install_01K…",
  "holder_key": "key_01K…", "runtime_class": "mobile_native", "operator": "Advatar Systems AB" }
```

Record the model as runtime metadata, not the credential subject:

```json
{ "model_provider": "…", "model": "…", "model_role": "reasoning_component" }
```

Swapping models should not force reissuing the mandate; changing the holder key, operator, or
execution environment should. **[proposed]**

---

## 6. One authority, three profiles

- **MAWP-1 Device Agent Wallet** — mobile / signed native: device-bound key, local encrypted VC,
  attested app, local policy enforcement, remote revocation/status.
- **MAWP-2 Hosted Agent Wallet** — web / cloud: KMS/TEE key, Mandamus-hosted VC, workload identity,
  server-side policy; browser is only the control UI.
- **MAWP-3 Brokered Local Agent Wallet** — terminal / local automation: `mandamusd` owns the
  long-lived mandate, processes get short-lived capabilities over a Unix socket/XPC, project/session
  policy, receipts synced to Mandamus.

All three implement the same logical API **[proposed]**:

```typescript
interface MandamusAuthority {
  registerAgent(input: AgentRegistration): Promise<AgentIdentity>;
  acceptMandate(offer: CredentialOffer): Promise<MandateReference>;
  listCapabilities(context?: Context): Promise<Capability[]>;
  proposeAction(action: ActionEnvelope): Promise<Decision>;
  executePlan(planId: string): Promise<ActionReceipt>;
  presentMandate(request: PresentationRequest): Promise<PresentationResult>;
  revokeOrRelinquish(mandateId: string): Promise<void>;
}
```

OpenID4VCI handles issuance and OpenID4VP handles presentation; the Mandamus profiles define custody,
runtime binding, local invocation, and execution — the parts those specs deliberately leave to the
platform. **[grounded — OpenID4VP/VCI, see refs]**

---

## 7. Concrete recommendation

Build around **Mandamus-hosted canonical authority** with **device-local exercise**:

```text
Mandamus (canonical)                 Device / workload (local)
  mandate record                       private holder key
  status + revocation                  encrypted VC or mandate reference
  policy                               local policy cache
  holder-key registration              short-lived tokens
  counters + receipts
  encrypted recovery copy (where allowed)
```

Defaults:

- **Mobile app** — local key + local VC, registered with Mandamus.
- **Web app** — server-side key + VC in Mandamus; nothing reusable in browser JavaScript.
- **Laptop native app** — local key + VC via `mandamusd` or an app-specific vault.
- **Terminal agent** — no long-lived VC; `mandamusd` holds it and delegates a short-lived session
  capability.

This gives portability without pretending every runtime is equally trustworthy, and makes Mandamus
the coherent authorization substrate across environments rather than merely a post-presentation
doorkeeper.

---

## References

- Apple — *Protecting keys with the Secure Enclave*:
  <https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave>
- Apple — *App Attest / DeviceCheck* (attesting a legitimate app instance).
- OpenID4VCI 1.0 — *OpenID for Verifiable Credential Issuance* (issuance protocol; SD-JWT VC + mdoc
  formats): <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html>
- OpenID4VP 1.0 — *OpenID for Verifiable Presentations* (presentation protocol; platform transport
  left to the platform).
- W3C — *Web Authentication Level 2 (WebAuthn)*: <https://www.w3.org/TR/webauthn-2/>
