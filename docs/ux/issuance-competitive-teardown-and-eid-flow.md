# Issuance teardown + German eID-NFC activation spec

**Date:** 2026-07-22 · **Status:** research-grounded deep-dive (no code changes) · Companion to
`docs/ux/issuance-first-proposal.md`.

Claims are marked **[verified]** (cited source) or **[inferred]** (reconstruction/synthesis — treat as a
design hypothesis, not observed fact). Screen sequences for the platform wallets are reconstructed from
public vendor docs, help pages, and press material; exact pixels/labels vary by OS version and issuer.

---

# Part 1 — Screen-by-screen issuance teardowns

## 1.1 Apple Wallet — adding a state ID / driver's licence and Digital ID

| # | Screen / step | What the user sees & does | Trust / friction mechanic |
|---|---|---|---|
| 1 | Wallet home | Tap the **`+`** (top-right), choose **Driver's License or ID** (or **Digital ID** from passport) | One consistent entry point; "add" is a system moment **[verified]** |
| 2 | Select issuer | Pick **state** (ID) or confirm **passport** (Digital ID) | Issuer is named up front — trust is anchored in the authority **[verified]** |
| 3 | Capture | **Scan front & back** of the physical card; for Digital ID, **tap the passport** so the iPhone reads the **NFC chip** on the photo page | Chip-read proves document authenticity; camera auto-guides **[verified]** |
| 4 | Liveness | **Selfie** + a guided series of **facial and head movements** | Anti-spoof liveness; framed as "simple verification steps" **[verified]** |
| 5 | Submit | Data "securely provided to the issuing state/authority for verification"; screen shows **pending** | Vendor does *not* verify — the state does; sets async expectation **[verified]** |
| 6 | Approved | Push notification → the ID card appears in Wallet | Completion is celebrated, not silent **[verified]** |
| — | Present | Hold near reader → **"Information Requested"** review → **double-click side button + Face ID** | Payment mental model; "no need to unlock or hand over your phone" **[verified]** |

**Lessons to steal:** protocol is 100% invisible; issuer is the trust anchor; async approval is explicit;
present == pay. **Device-binding pitfall:** the ID is bound to one iPhone/Watch and does **not** auto-transfer
— moving phones needs removal + full re-verification. **[verified]**

## 1.2 Google Wallet — ID pass

| # | Step | User action | Notes |
|---|---|---|---|
| 1 | Add | "Add your eligible driver's license or state ID", or **create an ID pass from your passport** | Passport path = universal fallback, no state rollout needed **[verified]** |
| 2 | Scan | Scan the physical licence (front/back) | — |
| 3 | Verify | Follow **state verification steps** (selfie/liveness) | Issuer-side approval **[verified]** |
| 4 | Present online | Apps/web request **proof of identity or age** via the Digital Credentials API, with **ZKP** so "there is no way to link the age back to your identity" (partners incl. Bumble, Uber, CVS) | Online presentation already migrating to the platform picker + ZKP **[verified]** |

**Lesson:** the age-proof-without-identity use case is the strongest consumer hook, and it's already the
platform default surface for *online* presentation. **[verified]**

## 1.3 Samsung Wallet — Digital ID

Open Wallet → **Quick access** tab → **`+`** → **Digital IDs** → **scan front/back** → **face-scan
verification** → **Submit** → authenticate with **fingerprint/PIN**. Lives in a gesture-reachable Quick
access tab. **[verified]**

**Lesson:** lock-screen / quick-access placement lowers the cost of the *present* moment; the *add* flow is
the same 4-verb pattern.

## 1.4 Italy IT-Wallet — the only mass EUDI-style consumer deployment

| # | Step | User action | Reality |
|---|---|---|---|
| 1 | No new app | Open the **pre-installed government "IO" app** | Bootstrapped off an app 30M+ already had — a huge cold-start advantage **[verified]** |
| 2 | Activate | Enable **"Documenti su IO"**; **log in with SPID or CIE**, then **re-authenticate** to bind documents to identity | Rides existing eID logins instead of a new wallet identity **[verified]** |
| 3 | Documents load | Driving licence, health card, EU disability card appear — **asynchronously**; driving licence may be delayed with a **notification when ready** | 10M+ activations, 17.3M documents — but only 3 document types **[verified]** |

**Failure modes observed (this is the cautionary tale):** documents not appearing despite a successful
login (auth mismatch / stale app); driving-licence delays at peak load; and the mental-model confusion that
the **CIE card is used to log in but is not itself stored** ("la CIE serve per accedere a IO, non per essere
memorizzata dentro IO"). **[verified]** → **Our flow must name the async state, notify on completion, provide
a "didn't appear?" recovery, and explicitly separate "the ID you log in with" from "the credential stored."**

## 1.5 EUDI reference wallet — the anti-pattern to replace

Welcome → **create a PIN** → add PID via **Documents → `+` → "From list" → "PID"** (a form) **or** **scan an
issuer QR credential offer**. Presentation is a **bare attribute checklist** ("select/deselect attributes…
at least one to proceed"). The store listing says it is "intended only for evaluators, integrators, and
developers … using sandbox identity data." **[verified]**

**Every one of these is developer scaffolding leaking the protocol** — "from a list", "PID", "issuer QR",
raw attribute toggles. This is exactly what the consumer redesign must remove.

## 1.6 Cross-cutting scorecard

| Dimension | Platform wallets | IT-Wallet | EUDI reference | Target for us |
|---|---|---|---|---|
| Protocol visible? | No | No | **Yes** (bad) | **No** |
| Issuer as trust anchor | Yes | Yes | Weak | **Yes, prominent** |
| Async issuance handled | Yes | Partly (delays) | No | **Yes, explicit + push** |
| Empty-wallet solved | Yes (passport ID) | Yes (IO app base) | No | **Yes (PID as base)** |
| Consent quality | Legible, minimal | n/a | Attribute checklist | **WHO/WHAT/WHY + "not shared"** |
| Present == pay | Yes | n/a | No | **Yes where DC-API/proximity allow** |

---

# Part 2 — German eID-NFC PID activation flow spec

**Why this gets its own spec:** Germany is staking PID issuance on the **national eID card over NFC** via a
wrapper around the **Ausweis SDK** (SPRIND "Funke" prototypes); the BMDS/Bundesdruckerei state wallet targets
"80 million potential users at Level of Assurance High" (~early 2027). The **card-tap + PIN step is the single
highest-risk UX moment** — historically low German eID usage, forgotten 6-digit PINs, and NFC-positioning
failures can strangle onboarding. **[verified]** Everything below is a design hypothesis grounded in that
context plus the KYC/passkey drop-off evidence; it is **[inferred]** unless marked otherwise.

## 2.1 Design constraints

- The eID PIN and card data are entered/handled **outside** our sans-IO core (Ausweis SDK / OS NFC); the wallet
  never sees the PIN. **[verified — architecture]**
- Keep the whole authorization under **~3 minutes**, mobile-first, with inline validation before submission
  (KYC: 70% abandon > 3 min; a re-upload/redo triples abandonment). **[verified]**
- Trigger this flow at a **moment of value/success**, never from a cold Settings menu. **[verified]**
- Every failure must be **named and one-tap recoverable**, never a dead end. **[verified]**

## 2.2 Screen sequence

| # | Screen | Purpose | Key copy (jargon-free) | Notes |
|---|---|---|---|---|
| 0 | **Value intro** | Say what PID unlocks before any friction | "Add your national ID to prove who you are online — in seconds, without paperwork." | Progressive disclosure; no protocol terms |
| 1 | **What you'll need** | Set expectations for the hard step | "You'll need your ID card and its 6-digit PIN. Have the card ready to tap." | Prevents mid-flow drop when the card isn't at hand |
| 2 | **PIN status check** | Fork on PIN state early | If PIN unknown/blocked → route to **PIN help** (2.4) *before* the tap | Do not let a forgotten PIN surface only after a failed tap |
| 3 | **Consent-to-issue** | Show what will be written & the authority | "[Issuing Authority] will add: name, date of birth, nationality… Continue?" | Issuer named + logo; the "what's being added and why" list |
| 4 | **NFC positioning** | The make-or-break moment | Animated diagram of card placement per device; "Hold the top of your phone against the card and keep still." | Live "reading… keep still" progress; device-specific antenna hint |
| 5 | **PIN entry** | Ausweis SDK / OS sheet | System-provided secure PIN entry | Wallet never sees the PIN; show remaining attempts |
| 6 | **Reading** | Feedback during chip read | Progress ring + "Reading your ID… keep the card still." | If the card slips: "Lost connection — reposition and hold still" (auto-resume, not restart) |
| 7 | **Submitting** | Hand-off to issuer | "Sending to [Authority] for approval…" | Sets async expectation |
| 8a | **Ready (sync)** | Fast path | "Your ID is in your wallet." → **what you can DO now** + next credential | Retention hook |
| 8b | **Preparing (async)** | Deferred path | "We're preparing your ID — we'll notify you." + push on completion | Never a silent spinner; add a "check status" affordance |
| 9 | **Success / first use** | Convert to active wallet | "Try it: prove your age without sharing your birth date." | Ties issuance to a named acceptance anchor |

## 2.3 State model (for implementation planning)

```
Intro → NeedsInfo → PinPreflight
  ├─ PinOk       → ConsentToIssue → NfcPositioning → PinEntry → Reading → Submitting
  │                                     │                          │
  │                                     └─ NfcLost ⇄ NfcPositioning └─ PinWrong ⇄ PinEntry (attempts--)
  └─ PinBlocked/PinUnknown → PinHelp (2.4) ──────────────────────────────────────────┐
Submitting → IssuedSync (8a)                                                          │
Submitting → IssuedAsyncPending (8b) → [push] → IssuedComplete (9)                    │
any → Recoverable{reason} → (retry same step)                                         │
PinHelp → (resume at ConsentToIssue) ─────────────────────────────────────────────────┘
```

## 2.4 PIN help sub-flow (must exist, not a dead end)

- **Forgotten PIN:** explain the transport-PIN → self-set-PIN distinction (a known German eID stumbling block),
  and link the official PIN-reset (PIN-Rücksetzbrief / branch/PIN-reset service). **[inferred + domain]**
- **Blocked PIN (after failed attempts):** explain the CAN (Card Access Number) and the 3-attempt lockout path;
  offer to resume issuance after reset. **[inferred + domain]**
- Always offer **"remind me / do this later"** and re-offer PID at a calibrated cadence (non-nagging). **[verified pattern]**

## 2.5 Error & recovery states (each named + one-tap recoverable)

| Failure | User-facing message | Recovery |
|---|---|---|
| NFC not positioned / lost | "Couldn't read the card — line up the top of your phone and hold still." | Return to positioning, auto-retry; do **not** restart the flow |
| Wrong PIN | "That PIN didn't match. You have N attempts left." | Re-enter; surface PIN-help link at N=1 |
| PIN blocked | "Your ID card PIN is blocked." | Route to PIN help (2.4); resume after |
| Authority declined | Show the **exact** decline reason from the issuer | One-tap retry or contact path |
| Timeout / connectivity | "Connection dropped — your progress is saved." | Resume from last step |
| Async never completes | "Still preparing — this can take longer at busy times." | Status check + notify; support link |

## 2.6 What to measure (validate the inference)

Instrument drop-off at **each** step, especially NFC positioning (4/6) and PIN (5) — the German state wallet's
real activation drop-off is currently an **inference from historically low eID usage, not measured EUDI data**;
these funnels are the first thing to A/B once the flow ships. **[verified — this is an open question]**

---

## Sources
See `docs/ux/issuance-first-proposal.md` §Sources. Germany-specific: SPRIND Funke / Ausweis SDK
(https://www.sprind.org/en/actions/challenges/eudi-wallet-prototypes); state-wallet timeline / LoA High
(https://www.corbado.com/blog/eudi-wallet-2026-deadline-rollout-eic-2026). IT-Wallet friction:
https://www.miniguide.it/post/app-io-non-funziona/ . Apple Digital ID flow:
https://www.apple.com/newsroom/2025/11/apple-introduces-digital-id-a-new-way-to-create-and-present-an-id-in-apple-wallet/ .
