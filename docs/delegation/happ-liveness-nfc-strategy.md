# HAPP liveness & NFC — client strategy (ADR)

**Status:** recommended · **Date:** 2026-08-03 · **Scope:** where iProov liveness (HAPP) and NFC
eID reading run across the EU Wallet, App Clips, and the web.

## Decision

1. **HAPP liveness → native iProov SDK inside the EU Wallet (primary).** Do the human step-up
   in-app on iOS and Android via the native iProov SDK, not the Web SDK.
2. **A liveness App Clip (iOS) is worthwhile only for the no-install, first-contact moment** —
   onboarding, or a relying party asking a person who has no wallet yet to prove liveness. It is
   **not** the agent-approval path.
3. **No NFC App Clip.** German eID / NFC stays in the full app.
4. **Web iProov SDK stays as a fallback** for browser-only relying-party flows and enrolment where
   no native app is present.

## Why native iProov in the wallet (not the Web SDK) for HAPP

HAPP is the human approving a consequential *agent* action (a T2+ power like a payment — see
`wallet_core::agent::AssuranceTier`). The wallet is already where the human, the Secure-Enclave
keys, the "My Agents" delegation surface, and the **approval-before-signing** gate live. A native
step-up therefore:

- gives the best capture UX (camera, no browser hop, accessibility, offline-tolerant handoff);
- lets the iProov assurance result bind **directly** into the OpenID4VP authorization and the HAPP
  receipt, rather than round-tripping through a browser token; and
- flows end-to-end with what already shipped:

  `native iProov result → HappEvidence { fresh, tier } (wallet_core::agent, gates T2+ actions)`
  `→ happ_fresh signal → Mandamus POST /v1/doorkeeper/eudi-wallet → gate → hash-chained receipt.`

The Web SDK cannot bind into the Secure Enclave / device-bound key path as tightly, so it is a
fallback, not the wallet default.

**Assurance mapping:** iProov's assurance (liveness vs Genuine Presence / authenticated) maps onto
the WAUTH tiers T0–T3. The tier can *raise* the approval bar for a power but can **never widen the
delegated scope** — the scope gate is independent (proved on both issuer and verifier stacks).

## App Clips — where they help, where they don't

App Clips / Instant Apps exist for a **fast, no-install, on-demand** moment (scan a code → do one
thing → optionally install later).

- **Liveness App Clip (iOS): yes, phase 2.** A user without the wallet can prove liveness on the
  spot (RP-initiated, or onboarding). The iProov native SDK fits comfortably within the iOS App
  Clip budget (≈15 MB), and liveness is a single self-contained task — an ideal clip. Gate it to
  first-contact; once the wallet is installed, HAPP runs in the full app.
- **NFC eID App Clip: no.** The German eID journey needs the **AusweisApp2 SDK** plus PACE / PIN /
  CAN / transport-PIN / blocked-PIN handling — too large for the App Clip size budget, and it is a
  genuinely multi-screen full-app journey (the consumer-UX work already treats "Do you know your
  PIN?", transport-PIN, CAN and blocked-PIN as first-class states). Keep NFC in the full app; for a
  no-install NFC moment use a **universal link** that deep-links into the app or prompts install.
- **Android:** Google has de-emphasised Instant Apps; do **not** invest in an Android liveness
  Instant App. Use the full app + App Links / deep links. So the App Clip strategy is iOS-leaning
  and optional.

## Rollout

| Phase | Client work |
|---|---|
| 1 (now) | Integrate the **native iProov SDK** in the iOS and Android wallets; wire its result into the "My Agents" approval-before-signing gate → `HappEvidence` → the Mandamus `happ_fresh` signal. Keep NFC eID in the full app (already there via the AusweisApp adapter). |
| 2 | Optional **iOS liveness App Clip** for no-install/RP-initiated first contact. |
| — | Web iProov SDK: browser-only RP fallback. **No** NFC App Clip, **no** Android Instant App. |

## Open items

- Confirm the iProov native SDK's assurance token format and how it seals into the OpenID4VP
  `consent_hash` / authorization binding (WYSIWYS).
- Licence/entitlement review for camera + App Clip; App Clip must not silently collect biometrics
  beyond the single liveness task.
