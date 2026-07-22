# Developer hand-off — Add & Prove wallet UX

**Date:** 2026-07-22 · **For:** the shell/app developer starting build.

## 0. Status — read first

**Can you start now? Yes.** The direction, boundary, journeys, screen inventory, states, and
acceptance criteria are **locked and buildable**. Build the structure now.

**Is it signed off as "final"? Not yet.** One gate remains: **moderated usability testing with people
aged ~65–85** (protocol in `accessibility-validation.md`). That round can only move **on-screen copy and
fine spacing** — it will **not** change the architecture, the flows, the states, or the accessibility
requirements. Therefore:

- **Frozen (build against these):** the wallet-owned boundary, the two journeys and their screen
  inventory, the state/transition model, the error/recovery set, the accessibility acceptance criteria,
  and the "UI ↔ verified data" binding contract (§3).
- **Provisional (don't hard-code painfully):** exact wording and micro-copy, exact spacing/type sizes,
  and any "portrait capture" screen. **Externalise all strings** (see §8) so copy changes after testing
  are a data edit, not a refactor.

## 1. Sources of truth

| Artifact | Path / URL |
|---|---|
| Interactive prototype (clickable) | `LandingPage/public/building/issuance-flow.html` → served at `/building/issuance-flow.html` |
| Proposal & rationale | `docs/ux/issuance-first-proposal.md` |
| Competitive teardown + **German eID/NFC/PIN spec** | `docs/ux/issuance-competitive-teardown-and-eid-flow.md` |
| Accessibility validation + **65–85 test protocol** | `docs/ux/accessibility-validation.md` |
| Shareable PDF (15 pp) | `docs/ux/issuance-flow-mockup.pdf` |
| Commits | EUWallet `8b7d27b` · LandingPage `1ac60f2` |

## 2. The boundary the UI must honor (non-negotiable)

The OS may mediate **selection** (which wallet/document answers a request). The **wallet** owns verifier
authentication, request validation, data-minimisation, understandable consent, explicit approval, secure
response construction, delivery, and recovery.

**In our architecture that means the SwiftUI/Android shell stays THIN:** it renders what the sans-IO core
tells it (`Effect::Render { screen: ScreenDescription }`) and sends user actions back as `Event`s. **No
trust decision, no minimisation, no consent binding, and no signing logic lives in the UI layer.** Keys
live in the Secure Enclave / StrongBox; the core emits `Effect::Sign` and the shell returns
`Event::DeviceSignatureProduced`.

## 3. Binding contract — every UI string is bound to verified core data (must not be weakened)

Visual simplification must never weaken verifier identity, consent integrity, or minimisation. The shell
renders these strings **from** authenticated core output; it must never synthesise them from
caller-supplied text.

| What the person sees | Bound to (from the core, never the shell) |
|---|---|
| "✓ Verified issuer — Bundesdruckerei" | Authenticated certificate path; identity from the leaf cert |
| "weindeals.example · registered verifier" | Verifier authenticated, `client_id` bound to its cert; purpose from its registration |
| "Over 18: Yes" — nothing else | The single selectively-disclosed claim the core placed in the response |
| "Not shared: name, date of birth, address" | The minimised response contents (non-requested attrs never assembled) |
| "…asking for more than it registered for" | The core's RP-registration over-ask check |
| "Approve with Face ID" | `Effect::Sign` → device-key signature over the request nonce |

## 4. Architecture mapping (screens ↔ existing core API)

Screens render from `presenter::ScreenDescription`; buttons dispatch `wallet_core::Event`; the core
returns `Effect`s. **Existing** variants you build on:

- `ScreenDescription::IssuanceOffer` — the Add offer screen (after `Event::CredentialOfferReceived`).
- `ScreenDescription::Consent(ConsentScreen)` — the **Prove** screen (requested claims already minimised).
- `ScreenDescription::Error { code, message }` — recovery screens (codes in §7).
- `ScreenDescription::CredentialList` / `CredentialDetail` — the **wallet home** and the home card.
- `ScreenDescription::AuthPrompt`, `ScanQr`, `PresentQr`, `TransactionHistory` — supporting surfaces.

**New core work these designs require (engineering task, keep it in the core, not the shell):** the rich
issuance sub-flow — *PIN question*, *NFC tap / reading*, *Preparing (async)*, *Ready*, and the home-card
*Needs-attention* state — are **not yet distinct `ScreenDescription` variants**. Add them to
`crates/presenter`, extend `formal/lean/NavigationModel.lean` (the verified navigation model) and its
Swift conformance, and surface issuance progress from the **durable checkpoint** (so Preparing/Ready/
Needs-attention survive app close + reboot). The eID card read is orchestrated via the Ausweis SDK in the
shell feeding the core's OpenID4VCI issuance machine; the PIN is entered in the system/SDK sheet and never
crosses into the core.

## 5. Journey 1 — Add (issuance)

Issuer-first; ordinary verbs; "National ID"/"Digital ID" (never "PID"); no time promises. As few screens
as needed — a confident user goes straight through; an unsure one is helped, never stuck.

| # | Screen | Purpose | Core touchpoint | Key controls |
|---|---|---|---|---|
| 1 | Offer | Named + verified issuer; one-line purpose; optional "What will be added?" | `IssuanceOffer` after `CredentialOfferReceived` | Add · What will be added? · Not now |
| 2 | PIN question | "Do you know your ID card PIN?" — never assumes | new screen | Yes, I know it · I'm not sure |
| — | PIN help | Transport-PIN/CAN/blocked detail lives **here**, not on primary screens | new screen | Continue · How to reset · Back |
| 3 | Tap / reading | Guided NFC, live "Reading… keep still", cancellable + resumable | new screen; Ausweis SDK → issuance machine | Continue(read ok) · It's not reading · Cancel |
| 4 | Confirm | Confirm by **purpose + issuer**, not an attribute checklist | new screen | Confirm · What will be added? |
| 5 | Preparing | Async issuer processing as a **state** + notification; user may leave | new screen; durable checkpoint | Done |
| 6 | Ready | Success → a useful next action | new screen / `CredentialDetail` | Prove your age · Go to Wallet |

## 6. Journey 2 — Prove (consent)

The wallet authenticates the verifier, validates the request, shows a plain request, shares the minimum,
takes an explicit approval, builds and delivers the response.

- Renders as `ScreenDescription::Consent(ConsentScreen)` after `AuthorizationRequestReceived` →
  `RpCertChainResolved` → core validation.
- Shows **who** (verifier + registered purpose), **what** (only the disclosed claim), **why**, **retention**,
  and an explicit **"Not shared"** line. Approve → `Event::UserConsented` → `Effect::Sign` →
  `Event::DeviceSignatureProduced` → delivery.
- **Over-ask** variant: when the request exceeds the verifier's registration, warn and default to "Don't
  share". (Surface the core's over-ask signal — do not compute it in the shell.)

## 7. States — happy **and** recovery (all required)

Each names the cause in plain words and offers one recovery; progress is always saved. Recovery screens
render from `Error { code }`:

| State | Core `code` (where applicable) | Recovery |
|---|---|---|
| Wrong PIN | (SDK/attempts) | Try again + attempts left; PIN help before last try |
| Blocked PIN | (SDK) | How to reset → resume |
| NFC lost / interrupted | (transport) | Auto-resume the read; Cancel present |
| Unsupported device (no NFC) | (pre-check) | Offer other ways to add |
| Issuer rejection | `credential_issuance_rejected` / `credential_rejected` | Exact reason + retry + contact |
| Revoked / suspended at present | `credential_revoked` / `credential_status_unavailable` | Refused before signing |
| Timeout / connection dropped | (transport) | Progress saved + Resume |
| Pending too long | (async) | Notify + check status on the home card |
| Returning / interrupted session | (durable) | Greet + Continue / Start over |

## 8. Accessibility — build requirements (part of Definition of Done)

- **Dynamic Type** end-to-end (no fixed point sizes); the prototype's large-text mode is the parity target.
- **VoiceOver:** each screen a labelled group; reading order = heading → context → actions; label every
  control; **live regions** narrate the NFC read and the Preparing state.
- **≥44 pt** targets; **WCAG AA** contrast (AAA where feasible); **never colour alone** (symbol + text);
  respect **reduced motion**.
- **No card-within-card**; primary action reachable without scrolling; critical instructions on-screen.
- Native iOS patterns: SF Symbols, system PIN sheet, Face ID prompt, grouped lists.

## 9. Copy & i18n

- **Externalise all strings** (de + en at minimum) — copy is provisional until testing.
- No protocol terms in UI ("PID", "credential offer", "OpenID4VCI", "SD-JWT", "mso_mdoc" are banned from
  consumer copy). Issuer/verifier names come from the authenticated certificate. No "in seconds / under N
  minutes" claims.

## 10. Suggested build order

1. Extend `presenter::ScreenDescription` + `NavigationModel.lean` + Swift conformance for the new issuance
   screens/states (keeps the sans-IO boundary and the verified navigation intact).
2. Build the **Prove** consent screen first (it maps to the existing `Consent` variant and is the highest
   trust-risk surface).
3. Build the **Add** happy path, then the **eID/NFC/PIN** journey to the spec, then every recovery state.
4. Wire the **durable home card** to issuance status. Add the a11y layer as you go (not at the end).

## 11. Definition of done (per screen)
Renders from the correct `Effect::Render` payload · dispatches the correct `Event` · all its error/recovery
states implemented · strings externalised · a11y criteria (§8) met · matches the prototype's intent (not
pixel-copy).

## 12. Open decisions (product/design sign-off, not blockers to starting)
- Final copy after the 65–85 sessions · dark-theme contrast recheck · whether a portrait-capture screen is
  needed for the applicable National ID profile · whether/when to adopt the Digital Credentials API
  `create()/get()` opportunistically (keep app/OID4VCI + custom-scheme OID4VP + proximity as defaults).

## 13. Do not
Put trust / consent / minimisation / signing logic in the shell · show protocol terms · promise times ·
nest cards · let a visual simplification drop a security check · synthesise issuer/verifier names from
caller-supplied text.
