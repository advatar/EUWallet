# Developer hand-off — Add & Prove wallet UX (contract-precise)

**Date:** 2026-07-22 · **For:** core + shell engineering.

## 0. How to read this

**Keep the complete product design.** Nothing in the prototype is trimmed to fit today's APIs — **existing
APIs are a starting point, not a ceiling.** Every design element that is not backed by an existing *typed,
decoded, tested* contract is marked **REQUIRED CORE WORK** below.

**Order of work is fixed: core first, then UI.** For each proposed element: add the typed core contract →
populate it from an authenticated source → include it in the consent/authorization binding where it is part
of what the user approves → make it durable where it must survive restart → prove the obligation in the
formal model → add presenter serialization tests and Swift **and** Android decoder conformance → **only
then** bind the UI. Engineering can start the UI *today* against the **existing consent payload** while the
richer typed fields land core-first.

**Frozen vs provisional.**
- **Frozen:** the wallet/OS trust boundary (§2); the *set of required states* (every happy + recovery
  state must exist); the accessibility acceptance criteria (§7); and the "UI ↔ verified data" binding rules
  (§3).
- **Provisional (usability testing with ~65–85 may change these):** **flow composition — navigation,
  ordering, screen count, and recovery composition — as well as copy and spacing.** Do not hard-freeze the
  number or order of screens.

**Authority.** The **typed core contract and its tests are authoritative.** The prototype
(`/building/issuance-flow.html`) is **design intent, not protocol truth** — where they disagree, the core
contract wins.

## 1. Sources of truth
| Artifact | Path |
|---|---|
| Interactive prototype (design intent) | `LandingPage/public/building/issuance-flow.html` |
| Proposal, teardown + eID/NFC/PIN spec, a11y validation + 65–85 protocol, PDF | `docs/ux/issuance-first-proposal.md`, `…competitive-teardown-and-eid-flow.md`, `…accessibility-validation.md`, `…issuance-flow-mockup.pdf` |
| Core contract | `crates/presenter` (`ScreenDescription`, `ConsentScreen`), `crates/wallet-core` (`Event`/`Effect`, hashing, durable), `formal/lean/{NavigationModel,IssuanceModel}.lean`, Swift/Android decoders |

## 2. Boundary (frozen, non-negotiable)
OS may mediate **selection**. The **wallet** owns verifier authentication, request validation,
minimisation, understandable consent, explicit approval, secure response construction, delivery, recovery.
The shell stays thin: it renders `Effect::Render { screen: ScreenDescription }` and returns `Event`s. **No
trust / minimisation / consent-binding / signing logic in the shell.**

## 3. UI ↔ verified data binding rules (frozen)
1. **Issuer/verifier display identity is NOT taken from raw certificate leaf text.** Bind it through trusted
   **issuer/registration metadata** that is cryptographically associated with the validated certificate or
   issuer identifier. Certificate subject text is not automatically safe UI copy.
2. **Approval ≠ signing.** "Approve with Face ID" is an **authenticated approval result**, a *separate*
   operation from `Effect::Sign`. The core must require a verified approval result **before** it requests the
   signature. (New event/gate — §5, matrix row A.)
3. **No raw issuer/verifier error text in the UI.** The core emits **stable error codes + bounded, structured
   context**; the shell maps those to **reviewed, localised** recovery copy. Raw diagnostics are debug-only.
4. Every consumer string is bound to authenticated core output; the shell never synthesises identity,
   purpose, retention, "not shared", or over-ask conclusions itself.

## 4. Contract tiers

**Tier E — Exists today (typed payload, decoded, tested — build the UI on these now):**
- `ScreenDescription::Consent(ConsentScreen{ rp_display_name, purpose, requested_claims })` — decoded in Swift.
- `ScreenDescription::Error { code, message }` — decoded in Swift.
- `Loading`, `PaymentConfirmation(PaymentScreen)`, `SignConfirmation(SignScreen)` — typed + decoded.
- WYSIWYS binding exists: `consent_hash`/`authorization_hash` over the rendered approval.

**Tier P — REQUIRED CORE WORK (proposed; not renderable until built core-first):**
- **Payload-free variants** `IssuanceOffer`, `CredentialList`, `CredentialDetail` exist as *empty* Rust
  variants **and the Swift decoder maps them to `.other`** — they carry no issuer/document/status content
  today. Adding that content is new typed payload + new decoders (matrix rows 8–11).
- **Consent enrichment**: registered-verifier status, Trust Mark, retention, "not shared", over-ask result
  are **new authenticated core fields** on the consent contract — not existing UI work (rows 4–7).
- **New issuance screens/states**: PIN-question, NFC tap/reading, Preparing, Ready, home-card
  Needs-attention (rows 11–12).
- **Authenticated approval gate** before signing (row A).
- **Structured, bounded error context** + code→copy mapping (row 15).

**Tier A — Product assumptions (validate in testing; do not encode as protocol truth):**
- Flow ordering, screen count, and recovery composition (may change with 65–85 testing).
- **Portrait:** presence is **already enforced** (PID Rulebook 1.7 profile — `validate_sd_jwt_pid_portrait`
  / `validate_mdoc_pid_portrait`, gated by `CredentialIngestionError::PidPortraitInvalid` at ingestion). The
  *only* open UX question is whether a **portrait-capture screen** is needed; normally the trusted issuer/eID
  process supplies the portrait.

## 5. Contract matrix (every proposed field)

Columns: **Exists** · **Authenticated source** · **Core type/variant** · **In consent/authz hash?** ·
**Durable across restart?** · **Swift/Android decoder** · **Formal obligation** · **Localised display rule**

| # | Screen · field | Exists | Authenticated source | Core type/variant | In hash? | Durable? | Swift / Android | Formal obligation | Display rule |
|---|---|---|---|---|---|---|---|---|---|
| 1 | Consent · rp_display_name | ✅ | trusted RP **registration** metadata bound to validated client_id/cert (see §3.1) | `ConsentScreen.rp_display_name` | ✅ consent_hash | no (session) | Swift ✅ / Android ⚠confirm | NavigationModel + Tamarin consent-binding | verbatim from registration, not cert text |
| 2 | Consent · purpose | ✅ | RP registration | `ConsentScreen.purpose` | ✅ | no | Swift ✅ / Android ⚠ | NavigationModel | from registration |
| 3 | Consent · requested_claims (minimised) | ✅ | core minimisation | `ConsentScreen.requested_claims` | ✅ | no | Swift ✅ / Android ⚠ | minimisation correspondence | catalogue-localised claim labels |
| 4 | Consent · registered-verifier + Trust Mark | ❌ REQUIRED | trusted list / RP-access registration cert | **new** `ConsentScreen` field | ✅ (must bind) | no | **new** both | serialization test + consent-binding obligation | symbol **and** text, never colour-only |
| 5 | Consent · retention | ❌ REQUIRED | RP registration / request policy | **new** field | ✅ | no | **new** both | serialization + obligation | plain phrase ("Not stored" / "Kept N days") from authenticated policy |
| 6 | Consent · "not shared" | ❌ REQUIRED | core: complement of held vs disclosed | **new** field (`Vec<String>`) | ✅ | no | **new** both | minimisation-correspondence test (shared ∪ not-shared = held; shared = requested) | catalogue-localised labels |
| 7 | Consent · over-ask result | ❌ REQUIRED | core RP-registration check | **new** field (enum) | ✅ | no | **new** both | over-ask obligation (Rust + Tamarin) | reviewed warning copy from code |
| 8 | Issuance · issuer display identity | ❌ REQUIRED (variant empty; Swift→.other) | trusted issuer metadata assoc. with validated issuer cert/identifier | **new** payload on `IssuanceOffer`/`CredentialDetail` | ✅ issuance-approval binding | ✅ stored with holding | **new** both | IssuanceModel + serialization + decoder conformance | from issuer metadata, not cert text |
| 9 | Issuance · document type/name | ❌ REQUIRED | catalogue (authenticated type) | **new** payload field | ✅ | ✅ | **new** both | IssuanceModel | catalogue-localised type name |
| 10 | Issuance · "what will be added" attrs | ❌ REQUIRED | catalogue / offer | **new** payload | ✅ | ✅ (granted set) | **new** both | IssuanceModel | catalogue-localised labels |
| 11 | Home card · status Preparing/Ready/Needs-attention | ❌ REQUIRED | issuance machine state + durable checkpoint + status list | **new** variant/field | n/a (status) but integrity-bound | ✅ **checkpoint** | **new** both | IssuanceModel + **durable-transition proofs** + trace correspondence | localised status + recovery action |
| 12 | Screens · PIN-question / tap / preparing / ready | ❌ REQUIRED | issuance machine | **new** `ScreenDescription` variants | mid-flow transitions bound | ✅ where mid-flow | **new** both | NavigationModel **and** IssuanceModel + trace correspondence + decoder conformance | verbs; no protocol terms; no time claims |
| A | Approval · authenticated approval result | ❌ REQUIRED | platform user-auth (LAContext / BiometricPrompt) result verified by core | **new** `Event` + core gate before `Effect::Sign` | part of authz binding | no | shell **produces**; both | oid4vp + IssuanceModel gate: *no signature without a verified approval* | system sheet (no custom copy) |
| 14 | Recovery · error code | ✅ | core | `Error.code` (stable string) | n/a | n/a | Swift ✅ / Android ⚠ | NavigationModel; codes are a stable enumerated set | shell maps **code → reviewed localised copy** |
| 15 | Recovery · structured context | ❌ REQUIRED | core | **new** bounded typed field on `Error` | n/a | n/a | **new** both | codes stable + context bounded | localised copy from code+context; **raw diagnostics debug-only** |

Existing error codes to design copy for (already emitted): `credential_revoked`, `credential_status_unavailable`,
`credential_expired`, `credential_not_yet_valid`, `credential_issuance_rejected`, `credential_rejected`,
`credential_provenance_invalid`, `presentation_trust_invalid`, `presentation_response_uri_invalid`,
`presentation_response_encryption_metadata_invalid`, `audit_log_unavailable`.

## 6. Core-first implementation plan (ordered slices)

Each slice lands **core-first and verified** before any UI binds it. Per-slice Definition of Done:
Rust type + in-core population from an authenticated source + hash/durable wiring + **presenter
serialization tests** + **formal obligation** (NavigationModel for shell containment; **IssuanceModel + trace
correspondence** for issuance gates and durable transitions) + **Swift and Android decoder conformance** +
`cargo fmt`/`clippy`/`test` green.

1. **Consent enrichment** (rows 4–7). Start with **"not shared"** (row 6) — fully core-derivable today (held
   − disclosed), no external dependency — then registered-verifier/Trust Mark/retention/over-ask, which also
   require the **RP-registration trust model** to carry that authenticated data (build that data path first).
   All new fields join the `consent_hash`.
2. **Payload-bearing `IssuanceOffer` / `CredentialDetail`** (rows 8–10) + new Swift/Android decoders
   (replace the `.other` fallback).
3. **Issuance screens + machine states + durable transitions** (rows 11–12): extend the Rust issuance
   machine and `IssuanceModel.lean`, prove the new gates + durable transitions with trace correspondence,
   surface status from the durable checkpoint.
4. **Authenticated approval gate** (row A): a verified approval `Event` the core requires before `Effect::Sign`.
5. **Structured error context + code→copy** (row 15).

Then, and only then, connect the UI screen-by-screen (Prove first — it maps to the existing `Consent`
payload extended by slice 1).

## 7. Accessibility acceptance criteria (frozen — part of DoD)
Dynamic Type end-to-end (large-text parity with the prototype); VoiceOver — labelled groups, heading→context
→actions order, labelled controls, live regions for NFC + Preparing; ≥44 pt targets; WCAG AA (AAA where
feasible), never colour-alone; reduced motion; no card-within-card; primary action reachable without
scrolling; native iOS patterns (SF Symbols, system PIN sheet, Face ID prompt, grouped lists).

## 8. Formal-verification obligations (correction to prior draft)
Extending `NavigationModel.lean` **alone is insufficient** — it proves *shell containment*, not issuance
security. New issuance gates and durable transitions additionally require: the **Rust issuance machine**,
**`IssuanceModel.lean`**, **trace correspondence** between them, **presenter serialization tests**, and
**Swift/Android decoder conformance**. Consent-binding and over-ask obligations extend the presentation
model + Tamarin.

## 9. Localisation & consent-text integrity (correction)
Externalising strings avoids a refactor, but **changing bundled localisation still ships in a new app
build.** Do **not** serve **remotely mutable** copy for security-critical **consent** text unless it is
**authenticated, versioned, and included in the authorization binding**. Non-security chrome may use bundled
localisation freely (de + en minimum). No protocol terms, no "PID", no time promises in any UI copy.

## 10. Do not
Trust/consent/minimisation/signing logic in the shell · protocol terms in UI · raw cert/issuer/verifier text
as display copy · raw issuer error strings · time promises · card-within-card · treating the prototype as
the contract · remotely-mutable unauthenticated consent copy · binding "approve" directly to signing.
