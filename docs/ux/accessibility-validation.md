# Accessibility validation — Add & Prove prototype

**Date:** 2026-07-22 · **Artifact:** `LandingPage/public/building/issuance-flow.html` (published at
`/building/issuance-flow.html`; source mirror `docs/ux/issuance-flow-mockup.html`). Companion to
`docs/ux/issuance-first-proposal.md`.

**Status — not yet final.** This records the validation that *can* be done on the design/build (large
text, VoiceOver semantics, contrast, target size, plain-language/older-user heuristics) and the fixes
made. **Empirical testing with people aged ~65–85 is the remaining gate** and has not been run; the
protocol for it is in §5. Do not present this as the final product direction until §5 is completed.

---

## 1. Defect found and fixed by the VoiceOver pass

The previous build wrapped each phone screen in `role="img"` with a single whole-screen `aria-label`.
That collapses the screen into **one image node**, so VoiceOver could not reach or operate the buttons
inside — the prototype was **not testable with a screen reader**. Fixed:

- Removed `role="img"`; each screen is now a labelled `role="group"` (`aria-label="Add, screen 2 of 6: …"`).
- Every action is a real `<button>` (including the former "link" actions); screen titles are real `<h3>`
  headings; decorative chrome (status bar, notch, home indicator, NFC animation, icons) is `aria-hidden`.
- The NFC read and the "Preparing" state use `aria-live="polite"` regions so progress and interruptions
  are announced.
- **DOM order = visual order = reading order** on every screen, so the documented order is the real one.

## 2. Large text — PASS (representative frames verified)

Rendered the whole prototype at the large setting (`--ui: 1.3`, ~22 px base / ~19–20 px in-screen):

- Titles, body, and buttons scale together; controls grow to ~65 px tall. Verified visually on the
  binding map and on content-heavy frames (Add · 3 “Hold your card…”, Add · 4 “Confirm”): text reflows,
  buttons stay full-width and legible, **no control is clipped or removed**.
- Fix applied during this pass: the phone screen body is `overflow-y: auto`, so if scaled content exceeds
  the device viewport it **scrolls within the screen** (as it would on a real phone) rather than clipping
  a button. Primary actions remain reachable.
- Honest limit: the shareable PDF is captured at the default size; large text is a runtime mode of the
  interactive page (a static PDF cannot show in-screen scroll).

## 3. Contrast — PASS (WCAG AA, mostly AAA), light theme

Computed against the design tokens (foreground on its actual background):

| Pair | Ratio | Verdict |
|---|---:|---|
| Body ink `#0F1426` on white | ~18:1 | AAA |
| Muted text `#454C6B` on white | ~8.3:1 | AAA |
| Primary button — white on `#1E3AC0` | ~8.6:1 | AAA |
| “Verified” green `#0C6E46` on white | ~5.9:1 | AA (normal) |
| Warning `#7E5200` on `#FAECCF` | ≥4.5:1 | AA |
| Critical `#A62A1B` on white | ~5.6:1 | AA |

No information is carried by colour alone — status also uses a symbol + text label (e.g. “✓ Verified
issuer”, “Needs attention”). Dark theme uses the same token discipline; re-run this table for dark before
final.

## 4. Target size & structure — PASS

- Primary/secondary buttons: `min-height` 50 px (≈53 pt), scaling with large text — above the 44 pt floor.
- Link-style actions, nav items, disclosure summaries, the large-text toggle: `min-height` 44 px.
- Single-column layout; **no card-within-card** (grouped rows + dividers); primary action reachable
  without horizontal scrolling; critical instructions are on the screen, not below a fold.
- `prefers-reduced-motion` respected (the tap animation is decorative with a spoken status beside it).

## 5. Older-user (≈65–85) validation — heuristic PASS, empirical PENDING

### 5a. Heuristic evaluation (against age-related UX guidance)
| Criterion | State |
|---|---|
| Text ≥ 16–19 px, adjustable larger | ✓ 17 px base, 15 px in-screen, large-text mode to ~1.3× |
| High contrast, no colour-only meaning | ✓ (§3) |
| Large, well-spaced targets | ✓ (§4) |
| Plain language, no jargon | ✓ verbs only; no “PID”, “credential offer”, “OpenID4VCI”, “SD-JWT” |
| Few steps, one decision per screen | ✓ as-few-screens-as-needed; single primary action |
| Forgiving errors, clear recovery | ✓ every error names the cause + one-tap recovery; progress saved |
| No time pressure / no time claims | ✓ async is a state; no “in seconds / under 3 minutes” |
| The hardest moment de-risked | ✓ PIN asked up front (“Do you know your PIN?” + “I’m not sure”); NFC guided + cancellable |

### 5b. Moderated test protocol (the remaining gate)
- **Participants:** 8–12, aged 65–85, mixed tech confidence; include reading glasses / low vision, mild
  tremor or dexterity limits, and at least two VoiceOver users. Recruit outside iProov/design staff.
- **Setup:** real device where possible; both default and large-text; one facilitator, one note-taker;
  think-aloud; record screen + audio with consent.
- **Tasks:** (1) “Add your National ID.” (2) “Prove you’re over 18 to this shop.” (3) Recover from a
  wrong PIN. (4) Come back later and finish an interrupted add.
- **Observe:** comprehension of the PIN question; NFC tap success and re-tries; whether the consent screen
  is understood (who/what/why/not-shared); reaction to the over-ask warning; where hesitation or
  abandonment happens; VoiceOver completion without sighted help.
- **Success signals:** unaided task completion; correct mental model of “ID I log in with” vs “document
  stored”; no critical control missed; consent understood; error states recovered from.
- **Gate:** findings feed a revision; the direction is not “final” until this round is run and material
  issues are resolved (and re-tested where needed).

## 6. Known follow-ups
- Re-run the contrast table for **dark theme** before final.
- Consider a **tap-to-advance** build (one screen at a time, back/next) for unmoderated/remote testing;
  the current build is a semantically-correct, VoiceOver-operable gallery suited to moderated sessions.
- Add a dedicated **portrait-capture** screen if the applicable National ID profile requires the portrait
  at issuance (kept out of consumer copy as protocol language).
