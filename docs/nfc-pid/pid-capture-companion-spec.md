# PID Capture Companion — specification & plan (App + App Clip)

Status: **specification / plan** (no code yet). A standalone iOS capture experience — a full app
**and** an App Clip — that does only what is behind "Read Passport" today (camera MRZ → eMRTD NFC
read → iProov liveness) and hands the evidence to VCIssuer. It is launched by scanning a QR that
**VCIssuer generates**, and it exists for people who want a PID issued **into some other wallet** —
the companion never holds a credential.

This decouples *capture* (hard: a capable native app with CoreNFC + camera + the iProov SDK) from
*holding* (any EUDI wallet). It reuses the capture code already built for the main app
(`PassportReader`, `MRZScannerView`, `ChipmunkNFC`, the iProov SDK) — see
[shell-integration-plan.md](shell-integration-plan.md) and the merged "Add from passport" flow.

---

## 1. Why

Reading a passport chip + proving liveness needs entitlements, CoreNFC, camera, and a biometric SDK
— too much to ask every wallet to embed, and impossible in a browser. The companion is the shared,
high-assurance **capture front-end**; VCIssuer is the trust root that mints the PID and delivers it
to whichever wallet the user chose. An **App Clip** means no install: scan → capture → the PID lands
in the target wallet.

## 2. Actors

| Actor | Role |
|-------|------|
| **Target wallet** | Any EUDI wallet the user wants the PID in. Starts a PID issuance with VCIssuer and owns the holder key the PID binds to. Not this project. |
| **VCIssuer** | Trust root. Generates the capture QR, mints the iProov token, receives + verifies the captured evidence through the Lean-proved NFC-PID gate, mints the PID, delivers it to the target wallet. |
| **Capture companion** | The new iOS App + App Clip. Reads MRZ + chip + liveness for one VCIssuer-issued session and posts the evidence. Holds nothing. |
| **service-nfc** | The relay backend the chip read tunnels to (unchanged; ChipmunkNFC talks to it). |
| **iProov** | GPA liveness. VCIssuer is the Service Provider (holds the SP key); the companion runs the SDK with a per-session token. |

## 3. End-to-end flow (cross-device / cross-wallet)

```
 Target wallet                     VCIssuer                         Capture companion (App/AppClip)
 ------------                      --------                         -------------------------------
 1. begin PID issuance ─────────▶  create capture session
    (OID4VCI, holder key)          {session_id, sub-nonce,
                                    holder_jkt binding}
 2.                     ◀───────── QR = https://<assoc-domain>/pid-capture?s=<session_id>#<frag>
    (wallet shows the QR, or VCIssuer shows it on a kiosk screen)
 3.                                                    scan QR ────▶ App Clip launches on session_id
 4.                                validate session ◀───────────── GET /v1/pid-capture/{session}
                                    {status, iproov_token,
                                     streamingURL, reader policy} ─▶
 5.                                                                 camera MRZ → NFC read (service-nfc,
                                                                    ship_encrypted to VCIssuer) →
                                                                    IProov.launch(token)
 6.                                verify evidence ◀─────────────── POST /v1/pid-capture/{session}/evidence
                                    (NFC-PID kernel gate:            {emrtd evidence ref, iproov token}
                                     PA + anti-clone + liveness) ──▶ {ok}
 7. poll / offer  ◀──────────────  session → issuable; mint PID
    receive PID (cnf = wallet       bound to the target wallet's
    holder key)                     holder key; deliver via OID4VCI
```

The **session** is the correlation spine: it ties the target wallet's issuance request (and its
holder key) to the capture evidence. The companion never sees or needs the target wallet.

## 4. iOS targets & code reuse

Three additions to `ios/` (XcodeGen `project.yml`), sharing one capture library:

- **`CaptureKit`** (framework target) — the reusable capture core, extracted from today's app-target
  files: `PassportReader` (ChipmunkNFC-backed, `#if canImport` guarded), `MRZScannerView`
  (Vision), the iProov launch wrapper, and the evidence-submit client. Shared by all three consumers
  (main app, capture app, App Clip) so there is one implementation.
- **`PIDCapture`** (application target) — the standalone full app. Thin: QR entry (or deep link) →
  `CaptureFlowView` (CaptureKit) → done. No wallet, no holdings, no engine.
- **`PIDCaptureClip`** (App Clip target — `com.apple.developer.on-demand-install-capable`) — the same
  `CaptureFlowView`, launched from the invocation URL. Ephemeral.

The main `EUWalletDemo` app keeps its embedded "Add from passport" flow (issue into *this* wallet);
CaptureKit lets both share the reader/liveness code rather than duplicating it.

## 5. App Clip specifics & the size budget (key risk)

- **Budget.** An App Clip's uncompressed thinned size must be **≤ 15 MB** (iOS 16+). CoreNFC, Vision,
  Camera are system frameworks (free). The variable cost is **the iProov SDK + ChipmunkNFC**.
  **Action: measure early** (Phase 0) — build a spike clip linking both and read the thinned size.
  If over budget: (a) drop liveness from the *clip* (chip-only clip; liveness in the full app), or
  (b) ship capture as full-app-only and use the clip solely to hand off to the App Store / a
  lightweight web capture. The main-app ADR previously ruled out an *AusweisApp* NFC clip for size;
  the ChipmunkNFC relay is far smaller, but iProov must be measured.
- **Invocation.** Register an **App Clip advanced experience** for the URL prefix
  `https://<assoc-domain>/pid-capture`. VCIssuer serves the **AASA** (`apple-app-site-association`
  with an `appclips.apps` entry) on that domain. Prefer **App Clip Codes** (Apple's scannable code,
  best UX + built-in NFC/URL) but a plain QR containing the https URL also launches the clip.
- **Entitlements** (clip + app): `com.apple.developer.nfc.readersession.formats = TAG`, the eMRTD +
  eID `iso7816.select-identifiers` (incl. `A0000002471001`), `NSCameraUsageDescription`,
  `NFCReaderUsageDescription`, and iProov's camera use. App Clips permit CoreNFC + camera.
- **Ephemerality.** The clip persists nothing across launches; all state is the session. No Keychain,
  no holdings.

## 6. QR / invocation URL

```
https://<assoc-domain>/pid-capture?s=<session_id>
```
- `<assoc-domain>` is a VCIssuer-controlled domain associated for App Clips (AASA).
- `s` = opaque session id (VCIssuer-minted, single-use, short TTL).
- The companion fetches session detail from VCIssuer (step 4) rather than trusting QR contents; the
  QR is a pointer, not data. The companion **must** verify it launched on the associated domain
  (App Clips guarantee the invocation URL's domain) before acting — a QR to any other host is
  ignored. No identity data is ever in the URL.

## 7. Security & privacy model

- **Session-bound everything.** The iProov token and the service-nfc reader-token are minted by
  VCIssuer *for this session*; the evidence submit is keyed by `session_id`. A capture cannot be
  replayed into another session.
- **Liveness ↔ chip ↔ session.** The kernel gate already requires `sod_passive_auth ∧ chip_authentic
  ∧ liveness_matched ∧ subject == request.subject`. **Decided: iProov is authoritative for
  `liveness_matched`** — VCIssuer validates the GPA capture server-to-server (`/claim/verify/validate`
  with the SP key) and *that* verdict sets `liveness_matched`; the reader attestation supplies only
  the chip verdicts (`sod_passive_auth`, `chip_authentic`) and the DG2 portrait. Liveness and portrait
  are bound to the session, and portrait-match is checked against DG2. So the issuer proves liveness
  itself rather than trusting the reader.
- **The holder-key gap (call out explicitly).** The captured human proves *the document is genuine
  and they are live and match it*. The PID is `cnf`-bound to the **target wallet's** holder key,
  proven by that wallet to VCIssuer. The link "the human who captured == the controller of the
  target wallet" holds for self-service (the user scans their own QR from their own wallet) but is a
  trust assumption to state; a supervised/kiosk variant may need an operator attestation. VCIssuer
  must bind `session_id` to exactly one target-wallet issuance request and refuse reuse.
- **Data minimisation.** Chip/MRZ/portrait transit companion → service-nfc/VCIssuer only; the clip
  keeps nothing after submit. `ship_encrypted` HPKE-to-VCIssuer keeps the raw blob off the wallet
  entirely (per the N3 architecture). No identity data in logs, URLs, or App Clip storage.
- **QR provenance.** Because the QR is VCIssuer-generated and the invocation domain is
  AASA-associated, a spoofed QR either fails the domain check or resolves to no valid session.

## 8. VCIssuer backend additions

| Endpoint | Purpose |
|----------|---------|
| `POST /v1/pid-capture/session` | Called during the target wallet's issuance. Creates a session bound to that issuance (holder key, nonce); returns `{session_id, qr_url, expires_at}`. |
| `GET /v1/pid-capture/{session_id}` | Companion fetches session state + the per-session `iproov_token`, `streamingURL`, and the reader-token / read policy. Fails closed if expired/consumed. The token is minted by VCIssuer calling iProov `/claim/verify/token` with the SP key. |
| `POST /v1/pid-capture/{session_id}/evidence` | Companion submits the eMRTD evidence (or the `ship_encrypted` reference) + the iProov token. VCIssuer runs `verify_emrtd_evidence` for the chip verdicts **and iProov `/claim/verify/validate` for the authoritative liveness** → the proved NFC-PID gate → marks the session **issuable**. Single-shot. |

**SP credentials via env (decided):** VCIssuer reads `IPROOV_API_KEY` / `IPROOV_API_SECRET` /
`IPROOV_SERVICE_LOCATION` (e.g. `eu.rp.secure.iproov.me`) from the environment; absent → the iProov
token/validate calls (and therefore NFC-PID capture) are disabled, fail-closed. Secrets are never
hard-coded or committed. `streamingURL` for the SDK is derived as `wss://<service_location>/ws`.
| `GET /.well-known/apple-app-site-association` | Serve the `appclips` association for `<assoc-domain>`. |
| (issuance) | The target wallet's OID4VCI credential request completes only once its session is **issuable**; the PID mints bound to the wallet's holder key, gated by the session's verified evidence. |

Reuses N3 (`PID_FROM_EMRTD_SD_JWT`, `verify_emrtd_evidence`, the kernel gate) + the iProov SP backend
(previous turn's design). QR generation: a small `qrcode`-style dependency or an SVG data-URI
generator (VCIssuer already renders metadata; a dependency bump is bundle-gated).

## 9. CI-safety (unchanged discipline)

The new targets go in the committed `project.yml`, but their **ChipmunkNFC + iProov linkage stays in
the git-ignored `project.local.yml` overlay** (extend it to add the packages to `PIDCapture` +
`PIDCaptureClip` too). advatar's GitHub-hosted CI generates from base `project.yml` → the capture
targets build against the `#if canImport` stubs, no private submodule, no iProov/SP credentials.
Device/enrolment builds use `--spec project.local.yml`. VCIssuer's new endpoints follow the 4-gate
CI + BUNDLE-manifest discipline; SP creds + `<assoc-domain>` are env config.

## 10. Build plan (phased)

- **Phase 0 — feasibility spike (do first):** a throwaway App Clip target linking iProov + ChipmunkNFC;
  measure thinned size vs the 15 MB budget. Decision gate for whether liveness lives in the clip.
- **Phase 1 — CaptureKit:** extract `PassportReader`/`MRZScannerView`/iProov-wrapper/evidence-client
  from the app target into a shared framework; main app keeps working.
- **Phase 2 — VCIssuer capture-session backend:** the 3 endpoints + AASA + QR, session lifecycle,
  bound to the target-wallet issuance; wire the iProov token/validate; extend the NFC-PID gate feed.
  (Rust, 4 gates, testable without live creds via injected HTTP + fixtures.)
- **Phase 3 — PIDCapture app target:** QR/deep-link entry → CaptureFlow → submit → result. Universal
  links + custom scheme; `project.local.yml` linkage.
- **Phase 4 — PIDCaptureClip App Clip:** the same flow behind the invocation URL; AASA; App Clip Code
  generation in VCIssuer; ephemeral-state review.
- **Phase 5 — cross-wallet issuance correlation:** the target wallet's OID4VCI issuance consumes the
  issuable session; end-to-end with a reference wallet; deferred-issuance vs credential-offer choice.
- **Phase 6 — hardening:** session TTL/replay, rate limits, privacy review, accessibility, size
  re-measure, docs + landing page.

## 11. Decisions & open questions

**Decided**
- **Liveness authority — iProov, validated by VCIssuer.** VCIssuer mints the iProov token and
  validates the capture server-to-server; that verdict is `liveness_matched`. The reader attestation
  is chip-verdicts + portrait only.
- **SP credentials — environment.** `MANDAMUS_IPROOV_BASE_URL` / `MANDAMUS_IPROOV_API_KEY` /
  `MANDAMUS_IPROOV_SECRET` (the same Service-Provider credentials that drive the iProov Web and iOS
  SDKs); absent → fail-closed. Never hard-coded or logged.

- **Cross-wallet delivery — credential-offer is primary; deferred/poll is a supported secondary.**
  Once NFC + liveness have gated the issuance there is no reason to delay, so the default is: when a
  session becomes **issuable**, VCIssuer emits an OpenID4VCI **credential-offer** (pre-authorized-code
  grant) to the target wallet — e.g. `openid-credential-offer://?credential_offer_uri=…` shown/sent
  back through the originating channel. Both models are supported: a target wallet that opened a
  (deferred) OID4VCI session may instead **poll** it to completion. The session therefore records its
  delivery mode; `offer` is the default.

**Still open (needed before / during Phase 2)**
1. **App Clip liveness** — depends on the Phase-0 size result: full capture in the clip, or chip-only
   clip + liveness in the full app.
2. **Associated domain** — which VCIssuer domain hosts the AASA / App Clip experience (prod vs dev).
3. **Supervised vs self-service** — is an operator/kiosk attestation needed to close the
   captured-human ↔ target-wallet-controller gap for non-self-service issuance?

## 12. Reused vs new

- **Reused:** `PassportReader`, `MRZScannerView`, ChipmunkNFC relay, the iProov SDK integration,
  VCIssuer's `PID_FROM_EMRTD_SD_JWT` + `verify_emrtd_evidence` + proved kernel gate, the
  `project.local.yml` CI-safe overlay pattern.
- **New:** `CaptureKit` framework, `PIDCapture` app, `PIDCaptureClip` App Clip, VCIssuer capture-session
  endpoints + AASA + QR, the cross-wallet issuance correlation, App Clip experience registration.
