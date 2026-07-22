# Issuance-first UX proposal for the EUDI wallet

**Date:** 2026-07-22 · **Status:** research-grounded proposal (no code changes) · **Scope:** consumer UX
redesign strategy, focused on issuance / "add to wallet".

Companion documents:
- `docs/ux/issuance-competitive-teardown-and-eid-flow.md` — screen-by-screen teardowns + German eID-NFC spec.
- Full 6-agent research brief with all source URLs is retained in the workflow output for this session.

Claims are marked **[verified]** (a cited source supports it) or **[analysis]** (our synthesis). Sources are
listed at the end.

---

## 1. The thesis, tested: right, with one correction that changes the design

> *"With the Digital Credentials API, most presentations will be via platform wallets anyway, so issuance
> becomes the more important process."*

**Verdict: agree — issuance is the right flagship bet — but reframe it as "the OS owns *selection*; the
wallet owns *everything after the handoff*," not "presentation belongs to the platform wallet."** Three
findings force this correction into the design:

1. **The DC API picker is cross-wallet, not platform-only.** On Android, third-party wallets register as
   credential providers (`RegistryManager` / `OpenId4VpRegistry`, `MdocEntry` + `SdJwtEntry` + display
   metadata) and appear in the OS chooser; WebKit states Safari requests IDs "from Apple Wallet **and third
   party Wallets**". So the wallet is not cut out of presentation — it is *de-chromed*: the bespoke
   presentation UI stops being a differentiator. **[verified]**
2. **Issuance does not fully escape the platform either.** Chrome 143 ships an OpenID4VCI `create()`
   *origin trial* that also shows an OS holder-picker bottom sheet, and a success result "only means the
   holder has successfully received the request" (issuance completes asynchronously). The durable
   wallet-owned surface is therefore the **post-handoff OID4VCI provisioning flow**, not the "which wallet"
   moment. **[verified]**
3. **Do not delete the wallet's own presentation UX yet.** Safari 26 supports only `org-iso-mdoc` (no
   OpenID4VP, which EUDI standardises on); ISO 18013-5 **BLE proximity bypasses the DC API entirely**; and
   the regime is provisional — the DC API is a W3C **Working Draft** (2026-07-16), and the EUDI ARF
   (Topic F / OIA_08) adopts it **only conditionally** on Recommendation status + platform-neutrality. **[verified]**

**Net:** issuance is the single strongest bet because, across every real deployment examined, it is the
**hardest, most failure-prone, and most fully wallet-owned** surface. But design for a world where
*selection* is platform-owned, and compete on what begins after the picker hands control back. The window is
**time-bound**: if the issuance origin trial graduates, some issuance selection moves to the platform too. **[analysis]**

---

## 2. What the platform wallets prove works (adopt these)

- **The 4-verb, protocol-invisible issuance narrative.** Apple / Google / Samsung all reduce "add an ID" to
  *Tap → Scan → Confirm → Send*. No user sees "credential offer", "scope", "OpenID4VCI", "SD-JWT", or
  "mso_mdoc". The current EUDI-reference-style "pick PID from a list / scan issuer QR" scaffolding must be
  replaced wholesale. **[verified]**
- **Trust is anchored in the government issuer, not the wallet vendor.** Proofing during "add" = NFC chip-read
  of the eID/passport + guided liveness selfie (facial/head movements), submitted to the authority, with an
  explicit *"submitted to [Authority], awaiting approval"* state. **[verified]**
- **Presentation rides the payment mental model** — hold-to-reader, one "Information Requested" review screen,
  single biometric approve, marketed as *"you never unlock or hand over your phone."* **[verified]**
- **Privacy stated as one plain absolute sentence** ("neither Apple nor the issuer can see when or where you
  use your ID"). EUDI can make a **stronger unlinkability** claim and should lead with it. **[verified]**
- **Never-empty wallet:** a universal base credential everyone can obtain (Apple's passport-derived Digital ID)
  prevents cold-start abandonment. EUDI's built-in analog is **PID** — position it as the always-obtainable
  base credential. **[verified]**
- **The real bottleneck is acceptance, not interface** — US mDL enrollment is still "single digits" because
  there is nowhere to use it. **Ship every credential with a named, high-frequency place to use it today.** **[verified]**

---

## 3. The issuance flow we propose (the flagship)

A **verb-labelled wizard, ≤5 steps, zero protocol vocabulary**, behaving like card **push-provisioning**
(which wins by removing manual entry — cards added "with just a few clicks… without downloading yet another
app"). **[verified]**

1. **Meet the offer where it lives** — email / SMS / web / QR / same-device deep-link — showing a
   recognisable **issuer name + logo** and a plain *"what's being added and why"* list. No forced app-store
   detour to complete an offer. **[verified]**
2. **Auto-parse the OpenID4VCI offer**; the issuer pre-fills. The user never retypes identity data the issuer
   already holds; confirm in one or two taps. **[verified/analysis]**
3. **Front-load value, defer friction.** Reach the highest-friction step (eID / NFC / PIN) only after value is
   shown and a low-cost step is done. Keep it **mobile-first, < 3 min, auto-capture + inline validation**
   (KYC data: 40–60% abandon poor flows; 70% abandon flows > 3 min; a re-upload request triples abandonment). **[verified]**
4. **Obsess over the eID NFC-tap + PIN** — German PID issuance lives or dies here (see the companion spec):
   NFC-positioning guidance, PIN-reset path, graceful fallback. **[verified]**
5. **Async issuance as a friendly deferred state** — *"We're preparing your ID, we'll notify you"* + push on
   completion; never a spinner or silent failure. Explicitly distinguish *"the ID you log in with"* from
   *"the credential stored in your wallet"* — the exact confusion that stalled IT-Wallet users. **[verified]**
6. **Trigger PID activation at a moment of success**, not from Settings — a post-success prompt drove **75% of
   passkey enrollments and +102%** vs a settings page. **[verified]**
7. **End on "what you can now DO", then offer the next credential / first real use** — convert one-time issuance
   into an active wallet, and beat the empty-wallet cold start (Italy reached 10M+ activations by bootstrapping
   off the pre-installed IO app + existing SPID/CIE logins). **[verified]**

Additional principles: jargon-free benefit-first copy on every screen; a non-nagging **"Not now"** for optional
credentials re-offered at a calibrated cadence; specific, recoverable error states with **one-tap retry** (name
the exact decline reason; never restart the whole flow). **[verified]**

---

## 4. Presentation — thin, standards-conformant, but not deleted

- **Registered display metadata IS the UX now.** The Android Credential Manager bottom sheet renders *your*
  app name, icon, human-readable field labels, and card art. Invest there; keep the registry fresh (stable
  ids, re-register on issuance/refresh) — a stale registry silently loses presentations. **[verified]**
- **The post-handoff consent screen is the real presentation surface:** three plain lines — **WHO** (verifier +
  Trust Mark), **WHAT**, **WHY** (registered purpose) — plus an explicit **"what is NOT shared"** line
  (*"only that you're over 18, not your date of birth"*). Default to the minimal set; avoid attribute/field
  lists and checkbox mazes. **[verified]**
- **Guide, don't just display.** A "Credential Assistant"-style nudge cut disclosure mistakes ~15% → ~7%;
  passive consent screens do not stop oversharing (~20% would hand an official ID to a news site). Surface
  **RP over-ask warnings** (*"asking for more than it's registered for"*) — a safety moment platform pickers
  structurally cannot offer. **[verified]**
- **Keep OID4VP + BLE proximity UX** for iOS app-to-app, the Safari OpenID4VP gap, and in-person. Reach the
  most-used credential in **~1 gesture from the lock screen**, or the physical card wins the counter. **[verified/analysis]**

---

## 5. Differentiation — compete where platform wallets cannot

- **A "who has my data & why" activity feed** built on the eIDAS-mandated transaction dashboard: one-tap
  stop-sharing + GDPR Art.17 erasure; logs record counterparty / data categories / purpose / outcome but not
  the attribute values, and providers cannot read logs without per-transaction consent. **[verified]**
- **RP over-ask warnings + the EUDI Trust Mark** as visible safety/assurance cues. **[verified]**
- **Breadth + cross-border** (many credentials, accepted across 27 states) and **wallet-to-wallet portability**
  marketed as *"no lock-in"* (eIDAS mandates it — "always the citizen, not the provider, in control"). **[verified]**
- **Lead marketing with the strongest hook:** prove over-18 *without revealing name/DOB* moved stated adoption
  intent by **~34 points** (≈29% → 63%). Trust is the strongest predictor of wallet adoption, above usefulness
  and ease of use. **[verified]**
- **Recovery that re-proofs at the original assurance level** (NFC ID + liveness), staged read-only → full —
  never phishable SMS/email fallback (which silently downgrades a High-assurance credential). High-assurance
  IDs are one-device-bound and don't ride cloud backup, so a new phone is a dead end without this. **[verified]**
- **Inclusion as retention:** assisted onboarding, plain/multi-language flows, non-QR/biometric alternatives
  for elderly, low-literacy, migrant, and disabled users. **[analysis]**

---

## 6. Caveats to hold in the design

- **Provisional & time-bound.** W3C Working Draft; ARF-conditional; Chrome issuance in origin trial. Keep
  **app/OID4VCI issuance + custom-scheme OID4VP + proximity as reliable defaults**, adopting DC-API
  `create()/get()` opportunistically where platforms allow. **[verified]**
- **A "wallet-selection binding" / pre-auth-code interception concern** is cited as a reason government issuers
  are cautious about DC-API issuance — reported only in secondary sources and not confirmed by Chrome's own
  blog. Treat as plausible-but-unverified. **[low-confidence]**
- **Sovereignty tension:** EUDI wallets reportedly lean on Google Play Integrity / Apple attestation for device
  checks (excludes de-Googled OS) — a live reputational risk given the sovereignty pitch. **[medium-confidence]**
- **The unanswered strategic question that outranks UX polish:** *what is the named, high-frequency acceptance
  anchor for each credential at launch, per member state?* That, not interface quality, is the proven adoption
  gate. **[verified]**

---

## 7. Recommended near-term moves (redesign backlog seeds)

1. Replace developer scaffolding ("pick from list", "scan issuer QR", visible protocol terms) with the
   4-verb issuance wizard; treat **PID issuance as the highest-drop-off consumer moment**, not a protocol handshake.
2. Build the **eID-NFC activation** step to the companion spec — it is the make-or-break screen for the German path.
3. Add the **async "preparing your document" state** + completion push + "didn't appear?" recovery.
4. Ship the **privacy activity feed + RP over-ask warning + Trust Mark** as the differentiating trust surfaces.
5. Invest in **Android Credential Manager display metadata** and keep OID4VP/proximity as the reliable
   presentation defaults; adopt DC-API opportunistically.
6. For each launch credential, pair it in-app with a **named place to use it now** (age verification, eGov login,
   banking KYC).

---

## Sources (selected, from the grounded research)

- W3C Digital Credentials API (Working Draft, 2026-07-16): https://www.w3.org/TR/digital-credentials/
- Android credential holder (registry, mdoc/SD-JWT, GET_CREDENTIAL): https://developer.android.com/identity/digital-credentials/credential-holder
- WebKit — online identity verification with the DC API (Safari, third-party wallets, org-iso-mdoc): https://webkit.org/blog/17431/online-identity-verification-with-the-digital-credentials-api/
- Chrome 143 issuance origin trial (OpenID4VCI): https://developer.chrome.com/blog/digital-credentials-api-143-issuance-ot
- DC API landscape (Chrome/Safari/Firefox support, protocol set): https://www.corbado.com/blog/digital-credentials-api
- EUDI ARF Topic F — Digital Credential API (conditional adoption, platform neutrality): https://eudi.dev/2.9.0/discussion-topics/f-digital-credential-api/
- EUDI ARF Topic H — transaction logs / privacy dashboard: https://eudi.dev/2.9.0/discussion-topics/h-transaction-logs-kept-by-the-wallet/
- EUDI ARF — relying-party registration / over-ask (RPRC_07): https://eudi.dev/latest/discussion-topics/x-relying-party-registration/
- Apple Digital ID (Nov 2025 newsroom; passport NFC + selfie; privacy claims): https://www.apple.com/newsroom/2025/11/apple-introduces-digital-id-a-new-way-to-create-and-present-an-id-in-apple-wallet/
- Apple Wallet ID consumer/how-to: https://learn.wallet.apple/id ; https://www.macworld.com/article/2482638/how-to-add-drivers-license-state-id-apple-wallet.html
- Apple device-binding (one device, no auto-transfer): https://support.apple.com/en-us/123719
- Samsung Wallet Digital ID: https://www.samsung.com/us/apps/samsung-wallet/digital-id/
- Google Wallet Digital ID + identity/age verification API: https://wallet.google/intl/en_us/digitalid/ ; https://developers.google.com/wallet/identity/verify
- Google + Sparkassen EU age-verification pilot: https://idtechwire.com/google-and-sparkassen-finanzgruppe-launch-eus-first-google-wallet-based-age-verification/
- mDL adoption / acceptance bottleneck: https://www.biometricupdate.com/202506/american-mdl-uptake-suggests-digital-id-mass-adoption-caught-in-the-slow-lane ; https://www.govtech.com/biz/data/digital-ids-are-here-but-where-are-they-used-and-accepted
- EUDI reference wallet (developer/sandbox, issuance UX): https://github.com/eu-digital-identity-wallet/eudi-app-ios-wallet-ui
- Italy IT-Wallet (IO app, SPID/CIE, activations): https://innovazione.gov.it/notizie/articoli/en/it-wallet-three-digital-documents-available-for-all-italian-citizens-and-resident/ ; https://www.miniguide.it/post/app-io-non-funziona/
- Germany SPRIND Funke prototypes / Ausweis SDK / state wallet timeline: https://www.sprind.org/en/actions/challenges/eudi-wallet-prototypes ; https://www.corbado.com/blog/eudi-wallet-2026-deadline-rollout-eic-2026
- Lissi EUDI wallet UX guide (empty-wallet, contextual issuance, Trust Mark, portability): https://www.lissi.id/blog/eudi-wallet-user-experience-guide-a-playbook-for-citizens-organizations-and-the-ecosystem
- IDnow — EUDI privacy vs usability (batch issuance, unlinkability cost): https://www.idnow.io/blog/eudi-wallets-privacy-usability/
- Consent oversharing + Credential Assistant study: https://arxiv.org/abs/2606.06354
- Push provisioning UX: https://www.lithic.com/blog/web-push-provisioning ; https://www.entrust.com/blog/2026/03/modernizing-digital-wallet-enrollment
- Passkey enrollment UX (post-success trigger, jargon-free copy): https://mojoauth.com/blog/passkey-ux-patterns-drive-adoption
- Fintech/KYC onboarding drop-off: https://getperspective.ai/blog/fintech-customer-experience-2026-onboarding-trust-drop-off ; https://zigment.ai/blog/7-ways-to-reduce-fintech-onboarding-drop-off-in-2026
- Trust as top adoption predictor; privacy-framing adoption lift: https://www.biometricupdate.com/202607/eudi-what-as-wallet-deadline-looms-awareness-remains-low
