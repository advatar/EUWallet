# Launch plan — independent, conformant EU (German) Digital Identity Wallet

> **`STATUS.md` is the living, checkbox-level engineering tracker.** This document is the
> **launch-oriented view**: milestones, the critical path, and the *external* (non-engineering)
> gates — so a decision-maker can sequence the launch and start the long-lead items now. It does not
> restate STATUS.md's task detail; where they overlap, STATUS.md wins.

Product target (per STATUS.md): an **independent, competing German EUDI Wallet solution** — native
iOS + Android clients, the sans-IO Rust core, wallet-provider services, trust/status/WUA
infrastructure, certified secure crypto, and the release + operating processes. Demo behavior is not
in the production target.

---

## Where we are (caught up, 2026-07-20)

Foundation ("P0 trustworthy") is largely landed and CI enforces the gates fail-closed:
- **Core**: one *verified* credential-ingestion path (SD-JWT VC + mdoc); verified OID4VCI issuance;
  per-credential, issuer/list-bound, fresh status; provenance + RP/issuer/status trust re-frozen
  before consent/sign/deliver; issuer identity bound to the authenticated **cert path** (not caller
  metadata); RFC 9901 recursive SD-JWT disclosures; bounded DCQL 1.0 with atomic, minimised
  `credential_sets`; mdoc tag-0 dates + `x5chain` authenticated through the strict validator;
  holder-authorization-hash-bound consent/payment/QES; CSPRNG operation IDs + typed terminal results.
- **Crypto / X.509**: strict *bounded* RFC 5280 path building (name constraints, basicConstraints/
  pathLen, keyUsage, AKI/SKI) + **RSA PKCS#1 certificate verification** (kept out of JOSE/COSE) +
  signature/SPKI strength profiles. *Open:* residual RFC 5280 (DN chaining, directoryName/rfc822Name,
  policy tree, RSASSA-PSS) and **frozen normative EUDI profiles** proven against PKITS + production
  chains + revocation.
- **Clients**: iOS shell hardened (fail-closed Secure Enclave, typed failures, SSRF-hardened
  transport, encrypted dual-slot durable store, lifecycle coordinator, German-eID client seam +
  fakes); **Android** production-shell foundation (StrongBox-first signing, HTTPS/SSRF policy,
  Intent/QR ingress parser, encrypted Keystore store). *Open:* Android production integration; the
  AusweisApp SDK adapters.
- **Durable state**: versioned encrypted checkpoint v1 + crash-safe lifecycle (commit-gated effect
  batches). *Open:* full store↔core wiring, a crash-safe acked outbox, and making the coordinator the
  *only* event path.
- **German PID issuance**: the OID4VCI 1.0 Final / HAIP authorization + credential-endpoint transport
  machines (PAR, PKCE S256, RFC 9207, DPoP + nonce, WIA + KA per TS3 1.5.2, atomic c_nonce
  reservation, distinct instance/DPoP/credential keys) are built and hardened **in isolation**.
  *Open:* the Rust-owned production issuance aggregate, native effect wiring, real PID-/Wallet-
  Provider trust, and the official AusweisApp SDK integration.
- **Assurance**: Lean 4 + Tamarin models, workspace + shell test suites, SBOM, mutation, benchmarks;
  CI on pinned, least-privilege, fail-closed actions; normative sources pinned in
  `docs/normative-baselines.md`.

## Critical path to launch (milestones)

- **M1 — Live German PID issuance (sandbox).** Integrate the reviewed OID4VCI/HAIP transports into a
  Rust-owned production issuance aggregate; wire native effects (browser auth via AusweisApp SDK,
  WIA/KA acquisition, DPoP/ES256 signing, durable outbox); resolve PID-/Wallet-Provider trust; ingest
  the PID (`eu.europa.ec.eudi.pid.1` mdoc + `urn:eudi:pid:1` SD-JWT VC) through verified ingestion.
  **This is the top engineering priority — it proves the whole chain end to end.**
- **M2 — Complete X.509 + freeze EUDI profiles.** Residual RFC 5280 surface; normative cert/algorithm
  profiles for PID / (Q)EAA·mdoc / RP / status / WUA·WIA; proven against official EUDI/PKITS suites +
  production chains + revocation. *(Gates certification.)*
- **M3 — Android first-class parity.** Android-specific formal shell model + exhaustive Kotlin
  model-conformance suite equivalent to the iOS NavigationModel/NavigationTests boundary; production
  app + StrongBox/KeyMint capability policy +
  encrypted rollback-resistant persistence + process-death recovery + accessibility + physical-device
  evidence; UniFFI production adapters with **no** demo doubles reachable in release.
- **M4 — Durable / crash-safe delivery complete.** Wire both stores to the Core checkpoint boundary;
  bounded outbox/inbox with acknowledged external delivery (no loss/dup across process death);
  lifecycle coordinator the sole production event path; durable evidence/count limits.
- **M5 — Proximity + remaining profiles.** ISO 18013-5 BLE/NFC proximity; non-PID OpenID profile
  extensions; wallet-to-wallet.
- **M6 — Provider platform.** Wallet-provider backend, remote WSCA/WSCD/HSM (QES via QTSP/CSC),
  WUA/WTE issuance, status/revocation, device management.
- **M7 — Privacy + UX completeness.** Pseudonyms, unlinkability (batch / one-time-use credentials),
  activity dashboard, reporting, erasure, portability; German localization; EN 301 549 / BITV
  accessibility; GDPR product controls + DPIA.
- **M8 — Assurance + certification readiness.** Bind formal oracles to the production machines;
  complete TOE, threat model, DPIA, key-lifecycle and algorithm-profile + KAT evidence; run and
  submit the OpenID Foundation self-certification for every shipped OpenID4VP/OpenID4VCI + HAIP
  profile with release-matched signed evidence; pass OIDF /
  FCAF / German-sandbox / cross-border interop; independent pen test + red team + bug bounty; signed
  reproducible releases + SBOM/provenance + IR / revocation / monitoring / rollback / DR.

## External launch gates (NOT engineering — long lead times, start in parallel now)

1. **Accepted German PID Provider** relationship + sandbox access; BVA authorization / technical
   certificates where applicable.
2. **Certified WSCA/WSCD** (Common Criteria protection profile) + a **certified Wallet Solution**.
3. **CAB / BSI certification** against **CIR (EU) 2024/2981** under **EUCC**, evidencing conformity to
   **2024/2977** (PID/attestations), **2024/2979** (integrity & core functionalities), **2024/2980**
   (notifications), **2024/2982** (protocols) + **ARF 2.9.0** + **PID Rulebook 1.7**.
4. **German recognition / notification** + Commission listing; **Wallet-Provider registration**.

## Sequencing & the timeline risk

- **Now → short term:** drive **M1** (live PID in the German sandbox) — it's the highest-signal
  engineering milestone and generates the interop evidence certification relies on. Run **M2**
  (profiles) alongside, since it blocks certification. **In parallel, open the external chain (gate
  1–4) immediately** — those are months of third-party process, not code.
- **Then:** **M3 + M4** → a shippable, multi-platform, crash-safe beta.
- **Then:** **M5–M7** → feature, proximity and privacy completeness.
- **Launch gate:** **M8** assurance + external certification. Engineering (M1–M7) must be
  *ready-to-certify* before the assessment starts.

**Biggest risk to the timeline is the external chain (PID-Provider acceptance → WSCD certification →
CAB/BSI → notification), not the code.** Begin it now, so it runs concurrently with M1–M4 rather than
serially after them.
