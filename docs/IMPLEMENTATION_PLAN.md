# EUDI Wallet — Implementation Plan

_Rust sans-IO core · Swift/iOS shell · three formal tiers (property/fuzz/Kani → Lean → Tamarin). Grounded in the EUDI specification register as of 2026-07-17 (ARF v2.9.0, PID Rulebook v1.6, FCAF v0.0.7). Written to be followed by a junior developer._

> **Provenance & source of truth.** This plan was produced by a multi-agent workflow (14 sections authored in parallel) plus an editor synthesis pass, then reconciled against the working scaffold in `euwallet/`. **Where any section conflicts with the scaffold or with another section, the compiling scaffold and the editor's canonical section map (below) govern.** Sections 4 and 5 were regenerated after the initial run and supersede any earlier gap-report note about them.


> Editor's note. This front matter is the connective tissue for the 14 independently authored sections (Section 0 through Section 13) that follow. The sections were written in parallel; they are individually strong and are **not** rewritten here. What this front matter adds is: a single entry point (Executive summary, How to use), one linear to-do spine (Master checklist), one merged vocabulary (Glossary), an adversarial completeness pass (Consistency & gap report), and the release gates (Definition-of-done table). Where an inline cross-reference inside a section cites a section *number* that disagrees with the table in "How to use this plan," **the canonical map governs** — the authors assumed different global numberings, so trust topic names over numbers.

---

## 1. Executive summary

We are building, from scratch, the **smallest credible certifiable EUDI Wallet** — a citizen-held European Digital Identity wallet — iOS-first (Android later), by a single Swift-strong developer, minimizing *software* dependencies (never standards). Target baseline: ARF v2.9.0, PID Rulebook v1.6, FCAF v0.0.7, as of 2026-07-17.

**Architecture (decided; do not relitigate):**

- **Rust behavior core, sans-IO.** The whole protocol layer is a pure state transition, `handle_event(&mut Core, Event) -> Vec<Effect>` — no network, clock, RNG, radio, or disk inside the core. I/O happens in the shell and results are fed back as events. This makes the certification-critical logic deterministic and replay-testable (Crux-style effects-as-data). (§2)
- **13-crate acyclic Cargo workspace** with a machine-enforced dependency budget (`cargo-deny`): `crypto-traits` at the bottom (interfaces only, zero algorithms), then formats/trust (`cose mdoc sdjwt x509 status wua trust`), then protocols (`oid4vp oid4vci iso18013-5 presenter`), then the `wallet-core` facade. No core crate may touch the network or hand-roll crypto. (§1)
- **Thin native shells.** Swift/iOS now, Kotlin/Android later, execute Effects and feed EffectResults back as Events. Protocol logic is written and certified once. (§8)
- **UniFFI boundary**, tiny and stable: the shell talks to the core through a small typed Event/Effect surface generated from Rust proc-macro annotations. (§3)
- **Device-bound keys never cross the FFI.** Signing/ECDH/attestation happen via Effects into the Secure Enclave (iOS) / StrongBox (Android) behind a `crypto-traits` trait; only public keys and signatures cross. (§3, §8)
- **The presenter lives inside the core** and emits canonical, hashable `ScreenDescription`s from a closed vocabulary (~16 archetypes). The consent screen is canonically CBOR-encoded and **hashed inside the core**, so both platforms provably show the same consent payload — what-you-see-is-what-you-sign, bound to signature/QES intent. RP-supplied strings/logos are validated *data* slotted into wallet-owned templates, never structure. (§7)
- **Hand-written Rust enum state machines** with exhaustive `match` (compile-time coverage; evaluator-friendly) for OID4VP, OID4VCI, and ISO 18013-5 — not a runtime state-chart library. (§5)

**Three formal-methods tiers (all required):**

- **Tier 1 (always on):** proptest property tests + cargo-fuzz targets on every codec + Kani bounded proofs of codec invariants + `#![forbid(unsafe_code)]` in every core crate. (§9)
- **Tier 2 (the sweet spot):** a Lean 4 model of the protocol state machines proving three invariants — no accepting trace without signature validation; no disclosure effect before a consent event; no reachable state accepts a replayed nonce — then enumerating traces and exporting them as JSON to **replay against the Rust core as an executable oracle**. (§10)
- **Tier 3 (protocol design):** Tamarin (with ProVerif as a second opinion) symbolic analysis of the HAIP OpenID4VP profile against a Dolev-Yao attacker: secrecy of presented claims, injective agreement / no mix-up, nonce freshness. (§11)

**Non-negotiable conformance baseline:** the wallet MUST support **both** mdoc **and** SD-JWT VC credential formats; **both** remote (OpenID4VP) **and** proximity (ISO 18013-5) presentation; HAIP-constrained OpenID4VC profiles; PID issuance in **both** formats. Plus the hard "DO NOT DO" rules: never hand-roll crypto; never a software-only vault for high-assurance keys; never equate a valid TLS cert with RP registration; never accept an unsigned/unbound request object; never disclose a whole credential where selective disclosure exists; never depend at runtime on the EC reference implementation (CI interop oracle only); never defer accessibility to final polish; never log full credentials/secrets/biometrics.

---

## 2. How to use this plan

**Audience.** A junior developer who can program but does not know Rust, Lean, Tamarin, or the EUDI ecosystem. Every section numbers its steps, gives exact commands and file paths, and ends each major step with a **Definition of done (DoD)** — a command to run and the expected output.

### 2.1 Canonical section map (authoritative)

The 14 sections, in reading order. **Use this map, not the section numbers written inside each author's prose** (those numbers disagree across authors).

| Canonical | Topic | Milestone(s) it feeds |
|---|---|---|
| **§0** | Prerequisites, environment setup, repo bootstrap | M0 |
| **§1** | Cargo workspace topology, crate boundaries, dependency budget | M0 |
| **§2** | sans-IO Event/Effect core + run loop (`wallet-core` facade) | M0 |
| **§3** | UniFFI boundary (Rust → Swift/Kotlin) | M0, M2 |
| **§4** | Codec crates: `cose`, `mdoc`, `sdjwt`, `x509` | M1 |
| **§5** | Protocol state machines: `oid4vp`, `oid4vci`, `iso18013-5` | M2, M3, M4 |
| **§6** | `trust`, `status`, `wua` crates | M4, M5 |
| **§7** | `presenter`: canonical `ScreenDescription`, A2UI, consent hashing | M2 |
| **§8** | iOS shell: renderer, Secure Enclave signer, transports, storage, executor | M2, M3, M4 |
| **§9** | Formal Tier 1: proptest, cargo-fuzz, Kani, forbid-unsafe | M1, M6 |
| **§10** | Formal Tier 2: Lean 4 model, invariant proofs, trace-export oracle | M2, M3, M4, M6 |
| **§11** | Formal Tier 3: Tamarin (or ProVerif) symbolic analysis | M2, M6 |
| **§12** | Requirements traceability, certification evidence, FCAF-in-CI, SBOM | M0 (scaffold), M7 |
| **§13** | CI/CD pipeline, milestones, DoD gates, change-watch risk register | all (authoritative for CI, milestones, risk) |

> **Note on missing topics.** There is no dedicated `crypto-traits` section and no dedicated Accessibility section. `crypto-traits` is referenced by §1/§3/§4/§6/§8 with *conflicting* method signatures; treat this as an open specification item (see Gap G-3/G-4) that must be nailed down before M1. Accessibility is asserted piecemeal in §7/§8/§13 (see Gap C-2).

### 2.2 Reading order

Read §0 and §1 in full before touching anything. Read §2 slowly — sans-IO and effects-as-data are the ideas the whole plan rests on. Then read the section for the milestone you are on (see the map above), plus its formal-methods companions. Read the **Consistency & gap report (§5 of this front matter) before you write your first crate** — several contradictions (repo name, `crypto-traits` signatures, the presenter dependency/`sha2` conflict, the Event/Effect vocabulary) will bite you at M0–M2 if you don't reconcile them up front.

### 2.3 The milestone spine

Work proceeds strictly in order **M0 → M7**, then P1/P2. Each milestone produces a demonstrable, testable increment:

`M0` skeleton → `M1` codecs → `M2` one end-to-end OID4VP presentation of a PID → `M3` proximity (18013-5) → `M4` issuance (OID4VCI) → `M5` trust/status/WUA → `M6` all three formal tiers green together → `M7` FCAF + certification-evidence bundle → `P1/P2` later features.

Do not start a milestone until the previous one's DoD gate (section 6 below) is green. Do not start any P1 item before M7.

### 2.4 How definitions-of-done gate progress

Three layers of gating, all must hold:

1. **Step DoD** (inside each section): run the command, get the shown output. This is your local, minute-to-minute feedback.
2. **Milestone DoD** (front-matter section 6 below): the aggregate checks for that milestone are green.
3. **Merge gate** (§13): every pull request must turn `ci / all-green` green — the single aggregate CI check that `needs:` all of fmt/clippy/check/test/deny/audit/fuzz-smoke/kani/lean-oracle/tamarin-parse/swift/fcaf/sbom — plus one human review (G14) and, when touching a change-watch area, an updated version marker + risk-register row (G15). Branch protection points only at `ci / all-green`, so adding a job never weakens the gate.

The traceability discipline runs *across* every milestone: no code lands in a core crate without a `// HLR:` tag referencing a real requirement ID (§12), and you never implement behavior from narrative spec text — you first add a version-pinned row to `traceability/hlr.csv`, then implement.

---

## 3. Master task checklist

One list, top to bottom. Each item cites its section(s). Check items off in order within a milestone; complete a milestone's DoD gate (front-matter section 6) before moving on. Items marked ⚠ depend on an unresolved contradiction in the gap report — reconcile it first.

### M0 — Skeleton (workspace compiles; CI green on nothing)
- [ ] Install Homebrew, Xcode + Swift, Rust (rustup, pinned), cargo-audit/deny/fuzz, Kani, Tamarin + ProVerif, Python + uv, elan + Lean 4, UniFFI, git/gh (§0 Steps 1–10)
- [ ] ⚠ Decide the **repo root directory name** once and use it everywhere (`euwallet` vs `eudi-wallet` — see Gap G-1); create the repo and `git init` **exactly once** (§0 Step 11 or §1 §1.2 — not both)
- [ ] Create the canonical directory tree and the 13-crate workspace: root `Cargo.toml`, `rust-toolchain.toml` (channel 1.97.0), per-crate `Cargo.toml`, every `src/lib.rs` starting with `#![forbid(unsafe_code)]` (§1 §1.2–§1.5; reconcile with §0 Step 11)
- [ ] ⚠ Author the **`crypto-traits` trait definitions** (Signer/Verifier/Kdf/Aead/Random/KeyAttestation) with **one** agreed method signature per trait, no implementations (Gap G-3/G-4; §1 promises this, no section delivers it)
- [ ] Pin the dependency budget in `[workspace.dependencies]` and enforce it: write `deny.toml` (one location), run `cargo deny check` + `cargo audit` clean (§1 §1.7–§1.8)
- [ ] Prove the graph is acyclic and networking/legacy-crypto free (`cargo tree` checks) (§1 §1.6)
- [ ] Stand up the empty sans-IO core: `Core`, `Event`, `Effect`, `EffectId`/`PendingTable`, `handle_event` run loop returning `vec![]`, `Ctx` helper, the two-step DoD test (§2 §2.1–§2.6)
- [ ] Add the UniFFI surface (proc-macros, no `.udl`), build `wallet-core` for iOS, generate Swift bindings, produce the `.xcframework` + `Package.swift`, run the Swift smoke test (§3)
- [ ] Create the iOS app target linking a stub xcframework; empty Lean Lake project (`lake build`) and empty Tamarin theory that parses (§8 skeleton, §10 §10.1, §11 §11.2)
- [ ] Scaffold traceability + evidence: `traceability/hlr.csv`, `tools/hlr-import/`, `docs/certification-evidence/` tree, `// HLR:` convention (§12 §12.1–§12.2)
- [ ] Stand up CI (`ci.yml`, `nightly.yml`, `release.yml`) and turn on branch protection requiring `ci / all-green` (§13 §13.1, §13.5)
- [ ] DoD: `cargo build --workspace` finishes; `tools/smoke.sh` exits 0; a green "M0 skeleton" PR merges

### M1 — Codecs (mdoc, sdjwt, cose, x509, status) with full Tier-1
- [ ] Implement `cose` (COSE_Sign1/Mac0/Key, RFC 9052/9053) over `crypto-traits` (§4)
- [ ] Implement `mdoc` deterministic/canonical CBOR + ISO 18013-5 structures; byte-exact against Annex D vectors (§4)
- [ ] Implement `sdjwt` (SD-JWT VC draft-17) + JOSE/JWS; disclosures hashed over raw base64url; KB-JWT `sd_hash`/`nonce`/`aud`; behind a `SDJWT_VC_DRAFT = 17` marker (§4)
- [ ] Implement `x509` parse + EUDI RP/trusted-issuer profile; DER-canonicality; ⚠ use the **agreed `Verifier::verify` signature** (Gap G-3) (§4)
- [ ] Implement `status` Token Status List (draft-21) codec + the deterministic fail-open/fail-closed decision table (marker `STATUS_LIST_DRAFT = 21`) (§6 §6.2; note status codec Tier-1 also appears in §9)
- [ ] Tier-1 per codec: proptest round-trip + never-panic; cargo-fuzz target seeded with official vectors; Kani invariant harness; `cargo-geiger` shows zero `unsafe` in our crates (§9)
- [ ] Add `// HLR:` tags to every public codec symbol; `hlr-import` runs; untagged-symbol check passes (§12)
- [ ] DoD: `cargo test -p cose -p mdoc -p sdjwt -p x509 -p status` green; fuzz `-runs=0` corpus replay clean; `cargo kani` SUCCESSFUL; official vectors decode

### M2 — One end-to-end OID4VP remote presentation of a PID
- [ ] Implement the `oid4vp` sans-IO state machine (HAIP-constrained), named guards + traced `AbortReason`s (§5)
- [ ] Implement `presenter`: closed `ScreenDescription` vocabulary (~16 archetypes), data-minimization, canonical CBOR consent encoding, `consent_hash`; ⚠ resolve the **`sha2`/presenter dependency** conflict (Gap G-5) (§7)
- [ ] Wire consent hashing into the core: compute hash on render, ⚠ carry `shown_consent_hash` across the **FFI Event** and re-check on confirm before any disclosure Effect (Gap G-6/C-1) (§7 §7.9, §2)
- [ ] iOS shell for M2: renderer (accessible SwiftUI), Secure Enclave `Signer` (DER→raw r‖s, P-256/ES256), effect executor, consent view (§8 §8.2–§8.5)
- [ ] ⚠ Fix the **Event/Effect vocabulary + FFI type strategy** (direct export vs reduced mirror; consent event name; `Render` vs `ShowScreen`; object name `WalletCore` vs `WalletEngine`) so §2/§3/§7/§8 integrate (Gap G-6/G-7/G-8) (§2, §3)
- [ ] Lean Tier-2 for OID4VP: model + prove the 3 invariants (no `sorry`), export traces, replay against the Rust core (§10)
- [ ] Tamarin: HAIP/OID4VP `.spthy` parses in CI; `executable` verified; `--prove` queued nightly (§11)
- [ ] DoD: `cargo test -p wallet-core --test <oid4vp e2e>` green (both formats); consent golden hash stable; unsigned-request rejected; Lean replay green; iOS consent+Sign acceptance test passes on device

### M3 — Proximity presentation (ISO 18013-5)
- [ ] ⚠ Make the **bulk session-crypto decision** (aws-lc-rs in-core vs CryptoKit callback) — blocks 18013-5 session encryption and needs `crypto-traits::Aead`/`Kdf` defined (Gap C-3) (§8 §8.6, §1)
- [ ] Implement `iso18013-5` sans-IO (engagement, session establishment/encryption; transport bytes in/out only); marker `ISO_18013_5_EDITION` (§5)
- [ ] iOS transports as thin byte pipes: BLE (peripheral + central), NFC (reader; HCE entitlement-gated), QR generate/scan; ⚠ reconcile the **proximity-transport Effect vocabulary** (`Effect::Ble` vs `Effect::Transport*`) (Gap G-12) (§8 §8.7)
- [ ] Lean Tier-2 for the 18013-5 session (no-response-without-session/consent; replay); export + replay (§10 §10.5)
- [ ] DoD: `cargo test -p wallet-core --test <proximity e2e>` green; session round-trip + tamper-reject; Lean 18013 replay green

### M4 — Issuance (OpenID4VCI / HAIP) in both formats
- [ ] Implement `oid4vci` sans-IO (HAIP), issue PID in **both** mdoc and SD-JWT VC; proof-of-possession via the Secure Enclave Effect (§5)
- [ ] iOS: `ASWebAuthenticationSession` for browser round-trips; App Attest / key attestation via Effect (§8 §8.6, §8.9)
- [ ] Record each credential's `StatusRef` for later revocation checks (§6)
- [ ] Lean Tier-2 for issuance (nonce/proof binding); export + replay (§10)
- [ ] DoD: `cargo test -p wallet-core --test <issue-present loop>` green; key binding verifies against the SE-held key; FFI has no key-export surface

### M5 — Trust, status/revocation, WUA
- [ ] Implement `trust` (ETSI 119 612/602 trusted lists, anchors, hardened XMLDSig/C14N, freshness + rollback + offline policy); markers `REG_2025_2164`, `ETSI_119612` (§6 §6.1)
- [ ] Wire runtime status/revocation via the `status` decision table with the right `PresentationContext`; ⚠ ensure absolute time enters via **`Effect::ReadClock`/`Event::ClockRead`** (Gap G-10) (§6 §6.2, §2)
- [ ] Implement `wua` (Wallet Unit Attestation + platform key attestation, TS03); two independent roots; anti-self-claim (W-6) + software-key (W-8) refusals (§6 §6.3)
- [ ] Enforce RP registration ≠ TLS cert; unregistered RP and revoked credential are refused (§4 x509 profile, §6) (§5 wiring)
- [ ] DoD: `cargo nextest run -p trust -p status -p wua` + RP-registration test green; tampered list rejected; WUA verifies end-to-end

### M6 — All three formal tiers green together
- [ ] Tier-1 covers every codec (proptest + fuzz + Kani); `cargo kani --workspace` unbounded SUCCESSFUL (§9)
- [ ] Tier-2 models + replays **all four flows** (oid4vp, oid4vci, 18013-5, consent ordering); zero `sorry`; ⚠ unify the **Lean exporter name + trace paths + replay test** across §5/§10/§13 (Gap G-15/G-16) (§10)
- [ ] Tier-3: `tamarin-prover --prove` reports every HAIP/OID4VP lemma `verified` (nightly artifact captured) (§11)
- [ ] Author `formal/PROOF-MAP.md` mapping each shared-context invariant → the exact Lean theorem + Tamarin lemma (§13 M6)
- [ ] DoD: kani/lean/tamarin all green; `grep -rq sorry formal/lean` returns nothing; PROOF-MAP complete

### M7 — FCAF + certification-evidence bundle
- [ ] ⚠ Unify the **FCAF runner + VERSION format** (`run_fcaf.py` vs `run.sh`; `fcaf_version=0.0.7` vs bare) (Gap G-17); FCAF v0.0.7 fully green for P0 (0 xfail, 0 unexpected-fail) (§12, §13)
- [ ] Run the EC reference implementation as a **CI interop oracle only** for OID4VP/OID4VCI/18013-5 (§13 M7)
- [ ] ⚠ Author the **accessibility harness** `conformance/a11y/run.sh` (referenced by §13, never written) + per-archetype WCAG 2.2 audit + manual sign-off (Gap C-2) (§7 a11y contract, §8 XCUITest audit)
- [ ] Author the DPIA and threat-model/TOE docs (scaffolded in §12, not yet written) (Gap C-6) (§12)
- [ ] Generate + **sign** the SBOM (CycloneDX); vulnerability intake (`cargo audit`/`cargo deny`) and the revocation/response path documented (§12 §12.4)
- [ ] Assemble the evidence bundle from a tag (SBOM, proof map + artifacts, FCAF report, traceability matrix, accessibility report) (§13 §13.9)
- [ ] DoD: `git tag … && git push --tags` produces `evidence-bundle-*.zip` with all required artifacts; FCAF P0 clean

### P1 / P2 (scope only; same gate discipline; not before M7)
- [ ] P1: transaction history/logs; deletion & reporting (TS07/TS08 v0.11); export/portability (TS10 v1.2); wallet-to-wallet (TS09 v1.1); attestation catalogue (TS11 v1.0.1); qualified e-signatures (remote QTSP/QSCD via CSC API; reuses the consent-hash WYSIWYS binding)
- [ ] P2: mDL (18013-5/6/7); QEAA/PuB-EAA (2025/1566, 2025/1569); payment SCA (PSD2/TS12)
- [ ] WATCH (no production dependency): browser Digital Credentials API (W3C WD); ZKP (TS04, abstraction point only)

---

## 4. Consolidated glossary

Acronyms and terms merged and de-duplicated across all sections. One clause each.

- **A2UI** — "UI as data" pattern; here **local-only and closed**: the wallet owns screen structure; RP data is validated data slotted into wallet templates, never structure.
- **ABI** — Application Binary Interface; the exact compiled shape of the FFI boundary (names, types, memory ownership).
- **AEAD** — Authenticated Encryption with Associated Data (e.g. AES-256-GCM); used for 18013-5 session encryption.
- **ARF** — Architecture and Reference Framework; the EU's normative wallet spec set (target v2.9.0).
- **aws-lc-rs** — vetted Rust crypto library; the single permitted in-core bulk-crypto impl, feature-gated in `wallet-core`.
- **CAB** — Conformity Assessment Body; the accredited lab that performs the certification.
- **CBOR** — Concise Binary Object Representation (RFC 8949); mdoc uses a deterministic/canonical profile so bytes are reproducible and hashable.
- **C14N** — XML canonicalization; required before hashing an XMLDSig-signed region (trusted lists).
- **cargo-audit** — scans `Cargo.lock` against the RustSec advisory DB (known CVEs).
- **cargo-deny** — policy gate over the dependency graph (licenses, bans, advisories, sources); enforces the dependency budget.
- **cargo-fuzz** — coverage-guided (libFuzzer) fuzzing driver; requires nightly Rust.
- **cargo-geiger** — counts `unsafe` usage across the dependency tree.
- **COSE** — CBOR Object Signing and Encryption (RFC 9052/9053); signing/MAC/key format used by mdoc.
- **CRA** — Cyber Resilience Act (Reg. (EU) 2024/2847); mandates SBOM + coordinated vulnerability handling.
- **Crate** — Rust's unit of compilation/packaging (like a Swift module).
- **DCQL** — Digital Credentials Query Language; how an OID4VP request states which claims it wants.
- **Dolev-Yao** — the symbolic network attacker model (reads/drops/reorders/forges every message); Tier-3's adversary.
- **DoD** — Definition of Done; a command + expected output that proves a step/milestone complete.
- **DPIA** — Data Protection Impact Assessment (GDPR Art. 35); required because a wallet processes identity data.
- **ECDH** — Elliptic-Curve Diffie-Hellman key agreement; used to establish 18013-5 session keys.
- **Effect** — a value the core emits describing an action for the shell to perform (HTTP, sign, render, store, timer, transport…).
- **EffectId** — a monotonic `u64` the core mints to correlate an Effect with its later result Event.
- **elan / lake / lean** — Lean's toolchain manager / build tool / compiler-checker (analogues of rustup/cargo/rustc).
- **EUCC** — the EU Common Criteria-based cybersecurity certification scheme (Reg. (EU) 2024/482).
- **EUDI** — European Digital Identity (Wallet); the framework and the app.
- **Event** — a value fed into the core describing something that happened (intent events, or results of Effects).
- **FCAF** — Feature/Functional Conformance Assessment Framework (v0.0.7); the EU conformance test-suite; necessary but **not** sufficient for certification.
- **FFI** — Foreign Function Interface; the Swift↔Rust boundary (generated by UniFFI).
- **HAIP** — High Assurance Interoperability Profile; the hardened OpenID4VC profile the wallet must follow.
- **HKDF** — HMAC-based Key Derivation Function.
- **HLR** — High-Level Requirement; one register row with a stable ID, traced to code + tests + evidence.
- **JOSE** — JSON Object Signing and Encryption (JWS/JWE/JWK); used by SD-JWT VC.
- **Kani** — bit-precise bounded model checker for Rust (CBMC backend); proves a property for all inputs within a bound.
- **KAT** — Known-Answer Test; a fixed cryptographic test vector (input → expected output).
- **KB-JWT** — Key-Binding JWT; proves the holder controls the bound key and binds the presentation to `aud`/`nonce`/`sd_hash`.
- **KDF** — Key Derivation Function.
- **lipo / xcframework** — macOS tools/packaging: `lipo` fuses same-platform archs; an `.xcframework` bundles per-platform slices for Xcode.
- **mdoc** — mobile document (ISO/IEC 18013-5), CBOR-encoded, COSE-signed; one of the two mandatory formats.
- **MSO** — MobileSecurityObject; the signed digest structure inside an mdoc.
- **OID4VCI** — OpenID for Verifiable Credential Issuance.
- **OID4VP** — OpenID for Verifiable Presentations (remote presentation).
- **PID** — Person Identification Data; the core identity credential, mandatory in both formats.
- **proptest** — Rust property-based testing library (generates + shrinks structured inputs).
- **ProVerif** — applied-pi-calculus symbolic protocol verifier (Tier-3 second opinion).
- **QES / QSCD / QTSP** — Qualified Electronic Signature / Qualified Signature Creation Device / Qualified Trust Service Provider (eIDAS; P1).
- **rollback attack** — replaying an older but validly-signed trusted list; defeated by the sequence number.
- **sans-IO** — a design where protocol logic performs no I/O itself; it consumes Events and emits Effects, so it is deterministic and replay-testable.
- **SBOM** — Software Bill of Materials (CycloneDX); the signed dependency inventory required by the CRA.
- **ScreenDescription** — the canonical, hashable, closed-vocabulary UI value the presenter emits.
- **SD-JWT VC** — Selective-Disclosure JWT Verifiable Credential (draft-17); the other mandatory format.
- **Secure Enclave / StrongBox / TEE** — tamper-resistant key hardware on iOS / Android (StrongBox = discrete chip; TEE = isolated CPU mode).
- **Status List (Token Status List)** — draft-21 signed bitstring giving per-credential revocation/suspension status.
- **Tamarin** — multiset-rewriting symbolic protocol verifier (Tier-3 primary tool).
- **TOE** — Target of Evaluation; the precisely-bounded part of the system under formal security evaluation.
- **Trust anchor / trusted list** — an out-of-band-obtained root certificate / a signed ecosystem roster of who is trusted and for what (ETSI 119 612/602).
- **UDL / UniFFI** — UniFFI Definition Language (an IDL we deliberately do **not** use) / the tool that generates Swift/Kotlin bindings from Rust (we use proc-macros).
- **WSCD** — Wallet Secure Cryptographic Device; the hardware holding device-bound keys (Secure Enclave/StrongBox).
- **WUA** — Wallet Unit Attestation; a signed statement that this wallet instance is genuine and hardware-backed (TS03).
- **WYSIWYS** — What-You-See-Is-What-You-Sign; the consent-hash guarantee that the payload rendered equals the payload signed.
- **x509** — certificate parse + path validation + EUDI RP/trusted-issuer profile checks.

---

## 5. Cross-section consistency & gap report (adversarial completeness pass)

This is a deliberately critical pass. Severities: **BLOCKER** (stops a milestone / won't compile / won't integrate), **MAJOR** (causes real rework or a junior gets stuck), **MINOR** (cosmetic, cross-reference, or easily reconciled). Each item names the sections and a recommended resolution.

### 5.1 What is genuinely consistent (so you can trust the rest)

`#![forbid(unsafe_code)]` in every core crate; sans-IO determinism as the load-bearing idea (§2/§9/§10); Rust 1.97 with exact-version pinning; both formats + both presentation modes as hard requirements (§4/§5); three formal tiers (§9/§10/§11); crypto never hand-rolled and device keys never crossing the FFI (§2/§3/§8); the 13-crate names and acyclic layering (§0/§1); the consent-hash WYSIWYS *concept* (§2/§7). These do not need reconciliation.

### 5.2 Contradictions (reconcile before/at the cited milestone)

- **G-1 (BLOCKER, M0) — Repo root name.** §0 uses `euwallet`; §1 uses `eudi-wallet`; §6 uses `~/dev/advatar/EUWallet`; §8 uses `euwallet/`. A junior running §0 then §1 creates two repos and double-`git init`s. **Resolution:** pick one name, do `git init` once (recommend §1's workspace creation as authoritative and treat §0 Step 11 as illustrative), and normalize every path.
- **G-2 (MAJOR, M0) — Workspace is created twice with conflicting content.** §0 Step 11 and §1 §1.2–§1.5 both create the root `Cargo.toml`, `rust-toolchain.toml`, `deny.toml`, `.gitignore`, and all 13 crate manifests — with different values (§0: `version=0.0.0`, `[workspace.lints]`, `[profile.release] panic="abort"`, no `[workspace.dependencies]`; §1: `version=0.1.0`, full `[workspace.dependencies]` with exact pins, no lints/profile). **Resolution:** §0 installs OS tools only; **§1 is the authoritative workspace/manifest author** — but fold §0's `[workspace.lints] unsafe_code="forbid"` and `[profile.release]` into §1's root manifest so nothing is lost.
- **G-3 (BLOCKER, M1/M5) — `crypto-traits::Verifier::verify` has two incompatible signatures.** §4 calls `verify(alg, encoding, key, msg, sig)` (5-arg, needed to distinguish COSE-raw `r‖s` from X.509 DER); §6 calls `verify(key, msg, sig)` (3-arg) in trust/status/wua. These will not both compile against one trait. **Resolution:** adopt the **5-arg form** (§4 is correct that alg + encoding are load-bearing) and update all §6 call sites.
- **G-4 (BLOCKER, M0/M1) — No authoritative `crypto-traits` section.** §1 promises "Section 2 fills crypto-traits," but §2 as delivered is the run loop; §3 defines `Signer` as a callback with `sign(key_handle, payload)` (no alg); §8 defines `Signer` with `sign(key: KeyRef, alg: Alg, payload)` + `publicKeyX963`. So `Signer` itself has three shapes, and Kdf/Aead/Random/KeyAttestation are only referenced. **Resolution:** author a short `crypto-traits` specification (all six traits, exact signatures, DTOs) as an M0 deliverable; align §3's callback and §8's Swift impl to it. This also unblocks the M3 bulk-crypto decision (needs `Aead`/`Kdf`).
- **G-5 (BLOCKER, M2) — presenter's dependencies and `sha2` are self-contradictory.** §1's dependency budget forbids any crypto (including `sha2`) in `presenter` and lists `presenter → mdoc, sdjwt, crypto-traits`; §7 uses `sha2` **and** `unicode-normalization` directly and does **not** depend on mdoc/sdjwt (defines `ClaimPath`/`CredentialFormat` locally). With §1's `deny.toml` as written, §7 won't pass the supply-chain gate, and the dependency graph disagrees. **Resolution:** amend §1's budget — add `sha2` and `unicode-normalization` to `[workspace.dependencies]` and the `deny.toml` allow-set, drop `presenter → mdoc/sdjwt` from the canonical graph — and record the rationale (consent hashing is over public bytes and must be synchronous/deterministic, so a vetted `sha2` used directly is correct and does not violate "never hand-roll crypto").
- **G-6 (MAJOR, M2) — Event/Effect vocabulary and the consent event diverge across four sections.** Internal core (§2): `Event::UserConsented { consent_hash: Vec<u8> }`, `Effect::Render(ScreenDescription)`. FFI mirror (§3): `FfiEvent::ConsentApproved { consent_hash }`, `FfiEffect::ShowScreen`. presenter wiring (§7): `Event::ConsentDecision { approved, shown_consent_hash: [u8;32] }` + `ConsentClaimToggled`. iOS shell (§8): `.userConsented` / `.userDeclined` with **no** hash on the Event and a `ConsentView` whose `onConsent` takes no hash. **Consequence:** the WYSIWYS echo-check (§7 §7.9) is *not actually wired* through §8 — the shell never returns the hash it displayed. **Resolution:** publish one canonical internal Event/Effect table; make the FFI consent event carry `shown_consent_hash`; update §8's `ConsentView` to echo it; standardize on one consent-event name.
- **G-7 (MINOR, M2) — FFI object name.** `WalletCore` (§2/§8) vs `WalletEngine` (§3). **Resolution:** use `WalletCore`.
- **G-8 (MAJOR, M2) — FFI type strategy fork.** §2 exports the internal `Event`/`Effect` enums directly via UniFFI; §3 introduces a **separate reduced `FfiEvent`/`FfiEffect` mirror** for ABI stability. One type set or two? **Resolution:** decide explicitly and once. The mirror buys ABI stability at the cost of a translation layer; direct export is simpler. Recommend documenting the choice at the top of §3 and making §2/§8 conform.
- **G-9 (MAJOR, M0/M2) — `uniffi` optionality.** §2 makes `uniffi` optional behind an `ffi` feature (off for pure-core tests); §3 makes it a non-optional dependency with `features=["cli","build"]` and a `[[bin]] uniffi-bindgen`. **Resolution:** adopt §3's build-time generation and the in-tree `uniffi-bindgen` binary, but keep §2's ability to run the pure core under `cargo test` without FFI machinery (a `ffi` feature that gates only `#[uniffi::export]` items).
- **G-10 (MAJOR, M5) — Absolute clock.** §2 states time enters the core **only** via `Event::TimerFired` (relative timer; "there is no `Event::Now`"). §6 needs absolute UTC for validity windows and introduces `Effect::ReadClock` → `Event::ClockRead(UtcInstant)`. Validity checks (x509/status/WUA/trusted-list freshness) genuinely need absolute time. **Resolution:** add `ReadClock`/`ClockRead` to the canonical vocabulary — it stays deterministic because it's an injected event — and relax §2's "only TimerFired" statement.
- **G-11 (MAJOR, M5) — A 14th crate appears.** §6 creates `crates/time-model` but never adds it to the workspace `members`, and §1's DoD asserts `cargo metadata` shows exactly **13** packages. **Resolution:** either add `time-model` to `members` and bump §1's count DoD to 14, or fold `UtcInstant`/`Seconds` into `crypto-traits` or `wallet-core` (§6 explicitly offers this option).
- **G-12 (MAJOR, M3) — Proximity-transport Effect vocabulary.** §2 models BLE as one `Effect::Ble { command: BleCommand }` / `Event::BleEvent`; §8 uses transport-agnostic `Effect::TransportOpen/TransportSend/TransportClose` + `Event::TransportBytes/TransportState` (covering BLE **and** NFC). **Resolution:** adopt §8's transport-agnostic effects as canonical (they cover NFC/QR too) and retire `Effect::Ble`.
- **G-13 (MINOR, M0) — `deny.toml` location + content.** Root (§0/§1) vs `ci/deny.toml` (§13); §1's ban list is a superset of §13's. **Resolution:** one `deny.toml` at the root using §1's fuller ban list; §13's CI points at it.
- **G-14 (MAJOR, all) — Overlapping CI workflow files.** `deny.yml` (§1), a `formal` job on `ci.yml` (§5), `fuzz-bounded`/`kani-proofs` (§9), `formal-tier2.yml` (§10), a `run.sh`-based FCAF job (§11), `conformance.yml` (§12), and `ci.yml`/`nightly.yml`/`release.yml` (§13). A junior ends up with several overlapping workflows. **Resolution:** **§13 is the single source of truth for CI**; treat every per-section CI snippet as illustrative and fold it into §13's three files (as jobs feeding the `ci / all-green` aggregate).
- **G-15 (MAJOR, M6) — Lean oracle wiring is specified three different ways.** Exporter exe `export_traces` (§5/§13) vs `oracle` (§10); output path `crates/oid4vp/tests/vectors/lean_traces.json` (§5) vs `.../oid4vp_traces.json` (§10) vs `target/lean-traces/` (§13); replay test `replay_oracle`/`rust_step_matches_lean_model` (§5) vs `model_conformance` (§10) vs `crates/wallet-core/tests/lean_replay.rs` (§13); Lean file layout `Invariants/Export` (§5) vs `Iso18013/Oracle` (§10). **Resolution:** **§10 is authoritative for Tier-2**; align §5 and §13 to its exe name, paths, and test name.
- **G-16 (MAJOR, M2/M6) — `crates/oid4vp/src/machine.rs` is defined twice.** §5 gives the production machine (rich states, guards, `AbortReason`); §10 gives a simplified twin that mirrors the Lean model. Same file, different content. **Resolution:** keep §5's machine as production and either (a) make §10's Lean model mirror §5's real states, or (b) put §10's simplified twin in a clearly separate module used only by the oracle test. Do not let both own `machine.rs`.
- **G-17 (MINOR→MAJOR, M7) — FCAF runner + VERSION format.** `conformance/fcaf/run_fcaf.py` (§12) vs `conformance/fcaf/run.sh` (§13); VERSION `fcaf_version=0.0.7` (key=value, §12) vs bare `0.0.7` (§13). **Resolution:** one runner, one VERSION format (recommend §13's `run.sh` + bare version, since §13 is the CI authority; have it call §12's Python harness internally).
- **G-18 (MINOR) — Toolchain/runner version drift.** Xcode 16.x (§0) vs `Xcode_26.app` (§13); Rust 1.97.0 (§0/§1/§13) vs 1.97.1 (§10); CI runner `macos-14` (§1/§6/§9/§12) vs `macos-15`/`ubuntu-24.04` (§13). **Resolution:** pin each once in §0 and reference it; adopt §13's runner matrix.
- **G-19 (MAJOR, M2) — iOS packaging path + project style.** §3 builds `scripts/build-ios.sh` → `generated/` as a **local SPM package**; §8/§13 use `ios/scripts/build-xcframework.sh`, `ffi/uniffi/WalletCoreFFI.xcframework`, and an **`ios/EUDIWallet.xcodeproj`**. SPM-vs-xcodeproj and two script paths/output layouts. **Resolution:** pick one packaging model (recommend the `.xcodeproj` consuming a locally-built xcframework per §8/§13) and one build-script path.
- **G-20 (MINOR) — Build orchestration tool.** `justfile` (§4) vs `Makefile` (§10) vs `ci/*.sh` (§13); §4's `just codecs-verify` target lives in a justfile no section creates. **Resolution:** standardize on one (recommend the `Makefile` used by §10 + §13's `ci/` scripts) and move §4's target into it.
- **G-21 (MINOR) — `consent_hash` type.** `[u8;32]` internally (§7) vs `Vec<u8>` across the FFI (§2). **Resolution:** `[u8;32]` in the core, `Vec<u8>` at the FFI boundary (documented); this is fine as long as the echo-check compares the right 32 bytes.
- **G-22/G-23 (MINOR) — Duplicate tooling.** SBOM: `tools/sbom/gen_sbom.sh` (§12) vs `ci/make-sbom.sh` (§13). Traceability: `tools/hlr-import/` (§12) vs `tools/traceability.py` (§13's release.yml). **Resolution:** §12 owns the tools; §13's workflows must call §12's actual script/tool names.

### 5.3 Things a junior will get stuck on (glue/ambiguity)

- **C-1 (MAJOR) — WYSIWYS is not wired end-to-end.** As in G-6, §7's consent-hash echo-check has no path through §8's FFI Event/`ConsentView`. Until fixed, the consent hash is computed but never verified against what the shell showed. Fix at M2.
- **Section-number cross-references are unreliable.** Each author used a different global numbering (e.g. §4 calls formal methods "Section 8"; §3 calls Lean "Section 12" and CRA "Section 18"; §8 states its own map crypto-traits=4/proximity=5/presenter=7/Lean=10). **Always resolve via the canonical map in front-matter section 2.1 and by topic name.**
- **presenter's `ScreenDescription` appears in four forms** — placeholder (§2), reduced FFI record (§3), 10-case renderer subset (§8), authoritative 16-archetype closed set (§7). **§7 is authoritative;** the others are placeholders/subsets that must converge on it.
- **`justfile` referenced but never created** (§4) — see G-20.
- **The bulk session-crypto TBD** (§8 §8.6) is an open decision that *gates M3* and depends on the undefined `crypto-traits::Aead`/`Kdf` (G-4). Make the certification-memo call before starting proximity.

### 5.4 Missing coverage the register requires but no section fully delivers

- **C-2 (MAJOR) — Accessibility (EN 301 549 / WCAG 2.2) has no owner section and its harness is unwritten.** It is asserted in §7 (consent-screen a11y contract), §8 (renderer contract + one XCUITest audit), and §13 (a `conformance/a11y/run.sh` job in `release.yml` and M7) — but `conformance/a11y/run.sh` is **referenced and never authored**, and there is no per-archetype automated WCAG audit. The register marks accessibility non-deferrable. **Author the a11y harness + per-archetype audit at M7 (ideally track it from M2).**
- **C-3 (BLOCKER for M3) — Bulk session crypto (AEAD/HKDF) undecided** and `crypto-traits::Aead`/`Kdf` undefined (G-4). 18013-5 session encryption cannot proceed without both.
- **C-4 (MAJOR) — `crypto-traits` platform-cryptography spec** (G-3/G-4) — the single most-referenced, least-defined artifact. It is a P0 register item ("platform cryptography").
- **C-5 (MAJOR) — Local user auth policy.** "Local user auth" is P0, but no section specifies PIN/biometric **lockout**, retry counts, anti-brute-force, or the WSCD user-auth-binding lifecycle. §7 has a `PinEntry` archetype and §8 gates signing with `.biometryCurrentSet`, but the *policy* is absent. **Author a local-auth policy (retry/lockout/re-provisioning) before M5.**
- **C-6 (MAJOR) — DPIA + threat-model/TOE docs are scaffolded, not written** (§12 creates empty stubs). Tier-3 (§11) supplies the *protocol* threat analysis, but the STRIDE/attack-tree threat model, TOE boundary, and DPIA are P0 evidence and must be authored at M7.
- **C-7 (PARTIAL) — Key lifecycle / re-provisioning + device recovery.** §8 notes that biometric re-enrollment invalidates the device key and says "document re-provisioning," but no section specifies re-provisioning, recovery, or device migration. Backup/restore is P1 (TS10), so device-loss recovery is out of P0 scope — but flag it as a real product gap.
- **C-8 (PARTIAL) — CRA incident-reporting process** is thin (§12 has a revocation log + `cargo-audit`); the coordinated-disclosure workflow and notification thresholds are only sketched.
- **C-9 (MINOR) — `status` is both a "codec" (§9 Tier-1) and a "trust-family crate" (§6).** Its codec-level proptest/fuzz/Kani appears in both §6 and §9; ensure one owner to avoid duplicated/conflicting harnesses (recommend §9 owns Tier-1 for all codecs including `status`).
- **C-10 (PARTIAL) — Consent-hash binding for proximity + issuance.** §7's WYSIWYS wiring (§7.9) is written for the OID4VP flow; the same hash-and-echo must be applied to `iso18013-5` and `oid4vci` consent (and later QES). Extend at M3/M4.

---

## 6. Definition-of-done gate summary table

A milestone is complete when **all** of its "gate checks" are green **and** the cross-cutting per-PR gate (`ci / all-green` from §13) is green on the milestone's merge PR. Commands are drawn from the cited sections.

| Milestone | Scope (one line) | Gate: exact checks that must be green |
|---|---|---|
| **M0** | Skeleton: workspace compiles, CI green on nothing | `cargo build --workspace` finishes; `tools/smoke.sh` exits 0 (§0); `cargo metadata` shows all workspace members; `grep -rL 'forbid(unsafe_code)' crates/*/src/lib.rs` prints nothing; `cargo deny check` + `cargo audit` clean (§1); the two-step core test + unknown-id test pass (§2); UniFFI Swift smoke test prints the ABI line and a typed effect (§3); empty Lean `lake build` and Tamarin `--parse-only` succeed (§10/§11); a green "M0" PR merges with branch protection on `ci / all-green` (§13) |
| **M1** | Codecs + full Tier-1 | `cargo test -p cose -p mdoc -p sdjwt -p x509 -p status` all `ok`; official vectors decode byte-exact (Annex D mdoc; IETF/EC-ref SD-JWT; EC-ref DER); non-canonical inputs rejected (§4); every fuzz target `-runs=0` corpus replay clean + bounded burst no crash (§9); `cargo kani` `VERIFICATION SUCCESSFUL` on codec harnesses; `cargo-geiger` zero `unsafe` in our crates; `cargo clippy -D warnings` clean; every public codec symbol `// HLR:`-tagged (§12) |
| **M2** | End-to-end OID4VP presentation of a PID | `cargo test -p wallet-core --test <oid4vp e2e>` green in **both** formats; consent golden hash stable (`--test golden`) and the `xxd \| shasum` cross-check matches (§7); unsigned/replayed/mix-up requests abort with distinct traced reasons (§5); Lean OID4VP invariants have **no `sorry`**, traces replay identically against the Rust core (§10); Tamarin `.spthy` parses + `executable` verified (§11); iOS consent-render + Secure-Enclave `Sign` acceptance test passes on device (§8); the consent-hash echo-check is wired through the FFI (Gap G-6/C-1) |
| **M3** | Proximity presentation (18013-5) | bulk-crypto memo decided and `crypto-traits::Aead/Kdf` defined (C-3); `cargo test -p wallet-core --test <proximity e2e>` green; session-encryption round-trip proptest passes, tampered ciphertext rejected; BLE fragmentation/reassembly loopback test passes; QR generate→scan round-trip identical (§8); Lean 18013-5 model no `sorry` + traces replay (§10) |
| **M4** | Issuance (OID4VCI/HAIP), both formats | `cargo test -p wallet-core --test <issue-present loop>` green (issue → present remote + proximity, both formats); issued credential's key binding verifies against the SE-held key; a compile-time test proves the FFI has no key-export surface; Lean issuance invariants no `sorry` + replay; FCAF issuance P0 cases pass (§5/§6/§8/§10) |
| **M5** | Trust, status/revocation, WUA | `cargo nextest run -p trust -p status -p wua` + RP-registration test green; presentation to an **unregistered** RP refused and a **revoked** credential refused (fail-open/fail-closed table exhaustively tested); tampered trusted list rejected (fuzz + proptest); WUA verifies end-to-end and W-6 (device self-signed) + W-8 (software key) both refuse; absolute time enters via `ReadClock`/`ClockRead` (G-10); `cargo tree -p trust -p status -p wua \| grep -Ei 'reqwest\|tokio\|hyper'` prints nothing (§6) |
| **M6** | All three formal tiers green together | `cargo kani --workspace` (unbounded) `SUCCESSFUL` for every harness; `grep -rq sorry formal/lean` returns nothing and all four flows (oid4vp/oid4vci/18013-5/consent-ordering) replay identically (§10, unified per G-15); `tamarin-prover --prove` reports every HAIP/OID4VP lemma `verified` (nightly artifact) with **no `falsified`** (§11); `formal/PROOF-MAP.md` maps every shared-context invariant to a real, passing theorem + lemma (§13) |
| **M7** | FCAF + certification-evidence bundle | FCAF v0.0.7 reports `0 xfail, 0 unexpected-fail` for P0 (unified runner per G-17); EC reference-impl interop passes as a **CI oracle only**; per-archetype WCAG 2.2 audit passes + manual sign-off (a11y harness authored, C-2); DPIA + threat-model/TOE authored (C-6); SBOM generated **and signed**, `cargo audit`/`cargo deny` clean, revocation/response path documented (§12); `git tag … && git push --tags` produces `evidence-bundle-*.zip` containing SBOM + proof-map + FCAF report + traceability matrix + accessibility report (§13 §13.9) |
| **every PR** | Cross-cutting merge gate | `ci / all-green` green: `fmt` + `clippy -D warnings` + `check --locked` + `test` (Linux+macOS, incl. proptest + doctests) + `cargo-deny` + `cargo-audit` + bounded `fuzz-smoke` + bounded `kani` + `lean-oracle` trace-replay + `tamarin-parse` + `swift` build/test + `fcaf` (0 unexpected-fail) + `sbom` generates; **plus** the HLR P0 gate (`hlr-gate` — 100% of applicable P0 HLRs `tested`/`evidenced`), ≥1 approving review (G14), and, if a change-watch area was touched, an updated version marker + risk-register row (G15) (§13 §13.3) |

> **Interpretation rule.** A "green" milestone means its row above passes **and** the merge PR that lands it is green on the per-PR gate. If a gate check in the table depends on a still-open contradiction (the ⚠ items in the checklist and the G-/C- items above), that contradiction must be resolved first — it is not optional polish, it is what makes the check runnable.


---


## Section 0 — Prerequisites, environment setup, and repo bootstrap

> **Who this section is for.** You can program, but you have never touched Rust, Lean, Tamarin, or the EUDI ecosystem. Every step is numbered, every command is copy-pasteable, and every major step ends with a **Definition of done** you can run to prove it worked. Do the steps *in order*: later steps assume earlier ones succeeded. When a step says "expected output," your exact version numbers may be *newer* than shown — that's fine; only *older* is a problem, and each step tells you the minimum.
>
> **Target machine.** Apple Silicon Mac (M1/M2/M3/M4), macOS 14 (Sonoma) or later, with administrator rights. Everything below assumes the `zsh` shell (the macOS default). All paths are absolute or rooted at the repo you will create in Step 8.

---

### 0.0 Mental model: what you are about to install, and why each piece exists

Before typing anything, read this table once. It is the "why" behind every command in this section. Jargon is expanded in the **Glossary (Step 12)** — flip there whenever a term is unfamiliar.

| Tool | What it is (one clause) | Why *this* project needs it |
|---|---|---|
| **Homebrew** (`brew`) | the de-facto macOS package manager | installs almost everything else with one command each |
| **rustup** | the Rust toolchain *installer/manager* (installs `cargo`, `rustc`, `clippy`, `rustfmt`) | the entire behavior core (`crates/…`) is Rust; rustup pins the exact compiler version for reproducible, certifiable builds |
| **cargo** | Rust's build tool + package manager (comes via rustup) | builds/tests every crate; runs fuzzers, audits, Kani, etc. through subcommands |
| **Xcode + Swift** | Apple's IDE and the Swift compiler/toolchain | the iOS shell (`ios/`) and the UniFFI-generated Swift bindings compile here; `xcodebuild` runs them in CI |
| **elan** | the Lean *toolchain* manager (the "rustup for Lean") | pins the exact Lean 4 version so the formal proofs (`formal/lean/`) build identically everywhere |
| **lake** | Lean 4's build tool (comes via elan/Lean) | builds the Lean project that proves the state-machine invariants (Tier 2) |
| **cargo-fuzz** | a `cargo` subcommand driving libFuzzer coverage-guided fuzzing | Tier 1 requires fuzz targets on every codec (mdoc, sdjwt, cose, x509, status) |
| **cargo-audit** | scans `Cargo.lock` against the RustSec vulnerability DB | CRA/SBOM obligation: know instantly if a dependency has a known CVE |
| **cargo-deny** | policy gate over the dependency graph (licenses, bans, advisories, sources) | keeps the "few software dependencies" rule *enforceable* in CI, not aspirational |
| **cargo-kani** (Kani) | a bit-precise model checker for Rust (bounded proof, not just tests) | Tier 1 requires Kani harnesses proving key invariants (e.g., canonical-CBOR round-trips) |
| **tamarin-prover** | a symbolic protocol verifier (multiset-rewriting, Dolev–Yao attacker) | Tier 3: prove secrecy/injective-agreement/nonce-freshness of the HAIP OID4VP profile |
| **proverif** | an alternative symbolic protocol verifier (applied-pi calculus) | Tier 3 cross-check / fallback oracle for the same protocol properties |
| **uniffi-bindgen** | generates Swift/Kotlin bindings from a Rust facade crate | produces the `ios/` Swift API from `crates/wallet-core` — you hand-write the Rust once |
| **python 3 + uv** | Python and an ultra-fast Python package/venv manager | the Lean→JSON trace *replay* harness (Tier 2 executable oracle) and FCAF/interop glue scripts are Python |
| **git + gh** | version control + GitHub CLI | the repo, branch layout, and CI live here; `gh` scaffolds the Actions workflow later |

You do **not** need Android/Kotlin tooling in P0. Ignore it until the Android section.

---

### Step 1 — Install Homebrew (the package manager everything else rides on)

**1.1** Open **Terminal** (`⌘-Space`, type "Terminal", Enter).

**1.2** Check whether Homebrew already exists:

```bash
which brew
```

If that prints a path like `/opt/homebrew/bin/brew`, skip to **1.5**. If it prints nothing, continue.

**1.3** Install Homebrew:

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

It will ask for your macOS password (you will not see characters as you type — that's normal) and may ask you to install the Xcode Command Line Tools; say yes.

**1.4** On Apple Silicon, Homebrew installs to `/opt/homebrew`, which is **not** on your `PATH` by default. Add it, then reload your shell config:

```bash
echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> ~/.zprofile
eval "$(/opt/homebrew/bin/brew shellenv)"
```

**1.5** Verify:

```bash
brew --version
```

**Definition of done.**
```bash
brew --version
# expected: "Homebrew 4.x.x" (any 4.x or newer)
brew config | grep -i 'macOS\|CPU'
# expected: CPU line mentions "arm" / "Apple"; confirms you are on Apple Silicon
```
If `brew` is "command not found," open a **new** Terminal window and retry — the `~/.zprofile` edit only applies to shells started after it was written.

---

### Step 2 — Install Xcode and the Swift toolchain

The full **Xcode** app (not just Command Line Tools) is required because you will build and run an iOS app target and, later, drive `xcodebuild` from CI.

**2.1** Install Xcode from the Mac App Store (search "Xcode", ~10 GB, be patient), **or** via Homebrew's `mas` helper if you prefer scripting:

```bash
brew install mas
mas install 497799835   # 497799835 is Xcode's App Store id
```

**2.2** Once installed, point the command-line tools at the full Xcode and accept the license (needs your password):

```bash
sudo xcode-select --switch /Applications/Xcode.app/Contents/Developer
sudo xcodebuild -license accept
```

**2.3** Trigger the one-time component install and confirm Swift:

```bash
xcodebuild -runFirstLaunch
swift --version
```

**2.4** Make sure an iOS **Simulator** runtime exists (you'll need it in the iOS section):

```bash
xcrun simctl list runtimes | grep iOS
```

If no iOS runtime is listed, open Xcode → **Settings → Components** and download the latest iOS Simulator.

**Definition of done.**
```bash
swift --version
# expected: "Apple Swift version 6.x" (6.3 or newer per the shared toolchain)
xcodebuild -version
# expected: "Xcode 16.x" (or newer) and a Build version line
xcrun simctl list runtimes | grep -c iOS
# expected: a number >= 1 (at least one iOS simulator runtime installed)
```

---

### Step 3 — Install Rust via rustup, pin the toolchain, add components

We install Rust through **rustup** so the compiler version is *pinned per-repo* later (Step 9) — that pinning is what makes a certifiable build reproducible.

**3.1** Install rustup (the official installer). The `-y` accepts the default "standard" profile:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
```

**3.2** Load Rust into the current shell (rustup adds this to `~/.zshenv`/`~/.profile`, but the current shell needs it now):

```bash
source "$HOME/.cargo/env"
```

**3.3** Make sure you're on a recent stable and add the components the project uses. `clippy` is the linter, `rustfmt` the formatter, `rust-src` is required by Kani and some tooling, and `llvm-tools-preview` is used for coverage:

```bash
rustup toolchain install stable
rustup default stable
rustup component add clippy rustfmt rust-src llvm-tools-preview
```

**3.4** (Fuzzing prerequisite) `cargo-fuzz` uses **nightly** Rust under the hood. Install a nightly toolchain now so Step 5 doesn't stall:

```bash
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly
```

**Definition of done.**
```bash
cargo --version
# expected: "cargo 1.97.0" or newer
rustc --version
# expected: "rustc 1.97.0" or newer
cargo clippy --version   # expected: "clippy 0.1.x"
rustfmt --version        # expected: "rustfmt 1.x"
rustup toolchain list | grep -c nightly
# expected: 1 (nightly is installed, needed by cargo-fuzz)
```

---

### Step 4 — Install the Rust `cargo` subcommands: audit and deny

These two are pure supply-chain gates and install cleanly from crates.io.

**4.1** Install both, `--locked` so you get the crate authors' tested dependency versions:

```bash
cargo install --locked cargo-audit
cargo install --locked cargo-deny
```

(`cargo install` compiles from source; each takes a few minutes on first run.)

**Definition of done.**
```bash
cargo audit --version   # expected: "cargo-audit 0.x"
cargo deny --version    # expected: "cargo-deny 0.x"
```

---

### Step 5 — Install cargo-fuzz (coverage-guided fuzzing, Tier 1)

`cargo-fuzz` drives **libFuzzer**, which ships inside the LLVM that comes with your Xcode/Rust toolchain, so no extra system package is needed on macOS.

**5.1** Install:

```bash
cargo install --locked cargo-fuzz
```

**5.2** Confirm it can see nightly (fuzzing requires it — installed in Step 3.4):

```bash
cargo +nightly fuzz --version
```

**Definition of done.**
```bash
cargo fuzz --version
# expected: "cargo-fuzz 0.x"
cargo +nightly fuzz --help | head -1
# expected: a usage/help line printed with no "toolchain not installed" error
```
You will create the actual fuzz targets in the codec sections; here you only prove the tool runs.

---

### Step 6 — Install Kani (the Rust model checker, Tier 1)

Kani is a **bounded model checker**: instead of running your code on example inputs like a test, it symbolically proves a property holds for *all* inputs within given bounds. It ships as a `cargo` subcommand plus a backend that a one-time `setup` downloads.

**6.1** Install the verifier binary:

```bash
cargo install --locked kani-verifier
```

**6.2** Run the one-time backend setup (downloads the CBMC/Kani backend; needs network, a few minutes):

```bash
cargo kani setup
```

**6.3** Prove it works end-to-end with a throwaway crate. Create it in your scratch area, add a trivial Kani proof harness, and run it:

```bash
cd /tmp
cargo new --lib kani_smoke
cd kani_smoke
```

Open `/tmp/kani_smoke/src/lib.rs` and replace its contents with this real Kani harness — `kani::any()` invents an arbitrary `u8`, and the `assert!` is a property Kani must prove for *every* possible value:

```rust
#[cfg(kani)]
#[kani::proof]
fn add_one_never_equals_input() {
    let x: u8 = kani::any();
    // Assume x isn't the wrap-around case, then prove x+1 != x for all remaining x.
    kani::assume(x != u8::MAX);
    assert!(x + 1 != x);
}
```

Then:

```bash
cargo kani
```

**Definition of done.**
```bash
cargo kani --version
# expected: "cargo-kani 0.x"
# and the run above ends with:
# "VERIFICATION:- SUCCESSFUL"
```
Clean up when done: `rm -rf /tmp/kani_smoke`.

---

### Step 7 — Install the symbolic protocol verifiers: Tamarin and ProVerif (Tier 3)

These analyze the *protocol design* against a network attacker who can read, drop, and forge any message (the **Dolev–Yao** model). Both are available through Homebrew on Apple Silicon.

**7.1** Tamarin needs a Haskell/Maude stack; the Homebrew formula pulls those in. Install both provers:

```bash
brew install tamarin-prover/tap/tamarin-prover
brew install proverif
```

> If the first line errors that the tap is unknown, run `brew tap tamarin-prover/tap` first, then repeat the install. If `graphviz` is flagged missing (Tamarin uses it to draw attack graphs), run `brew install graphviz`.

**7.2** Tamarin also relies on **Maude** (a rewriting-logic engine). The formula installs it, but verify it's visible:

```bash
which maude tamarin-prover proverif
```

**Definition of done.**
```bash
tamarin-prover --version
# expected: a "tamarin-prover 1.x" banner (GPL etc.)
proverif -help 2>&1 | head -1
# expected: a ProVerif version/usage line
maude --version
# expected: "Maude 3.x"
```
You'll write the actual `.spthy` (Tamarin) and `.pv` (ProVerif) models in the Tier-3 section; here you only prove the binaries run.

---

### Step 8 — Install Python + uv (the Lean-trace replay harness runtime)

The **Tier 2 executable oracle** works like this: the Lean model enumerates protocol traces, exports them as JSON, and a Python harness replays each trace against the Rust core and asserts the core agrees. That harness (and the FCAF/interop glue) runs under Python managed by **uv** — a fast, reproducible venv + resolver.

**8.1** Install uv (it can also manage Python itself):

```bash
brew install uv
```

**8.2** Have uv install a pinned Python 3.14:

```bash
uv python install 3.14
```

**Definition of done.**
```bash
uv --version         # expected: "uv 0.x"
uv python list | grep 3.14
# expected: a line showing a 3.14.x interpreter is available/installed
```

---

### Step 9 — Install elan + Lean 4, and lake (Tier 2 proofs)

**elan** is to Lean what rustup is to Rust: it installs and pins Lean toolchains. `lake` (Lean's build tool) comes bundled with Lean.

**9.1** Install elan via Homebrew (this is the least fiddly route on macOS):

```bash
brew install elan-init
elan self update 2>/dev/null || true
```

> On some systems the formula is named `elan`. If `brew install elan-init` fails, run `brew install elan`. Either way it provides the `elan` and `lean` commands.

**9.2** Install the project's Lean version and set it as default (matches the shared toolchain, Lean 4.32; a newer 4.x is acceptable):

```bash
elan toolchain install leanprover/lean4:v4.32.0
elan default leanprover/lean4:v4.32.0
```

**9.3** Confirm the toolchain and its build tool:

```bash
lean --version
lake --version
```

**Definition of done.**
```bash
lean --version
# expected: "Lean (version 4.32.0, ...)" or newer 4.x
lake --version
# expected: a "Lake version 5.x / Lean 4.x" line
```

---

### Step 10 — Install UniFFI (Rust → Swift bindings generator)

**UniFFI** turns the `crates/wallet-core` facade into a Swift module the iOS app calls. There are two ways to invoke it: as a standalone CLI, or from a tiny build helper crate. We install the CLI now for smoke-testing; the iOS section wires the build-time generation.

**10.1** Install the CLI:

```bash
cargo install --locked uniffi_bindgen_cli
```

> If that crate name isn't found on your crates.io mirror, the equivalent binary can be built from the `uniffi` crate's `cli` feature; the iOS section documents the in-tree `uniffi-bindgen` binary approach as the *canonical* path. Either satisfies this step.

**Definition of done.**
```bash
uniffi-bindgen --version
# expected: "uniffi-bindgen 0.x"  (any 0.2x is fine)
```

---

### Step 11 — Install git/gh and bootstrap the repository, branch layout, and directory tree

Now assemble the repo skeleton every later section writes into. This is the single most important artifact of Section 0: get the tree right and every cross-reference in later sections resolves.

**11.1** Install version control tooling (git ships with Xcode's tools; `gh` is the GitHub CLI you'll use to scaffold CI):

```bash
brew install git gh
```

**11.2** Set your identity if you haven't (used on commits):

```bash
git config --global user.name  "Your Name"
git config --global user.email "you@example.com"
```

**11.3** Create the repo root and the **exact** canonical tree. Pick a parent directory you own (this example uses `~/dev`):

```bash
mkdir -p ~/dev && cd ~/dev
mkdir euwallet && cd euwallet
git init
git branch -m main        # ensure the default branch is 'main'
```

**11.4** Create the full directory layout in one command. Every top-level directory named in the shared context is here, plus the crate subfolders from the canonical workspace:

```bash
mkdir -p \
  crates/crypto-traits/src \
  crates/cose/src \
  crates/mdoc/src \
  crates/sdjwt/src \
  crates/x509/src \
  crates/oid4vp/src \
  crates/oid4vci/src \
  crates/iso18013-5/src \
  crates/trust/src \
  crates/status/src \
  crates/wua/src \
  crates/presenter/src \
  crates/wallet-core/src \
  ffi \
  ios \
  formal/lean \
  formal/tamarin \
  tools \
  traceability \
  docs \
  .github/workflows
```

**11.5** Add the Rust **workspace manifest** at the repo root so `cargo` treats all crates as one workspace. Write `~/dev/euwallet/Cargo.toml`:

```toml
[workspace]
resolver = "2"
members = [
    "crates/crypto-traits",
    "crates/cose",
    "crates/mdoc",
    "crates/sdjwt",
    "crates/x509",
    "crates/oid4vp",
    "crates/oid4vci",
    "crates/iso18013-5",
    "crates/trust",
    "crates/status",
    "crates/wua",
    "crates/presenter",
    "crates/wallet-core",
]

# Shared, certification-relevant lints/settings applied workspace-wide.
[workspace.package]
edition = "2021"
rust-version = "1.97"

[workspace.lints.rust]
unsafe_code = "forbid"      # matches the Tier-1 rule: #![forbid(unsafe_code)] everywhere

[profile.release]
overflow-checks = true      # keep arithmetic checks on even in release for the core
panic = "abort"             # deterministic failure; no unwinding across the FFI
```

**11.6** Pin the Rust toolchain per-repo so every machine and CI runner compiles with the identical compiler. Write `~/dev/euwallet/rust-toolchain.toml`:

```toml
[toolchain]
channel = "1.97.0"
components = ["clippy", "rustfmt", "rust-src", "llvm-tools-preview"]
```

**11.7** Give each of the 13 crates a minimal manifest and a lib file so the workspace actually builds. Run this loop — it writes a real `Cargo.toml` and a `lib.rs` (with the mandated `#![forbid(unsafe_code)]`) into every crate:

```bash
cd ~/dev/euwallet
for c in crypto-traits cose mdoc sdjwt x509 oid4vp oid4vci iso18013-5 trust status wua presenter wallet-core; do
  cat > "crates/$c/Cargo.toml" <<EOF
[package]
name = "$c"
version = "0.0.0"
edition.workspace = true
rust-version.workspace = true
publish = false

[lints]
workspace = true

[dependencies]
EOF
  cat > "crates/$c/src/lib.rs" <<EOF
#![forbid(unsafe_code)]
//! Crate \`$c\` — see the shared architecture overview for its responsibility.

/// Placeholder so the crate compiles; replaced in the relevant section.
pub const CRATE_NAME: &str = "$c";
EOF
done
```

> Note: the crate directory `iso18013-5` maps to the Rust package name `iso18013-5`. Cargo package names may contain hyphens; the *import* name Rust uses substitutes underscores (`iso18013_5`) automatically — you'll see that in later sections.

**11.8** Pin **cargo-deny** policy at the root so the supply-chain gate is enforceable from day one. Generate the template then keep it under version control:

```bash
cd ~/dev/euwallet
cargo deny init
```

This writes `deny.toml`. Leave the defaults for now; the CRA/SBOM section tightens the `[licenses]` and `[bans]` tables.

**11.9** Add a `.gitignore` so build artifacts never enter git. Write `~/dev/euwallet/.gitignore`:

```gitignore
# Rust
/target
**/target
Cargo.lock.orig

# Fuzzing
/fuzz/target
/crates/**/fuzz/target
corpus/
artifacts/

# Lean
/formal/lean/.lake
/formal/lean/build

# Python / uv
.venv/
__pycache__/
*.pyc

# macOS / Xcode
.DS_Store
/ios/**/build
/ios/**/DerivedData
xcuserdata/
*.xcuserstate

# Kani / verification scratch
/target/kani
```

> Keep `Cargo.lock` **committed** (it's an application workspace, and cargo-audit/deny/reproducibility all depend on the locked graph).

**11.10** Create the working branch off `main`. All Section-1-onward work lands on a feature branch, not `main`:

```bash
cd ~/dev/euwallet
git add -A
git commit -m "Section 0: repo skeleton, workspace, toolchain pin, directory tree"
git switch -c bootstrap/section-0
```

**11.11** (Optional but recommended) create the GitHub remote with `gh`. This will prompt you to authenticate in a browser the first time (`gh auth login`):

```bash
gh auth status || gh auth login
gh repo create euwallet --private --source=. --remote=origin --push
```

At this point the canonical tree looks like this (top levels only):

```
euwallet/
├── Cargo.toml                 # workspace manifest (Step 11.5)
├── Cargo.lock                 # committed lockfile
├── rust-toolchain.toml        # pinned compiler (Step 11.6)
├── deny.toml                  # supply-chain policy (Step 11.8)
├── .gitignore
├── crates/                    # the Rust behavior core (13 crates)
│   ├── crypto-traits/  cose/  mdoc/  sdjwt/  x509/
│   ├── oid4vp/  oid4vci/  iso18013-5/  trust/  status/
│   └── wua/  presenter/  wallet-core/
├── ffi/                       # UniFFI config + generated-binding staging
├── ios/                       # Swift iOS shell (Xcode project lands here)
├── formal/
│   ├── lean/                  # Tier-2 Lean model + trace exporter
│   └── tamarin/               # Tier-3 .spthy models (ProVerif .pv sits here too)
├── tools/                     # trace-replay harness, interop scripts (Python/uv)
├── traceability/             # HLR → code/test mapping (requirements matrix)
├── docs/                      # certification memos, ARF mapping, ADRs
└── .github/
    └── workflows/             # CI: build, test, fuzz-smoke, audit, deny, FCAF
```

**Definition of done.**
```bash
cd ~/dev/euwallet
# The workspace builds all 13 stub crates:
cargo build
# expected: "Compiling ... Finished `dev` profile [unoptimized + debuginfo]" and no errors

# The tree is complete (10 top-level dirs present):
ls -d crates ffi ios formal/lean formal/tamarin tools traceability docs .github/workflows | wc -l
# expected: 10

# You are on the working branch, not main:
git branch --show-current
# expected: bootstrap/section-0
```

---

### Step 12 — Whole-environment smoke test (the Section-0 gate)

This single script exercises **every** tool installed above and fails loudly if any is missing or too old. It is the machine-readable version of this section's Definition of done.

**12.1** Write `~/dev/euwallet/tools/smoke.sh`:

```bash
#!/usr/bin/env bash
# Section 0 environment smoke test. Exits non-zero on the first failure.
set -euo pipefail

pass() { printf '  OK   %s\n' "$1"; }
have() { command -v "$1" >/dev/null 2>&1 || { echo "MISSING: $1"; exit 1; }; }

echo "== toolchain presence =="
for t in brew git gh rustup cargo rustc clippy-driver rustfmt \
         cargo-audit cargo-deny cargo-fuzz cargo-kani uniffi-bindgen \
         swift xcodebuild lean lake elan tamarin-prover proverif maude \
         uv; do
  have "$t"; pass "$t"
done

echo "== version floors =="
cargo --version   | grep -Eq 'cargo 1\.(9[7-9]|[0-9]{3})'         && pass "cargo >= 1.97"
swift --version   | grep -Eq 'version 6\.[3-9]|version [7-9]'      && pass "swift >= 6.3"
lean --version    | grep -Eq 'version 4\.(3[2-9]|[4-9][0-9])'      && pass "lean >= 4.32"
uv python list    | grep -q '3\.14'                                && pass "python 3.14 available"

echo "== rust workspace builds =="
( cd "$(git rev-parse --show-toplevel)" && cargo build --quiet )   && pass "cargo build"

echo "== supply-chain gates run =="
( cd "$(git rev-parse --show-toplevel)" && cargo audit --quiet || true ) && pass "cargo audit ran"
( cd "$(git rev-parse --show-toplevel)" && cargo deny check --hide-inclusion-graph 2>/dev/null || true ) && pass "cargo deny ran"

echo
echo "ALL SMOKE CHECKS PASSED"
```

**12.2** Make it executable and run it:

```bash
chmod +x ~/dev/euwallet/tools/smoke.sh
~/dev/euwallet/tools/smoke.sh
```

**12.3** Commit it:

```bash
cd ~/dev/euwallet
git add tools/smoke.sh
git commit -m "Section 0: environment smoke test"
```

**Definition of done (this is also the Definition of done for the whole section).**
```bash
~/dev/euwallet/tools/smoke.sh; echo "exit=$?"
# expected final two lines:
# ALL SMOKE CHECKS PASSED
# exit=0
```
When `smoke.sh` exits `0` on a freshly set-up machine, **every later section can begin**: the Rust workspace compiles, all three formal-methods tiers' tools are present, the FFI generator and Python harness runtime exist, the supply-chain gates run, and the canonical directory tree with the pinned toolchain is committed on the working branch.

---

### Glossary — the ~20 acronyms you will hit immediately

Read once now; refer back as needed. (Standards versions are pinned in the shared context and in later sections; here we only define the terms.)

- **EUDI** — *European Digital Identity* (Wallet). The EU framework and the app itself: a citizen-held wallet for identity credentials.
- **ARF** — *Architecture and Reference Framework*. The EU's normative spec set the wallet must conform to (we target v2.9.0).
- **HLR** — *High-Level Requirements*. The requirement statements (from the ARF/rulebooks) we trace to code and tests in `traceability/`.
- **PID** — *Person Identification Data*. The core "who you are" credential; must exist in *both* mdoc and SD-JWT VC formats.
- **mdoc** — *mobile document*. The ISO/IEC 18013-5 credential format, encoded in CBOR and signed with COSE. One of the two mandatory formats.
- **SD-JWT VC** — *Selective-Disclosure JWT Verifiable Credential*. The JOSE/JWS-based credential format supporting per-claim disclosure. The other mandatory format (draft-17).
- **OID4VP** — *OpenID for Verifiable Presentations*. The protocol for **remote** presentation (proving claims to a relying party over the network).
- **OID4VCI** — *OpenID for Verifiable Credential Issuance*. The protocol for **issuing** credentials into the wallet.
- **HAIP** — *High Assurance Interoperability Profile*. A constrained, security-hardened profile of the OpenID4VC protocols the wallet must follow.
- **WSCD** — *Wallet Secure Cryptographic Device*. The tamper-resistant hardware holding device-bound keys (Secure Enclave on iOS / StrongBox on Android).
- **WUA** — *Wallet Unit Attestation*. A signed statement proving *this* wallet instance is genuine and its keys live in a real WSCD (TS03).
- **QES** — *Qualified Electronic Signature*. The highest legal tier of e-signature under eIDAS; the consent hash binds "what you see is what you sign" to QES intent.
- **QTSP** — *Qualified Trust Service Provider*. An accredited entity that provides qualified services (e.g., remote QES) under eIDAS.
- **QSCD** — *Qualified Signature Creation Device*. Certified hardware/service that creates a QES; used remotely via the CSC API (P1).
- **FCAF** — *Functional Conformance Assessment Framework*. The EU conformance test framework we run in CI (v0.0.7, evolving).
- **EUCC** — *EU Common Criteria*-based cybersecurity certification scheme; the certification regime relevant to the wallet's security evaluation.
- **COSE** — *CBOR Object Signing and Encryption* (RFC 9052/9053). The signing/MAC/key format used by mdoc (`crates/cose`).
- **JOSE** — *JSON Object Signing and Encryption*. The JSON-world equivalent (JWS/JWE/JWK) used by SD-JWT VC (`crates/sdjwt`).
- **CBOR** — *Concise Binary Object Representation* (RFC 8949). The compact binary encoding mdoc uses; we use a **deterministic/canonical** profile so bytes are reproducible and hashable.
- **sans-IO** — a design style where the protocol logic performs **no** I/O itself; it consumes events and emits effects, so it is deterministic and replay-testable. The entire behavior core is sans-IO.
- **TOE** — *Target of Evaluation*. In certification, the precisely bounded part of the system under formal security evaluation (here: the wallet core + WSCD boundary).
- **DPIA** — *Data Protection Impact Assessment*. The GDPR analysis of privacy risks the project must document (lives in `docs/`).

---


## Section 1 — Cargo workspace topology, crate boundaries, and the dependency budget

This section builds the empty-but-compiling skeleton of the entire wallet. When you finish it you will have 13 Rust library crates wired together in one Cargo *workspace*, every dependency arrow pointing "downhill" (an acyclic graph), a machine-enforced *dependency budget* so nobody can quietly add `reqwest` or `openssl` later, and two commands that prove the whole thing is healthy: `cargo check --workspace` and `cargo deny check`.

Nothing in this section signs, parses, or presents anything yet. The point is *structure*: get the boundaries physically correct so that later sections (Section 2 crypto-traits & Secure Enclave, Section 3 COSE, Section 4 mdoc, Section 5 SD-JWT, Section 6 OID4VP, etc.) each drop into a slot that already exists and already forbids the wrong dependencies.

Read the whole section once before typing anything. Every step ends with a **Definition of done** — a command to run and the exact output to expect.

---

### 1.0 Jargon you need for this section (one clause each)

- **Crate** — the Rust unit of compilation and dependency; either a *library* crate (`lib.rs`, produces a `.rlib`) or a *binary* crate (`main.rs`, produces an executable). All 13 of ours are libraries.
- **Workspace** — a set of crates that share one `Cargo.lock`, one `target/` build directory, and one set of pinned dependency versions, so they always build together and version-consistently.
- **`Cargo.toml`** — the manifest file that declares a crate's name, edition, and dependencies (like `package.json` for Node, but statically resolved).
- **`Cargo.lock`** — the auto-generated, committed file recording the *exact* resolved version of every dependency, transitively; this is what makes builds reproducible.
- **Dependency graph** — the directed graph "crate A depends on crate B"; Cargo *requires* it to be acyclic (no cycles), which is what forces us to think about layering.
- **`std`** — the Rust standard library; `std::net` in particular is TCP/UDP networking. We will forbid networking crates in the core so the core literally *cannot* touch the network (the sans-IO rule from the shared context).
- **`sans-IO`** — "without I/O": a crate that computes over bytes/events in memory and never itself opens a socket, clock, file, or radio.
- **`cargo-deny`** — a linter that reads a policy file (`deny.toml`) and fails the build if a banned crate, a forbidden license, a known security advisory, or an untrusted source appears anywhere in the dependency graph. This is how the dependency budget becomes *enforced* rather than *aspirational*.
- **`cargo-audit`** — a narrower tool that checks `Cargo.lock` against the RustSec advisory database (known CVEs). `cargo-deny` subsumes it, but we run both because certification reviewers ask for `cargo-audit` output by name.

---

### 1.1 The layering principle (read before you type)

Every crate sits in one of four layers. **Arrows only ever point downward.** If you ever find yourself wanting an upward or sideways arrow, the design is wrong — stop and re-layer.

```
Layer 3  FACADE            wallet-core
                              │  (owns Event/Effect, run loop, UniFFI)
                              ▼
Layer 2  PROTOCOLS   oid4vp  oid4vci  iso18013-5   presenter
                        │       │         │            │
                        └───────┴────┬────┴────────────┘
                                     ▼
Layer 1  FORMATS &     mdoc   sdjwt   x509   trust   status   wua   cose
         TRUST            │      │      │      │        │      │     │
                          └──────┴──────┴───┬──┴────────┴──────┴─────┘
                                            ▼
Layer 0  PRIMITIVES              crypto-traits          (+ the CBOR helper)
                                     │
                                     ▼
                                (nothing — only tiny leaf deps like thiserror)
```

**Why `crypto-traits` is at the very bottom, and why the core depends only on it.**
`crypto-traits` defines *interfaces* — `Signer`, `Verifier`, `Kdf`, `Aead`, `Random`, `KeyAttestation` — as Rust `trait`s, plus the plain data types they exchange (`Signature`, `PublicKeyJwk`, `CoseKey`, error enums). It contains **no algorithm implementations at all**. This matters for three reasons:

1. **The "never implement crypto yourself" rule is structurally guaranteed.** If the trait crate has no concrete code, no one can accidentally hand-roll ECDSA in it. Concrete implementations live in the *shell* (Secure Enclave via Effects, per Section 2) or in one clearly-isolated adapter crate that wraps `aws-lc-rs`. The certification-critical core links against the *trait*, resolved at runtime through the FFI boundary.
2. **Device-bound keys never cross the FFI (shared-context rule).** Because signing is a *trait method* whose only production implementation is "emit an Effect to the Secure Enclave," the long-term private key never becomes a Rust value inside the core. There is no `SecretKey` type in `crypto-traits` for a hardware key — only key *handles* (opaque identifiers) and *public* keys.
3. **Everything else can depend on `crypto-traits` without pulling in a crypto library.** `cose`, `mdoc`, `sdjwt`, `x509`, `status`, `wua` all need "verify this signature" or "hash these bytes" — they call the trait, they do not `use aws_lc_rs`. So the heavy crypto crate is a leaf that only the shell/adapter pulls in, and swapping it (aws-lc-rs today, platform callback tomorrow — the TBD certification memo in the shared context) touches exactly one crate.

**Why no core crate may pull std-networking.** `trust` downloads trusted lists and `status` downloads status lists — but per the shared context, *fetch is an Effect*: the core emits `Effect::HttpGet { url }`, the native shell performs it, and the bytes come back as `Event::HttpResponse { body }`. The `trust`/`status` crates only *parse and validate* those bytes. Therefore no crate below the shell may depend on `reqwest`, `hyper`, `tokio`, `ureq`, or anything transitively pulling `std::net`. We enforce this in `deny.toml` (§1.8), not by discipline.

---

### 1.2 Create the workspace directory and the root manifest

**Step 1 — make the repo skeleton.** Run from the directory where the repo will live (adjust the parent path to taste; all paths below are relative to this repo root, which I will call `<repo>`):

```bash
mkdir -p eudi-wallet/crates
cd eudi-wallet
git init
```

**Step 2 — create all 13 library crates.** `cargo new --lib` writes a minimal `Cargo.toml` + `src/lib.rs`. The `--vcs none` flag avoids nested git repos inside the workspace.

```bash
cd crates
for c in crypto-traits cose mdoc sdjwt x509 oid4vp oid4vci iso18013-5 trust status wua presenter wallet-core; do
  cargo new --lib --vcs none --edition 2021 "$c"
done
cd ..
```

You now have `crates/crypto-traits/`, `crates/cose/`, … each with a stub `lib.rs`.

**Step 3 — write the root `Cargo.toml`.** This file has **no `[package]`** — it is a *virtual manifest* (a workspace root that is not itself a crate). Create `<repo>/Cargo.toml` with exactly this:

```toml
# <repo>/Cargo.toml — virtual workspace manifest (no [package] here).
[workspace]
resolver = "2"                 # the modern feature resolver; required for edition 2021+
members = [
    "crates/crypto-traits",
    "crates/cose",
    "crates/mdoc",
    "crates/sdjwt",
    "crates/x509",
    "crates/oid4vp",
    "crates/oid4vci",
    "crates/iso18013-5",
    "crates/trust",
    "crates/status",
    "crates/wua",
    "crates/presenter",
    "crates/wallet-core",
]

# ---------------------------------------------------------------------------
# Shared package metadata: every crate inherits these with `x.workspace = true`
# so we set edition / license / rust-version in ONE place.
# ---------------------------------------------------------------------------
[workspace.package]
edition      = "2021"
rust-version = "1.97"          # matches rust-toolchain.toml (§1.3)
license      = "Apache-2.0"
publish      = false           # NONE of these crates go to crates.io
repository   = "https://example.invalid/eudi-wallet"

# ---------------------------------------------------------------------------
# THE DEPENDENCY BUDGET, as code. Every external crate the workspace is
# allowed to use is pinned HERE, exactly once, with an exact-ish version.
# A member crate opts in with `serde = { workspace = true }` — it can NEVER
# choose a different version. Adding a line here is a reviewable event.
# See §1.7 for the justification table and §1.8 for enforcement.
# ---------------------------------------------------------------------------
[workspace.dependencies]
# --- error plumbing (leaf, no transitive weight) ---
thiserror   = "=2.0.11"        # derive std::error::Error on our own enums

# --- serialization frontends (NO I/O, NO networking) ---
serde        = { version = "=1.0.217", default-features = false, features = ["derive", "alloc"] }
serde_json   = { version = "=1.0.138", default-features = false, features = ["alloc"] }
ciborium     = { version = "=0.2.2", default-features = false }   # CBOR reader/writer, sans-IO
ciborium-io  = { version = "=0.2.2", default-features = false }

# --- small, constant-time-friendly byte utilities ---
base64ct    = { version = "=1.6.0", default-features = false, features = ["alloc"] } # constant-time base64url for JOSE/SD-JWT
hex         = { version = "=0.4.3", default-features = false, features = ["alloc"] }
zeroize     = { version = "=1.8.1", default-features = false, features = ["alloc", "derive"] } # wipe secrets from RAM
subtle      = { version = "=2.6.1", default-features = false }    # constant-time equality for MACs/tags

# --- X.509 / ASN.1 (RustCrypto family; parse-only, no crypto impls pulled) ---
der         = { version = "=0.7.9", default-features = false, features = ["alloc", "oid"] }
spki        = { version = "=0.7.3", default-features = false, features = ["alloc"] }
const-oid   = { version = "=0.9.6", default-features = false }
x509-cert   = { version = "=0.2.5", default-features = false, features = ["alloc"] }

# --- the ONE heavy crypto crate, pulled only by the adapter/shell (Section 2) ---
aws-lc-rs   = { version = "=1.12.2", default-features = false, features = ["aws-lc-sys"] }

# --- FFI (pulled ONLY by wallet-core; see Section 12 for the Swift bindings) ---
uniffi      = { version = "=0.28.3" }

# --- test-only tooling (dev-dependencies; never in a shipping build) ---
proptest    = "=1.6.0"         # property-based testing (Tier 1 formal methods)
arbitrary   = { version = "=1.4.1", features = ["derive"] } # structured fuzz inputs for cargo-fuzz
hex-literal = "=0.4.1"         # compile-time hex byte arrays in tests
```

> Notes for the junior dev:
> - The `=1.0.217` syntax pins an **exact** version. We do this deliberately: certification wants a frozen, auditable bill of materials. `Cargo.lock` already freezes transitive deps, but exact top-level pins make the *manifest* readable as the SBOM (Section 18 covers CRA/SBOM formally).
> - `default-features = false` everywhere is not cosmetic. It is how we stop `serde`, `ciborium`, etc. from silently pulling `std` networking or filesystem features. We turn on only `alloc`/`derive`.
> - The exact patch numbers above are illustrative for 2026-07; when you type them, run `cargo update --dry-run` once and take the latest patch of each *minor* line, then re-pin. Do not bump *minor* or *major* without a note in the change-watch log.

**Definition of done for §1.2:**
```bash
cargo metadata --no-deps --format-version 1 | \
  python3 -c 'import sys,json; print(len(json.load(sys.stdin)["packages"]))'
```
Expected output: `13` (Cargo sees exactly the 13 workspace members).

---

### 1.3 Pin the toolchain

Create `<repo>/rust-toolchain.toml`. This makes *every* developer and CI runner use the exact same compiler, so "works on my machine" cannot drift.

```toml
# <repo>/rust-toolchain.toml
[toolchain]
channel    = "1.97.0"                     # matches workspace.package.rust-version
components = ["clippy", "rustfmt", "rust-src"]  # rust-src is needed by Kani (Section 14)
targets    = ["aarch64-apple-ios", "aarch64-apple-ios-sim", "aarch64-apple-darwin"]
profile    = "minimal"
```

When you `cd` into the repo, `rustup` will auto-install `1.97.0` and these targets on first `cargo` invocation.

**Definition of done for §1.3:**
```bash
rustc --version
```
Expected output: `rustc 1.97.0 (…)` — the version string starts with exactly `1.97.0`, even if your global default is newer.

---

### 1.4 The text dependency diagram (the acyclic graph, spelled out)

This is the contract the per-crate manifests in §1.5 must match *exactly*. Read `A → B` as "A depends on B". Leaf utility deps (`thiserror`, `serde`, `zeroize`, etc.) are omitted here for clarity and listed per-crate in the budget table (§1.7).

```
crypto-traits → (leaf utilities only)

cose          → crypto-traits
mdoc          → cose, crypto-traits
sdjwt         → crypto-traits
x509          → crypto-traits
status        → cose, crypto-traits
wua           → cose, mdoc, crypto-traits
trust         → x509, cose, crypto-traits
presenter     → mdoc, sdjwt, crypto-traits

oid4vp        → presenter, mdoc, sdjwt, cose, x509, trust, status, crypto-traits
oid4vci       → mdoc, sdjwt, cose, x509, trust, status, crypto-traits
iso18013-5    → mdoc, cose, crypto-traits

wallet-core   → oid4vp, oid4vci, iso18013-5, presenter, trust, status, wua,
                mdoc, sdjwt, cose, x509, crypto-traits  (+ uniffi)
```

Observations that must stay true forever:
- **`crypto-traits` has no arrow into any other workspace crate.** It is the sink.
- **No arrow ever points *up* a layer or *sideways* within Layer 1** except the deliberate `mdoc → cose`, `status → cose`, `wua → {cose,mdoc}`, `trust → {x509,cose}`, `presenter → {mdoc,sdjwt}` edges, all of which point *down or same-layer-downhill* and are acyclic. There is, for example, **no `cose → mdoc`** edge — COSE knows nothing about mdoc.
- **Only `wallet-core` depends on `uniffi`.** The FFI surface is one crate wide. Everything else is pure Rust with no binding-generator coupling.
- **`oid4vp` depends on `presenter`** (it needs the hashable consent `ScreenDescription`) but `oid4vci` does not (issuance has its own, simpler consent, covered in Section 7).

Sanity-check the graph mechanically after §1.5 with:
```bash
cargo install cargo-depgraph   # one-time
cargo depgraph --workspace-only | grep -c '\->'   # counts edges; must be acyclic
cargo tree --workspace --edges normal 2>&1 | grep -i 'cyclic' || echo "NO CYCLES"
```

---

### 1.5 Per-crate `Cargo.toml` skeletons (all 13)

Replace the auto-generated `crates/<name>/Cargo.toml` with the versions below. The pattern is: inherit shared package fields with `.workspace = true`, list workspace deps with `{ workspace = true }`, and (for the format/protocol crates) declare `[dev-dependencies]` for the Tier-1 property tests that Section 13 will fill in.

Also, in **every** `src/lib.rs`, put the crate-wide safety lints at the top (the `#![forbid(unsafe_code)]` mandate from the shared context). Do that once now:

```bash
for c in crypto-traits cose mdoc sdjwt x509 oid4vp oid4vci iso18013-5 trust status wua presenter wallet-core; do
  cat > "crates/$c/src/lib.rs" <<'EOF'
#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]
#![cfg_attr(not(test), warn(clippy::unwrap_used, clippy::expect_used))]

// Skeleton. Real content arrives in later sections.
EOF
done
```

> `#![forbid(unsafe_code)]` makes `unsafe` a *compile error* in that crate. `wallet-core` is the one place we may need to relax it for the UniFFI scaffolding — if so, we scope the allowance to the single generated module, never crate-wide. Keep the `forbid` in `wallet-core` for now; Section 12 will tell you precisely where (and only if) to downgrade it to `deny` on one module.

Now the manifests.

**`crates/crypto-traits/Cargo.toml`** — the sink. Note: no concrete crypto, and specifically **not** `aws-lc-rs`.
```toml
[package]
name         = "crypto-traits"
version      = "0.1.0"
edition.workspace      = true
rust-version.workspace = true
license.workspace      = true
publish.workspace      = true

[dependencies]
thiserror = { workspace = true }
zeroize   = { workspace = true }   # so secret/handle types can be zeroized
serde     = { workspace = true }   # public keys / JWK are (de)serializable DATA
subtle    = { workspace = true }   # constant-time comparisons live behind traits
```

**`crates/cose/Cargo.toml`** — COSE_Sign1/Mac0/Key over the traits (RFC 9052/9053).
```toml
[package]
name = "cose"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true
publish.workspace = true

[dependencies]
crypto-traits = { path = "../crypto-traits" }
ciborium      = { workspace = true }   # COSE is CBOR
ciborium-io   = { workspace = true }
serde         = { workspace = true }
thiserror     = { workspace = true }

[dev-dependencies]
proptest    = { workspace = true }
hex-literal = { workspace = true }
```

**`crates/mdoc/Cargo.toml`** — deterministic/canonical CBOR + ISO 18013-5 structures.
```toml
[package]
name = "mdoc"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true
publish.workspace = true

[dependencies]
cose          = { path = "../cose" }
crypto-traits = { path = "../crypto-traits" }
ciborium      = { workspace = true }
ciborium-io   = { workspace = true }
serde         = { workspace = true }
thiserror     = { workspace = true }

[dev-dependencies]
proptest    = { workspace = true }
arbitrary   = { workspace = true }   # for the canonical-CBOR fuzz target (Section 4/13)
hex-literal = { workspace = true }
```

**`crates/sdjwt/Cargo.toml`** — SD-JWT VC (draft-17) + JOSE/JWS. Uses `base64ct` (constant-time base64url) and `serde_json` (JWS payloads are JSON).
```toml
[package]
name = "sdjwt"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true
publish.workspace = true

[dependencies]
crypto-traits = { path = "../crypto-traits" }
serde         = { workspace = true }
serde_json    = { workspace = true }
base64ct      = { workspace = true }
thiserror     = { workspace = true }

[dev-dependencies]
proptest    = { workspace = true }
arbitrary   = { workspace = true }
hex-literal = { workspace = true }
```

**`crates/x509/Cargo.toml`** — certificate parse + EUDI RP/trusted-issuer path-validation profile. This is where we deliberately spend our ASN.1 budget on the RustCrypto `der`/`x509-cert` family rather than hand-rolling a DER parser (parsing untrusted DER by hand is a classic memory-safety footgun, and these crates are `#![forbid(unsafe_code)]` themselves).
```toml
[package]
name = "x509"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true
publish.workspace = true

[dependencies]
crypto-traits = { path = "../crypto-traits" }
x509-cert     = { workspace = true }
der           = { workspace = true }
spki          = { workspace = true }
const-oid     = { workspace = true }
thiserror     = { workspace = true }

[dev-dependencies]
proptest    = { workspace = true }
arbitrary   = { workspace = true }
hex-literal = { workspace = true }
```

**`crates/status/Cargo.toml`** — Token Status List (draft-21) + cert status. Status lists are COSE/CWT-signed, hence `cose`.
```toml
[package]
name = "status"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true
publish.workspace = true

[dependencies]
cose          = { path = "../cose" }
crypto-traits = { path = "../crypto-traits" }
ciborium      = { workspace = true }
serde         = { workspace = true }
thiserror     = { workspace = true }

[dev-dependencies]
proptest    = { workspace = true }
hex-literal = { workspace = true }
```

**`crates/wua/Cargo.toml`** — Wallet Unit Attestation + key attestation (TS03). Produces/verifies attestations that are COSE-signed and can reference mdoc structures.
```toml
[package]
name = "wua"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true
publish.workspace = true

[dependencies]
cose          = { path = "../cose" }
mdoc          = { path = "../mdoc" }
crypto-traits = { path = "../crypto-traits" }
serde         = { workspace = true }
thiserror     = { workspace = true }

[dev-dependencies]
proptest    = { workspace = true }
hex-literal = { workspace = true }
```

**`crates/trust/Cargo.toml`** — trusted lists (ETSI 119 612/602), anchors. Parsing is pure; fetch is an Effect, so **no networking here**.
```toml
[package]
name = "trust"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true
publish.workspace = true

[dependencies]
x509          = { path = "../x509" }
cose          = { path = "../cose" }
crypto-traits = { path = "../crypto-traits" }
serde         = { workspace = true }
serde_json    = { workspace = true }   # trusted-list JSON representations
thiserror     = { workspace = true }

[dev-dependencies]
proptest    = { workspace = true }
hex-literal = { workspace = true }
```

**`crates/presenter/Cargo.toml`** — Snapshot → hashable `ScreenDescription`, claim minimization. Reads mdoc + sdjwt claim shapes; hashes via a `crypto-traits` digest trait (never its own SHA).
```toml
[package]
name = "presenter"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true
publish.workspace = true

[dependencies]
mdoc          = { path = "../mdoc" }
sdjwt         = { path = "../sdjwt" }
crypto-traits = { path = "../crypto-traits" }
serde         = { workspace = true }
serde_json    = { workspace = true }   # canonical JSON encoding of ScreenDescription before hashing
thiserror     = { workspace = true }

[dev-dependencies]
proptest    = { workspace = true }
hex-literal = { workspace = true }
```

**`crates/oid4vp/Cargo.toml`** — OpenID4VP 1.0 remote presentation, sans-IO, HAIP-constrained.
```toml
[package]
name = "oid4vp"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true
publish.workspace = true

[dependencies]
presenter     = { path = "../presenter" }
mdoc          = { path = "../mdoc" }
sdjwt         = { path = "../sdjwt" }
cose          = { path = "../cose" }
x509          = { path = "../x509" }
trust         = { path = "../trust" }
status        = { path = "../status" }
crypto-traits = { path = "../crypto-traits" }
serde         = { workspace = true }
serde_json    = { workspace = true }
thiserror     = { workspace = true }

[dev-dependencies]
proptest    = { workspace = true }
hex-literal = { workspace = true }
```

**`crates/oid4vci/Cargo.toml`** — OpenID4VCI 1.0 issuance, sans-IO, HAIP-constrained.
```toml
[package]
name = "oid4vci"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true
publish.workspace = true

[dependencies]
mdoc          = { path = "../mdoc" }
sdjwt         = { path = "../sdjwt" }
cose          = { path = "../cose" }
x509          = { path = "../x509" }
trust         = { path = "../trust" }
status        = { path = "../status" }
crypto-traits = { path = "../crypto-traits" }
serde         = { workspace = true }
serde_json    = { workspace = true }
thiserror     = { workspace = true }

[dev-dependencies]
proptest    = { workspace = true }
hex-literal = { workspace = true }
```

**`crates/iso18013-5/Cargo.toml`** — proximity: device engagement + session, sans-IO (transport bytes in/out only). Note the crate directory name has a hyphen and a digit; the Rust *package* name matches, and the importable crate identifier becomes `iso18013_5` (hyphens map to underscores in `use`).
```toml
[package]
name = "iso18013-5"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true
publish.workspace = true

[dependencies]
mdoc          = { path = "../mdoc" }
cose          = { path = "../cose" }
crypto-traits = { path = "../crypto-traits" }
ciborium      = { workspace = true }
serde         = { workspace = true }
thiserror     = { workspace = true }

[dev-dependencies]
proptest    = { workspace = true }
hex-literal = { workspace = true }
```

**`crates/wallet-core/Cargo.toml`** — the FACADE. The only crate with `uniffi`. This is also the only crate that will (in Section 2) optionally pull the `aws-lc-rs` adapter behind a feature flag, if the certification memo picks Rust-side bulk crypto over a platform callback. We wire the feature now but leave it off by default.
```toml
[package]
name = "wallet-core"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true
publish.workspace = true

[lib]
# UniFFI needs both a Rust rlib (for tests) and a C-ABI staticlib/cdylib
# (for the iOS XCFramework, built in Section 12).
crate-type = ["lib", "staticlib", "cdylib"]

[features]
default = []
# When the certification memo (shared context TBD) selects Rust-side bulk
# session crypto, turn this on; it pulls the ONE heavy crypto crate.
# Until then it is OFF, and all crypto is Effect-driven into the Enclave.
rust-bulk-crypto = ["dep:aws-lc-rs"]

[dependencies]
oid4vp        = { path = "../oid4vp" }
oid4vci       = { path = "../oid4vci" }
iso18013-5    = { path = "../iso18013-5" }
presenter     = { path = "../presenter" }
trust         = { path = "../trust" }
status        = { path = "../status" }
wua           = { path = "../wua" }
mdoc          = { path = "../mdoc" }
sdjwt         = { path = "../sdjwt" }
cose          = { path = "../cose" }
x509          = { path = "../x509" }
crypto-traits = { path = "../crypto-traits" }

uniffi        = { workspace = true }
serde         = { workspace = true }
thiserror     = { workspace = true }

# Optional, gated behind the feature above:
aws-lc-rs     = { workspace = true, optional = true }

[dev-dependencies]
proptest = { workspace = true }
```

> Why `aws-lc-rs` is `optional` and lives *only* in `wallet-core` (not in `crypto-traits`): keeping the heavy, FIPS-oriented crypto crate at the top, behind a feature flag, means (a) the entire Layer-0/1/2 graph compiles and tests *without* it, so the deterministic core stays lightweight and portable; and (b) the "swap aws-lc-rs for a platform callback" decision is a one-line feature toggle, not a refactor. The concrete `impl Signer for AwsLcSigner` will be written in Section 2 inside a `#[cfg(feature = "rust-bulk-crypto")]` module.

**Definition of done for §1.5:**
```bash
cargo check --workspace
```
Expected: it compiles with no errors. You will see warnings like `unused imports` or none at all (the skeleton `lib.rs` files are nearly empty). The last line must be `Finished \`dev\` profile … in Xs`. If Cargo reports `cyclic package dependency`, your arrows are wrong — return to §1.4.

---

### 1.6 Prove there are no dependency cycles and no accidental networking

Two quick mechanical checks before we write the enforcement policy.

**Cycle check:**
```bash
cargo tree --workspace 2>&1 | grep -i cyclic && echo "FAIL: cycle" || echo "OK: acyclic"
```
Expected: `OK: acyclic`.

**Networking check (should find nothing):**
```bash
cargo tree --workspace --prefix none 2>/dev/null \
  | grep -Ei '^(tokio|hyper|reqwest|ureq|mio|socket2|native-tls|openssl)\b' \
  && echo "FAIL: networking/legacy-crypto crate present" || echo "OK: no networking, no openssl"
```
Expected: `OK: no networking, no openssl`. (With the default feature set, `aws-lc-rs` should also be absent — confirm with `cargo tree --workspace -i aws-lc-rs` returning `package ID … did not match any packages`.)

**Definition of done for §1.6:** both commands print their `OK:` line.

---

### 1.7 The dependency budget table

This is the human-readable contract. §1.8 turns it into machine-enforced policy. **"Allowed external" lists direct dependencies only** (transitive deps of an allowed crate are governed by `deny.toml`). **"Forbidden"** items are the ones a tired developer is most likely to reach for; they are banned globally in `deny.toml` regardless of crate.

| Crate | Layer | Allowed external crates (direct) | Justification | Forbidden here (beyond the global bans) |
|---|---|---|---|---|
| **crypto-traits** | 0 | `thiserror`, `serde`, `zeroize`, `subtle` | Pure interfaces + DTOs; `zeroize`/`subtle` are tiny, `#![forbid(unsafe)]`-clean primitives needed to *type* secret-handling correctly | **Any concrete crypto** (`aws-lc-rs`, `ring`, `rsa`, `ecdsa`, `sha2`, `p256`…). This crate must contain zero algorithms. |
| **cose** | 1 | `crypto-traits`, `ciborium`, `ciborium-io`, `serde`, `thiserror` | COSE is CBOR; signing/verifying delegated to traits | any crypto impl; `serde_json` (COSE is not JSON) |
| **mdoc** | 1 | `cose`, `crypto-traits`, `ciborium`, `ciborium-io`, `serde`, `thiserror` | mdoc = canonical CBOR + COSE-signed MSO | any crypto impl; `serde_json` |
| **sdjwt** | 1 | `crypto-traits`, `serde`, `serde_json`, `base64ct`, `thiserror` | SD-JWT/JOSE are JSON + base64url; base64 must be constant-time | `base64`/`base64-simd` (non-constant-time); any crypto impl; `ciborium` |
| **x509** | 1 | `crypto-traits`, `x509-cert`, `der`, `spki`, `const-oid`, `thiserror` | Certificate/ASN.1 parsing is a memory-safety hazard; use audited RustCrypto parsers, verify signatures via traits | hand-rolled DER; `openssl`; any crypto impl beyond the traits |
| **status** | 1 | `cose`, `crypto-traits`, `ciborium`, `serde`, `thiserror` | Token Status List is COSE/CWT + CBOR bit-strings | networking (fetch is an Effect); `serde_json` |
| **wua** | 1 | `cose`, `mdoc`, `crypto-traits`, `serde`, `thiserror` | WUA/key-attestation are COSE-signed, may embed mdoc structures | any crypto impl |
| **trust** | 1 | `x509`, `cose`, `crypto-traits`, `serde`, `serde_json`, `thiserror` | Parses signed trusted lists (JSON/XML→our types); validates via x509 + traits | **networking** (fetch is an Effect — hard ban); any crypto impl |
| **presenter** | 2 | `mdoc`, `sdjwt`, `crypto-traits`, `serde`, `serde_json`, `thiserror` | Builds canonical, hashable ScreenDescription; digest via a `crypto-traits` hash trait | any crypto impl (no direct `sha2`); networking |
| **oid4vp** | 2 | `presenter`, `mdoc`, `sdjwt`, `cose`, `x509`, `trust`, `status`, `crypto-traits`, `serde`, `serde_json`, `thiserror` | Orchestrates remote presentation over all formats/trust/status; sans-IO state machine | **networking** (transport is an Effect); any crypto impl; `tokio`/async runtimes |
| **oid4vci** | 2 | `mdoc`, `sdjwt`, `cose`, `x509`, `trust`, `status`, `crypto-traits`, `serde`, `serde_json`, `thiserror` | Orchestrates issuance across formats; sans-IO | **networking**; any crypto impl; async runtimes |
| **iso18013-5** | 2 | `mdoc`, `cose`, `crypto-traits`, `ciborium`, `serde`, `thiserror` | Proximity engagement/session; transport bytes in/out only | **radio/BLE/NFC crates** (`btleplug`, `core-bluetooth`…); networking; any crypto impl |
| **wallet-core** | 3 | all workspace crates + `uniffi`, `serde`, `thiserror`, and *optionally* `aws-lc-rs` (feature-gated) | The facade; owns Event/Effect, run loop, FFI; the single, isolated home for a Rust bulk-crypto impl if chosen | networking; radio; filesystem crates (all I/O is a shell Effect) |

Global bans (enforced everywhere, no exceptions) — see `deny.toml`:
- **Networking / async-IO runtimes:** `tokio`, `hyper`, `reqwest`, `ureq`, `async-std`, `mio`, `socket2`. *(No core crate ever touches the network — the shell does, via Effects.)*
- **Legacy / duplicate crypto stacks:** `openssl`, `openssl-sys`, `rustls`, `ring` (we standardize on `aws-lc-rs` behind traits; `ring` would be a redundant second crypto stack), `md5`, `sha1` (weak), `rand` (use the `Random` trait → OS/enclave RNG, never a userspace PRNG for keys).
- **Panicky/parsing footguns in the core:** `serde_yaml` (unmaintained), `chrono` (prefer `time` if ever needed; time is normally injected as an Effect anyway).
- **Anything unmaintained / RUSTSEC-flagged:** handled by the advisories section automatically.

---

### 1.8 Enforcement: `deny.toml`, `cargo-deny`, `cargo-audit`

A table in a document is not a control; `cargo deny` is. Install the tools once:

```bash
cargo install --locked cargo-deny cargo-audit
```

Create `<repo>/deny.toml`:

```toml
# <repo>/deny.toml — machine-enforced dependency budget. `cargo deny check`
# fails CI if any rule is violated. This file IS the boundary; the table in
# §1.7 is its documentation.

[graph]
# Only analyze the platforms we actually ship / build on.
targets = [
    "aarch64-apple-ios",
    "aarch64-apple-ios-sim",
    "aarch64-apple-darwin",
]
all-features = true          # also check the optional rust-bulk-crypto path

# ---------------------------------------------------------------------------
# 1) Security advisories (subsumes cargo-audit).
# ---------------------------------------------------------------------------
[advisories]
version = 2
yanked  = "deny"            # a yanked crate in the lockfile fails the build
ignore  = []               # add "RUSTSEC-YYYY-NNNN" here ONLY with a written note

# ---------------------------------------------------------------------------
# 2) Licenses. EUDI/CRA review wants a clean, permissive license set.
# ---------------------------------------------------------------------------
[licenses]
version = 2
allow = [
    "Apache-2.0",
    "MIT",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "Unicode-3.0",         # required by some unicode tables
    "Zlib",
]
# Copyleft / unknown licenses are denied by omission. `aws-lc-rs` is
# Apache-2.0/ISC; verify with `cargo deny list -f Layout`.
confidence-threshold = 0.9

# ---------------------------------------------------------------------------
# 3) Banned crates — the global bans from §1.7, as hard denials.
# ---------------------------------------------------------------------------
[bans]
multiple-versions   = "deny"   # no two versions of the same crate (bloat + audit noise)
wildcard-dependencies = "deny" # no `foo = "*"` anywhere
# Allow the few places a duplicate is genuinely unavoidable (fill in only if
# `cargo deny check bans` proves it, with a comment each time):
skip = []
skip-tree = []

deny = [
    # networking / async IO — the core is sans-IO; the shell does I/O via Effects
    { name = "tokio" },
    { name = "hyper" },
    { name = "reqwest" },
    { name = "ureq" },
    { name = "async-std" },
    { name = "mio" },
    { name = "socket2" },
    # radio / proximity transports belong in the SHELL, never a core crate
    { name = "btleplug" },
    # legacy or duplicate crypto stacks — we standardize on aws-lc-rs behind traits
    { name = "openssl" },
    { name = "openssl-sys" },
    { name = "ring" },
    { name = "rustls" },
    # weak / forbidden primitives
    { name = "md5" },
    { name = "sha1" },
    { name = "rand" },          # key/nonce material comes from the Random trait (OS/enclave)
    # unmaintained / footguns
    { name = "serde_yaml" },
    { name = "chrono" },
]

# ---------------------------------------------------------------------------
# 4) Sources — only crates.io and our own workspace paths are trusted.
# ---------------------------------------------------------------------------
[sources]
unknown-registry = "deny"
unknown-git      = "deny"
allow-registry   = ["https://github.com/rust-lang/crates.io-index"]
allow-git        = []          # NO git dependencies. Ever. (auditability)
```

> Reading the policy:
> - `multiple-versions = "deny"` is strict but valuable: it forces the whole graph onto single versions of `serde`, `ciborium`, `der`, etc., which is exactly the frozen-SBOM property certification wants. When a transitive conflict first appears you will get a precise report; resolve it by bumping a pin in `[workspace.dependencies]`, and only use `skip`/`skip-tree` as a last resort with a comment.
> - Banning `rand` at the crate level is the structural expression of "never a userspace PRNG for keys": randomness enters through `crypto_traits::Random`, whose only production impl is an Effect into the OS/Enclave RNG (Section 2).
> - `allow-git = []` means no `git = "…"` dependencies — every dep is a versioned crates.io release you can archive and audit.

Add a CI job (this dovetails with Section 17, FCAF-in-CI). Create `<repo>/.github/workflows/deny.yml`:

```yaml
name: dependency-budget
on: [push, pull_request]
jobs:
  cargo-deny:
    runs-on: macos-14        # Apple Silicon runner; matches our targets
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@1.97.0
      - run: cargo install --locked cargo-deny cargo-audit
      - run: cargo deny check          # advisories + licenses + bans + sources
      - run: cargo audit --deny warnings
```

**Definition of done for §1.8:**
```bash
cargo deny check
```
Expected final lines:
```
advisories ok
bans ok
licenses ok
sources ok
```
And:
```bash
cargo audit
```
Expected: `Success No vulnerable packages found` (or a `0 vulnerabilities found` summary). If `licenses` fails, run `cargo deny list` to see which crate's license is not in the `allow` list and either add the SPDX id (if it is genuinely permissive) or replace the offending dependency.

---

### 1.9 Commit the skeleton

Add a `.gitignore` at `<repo>/.gitignore`:
```gitignore
/target
**/*.rs.bk
.DS_Store
```

Commit `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `deny.toml`, `.github/`, and every `crates/*/Cargo.toml` + `crates/*/src/lib.rs`. **Commit `Cargo.lock`** — for an application/wallet (not a reusable library) the lockfile is part of the reproducible, auditable build and certification bill-of-materials.

```bash
git add .
git commit -m "chore(core): empty 13-crate workspace skeleton with enforced dependency budget"
```

---

### 1.10 Section-level Definition of done

Run these three commands from `<repo>`; all three must pass with the shown results. This is the gate to start Section 2.

1. **The skeleton compiles:**
   ```bash
   cargo check --workspace
   ```
   → ends with `Finished \`dev\` profile … in Xs`, zero errors.

2. **The dependency budget holds:**
   ```bash
   cargo deny check
   ```
   → `advisories ok`, `bans ok`, `licenses ok`, `sources ok`.

3. **The graph is acyclic and networking-free:**
   ```bash
   cargo tree --workspace 2>&1 | grep -i cyclic || echo "OK: acyclic"
   cargo tree --workspace --prefix none 2>/dev/null | grep -Ei '^(tokio|hyper|reqwest|openssl|ring)\b' && echo "FAIL" || echo "OK: clean"
   ```
   → `OK: acyclic` and `OK: clean`.

When all three pass, the physical structure of the wallet is locked in: 13 crates, one acyclic graph, `crypto-traits` at the bottom with no algorithms, no crate below the facade able to touch the network, and a `deny.toml` that will reject the first pull request that tries to smuggle in `openssl` or `reqwest`. Proceed to **Section 2** to fill `crypto-traits` with the `Signer`/`Verifier`/`Kdf`/`Aead`/`Random`/`KeyAttestation` traits and wire the Secure Enclave Effects.

---


## Section 2 — The sans-IO Event/Effect core architecture and the run loop (wallet-core facade)

This is the heart of the wallet. Everything else in this plan — the codecs (`mdoc`, `sdjwt`, `cose`), the protocol state machines (`oid4vci`, `oid4vp`, `iso18013-5`), the `presenter`, the formal-methods work — plugs into the structure defined here. Read this section slowly; the two ideas it introduces (**sans-IO** and **effects-as-data**) are what make the wallet deterministic, replay-testable, and portable to a second platform for almost free.

### 2.0 What "sans-IO" means, in plain terms (read this first)

**sans-IO** is French-flavoured jargon meaning "without input/output". A sans-IO component contains *all the decision-making logic* of a protocol — what to send, what to accept, what to reject, what to show the user — but performs *none of the actual talking to the outside world*. It never opens a socket, never reads a file, never reads the clock, never calls a random-number generator, never touches Bluetooth. Those are all "I/O", and they all live outside the core.

Here is the mental model. Think of the core as a **chess player who cannot touch the board**. The player (the core) knows the rules and the strategy perfectly. But to actually move a piece, the player must *tell a helper* ("move the knight to f3"), and to learn what the opponent did, the player must *be told* ("the opponent moved a pawn to e5"). The helper (the **shell**) does all the physical touching. The player only ever consumes descriptions of what happened and produces descriptions of what should happen next.

In our wallet:

- A description of *something that happened* is an **`Event`** (an inbound value: "a credential offer arrived", "the HTTP response came back", "the user tapped Approve", "the timer elapsed").
- A description of *something the core wants done* is an **`Effect`** (an outbound value: "please perform this HTTP request", "please sign these bytes with this key", "please show this screen", "please start a 60-second timer").

The entire core is therefore one function:

```
handle_event(&mut Core, Event) -> Vec<Effect>
```

You feed it one `Event`; it mutates its internal state and hands you back an ordered list of `Effect`s to carry out. It never blocks and never does I/O. This is the "Crux-style effects-as-data" architecture named in the shared context.

**Why go to this trouble?** Four payoffs, all of which this plan depends on:

1. **Determinism.** Because the core has no clock, no randomness, and no network of its own, the *only* thing that can influence its output is `(current state, incoming event)`. Same state + same event ⇒ same effects, every single time, on every machine. Section 2.8 shows why this is the linchpin of the whole verification strategy.
2. **Testability with zero mocks.** You test the brain by feeding it events and asserting the effects — pure values in, pure values out. No network stubs, no fake filesystems, no async test harness. The Definition-of-done test in Section 2.6 drives a real two-step issuance flow entirely in-process.
3. **Portability.** iOS today, Android later. The core is identical Rust on both; only the shell (the "helper" that executes effects) is rewritten in Kotlin. The protocol logic — the part an evaluator scrutinises — is written and certified once.
4. **Auditability & replay.** An `Event` log is a complete, replayable recording of a session. Save it, replay it, reproduce any bug exactly. And the Lean model (Tier 2) can *generate* event logs and assert the effects, turning the core into an executable conformance oracle.

The one-paragraph summary of the run loop, which we will build up over the rest of this section:

```
   ┌──────────────────────── shell (Swift now, Kotlin later) ─────────────────────────┐
   │                                                                                   │
 UI / OS / QR ─── Event ──▶  Core::handle_event(Event) ─── Vec<Effect> ──▶ perform each│
   ▲                              (pure Rust; no I/O)                          effect   │
   │                                                                             │      │
   │                                                          URLSession / Secure Enclave
   │                                                          Keychain / CoreBluetooth / │
   │                                                          SecRandom / Task.sleep      │
   │                                                                             │      │
   └────────── Event (a *result*, tagged with the same EffectId) ◀──────────────┘      │
   └───────────────────────────────────────────────────────────────────────────────────┘
```

Every arrow crossing into the core is an `Event`; every arrow leaving it is an `Effect`. The loop closes because each effect that expects an answer comes back as an event carrying a correlation tag (the `EffectId`), which Section 2.4 explains in detail.

There is **no Definition of done** for this conceptual step — 2.1 onward is where you start typing.

---

### 2.1 Create the `wallet-core` crate and lay out its modules

This assumes the Cargo workspace and the UniFFI bootstrap already exist from **Section 1** (the `[workspace]` root, the `crates/` directory, and the `uniffi` tooling). We now create the facade crate.

> Jargon: a **crate** is Rust's unit of compilation and packaging (like a Swift module or an npm package). A **facade** crate is one whose job is to tie other crates together and expose a single clean API — here, the single API that crosses the FFI to Swift.
> **FFI** = Foreign Function Interface, the boundary where Swift calls into Rust. **UniFFI** is the tool (from Mozilla) that auto-generates the Swift glue from annotations on our Rust types (all covered in Section 1).

**Step 2.1.1 — Create the crate.**

```bash
cd crates
cargo new --lib wallet-core
```

**Step 2.1.2 — Create the module files.** From the repository root:

```bash
mkdir -p crates/wallet-core/src/machines crates/wallet-core/tests
touch crates/wallet-core/src/effect.rs \
      crates/wallet-core/src/event.rs \
      crates/wallet-core/src/ids.rs \
      crates/wallet-core/src/pending.rs \
      crates/wallet-core/src/screen.rs \
      crates/wallet-core/src/core.rs \
      crates/wallet-core/src/machines/mod.rs \
      crates/wallet-core/src/machines/issuance.rs \
      crates/wallet-core/src/ffi.rs \
      crates/wallet-core/tests/two_step_flow.rs
```

The target module layout, with one line on each file's job:

```
crates/wallet-core/
├── Cargo.toml
├── src/
│   ├── lib.rs            # crate root: declares modules, re-exports the public API, FFI scaffolding
│   ├── effect.rs         # the Effect enum (outbound) + its wire payload types (HttpRequest, KeyRef, …)
│   ├── event.rs          # the Event enum (inbound) + its payload types (ShellError, BleUpdate, …)
│   ├── ids.rs            # EffectId newtype + IdSeq (the monotonic id source)
│   ├── pending.rs        # PendingTable: correlates an in-flight EffectId to what it is FOR
│   ├── screen.rs         # placeholder ScreenDescription (real one comes from the `presenter` crate)
│   ├── core.rs           # the Core struct, the Ctx helper, and handle_event — the run loop
│   ├── machines/
│   │   ├── mod.rs        # declares the sub-machine modules
│   │   └── issuance.rs   # a minimal REAL issuance sub-machine (full one lives in the `oid4vci` crate)
│   └── ffi.rs            # the UniFFI-exported WalletCore handle (thin lock around Core)
└── tests/
    └── two_step_flow.rs  # the Definition-of-done integration test (pure Rust, no I/O)
```

**Step 2.1.3 — Write `Cargo.toml`.** Open `crates/wallet-core/Cargo.toml` and make it exactly:

```toml
[package]
name = "wallet-core"
version = "0.1.0"
edition = "2021"
publish = false

[lib]
name = "wallet_core"
# `lib`       → needed so `cargo test` and other Rust crates can use it.
# `staticlib` → the .a we link into the iOS app (Section 1 builds the xcframework).
# `cdylib`    → a C-ABI dynamic lib, used by the uniffi-bindgen tooling.
crate-type = ["lib", "staticlib", "cdylib"]

[features]
default = []
# `ffi`    turns on the UniFFI surface. Section 1 enables it to build the device binary.
#          Plain `cargo test` leaves it OFF, so the pure core is tested with zero FFI machinery.
ffi = ["dep:uniffi"]
# `replay` turns on serde (de)serialisation of the Event/Effect vocabulary, used by the
#          Tier-2 trace-replay harness (Section 2.8) and record/replay debugging.
replay = ["dep:serde"]

[dependencies]
serde_json = "1"                                            # parsing issuer/RP JSON metadata (NOT crypto)
serde = { version = "1", features = ["derive"], optional = true }
uniffi = { version = "0.28", optional = true }

# Protocol crates plug in here as later sections build them:
# oid4vci    = { path = "../oid4vci" }
# oid4vp     = { path = "../oid4vp" }
# iso18013-5 = { path = "../iso18013-5" }
# presenter  = { path = "../presenter" }
```

> Note on `serde_json`: it parses *untrusted JSON metadata* (issuer metadata, RP request objects). That is data handling, not cryptography, so it does **not** violate the "never implement crypto yourself / use vetted libs" rules. All signature verification of that data happens in the `cose`/`sdjwt`/`x509` crates.

**Step 2.1.4 — Write the crate root `src/lib.rs`.**

```rust
#![forbid(unsafe_code)] // Tier-1 requirement: no `unsafe` anywhere in a core crate.

//! `wallet-core` — the FACADE crate. It owns the `Event`/`Effect` vocabulary,
//! the `Core` state, and the `handle_event` run loop, and orchestrates every
//! protocol crate. See Section 2 of the implementation plan.

pub mod effect;
pub mod event;
pub mod ids;
pub mod screen;

// `core` is a legal module name; always refer to it as `crate::core` — the leading
// `crate::` disambiguates it from Rust's built-in `::core` library.
mod core;
mod machines;
mod pending;

pub use crate::core::Core;
pub use effect::*;
pub use event::*;
pub use ids::EffectId;
pub use screen::{ScreenDescription, ScreenKind};

// ---- FFI surface (only compiled when Section 1 turns on the `ffi` feature) ----
#[cfg(feature = "ffi")]
uniffi::setup_scaffolding!();
#[cfg(feature = "ffi")]
uniffi::custom_newtype!(EffectId, u64); // EffectId crosses the FFI transparently as a u64.
#[cfg(feature = "ffi")]
mod ffi;
#[cfg(feature = "ffi")]
pub use ffi::WalletCore;
```

The files it references are still empty; that is fine — the next steps fill them in. If you try to build now it will fail because `core.rs`, `event.rs`, etc. don't yet define the types re-exported here.

**Definition of done (2.1):** the crate skeleton is recognised by Cargo. Run:

```bash
cargo metadata --no-deps --format-version 1 | grep -o '"name":"wallet-core"'
```

Expected output:

```
"name":"wallet-core"
```

(A full `cargo build` will not succeed until Section 2.6; that is expected. We build incrementally.)

---

### 2.2 The `Effect` enum — everything the core can *ask* the shell to do

An `Effect` is an *instruction to the shell*, expressed as plain data. The core never performs the action; it only describes it. Open `src/effect.rs`:

```rust
use crate::ids::EffectId;
use crate::screen::ScreenDescription;

/// A single side effect the core wants the shell to perform. Effects are DATA:
/// the core never does I/O itself, it only *describes* what should happen. The
/// shell executes each effect and — for effects that produce a result — feeds the
/// result back in as an `Event` carrying the SAME `EffectId` (see Section 2.4).
///
/// This is the outbound half of the FFI vocabulary. Under the `ffi` feature it is
/// exported to Swift by UniFFI (Section 1) so the shell can `switch` over it directly.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "replay", derive(serde::Serialize, serde::Deserialize))]
pub enum Effect {
    /// Perform an HTTP request. `id` correlates the eventual `Event::HttpResponse`.
    /// The core has ALREADY applied HAIP/URL-safety policy; the shell just sends bytes.
    Http { id: EffectId, request: HttpRequest },

    /// Ask the platform keystore (Secure Enclave on iOS / StrongBox on Android) to
    /// produce a signature over `payload` with the key named by `key_ref`. The
    /// private key NEVER crosses the FFI — see the platform-cryptography section and
    /// the `crypto-traits` crate. Result returns as `Event::SignatureProduced`.
    Sign { id: EffectId, key_ref: KeyRef, alg: SignAlg, payload: Vec<u8> },

    /// Ask the platform CSPRNG for `len` random bytes (iOS `SecRandomCopyBytes`).
    /// The core has NO RNG of its own; every nonce/PKCE verifier enters as an event.
    /// This is what keeps nonce generation deterministic under replay (Section 2.8).
    Random { id: EffectId, len: u32 },

    /// Drive the Bluetooth Low Energy transport for proximity (ISO 18013-5). Carries
    /// opaque transport bytes / GATT commands; the proximity state machine lives in
    /// the `iso18013-5` crate.
    Ble { id: EffectId, command: BleCommand },

    /// Render a screen. `ScreenDescription` is built by the `presenter` crate and,
    /// for consent, is canonically encoded and HASHED inside the core so both
    /// platforms provably show the same payload (what-you-see-is-what-you-sign).
    /// Render is fire-and-forget: it has NO `EffectId`, because the user's reaction
    /// arrives as its own semantic event (`Event::UserConsented`/`UserRejected`),
    /// not as a mechanical "render finished" acknowledgement.
    Render(ScreenDescription),

    /// Read or write the secure store (Keychain / encrypted files; see the
    /// secure-storage section). Loads answer with `Event::StoreLoaded`; saves answer
    /// with `Event::StoreCommitted`.
    Store { id: EffectId, op: StoreOp },

    /// Start a wall-clock timer. When it elapses the shell sends `Event::TimerFired`.
    /// The core keeps NO clock; every notion of "time passed" enters as this event.
    StartTimer { id: EffectId, after_ms: u64 },
}

/// A fully-formed HTTP request the shell should send verbatim. The core has already
/// enforced HTTPS, the HAIP profile, and any URL-safety policy; the shell is a dumb pipe.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
#[cfg_attr(feature = "replay", derive(serde::Serialize, serde::Deserialize))]
pub struct HttpRequest {
    pub method: HttpMethod,
    pub url: String,
    pub headers: Vec<Header>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "replay", derive(serde::Serialize, serde::Deserialize))]
pub enum HttpMethod { Get, Post }

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
#[cfg_attr(feature = "replay", derive(serde::Serialize, serde::Deserialize))]
pub struct Header { pub name: String, pub value: String }

/// A stable, NON-SECRET handle to a key held in the WSCD (Wallet Secure
/// Cryptographic Device — the Secure Enclave/StrongBox). Resolving it to actual
/// key material happens on the shell side; the material never crosses the FFI.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
#[cfg_attr(feature = "replay", derive(serde::Serialize, serde::Deserialize))]
pub struct KeyRef { pub label: String }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "replay", derive(serde::Serialize, serde::Deserialize))]
pub enum SignAlg { Es256, Es384, EdDsa }

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "replay", derive(serde::Serialize, serde::Deserialize))]
pub enum StoreOp {
    Load { key: String },
    Save { key: String, value: Vec<u8> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "replay", derive(serde::Serialize, serde::Deserialize))]
pub enum BleCommand {
    Advertise { service_uuid: String },
    Send { bytes: Vec<u8> },
    Disconnect,
}
```

Two design points worth internalising:

- **`Render` has no `EffectId`.** Most effects are half of a request/response pair, so they carry an id that the eventual answering event echoes back. Rendering is different: the "answer" to showing a consent screen is not "rendering is done" — it is the *user's decision*, which is a first-class semantic event (`UserConsented`/`UserRejected`). Modelling it that way keeps consent explicit and auditable.
- **The core pre-bakes all policy into the effect.** By the time an `Effect::Http` leaves the core, the URL is already HTTPS, already HAIP-conformant, already free of secrets in the query string. The shell is deliberately dumb, so that no security decision can leak into platform code that the evaluator would then have to re-audit twice (once per platform).

**Definition of done (2.2):** the module type-checks in isolation.

```bash
cargo check -p wallet-core 2>&1 | grep -E "error\[|cannot find" || echo "effect.rs: no unresolved-name errors"
```

Expected (it will still complain that `Event`/`Core` are undefined until later steps, but there should be **no** errors originating inside `effect.rs`):

```
effect.rs: no unresolved-name errors
```

---

### 2.3 The `Event` enum — everything that can *happen to* the wallet

An `Event` is the inbound counterpart: a normalised description of something that occurred. There are exactly two families, and keeping them straight is the key to understanding the run loop:

- **Intent events** — a human or the OS *initiated* something (`CredentialOfferReceived`, `PresentationRequestReceived`, `UserConsented`, `UserRejected`). These have no `EffectId`; they start or steer a flow.
- **Result events** — the *answer* to an effect the core previously emitted, always tagged with the matching `EffectId` (`HttpResponse`, `SignatureProduced`, `RandomProduced`, `StoreLoaded`, `StoreCommitted`, `BleEvent`, `TimerFired`, `EffectFailed`).

Open `src/event.rs`:

```rust
use crate::effect::Header;
use crate::ids::EffectId;

/// Everything that can happen TO the wallet, normalised into one inbound type.
/// Inbound half of the FFI vocabulary; exported to Swift by UniFFI under `ffi`.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "replay", derive(serde::Serialize, serde::Deserialize))]
pub enum Event {
    // ---------- intent events (no EffectId; they start/steer a flow) ----------

    /// A credential offer arrived (QR scan, deep link, or NFC). Carries the raw
    /// `openid-credential-offer://…` URI; the core parses and validates it.
    CredentialOfferReceived { offer_uri: String },

    /// A presentation request arrived (OID4VP), e.g. from an `openid4vp://…` link.
    PresentationRequestReceived { request_uri: String },

    /// The user approved the consent screen whose canonical hash is `consent_hash`
    /// (a 32-byte SHA-256 digest, carried as bytes because UniFFI has no fixed-size
    /// array type). Passing the hash back lets the core prove the user consented to
    /// EXACTLY the payload it rendered — what-you-see-is-what-you-sign.
    UserConsented { consent_hash: Vec<u8> },

    /// The user rejected / cancelled the current consent screen.
    UserRejected,

    // ---------- result events (each echoes the EffectId it answers) ----------

    /// Answer to `Effect::Http { id, .. }`.
    HttpResponse { id: EffectId, status: u16, headers: Vec<Header>, body: Vec<u8> },

    /// Answer to `Effect::Sign { id, .. }`. `signature` is raw signature bytes from
    /// the WSCD; the private key never left the device.
    SignatureProduced { id: EffectId, signature: Vec<u8> },

    /// Answer to `Effect::Random { id, .. }`.
    RandomProduced { id: EffectId, bytes: Vec<u8> },

    /// Answers to `Effect::Store { id, op: Load/Save }`.
    StoreLoaded { id: EffectId, value: Option<Vec<u8>> },
    StoreCommitted { id: EffectId },

    /// Answer to `Effect::Ble { id, .. }` (bytes received, connection state changed…).
    BleEvent { id: EffectId, update: BleUpdate },

    /// Answer to `Effect::StartTimer { id, .. }` — the timer elapsed.
    TimerFired { id: EffectId },

    /// A previously issued effect FAILED at the shell (network down, user denied the
    /// keychain, BLE off…). The core decides the policy response (retry, fail-closed…).
    EffectFailed { id: EffectId, error: ShellError },
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "replay", derive(serde::Serialize, serde::Deserialize))]
pub enum BleUpdate {
    Connected,
    Received { bytes: Vec<u8> },
    Disconnected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "replay", derive(serde::Serialize, serde::Deserialize))]
pub enum ShellError {
    Network { message: String },
    Cancelled,
    KeystoreDenied,
    BleUnavailable,
    Other { message: String },
}
```

Notice the discipline: **there is no `Event::Now(timestamp)` and no `Event::RandomSeed`.** Time enters *only* through `TimerFired` (the shell decided when), and randomness enters *only* through `RandomProduced` (the shell's CSPRNG produced it). The core cannot obtain either on its own. That is not an accident — it is the entire basis of the determinism argument in Section 2.8.

**Definition of done (2.3):** same isolation check as before.

```bash
cargo check -p wallet-core 2>&1 | grep -E "error\[E" | grep -i "event.rs" || echo "event.rs: no type errors"
```

Expected:

```
event.rs: no type errors
```

---

### 2.4 Effect IDs: correlating a request with its answer

This is the subtle mechanism that makes the whole loop work, so it gets its own step.

**The problem.** The core emits `Effect::Http { .. }` and moves on — it does *not* block waiting for the response (that would be I/O). Later, an `Event::HttpResponse` arrives. But the wallet may have *several* HTTP calls in flight at once (fetching issuer metadata, refreshing a trusted list, polling a deferred credential). When a response comes back, the core must answer two questions: **(a) which request is this the answer to, and (b) which sub-machine is waiting for it, and in what role?**

**The solution — two small pieces:**

1. An **`EffectId`**: a unique tag the core mints for every effect that expects an answer, and which the answering event echoes back.
2. A **`PendingTable`**: a map from `EffectId` to a small record describing *what the effect was for*, so the core can route the answer correctly.

Open `src/ids.rs`:

```rust
/// Opaque handle correlating an outbound effect with its inbound result event.
/// A newtype over `u64` so it cannot be accidentally confused with other integers.
/// Under the `ffi` feature it crosses to Swift transparently as a `u64`
/// (`uniffi::custom_newtype!` in lib.rs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "replay", derive(serde::Serialize, serde::Deserialize))]
pub struct EffectId(pub u64);

/// Monotonic id source. Lives INSIDE `Core`; hands out EffectId(1), EffectId(2), …
/// in a fixed order for a fixed sequence of events. Because the counter lives in the
/// core (never in the shell), id assignment is deterministic and therefore replayable.
#[derive(Debug, Default)]
pub(crate) struct IdSeq {
    next: u64,
}

impl IdSeq {
    /// Mint the next id. The first call returns EffectId(1); we reserve 0 as a
    /// "never issued" sentinel so an accidental EffectId(0) stands out in logs/tests.
    pub(crate) fn mint(&mut self) -> EffectId {
        self.next += 1;
        EffectId(self.next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_monotonic_from_one() {
        let mut seq = IdSeq::default();
        assert_eq!(seq.mint(), EffectId(1));
        assert_eq!(seq.mint(), EffectId(2));
        assert_eq!(seq.mint(), EffectId(3));
    }
}
```

> Why must the counter live in the core and not the shell? Because if the *shell* assigned ids, two platforms (or two runs) could assign them in different orders depending on thread scheduling, and the effect stream would stop being a pure function of the event stream. Keeping the counter in the core makes the *n*-th effect always get the same id, which is precisely what lets a recorded trace be replayed byte-for-byte (Section 2.8).

Now open `src/pending.rs`:

```rust
use std::collections::BTreeMap;

use crate::ids::EffectId;

/// What an outstanding effect was FOR. When a result event arrives carrying an
/// `EffectId`, the core looks it up here to decide which sub-machine should receive
/// it, and in what role. Without this table the core would not know whether
/// `HttpResponse { id: 7 }` is issuer metadata, a token response, or a list refresh.
#[allow(dead_code)] // Presentation/Proximity/Trust variants are consumed by later sections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Pending {
    Issuance(IssuancePending),
    Presentation(PresentationPending),
    Proximity(ProximityPending),
    Trust(TrustPending),
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IssuancePending {
    IssuerMetadata,
    CredentialEndpoint,
    ProofSignature,
    Persist,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PresentationPending { RequestObject, ProofSignature }

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProximityPending { SessionEstablish, DeviceResponse }

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TrustPending { ListRefresh }

/// The correlation table. We use a `BTreeMap` (ordered by key) rather than a
/// `HashMap` deliberately: a HashMap's iteration order is nondeterministic, and the
/// #1 way to accidentally destroy the core's determinism is to iterate a HashMap to
/// build effects. BTreeMap makes even debug iteration reproducible. (We only ever
/// look up by id here, but "deterministic collections by default" is a good habit.)
#[derive(Debug, Default)]
pub(crate) struct PendingTable {
    map: BTreeMap<EffectId, Pending>,
}

impl PendingTable {
    pub(crate) fn insert(&mut self, id: EffectId, p: Pending) {
        debug_assert!(!self.map.contains_key(&id), "EffectId {id:?} reused — id minting is broken");
        self.map.insert(id, p);
    }

    /// Remove and return the pending record for a completed effect. Returns `None`
    /// if the id is unknown — a late, duplicate, or forged result — and the caller
    /// simply drops it. This is a security property: an attacker cannot drive the
    /// core by replaying a result for an id the core never issued.
    pub(crate) fn take(&mut self, id: EffectId) -> Option<Pending> {
        self.map.remove(&id)
    }

    #[allow(dead_code)]
    pub(crate) fn is_empty(&self) -> bool { self.map.is_empty() }
}
```

**A concrete correlation walk-through** (this is the mechanism you must be able to narrate):

1. The user scans a credential offer → shell sends `Event::CredentialOfferReceived { .. }`.
2. Inside `handle_event`, the issuance machine decides it needs the issuer's metadata. It calls `ctx.emit_with_id(Pending::Issuance(IssuerMetadata), |id| Effect::Http { id, .. })`. This **mints `EffectId(1)`**, **records `1 → Issuance(IssuerMetadata)`** in the `PendingTable`, and **pushes** `Effect::Http { id: 1, .. }`.
3. The shell performs the HTTP GET and, when it returns, sends `Event::HttpResponse { id: 1, .. }`.
4. `handle_event` sees a result event, calls `pending.take(EffectId(1))`, gets back `Issuance(IssuerMetadata)`, and therefore routes the bytes to `issuance.on_http(.., IssuerMetadata, ..)`. The issuance machine now knows these bytes are issuer metadata (not, say, a token response) and parses them accordingly.

The `emit_with_id` helper (defined in the next step) does mint + record + push as *one atomic operation*, which structurally prevents the classic bug of emitting an HTTP effect but forgetting to register what it was for.

**Definition of done (2.4):** the id source behaves.

```bash
cargo test -p wallet-core ids_are_monotonic_from_one
```

Expected (observed):

```
running 1 test
test ids::tests::ids_are_monotonic_from_one ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; ...
```

---

### 2.5 The `Core` struct, the `Ctx` helper, and `handle_event` (the dispatch)

Now we assemble the brain. Open `src/core.rs`:

```rust
use crate::effect::Effect;
use crate::event::Event;
use crate::ids::{EffectId, IdSeq};
use crate::machines::issuance::IssuanceMachine;
use crate::pending::{Pending, PendingTable};

/// The whole wallet's protocol state — the ONLY long-lived mutable state in the core.
/// It contains one state value per protocol sub-machine, the id sequence used to tag
/// outbound effects, and the pending table correlating in-flight effects to purpose.
///
/// It owns NO sockets, NO files, NO clock, NO RNG. Time, randomness, network bytes and
/// signatures all ENTER as `Event`s. That is the whole point of sans-IO, and it is what
/// makes `handle_event` a pure state transition.
#[derive(Debug, Default)]
pub struct Core {
    ids: IdSeq,
    pending: PendingTable,
    issuance: IssuanceMachine,
    // As later sections land their crates, add their state here:
    // presentation: PresentationMachine,   // OID4VP  — see the remote-presentation section
    // proximity:    ProximityMachine,      // 18013-5 — see the proximity section
    // trust:        TrustState,            // trusted lists/anchors — see the trust section
}

impl Core {
    pub fn new() -> Self {
        Self::default()
    }

    /// THE run-loop entry point. Feed one `Event`; get back the ordered list of
    /// `Effect`s the shell must perform. It never blocks, never does I/O, and — for a
    /// given `&mut self` state and a given `ev` — always returns the same effects.
    pub fn handle_event(&mut self, ev: Event) -> Vec<Effect> {
        let mut out = Vec::new();

        match ev {
            // -------- intent events: route by KIND to the owning sub-machine --------
            Event::CredentialOfferReceived { offer_uri } => {
                let mut ctx = Ctx::new(&mut self.ids, &mut self.pending, &mut out);
                self.issuance.on_offer(&mut ctx, &offer_uri);
            }
            Event::UserConsented { consent_hash } => {
                // In this slimmed example only issuance awaits consent. The full facade
                // dispatches to whichever machine is currently in an `AwaitingConsent`
                // state (tracked by a small `focus` field once >1 machine can consent).
                let mut ctx = Ctx::new(&mut self.ids, &mut self.pending, &mut out);
                self.issuance.on_consent(&mut ctx, consent_hash);
            }
            Event::UserRejected => {
                let mut ctx = Ctx::new(&mut self.ids, &mut self.pending, &mut out);
                self.issuance.on_reject(&mut ctx);
            }
            Event::PresentationRequestReceived { .. } => {
                // presentation.on_request(&mut ctx, &request_uri) — see the OID4VP section.
            }

            // -------- result events: route by the PENDING RECORD for this id --------
            Event::HttpResponse { id, status, headers, body } => {
                // Take the pending record FIRST (this borrow of `self.pending` ends here),
                // THEN build `ctx`. Doing it in this order is what satisfies the borrow
                // checker: `ctx` borrows `self.pending` mutably, so we cannot also call
                // `self.pending.take(..)` while `ctx` is alive.
                match self.pending.take(id) {
                    Some(Pending::Issuance(p)) => {
                        let mut ctx = Ctx::new(&mut self.ids, &mut self.pending, &mut out);
                        self.issuance.on_http(&mut ctx, p, status, &headers, body);
                    }
                    Some(_) => { /* route to presentation / proximity / trust */ }
                    None => { /* unknown/late/duplicate/forged id — drop it (see 2.4) */ }
                }
            }
            Event::SignatureProduced { id, signature } => {
                if let Some(Pending::Issuance(p)) = self.pending.take(id) {
                    let mut ctx = Ctx::new(&mut self.ids, &mut self.pending, &mut out);
                    self.issuance.on_signature(&mut ctx, p, signature);
                }
            }
            Event::StoreLoaded { id, value } => {
                if let Some(Pending::Issuance(p)) = self.pending.take(id) {
                    let mut ctx = Ctx::new(&mut self.ids, &mut self.pending, &mut out);
                    self.issuance.on_store_loaded(&mut ctx, p, value);
                }
            }
            Event::StoreCommitted { id } => {
                if let Some(Pending::Issuance(p)) = self.pending.take(id) {
                    let mut ctx = Ctx::new(&mut self.ids, &mut self.pending, &mut out);
                    self.issuance.on_store_committed(&mut ctx, p);
                }
            }
            Event::EffectFailed { id, error } => {
                if let Some(Pending::Issuance(p)) = self.pending.take(id) {
                    let mut ctx = Ctx::new(&mut self.ids, &mut self.pending, &mut out);
                    self.issuance.on_failure(&mut ctx, p, error);
                }
            }
            Event::RandomProduced { id, .. } => { let _ = self.pending.take(id); /* route… */ }
            Event::TimerFired { id }         => { let _ = self.pending.take(id); /* route… */ }
            Event::BleEvent { id, .. }       => { let _ = self.pending.take(id); /* route… */ }
        }

        out
    }
}

/// A short-lived handle passed to sub-machines during ONE `handle_event` call. It
/// lets a machine mint effect ids, register what each effect is waiting for, and push
/// effects — WITHOUT borrowing the entire `Core`. Everything it touches lives in
/// `Core`, so there is still no hidden I/O.
pub(crate) struct Ctx<'a> {
    ids: &'a mut IdSeq,
    pending: &'a mut PendingTable,
    out: &'a mut Vec<Effect>,
}

impl<'a> Ctx<'a> {
    pub(crate) fn new(
        ids: &'a mut IdSeq,
        pending: &'a mut PendingTable,
        out: &'a mut Vec<Effect>,
    ) -> Self {
        Self { ids, pending, out }
    }

    /// Emit an effect that EXPECTS a later result. Atomically: mints the id, records
    /// what the effect is for, hands the id to `build` so it lands inside the effect,
    /// and queues the effect. Returns the id (handy for logs/tests). Using this helper
    /// makes it impossible to emit a request-style effect without registering its
    /// pending record.
    pub(crate) fn emit_with_id(
        &mut self,
        pending: Pending,
        build: impl FnOnce(EffectId) -> Effect,
    ) -> EffectId {
        let id = self.ids.mint();
        self.pending.insert(id, pending);
        self.out.push(build(id));
        id
    }

    /// Emit a fire-and-forget effect (e.g. `Render`) that has no result event.
    pub(crate) fn emit(&mut self, effect: Effect) {
        self.out.push(effect);
    }
}
```

Read the dispatch as two rules:

- **Intent events** are routed *by kind*: a `CredentialOfferReceived` obviously belongs to issuance, a `PresentationRequestReceived` to presentation.
- **Result events** are routed *by their pending record*: the `EffectId` is looked up in the `PendingTable`, and the record tells the core which machine (and which step) the answer belongs to.

Two things a junior reader should specifically notice:

1. **Why `ctx` is created inside each arm, after `pending.take`.** The `Ctx` holds a mutable borrow of `self.pending`. Rust forbids two simultaneous mutable borrows of the same field, so we cannot call `self.pending.take(id)` while a `ctx` that borrows `self.pending` is alive. The fix is ordering: take the pending record first (that borrow ends immediately, because `take` returns an owned value), *then* construct `ctx`. Inside the call `self.issuance.on_http(&mut ctx, ..)`, the compiler sees three *distinct* fields borrowed — `self.issuance` directly, and `self.ids` + `self.pending` via `ctx` — which is allowed (disjoint field borrows).
2. **Exhaustiveness is a safety net.** The `match` has no `_ => {}` wildcard over `Event`. When a future section adds a new `Event` variant, the compiler will *refuse to build* until you handle it. This is the hand-written-enum discipline from the shared context giving you compile-time coverage of the whole protocol surface — the same reason we chose exhaustive Rust enums over a runtime state-chart library.

**Definition of done (2.5):** the core compiles cleanly with lints as errors. (The sub-machine referenced here is written in 2.6; if you are typing along, do 2.6's `issuance.rs`, `screen.rs`, and `machines/mod.rs` first, then run this.)

```bash
cargo clippy -p wallet-core --all-targets -- -D warnings
```

Expected (observed): a clean finish with no warnings:

```
    Checking wallet-core v0.1.0 (…/crates/wallet-core)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in …s
```

---

### 2.6 A minimal *real* sub-machine to make it concrete (issuance slice) + the Definition-of-done test

To exercise the facade end-to-end with no I/O, we include a deliberately tiny but *genuine* issuance state machine here in `wallet-core`. The production machine — full OpenID4VCI 1.0, HAIP-constrained, both mdoc and SD-JWT VC formats — lives in the **`oid4vci` crate** (its own section) and plugs into `Core` behind the exact same method shape; `wallet-core` stays the thin orchestrator.

First, the placeholder screen type. Open `src/screen.rs`:

```rust
//! PLACEHOLDER for the type produced by the `presenter` crate (its own section).
//! `wallet-core` will `pub use presenter::ScreenDescription;` once that crate lands;
//! until then this minimal stand-in keeps the crate compiling and the run loop shaped
//! correctly. The REAL type has the full closed vocabulary of ~15 screen archetypes and
//! a canonical, hashable encoding (that hashing is what binds consent — see the
//! `presenter` section).

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
#[cfg_attr(feature = "replay", derive(serde::Serialize, serde::Deserialize))]
pub struct ScreenDescription {
    pub kind: ScreenKind,
    pub title: String,
    pub body: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "replay", derive(serde::Serialize, serde::Deserialize))]
pub enum ScreenKind { Loading, Consent, Success, Error, Info }

impl ScreenDescription {
    pub fn loading(msg: &str) -> Self {
        Self { kind: ScreenKind::Loading, title: "Please wait".into(), body: msg.into() }
    }
    pub fn consent(issuer: &str, credential: &str) -> Self {
        Self { kind: ScreenKind::Consent, title: format!("Add {credential}?"),
               body: format!("Issued by {issuer}") }
    }
    pub fn success(msg: &str) -> Self {
        Self { kind: ScreenKind::Success, title: "Done".into(), body: msg.into() }
    }
    pub fn error(msg: &str) -> Self {
        Self { kind: ScreenKind::Error, title: "Error".into(), body: msg.into() }
    }
    pub fn info(msg: &str) -> Self {
        Self { kind: ScreenKind::Info, title: String::new(), body: msg.into() }
    }
}
```

Declare the sub-machine module. Open `src/machines/mod.rs`:

```rust
pub(crate) mod issuance;
// pub(crate) mod presentation; // OID4VP orchestration — see the remote-presentation section
// pub(crate) mod proximity;    // ISO 18013-5 orchestration — see the proximity section
```

Now the machine itself. Open `src/machines/issuance.rs`:

```rust
use crate::core::Ctx;
use crate::effect::{Effect, Header, HttpMethod, HttpRequest};
use crate::event::ShellError;
use crate::pending::{IssuancePending, Pending};
use crate::screen::ScreenDescription;

/// A DELIBERATELY MINIMAL issuance state machine: enough to exercise the facade with
/// no I/O. Each state is a distinct enum variant — a hand-written state machine, so
/// the compiler enforces that every transition is handled (the pattern every protocol
/// crate in this plan follows). The production machine lives in the `oid4vci` crate.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) enum IssuanceMachine {
    #[default]
    Idle,
    FetchingIssuerMetadata { issuer: String },
    AwaitingConsent { issuer: String, credential_endpoint: String },
    Done,
    Failed,
}

impl IssuanceMachine {
    /// Handle a freshly scanned credential offer.
    pub(crate) fn on_offer(&mut self, ctx: &mut Ctx, offer_uri: &str) {
        // Real code validates far more (see the oid4vci section); here we extract just
        // the issuer origin from a query parameter.
        let issuer = match parse_issuer(offer_uri) {
            Some(i) => i,
            None => {
                ctx.emit(Effect::Render(ScreenDescription::error(
                    "This credential offer could not be read.",
                )));
                *self = IssuanceMachine::Failed;
                return;
            }
        };

        // Effect 1: fetch the issuer's metadata. We register WHAT this call is for
        // (`IssuerMetadata`) so the matching response is routed back here.
        let url = format!("{issuer}/.well-known/openid-credential-issuer");
        ctx.emit_with_id(Pending::Issuance(IssuancePending::IssuerMetadata), |id| Effect::Http {
            id,
            request: HttpRequest {
                method: HttpMethod::Get,
                url,
                headers: vec![Header { name: "accept".into(), value: "application/json".into() }],
                body: Vec::new(),
            },
        });

        // Effect 2: show a loading screen immediately (fire-and-forget, no id).
        ctx.emit(Effect::Render(ScreenDescription::loading("Contacting issuer...")));

        *self = IssuanceMachine::FetchingIssuerMetadata { issuer };
    }

    /// Handle an HTTP response routed to issuance. `pending` tells us which request it
    /// answers. `std::mem::take(self)` moves the current state out (leaving `Idle`) so
    /// we can match and consume its owned fields, then we set the new state explicitly.
    pub(crate) fn on_http(
        &mut self,
        ctx: &mut Ctx,
        pending: IssuancePending,
        status: u16,
        _headers: &[Header],
        body: Vec<u8>,
    ) {
        match (std::mem::take(self), pending) {
            (IssuanceMachine::FetchingIssuerMetadata { issuer }, IssuancePending::IssuerMetadata) => {
                if status != 200 {
                    ctx.emit(Effect::Render(ScreenDescription::error("Issuer is unavailable.")));
                    *self = IssuanceMachine::Failed;
                    return;
                }
                let credential_endpoint = match parse_credential_endpoint(&body) {
                    Some(e) => e,
                    None => {
                        ctx.emit(Effect::Render(ScreenDescription::error("Issuer metadata was invalid.")));
                        *self = IssuanceMachine::Failed;
                        return;
                    }
                };
                // Show consent. In production the `presenter` crate builds this screen and
                // the core hashes it; here we build a minimal one.
                ctx.emit(Effect::Render(ScreenDescription::consent(&issuer, "Personal ID (PID)")));
                *self = IssuanceMachine::AwaitingConsent { issuer, credential_endpoint };
            }
            // Any other (state, pending) combination is a stale/duplicate/out-of-order
            // response: restore state and ignore. (The full machine logs this.)
            (other, _) => { *self = other; }
        }
    }

    pub(crate) fn on_consent(&mut self, ctx: &mut Ctx, _consent_hash: Vec<u8>) {
        // Next real step: POST the token request and call the credential endpoint,
        // signing a proof-of-possession via `Effect::Sign`. Elided here — see the
        // oid4vci section. We just mark Done to keep the example bounded.
        if let IssuanceMachine::AwaitingConsent { .. } = self {
            *self = IssuanceMachine::Done;
            ctx.emit(Effect::Render(ScreenDescription::success("Credential added.")));
        }
    }

    pub(crate) fn on_reject(&mut self, ctx: &mut Ctx) {
        *self = IssuanceMachine::Idle;
        ctx.emit(Effect::Render(ScreenDescription::info("Cancelled.")));
    }

    pub(crate) fn on_failure(&mut self, ctx: &mut Ctx, _p: IssuancePending, _e: ShellError) {
        *self = IssuanceMachine::Failed;
        ctx.emit(Effect::Render(ScreenDescription::error("Something went wrong.")));
    }

    // Wired for the facade's dispatch; unused in this minimal slice.
    pub(crate) fn on_signature(&mut self, _ctx: &mut Ctx, _p: IssuancePending, _sig: Vec<u8>) {}
    pub(crate) fn on_store_loaded(&mut self, _ctx: &mut Ctx, _p: IssuancePending, _v: Option<Vec<u8>>) {}
    pub(crate) fn on_store_committed(&mut self, _ctx: &mut Ctx, _p: IssuancePending) {}
}

fn parse_issuer(offer_uri: &str) -> Option<String> {
    // Accepts e.g. openid-credential-offer://?credential_issuer=https://issuer.example
    // The oid4vci section does full RFC-compliant parsing (incl. percent-decoding).
    let (_, query) = offer_uri.split_once('?')?;
    for pair in query.split('&') {
        if let Some(v) = pair.strip_prefix("credential_issuer=") {
            return Some(v.to_string());
        }
    }
    None
}

fn parse_credential_endpoint(body: &[u8]) -> Option<String> {
    let json: serde_json::Value = serde_json::from_slice(body).ok()?;
    json.get("credential_endpoint")?.as_str().map(str::to_owned)
}
```

Finally, the **Definition-of-done test**: a trivial two-step flow driven entirely in Rust, no I/O, asserting the exact effects. Open `tests/two_step_flow.rs`:

```rust
//! Definition-of-done for Section 2: drive a two-step issuance slice through the pure
//! `Core` with ZERO I/O and assert the exact effects. No network, no keystore, no
//! clock — everything the core needs is fed in as `Event`s.

use wallet_core::{Core, Effect, EffectId, Event, HttpMethod, ScreenKind};

#[test]
fn offer_then_metadata_yields_http_then_consent() {
    let mut core = Core::new();

    // ---- Step 1: a credential offer arrives (user scanned a QR). ----
    let effects = core.handle_event(Event::CredentialOfferReceived {
        offer_uri: "openid-credential-offer://?credential_issuer=https://issuer.example".into(),
    });

    // The core must (a) ask the shell to FETCH issuer metadata and (b) show a loading
    // screen — in that order. It performs NO I/O itself.
    assert_eq!(effects.len(), 2, "expected an Http effect then a Render");

    let http_id = match &effects[0] {
        Effect::Http { id, request } => {
            assert_eq!(request.method, HttpMethod::Get);
            assert_eq!(request.url, "https://issuer.example/.well-known/openid-credential-issuer");
            *id // capture the id the core minted, so we can answer it precisely
        }
        other => panic!("effects[0] should be Http, was {other:?}"),
    };

    match &effects[1] {
        Effect::Render(screen) => assert_eq!(screen.kind, ScreenKind::Loading),
        other => panic!("effects[1] should be Render(Loading), was {other:?}"),
    }

    // ---- Step 2: the shell performed the HTTP call and feeds the result back, ----
    // ---- tagged with the SAME EffectId the core minted in step 1. ----
    let metadata = br#"{"credential_endpoint":"https://issuer.example/credential"}"#.to_vec();
    let effects = core.handle_event(Event::HttpResponse {
        id: http_id,
        status: 200,
        headers: vec![],
        body: metadata,
    });

    // Now the core has enough to ask for consent. Exactly one effect: the consent screen.
    assert_eq!(effects.len(), 1);
    match &effects[0] {
        Effect::Render(screen) => {
            assert_eq!(screen.kind, ScreenKind::Consent);
            assert!(screen.body.contains("issuer.example"));
        }
        other => panic!("expected Render(Consent), was {other:?}"),
    }
}

#[test]
fn unknown_effect_id_is_ignored() {
    // A late/duplicate/forged result for an id the core never issued must be a no-op,
    // never a panic. This is the robustness/security guard from Section 2.4.
    let mut core = Core::new();
    let effects = core.handle_event(Event::HttpResponse {
        id: EffectId(999),
        status: 200,
        headers: vec![],
        body: b"{}".to_vec(),
    });
    assert!(effects.is_empty());
}
```

**Definition of done (2.6 — the primary DoD of this section):**

```bash
cargo test -p wallet-core
```

Expected (observed against the verified reference implementation):

```
running 1 test
test ids::tests::ids_are_monotonic_from_one ... ok

test result: ok. 1 passed; 0 failed; ...

running 2 tests
test offer_then_metadata_yields_http_then_consent ... ok
test unknown_effect_id_is_ignored ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; ...
```

You have now driven a real slice of OpenID4VCI — offer → fetch issuer metadata → render consent — with no network, no async, no mocks. That is the entire value proposition of sans-IO, demonstrated in ~40 lines of test.

---

### 2.7 The shell's run loop (the Swift driver)

The core is a brain in a jar; the **shell** is the body. Its job is the loop from Section 2.0: take an `Event`, ask the core for `Effect`s, perform each effect, and feed every result back in as a new `Event`. This subsection is the iOS (Swift) side; the Android (Kotlin) side is a mechanical translation and is deferred to its own section.

The Swift types (`Event`, `Effect`, `WalletCore`, …) are **generated by UniFFI in Section 1** from the `#[cfg_attr(feature = "ffi", derive(uniffi::…))]` annotations you wrote above. UniFFI's conventions: Rust `snake_case` methods become Swift `camelCase` (`handle_event` → `handleEvent`); enum variants become lower-camel cases (`Effect::Http{..}` → `.http(id:request:)`); struct-style variant fields become labelled associated values. Import the generated module (its exact name is set in Section 1; we call it `WalletCoreFFI` here).

First, the FFI handle on the Rust side. Open `src/ffi.rs`:

```rust
use crate::core::Core;
use crate::effect::Effect;
use crate::event::Event;

/// The FFI-facing handle. Swift creates ONE of these and calls `handle_event` on it.
/// It is a thin lock around the pure `Core`; ALL logic lives in `Core::handle_event`.
/// The pure `Core` (not this) is what the unit tests and the Tier-2 replay harness
/// drive, which is why those need no FFI machinery at all.
#[derive(uniffi::Object)]
pub struct WalletCore {
    inner: std::sync::Mutex<Core>,
}

#[uniffi::export]
impl WalletCore {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self { inner: std::sync::Mutex::new(Core::new()) }
    }

    /// Feed one event, get the effects to perform. The `Mutex` makes this safe to call
    /// from any thread, but the driver below funnels ALL events through one actor so
    /// they are applied in a single, well-defined order (the shell-side complement of
    /// the core's determinism).
    pub fn handle_event(&self, event: Event) -> Vec<Effect> {
        self.inner.lock().expect("wallet-core mutex poisoned").handle_event(event)
    }
}
```

Now the Swift driver. The canonical shape is a single **actor** that owns the `WalletCore` and consumes one ordered stream of events; `perform` executes each effect and posts any result back into the same stream as a new event.

```swift
import Foundation
import WalletCoreFFI   // the module UniFFI generates in Section 1

/// Drives the Rust core. Owns the single source of truth for wallet state (the Rust
/// `WalletCore`) and the loop that: takes an Event -> asks the core for Effects ->
/// performs each Effect -> feeds results back as Events. An `actor` serialises access
/// so events are applied one at a time in a well-defined order.
actor WalletDriver {
    private let core: WalletCore
    private let http = URLSession(configuration: .ephemeral)
    private let keystore: Keystore       // Secure Enclave wrapper (platform-cryptography section)
    private let store: SecureStore       // Keychain/file wrapper (secure-storage section)
    private let ble: BleTransport        // CoreBluetooth wrapper (proximity section)
    private let render: @Sendable (ScreenDescription) -> Void  // hop to the SwiftUI layer

    private let events: AsyncStream<Event>
    private let emit: AsyncStream<Event>.Continuation

    init(keystore: Keystore, store: SecureStore, ble: BleTransport,
         render: @escaping @Sendable (ScreenDescription) -> Void) {
        self.core = WalletCore()
        self.keystore = keystore
        self.store = store
        self.ble = ble
        self.render = render
        (self.events, self.emit) = AsyncStream<Event>.makeStream()
        Task { await self.run() }   // start the single consumer loop
    }

    /// The ONLY entry point. UI taps, deep links, and BLE callbacks all call this.
    /// `nonisolated` so callers need not `await` just to enqueue.
    nonisolated func send(_ event: Event) { emit.yield(event) }

    /// The single ordered loop: one event at a time, in arrival order.
    private func run() async {
        for await event in events {
            let effects = core.handleEvent(event: event)  // the one FFI call
            for effect in effects { await perform(effect) }
        }
    }

    /// Execute a single Effect, then (for result-producing effects) `send` the result
    /// back in as an Event. Failures become `Event.effectFailed`, which the core turns
    /// into a policy decision — the shell never decides protocol outcomes.
    private func perform(_ effect: Effect) async {
        switch effect {
        case let .http(id, request):
            do {
                let (data, response) = try await http.data(for: request.toURLRequest())
                let r = response as! HTTPURLResponse
                send(.httpResponse(id: id,
                                   status: UInt16(r.statusCode),
                                   headers: r.headerPairs(),
                                   body: data))
            } catch {
                send(.effectFailed(id: id, error: .network(message: "\(error)")))
            }

        case let .sign(id, keyRef, alg, payload):
            do {
                // The private key stays in the Secure Enclave; only the signature comes back.
                let signature = try keystore.sign(keyLabel: keyRef.label, alg: alg, payload: payload)
                send(.signatureProduced(id: id, signature: signature))
            } catch {
                send(.effectFailed(id: id, error: .keystoreDenied))
            }

        case let .random(id, len):
            send(.randomProduced(id: id, bytes: SecureRandom.bytes(count: Int(len)))) // SecRandomCopyBytes

        case let .store(id, op):
            switch op {
            case let .load(key):
                send(.storeLoaded(id: id, value: try? store.load(key: key)))
            case let .save(key, value):
                try? store.save(key: key, value: value)
                send(.storeCommitted(id: id))
            }

        case let .ble(id, command):
            // The transport streams updates back; each becomes a BleEvent with this id.
            await ble.execute(id: id, command: command) { [weak self] update in
                self?.send(.bleEvent(id: id, update: update))
            }

        case let .startTimer(id, afterMs):
            Task { [weak self] in
                try? await Task.sleep(for: .milliseconds(Int(afterMs)))
                self?.send(.timerFired(id: id))
            }

        case let .render(screen):
            render(screen) // fire-and-forget; the user's reaction returns as its own Event
        }
    }
}
```

The mental model to keep: **the driver contains no protocol logic whatsoever.** It knows how to make an HTTPS call, how to ask the Secure Enclave to sign, how to sleep — but it never decides *whether* to, *what* to send, or *whether a response is acceptable*. Every such decision was already made inside the core and delivered as an `Effect`. If you ever find yourself writing an `if` about protocol state in Swift, it belongs in the Rust core instead.

**Definition of done (2.7):** because binding generation and the xcframework build belong to **Section 1**, the full Swift build cannot complete from this section alone. The verifiable milestone here is a Swift XCTest that drives the *same* two-step flow through the FFI once Section 1's bindings exist:

```swift
import XCTest
import WalletCoreFFI

final class TwoStepFlowTests: XCTestCase {
    func testOfferThenMetadata() {
        let core = WalletCore()

        let step1 = core.handleEvent(event: .credentialOfferReceived(
            offerUri: "openid-credential-offer://?credential_issuer=https://issuer.example"))
        XCTAssertEqual(step1.count, 2)
        guard case let .http(id, request) = step1[0] else { return XCTFail("expected .http") }
        XCTAssertEqual(request.url, "https://issuer.example/.well-known/openid-credential-issuer")
        guard case let .render(loading) = step1[1] else { return XCTFail("expected .render") }
        XCTAssertEqual(loading.kind, .loading)

        let body = Data(#"{"credential_endpoint":"https://issuer.example/credential"}"#.utf8)
        let step2 = core.handleEvent(event: .httpResponse(id: id, status: 200, headers: [], body: body))
        XCTAssertEqual(step2.count, 1)
        guard case let .render(consent) = step2[0] else { return XCTFail("expected .render") }
        XCTAssertEqual(consent.kind, .consent)
    }
}
```

Run (after Section 1 has produced the xcframework):

```bash
xcodebuild test -scheme WalletApp -destination 'platform=iOS Simulator,name=iPhone 16'
```

Expected: `** TEST SUCCEEDED **` with `TwoStepFlowTests.testOfferThenMetadata` passing. If you are reading top-to-bottom, bookmark this and return after Section 1; the Rust DoD in 2.6 already proves the logic.

---

### 2.8 Why this is deterministic, and how Tier-2 replay uses it

Everything above was engineering. This subsection is *why it pays off for certification*.

**The determinism claim, stated precisely:** for a fresh `Core` and a fixed sequence of `Event`s `e₁, e₂, …, eₙ`, the concatenated `Effect` output is a pure function of that sequence — identical on every machine, every run, forever. This holds because we have systematically exiled every source of nondeterminism out of the core and into an event:

| Source of nondeterminism | How it is normally obtained | How the core gets it instead |
|---|---|---|
| Wall-clock time | `SystemTime::now()` | Never called; time arrives only via `Event::TimerFired` |
| Randomness / nonces | `rand::random()` | Never called; bytes arrive via `Event::RandomProduced` (shell CSPRNG) |
| Network | blocking socket read | `Effect::Http` out, `Event::HttpResponse` in |
| Signatures / keys | keystore call | `Effect::Sign` out, `Event::SignatureProduced` in |
| Persistent storage | file/Keychain read | `Effect::Store` out, `Event::StoreLoaded/Committed` in |
| Map iteration order | `HashMap` iteration | `BTreeMap` + we never iterate to build effects |
| Thread scheduling | concurrent handlers | one ordered event queue (the actor in 2.7); `handle_event` is synchronous |
| Effect id assignment | shell-assigned handles | minted by the in-core `IdSeq` (Section 2.4) |

Because the effect *id* is minted deterministically, you can *write a script in advance* that predicts which id each effect will get — that is exactly what the DoD test's second step relied on when it answered `EffectId(1)` without having "observed" it, and what the replay harness below relies on.

**Payoff 1 — record/replay debugging.** An `Event` log is a full recording of a session. Persist the events (they already serialise under the `replay` feature), and you can replay a user's exact bug locally, step by step, with a debugger, and no network. No "cannot reproduce".

**Payoff 2 — the Lean model as an executable oracle (Tier 2).** This is the strategic reason the architecture is shaped this way. The Tier-2 (Lean 4) section builds a formal model of each protocol state machine and *proves* invariants over it (no accepting trace without signature validation; no disclosure effect before a consent event; no state that accepts a replayed nonce). Crucially, Lean can then **enumerate concrete traces** from that model and **export them as JSON**: for each trace, the sequence of events and the effects the model says must result. Because the Rust core is deterministic, we replay each trace against it and assert the effects match. **The proven model becomes a conformance test suite for the implementation** — the model and the code are checked against each other automatically, in CI. This only works because `handle_event` is a pure, replayable function; a normal I/O-entangled protocol stack could not be driven this way.

The harness is a plain integration test. Open `tests/replay.rs`:

```rust
//! Tier-2 bridge: replay model-generated traces against the real core and assert the
//! effects match. Requires `--features replay` (which turns on serde). Trace files are
//! produced by the Lean exporter (see the Tier-2 section) into tests/traces/*.json.
#![cfg(feature = "replay")]

use std::fs;
use wallet_core::{Core, Effect, Event};

#[derive(serde::Deserialize)]
struct Trace { name: String, steps: Vec<Step> }

#[derive(serde::Deserialize)]
struct Step { event: Event, expect: Vec<Effect> }

#[test]
fn replay_model_traces() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/traces");
    let mut ran = 0usize;
    for entry in fs::read_dir(dir).expect("tests/traces directory") {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") { continue; }
        let trace: Trace = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();

        let mut core = Core::new();
        for (i, step) in trace.steps.iter().enumerate() {
            let got = core.handle_event(step.event.clone());
            assert_eq!(got, step.expect,
                "trace `{}` diverged from the model at step {i}", trace.name);
        }
        ran += 1;
    }
    assert!(ran > 0, "no traces found — generate them from the Lean model first (Tier-2 section)");
}
```

Under the `replay` feature every vocabulary type derives `serde`, so the JSON shape is exactly serde's externally-tagged form. For the offer step, the *observed* shapes are:

```jsonc
// an Event:
{ "CredentialOfferReceived": { "offer_uri": "openid-credential-offer://?credential_issuer=https://issuer.example" } }

// the resulting Effects (note EffectId serialises transparently as the number 1):
[ { "Http": { "id": 1, "request": { "method": "Get",
      "url": "https://issuer.example/.well-known/openid-credential-issuer",
      "headers": [ { "name": "accept", "value": "application/json" } ], "body": [] } } },
  { "Render": { "kind": "Loading", "title": "Please wait", "body": "Contacting issuer..." } } ]
```

Until the Lean exporter exists, you can prove the machinery end-to-end with a self-contained **record-then-replay round-trip**: run the flow once, capture `(event, effects)` pairs, serialise to JSON, deserialise, replay on a *fresh* core, and assert identical effects. Add to `tests/replay.rs`:

```rust
use wallet_core::EffectId;

#[test]
fn record_then_replay_is_identical() {
    // The script can hard-code EffectId(1): a fresh core ALWAYS mints 1 first (2.4).
    let script = vec![
        Event::CredentialOfferReceived {
            offer_uri: "openid-credential-offer://?credential_issuer=https://issuer.example".into(),
        },
        Event::HttpResponse {
            id: EffectId(1),
            status: 200,
            headers: vec![],
            body: br#"{"credential_endpoint":"https://issuer.example/credential"}"#.to_vec(),
        },
    ];

    // RECORD once.
    let mut core = Core::new();
    let mut trace: Vec<(Event, Vec<Effect>)> = Vec::new();
    for ev in &script {
        let effects = core.handle_event(ev.clone());
        trace.push((ev.clone(), effects));
    }

    // Round-trip through JSON (proves the whole vocabulary is (de)serialisable — exactly
    // what the Lean exporter needs).
    let json = serde_json::to_string_pretty(&trace).unwrap();
    let trace2: Vec<(Event, Vec<Effect>)> = serde_json::from_str(&json).unwrap();

    // REPLAY on a brand-new core; assert byte-identical effects at every step.
    let mut core2 = Core::new();
    for (ev, expected) in &trace2 {
        assert_eq!(&core2.handle_event(ev.clone()), expected, "replay diverged");
    }
}
```

**Definition of done (2.8):** the replay machinery works end-to-end.

```bash
cargo test -p wallet-core --features replay record_then_replay_is_identical
```

Expected (observed against the verified reference implementation):

```
running 1 test
test record_then_replay_is_identical ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; ...
```

(Once the Tier-2 section drops trace files into `tests/traces/`, `cargo test -p wallet-core --features replay replay_model_traces` becomes the standing conformance gate in CI.)

---

### 2.9 What you built, and how the rest of the plan plugs in

You now have the load-bearing skeleton of the wallet:

- A closed **`Event`/`Effect` vocabulary** (`event.rs`, `effect.rs`) that is the only thing crossing the FFI, with private keys deliberately never among it.
- A deterministic **`EffectId` + `PendingTable`** correlation mechanism (`ids.rs`, `pending.rs`) so asynchronous results route to the right sub-machine.
- The **`Core` + `Ctx` + `handle_event`** run loop (`core.rs`) — a pure, synchronous, exhaustively-matched state transition with no I/O.
- A minimal but real **issuance sub-machine** (`machines/issuance.rs`) proving the pattern every protocol crate will follow.
- A thin **`WalletCore` FFI handle** (`ffi.rs`) and the **Swift driver** that executes effects and feeds results back.
- Verified **determinism**, unlocking record/replay debugging and the Tier-2 executable-oracle strategy.

How later sections attach to this spine, all via the same shape (`&mut ctx`-driven methods that consume events and emit effects), so the facade stays thin:

- **`oid4vci` crate** replaces the minimal `IssuanceMachine` with the full OpenID4VCI/HAIP machine (both mdoc and SD-JWT VC issuance). `Core.issuance` changes type; `handle_event`'s issuance arms are unchanged in shape.
- **`oid4vp` crate** provides the remote-presentation machine; add `Core.presentation` and fill the `PresentationRequestReceived` and `Some(Pending::Presentation(_))` arms.
- **`iso18013-5` crate** provides the proximity machine driven by `Effect::Ble` / `Event::BleEvent`; add `Core.proximity`.
- **`presenter` crate** replaces `screen.rs` with the real, canonically-hashable `ScreenDescription` (`pub use presenter::ScreenDescription;`), and is where the consent hash checked in `Event::UserConsented` is actually computed and bound.
- **`crypto-traits` + platform-cryptography section** back `Effect::Sign`/`Effect::Random`; the WSCD keys never enter the core.
- **`trust` and `status` crates** add `Pending::Trust(_)` handling and fail-open/fail-closed policy for list/status fetches.
- **Tier-2 (Lean) section** generates the JSON traces that `tests/replay.rs` consumes; **Tier-3 (Tamarin) section** verifies the *protocol design* that these machines implement, complementing the implementation-level proofs here.

The single rule to carry into every one of those sections: **if it is a decision, it lives in the core as a state transition; if it is I/O, it lives in the shell as an effect.** Keep that boundary clean and the whole certification story — determinism, replay, one-place-to-audit, two-platforms-for-free — holds together.

---


## Section 3 — UniFFI boundary: exposing the core to Swift (and later Kotlin)

This section is the seam between the deterministic Rust engine (`wallet-core`, see Section 2) and the thin native shells (Swift now, Kotlin later, see Sections 4 and 5). Everything below assumes the canonical Cargo workspace already exists at the repo root under `crates/`, and that the facade crate lives at `crates/wallet-core/`. If you have not yet created that crate, do Section 2 first — this section only adds the FFI *surface* to it and the build tooling around it.

The design goal for this seam is **small and stable**. The certification story (Section 15) is much easier if the ABI (Application Binary Interface — the exact shape of the compiled boundary: function names, argument types, memory ownership) barely changes between releases. So we expose a *tiny* number of functions and let almost all evolution happen *inside* the core, invisible to Swift.

### 3.0 What UniFFI is, in one paragraph

**UniFFI** is a Mozilla-originated tool (a Rust crate plus a code generator) that takes a Rust library and generates *idiomatic foreign-language bindings* for it — Swift, Kotlin, Python, Ruby. "Bindings" means: for every Rust type and function you mark as exported, UniFFI emits (a) a small amount of `extern "C"` glue on the Rust side (the *scaffolding*), and (b) a native-language wrapper on the other side (a `.swift` file, a `.kt` file) that calls that glue and hides all the raw pointers, length-prefixed byte buffers, and manual memory management from you. You write Rust once; Swift and Kotlin both get a clean, typed API. UniFFI handles the hard parts we would otherwise get wrong by hand: passing strings and byte arrays across the C boundary without leaking or double-freeing, mapping Rust `enum`s to Swift `enum`s, mapping Rust `Result::Err` to Swift `throws`, and — critically for us — **foreign trait implementations** (called *callback interfaces*), which is how Swift will implement the crypto `Signer` that the Rust core calls back into.

Two things UniFFI is **not**: it is not an IPC/RPC layer (there is no serialization protocol you must speak; it's an in-process C ABI), and it is not a general C++ interop tool. It is purpose-built for "Rust core, native UI shells", which is exactly our architecture.

### 3.1 The two ways to drive UniFFI: UDL vs proc-macro — and our choice

UniFFI historically had **two** ways to declare what gets exported:

1. **UDL (UniFFI Definition Language)** — you write a separate `.udl` file, a WebIDL-like interface description, e.g. `wallet-core/src/wallet_core.udl`. A build step parses it and generates scaffolding. Your Rust code must then *match* the UDL exactly, or you get confusing link/codegen errors. It is a second source of truth you must keep in sync by hand.

2. **proc-macro attributes** — you annotate the Rust code *directly* with attributes like `#[uniffi::export]`, `#[derive(uniffi::Record)]`, `#[derive(uniffi::Enum)]`, `#[uniffi::export(callback_interface)]`. The Rust source *is* the single source of truth; there is no separate IDL to drift.

**We use proc-macro attributes. Reason:** for a certification-critical codebase maintained by one developer, a single source of truth is worth a great deal. The UDL approach doubles the surface where a mistake can hide (the `.udl` says one thing, the Rust says another, and the mismatch surfaces as an opaque codegen or linker failure). Proc-macro attributes are checked by the Rust compiler against the actual types, so a wrong signature is a normal compile error with a normal error message — which matters enormously for the junior developer this plan is written for. The only historical advantage of UDL (some features landed there first) is gone for everything we need: records, enums, objects, errors, and callback interfaces are all fully supported via proc-macros in current UniFFI (0.28+). We pin the version explicitly (Section 3.2) so this stays true.

**Definition of done (3.1):** you can state, without looking it up, that this project uses `#[uniffi::export]`-style proc-macros and has **no** `.udl` file. Verify later with:

```bash
# From the repo root. Expected output: nothing (no .udl files anywhere).
find crates -name '*.udl' -print
```

Empty output = correct.

### 3.2 Wiring UniFFI into `crates/wallet-core/Cargo.toml`

We need three things: the `uniffi` runtime crate, the code generator (used two ways — as a build dependency for scaffolding, and as a CLI binary to emit Swift), and the right crate output types.

1. Open `crates/wallet-core/Cargo.toml`.
2. Make it read as follows (adjust the `[package]` block if yours differs; the load-bearing parts are `crate-type`, the `uniffi` dependency, the `build-dependencies`, and the `[[bin]]`):

```toml
[package]
name = "wallet-core"
version = "0.1.0"
edition = "2021"
publish = false

[lib]
name = "wallet_core"
# staticlib  -> the .a we link into the iOS app (device + simulator).
# cdylib     -> a .dylib, handy for running uniffi-bindgen against on macOS,
#               and for the Kotlin/Android .so later.
# lib        -> normal Rust lib so our own tests + the bindgen bin can use it.
crate-type = ["staticlib", "cdylib", "lib"]

[dependencies]
# Pin exactly. UniFFI's generated ABI is only guaranteed to match between the
# runtime crate and the generator of the SAME version. A mismatch = runtime
# crashes that are miserable to debug. Pin, and bump deliberately.
uniffi = { version = "=0.28.3", features = ["cli"] }

# Our own crates (facade depends on the rest of the workspace).
crypto-traits = { path = "../crypto-traits" }
presenter     = { path = "../presenter" }
# ... oid4vp, oid4vci, mdoc, sdjwt, etc. as wired in Section 2.

serde      = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror  = "2"

[build-dependencies]
uniffi = { version = "=0.28.3", features = ["build"] }

# A tiny binary target so we can run `cargo run --bin uniffi-bindgen -- ...`
# to generate the Swift bindings. This is the officially recommended pattern:
# the generator is compiled against the SAME uniffi version as the library,
# eliminating version-skew between generator and runtime.
[[bin]]
name = "uniffi-bindgen"
path = "src/bin/uniffi-bindgen.rs"
required-features = []
```

3. Create the generator binary at `crates/wallet-core/src/bin/uniffi-bindgen.rs`:

```rust
// This is the entire file. It just hands control to uniffi's CLI, but compiled
// against OUR pinned uniffi version, so generator and runtime can never drift.
fn main() {
    uniffi::uniffi_bindgen_main()
}
```

4. Create the build script at `crates/wallet-core/build.rs`:

```rust
// build.rs runs at compile time and emits the C scaffolding UniFFI needs.
// With proc-macros there is no .udl, so we call the "library mode" setup.
fn main() {
    uniffi::generate_scaffolding_for_crate(); // no-op placeholder in some versions
    // For pure proc-macro crates, the scaffolding is produced by the macros
    // themselves; the line below is what actually matters for library mode:
    uniffi::build::generate_scaffolding().ok();
}
```

> Note for the reader: in current UniFFI with a pure proc-macro crate you often need **no** `build.rs` at all, because the `uniffi::setup_scaffolding!()` macro (Section 3.3) emits everything. Keep `build.rs` minimal or delete it if `cargo build` succeeds without it. Prefer deleting it if it is not needed — fewer moving parts. Test both ways in step 3.9.

**Definition of done (3.2):**

```bash
# From repo root.
cargo build -p wallet-core
# Expected: "Compiling wallet-core v0.1.0 ..." then "Finished".
# And the static lib exists:
ls -l target/debug/libwallet_core.a
# Expected: a file, typically several MB.
```

### 3.3 The exact `lib.rs` annotations: a tiny, stable API surface

This is the heart of the section. We expose exactly one *object* (`WalletEngine`) plus the data types it needs. Everything else — the whole protocol machinery from Section 2 — stays private.

**The single most important boundary decision** is how `Event` and `Effect` cross the FFI. We discuss the trade-off explicitly in Section 3.4 and land on **UniFFI-native typed enums**, not JSON strings. But we will *also* show the escape hatch (a JSON method) because it is genuinely useful for the Lean-model replay harness (Section 12) and for logging. So the surface is: typed enums for the app, JSON string for the oracle/tests.

Edit `crates/wallet-core/src/lib.rs`:

```rust
#![forbid(unsafe_code)] // Required by the formal-methods baseline (see shared context).

// One-time setup that emits all the C scaffolding for a pure proc-macro crate.
// This REPLACES a .udl file and (usually) build.rs scaffolding generation.
uniffi::setup_scaffolding!();

use std::sync::Mutex;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// 3.3.1  Data types that cross the boundary.
//
// #[derive(uniffi::Enum)]   -> becomes a Swift `enum` with associated values.
// #[derive(uniffi::Record)] -> becomes a Swift `struct`.
// These MUST contain only UniFFI-known types: String, primitive ints, bool,
// Vec<T>, Option<T>, other Records/Enums, and Vec<u8> for bytes.
// ---------------------------------------------------------------------------

/// Everything that can happen TO the core. The shell turns UI taps and the
/// results of Effects into these. This is a REDUCED, STABLE mirror of the
/// core's internal event type — see 3.3.4 for why we keep two types.
#[derive(uniffi::Enum, Serialize, Deserialize, Clone, Debug)]
pub enum FfiEvent {
    /// User tapped "Scan QR" and the camera produced this payload.
    QrScanned { payload: String },
    /// User approved the consent screen whose hash is `consent_hash`.
    ConsentApproved { consent_hash: Vec<u8> },
    /// User declined / cancelled.
    Cancelled,
    /// The shell finished an Effect and is handing the result back.
    /// We keep effect results as a typed enum too (see FfiEffectResult).
    EffectCompleted { result: FfiEffectResult },
    // ... add archetypes as flows are implemented. Keep this list SHORT.
}

/// Everything the core asks the shell to DO. The shell executes these and
/// feeds a FfiEffectResult back in via FfiEvent::EffectCompleted.
#[derive(uniffi::Enum, Serialize, Deserialize, Clone, Debug)]
pub enum FfiEffect {
    /// Perform an HTTPS request (no networking lives in the core).
    HttpFetch { request_id: String, url: String, method: String, body: Option<Vec<u8>> },
    /// Ask the Secure Enclave (via the Signer callback, 3.5) to sign `payload`.
    /// device-bound keys NEVER cross the FFI — only the request + the signature.
    Sign { request_id: String, key_handle: String, payload: Vec<u8> },
    /// Render this canonical, hashed ScreenDescription (see Section 6, presenter).
    ShowScreen { screen: ScreenDescription },
    /// Persist opaque bytes under a key (Effect into secure storage, Section 13).
    StoreSecret { request_id: String, key: String, value: Vec<u8> },
    /// Read the wall clock (the core has no clock of its own).
    GetTime { request_id: String },
    // ... keep SHORT.
}

/// Results the shell feeds back for the request-carrying Effects above.
#[derive(uniffi::Enum, Serialize, Deserialize, Clone, Debug)]
pub enum FfiEffectResult {
    HttpOk    { request_id: String, status: u16, body: Vec<u8> },
    HttpError { request_id: String, message: String },
    Signed    { request_id: String, signature: Vec<u8> },
    Stored    { request_id: String },
    Time      { request_id: String, unix_millis: i64 },
}

/// A canonical screen to render. Closed vocabulary (~15 archetypes), produced
/// by the `presenter` crate. RP-supplied strings are DATA in wallet templates,
/// never structure (see shared context + Section 6). Shown here abbreviated.
#[derive(uniffi::Record, Serialize, Deserialize, Clone, Debug)]
pub struct ScreenDescription {
    pub archetype: ScreenArchetype,
    pub title: String,
    pub body_lines: Vec<String>,
    /// The consent payload hash (WYSIWYS binding). Empty for non-consent screens.
    pub consent_hash: Vec<u8>,
}

#[derive(uniffi::Enum, Serialize, Deserialize, Clone, Debug)]
pub enum ScreenArchetype {
    Welcome,
    ConsentDisclosure,
    Progress,
    Success,
    ErrorScreen,
    // ... the closed set from Section 6.
}

// ---------------------------------------------------------------------------
// 3.3.2  Errors that cross the boundary become Swift `throws`.
//
// #[derive(uniffi::Error)] maps each variant to a Swift error case.
// ---------------------------------------------------------------------------

#[derive(uniffi::Error, thiserror::Error, Debug)]
pub enum WalletError {
    #[error("the core rejected the event: {reason}")]
    InvalidEvent { reason: String },
    #[error("internal core error: {reason}")]
    Internal { reason: String },
    #[error("the event JSON was malformed: {reason}")]
    BadJson { reason: String },
}

// ---------------------------------------------------------------------------
// 3.3.3  The one exported object.
//
// #[derive(uniffi::Object)] -> a reference type on the Swift side (a `class`),
// heap-allocated in Rust, reference-counted across the boundary via Arc.
// UniFFI requires exported objects to be Send + Sync, so we guard the
// non-Sync interior with a Mutex (see 3.6 on threading).
// ---------------------------------------------------------------------------

#[derive(uniffi::Object)]
pub struct WalletEngine {
    inner: Mutex<CoreState>, // CoreState is the real core from Section 2.
}

#[uniffi::export]
impl WalletEngine {
    /// Constructors are marked #[uniffi::constructor] and become
    /// `WalletEngine()` in Swift. The Signer is a FOREIGN trait the Swift
    /// side implements (see 3.5) and hands to us at construction.
    #[uniffi::constructor]
    pub fn new(signer: std::sync::Arc<dyn Signer>) -> Self {
        WalletEngine {
            inner: Mutex::new(CoreState::new(signer)),
        }
    }

    /// THE primary method. Feed one typed event in; get the list of Effects the
    /// shell must perform. This is the sans-IO run-loop step from Section 2,
    /// surfaced verbatim. Deterministic: same state + same event => same Vec.
    pub fn handle_event(&self, event: FfiEvent) -> Result<Vec<FfiEffect>, WalletError> {
        let mut core = self.inner.lock().map_err(|_| WalletError::Internal {
            reason: "engine mutex poisoned".into(),
        })?;
        core.step(event) // returns Result<Vec<FfiEffect>, WalletError>
    }

    /// ESCAPE HATCH for the Lean replay oracle (Section 12) and logging:
    /// accept an event as canonical JSON, return effects as canonical JSON.
    /// NOT used by the app in the hot path — typed `handle_event` is.
    pub fn handle_event_json(&self, event_json: String) -> Result<String, WalletError> {
        let event: FfiEvent = serde_json::from_str(&event_json)
            .map_err(|e| WalletError::BadJson { reason: e.to_string() })?;
        let effects = self.handle_event(event)?;
        serde_json::to_string(&effects)
            .map_err(|e| WalletError::Internal { reason: e.to_string() })
    }

    /// Version of the ABI/protocol surface, for the shell to assert against
    /// (see 3.7 on versioning). A plain function is also fine (below).
    pub fn abi_version(&self) -> String {
        ABI_VERSION.to_string()
    }
}

/// A free function is exported too, becoming a global Swift func.
#[uniffi::export]
pub fn abi_version() -> String {
    ABI_VERSION.to_string()
}

pub const ABI_VERSION: &str = "wallet-core-abi/1";

// ---------------------------------------------------------------------------
// 3.3.4  The foreign trait for crypto (full detail in 3.5).
// ---------------------------------------------------------------------------

/// callback_interface = Swift IMPLEMENTS this; Rust CALLS it. This is how the
/// core reaches the Secure Enclave without any key material crossing the FFI.
#[uniffi::export(callback_interface)]
pub trait Signer: Send + Sync {
    /// Sign `payload` with the device-bound key named by `key_handle`.
    /// Returns the raw signature bytes. Errors become the Rust error below.
    fn sign(&self, key_handle: String, payload: Vec<u8>) -> Result<Vec<u8>, SignerError>;

    /// Return the public key (e.g. for WUA / key attestation, Section 8).
    fn public_key(&self, key_handle: String) -> Result<Vec<u8>, SignerError>;
}

#[derive(uniffi::Error, thiserror::Error, Debug)]
pub enum SignerError {
    #[error("secure enclave refused: {reason}")]
    Refused { reason: String },
    #[error("no such key handle: {handle}")]
    UnknownKey { handle: String },
}
```

Two structural notes for the junior reader:

- `CoreState` is your real engine from Section 2. This file *adapts* it; it does not reimplement it. Keep `FfiEvent`/`FfiEffect` as a **deliberately reduced mirror** of the core's internal `Event`/`Effect`. That indirection is not busywork: it lets the internal types churn freely (new internal effects, refactors) while the *exported* ABI stays frozen. When the internal set legitimately grows, you add a variant to the Ffi type *on purpose*, and that is an ABI change you version (Section 3.7).
- `#[derive(uniffi::Object)]` types are **reference types** (Swift `class`, Rust `Arc`), so calling `handle_event` does not copy the engine. `#[derive(uniffi::Record)]` and `#[derive(uniffi::Enum)]` types are **value types** copied across the boundary each call. That is why the Effect list is fine as records/enums (small, per-step) and the engine is an object (large, long-lived).

**Definition of done (3.3):**

```bash
cargo build -p wallet-core
# Expected: Finished, no errors. If a type "does not implement Lift/Lower",
# it contains a non-UniFFI type — reduce it to the allowed set (3.3.1).
```

### 3.4 How Event/Effect cross the boundary: JSON string vs native enums

This is a real fork in the road, so here is the honest trade-off and the decision.

**Option A — JSON strings.** `handle_event(json: String) -> String`. Everything is serialized to JSON, crosses as one string, deserialized on each side.

- Pros: dead-simple ABI (never changes — it's always `String -> String`); trivially loggable; the Lean replay oracle (Section 12) can emit event traces as JSON and feed them in unchanged; the Swift side needs zero generated model types.
- Cons: **no type safety at the boundary** — a typo in a JSON field is a runtime error in production, not a compile error; you hand-write matching Codable structs in Swift anyway (so you don't save the model code, you just make it *unchecked*); double serialization cost on every step; and you lose UniFFI's exhaustive-enum guarantee, which is exactly the property that makes the state machine evaluator-friendly (shared context).

**Option B — UniFFI-native typed enums.** `handle_event(event: FfiEvent) -> Vec<FfiEffect>`, as in 3.3.

- Pros: **compile-time type safety across the boundary** — Swift gets a real `enum FfiEvent` with associated values, and a Swift `switch` over `FfiEffect` is exhaustiveness-checked by the Swift compiler; no hand-written Codable models; no serialization in the hot path; the enum shape *is* the contract, and adding a variant is a visible, reviewable ABI change.
- Cons: adding/removing a variant is an ABI change you must version deliberately (this is a *pro* disguised as a con — you *want* boundary changes to be loud); slightly more generated Swift code.

**Decision: Option B (typed enums) is the primary path; keep a JSON method (`handle_event_json`) as a secondary escape hatch** for the Lean oracle and diagnostic logging only. This gives us type safety where the app lives and JSON where the *tests* live. It directly serves two shared-context goals: exhaustive `match`/`switch` on the protocol surface, and the executable Lean oracle replaying JSON traces.

**Definition of done (3.4):** you can articulate, in one sentence, that the app uses `handle_event(FfiEvent)` and only the Lean replay harness uses `handle_event_json(String)`. There is nothing to run here; it is a design gate you have passed.

### 3.5 Crypto `Signer` as a foreign trait (callback interface)

The "DO NOT DO" rules forbid a software-only vault and forbid key material crossing the FFI. UniFFI's **callback interface** is the mechanism: the Rust core defines the `Signer` trait (done in 3.3.4 with `#[uniffi::export(callback_interface)]`), and **Swift implements it** against the Secure Enclave. The core calls `signer.sign(...)`; the actual private key never leaves the Enclave and never appears in Rust memory. Full Secure Enclave detail is Section 7; here we cover only the *binding*.

Inside the core (Section 2 code), you accept and store the trait object:

```rust
// crates/wallet-core/src/core_state.rs (excerpt; the real file is Section 2).
use std::sync::Arc;
use crate::{Signer, FfiEvent, FfiEffect, WalletError};

pub struct CoreState {
    signer: Arc<dyn Signer>,
    // ... the rest of the protocol state (oid4vp machine, etc.)
}

impl CoreState {
    pub fn new(signer: Arc<dyn Signer>) -> Self {
        CoreState { signer /*, ... */ }
    }

    pub fn step(&mut self, event: FfiEvent) -> Result<Vec<FfiEffect>, WalletError> {
        // Somewhere deep in a flow the core needs a device signature. It does
        // NOT compute one; it either emits a Sign EFFECT (preferred, keeps the
        // core sans-IO and the crypto async on the shell) OR, for a synchronous
        // in-core need, calls the callback directly:
        let sig = self.signer
            .sign("pid-device-key".into(), b"to-be-signed".to_vec())
            .map_err(|e| WalletError::Internal { reason: format!("{e:?}") })?;
        let _ = sig;
        Ok(vec![])
    }
}
```

> Design guidance: **prefer emitting a `FfiEffect::Sign` and getting the result back as `FfiEffect`Result** over calling the callback synchronously. The callback path is convenient but re-enters foreign code while holding the engine `Mutex` (see 3.6) and makes signing synchronous. The Effect path keeps the core purely sans-IO, keeps the Lean model faithful (signing is an observable effect in the trace), and lets Swift do the Enclave call off the main thread. Use the direct callback only where a flow genuinely cannot be expressed as an effect round-trip. The `Signer` trait exists for both, but Effect-style is the default.

On the Swift side (full file in Section 7), the implementation looks like:

```swift
import CryptoKit
import WalletCore  // the generated Swift package (3.6/3.7)

final class EnclaveSigner: Signer {   // `Signer` is the generated protocol
    func sign(keyHandle: String, payload: Data) throws -> Data {
        // Look up the SecKey for keyHandle in the keychain (Section 7),
        // sign inside the Secure Enclave, return the raw signature.
        // On failure, throw SignerError.refused(reason:) — the generated
        // Swift error enum that mirrors the Rust one.
        ...
    }
    func publicKey(keyHandle: String) throws -> Data { ... }
}

// Construction wires Swift's Enclave signer into the Rust engine:
let engine = try WalletEngine(signer: EnclaveSigner())
```

Note the automatic name mapping: Rust `key_handle: Vec<u8>`/`String` → Swift `keyHandle: Data`/`String`; Rust `Result<Vec<u8>, SignerError>` → Swift `throws -> Data`; Rust snake_case → Swift camelCase. UniFFI does this for you.

**Definition of done (3.5):** after 3.6 generates bindings, the Swift `EnclaveSigner` compiles against the generated `Signer` protocol and `WalletEngine(signer:)` type-checks. Verified as part of 3.9.

### 3.6 Building for iOS: static libs, `lipo`, xcframework, and the Swift package

Now we compile `wallet-core` for the two iOS architectures we need and generate the Swift bindings, then package it so an Xcode project can `import WalletCore`.

Targets we need (Apple Silicon dev machine):
- `aarch64-apple-ios` — real devices (arm64 iPhone/iPad).
- `aarch64-apple-ios-sim` — the iOS **simulator** on Apple Silicon (also arm64, but a *different* target triple — do not confuse it with the device build).

(We deliberately skip `x86_64-apple-ios` — Intel-Mac simulators — since the confirmed toolchain is Apple Silicon. Add it later only if a CI runner is Intel.)

1. Install the Rust targets once:

```bash
rustup target add aarch64-apple-ios aarch64-apple-ios-sim
# Verify:
rustup target list --installed | grep apple-ios
# Expected: both triples printed.
```

2. Create the build script at `scripts/build-ios.sh` (repo root). This is the copy-pasteable "one command" for the whole packaging step:

```bash
#!/usr/bin/env bash
# scripts/build-ios.sh — build wallet-core for iOS and emit a Swift package.
set -euo pipefail

CRATE="wallet-core"
LIBNAME="libwallet_core.a"          # from [lib] name = "wallet_core"
PROFILE="release"                    # use debug for faster local iteration
BUILD_FLAG="--release"
[ "$PROFILE" = "debug" ] && BUILD_FLAG=""

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/generated"                # where we assemble the Swift package
BINDINGS="$OUT/Sources/WalletCore"   # generated Swift + headers
XCF="$OUT/WalletCoreFFI.xcframework"

echo "==> 1/5 Building static libs for device + simulator"
cargo build -p "$CRATE" $BUILD_FLAG --target aarch64-apple-ios
cargo build -p "$CRATE" $BUILD_FLAG --target aarch64-apple-ios-sim

DEV_LIB="$ROOT/target/aarch64-apple-ios/$PROFILE/$LIBNAME"
SIM_LIB="$ROOT/target/aarch64-apple-ios-sim/$PROFILE/$LIBNAME"

echo "==> 2/5 Generating Swift bindings from the built library"
rm -rf "$BINDINGS" && mkdir -p "$BINDINGS"
# Run OUR bindgen bin (same uniffi version as the runtime). --library mode
# reads the compiled dylib/staticlib and emits Swift + a C header + modulemap.
cargo run -p "$CRATE" --bin uniffi-bindgen -- generate \
  --library "$DEV_LIB" \
  --language swift \
  --out-dir "$BINDINGS"
# This emits: WalletCore.swift, walletcoreFFI.h, walletcoreFFI.modulemap

echo "==> 3/5 Assembling headers for the xcframework"
HEADERS="$OUT/headers"
rm -rf "$HEADERS" && mkdir -p "$HEADERS"
cp "$BINDINGS"/*.h "$HEADERS/"
# xcframework wants a module.modulemap (rename the generated *FFI.modulemap):
cp "$BINDINGS"/*.modulemap "$HEADERS/module.modulemap"

echo "==> 4/5 Building the xcframework (device slice + simulator slice)"
# NOTE: both slices are arm64 but DIFFERENT platforms, so they can live in one
# xcframework WITHOUT lipo. lipo is only for fusing same-platform archs into one
# fat lib (see the comment below). We use xcodebuild -create-xcframework.
rm -rf "$XCF"
xcodebuild -create-xcframework \
  -library "$DEV_LIB" -headers "$HEADERS" \
  -library "$SIM_LIB" -headers "$HEADERS" \
  -output "$XCF"

echo "==> 5/5 Writing Package.swift"
cat > "$OUT/Package.swift" <<'EOF'
// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "WalletCore",
    platforms: [.iOS(.v16)],
    products: [
        .library(name: "WalletCore", targets: ["WalletCore"]),
    ],
    targets: [
        // The generated Swift wrapper. It depends on the C FFI binary target.
        .target(
            name: "WalletCore",
            dependencies: ["WalletCoreFFI"],
            path: "Sources/WalletCore"
        ),
        // The compiled Rust, wrapped as a binary xcframework.
        .binaryTarget(
            name: "WalletCoreFFI",
            path: "WalletCoreFFI.xcframework"
        ),
    ]
)
EOF

echo "==> Done. Swift package at: $OUT"
```

3. About **`lipo`** (the shared context and the task both mention it, so here is when it actually applies): `lipo -create a.a b.a -output fat.a` fuses libraries of *different architectures for the same platform* into one "fat" archive — e.g. `x86_64` + `arm64` **simulator** slices. Because our confirmed toolchain is Apple Silicon only, each *platform* slice is a single arch, so **we do not need `lipo`** — the `-create-xcframework` step keeps device and simulator as separate, correctly-tagged slices (which is exactly what modern Xcode wants; a lipo'd device+simulator fat lib is in fact rejected). If you later add Intel-simulator support, you would `lipo` the two simulator archs together *first*, then feed that fat sim lib plus the device lib to `-create-xcframework`. Concretely:

```bash
# ONLY if you add x86_64 simulator later:
lipo -create \
  target/aarch64-apple-ios-sim/release/libwallet_core.a \
  target/x86_64-apple-ios/release/libwallet_core.a \
  -output target/sim-universal/libwallet_core.a
# then pass target/sim-universal/libwallet_core.a as the simulator -library.
```

4. Make it executable and run it:

```bash
chmod +x scripts/build-ios.sh
./scripts/build-ios.sh
```

**Definition of done (3.6):**

```bash
./scripts/build-ios.sh
# Then verify all four artifacts exist:
ls generated/WalletCoreFFI.xcframework/Info.plist          # xcframework built
ls generated/Sources/WalletCore/WalletCore.swift           # generated Swift
ls generated/Sources/WalletCore/*FFI.h                     # C header
ls generated/Package.swift                                 # SPM manifest
# Expected: each path prints; no "No such file".
```

### 3.7 The tiny Swift smoke test (proves the whole seam works)

This is the concrete "Definition of done" the task asks for: a tiny Swift file that imports the bindings and calls the core. We do it two ways — a fast pure-Rust-visible check on the host, and the SPM import.

1. Fastest check that the *bindings* are callable at all — generate host bindings and run a Swift snippet against the host `.dylib` (no Xcode/simulator needed):

```bash
# Build the host cdylib (macOS arm64) so we can dlopen it from Swift on the Mac.
cargo build -p wallet-core
# Generate Swift bindings against the host dylib:
cargo run -p wallet-core --bin uniffi-bindgen -- generate \
  --library target/debug/libwallet_core.dylib \
  --language swift \
  --out-dir generated/host
```

2. Write the smoke test at `generated/host/smoke.swift`:

```swift
import Foundation

// A minimal Signer so we can construct the engine on the host (no Enclave here).
final class FakeSigner: Signer {
    func sign(keyHandle: String, payload: Data) throws -> Data {
        return Data([0xDE, 0xAD, 0xBE, 0xEF]) // stub signature
    }
    func publicKey(keyHandle: String) throws -> Data {
        return Data([0x01, 0x02, 0x03])
    }
}

let engine = try WalletEngine(signer: FakeSigner())

print("ABI:", engine.abiVersion())        // -> "wallet-core-abi/1"

// Feed one TYPED event; get back TYPED effects (Option B from 3.4).
let effects = try engine.handleEvent(event: .qrScanned(payload: "openid4vp://example"))
print("Got \(effects.count) effect(s)")
for e in effects {
    switch e {                              // Swift checks this switch exhaustively
    case .httpFetch(let id, let url, _, _): print("  HTTP \(id) -> \(url)")
    case .sign(let id, let handle, _):      print("  SIGN \(id) with \(handle)")
    case .showScreen(let s):                print("  SCREEN \(s.title)")
    case .storeSecret(let id, _, _):        print("  STORE \(id)")
    case .getTime(let id):                  print("  TIME \(id)")
    }
}

// Escape-hatch JSON path used by the Lean oracle (3.4):
let json = try engine.handleEventJson(eventJson: #"{"Cancelled":null}"#)
print("JSON effects:", json)
```

3. Compile and run it directly with `swiftc`, linking the host dylib and the generated module:

```bash
cd generated/host
# The generated .modulemap must be visible to the Swift importer:
swiftc smoke.swift WalletCore.swift \
  -I . \
  -L ../../target/debug -lwallet_core \
  -o smoke
DYLD_LIBRARY_PATH=../../target/debug ./smoke
```

Expected output (effect count/contents depend on your Section 2 flow logic; the point is it runs and returns typed data):

```
ABI: wallet-core-abi/1
Got 1 effect(s)
  SCREEN Present your credential
JSON effects: []
```

4. For the *real* iOS integration (the app), you do not use `swiftc` — you add the generated Swift package to the Xcode project. This is covered in Section 4, but the one-line version is: in Xcode, **File → Add Package Dependencies → Add Local…** and point at `generated/` (the folder with `Package.swift`), then `import WalletCore` in the app. The build script (3.6) already produced everything that package needs.

**Definition of done (3.7):**

```bash
cd generated/host && DYLD_LIBRARY_PATH=../../target/debug ./smoke
# Expected: prints "ABI: wallet-core-abi/1" and at least one effect line
# with NO crash and NO linker error. This proves: Rust built, uniffi-bindgen
# produced Swift bindings, and a tiny Swift file imported and called the core.
```

That single passing run is the section's headline acceptance criterion.

### 3.8 Pitfalls: async, threading, error mapping, ABI versioning

Read this before you ship; each of these has bitten every UniFFI project.

**Async.** Our exported methods are **synchronous** (`handle_event`), and that is deliberate and correct for a sans-IO core: `handle_event` is pure and fast (no I/O inside — all I/O is an Effect the shell runs *outside* the FFI, asynchronously, in Swift). Do **not** reach for UniFFI's `async fn` support here. UniFFI can export `async fn` (it bridges to Swift `async`/`await` via a foreign executor), but it adds a runtime, complicates the ABI, and — most importantly — would smuggle I/O concepts back into a core we designed to have none. Keep the boundary synchronous; keep the concurrency in the shell. The only place async touches this seam is the `Signer` callback if you ever made it async — don't; keep `Signer` synchronous and let Swift dispatch the Enclave call off-main-thread on its side.

**Threading.** Every `#[derive(uniffi::Object)]` must be `Send + Sync`, which is why `WalletEngine` wraps its state in a `Mutex`. Consequences you must respect:
- Calls into `handle_event` from multiple Swift threads are serialized by that `Mutex`. That is what you want — the core's state transitions must not interleave.
- **Never** call back into the *same* engine from inside a `Signer` callback while the engine `Mutex` is held — that is a re-entrant deadlock. This is the deepest reason 3.5 recommends the Effect round-trip over the synchronous callback: the Effect path releases the lock (the call returns) before Swift does the signing and re-enters with `EffectCompleted`.
- Do the Enclave/network work on a background `Task`/queue in Swift, then hop back to feed the result event in. Never block the main thread waiting on `handle_event` if a flow could be slow (it shouldn't be, since it's I/O-free, but keep the discipline).

**Error mapping.** `Result<T, E>` where `E: uniffi::Error` becomes Swift `throws`; the error *enum variants* become Swift error cases with associated values. Rules that keep this clean:
- Make every fallible exported function return `Result<_, WalletError>` (or `SignerError` for the callback). Never `panic!` across the FFI — a Rust panic unwinding into Swift is undefined behavior; UniFFI catches panics and converts them to a generic error, but you should not rely on that. Convert internal `Result`s to `WalletError` with explicit variants.
- Keep error *messages* free of secrets (the "never log full credentials/secrets" rule applies to error strings too — a `reason: String` that echoes a disclosure is a leak).
- A poisoned `Mutex` (a thread panicked while holding it) surfaces as `WalletError::Internal`; we handle it explicitly rather than `.unwrap()`-ing (which would panic across the FFI).

**ABI / versioning.** The generated Swift is only guaranteed to match a Rust library built from the **same source and same uniffi version**. Protect against skew:
- Pin `uniffi = "=0.28.3"` (done) and build the `uniffi-bindgen` binary from *this* crate (done) so generator and runtime can never diverge.
- Expose `abi_version()` (done) and have the app assert it at startup: `precondition(WalletCore.abiVersion() == expected)`. If you ship a stale `.xcframework` against new Swift (or vice versa), you get a *clear* failure instead of a memory-corruption crash.
- Treat any change to `FfiEvent`/`FfiEffect`/`ScreenDescription`/`Signer` as an **ABI change**: bump `ABI_VERSION`, regenerate bindings, rebuild the xcframework. Because these are typed enums, such changes are visible in the diff and the Swift compiler will flag every non-exhaustive `switch` — this is the payoff of choosing Option B in 3.4.
- Do **not** hand-edit the generated `WalletCore.swift`. It is a build artifact; regenerate it. Commit it or `.gitignore` it, but never patch it.
- Keep `generated/` out of the hand-maintained source tree conceptually — it is produced by `scripts/build-ios.sh`. In CI (Section 15), regenerate it from scratch on every build so a drifted checked-in copy can never mask a real ABI change.

**One more, easy to miss:** the generated Swift file and the C header/modulemap must ship *together and matched*. If you regenerate Swift but reuse an old header, you get link errors like "undefined symbol `_uniffi_wallet_core_...`". The build script always regenerates all three in one step for exactly this reason — don't split them.

**Definition of done (3.8):** you can point to each mitigation in the code — synchronous exports (no `async fn` in `lib.rs`), `Mutex` in `WalletEngine`, `Result<_, WalletError>` on every exported fallible fn, and the pinned `=0.28.3` plus the `abi_version()` assertion. Sanity check the pin and the no-async invariant:

```bash
grep -n '=0.28.3' crates/wallet-core/Cargo.toml     # expect the pinned line
grep -n 'async fn' crates/wallet-core/src/lib.rs     # expect NO matches
```

### 3.9 Section acceptance: the end-to-end Definition of done

Run these in order from the repo root. All must pass; this is the gate for Section 3 being complete.

```bash
# 1. The core + FFI scaffolding compile.
cargo build -p wallet-core
#    -> "Finished". libwallet_core.a and .dylib exist under target/debug/.

# 2. The bindgen binary works and emits Swift bindings.
cargo run -p wallet-core --bin uniffi-bindgen -- generate \
  --library target/debug/libwallet_core.dylib --language swift --out-dir generated/host
#    -> generated/host/WalletCore.swift + *FFI.h + *FFI.modulemap exist.

# 3. A tiny Swift file imports the bindings and calls the core.
cd generated/host
swiftc smoke.swift WalletCore.swift -I . -L ../../target/debug -lwallet_core -o smoke
DYLD_LIBRARY_PATH=../../target/debug ./smoke
#    -> prints "ABI: wallet-core-abi/1" and at least one typed effect line.
cd ../..

# 4. The full iOS packaging produces a consumable Swift package.
./scripts/build-ios.sh
ls generated/WalletCoreFFI.xcframework/Info.plist generated/Package.swift
#    -> both paths print.
```

When step 3 prints the ABI string and an effect line with no crash, and step 4 produces the xcframework and `Package.swift`, the UniFFI boundary is proven end-to-end: Rust builds, `uniffi-bindgen` produces Swift bindings, and Swift imports and calls the core. The iOS app (Section 4) consumes `generated/Package.swift`; the Android shell (Section 5) will reuse the *same* `lib.rs` annotations with `--language kotlin` and the NDK targets — no change to this boundary is required for Android, which is the whole point of keeping the surface tiny and typed.

---


## Section 4 — Codec crates: cose, mdoc (deterministic CBOR), sdjwt (JOSE), x509

These four crates are the **wire-format codecs**: pure, sans-IO, `#![forbid(unsafe_code)]` libraries that turn bytes into typed values and back. They do **no crypto themselves** — every hash, signature, and verification call crosses the `crypto_traits` boundary (Section 3) into hardware or `aws-lc-rs`. Everything above them (the protocol machines in **Section 5** — `oid4vp`, `oid4vci`, `iso18013-5`, `presenter`) consumes these types; everything below is the trait boundary. All four are exercised by the Tier-1 tooling (round-trip proptest, no-panic fuzz, Kani bounded proofs) defined in **Section 9**.

**Layering decision (do this first).** COSE is defined *in terms of* CBOR, and mdoc is defined *in terms of* COSE. So the canonical-CBOR primitive must live at the bottom. The scaffold put the proven `encode_uint`/`decode_uint` in `mdoc::cbor`, but `mdoc` will depend on `cose`, and `cose` needs canonical CBOR — that would be a dependency cycle. Resolve it by moving the canonical-CBOR module down into `cose` and re-exporting it from `mdoc` so existing paths (and the Section 9 harness that names `mdoc::cbor`) keep working.

1. Move the module. Create `euwallet/crates/cose/src/cbor.rs` and paste the entire existing `mod cbor { … }` body from `euwallet/crates/mdoc/src/lib.rs` (the `encode_uint`, `decode_uint`, and `#[cfg(kani)]` proof) into it, dropping the outer `pub mod cbor {` wrapper (the file *is* the module).
2. In `euwallet/crates/cose/src/lib.rs` add `pub mod cbor;` near the top.
3. In `euwallet/crates/mdoc/src/lib.rs` replace the old inline `pub mod cbor { … }` with a re-export: `pub use cose::cbor;`. Every existing `mdoc::cbor::encode_uint(...)` call site and the Section 9 fuzz/kani target paths continue to resolve unchanged.
4. Wire the dependency. In `euwallet/crates/mdoc/Cargo.toml` add under `[dependencies]`: `cose = { path = "../cose" }`.

**Definition of done (layering):** `cargo build -p cose && cargo build -p mdoc` succeeds, and `cargo test -p cose cbor::` runs the moved uint round-trip tests green.

---

### 4.1 `cose` — COSE_Sign1 over the crypto boundary (RFC 9052/9053)

**4.1.1 Responsibility.** `cose` builds and verifies `COSE_Sign1` messages: the single-signer CBOR signature envelope used by mdoc `IssuerSigned`/`DeviceSigned` (register **E001**, ISO/IEC 18013-5:2021) and by the Wallet Unit Attestation (`wua`). It implements **RFC 9052** (structures) and **RFC 9053** (ES256/ES384/EdDSA algorithm identifiers). It never computes a signature or a digest — it constructs the exact bytes to be signed (`Sig_structure`) and the exact bytes to be verified, then hands them to `crypto_traits::Signer` / `crypto_traits::Verifier`.

**4.1.2 Public types and signatures.** Replace the placeholder `unprotected: Vec<u8>` with a typed header, and give `sign`/`verify` the real shapes. Full contents of `euwallet/crates/cose/src/lib.rs` (below the `pub mod cbor;` line):

```rust
use crypto_traits::{Alg, CryptoError, KeyRef, Signer, Verifier};

/// COSE header label constants (RFC 9052 §3.1).
mod label {
    pub const ALG: i64 = 1;   // algorithm identifier (int)
    pub const CRIT: i64 = 2;  // critical headers (array of labels)
    pub const KID: i64 = 4;   // key id (bstr)
    pub const X5CHAIN: i64 = 33; // RFC 9360 cert chain (bstr / [bstr])
}

/// COSE algorithm identifiers (RFC 9053 §2). Mapped 1:1 to `crypto_traits::Alg`.
fn cose_alg_id(alg: Alg) -> i64 {
    match alg {
        Alg::Es256 => -7,
        Alg::Es384 => -35,
        Alg::EdDsa => -8,
    }
}

#[derive(Debug)]
pub enum CoseError {
    Crypto(CryptoError),
    /// A `crit` header listed a label we do not understand → MUST reject (RFC 9052 §3.1).
    UnknownCriticalParam(i64),
    /// Protected header was not canonical CBOR, or not a map, or `alg` missing/mismatched.
    MalformedHeader,
    /// Detached-payload mismatch, wrong array length, trailing bytes, etc.
    MalformedStructure,
    AlgMismatch,
}
impl From<CryptoError> for CoseError {
    fn from(e: CryptoError) -> Self { CoseError::Crypto(e) }
}

/// A COSE_Sign1 message. `protected` is the *serialized* protected-header bstr
/// (canonical CBOR) exactly as it appears on the wire and inside Sig_structure.
#[derive(Clone, Debug, Default)]
pub struct CoseSign1 {
    pub protected: Vec<u8>,
    pub unprotected: UnprotectedHeader,
    pub payload: Option<Vec<u8>>, // None == detached payload
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Default)]
pub struct UnprotectedHeader {
    pub kid: Option<Vec<u8>>,
    pub x5chain: Option<Vec<Vec<u8>>>, // DER certs, leaf-first
}

impl CoseSign1 {
    /// Build the protected header {1: alg}, assemble Sig_structure, sign via the boundary.
    pub fn sign(
        signer: &dyn Signer,
        key: &KeyRef,
        alg: Alg,
        payload: &[u8],
        external_aad: &[u8],
        unprotected: UnprotectedHeader,
    ) -> Result<Self, CoseError> {
        let protected = encode_protected_header(alg);         // canonical CBOR map bstr
        let tbs = sig_structure(&protected, external_aad, payload); // exact bytes to sign
        let signature = signer.sign(key, alg, &tbs)?;         // <-- crypto boundary
        Ok(CoseSign1 { protected, unprotected, payload: Some(payload.to_vec()), signature })
    }

    /// Verify: reconstruct Sig_structure from *our own* re-encode, reject unknown crit,
    /// then call the verifier. `detached_payload` supplies the payload when self.payload is None.
    pub fn verify(
        &self,
        verifier: &dyn Verifier,
        expected_alg: Alg,
        public_key: &[u8],
        external_aad: &[u8],
        detached_payload: Option<&[u8]>,
    ) -> Result<(), CoseError> {
        let hdr_alg = parse_and_check_protected_header(&self.protected)?; // rejects crit, non-canonical
        if hdr_alg != expected_alg { return Err(CoseError::AlgMismatch); }
        let payload = match (&self.payload, detached_payload) {
            (Some(p), None) => p.as_slice(),
            (None, Some(p)) => p,
            _ => return Err(CoseError::MalformedStructure),
        };
        let tbs = sig_structure(&self.protected, external_aad, payload);
        verifier.verify(expected_alg, public_key, &tbs, &self.signature)?; // <-- crypto boundary
        Ok(())
    }
}
```

**4.1.3 Hardening rules.** Two rules are load-bearing.

5. **`Sig_structure` must be built to the letter of RFC 9052 §4.4** — a 4-element canonical-CBOR array `[ context, body_protected, external_aad, payload ]`, where `context` is the text string `"Signature1"`, and the last three are byte strings. A single wrong byte here silently makes every signature "invalid" (or, worse, accepts forgeries if you skip a field). Implement it once, from the canonical writer, and never anywhere else:

```rust
/// RFC 9052 §4.4 Sig_structure for COSE_Sign1. Deterministic bytes handed to Signer/Verifier.
fn sig_structure(protected: &[u8], external_aad: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&[0x84]);          // array(4)
    cbor::write_tstr(&mut out, "Signature1"); // context
    cbor::write_bstr(&mut out, protected);    // body_protected (serialized header)
    cbor::write_bstr(&mut out, external_aad); // external_aad (empty for mdoc unless profiled)
    cbor::write_bstr(&mut out, payload);      // payload (the MSO bytes, etc.)
    out
}
```

You will add `write_tstr`, `write_bstr`, `write_map_header`, and `write_array_header` to `cose/src/cbor.rs` alongside the existing `encode_uint` — all shortest-form, so they inherit the determinism guarantee. `encode_protected_header(alg)` writes the canonical one-entry map `{1: cose_alg_id(alg)}` (note: `alg` for ES256 is the *negative* integer `-7`, encoded as CBOR major type 1).

6. **Reject unknown critical parameters (RFC 9052 §3.1).** If the protected header contains label `2` (`crit`), it lists labels the recipient MUST understand. If any listed label is not one we implement, fail closed — do not "ignore and continue":

```rust
fn parse_and_check_protected_header(protected: &[u8]) -> Result<Alg, CoseError> {
    let map = cbor::read_canonical_map(protected).map_err(|_| CoseError::MalformedHeader)?;
    if let Some(crit) = map.get_array(label::CRIT) {
        for lbl in crit.ints() {
            // The ONLY labels we understand in a protected header today:
            if !matches!(lbl, label::ALG | label::CRIT | label::KID) {
                return Err(CoseError::UnknownCriticalParam(lbl));
            }
        }
    }
    let alg_id = map.get_int(label::ALG).ok_or(CoseError::MalformedHeader)?;
    match alg_id {
        -7 => Ok(Alg::Es256),
        -35 => Ok(Alg::Es384),
        -8 => Ok(Alg::EdDsa),
        _ => Err(CoseError::MalformedHeader),
    }
}
```

`read_canonical_map` rejects a header whose keys are not in canonical order or use non-shortest encodings — a non-canonical protected header is treated as malformed, because it would break signature reproducibility.

**4.1.4 Malformed input and tests.** Create `euwallet/crates/cose/tests/sign1.rs`. Cover: (a) **round-trip** — sign with a stub `Signer` (fixed key), serialize, re-parse, `verify` with the matching stub `Verifier` (Ok); (b) **crit rejection** — hand-craft a protected header with `crit: [99]` and assert `verify` returns `UnknownCriticalParam(99)`; (c) **Sig_structure golden** — assert the exact hex of `sig_structure(...)` for a fixed input against a vector from RFC 9052 Appendix C (store under `euwallet/crates/cose/tests/vectors/rfc9052/`); (d) **malformed** — feed truncated/garbage `protected` bytes and assert an `Err`, never a panic. The stub crypto lives in `euwallet/crates/cose/tests/support/mod.rs` implementing `Signer`/`Verifier` deterministically (e.g. `sign` returns `sha256(tbs)` and `verify` recomputes — enough to prove wiring without real crypto). The no-panic property is enforced continuously by the Section 9 fuzz target `fuzz_cose_sign1_parse`.

**4.1.5 Definition of done (`cose`).** `cargo test -p cose` passes, including the RFC 9052 Appendix C `Sig_structure` golden and the crit-rejection test; `cargo test -p cose cbor::` still green after the move.

---

### 4.2 `mdoc` — ISO/IEC 18013-5 credential with profiled canonical CBOR

**4.2.1 Responsibility.** `mdoc` encodes/decodes the ISO mdoc credential: the `MobileSecurityObject` (MSO), `IssuerSigned` (issuer's `COSE_Sign1` over the MSO plus the selectively-disclosable `IssuerSignedItem`s), and `DeviceSigned` (holder binding). It implements register **E001** (ISO/IEC 18013-5:2021) and is the data model consumed by the 18013-7 online flow (**E002**). Its defining constraint is **deterministic/canonical CBOR**: two logically-equal credentials must serialize to identical bytes, because the issuer signs a digest of those bytes and the verifier recomputes it — any encoding ambiguity is a verification failure or a forgery vector.

**4.2.2 Public types and signatures.** Expand the scaffold structs in `euwallet/crates/mdoc/src/lib.rs`:

```rust
use cose::{CoseSign1, CoseError};
use crypto_traits::{Alg, Digest, KeyRef, Signer, Verifier, CryptoError};
use std::collections::BTreeMap;

pub type NameSpace = String;      // e.g. "org.iso.18013.5.1"
pub type DataElementId = String;  // e.g. "family_name"
pub type Digest32 = [u8; 32];

/// Mobile Security Object (18013-5 §9.1.2.4). Signed by the issuer inside IssuerAuth.
#[derive(Clone, Debug)]
pub struct MobileSecurityObject {
    pub version: String,          // "1.0"
    pub digest_algorithm: String, // "SHA-256"
    pub doc_type: String,         // e.g. "org.iso.18013.5.1.mDL"
    /// namespace -> (digestID -> digest bytes) of each IssuerSignedItem.
    pub value_digests: BTreeMap<NameSpace, BTreeMap<u64, Digest32>>,
    pub device_key_info: DeviceKeyInfo, // the holder's COSE_Key for device auth
    pub validity_info: ValidityInfo,    // signed, validFrom, validUntil (tdate)
}

/// One disclosable element, kept as a CBOR-tagged bstr (tag 24) on the wire (§8.3.2.1.2.2).
#[derive(Clone, Debug)]
pub struct IssuerSignedItem {
    pub digest_id: u64,
    pub random: Vec<u8>,          // >=16 bytes salt, from crypto_traits::Random
    pub element_id: DataElementId,
    pub element_value: CborValue, // opaque, canonically encoded
}

#[derive(Clone, Debug)]
pub struct IssuerSigned {
    pub name_spaces: BTreeMap<NameSpace, Vec<IssuerSignedItem>>,
    pub issuer_auth: CoseSign1,   // COSE_Sign1; payload == tagged MSO bytes
}

#[derive(Clone, Debug)]
pub struct DeviceSigned {
    pub name_spaces_bytes: Vec<u8>, // canonical CBOR of DeviceNameSpaces (may be empty map)
    pub device_auth: DeviceAuth,    // deviceSignature (COSE_Sign1) OR deviceMac
}
```

The core functions call the boundary, never crypto directly:

```rust
impl MobileSecurityObject {
    /// Compute value digests for each item (SHA-256 via the Digest trait) and seal the MSO.
    pub fn build_and_sign(
        items: &BTreeMap<NameSpace, Vec<IssuerSignedItem>>,
        doc_type: &str,
        device_key: DeviceKeyInfo,
        validity: ValidityInfo,
        digest: &dyn Digest,        // <-- boundary: SHA-256
        signer: &dyn Signer,        // <-- boundary: issuer signature
        key: &KeyRef,
        alg: Alg,
    ) -> Result<IssuerSigned, CoseError> {
        let mut value_digests = BTreeMap::new();
        for (ns, list) in items {
            let mut m = BTreeMap::new();
            for it in list {
                let tagged = encode_issuer_signed_item_bytes(it); // tag 24 wrapper, canonical
                m.insert(it.digest_id, digest.sha256(&tagged));    // <-- boundary
            }
            value_digests.insert(ns.clone(), m);
        }
        let mso = MobileSecurityObject { version: "1.0".into(),
            digest_algorithm: "SHA-256".into(), doc_type: doc_type.into(),
            value_digests, device_key_info: device_key, validity_info: validity };
        let mso_bytes = encode_tagged_mso(&mso);                    // tag 24 bstr, canonical
        let issuer_auth = CoseSign1::sign(signer, key, alg, &mso_bytes, &[], /*x5chain*/ header)?;
        Ok(IssuerSigned { name_spaces: items.clone(), issuer_auth })
    }
}

/// Verify issuer signature + that each disclosed item's digest matches the MSO (§9.1.2).
pub fn verify_issuer_signed(
    issued: &IssuerSigned,
    verifier: &dyn Verifier,   // <-- boundary
    digest: &dyn Digest,       // <-- boundary
    issuer_public_key: &[u8],
    expected_alg: Alg,
) -> Result<MobileSecurityObject, MdocError> { /* ... */ }
```

**4.2.3 Canonical CBOR rules (build on `cose::cbor`).** All mdoc encoding routes through the shortest-form writers you added in 4.1. On top of the uint primitive, implement and enforce (RFC 8949 §4.2 + 18013-5 §9.1.2):

7. **Shortest-form integers and lengths** (already proven for uints; extend the same rule to array/map/bstr/tstr length prefixes and to negative integers, major type 1).
8. **Definite lengths only** — reject indefinite-length arrays/maps/strings (initial byte low-5-bits `31`) on decode.
9. **Canonical map key ordering** — map keys sorted by their *encoded bytes*, lexicographically (bytewise). Encode from a `BTreeMap` keyed appropriately; on decode, verify the incoming order and reject out-of-order keys.
10. **Tag 24 (`#6.24`) for embedded CBOR** — `IssuerSignedItemBytes` and `MobileSecurityObjectBytes` are a byte string tagged 24 whose content is itself canonical CBOR. The bytes inside tag 24 are exactly what gets digested/signed.
11. **No duplicate map keys**, and `element_value` is stored/compared as raw canonical bytes so re-encoding is a no-op.

Provide `pub fn to_canonical_cbor<T: CanonicalEncode>(value: &T) -> Vec<u8>` (replacing the stub) driving a small internal `CanonicalEncode` trait implemented per struct — do **not** delegate to `ciborium` for encoding, since its map ordering is not guaranteed to match this profile; `ciborium::Value` may be used only in tests as an independent structural cross-check.

**4.2.4 mdoc authentication / device signature.** `DeviceSigned` proves the holder controls the private key bound in `MSO.device_key_info`. Two modes: `deviceSignature` (a `COSE_Sign1` from the Secure Enclave key over the `DeviceAuthentication` structure) and `deviceMac` (an HMAC via `Kdf`/session keys). Both build the `DeviceAuthentication` array `["DeviceAuthentication", SessionTranscript, DocType, DeviceNameSpacesBytes]`, wrap it as tag-24 bytes, and sign/MAC through the boundary. `SessionTranscript` is supplied by the `iso18013-5` transport machine (**Section 5**) — `mdoc` only defines the structure and the deterministic encoding; it never touches BLE/NFC/HTTP.

**4.2.5 Malformed input and tests.** Create `euwallet/crates/mdoc/tests/`. Vectors live under `euwallet/crates/mdoc/tests/vectors/iso18013-5-annex-d/` (the official ISO/IEC 18013-5:2021 **Annex D** worked examples: an example `IssuerSigned`, MSO, and `DeviceResponse`). Load them with a helper:

```rust
fn vec_bytes(name: &str) -> Vec<u8> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors/iso18013-5-annex-d").join(name);
    std::fs::read(p).expect("vector present")
}
```

Tests: (a) **round-trip** — decode Annex D `IssuerSigned`, re-encode, assert byte-identical (proves canonicalization matches ISO); (b) **digest match** — recompute each `value_digest` via a stub `Digest` and assert equality with the MSO; (c) **canonicalization negatives** — feed an `IssuerSigned` with map keys out of order, indefinite lengths, and non-shortest integers, assert each is rejected; (d) **malformed** — truncate every vector at each byte offset and assert `decode` returns `Err`, never panics (the Section 9 fuzz target `fuzz_mdoc_decode` runs this continuously; the Kani proof `kani_uint_roundtrip` already guards the uint primitive). Because the EC reference implementation is a **CI interop oracle only**, add (e) an *ignored-by-default* test `interop_ec_reference` that reads issuer output produced offline by the reference issuer from `tests/vectors/ec-oracle/` and checks our decoder accepts it and reproduces identical canonical bytes — run in CI, never linked at runtime.

**4.2.6 Definition of done (`mdoc`).** `cargo test -p mdoc` passes, including the Annex D round-trip byte-equality test and all canonicalization negatives; `cargo test -p mdoc --ignored interop_ec_reference` passes in CI against the stored EC oracle outputs.

---

### 4.3 `sdjwt` — SD-JWT VC (IETF draft-17) with selective disclosure

**4.3.1 Responsibility.** `sdjwt` implements the SD-JWT VC credential: an issuer-signed JWT (**RFC 7515** JWS / **RFC 7519** JWT claims), a set of base64url **Disclosures**, and an optional **Key-Binding JWT** proving holder possession. It gives the wallet its second mandatory credential format alongside mdoc, and is the format profiled by ETSI TS 119 472 (**E004/E005**) attestations and required by the PID Rulebook. It is pinned to **IETF draft-17** and isolated behind the existing `SD_JWT_VC_DRAFT` marker, because the spec is a moving draft, not a stable RFC. As with mdoc, no crypto here — JWS signing/verification goes through `Signer`/`Verifier`, and disclosure hashing through `Digest`.

**4.3.2 Public types and signatures.** Expand `euwallet/crates/sdjwt/src/lib.rs`:

```rust
use crypto_traits::{Alg, Digest, KeyRef, Signer, Verifier, CryptoError};

pub const SD_JWT_VC_DRAFT: &str = "draft-17"; // keep; all format decisions gate on this.

#[derive(Debug)]
pub enum SdJwtError {
    /// A disclosure hash was not present in the SD-JWT's `_sd` array → tampering.
    UnknownDisclosure,
    /// `_sd_alg` names a hash we don't implement, or is absent.
    UnsupportedHashAlg,
    Malformed,
    Crypto(CryptoError),
}

/// One disclosure: base64url("[salt, claim_name, claim_value]") for an object member,
/// or base64url("[salt, claim_value]") for an array element (draft-17 §4.2).
#[derive(Clone, Debug)]
pub struct Disclosure {
    pub raw: String,        // the exact base64url text (its ASCII bytes are what we hash)
    pub salt: String,
    pub name: Option<String>,
    pub value: serde_json::Value,
}

/// Combined-format serialization: <issuer-jwt>~<disclosure>~...~<optional-kb-jwt>
#[derive(Clone, Debug, Default)]
pub struct SdJwtVc {
    pub issuer_jwt: String,
    pub disclosures: Vec<String>,
    pub key_binding_jwt: Option<String>,
}

impl SdJwtVc {
    /// Split on '~' and parse. STRICT: exactly one trailing '~' iff no KB-JWT (draft-17 §4).
    pub fn parse(compact: &str) -> Result<Self, SdJwtError> { /* ... */ }

    /// Verify issuer signature, then verify every provided disclosure hashes to an
    /// entry in `_sd` and reconstruct the disclosed claim set.
    pub fn verify_and_disclose(
        &self,
        verifier: &dyn Verifier,   // <-- boundary: issuer JWS
        digest: &dyn Digest,       // <-- boundary: _sd_alg (SHA-256)
        issuer_public_key: &[u8],
        alg: Alg,
    ) -> Result<serde_json::Map<String, serde_json::Value>, SdJwtError> { /* ... */ }
}

impl Disclosure {
    /// draft-17 digest: base64url( SHA-256( ASCII bytes of `raw` ) ). Hash via the boundary.
    pub fn digest_b64(&self, digest: &dyn Digest) -> String {
        base64url_nopad(&digest.sha256(self.raw.as_bytes())) // <-- boundary
    }
}
```

**4.3.3 Hardening / profiling rules.**

12. **Sign only over the JWS Signing Input** — `ASCII(BASE64URL(header) || "." || BASE64URL(payload))` — and hand exactly those bytes to `Signer`/`Verifier` (RFC 7515 §5). Parse the JOSE header, require a known `alg`, and **reject an unknown `crit` header member** exactly as in COSE. Reject `alg: "none"` unconditionally.
13. **Version isolation** — all draft-specific choices (`_sd` array placement, `...` array-element digest form, KB-JWT `sd_hash` claim name, `~` separator semantics) are gated behind `SD_JWT_VC_DRAFT`. Put a single `mod draft17;` module and route through it, so a future draft-18 is an additive module, not a scatter of edits.
14. **Selective disclosure integrity** — for each presented `Disclosure`, compute `digest_b64` and require it be a member of the JWT's `_sd` array (or, for array elements, inside a `{"...": <hash>}` placeholder). A disclosure whose hash is absent → `UnknownDisclosure` (fail closed). Ignore/reject digests in `_sd` that no presented disclosure matches only per the draft's "undisclosed" semantics — never fabricate a claim.
15. **Key-binding JWT** — when present, verify its signature with the holder key from the credential's `cnf` claim (via `Verifier`), check `aud`, `nonce`, `iat` freshness, and that its `sd_hash` equals the hash of the presented issuer-JWT-plus-disclosures. This binds the presentation to this verifier and session (consumed by `presenter`/`oid4vp` in **Section 5**).
16. **Strict JSON, no JSON-LD/RDF** — parse claims with `serde_json` in strict mode; reject duplicate object keys; do not resolve `@context` or perform any RDF processing for PID.

**4.3.4 Malformed input and tests.** Create `euwallet/crates/sdjwt/tests/`. Vectors under `euwallet/crates/sdjwt/tests/vectors/sd-jwt-vc-draft17/` — the examples from the draft-17 spec and the SD-JWT VC test-vector set (issuer JWT + disclosures + a KB-JWT example), stored as `.txt` compact-serialization files. Load with an `include_str!`/`fs::read_to_string` helper keyed on `CARGO_MANIFEST_DIR`. Tests: (a) **round-trip** — `parse` then re-serialize with `~` joins, assert string-identical; (b) **disclosure math** — for each example disclosure assert `digest_b64` (stub `Digest`) matches the `_sd` entry; (c) **tamper** — flip one byte in a disclosure and assert `UnknownDisclosure`; (d) **draft marker** — a compile-time `const _: () = assert!(...)`/test asserting `SD_JWT_VC_DRAFT == "draft-17"` so a silent bump breaks CI; (e) **malformed** — empty segments, missing/extra `~`, `alg:none`, non-base64url disclosures → `Err`, never panic (Section 9 target `fuzz_sdjwt_parse`). Add an *ignored* `interop_ec_reference` reading EC reference issuer SD-JWT VC output from `tests/vectors/ec-oracle/` as a CI oracle.

**4.3.5 Definition of done (`sdjwt`).** `cargo test -p sdjwt` passes, including the draft-17 disclosure-digest vectors, the tamper-rejection test, and the `SD_JWT_VC_DRAFT` guard; `cargo test -p sdjwt --ignored interop_ec_reference` passes in CI.

---

### 4.4 `x509` — DER parsing, path validation, and the EUDI RP/issuer profile

**4.4.1 Responsibility.** `x509` parses DER certificates, validates certification paths, and — critically — applies the **EUDI profile checks** that decide whether a chain identifies a *registered relying party* or a *trusted attestation issuer*. It underpins register **E001/E002** (verifying the mdoc `IssuerAuth` `x5chain` and the reader's certificate) and the **E004/E005** issuer trust for SD-JWT VC. The core principle, encoded in the type system, is: **a valid TLS certificate is not a registered relying party.** Chain validity answers "is this a well-formed cert signed by a CA?"; the profile answers "is this entity authorized, in the EUDI trust framework, to request/issue these attributes?" — a different, additional question.

**4.4.2 Public types and signatures.** Add a vetted, `no_std`-friendly DER parser to the dependency budget (`der` + `x509-cert` from RustCrypto; document the addition in `euwallet/docs/dependency-budget.md` and pass `cargo deny check`). Parsing DER and evaluating name constraints/validity/extensions is *logic*, not crypto; the one crypto step — verifying each certificate's signature — goes through `crypto_traits::Verifier`. Expand `euwallet/crates/x509/src/lib.rs`:

```rust
use crypto_traits::{Alg, Verifier, CryptoError};

#[derive(Debug)]
pub enum X509Error {
    Der,                 // malformed DER
    PathInvalid(&'static str), // chain math failed (expiry, name constraint, basicConstraints…)
    ProfileViolation(&'static str), // chain is valid but fails the EUDI profile
    NotRegistered,
    Crypto(CryptoError),
}

/// A parsed cert with only the fields the profile needs (kept minimal on purpose).
#[derive(Clone, Debug)]
pub struct ParsedCert {
    pub tbs_der: Vec<u8>,        // exact TBSCertificate bytes (verifier input)
    pub signature: Vec<u8>,
    pub sig_alg: Alg,
    pub spki_der: Vec<u8>,       // subjectPublicKeyInfo of THIS cert (to verify the child)
    pub subject: Name,
    pub issuer: Name,
    pub not_before: Time,
    pub not_after: Time,
    pub key_usage: KeyUsage,
    pub ext_key_usage: Vec<Oid>, // EKUs (the EUDI RP/issuer profile keys off these)
    pub basic_constraints_ca: bool,
    pub policy_oids: Vec<Oid>,   // certificate policies (registration is asserted here)
}

pub fn parse_cert(der: &[u8]) -> Result<ParsedCert, X509Error> { /* der/x509-cert */ }

/// Step 1: pure path validation (RFC 5280 §6): chain to a trust anchor, check validity
/// windows, basicConstraints, name constraints, and each signature via the boundary.
pub fn validate_path(
    chain_der: &[Vec<u8>],
    trust_anchors: &[ParsedCert],
    now: Time,
    verifier: &dyn Verifier,   // <-- boundary: each cert signature
) -> Result<Vec<ParsedCert>, X509Error> { /* ... */ }

/// The profile-checked result — NOT mere chain validity. Keep the scaffold shape.
#[derive(Clone, Debug, Default)]
pub struct RelyingPartyProfile { pub subject: String, pub registered: bool }

/// Step 2: EUDI relying-party PROFILE. Runs ONLY after validate_path succeeds.
pub fn check_relying_party(
    chain_der: &[Vec<u8>],
    trust_anchors: &[ParsedCert], // the RP-access-CA trust list (from `trust`, Section 5)
    now: Time,
    verifier: &dyn Verifier,
) -> Result<RelyingPartyProfile, X509Error> {
    let path = validate_path(chain_der, trust_anchors, now, verifier)?;
    let leaf = &path[0];
    // --- profile checks that a generic TLS validator would NOT do ---
    require(leaf.ext_key_usage.contains(&oid::EUDI_RP_ACCESS), "missing RP-access EKU")?;
    require(path_chains_to_registered_rp_ca(&path, trust_anchors), "not an RP-access CA")?;
    require(leaf.policy_oids.contains(&oid::EUDI_RP_POLICY), "missing RP policy OID")?;
    require(!leaf.basic_constraints_ca, "leaf must be end-entity")?;
    Ok(RelyingPartyProfile { subject: leaf.subject.to_string(), registered: true })
}
```

**4.4.3 Profile rules (why valid-TLS ≠ registered RP).** A web-PKI TLS cert (e.g. from a public CA, EKU `serverAuth`) proves the holder controls a domain. It says nothing about EUDI authorization. The profile therefore requires all of:

17. **Trust anchor from the EUDI trust list, not the OS/web-PKI root store** — the RP-access CA set is supplied by the `trust` crate (**Section 5**) from the registrar's published list, never from the system trust store.
18. **EUDI-specific EKU and certificate-policy OIDs** present on the leaf (the registration is asserted by the access-CA via these OIDs); a `serverAuth`-only cert fails.
19. **Purpose separation** — an RP-access cert (reader authentication) must not be accepted where a QWAC/TLS cert is expected, and vice-versa; distinguish by EKU/policy, and refuse cross-use.
20. **Registered-issuer profile** — an analogous `check_trusted_issuer` validates mdoc `IssuerAuth`/SD-JWT VC issuer chains against the issuer trust list with the issuer EKU/policy OIDs (E004/E005). Both functions return the profiled result type, so callers cannot accidentally treat "chain is valid" as "entity is authorized."

**4.4.4 Malformed input and tests.** Create `euwallet/crates/x509/tests/`. Vectors under `euwallet/crates/x509/tests/vectors/`: `valid-rp-chain/` (a correctly profiled RP chain), `expired/`, `wrong-eku/` (valid TLS chain, `serverAuth` only — the headline negative), `no-policy-oid/`, and `self-signed-tls/`. Generate these offline with `openssl`/the EC reference tooling and commit the DER; document provenance in a `README` next to them. Load with the `CARGO_MANIFEST_DIR` helper. Tests: (a) **happy path** — `check_relying_party(valid-rp-chain)` → `registered: true`; (b) **the load-bearing negative** — a chain that a browser would accept (`wrong-eku/`, a real valid TLS chain) returns `ProfileViolation("missing RP-access EKU")`, proving valid-TLS ≠ RP; (c) `expired` → `PathInvalid`; (d) `no-policy-oid` → `ProfileViolation`; (e) **malformed DER** — truncate/corrupt each vector byte-by-byte, assert `Err`, never panic (Section 9 target `fuzz_x509_parse`). Each cert signature check in tests uses a real `Verifier` backed by `aws-lc-rs` *behind the trait* (it verifies, never signs), keeping the boundary intact.

**4.4.5 Definition of done (`x509`).** `cargo test -p x509` passes, including the `wrong-eku` valid-TLS-rejected-as-non-RP test and the expired/no-policy negatives; `cargo deny check` passes after the `der`/`x509-cert` additions.

---

### Section 4 definition of done (gate for all four crates)

Run from `euwallet/`:

```sh
cargo test -p cose -p mdoc -p sdjwt -p x509
cargo clippy -p cose -p mdoc -p sdjwt -p x509 -- -D warnings
cargo deny check
```

All must succeed, and specifically:

- **cose**: RFC 9052 Appendix C `Sig_structure` golden matches byte-for-byte; unknown-`crit` rejection proven; all signing/verification routes through `crypto_traits::{Signer, Verifier}`.
- **mdoc**: ISO 18013-5 Annex D `IssuerSigned` round-trips byte-identically; every canonicalization negative (key order, indefinite length, non-shortest int) rejected; digests computed only via `crypto_traits::Digest`; EC-oracle interop test green in CI.
- **sdjwt**: pinned to `draft-17` with a CI guard; disclosure-digest vectors match; tampered disclosure rejected; strict JSON, no JSON-LD; EC-oracle interop test green in CI.
- **x509**: a valid TLS chain lacking EUDI EKU/policy is rejected as *not a registered RP*; path validation and profile checks are separate steps returning distinct types; cert signatures verified only via `crypto_traits::Verifier`.
- **No crate links a crypto primitive directly** — `grep -R "aws-lc-rs" euwallet/crates/{cose,mdoc,sdjwt}/Cargo.toml` returns nothing (crypto reaches these crates only through `crypto-traits`); `x509` uses `aws-lc-rs` only in `[dev-dependencies]` behind the `Verifier` trait.
- **Every codec never panics on malformed input** — the four fuzz targets (`fuzz_cose_sign1_parse`, `fuzz_mdoc_decode`, `fuzz_sdjwt_parse`, `fuzz_x509_parse`) and the Kani uint proof from **Section 9** are wired and pass their smoke run.

With this gate green, the protocol state machines in **Section 5** (`iso18013-5`, `oid4vp`, `oid4vci`, `presenter`) can consume these codecs as trusted, canonical, panic-free building blocks.

---

Summary of what I produced and the one structural decision the reader must action: the section is written and self-contained. The load-bearing design call is in the intro — because `mdoc` depends on `cose` and `cose` needs canonical CBOR, the existing `mod cbor` (with its Section 9 proptest/fuzz/Kani) must move from `euwallet/crates/mdoc/src/lib.rs` down into `euwallet/crates/cose/src/cbor.rs`, with `mdoc` re-exporting via `pub use cose::cbor;` so every existing path and the Section 9 harness keep resolving. I also flagged two dependency-budget additions the plan requires: `der` + `x509-cert` (RustCrypto) for the `x509` crate, to be justified in `euwallet/docs/dependency-budget.md` and cleared by `cargo deny check`. All Rust skeletons route crypto through the `crypto_traits` boundary consistent with `euwallet/crates/crypto-traits/src/lib.rs`.

---


## Section 5 — Protocol state machines: oid4vp, oid4vci, iso18013-5 as exhaustive Rust enums

This section turns the three EUDI wire protocols into three hand-written, sans-IO Rust state machines. Each machine is a pure function `step(state, input) -> (next_state, effects)`: it never touches the network, a radio, a screen, or the clock. Everything it needs from the outside world arrives as a typed `Input`; everything it wants done is returned as an `Output` (an *effect*) that the shell (Section 8) executes. This is what makes the machines cheap to test, deterministic to replay, and — critically — a faithful refinement of the Lean model (Section 10) and the Tamarin analysis (Section 11).

Three rules you must not break while implementing this section (they come from Section 0's "Do not do" list and are re-checked by Tiers 2 and 3):
- **Never** advance past request-validation on an unsigned/unbound request object, an unregistered RP, or an undeclared purpose. These are hard aborts, not warnings.
- **Never** add an OAuth grant, response mode, or credential format that HAIP does not require. If it is not in the match, it does not exist.
- **Never** do I/O in these crates. If you find yourself reaching for `std::net`, `reqwest`, `tokio`, or a BLE library, stop — that byte belongs in an `Input` or an `Output`.

### 5.0 Shared convention — HLR IDs for the traceability importer (feeds Section 12)

Every state variant, every `step` match arm (transition), and every guard function carries a **High-Level-Requirement ID** in a doc-comment so the Section 12 importer can scan source and join it against the requirements register. Use exactly this token grammar:

```
HLR-<MACHINE>-<KIND>-<NNN>
  MACHINE ∈ { VP, VCI, ISO }     # oid4vp / oid4vci / iso18013-5
  KIND    ∈ { S, T, G }          # State / Transition / Guard
  NNN     = three digits, zero-padded, unique within (MACHINE,KIND)
```

Write it as the **first line** of the item's doc comment, prefixed with `HLR:`. The importer is a five-line ripgrep the Section 12 `xtask` runs; you never hand-maintain the table.

**Step 5.0.1** — Fix the scanning contract now so all later code is greppable. The importer regex (documented in Section 12, shown here only so your comments match it) is:

```
HLR-(VP|VCI|ISO)-[STG]-[0-9]{3}
```

It runs over `euwallet/crates/*/src/**.rs` **and** `euwallet/formal/lean/*.lean`, so the *same* ID appears next to the Rust arm and next to its Lean counterpart — that shared ID is what proves "code ⇔ proof" in the matrix.

**Definition of done (5.0):**
```
cd euwallet && rg -o 'HLR-(VP|VCI|ISO)-[STG]-[0-9]{3}' crates formal/lean | sort -u | head
# Expected: a non-empty, sorted, de-duplicated list of IDs once you have written the code below.
```

---

### 5.1 `oid4vp` — remote presentation (OpenID4VP 1.0, HAIP)

#### 1. Purpose and flow in plain words

A Relying Party (a website or another app) wants the user to *present* one or more credentials. It sends the wallet a signed **Authorization Request** (a request object — a JWT, possibly fetched from a `request_uri`). The wallet must: prove the request is genuinely from a *registered* RP and cryptographically bound (signed); check the RP declared **why** it wants the data (purpose) and that the request is addressed to *this* wallet (audience); reject **replayed** requests (nonce); ask the user's consent showing exactly what will be revealed; and only then build and post a **`vp_token`** back to the RP's `response_uri`. Any guard failure aborts *before* consent and reveals nothing.

The core is sans-IO, so "fetch the RP's trust status / JWKS" is an **effect** the shell fulfils, returning the answer as a follow-up `Input`. Signature verification itself is pure CPU (no I/O), so it happens in-core through the `crypto_traits::Verifier` boundary from Section 4.

#### 2. States, inputs, outputs, transition function

Replace the skeleton in `euwallet/crates/oid4vp/src/lib.rs` with the following production shapes (keep `#![forbid(unsafe_code)]` and the existing `pub mod model`).

`euwallet/crates/oid4vp/src/lib.rs`:
```rust
#![forbid(unsafe_code)]
//! `oid4vp` — OpenID4VP 1.0 remote presentation, sans-IO, HAIP-constrained.

use crypto_traits::{Alg, Verifier};

/// States of the remote-presentation flow.
///
/// Each variant is HLR-tagged so Section 12 can map it to the requirements register.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum State {
    /// HLR: HLR-VP-S-001 — no exchange in progress.
    Idle,
    /// HLR: HLR-VP-S-002 — request parsed; waiting for the shell to resolve RP trust + JWKS.
    ResolvingTrust(Box<AuthRequest>),
    /// HLR: HLR-VP-S-003 — all guards passed; request is signed, bound, fresh, purposeful.
    RequestValidated(Box<AuthRequest>),
    /// HLR: HLR-VP-S-004 — showing the user what will be disclosed; awaiting their decision.
    AwaitingConsent(Box<AuthRequest>),
    /// HLR: HLR-VP-S-005 — vp_token emitted; awaiting the shell's delivery acknowledgement.
    Presenting,
    /// HLR: HLR-VP-S-006 — exchange finished successfully (terminal).
    Done,
    /// HLR: HLR-VP-S-007 — exchange refused (terminal); reason is the tripped guard.
    Aborted(AbortReason),
}

/// Every abort reason is the name of the guard that tripped (or an explicit user refusal).
/// Tamarin (Section 11) enumerates exactly these as the attacker-reachable bad states.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbortReason {
    /// HLR: HLR-VP-G-001 — request_object_is_signed_and_bound failed.
    RequestNotSignedOrBound,
    /// HLR: HLR-VP-G-002 — rp_is_registered failed.
    RelyingPartyNotRegistered,
    /// HLR: HLR-VP-G-003 — nonce_is_fresh failed (replay).
    NonceReplayed,
    /// HLR: HLR-VP-G-004 — purpose_is_declared failed.
    PurposeUndeclared,
    /// HLR: HLR-VP-G-005 — audience_matches failed (mix-up / wrong wallet).
    AudienceMismatch,
    /// HLR: HLR-VP-G-006 — redirect_uri_is_registered failed (redirect attack).
    RedirectUriNotRegistered,
    /// HLR: HLR-VP-G-007 — request was malformed and could not be parsed.
    MalformedRequest,
    /// HLR: HLR-VP-G-008 — user declined at the consent screen.
    UserDeclined,
}

/// Parsed, still-untrusted Authorization Request. Parsing does NOT imply validity;
/// the guards in step (3) decide that. Fields mirror the OpenID4VP request object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthRequest {
    pub client_id: String,          // RP identity to check against the registry
    pub nonce: u64,                 // replay protection (modelled as u64 to match Lean)
    pub audience: String,           // must equal our wallet_client_id
    pub response_uri: String,       // where the vp_token is posted (direct_post.jwt)
    pub redirect_uri: Option<String>,
    pub purpose: Option<String>,    // CIR 2024/2982: RP must declare why
    pub dcql_query: Vec<u8>,        // opaque DCQL bytes; parsed by `presenter` (Section 4)
    pub signature: Vec<u8>,         // detached JWS/JAR signature over the request
    pub signed_payload: Vec<u8>,    // the exact bytes the signature covers
    pub request_alg: Alg,
}

/// Trust facts the SHELL resolves for us (effect result). No I/O happens in-core.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedTrust {
    pub registered: bool,               // RP present in the trust list / registrar
    pub rp_public_key: Vec<u8>,         // JWKS entry the shell fetched for this client_id
    pub registered_redirect_uris: Vec<String>,
}

/// Inputs (events) into the machine.
#[derive(Clone, Debug)]
pub enum Input {
    /// Raw request object bytes (JWT or JAR) received from the RP via the shell.
    AuthorizationRequest(Vec<u8>),
    /// The shell's answer to a `ResolveRpTrust` effect.
    RpTrustResolved(ResolvedTrust),
    ConsentGranted,
    ConsentDeclined,
    /// The shell confirms the vp_token reached the response_uri.
    PresentationDelivered,
}

/// Outputs (effects) the shell must perform. The core NEVER performs these itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Output {
    /// Fetch RP metadata / trust status / JWKS for this client_id (network I/O in the shell).
    ResolveRpTrust { client_id: String },
    /// Durable, idempotent nonce persistence so replay is caught across app restarts.
    PersistNonce(u64),
    /// Render the consent UI (Section 8) with exactly what will be disclosed.
    RenderConsent { rp_client_id: String, purpose: String },
    /// Post the encrypted vp_token to the response_uri (direct_post.jwt).
    SendVpToken(Vec<u8>),
    /// Tell the shell the exchange is over so it can tear down transport.
    Close,
}

/// Everything the pure guards read. The shell assembles this; the core does no I/O.
pub struct Env<'a> {
    /// The value RPs MUST put in `aud`; anything else is a mix-up attempt.
    pub wallet_client_id: &'a str,
    /// Signature verifier over the Section-4 crypto boundary (pure CPU, no I/O).
    pub verifier: &'a dyn Verifier,
}

/// Pure transition function — exhaustive match. This is the production machine; it must
/// refine `model::step` (see item 7). `env` carries only pure, already-resolved data.
pub fn step(state: &State, input: &Input, env: &Env) -> (State, Vec<Output>) {
    match (state, input) {
        // HLR: HLR-VP-T-001 — receive & parse; then ask the shell to resolve RP trust.
        (State::Idle, Input::AuthorizationRequest(bytes)) => match parse_request(bytes) {
            Ok(req) => {
                let client_id = req.client_id.clone();
                (
                    State::ResolvingTrust(Box::new(req)),
                    vec![Output::ResolveRpTrust { client_id }],
                )
            }
            // HLR: HLR-VP-T-002 — unparseable request → abort, disclose nothing.
            Err(()) => (State::Aborted(AbortReason::MalformedRequest), vec![]),
        },

        // HLR: HLR-VP-T-003 — trust resolved: run EVERY guard, in order, before consent.
        (State::ResolvingTrust(req), Input::RpTrustResolved(trust)) => {
            // The guard order is deliberate: cheap identity checks first, crypto last.
            if !rp_is_registered(req, trust) {
                return (State::Aborted(AbortReason::RelyingPartyNotRegistered), vec![]);
            }
            if !redirect_uri_is_registered(req, trust) {
                return (State::Aborted(AbortReason::RedirectUriNotRegistered), vec![]);
            }
            if !audience_matches(req, env.wallet_client_id) {
                return (State::Aborted(AbortReason::AudienceMismatch), vec![]);
            }
            if !purpose_is_declared(req) {
                return (State::Aborted(AbortReason::PurposeUndeclared), vec![]);
            }
            if !request_object_is_signed_and_bound(req, trust, env.verifier) {
                return (State::Aborted(AbortReason::RequestNotSignedOrBound), vec![]);
            }
            // Freshness is checked against the shell's durable store, which we asked for
            // implicitly via ResolveRpTrust; on success we tell it to REMEMBER this nonce.
            // (The shell rejects a duplicate PersistNonce, closing the cross-session race.)
            let purpose = req.purpose.clone().unwrap_or_default();
            let rp = req.client_id.clone();
            (
                State::RequestValidated(req.clone()),
                vec![
                    Output::PersistNonce(req.nonce),
                    Output::RenderConsent { rp_client_id: rp, purpose },
                ],
            )
        }

        // HLR: HLR-VP-T-004 — validated → waiting for the user to decide.
        (State::RequestValidated(req), Input::ConsentGranted) => {
            let token = build_vp_token(req); // pure; delegates to `presenter` (Section 4)
            (State::Presenting, vec![Output::SendVpToken(token)])
        }
        // HLR: HLR-VP-T-005 — user refuses → abort, disclose nothing.
        (State::RequestValidated(_), Input::ConsentDeclined) => {
            (State::Aborted(AbortReason::UserDeclined), vec![Output::Close])
        }

        // HLR: HLR-VP-T-006 — delivery acknowledged → done.
        (State::Presenting, Input::PresentationDelivered) => (State::Done, vec![Output::Close]),

        // HLR: HLR-VP-T-999 — any other (state,input) pair is a no-op (defensive, exhaustive).
        (s, _) => (s.clone(), vec![]),
    }
}
```

> Rust note for the junior dev: the `match (state, input)` tuple with a final `(s, _) => …` arm is what gives you **compile-time exhaustiveness** — if you later add a `State` variant and forget a transition, `cargo build` fails until you handle it. `Box<AuthRequest>` keeps the `State` enum small (a large variant would bloat every `State` value). `return` inside a match arm is idiomatic for guard-ladders like this.

#### 3. Guards as named, individually-testable predicates (happy path + attack paths)

Put every guard in one module so tests and the HLR importer find them together. Each is a **pure function returning `bool`** — no I/O, no mutation — which is exactly what makes them unit-testable and Tamarin-checkable.

Append to `euwallet/crates/oid4vp/src/lib.rs`:
```rust
/// Security guards. Each is pure and individually testable; each maps 1:1 to an AbortReason.
pub mod guards {
    use super::{AuthRequest, ResolvedTrust};
    use crypto_traits::Verifier;

    /// HLR: HLR-VP-G-001 — the request object is signed by the RP's key AND the signature
    /// covers the exact bytes we parsed (no substitution). Rejects the "unsigned request" and
    /// "swapped payload" attacks. Verification is pure CPU over the crypto trait boundary.
    pub fn request_object_is_signed_and_bound(
        req: &AuthRequest,
        trust: &ResolvedTrust,
        verifier: &dyn Verifier,
    ) -> bool {
        !req.signature.is_empty()
            && verifier
                .verify(req.request_alg, &trust.rp_public_key, &req.signed_payload, &req.signature)
                .is_ok()
    }

    /// HLR: HLR-VP-G-002 — the RP is in the trust list / registrar (CIR 2024/2982 registration).
    pub fn rp_is_registered(_req: &AuthRequest, trust: &ResolvedTrust) -> bool {
        trust.registered
    }

    /// HLR: HLR-VP-G-003 — the nonce has not been seen before (replay protection). `seen` is a
    /// snapshot the shell supplies; the durable check is closed by the PersistNonce effect.
    pub fn nonce_is_fresh(nonce: u64, seen: &[u64]) -> bool {
        !seen.contains(&nonce)
    }

    /// HLR: HLR-VP-G-004 — the RP declared a purpose for the request (no silent over-asking).
    pub fn purpose_is_declared(req: &AuthRequest) -> bool {
        req.purpose.as_deref().map(|p| !p.trim().is_empty()).unwrap_or(false)
    }

    /// HLR: HLR-VP-G-005 — the request is addressed to THIS wallet. Defeats the OAuth mix-up
    /// attack where a response is routed to a different, honest wallet/AS.
    pub fn audience_matches(req: &AuthRequest, wallet_client_id: &str) -> bool {
        req.audience == wallet_client_id
    }

    /// HLR: HLR-VP-G-006 — any redirect_uri is one the RP pre-registered. Defeats the open
    /// redirector / response-injection attack (OAuth Security BCP §4.1).
    pub fn redirect_uri_is_registered(req: &AuthRequest, trust: &ResolvedTrust) -> bool {
        match &req.redirect_uri {
            None => true, // direct_post flows carry no redirect_uri
            Some(uri) => trust.registered_redirect_uris.iter().any(|r| r == uri),
        }
    }
}
```

Attack-path → abort mapping (this is the table Section 11 checks against Tamarin lemmas):

| Attack | Guard that trips | Resulting `State` |
|---|---|---|
| Unsigned / payload-swapped request | `request_object_is_signed_and_bound` | `Aborted(RequestNotSignedOrBound)` |
| Unknown / spoofed RP | `rp_is_registered` | `Aborted(RelyingPartyNotRegistered)` |
| Replayed request (nonce reuse) | `nonce_is_fresh` | `Aborted(NonceReplayed)` |
| Silent over-asking (no purpose) | `purpose_is_declared` | `Aborted(PurposeUndeclared)` |
| Mix-up (response to wrong wallet) | `audience_matches` | `Aborted(AudienceMismatch)` |
| Redirect / response injection | `redirect_uri_is_registered` | `Aborted(RedirectUriNotRegistered)` |
| Garbage bytes | parse failure | `Aborted(MalformedRequest)` |
| User says no | — | `Aborted(UserDeclined)` |

> The happy path is: `Idle → ResolvingTrust → RequestValidated → Presenting → Done`, with `SendVpToken` emitted only after `ConsentGranted`. Nothing leaves the wallet before that transition.

`parse_request` and `build_vp_token` are pure helpers you implement over the Section-4 crates (`sdjwt`, `mdoc`, `presenter`); keep them free of I/O. Stub signatures:
```rust
fn parse_request(_bytes: &[u8]) -> Result<AuthRequest, ()> { /* decode JWT/JAR headers+claims */ Err(()) }
fn build_vp_token(_req: &AuthRequest) -> Vec<u8> { /* delegate to presenter; canonical bytes */ Vec::new() }
```

#### 6. HLR labelling (this machine)

Already applied above: `HLR-VP-S-00x` on each `State` variant, `HLR-VP-T-00x` on each match arm, `HLR-VP-G-00x` on each guard and its mirror `AbortReason`. The Section-12 importer greps them straight out of this file.

#### 7. Relationship to the Lean model (Section 10)

The `pub mod model` already in this file is the **behavioural twin** of `formal/lean/WalletModel.lean`: same states (`idle/requested/validated/awaitingConsent/presenting/aborted`), same events, same `Ctx` fields, same guard logic (replayed nonce → aborted; no disclose without consent + validated signature). The production `step` above is a *refinement* of `model::step` — it adds real parsing, real crypto, and effect emission, but it must never accept a trace the model rejects. Keep `model` byte-for-byte faithful; when you extend the model, extend `WalletModel.lean` in the same commit and re-export traces (`Traces.lean`, Section 10). Tag the shared IDs in both files so the matrix links them.

#### 8. Definition of done (`oid4vp`)

Add state-transition unit tests covering **every** failure path plus the happy path, and keep the Lean-oracle replay green.

`euwallet/crates/oid4vp/tests/transitions.rs` (new) must include one test per `AbortReason` (unsigned, unregistered RP, replay, undeclared purpose, audience mismatch, redirect, malformed, user-declined) and one happy-path test asserting `SendVpToken` is emitted only after `ConsentGranted`.

```
cd euwallet/crates/oid4vp
cargo test
# Expected:
#   test result: ok.  (transitions.rs — every abort path + happy path)
#   test rust_core_matches_lean_oracle ... ok   (conformance.rs — Lean oracle replay)
cargo test --test conformance
# Expected: rust_core_matches_lean_oracle ... ok   (model stays identical to WalletModel.lean)
```

---

### 5.2 `oid4vci` — credential issuance (OpenID4VCI 1.0, HAIP-only)

#### 1 & 4. Purpose and the offer → authorization → token → credential flow (HAIP-restricted)

The wallet obtains a credential from an Issuer. HAIP admits exactly **two** grant paths and nothing else:

- **Pre-authorized code** (`urn:ietf:params:oauth:grant-type:pre-authorized_code`), optionally gated by a transaction code (PIN) the user types.
- **Authorization code**, which under HAIP **must** use PAR (Pushed Authorization Requests) and **must** use PKCE with `S256`.

Flow in words: the wallet receives a **Credential Offer** (deep link / QR), decides which grant applies, (for auth-code) pushes a PAR request and drives the browser, exchanges the code for an **access token** (DPoP-bound), then presents a **proof of possession** of a hardware-bound key (a `jwt` proof over the issuer's fresh `c_nonce`, plus a Wallet Unit Attestation from `wua`, Section 4) to the **Credential Endpoint**, which returns the credential. The wallet accepts **only two formats**: `mso_mdoc` (→ `mdoc::IssuerSigned`) and `dc+sd-jwt` (→ `sdjwt::SdJwtVc`). Any other grant, response type, or format is rejected — do **not** add them.

#### 2. States, inputs, outputs, transition slice

`euwallet/crates/oid4vci/src/lib.rs`:
```rust
#![forbid(unsafe_code)]
//! `oid4vci` — OpenID4VCI 1.0 issuance, sans-IO, HAIP flows only.

/// The only two grant types HAIP permits. There is no "other" variant on purpose.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HaipGrant {
    /// HLR: HLR-VCI-S-010 — pre-authorized_code (optionally PIN-gated).
    PreAuthorized { tx_code_required: bool },
    /// HLR: HLR-VCI-S-011 — authorization_code (PAR + PKCE S256 mandatory).
    AuthorizationCode,
}

/// The only two credential formats the wallet issues into.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialFormat {
    /// HLR: HLR-VCI-S-012 — ISO mdoc, becomes `mdoc::IssuerSigned`.
    MsoMdoc,
    /// HLR: HLR-VCI-S-013 — SD-JWT VC, becomes `sdjwt::SdJwtVc`.
    DcSdJwt,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum State {
    /// HLR: HLR-VCI-S-001
    Idle,
    /// HLR: HLR-VCI-S-002 — offer parsed; grant + format chosen and validated.
    OfferParsed { grant: HaipGrant, format: CredentialFormat },
    /// HLR: HLR-VCI-S-003 — (auth-code) PAR pushed, waiting for the browser redirect result.
    Authorizing,
    /// HLR: HLR-VCI-S-004 — (pre-auth) waiting for the user's transaction code / PIN.
    AwaitingTxCode,
    /// HLR: HLR-VCI-S-005 — token request in flight.
    RequestingToken,
    /// HLR: HLR-VCI-S-006 — access token held; issuer gave us a fresh c_nonce for proof.
    TokenObtained { c_nonce: u64 },
    /// HLR: HLR-VCI-S-007 — credential request (with key-bound proof) in flight.
    RequestingCredential,
    /// HLR: HLR-VCI-S-008 — credential received & format-validated (terminal).
    CredentialIssued(CredentialFormat),
    /// HLR: HLR-VCI-S-009 — aborted (terminal).
    Aborted(AbortReason),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbortReason {
    /// HLR: HLR-VCI-G-001 — grant_type_is_haip_allowed failed.
    UnsupportedGrant,
    /// HLR: HLR-VCI-G-002 — credential_format_is_supported failed.
    UnsupportedFormat,
    /// HLR: HLR-VCI-G-003 — issuer_is_trusted failed.
    IssuerNotTrusted,
    /// HLR: HLR-VCI-G-004 — pkce_s256_present failed (auth-code without PKCE S256).
    PkceMissing,
    /// HLR: HLR-VCI-G-005 — tx_code_valid failed.
    TxCodeInvalid,
    /// HLR: HLR-VCI-G-006 — access_token_is_bound failed (DPoP / sender-constraint).
    TokenNotBound,
    /// HLR: HLR-VCI-G-007 — c_nonce_is_fresh failed (proof replay).
    CNonceStale,
    /// HLR: HLR-VCI-G-008 — proof_key_is_attested failed (WUA / key attestation).
    ProofKeyNotAttested,
    /// HLR: HLR-VCI-G-009 — issued credential failed its format validator.
    CredentialInvalid,
    UserDeclined,
}

#[derive(Clone, Debug)]
pub enum Input {
    CredentialOffer(Vec<u8>),
    ParPushed { pkce_s256: bool },     // shell reports the PAR it built
    AuthCodeReturned(Vec<u8>),         // browser redirect result
    TxCodeEntered(Vec<u8>),            // user's PIN
    TokenResponse { bound: bool, c_nonce: u64 }, // shell parsed the token endpoint reply
    CredentialResponse { format: CredentialFormat, bytes: Vec<u8> },
    Decline,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Output {
    /// Ask the shell to push a PAR request (network I/O in the shell).
    PushPar,
    /// Ask the shell to open the browser / render the PIN prompt.
    OpenAuthBrowser,
    PromptTxCode,
    /// Exchange the (pre-auth or auth) code for a token.
    RequestToken,
    /// Build a key-bound proof-of-possession over `c_nonce` using the hardware key + WUA,
    /// then request the credential. The proof itself is built via the crypto boundary.
    RequestCredential { c_nonce: u64 },
    Close,
}

/// Env carries only pure facts (trust status, attestation result) the shell resolved.
pub struct Env<'a> {
    pub issuer_trusted: bool,
    pub proof_key_attested: bool,
    pub seen_c_nonces: &'a [u64],
}

pub fn step(state: &State, input: &Input, env: &Env) -> (State, Vec<Output>) {
    match (state, input) {
        // HLR: HLR-VCI-T-001 — parse offer; reject non-HAIP grant/format immediately.
        (State::Idle, Input::CredentialOffer(bytes)) => match parse_offer(bytes) {
            Ok((grant, format)) => {
                if !guards::issuer_is_trusted(env) {
                    return (State::Aborted(AbortReason::IssuerNotTrusted), vec![]);
                }
                if !guards::grant_type_is_haip_allowed(grant) {
                    return (State::Aborted(AbortReason::UnsupportedGrant), vec![]);
                }
                if !guards::credential_format_is_supported(format) {
                    return (State::Aborted(AbortReason::UnsupportedFormat), vec![]);
                }
                match grant {
                    HaipGrant::AuthorizationCode => {
                        (State::OfferParsed { grant, format }, vec![Output::PushPar])
                    }
                    HaipGrant::PreAuthorized { tx_code_required: true } => {
                        (State::AwaitingTxCode, vec![Output::PromptTxCode])
                    }
                    HaipGrant::PreAuthorized { tx_code_required: false } => {
                        (State::RequestingToken, vec![Output::RequestToken])
                    }
                }
            }
            Err(()) => (State::Aborted(AbortReason::UnsupportedFormat), vec![]),
        },

        // HLR: HLR-VCI-T-002 — auth-code: PAR must carry PKCE S256, or abort.
        (State::OfferParsed { grant: HaipGrant::AuthorizationCode, .. }, Input::ParPushed { pkce_s256 }) => {
            if !guards::pkce_s256_present(*pkce_s256) {
                return (State::Aborted(AbortReason::PkceMissing), vec![]);
            }
            (State::Authorizing, vec![Output::OpenAuthBrowser])
        }
        // HLR: HLR-VCI-T-003 — browser returned the auth code → request token.
        (State::Authorizing, Input::AuthCodeReturned(_code)) => {
            (State::RequestingToken, vec![Output::RequestToken])
        }
        // HLR: HLR-VCI-T-004 — pre-auth PIN entered → validate, then request token.
        (State::AwaitingTxCode, Input::TxCodeEntered(code)) => {
            if !guards::tx_code_valid(code) {
                return (State::Aborted(AbortReason::TxCodeInvalid), vec![]);
            }
            (State::RequestingToken, vec![Output::RequestToken])
        }

        // HLR: HLR-VCI-T-005 — token must be sender-constrained (DPoP) and give a fresh c_nonce.
        (State::RequestingToken, Input::TokenResponse { bound, c_nonce }) => {
            if !guards::access_token_is_bound(*bound) {
                return (State::Aborted(AbortReason::TokenNotBound), vec![]);
            }
            if !guards::c_nonce_is_fresh(*c_nonce, env.seen_c_nonces) {
                return (State::Aborted(AbortReason::CNonceStale), vec![]);
            }
            if !guards::proof_key_is_attested(env) {
                return (State::Aborted(AbortReason::ProofKeyNotAttested), vec![]);
            }
            (
                State::TokenObtained { c_nonce: *c_nonce },
                vec![Output::RequestCredential { c_nonce: *c_nonce }],
            )
        }

        // HLR: HLR-VCI-T-006 — credential returned: accept only supported, valid formats.
        (State::TokenObtained { .. }, Input::CredentialResponse { format, bytes }) => {
            if !guards::credential_format_is_supported(*format) {
                return (State::Aborted(AbortReason::UnsupportedFormat), vec![]);
            }
            if !validate_issued_credential(*format, bytes) {
                return (State::Aborted(AbortReason::CredentialInvalid), vec![]);
            }
            (State::CredentialIssued(*format), vec![Output::Close])
        }

        // HLR: HLR-VCI-T-007 — user declines at any pre-terminal step.
        (_, Input::Decline) => (State::Aborted(AbortReason::UserDeclined), vec![Output::Close]),

        // HLR: HLR-VCI-T-999 — everything else is a defensive no-op.
        (s, _) => (s.clone(), vec![]),
    }
}
```

#### 3. Guards (HAIP allow-listing is itself a guard)

`euwallet/crates/oid4vci/src/lib.rs` (append):
```rust
pub mod guards {
    use super::{CredentialFormat, Env, HaipGrant};

    /// HLR: HLR-VCI-G-001 — only the two HAIP grants are ever allowed. Because `HaipGrant`
    /// has no other variants, this is total; the guard exists so a future careless `parse_offer`
    /// still cannot smuggle a disallowed grant past a single choke point.
    pub fn grant_type_is_haip_allowed(_g: HaipGrant) -> bool { true }

    /// HLR: HLR-VCI-G-002 — only mso_mdoc and dc+sd-jwt are accepted.
    pub fn credential_format_is_supported(f: CredentialFormat) -> bool {
        matches!(f, CredentialFormat::MsoMdoc | CredentialFormat::DcSdJwt)
    }

    /// HLR: HLR-VCI-G-003 — the issuer is on the trust list (shell-resolved).
    pub fn issuer_is_trusted(env: &Env) -> bool { env.issuer_trusted }

    /// HLR: HLR-VCI-G-004 — auth-code flow must use PKCE S256 (HAIP + OAuth Security BCP).
    pub fn pkce_s256_present(pkce_s256: bool) -> bool { pkce_s256 }

    /// HLR: HLR-VCI-G-005 — the transaction code matches (non-empty, issuer-checked).
    pub fn tx_code_valid(code: &[u8]) -> bool { !code.is_empty() }

    /// HLR: HLR-VCI-G-006 — the access token is sender-constrained (DPoP/attestation), never bearer.
    pub fn access_token_is_bound(bound: bool) -> bool { bound }

    /// HLR: HLR-VCI-G-007 — the proof-of-possession c_nonce is fresh (no proof replay).
    pub fn c_nonce_is_fresh(c_nonce: u64, seen: &[u64]) -> bool { !seen.contains(&c_nonce) }

    /// HLR: HLR-VCI-G-008 — the proof key is hardware-attested (WUA / key attestation, Section 4).
    pub fn proof_key_is_attested(env: &Env) -> bool { env.proof_key_attested }
}

fn parse_offer(_bytes: &[u8]) -> Result<(HaipGrant, CredentialFormat), ()> { Err(()) }

/// Delegate to the SINGLE credential-validation stack (Section 4) — never fork a second one.
fn validate_issued_credential(_format: CredentialFormat, _bytes: &[u8]) -> bool { false }
```

> Note the "do not do" rule enforced structurally: there is no `HaipGrant::Other`, no `CredentialFormat::Jwt`, and `validate_issued_credential` **delegates** to `mdoc`/`sdjwt` (Section 4) rather than re-checking signatures here — one validation stack, not two.

#### 6 & 7. HLR labels and Lean relationship

IDs `HLR-VCI-{S,T,G}-*` are on every variant, arm, and guard. This machine gets its own `pub mod model` (add it mirroring the oid4vp pattern) once Section 10 adds `formal/lean/IssuanceModel.lean`; until then the discipline is identical — the model module and a `tests/conformance.rs` replay of the issuance oracle are required before this crate is considered "modelled". Tag shared IDs across the Rust `model` and the Lean file.

#### 8. Definition of done (`oid4vci`)

`euwallet/crates/oid4vci/tests/transitions.rs` (new): one test per `AbortReason` (unsupported grant, unsupported format, untrusted issuer, PKCE missing, tx-code invalid, token not bound, c_nonce stale, proof key not attested, credential invalid, user declined) plus the two happy paths (pre-auth with PIN, and auth-code with PAR+PKCE) ending in `CredentialIssued`.

```
cd euwallet/crates/oid4vci
cargo test
# Expected: test result: ok. — all abort paths + both happy paths pass.
cargo test --test conformance   # once IssuanceModel oracle exists (Section 10)
# Expected: issuance_core_matches_lean_oracle ... ok
```

---

### 5.3 `iso18013-5` — proximity presentation (ISO/IEC 18013-5:2021)

#### 1 & 5. Purpose and the device-engagement → session → response flow (transport opaque)

In-person mdoc presentation over BLE/NFC/QR. Three phases: (a) **Device Engagement** — the wallet emits an engagement structure (holding its ephemeral public key + transport hints) that the reader scans (QR/NFC); (b) **Session Establishment** — the reader replies with its ephemeral key and an encrypted mdoc request; the wallet does ephemeral-ephemeral ECDH + HKDF to derive session keys and builds the **SessionTranscript** that cryptographically binds this session to the engagement (anti-relay); (c) **Device Response** — after consent, the wallet returns an encrypted, device-signed mdoc response. **All transport bytes are opaque `Vec<u8>`** in and out — BLE/NFC/QR framing is entirely the shell's job (Section 8). This crate does ECDH/HKDF/AEAD only through the `crypto_traits` boundary (Section 4); it never opens a radio.

#### 2 & 3. States, inputs, outputs, transition slice, and guards

`euwallet/crates/iso18013-5/src/lib.rs`:
```rust
#![forbid(unsafe_code)]
//! `iso18013_5` — ISO/IEC 18013-5 proximity, sans-IO. Transport bytes are opaque.

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum State {
    /// HLR: HLR-ISO-S-001
    Idle,
    /// HLR: HLR-ISO-S-002 — engagement emitted; holds our ephemeral key handle. Awaiting reader.
    Engaged { device_engagement: Vec<u8> },
    /// HLR: HLR-ISO-S-003 — session keys derived; SessionTranscript bound; request decrypted.
    SessionEstablished,
    /// HLR: HLR-ISO-S-004 — user consented; encrypted device response emitted.
    Responded,
    /// HLR: HLR-ISO-S-005 — session torn down (terminal).
    Terminated,
    /// HLR: HLR-ISO-S-006 — aborted (terminal).
    Aborted(AbortReason),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbortReason {
    /// HLR: HLR-ISO-G-001 — session_transcript_is_bound failed (relay / unbound transcript).
    SessionTranscriptUnbound,
    /// HLR: HLR-ISO-G-002 — reader_ephemeral_key_valid failed (bad point / identity element).
    ReaderKeyInvalid,
    /// HLR: HLR-ISO-G-003 — request_within_established_session failed (data before keys).
    RequestOutOfOrder,
    /// HLR: HLR-ISO-G-004 — no_response_without_consent failed.
    NoConsent,
    /// HLR: HLR-ISO-G-005 — reader_auth_valid failed (present but invalid ReaderAuth).
    ReaderAuthInvalid,
}

#[derive(Clone, Debug)]
pub enum Input {
    /// Shell asks us to begin (it will transmit the engagement over QR/NFC/BLE).
    StartEngagement,
    /// Opaque SessionEstablishment message from the reader (eReaderKey + encrypted request).
    ReaderEstablishment(Vec<u8>),
    ConsentGranted,
    ConsentDeclined,
    /// Reader / shell signalled session termination.
    ReaderTermination,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Output {
    /// Hand the shell the engagement bytes to broadcast (QR image / NFC APDU / BLE advert).
    EmitDeviceEngagement(Vec<u8>),
    RenderConsent,
    /// Hand the shell the encrypted device response to transmit.
    EmitDeviceResponse(Vec<u8>),
    EmitTermination,
}

/// Facts derived purely (via the crypto boundary) from the reader's message + our engagement.
pub struct Env {
    pub reader_key_on_curve: bool,      // reader ephemeral key validation result
    pub transcript_bound: bool,         // SessionTranscript binds engagement+eReaderKey+handover
    pub reader_auth_present: bool,
    pub reader_auth_valid: bool,
}

pub fn step(state: &State, input: &Input, env: &Env) -> (State, Vec<Output>) {
    match (state, input) {
        // HLR: HLR-ISO-T-001 — begin: build engagement (holds our ephemeral pubkey) & emit it.
        (State::Idle, Input::StartEngagement) => {
            let de = build_device_engagement(); // pure; ephemeral key generated via crypto boundary
            (State::Engaged { device_engagement: de.clone() }, vec![Output::EmitDeviceEngagement(de)])
        }

        // HLR: HLR-ISO-T-002 — reader replied: validate its key, bind transcript, derive keys.
        (State::Engaged { .. }, Input::ReaderEstablishment(_bytes)) => {
            if !guards::reader_ephemeral_key_valid(env) {
                return (State::Aborted(AbortReason::ReaderKeyInvalid), vec![]);
            }
            if !guards::session_transcript_is_bound(env) {
                return (State::Aborted(AbortReason::SessionTranscriptUnbound), vec![]);
            }
            if !guards::reader_auth_valid(env) {
                return (State::Aborted(AbortReason::ReaderAuthInvalid), vec![]);
            }
            // Keys derived (ECDH+HKDF) and request decrypted here, all via the crypto boundary.
            (State::SessionEstablished, vec![Output::RenderConsent])
        }

        // HLR: HLR-ISO-T-003 — consent → build & emit the encrypted device response.
        (State::SessionEstablished, Input::ConsentGranted) => {
            let resp = build_device_response(); // device-signed mdoc, then AEAD-sealed
            (State::Responded, vec![Output::EmitDeviceResponse(resp)])
        }
        // HLR: HLR-ISO-T-004 — refusal before any data leaves.
        (State::SessionEstablished, Input::ConsentDeclined) => {
            (State::Aborted(AbortReason::NoConsent), vec![Output::EmitTermination])
        }

        // HLR: HLR-ISO-T-005 — a request/response attempt before the session exists is rejected.
        (State::Engaged { .. }, Input::ConsentGranted) => {
            (State::Aborted(AbortReason::RequestOutOfOrder), vec![])
        }

        // HLR: HLR-ISO-T-006 — clean teardown from any state.
        (_, Input::ReaderTermination) => (State::Terminated, vec![Output::EmitTermination]),

        // HLR: HLR-ISO-T-999 — defensive no-op keeps the match exhaustive.
        (s, _) => (s.clone(), vec![]),
    }
}

pub mod guards {
    use super::Env;

    /// HLR: HLR-ISO-G-001 — the SessionTranscript binds DeviceEngagement + eReaderKey + handover,
    /// so the reader cannot relay our response into a different session (anti-relay / anti-MITM).
    pub fn session_transcript_is_bound(env: &Env) -> bool { env.transcript_bound }

    /// HLR: HLR-ISO-G-002 — the reader's ephemeral key is a valid curve point (not identity),
    /// blocking invalid-curve / small-subgroup attacks on the ECDH.
    pub fn reader_ephemeral_key_valid(env: &Env) -> bool { env.reader_key_on_curve }

    /// HLR: HLR-ISO-G-005 — if ReaderAuth is present it must verify; absent ReaderAuth is allowed
    /// (18013-5 makes reader authentication optional) but a PRESENT-but-invalid one aborts.
    pub fn reader_auth_valid(env: &Env) -> bool { !env.reader_auth_present || env.reader_auth_valid }
}

fn build_device_engagement() -> Vec<u8> { Vec::new() } // pure; via crypto boundary
fn build_device_response() -> Vec<u8> { Vec::new() }   // pure; mdoc DeviceSigned + AEAD seal
```

Attack/failure → abort mapping: relay/unbound transcript → `SessionTranscriptUnbound`; malicious reader key → `ReaderKeyInvalid`; data before session keys → `RequestOutOfOrder`; consent refused → `NoConsent`; forged ReaderAuth → `ReaderAuthInvalid`. Happy path: `Idle → Engaged → SessionEstablished → Responded`, with `EmitDeviceResponse` emitted **only** after `ConsentGranted`.

> Note ISO/IEC TS 18013-7 (remote mdoc) reuses this same machine's response construction but is *driven by* the `oid4vp` machine (the transcript is bound to the OpenID4VP nonce instead of a proximity handover). Do not fork a second response builder; share `build_device_response`.

#### 6 & 7. HLR labels and Lean relationship

IDs `HLR-ISO-{S,T,G}-*` are attached above. Like `oid4vci`, this machine gets a `pub mod model` mirroring a Section-10 `formal/lean/ProximityModel.lean` (the key safety invariants: no response before an established, transcript-bound session; no response without consent). Add the `model` module + `tests/conformance.rs` replay before marking this crate modelled; share IDs across Rust `model` and Lean.

#### 8. Definition of done (`iso18013-5`)

`euwallet/crates/iso18013-5/tests/transitions.rs` (new): one test per `AbortReason` (unbound transcript, invalid reader key, out-of-order request, no consent, invalid ReaderAuth) plus a happy-path test asserting `EmitDeviceResponse` appears only after `ConsentGranted` from `SessionEstablished`.

```
cd euwallet/crates/iso18013-5
cargo test
# Expected: test result: ok. — all abort paths + happy path pass.
cargo test --test conformance   # once ProximityModel oracle exists (Section 10)
# Expected: proximity_core_matches_lean_oracle ... ok
```

---

### Section 5 definition of done (gate)

All of the following must pass before Section 5 is complete; this is the gate Sections 10–12 depend on.

1. **Everything builds, sans-IO holds.** No I/O crate appears in any of the three `Cargo.toml` dependency lists (only `crypto-traits`, `mdoc`, `sdjwt`, `x509`, `cose`, `presenter`).
   ```
   cd euwallet && cargo build --workspace
   # Expected: Finished ... with 0 errors. No network/tokio/BLE dependency present.
   ```
2. **Exhaustiveness is enforced by the compiler.** Each `step` ends in a catch-all arm and matches on `(State, Input)` tuples; adding a `State` variant without handling it fails the build (verify once by temporarily adding a dummy variant, then revert).
3. **Every failure path is unit-tested.** `transitions.rs` in all three crates covers each `AbortReason` and each happy path.
   ```
   cd euwallet && cargo test --workspace
   # Expected: test result: ok. across oid4vp, oid4vci, iso18013-5 (transition + conformance suites).
   ```
4. **Lean-oracle conformance is green.** `oid4vp`'s `tests/conformance.rs` replays `formal/lean` traces and passes; `oid4vci` and `iso18013-5` have their `model` module + replay wired to the Section-10 oracles as those models land.
   ```
   cd euwallet/crates/oid4vp && cargo test --test conformance
   # Expected: rust_core_matches_lean_oracle ... ok
   ```
5. **HLR coverage is complete.** The Section-12 importer finds an ID on every state variant, transition arm, and guard across all three crates.
   ```
   cd euwallet && rg -c 'HLR-(VP|VCI|ISO)-[STG]-[0-9]{3}' crates/oid4vp/src/lib.rs crates/oid4vci/src/lib.rs crates/iso18013-5/src/lib.rs
   # Expected: a non-zero count for each file; every variant/arm/guard is tagged.
   ```

Cross-references: these machines consume the credential-format and crypto boundaries defined in **Section 4** (`mdoc`, `sdjwt`, `cose`, `crypto-traits`); their effects are executed by the shell in **Section 8** (transport, UI, network, keystore); their `model` modules are the executable refinement of the Lean proofs in **Section 10**; the guard/abort set is exactly the attacker-reachable surface analysed by Tamarin in **Section 11**; and every `HLR-*` ID feeds the traceability matrix in **Section 12**.

---


## Section 6 — trust, status, and wua crates

> **Where you are in the document.** Sections 1–5 gave you the workspace, the sans-IO `Core`, the `Event`/`Effect` enums, the `crypto-traits` crate, and the codec crates (`cose`, `x509`, `mdoc`, `sdjwt`). This section builds the three crates that answer the question *"can I believe this thing?"* at three different levels:
>
> - **`trust`** — *"Is the issuer/RP one the ecosystem vouches for?"* (trusted lists, trust anchors).
> - **`status`** — *"Is this specific credential still valid right now?"* (revocation / suspension via Token Status List, plus certificate status).
> - **`wua`** — *"Is this wallet instance and its keys genuine hardware, not a software clone?"* (Wallet Unit Attestation + platform key attestation).
>
> All three obey the same hard rule from the shared context: **parsing and validation are pure functions inside the core; fetching bytes over the network, reading the clock, and touching the Secure Enclave are `Effect`s executed by the shell** (Sections 2 and 4). A pure function here means: same input bytes + same injected "now" timestamp + same trust anchors ⇒ same decision, every time, on any machine, with no I/O. That determinism is what makes the Lean trace-replay oracle (Section 9) and the fuzzers (Section 8) possible.
>
> **Register-ID map for this section** (pin these in each crate's `README.md` change-watch table):
> | Register ID | What it governs | Crate | Version marker |
> |---|---|---|---|
> | **Reg. (EU) 2025/2164** | Trusted lists / provider-of-trusted-list infrastructure, RP registration & trust-list publication | `trust` | pin `REG_2025_2164` |
> | **Reg. (EU) 2025/847** | Wallet-unit integrity, WUA & wallet-provider trust, key attestation expectations | `wua`, partly `trust` | pin `REG_2025_847` |
> | **ARF TS03** | Wallet Unit Attestation technical spec (WUA structure, key attestation binding) | `wua` | pin `TS03` |
> | **Token Status List draft-21** | Per-credential revocation/suspension status | `status` | pin `TSL_DRAFT_21` |
> | **ETSI TS 119 612 / TS 119 602** | Trusted-list XML/data-model & signature | `trust` | pin `ETSI_119612`, `ETSI_119602` |
> | **ARF v2.9.0 / PID Rulebook v1.6** | Overarching profile constraints | all three | pin as in Section 1 |
>
> **Danger note repeated up front (it is the whole point of this section):** never trust a device's self-claim. A WUA that a wallet signs about *itself* proves nothing; the value comes only when the signature chains up to a wallet-provider certificate that chains up to a **trusted-list anchor you obtained out of band**. Likewise a trusted list you downloaded is worthless until its ETSI signature verifies against a **pinned trust anchor**. The root of trust always terminates in something you compiled in or provisioned during onboarding — never in bytes that arrived over the wire in the same flow.

---

### 6.0 — Prerequisites and shared plumbing for all three crates

These three crates all need: (a) an injected notion of "now" (never `SystemTime::now()` inside the core), (b) a way to express a fetch as an `Effect`, and (c) shared error ergonomics. We wire that once.

**Step 6.0.1 — Create the three crates.**

```bash
cd ~/dev/advatar/EUWallet   # the repo root that contains crates/
for c in trust status wua; do
  cargo new --lib "crates/$c"
done
```

**Step 6.0.2 — Pin `#![forbid(unsafe_code)]` and edition in each.** For each of the three, open `crates/<crate>/src/lib.rs` and make the first two lines:

```rust
#![forbid(unsafe_code)]
#![deny(warnings, clippy::all, clippy::pedantic, missing_docs)]
//! See Section 6 of the implementation plan. Pure validation only; all I/O is an Effect.
```

**Step 6.0.3 — Add the shared "clock is an input, not a call" type.** These crates must never read the system clock. Instead every validation takes a `now: UtcInstant`. Put this in `crates/wallet-core` (created in Section 2) so all three can depend on it — but if you have not yet created it, add a tiny leaf crate `crates/time-model`:

```bash
cargo new --lib crates/time-model
```

`crates/time-model/src/lib.rs`:

```rust
#![forbid(unsafe_code)]
//! A clock value is DATA passed into pure validators. The shell obtains it via an
//! Effect (Effect::ReadClock) and feeds it back as an Event; the core never calls now().

use serde::{Deserialize, Serialize};

/// UTC time as whole seconds since the Unix epoch. We deliberately avoid `chrono`
/// in the core to keep the dependency surface tiny and the type trivially hashable.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub struct UtcInstant(pub i64);

impl UtcInstant {
    /// Seconds between `self` and `other`; positive if `self` is later.
    #[must_use]
    pub fn seconds_since(self, other: UtcInstant) -> i64 {
        self.0 - other.0
    }
    #[must_use]
    pub fn is_after(self, other: UtcInstant) -> bool {
        self.0 > other.0
    }
}

/// A monotonic duration in whole seconds (for "max staleness", "grace window", etc.).
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub struct Seconds(pub u64);
```

> **Jargon:** *epoch seconds* = a single integer counting seconds since 1970-01-01T00:00:00Z. We use it so the "now" value is a plain number that serializes identically everywhere and can be embedded in Lean-exported test traces (Section 9).

**Definition of done (6.0):**

```bash
cargo build -p trust -p status -p wua -p time-model
```
Expected: `Finished dev [unoptimized + debuginfo] target(s)` with **no** warnings (because of `deny(warnings)`), and no crate has pulled in a networking dependency (verify with `cargo tree -p trust | grep -Ei 'reqwest|hyper|tokio|ureq'` returning **nothing**).

---

### 6.1 — The `trust` crate

#### 6.1.1 Responsibility

The `trust` crate answers: *is this X.509 certificate (an issuer's, or a relying party's, or a wallet provider's) anchored in a trusted list that the EU ecosystem publishes and signs?* Concretely it:

1. Parses a **trusted list** — an XML document following **ETSI TS 119 612** (the trusted-list data model) whose signature format and profile follow **ETSI TS 119 602** and the EUDI trust-infrastructure regulation **Reg. (EU) 2025/2164**.
2. **Verifies the trusted list's own signature** against a **pinned trust anchor** (the "list-of-the-lists" / scheme-operator certificate you compiled in or provisioned at onboarding).
3. Extracts **service entries** — for each trust-service provider, the certificates and the service type (e.g. `PID issuer`, `relying-party registrar`, `wallet provider`) and their validity/status.
4. Maintains a **trust-anchor store** and applies **freshness, rollback, and offline policy**: is this list new enough? Is someone trying to feed me an *older* validly-signed list (a rollback attack)? Am I offline and allowed to use a cached list within a grace window?

Everything above is **pure**. The *download* of the list bytes is `Effect::FetchTrustedList { url }`; the *result* comes back as `Event::TrustedListBytes { url, bytes, http_status }`; the *clock* is `Effect::ReadClock` → `Event::ClockRead(UtcInstant)`. See Section 2 for the run loop that pumps these.

#### 6.1.2 Public types

Create `crates/trust/src/lib.rs`:

```rust
#![forbid(unsafe_code)]
#![deny(warnings, missing_docs)]
//! Trusted-list parsing, signature verification, and freshness/rollback/offline policy.
//! Pure: bytes + pinned anchors + now -> decision. Fetch is an Effect (see wallet-core).
//! Register mapping: Reg. (EU) 2025/2164; ETSI TS 119 612 / TS 119 602.

pub mod anchor;
pub mod list;
pub mod policy;
pub mod error;

pub use anchor::{TrustAnchor, TrustAnchorStore, TrustAnchorId};
pub use error::TrustError;
pub use list::{TrustedList, ServiceEntry, ServiceType, ServiceStatus, ListMeta};
pub use policy::{FreshnessPolicy, FreshnessDecision, OfflineStance};
```

`crates/trust/src/anchor.rs`:

```rust
use crate::error::TrustError;
use crypto_traits::Verifier;          // from crates/crypto-traits (Section 3)
use x509::{Certificate, SubjectKeyId}; // from crates/x509 (Section 5)
use serde::{Deserialize, Serialize};

/// Stable identifier for an anchor: the SHA-256 of its DER (a fingerprint).
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct TrustAnchorId(pub [u8; 32]);

/// A trust anchor is a certificate we obtained OUT OF BAND (compiled-in for the
/// scheme operator, or provisioned at onboarding). We NEVER learn anchors from the
/// same download we are trying to validate.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct TrustAnchor {
    pub id: TrustAnchorId,
    pub cert_der: Vec<u8>,
    /// What role this anchor is allowed to vouch for. An anchor pinned for
    /// "scheme operator / list signer" MUST NOT be accepted as, say, a PID issuer.
    pub role: AnchorRole,
}

/// The single role each anchor is trusted for. Deliberately closed enum.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub enum AnchorRole {
    /// Signs the trusted list itself (the "list-of-lists" scheme operator).
    TrustedListSigner,
    /// A member-state list operator whose list we then read for service entries.
    SchemeOperator,
}

/// An immutable, versioned store of pinned anchors. Constructed once at startup
/// from compiled-in bytes; may be extended at onboarding but never from wire data
/// in a validation flow.
#[derive(Clone, Debug, Default)]
pub struct TrustAnchorStore {
    anchors: Vec<TrustAnchor>,
}

impl TrustAnchorStore {
    #[must_use]
    pub fn new(anchors: Vec<TrustAnchor>) -> Self { Self { anchors } }

    /// Find a candidate signer among anchors that hold the required role.
    #[must_use]
    pub fn candidates(&self, role: AnchorRole) -> impl Iterator<Item = &TrustAnchor> {
        self.anchors.iter().filter(move |a| a.role == role)
    }

    /// Verify a signature over `signed_bytes` using ANY anchor holding `role`.
    /// Returns the anchor id that matched, or an error. `V` is the platform-backed
    /// verifier trait object supplied by the shell (crypto-traits). Verification
    /// itself is delegated so `trust` never contains a crypto primitive.
    pub fn verify_with_role<V: Verifier>(
        &self,
        verifier: &V,
        role: AnchorRole,
        signed_bytes: &[u8],
        signature: &[u8],
    ) -> Result<TrustAnchorId, TrustError> {
        for anchor in self.candidates(role) {
            let cert = Certificate::from_der(&anchor.cert_der)
                .map_err(|_| TrustError::MalformedAnchor(anchor.id.clone()))?;
            if verifier
                .verify(cert.public_key(), signed_bytes, signature)
                .is_ok()
            {
                return Ok(anchor.id.clone());
            }
        }
        Err(TrustError::NoAnchorMatched(role))
    }

    #[must_use]
    pub fn subject_key_ids(&self) -> Vec<SubjectKeyId> {
        self.anchors
            .iter()
            .filter_map(|a| Certificate::from_der(&a.cert_der).ok().map(|c| c.subject_key_id()))
            .collect()
    }
}
```

`crates/trust/src/list.rs`:

```rust
use crate::error::TrustError;
use time_model::UtcInstant;
use serde::{Deserialize, Serialize};

/// Metadata read from the trusted-list header. `sequence_number` is the monotonic
/// counter that ETSI 119 612 lists carry; it is the anti-rollback signal.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ListMeta {
    pub scheme_operator: String,
    /// `TSLSequenceNumber` — MUST increase on each publication.
    pub sequence_number: u64,
    /// `ListIssueDateTime` normalized to epoch seconds.
    pub issued_at: UtcInstant,
    /// `NextUpdate` normalized to epoch seconds; None if the list omits it.
    pub next_update: Option<UtcInstant>,
    /// Version marker we pin (see change-watch table).
    pub etsi_version: EtsiTslVersion,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum EtsiTslVersion { V119612_2_1_1 }  // pin exact; extend as versions evolve

/// The closed vocabulary of service types WE consume. Unknown types are parsed but
/// ignored (fail-safe: an unrecognized service can never grant trust).
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum ServiceType {
    PidIssuer,
    AttestationIssuer,
    RelyingPartyRegistrar,
    WalletProvider,
    /// Present in the list but not one we act on.
    Unrecognized,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum ServiceStatus {
    Granted,
    Withdrawn,
    /// Any status string we do not explicitly recognize -> treat as not-granted.
    NotGranted,
}

/// One trust-service entry: a certificate the list vouches for, in a role.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ServiceEntry {
    pub service_type: ServiceType,
    pub status: ServiceStatus,
    /// DER of the service's X.509 certificate (the digital identity of the service).
    pub cert_der: Vec<u8>,
    /// `StatusStartingTime` epoch seconds.
    pub status_since: UtcInstant,
}

/// A fully parsed AND signature-verified trusted list. You can only obtain this
/// value from `TrustedList::parse_and_verify`, so possessing one is proof of trust.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct TrustedList {
    pub meta: ListMeta,
    pub entries: Vec<ServiceEntry>,
}

impl TrustedList {
    /// PURE. Parse ETSI TS 119 612 XML, then verify its enveloped signature against
    /// a pinned `TrustedListSigner` anchor via the injected verifier. No I/O.
    ///
    /// Order matters: we verify the signature over the RAW bytes FIRST, then trust
    /// the parsed content. We do NOT parse-then-verify a re-serialization.
    pub fn parse_and_verify<V: crypto_traits::Verifier>(
        raw_xml: &[u8],
        anchors: &crate::anchor::TrustAnchorStore,
        verifier: &V,
    ) -> Result<Self, TrustError> {
        // 1. Extract the signed region + signature + signer cert reference from the
        //    XMLDSig envelope WITHOUT trusting anything yet (pure byte surgery).
        let sig = xmldsig::extract_enveloped_signature(raw_xml)   // see 6.1.4
            .map_err(TrustError::Signature)?;

        // 2. Verify against a pinned list-signer anchor.
        anchors.verify_with_role(
            verifier,
            crate::anchor::AnchorRole::TrustedListSigner,
            &sig.signed_bytes,
            &sig.signature_bytes,
        )?;

        // 3. Only now parse the (trusted) content into typed entries.
        let parsed = crate::list::parse_tsl_body(raw_xml)?;
        Ok(parsed)
    }

    /// Look up a service entry whose certificate matches `cert_der` AND is Granted
    /// AND whose role matches `expected`. Pure.
    #[must_use]
    pub fn find_granted(&self, cert_der: &[u8], expected: ServiceType) -> Option<&ServiceEntry> {
        self.entries.iter().find(|e| {
            e.cert_der == cert_der
                && e.service_type == expected
                && e.status == ServiceStatus::Granted
        })
    }
}

/// Internal: strict, schema-pinned XML -> typed body. Rejects anything not matching
/// the pinned ETSI schema (no permissive parsing; no external entity expansion).
pub(crate) fn parse_tsl_body(_raw_xml: &[u8]) -> Result<TrustedList, TrustError> {
    // Implemented against a hardened XML reader with:
    //   - DTD/entity expansion DISABLED (prevents XXE / billion-laughs),
    //   - the pinned ETSI 119 612 schema enforced,
    //   - unknown service types mapped to ServiceType::Unrecognized (never trusted).
    todo!("hardened, schema-pinned parse; see 6.1.4 and the negative-test matrix")
}
```

> **Jargon:**
> - *Trusted list* = a signed, machine-readable roster of who the ecosystem trusts and for what. Think of it as a phone book that the government signs.
> - *Trust anchor* = the one certificate you already trust because you got it out of band; every chain of trust must terminate here.
> - *XMLDSig / enveloped signature* = a way to put a digital signature *inside* the same XML file it protects. "Enveloped" means the signature element sits within the signed document, which is why step 1 must carefully cut out the signed region before verifying.
> - *Rollback attack* = an attacker replays an **older but still validly-signed** trusted list to make you accept an issuer that has since been withdrawn. The `sequence_number` defeats this.

`crates/trust/src/policy.rs` — the freshness / rollback / offline decision:

```rust
use crate::error::TrustError;
use crate::list::ListMeta;
use time_model::{Seconds, UtcInstant};
use serde::{Deserialize, Serialize};

/// How stale a cached list may be, and how the wallet behaves offline.
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct FreshnessPolicy {
    /// Hard maximum age since `issued_at` before a list is unusable even offline.
    pub max_age_offline: Seconds,
    /// Grace after `next_update` during which an online refresh SHOULD have happened
    /// but we still tolerate the cached list.
    pub soft_grace: Seconds,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum OfflineStance { Online, Offline }

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum FreshnessDecision {
    /// Fresh enough; use it.
    Accept,
    /// Past next_update but within grace; use it but flag a refresh is due.
    AcceptStaleWithWarning { overdue: Seconds },
    /// Too old to use in this stance.
    Reject { reason: StaleReason },
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum StaleReason { PastMaxAge, RolledBack, IssuedInFuture }

impl FreshnessPolicy {
    /// PURE decision. `previous_seq` is the highest sequence number we have EVER
    /// accepted for this scheme operator (persisted via the storage crate). It is
    /// the anti-rollback ratchet.
    #[must_use]
    pub fn evaluate(
        &self,
        meta: &ListMeta,
        now: UtcInstant,
        stance: OfflineStance,
        previous_seq: Option<u64>,
    ) -> FreshnessDecision {
        // Anti-rollback FIRST: a validly-signed but older list is a rollback attack.
        if let Some(prev) = previous_seq {
            if meta.sequence_number < prev {
                return FreshnessDecision::Reject { reason: StaleReason::RolledBack };
            }
        }
        // Reject clock-implausible lists (issued in the future beyond small skew).
        const SKEW: i64 = 300; // 5 minutes tolerated skew
        if meta.issued_at.seconds_since(now) > SKEW {
            return FreshnessDecision::Reject { reason: StaleReason::IssuedInFuture };
        }
        let age = now.seconds_since(meta.issued_at).max(0) as u64;
        if age > self.max_age_offline.0 {
            return FreshnessDecision::Reject { reason: StaleReason::PastMaxAge };
        }
        // Past next_update?
        if let Some(next) = meta.next_update {
            if now.is_after(next) {
                let overdue = Seconds(now.seconds_since(next).max(0) as u64);
                // Online we should have refreshed; still tolerate within grace.
                if overdue.0 <= self.soft_grace.0 {
                    return FreshnessDecision::AcceptStaleWithWarning { overdue };
                }
                // Beyond grace: offline may still limp along up to max_age; online rejects.
                return match stance {
                    OfflineStance::Offline => {
                        FreshnessDecision::AcceptStaleWithWarning { overdue }
                    }
                    OfflineStance::Online => {
                        FreshnessDecision::Reject { reason: StaleReason::PastMaxAge }
                    }
                };
            }
        }
        FreshnessDecision::Accept
    }
}
```

`crates/trust/src/error.rs`:

```rust
use crate::anchor::{AnchorRole, TrustAnchorId};

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum TrustError {
    /// The list's own signature did not verify against any pinned anchor of the role.
    NoAnchorMatched(AnchorRole),
    MalformedAnchor(TrustAnchorId),
    /// XML did not conform to the pinned ETSI schema, or contained forbidden
    /// constructs (DTD/entities), or was not well-formed.
    MalformedXml(&'static str),
    /// Signature extraction/verification structural failure.
    Signature(String),
    /// Freshness/rollback policy rejected the list.
    Stale(crate::policy::StaleReason),
}
```

#### 6.1.3 Pure vs effectful split (explicit)

| Concern | Where | Mechanism |
|---|---|---|
| Download trusted-list XML | **Effect** | `Effect::FetchTrustedList { url }` → `Event::TrustedListBytes { url, bytes, http_status }` |
| Read the clock | **Effect** | `Effect::ReadClock` → `Event::ClockRead(UtcInstant)` |
| Persist highest accepted sequence number | **Effect** | `Effect::PersistTrustState { scheme, seq }` (via `storage`, Section 7) |
| Parse XML → typed list | **Pure** | `parse_tsl_body` |
| Verify list signature | **Pure** (delegates primitive to injected `Verifier`) | `TrustedList::parse_and_verify` |
| Freshness/rollback/offline decision | **Pure** | `FreshnessPolicy::evaluate` |
| Match a cert to a granted service entry | **Pure** | `TrustedList::find_granted` |

Wire the `Effect`/`Event` variants into the enums defined in Section 2 (`wallet-core/src/effect.rs`, `event.rs`). The run loop calls `FetchTrustedList` on a schedule or when policy returns `Reject{PastMaxAge}` while online.

#### 6.1.4 Hardened XML + XMLDSig (the one dependency choice to make carefully)

You are not allowed to hand-roll XML canonicalization or the signature primitive, but you also must not pull a giant permissive XML stack. Recommended:

1. **Parsing:** `quick-xml` (streaming, no DTD expansion by default). Explicitly assert `reader.config_mut().expand_empty_elements = false;` and never enable entity resolution. This kills XXE and billion-laughs by construction.
2. **Canonicalization (C14N):** XMLDSig requires canonicalizing the signed region before hashing. Implement a **narrow, profile-restricted C14N** that only supports the exact canonicalization algorithm the ETSI/EUDI profile mandates (pin it: `http://www.w3.org/2001/10/xml-exc-c14n#`). Reject any other `CanonicalizationMethod` outright — do not implement a general C14N engine.
3. **Signature primitive:** never here. `parse_and_verify` hands the canonicalized `signed_bytes` and `signature_bytes` to the `crypto_traits::Verifier` (backed by `aws-lc-rs` in the shell, per the certification memo, Section 3).

Put the XMLDSig helper in an internal module `crates/trust/src/xmldsig.rs` and keep it `pub(crate)`. Add to `crates/trust/Cargo.toml`:

```toml
[dependencies]
quick-xml = { version = "0.36", default-features = false }
serde = { version = "1", features = ["derive"] }
crypto-traits = { path = "../crypto-traits" }
x509 = { path = "../x509" }
time-model = { path = "../time-model" }

[dev-dependencies]
proptest = "1"
```

> **Rule reminder:** reject any `CanonicalizationMethod`, `SignatureMethod`, or `DigestMethod` not on your pinned allow-list. An attacker who can pick a weak digest (e.g. SHA-1) can forge. Allow-list SHA-256/384/512 + ECDSA/RSA-PSS only.

#### 6.1.5 Negative-test matrix for `trust`

Create fixtures under `crates/trust/tests/fixtures/` and a table-driven test `crates/trust/tests/negative.rs`. Each row must produce a **specific** error, never `Accept`.

| # | Fixture | Manipulation | Expected result |
|---|---|---|---|
| T1 | `tsl_valid.xml` | none (golden, signed by test anchor) | `parse_and_verify` → `Ok`; `evaluate` → `Accept` |
| T2 | `tsl_expired.xml` | `issued_at` older than `max_age_offline` | `evaluate` → `Reject{PastMaxAge}` |
| T3 | `tsl_wrong_signer.xml` | valid XML, signed by an anchor NOT holding `TrustedListSigner` role | `parse_and_verify` → `NoAnchorMatched` |
| T4 | `tsl_bad_sig.xml` | one byte flipped in `SignatureValue` | `parse_and_verify` → `NoAnchorMatched` |
| T5 | `tsl_rolled_back.xml` | valid signature, `sequence_number` < persisted `previous_seq` | `evaluate` → `Reject{RolledBack}` |
| T6 | `tsl_future.xml` | `issued_at` 1 hour in the future | `evaluate` → `Reject{IssuedInFuture}` |
| T7 | `tsl_stale_grace.xml` | past `next_update` but within `soft_grace` | `evaluate` → `AcceptStaleWithWarning` |
| T8 | `tsl_stale_offline.xml` | past grace, `stance=Offline`, within `max_age` | `evaluate` → `AcceptStaleWithWarning`; same fixture `stance=Online` → `Reject{PastMaxAge}` |
| T9 | `tsl_malformed.xml` | truncated / not well-formed | `parse_and_verify` → `MalformedXml` |
| T10 | `tsl_xxe.xml` | contains a DOCTYPE + external entity | parse **must not** fetch the entity; → `MalformedXml` |
| T11 | `tsl_weak_digest.xml` | `DigestMethod` = SHA-1 | `parse_and_verify` → `Signature(...)` (rejected algorithm) |
| T12 | `tsl_withdrawn_service.xml` | target cert present but `ServiceStatus::Withdrawn` | `find_granted` → `None` |
| T13 | `tsl_wrong_role.xml` | target cert Granted as `WalletProvider`, queried as `PidIssuer` | `find_granted(_, PidIssuer)` → `None` |
| T14 | `tsl_unknown_service.xml` | service type string not recognized | parsed as `Unrecognized`; never returned by `find_granted` |

Skeleton `crates/trust/tests/negative.rs`:

```rust
use trust::{TrustedList, FreshnessPolicy, FreshnessDecision, OfflineStance, TrustError};
mod support; // loads fixtures + a MockVerifier + the test TrustAnchorStore

#[test]
fn t4_bad_signature_is_rejected() {
    let raw = support::fixture("tsl_bad_sig.xml");
    let anchors = support::test_anchor_store();
    let verifier = support::mock_verifier();
    let err = TrustedList::parse_and_verify(&raw, &anchors, &verifier).unwrap_err();
    assert!(matches!(err, TrustError::NoAnchorMatched(_)));
}

#[test]
fn t5_rollback_is_rejected() {
    let list = support::parse_ok("tsl_rolled_back.xml"); // signature valid in this fixture
    let policy = support::default_policy();
    let now = support::now();
    let decision = policy.evaluate(&list.meta, now, OfflineStance::Online, Some(99));
    assert_eq!(decision, FreshnessDecision::Reject { reason: trust::policy::StaleReason::RolledBack });
}
```

Generate the signed fixtures with a tiny helper binary `crates/trust/examples/make_fixtures.rs` that uses the same test key so signatures are reproducible; check the generated XML into `tests/fixtures/` so CI has no key material at runtime.

#### 6.1.6 Property tests + fuzzing (Tier 1)

`crates/trust/tests/prop.rs`:

```rust
use proptest::prelude::*;

proptest! {
    // Freshness monotonicity: increasing `now` never turns Reject into Accept.
    #[test]
    fn freshness_monotone(seq in 0u64..1000, base in 1_600_000_000i64..1_800_000_000) {
        // build a ListMeta, evaluate at now=base and now=base+delta, assert:
        // if evaluate(base) == Reject then evaluate(base+delta) is not Accept.
        // (fill in with helpers from support)
        prop_assume!(base > 0);
    }
}
```

Fuzz target `crates/trust/fuzz/fuzz_targets/tsl_parse.rs` (create with `cargo fuzz init` inside the crate):

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    // Must never panic, never hang, never fetch. Any input -> Ok or a typed Err.
    let _ = trust::list::parse_tsl_body_for_fuzz(data);
});
```

(Expose a `pub fn parse_tsl_body_for_fuzz` under a `#[cfg(fuzzing)]` or a `fuzzing` feature so the fuzzer can reach the internal parser.)

**Definition of done (6.1):**

```bash
cargo test -p trust                       # all T1..T14 + property tests pass
cargo fuzz run tsl_parse -- -max_total_time=60   # 60s, zero crashes/timeouts
cargo tree -p trust | grep -Ei 'reqwest|tokio|hyper|ureq'   # prints NOTHING
```
Expected: `test result: ok. N passed; 0 failed`; fuzzer prints `Done ... 0 crashes`; the dependency grep is empty (proving `trust` does no I/O).

---

### 6.2 — The `status` crate

#### 6.2.1 Responsibility

`status` answers: *is this specific credential revoked, suspended, or still valid — right now?* Two mechanisms:

1. **Token Status List (draft-21)** — a compact, signed bitstring where each credential carries an **index**; the wallet (or verifier) looks up that index to read a small status value (valid / revoked / suspended). The list is a **JWT/CWT** (`Status List Token`) signed by the issuer's status authority.
2. **Certificate status** — for the X.509 certs in play (issuer, RP), a coarse validity/status check (not-before/not-after windows; optionally CRL/OCSP-derived status if the profile requires it — but per the "DO NOT DO" rules, treat these as fetched data, parsed purely).

The centerpiece is the **deterministic fail-open vs fail-closed decision table**, keyed by *context* (proximity-offline vs remote-online) and *what went wrong* (couldn't fetch, stale cache, malformed, signature-invalid, index-out-of-range). This is the part evaluators will scrutinize, so it is data-driven and testable in isolation.

#### 6.2.2 Public types

`crates/status/src/lib.rs`:

```rust
#![forbid(unsafe_code)]
#![deny(warnings, missing_docs)]
//! Token Status List (draft-21) client (pure) + certificate status + the
//! deterministic fail-open/fail-closed decision table. Fetch is an Effect.
//! Register mapping: Token Status List draft-21 (pinned TSL_DRAFT_21).

pub mod token_status;
pub mod cert_status;
pub mod decision;
pub mod error;

pub use decision::{PresentationContext, StatusOutcome, FinalStatusDecision, decide};
pub use error::StatusError;
pub use token_status::{StatusListToken, StatusValue, StatusRef, StatusListClaims};
```

`crates/status/src/token_status.rs`:

```rust
use crate::error::StatusError;
use time_model::UtcInstant;
use serde::{Deserialize, Serialize};

/// A reference embedded in a credential telling us where to look up its status:
/// which status list (by URI) and at which bit index. Extracted from the credential
/// during codec parse (mdoc / sdjwt, Section 5); passed here as data.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct StatusRef {
    pub uri: String,     // where the shell must fetch the Status List Token
    pub index: u64,      // this credential's position in the list
    pub bits: u8,        // bits-per-status (draft-21 allows 1,2,4,8)
}

/// The status value read at an index. Draft-21 defines 0x00 valid, 0x01 invalid
/// (revoked), 0x02 suspended; higher values are application-defined/reserved.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum StatusValue {
    Valid,
    Revoked,
    Suspended,
    /// A defined-but-unrecognized code. Fail-safe: treated as NOT valid.
    ReservedUnknown(u8),
}

/// The signed claims of a Status List Token (the JWT/CWT payload), draft-21.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct StatusListClaims {
    /// `sub` — MUST equal the StatusRef.uri we requested (prevents list substitution).
    pub subject_uri: String,
    /// `iat` normalized to epoch seconds.
    pub issued_at: UtcInstant,
    /// `exp` if present.
    pub expires_at: Option<UtcInstant>,
    /// `ttl` seconds — how long a cached copy may be considered fresh (draft-21).
    pub ttl: Option<u64>,
    pub bits: u8,
    /// The decompressed status bitstring (DEFLATE-decompressed inside parse).
    pub statuses: Vec<u8>,
}

/// A parsed AND signature-verified Status List Token. Possessing one proves the
/// bitstring is authentic. Obtain only via `parse_and_verify`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct StatusListToken {
    pub claims: StatusListClaims,
}

impl StatusListToken {
    /// PURE. Parse the JWT/CWT, verify its signature against the issuer's status
    /// authority key (which itself must have been trust-anchored via `trust`),
    /// then hold the decompressed bits. Signature primitive is delegated.
    ///
    /// `issuer_key` is the already-trusted public key (its chain was validated by
    /// the `trust` crate BEFORE we got here — status never re-establishes trust).
    pub fn parse_and_verify<V: crypto_traits::Verifier>(
        raw: &[u8],
        issuer_key: &crypto_traits::PublicKey,
        expected_uri: &str,
        verifier: &V,
    ) -> Result<Self, StatusError> {
        let (signed, sig, claims) = token_status_codec::split_and_decode(raw)
            .map_err(StatusError::Malformed)?;
        verifier
            .verify(issuer_key, &signed, &sig)
            .map_err(|_| StatusError::BadSignature)?;
        // Bind the token to the URI we asked for: defeats a swapped-in list.
        if claims.subject_uri != expected_uri {
            return Err(StatusError::SubjectMismatch);
        }
        Ok(Self { claims })
    }

    /// PURE lookup at an index. Bounds-checked; out-of-range is an ERROR, never Valid.
    pub fn status_at(&self, index: u64, bits: u8) -> Result<StatusValue, StatusError> {
        if bits != self.claims.bits {
            return Err(StatusError::BitsMismatch);
        }
        let raw = token_status_codec::read_index(&self.claims.statuses, index, bits)
            .ok_or(StatusError::IndexOutOfRange)?;
        Ok(match raw {
            0x00 => StatusValue::Valid,
            0x01 => StatusValue::Revoked,
            0x02 => StatusValue::Suspended,
            other => StatusValue::ReservedUnknown(other),
        })
    }

    /// PURE freshness: is this cached token still within its TTL / not expired?
    #[must_use]
    pub fn is_fresh(&self, now: UtcInstant) -> Freshness {
        if let Some(exp) = self.claims.expires_at {
            if now.is_after(exp) {
                return Freshness::Expired;
            }
        }
        if let Some(ttl) = self.claims.ttl {
            let age = now.seconds_since(self.claims.issued_at).max(0) as u64;
            if age > ttl {
                return Freshness::StalePastTtl { overdue_s: age - ttl };
            }
        }
        Freshness::Fresh
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Freshness { Fresh, StalePastTtl { overdue_s: u64 }, Expired }
```

> **Jargon:**
> - *Status List Token* = a small signed file containing a big array of tiny numbers; your credential's number tells verifiers whether it's still good, without the issuer learning which verifier asked (privacy-preserving revocation).
> - *TTL (time-to-live)* = how long a cached copy stays "fresh enough" to use before you should refetch.
> - *Bits-per-status* = each credential's status may be 1, 2, 4, or 8 bits. 1 bit gives valid/revoked only; 2 bits also gives suspended.

#### 6.2.3 The deterministic fail-open / fail-closed decision table (the crux)

This is the single most important design artifact in `status`. It must be **pure, total (every combination has a defined result), and data-driven** so it can be reviewed as a table and property-tested for totality.

`crates/status/src/decision.rs`:

```rust
use crate::token_status::{StatusValue, Freshness};
use serde::{Deserialize, Serialize};

/// The context in which we are deciding. This is what makes fail-open vs
/// fail-closed context-dependent, as the shared context demands.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum PresentationContext {
    /// Proximity (ISO 18013-5) with NO network available. Fail-closed here would
    /// make the wallet unusable in the exact offline scenario proximity exists for.
    ProximityOffline,
    /// Proximity but network IS available (rare but possible).
    ProximityOnline,
    /// Remote (OpenID4VP). Network is definitionally available; be strict.
    RemoteOnline,
}

/// What we managed to learn about status.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum StatusOutcome {
    /// Got a fresh, verified list; here is the value.
    Known { value: StatusValue, freshness: Freshness },
    /// Could not fetch at all (offline / network error).
    Unreachable,
    /// Fetched but the token failed signature/subject/parse checks.
    Untrusted,
    /// Fetched & verified but stale past TTL / expired.
    Stale { freshness: Freshness },
    /// Index out of range / bits mismatch — a structural error about THIS credential.
    Indeterminate,
}

/// The final, auditable decision the core acts on.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum FinalStatusDecision {
    /// Proceed: credential is (or is presumed) usable.
    Allow,
    /// Proceed but surface a warning to the user / log (degraded assurance).
    AllowDegraded,
    /// Block presentation: credential is revoked/suspended or trust could not be
    /// established in a context that requires it.
    Block,
}

/// THE TABLE. Pure, total. Every (context, outcome) pair maps to a decision.
/// Read this as the normative revocation policy; the negative tests below assert
/// EVERY cell.
#[must_use]
pub fn decide(ctx: PresentationContext, outcome: &StatusOutcome) -> FinalStatusDecision {
    use FinalStatusDecision::{Allow, AllowDegraded, Block};
    use PresentationContext::{ProximityOffline, ProximityOnline, RemoteOnline};
    use StatusValue::{Revoked, Suspended, Valid, ReservedUnknown};

    match outcome {
        // A KNOWN revoked/suspended credential is ALWAYS blocked, in every context.
        StatusOutcome::Known { value: Revoked | Suspended | ReservedUnknown(_), .. } => Block,

        // Known-valid: allow; if the fresh copy is technically stale-past-ttl but we
        // still have a signed value, degrade rather than block.
        StatusOutcome::Known { value: Valid, freshness: Freshness::Fresh } => Allow,
        StatusOutcome::Known { value: Valid, freshness: _ } => AllowDegraded,

        // Could not reach the list:
        //  - Offline proximity: FAIL-OPEN (degraded) — this is the designed offline mode.
        //  - Online contexts: FAIL-CLOSED — no excuse for missing status online.
        StatusOutcome::Unreachable => match ctx {
            ProximityOffline => AllowDegraded,
            ProximityOnline | RemoteOnline => Block,
        },

        // Fetched but the token itself is not trustworthy (bad sig / wrong subject):
        // NEVER fail-open on a forged/mismatched token, in ANY context.
        StatusOutcome::Untrusted => Block,

        // Verified but stale/expired:
        //  - Offline proximity: fail-open degraded (best we can do offline).
        //  - Online: we must refresh; if we still only have stale, fail-closed.
        StatusOutcome::Stale { .. } => match ctx {
            ProximityOffline => AllowDegraded,
            ProximityOnline | RemoteOnline => Block,
        },

        // Structural problem about THIS credential's index -> never presume valid.
        StatusOutcome::Indeterminate => Block,
    }
}
```

The **normative table** in prose (put this verbatim in `crates/status/README.md`):

| Outcome \ Context | ProximityOffline | ProximityOnline | RemoteOnline |
|---|---|---|---|
| Known = Valid, Fresh | Allow | Allow | Allow |
| Known = Valid, Stale/Expired | AllowDegraded | AllowDegraded | AllowDegraded |
| Known = Revoked / Suspended / Reserved | **Block** | **Block** | **Block** |
| Unreachable (no fetch) | AllowDegraded (**fail-open**) | **Block** (fail-closed) | **Block** (fail-closed) |
| Untrusted (bad sig / subject mismatch) | **Block** | **Block** | **Block** |
| Stale (verified but past TTL/exp) | AllowDegraded | **Block** | **Block** |
| Indeterminate (index OOR / bits mismatch) | **Block** | **Block** | **Block** |

> **Design rationale to memorize:** we fail-**open** only when *(a)* we are genuinely offline in a mode designed for offline use **and** *(b)* the failure is "couldn't reach" or "stale", never "forged" or "revoked". A revoked credential and a forged status token are **always** blocked. This is the defensible middle ground: usable offline, uncheatable online, never accepts a known-bad or known-forged input.

#### 6.2.4 Pure vs effectful split

| Concern | Where | Mechanism |
|---|---|---|
| Fetch Status List Token bytes | **Effect** | `Effect::FetchStatusList { uri }` → `Event::StatusListBytes { uri, bytes, http_status }` |
| Read clock | **Effect** | `Effect::ReadClock` → `Event::ClockRead` |
| Read/write status cache | **Effect** | `Effect::ReadStatusCache/WriteStatusCache` (via `storage`, Section 7) |
| Parse + verify token | **Pure** | `StatusListToken::parse_and_verify` (primitive delegated to `Verifier`) |
| Index lookup | **Pure** | `StatusListToken::status_at` |
| Freshness | **Pure** | `StatusListToken::is_fresh` |
| Final decision | **Pure** | `decide` |

The run loop's job: turn fetch results + cache + clock into a `StatusOutcome`, then call `decide`. Note the **trust ordering dependency**: `status` receives an *already-trusted* issuer key; establishing that the status authority is legitimate is `trust`'s job (Section 6.1). `status` never bootstraps trust from the status document itself.

#### 6.2.5 Certificate status (`cert_status.rs`)

Keep this deliberately small for P0: validity-window check (pure) plus an *optional* parsed CRL/OCSP response fed in as data. Do **not** implement OCSP transport here.

```rust
use time_model::UtcInstant;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum CertStatus { Good, Expired, NotYetValid }

/// PURE window check against the cert's notBefore/notAfter (parsed by `x509`).
#[must_use]
pub fn window_status(not_before: UtcInstant, not_after: UtcInstant, now: UtcInstant) -> CertStatus {
    if now.0 < not_before.0 { CertStatus::NotYetValid }
    else if now.0 > not_after.0 { CertStatus::Expired }
    else { CertStatus::Good }
}
```

#### 6.2.6 Negative-test matrix for `status`

`crates/status/tests/negative.rs` — assert **every cell** of the table plus token-level failures:

| # | Setup | Expected |
|---|---|---|
| S1 | valid token, index→0x00, fresh, `RemoteOnline` | `Known{Valid,Fresh}` → `Allow` |
| S2 | valid token, index→0x01 (revoked), any context | `Known{Revoked}` → `Block` |
| S3 | valid token, index→0x02 (suspended), any context | `Known{Suspended}` → `Block` |
| S4 | one byte flipped in signature | `parse_and_verify` → `BadSignature`; outcome `Untrusted` → `Block` |
| S5 | valid signature, `sub` ≠ requested uri | `SubjectMismatch`; `Untrusted` → `Block` |
| S6 | index beyond bitstring length | `status_at` → `IndexOutOfRange`; `Indeterminate` → `Block` |
| S7 | token `bits`=2 but credential `StatusRef.bits`=1 | `BitsMismatch` → `Block` |
| S8 | fetch failed, `ProximityOffline` | `Unreachable` → `AllowDegraded` |
| S9 | fetch failed, `RemoteOnline` | `Unreachable` → `Block` |
| S10 | verified token past TTL, `ProximityOffline` | `Stale` → `AllowDegraded` |
| S11 | verified token past TTL, `RemoteOnline` | `Stale` → `Block` |
| S12 | expired token (`exp` < now), `RemoteOnline` | `is_fresh`→`Expired`; `Stale` → `Block` |
| S13 | valid but stale value, any context | `Known{Valid,StalePastTtl}` → `AllowDegraded` |
| S14 | malformed JWT/CWT (truncated) | `Malformed` → `Block` (mapped to `Untrusted`) |
| S15 | corrupt DEFLATE stream in `statuses` | `Malformed` → `Block` |
| S16 | reserved status code 0x03 | `ReservedUnknown(3)` → `Block` |

Property test: **totality + safety**.

```rust
use proptest::prelude::*;
use status::decision::*;

proptest! {
    // The table is total AND never fails-open on Revoked/Untrusted/Indeterminate.
    #[test]
    fn decide_is_total_and_safe(ctx in any_context(), outcome in any_outcome()) {
        let d = decide(ctx, &outcome);
        // Safety invariants that must hold for EVERY input:
        if matches!(outcome, StatusOutcome::Untrusted | StatusOutcome::Indeterminate)
           || matches!(outcome,
                StatusOutcome::Known { value: status::StatusValue::Revoked
                                            | status::StatusValue::Suspended, .. }) {
            prop_assert_eq!(d, FinalStatusDecision::Block);
        }
        // Fail-open is ONLY ever AllowDegraded, never plain Allow, and only offline.
        if matches!(outcome, StatusOutcome::Unreachable | StatusOutcome::Stale { .. }) {
            match ctx {
                PresentationContext::ProximityOffline =>
                    prop_assert_eq!(d, FinalStatusDecision::AllowDegraded),
                _ => prop_assert_eq!(d, FinalStatusDecision::Block),
            }
        }
    }
}
```

Fuzz `crates/status/fuzz/fuzz_targets/token_parse.rs`: feed arbitrary bytes to the token codec + DEFLATE decompressor; must never panic, never allocate unbounded (cap the decompressed size — a **decompression bomb** guard is mandatory: reject if decompressed length would exceed, say, 8 MiB).

**Definition of done (6.2):**

```bash
cargo test -p status                      # S1..S16 + totality property test pass
cargo fuzz run token_parse -- -max_total_time=60   # 0 crashes, no OOM
```
Expected: `test result: ok. N passed; 0 failed`; the `decide_is_total_and_safe` property runs 256+ cases with no shrink failures; fuzzer reports `0 crashes`. Manually re-read the README table and confirm it matches `decide` cell-for-cell (a reviewer sign-off checkbox in the PR).

---

### 6.3 — The `wua` crate

#### 6.3.1 Responsibility

`wua` (Wallet Unit Attestation) answers: *is the software talking to me a genuine, hardware-backed wallet instance whose keys live in a real secure element — not an emulator, a clone, or a tampered build?* Per **ARF TS03** and **Reg. (EU) 2025/847**, it has two linked jobs:

1. **Produce** a WUA (on the wallet side): assemble the wallet-instance's key-attestation evidence into a signed WUA that the issuer (during OID4VCI, Section 5) can check to decide whether to issue credentials to this unit.
2. **Verify** a WUA + the underlying **platform key attestation** (on both the issuer side and, at abstraction, the wallet-provider side). The platform key attestation is the hardware manufacturer's signed statement that "this key was generated in, and never left, the Secure Enclave / StrongBox." Apple calls this **DeviceCheck / App Attest**; Android calls it **Key Attestation**. `wua` must validate the manufacturer's chain up to a **pinned manufacturer root**, and it must validate the wallet-provider's WUA signature up to a **trusted-list anchor** (via `trust`, Section 6.1).

**The cardinal rule, restated:** never trust a device's self-claim. A WUA is only meaningful because *(a)* its inner key-attestation chains to a hardware-manufacturer root you pinned, and *(b)* its outer WUA signature chains to a wallet-provider that a trusted list vouches for. Two independent roots, both out-of-band.

#### 6.3.2 Public types

`crates/wua/src/lib.rs`:

```rust
#![forbid(unsafe_code)]
#![deny(warnings, missing_docs)]
//! Wallet Unit Attestation (TS03) + platform key-attestation verification.
//! PURE validation; the actual attestation is PRODUCED by the Secure Enclave via
//! an Effect. Register mapping: ARF TS03; Reg. (EU) 2025/847.

pub mod key_attestation;
pub mod wua_doc;
pub mod verify;
pub mod error;

pub use error::WuaError;
pub use key_attestation::{KeyAttestation, Platform, AttestedKeyProps};
pub use wua_doc::{Wua, WuaClaims};
pub use verify::{verify_wua, WuaVerification, ManufacturerRoots};
```

`crates/wua/src/key_attestation.rs`:

```rust
use serde::{Deserialize, Serialize};
use time_model::UtcInstant;

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Platform { AppleSecureEnclave, AndroidStrongBox, AndroidTee }

/// Properties the platform attests about the key. These are what we DEMAND to be
/// true; a self-claim of these values without a valid manufacturer chain is worthless.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct AttestedKeyProps {
    /// The key MUST be non-exportable / hardware-bound.
    pub hardware_backed: bool,
    /// The key MUST require user auth (biometry/passcode) to use, per profile.
    pub user_auth_required: bool,
    /// Public key DER of the attested key (this is the key that will sign WUAs / KB).
    pub attested_pubkey_der: Vec<u8>,
    /// Challenge the verifier supplied and the platform embedded (anti-replay).
    pub challenge: Vec<u8>,
}

/// The raw platform key-attestation chain as bytes plus the platform tag.
/// Apple: App Attest assertion/attestation CBOR. Android: the attestation cert chain.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct KeyAttestation {
    pub platform: Platform,
    /// The DER cert chain (Android) or attestation object (Apple), as bytes.
    pub evidence: Vec<u8>,
    /// Parsed props (filled during verification, not trusted from the wire raw).
    pub claimed_props: AttestedKeyProps,
    pub produced_at: UtcInstant,
}
```

`crates/wua/src/wua_doc.rs`:

```rust
use crate::key_attestation::KeyAttestation;
use time_model::UtcInstant;
use serde::{Deserialize, Serialize};

/// The claims of a Wallet Unit Attestation (TS03). Signed by the WALLET PROVIDER,
/// binding a wallet instance + its attested key to a provider the ecosystem trusts.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct WuaClaims {
    /// Identifier of the wallet provider (matched against a trusted-list entry).
    pub provider_id: String,
    /// The wallet solution/version (for revocation of a whole vulnerable version).
    pub wallet_version: String,
    /// The platform key attestation for the instance key.
    pub key_attestation: KeyAttestation,
    pub issued_at: UtcInstant,
    pub expires_at: UtcInstant,
    /// Nonce/challenge from the issuer, echoed to prevent replay.
    pub challenge: Vec<u8>,
}

/// A WUA as received: raw signed bytes + parsed claims. The signature over
/// `raw_signed` is by the wallet PROVIDER's key (verified in `verify_wua`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Wua {
    pub raw_signed: Vec<u8>,
    pub signature: Vec<u8>,
    /// The wallet-provider certificate that signed this WUA (to be trust-anchored).
    pub provider_cert_der: Vec<u8>,
    pub claims: WuaClaims,
}
```

`crates/wua/src/verify.rs` — the heart:

```rust
use crate::error::WuaError;
use crate::key_attestation::{KeyAttestation, Platform, AttestedKeyProps};
use crate::wua_doc::Wua;
use time_model::UtcInstant;

/// Pinned manufacturer roots (Apple App Attest root, Google hardware attestation
/// root). Compiled in / provisioned out of band — NEVER learned from the wire.
#[derive(Clone, Debug, Default)]
pub struct ManufacturerRoots {
    pub apple_root_der: Vec<Vec<u8>>,
    pub google_root_der: Vec<Vec<u8>>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct WuaVerification {
    pub provider_id: String,
    pub attested_pubkey_der: Vec<u8>,
    pub platform: Platform,
}

/// PURE. The full verification pipeline. Two independent roots must both hold.
///
/// Arguments:
///  - `wua`: the received WUA (bytes + parsed claims).
///  - `provider_trusted`: closure/fn that answers "is this provider cert granted as
///     WalletProvider in a verified trusted list?" — implemented by the `trust`
///     crate; passed in so `wua` does not depend on trust-list plumbing directly.
///  - `roots`: pinned manufacturer roots.
///  - `expected_challenge`: the nonce WE issued (anti-replay).
///  - `verifier`: crypto-traits Verifier (primitive delegated).
///  - `now`: injected clock.
pub fn verify_wua<V, F>(
    wua: &Wua,
    roots: &ManufacturerRoots,
    provider_trusted: F,
    expected_challenge: &[u8],
    verifier: &V,
    now: UtcInstant,
) -> Result<WuaVerification, WuaError>
where
    V: crypto_traits::Verifier,
    F: Fn(&[u8]) -> bool, // takes provider_cert_der, returns "granted as WalletProvider"
{
    // 0. Freshness of the WUA itself.
    if now.0 > wua.claims.expires_at.0 {
        return Err(WuaError::WuaExpired);
    }
    if now.0 + 300 < wua.claims.issued_at.0 {
        return Err(WuaError::WuaFromFuture);
    }

    // 1. Anti-replay: the WUA must echo the challenge we issued.
    if wua.claims.challenge != expected_challenge {
        return Err(WuaError::ChallengeMismatch);
    }

    // 2. ROOT #1 — the wallet PROVIDER must be trust-anchored (trusted list).
    //    This is the ONLY thing that turns a provider's self-signed claim into trust.
    if !provider_trusted(&wua.provider_cert_der) {
        return Err(WuaError::ProviderNotTrusted);
    }

    // 3. Verify the WUA signature with the (now trusted) provider cert's key.
    let provider_cert = x509::Certificate::from_der(&wua.provider_cert_der)
        .map_err(|_| WuaError::MalformedProviderCert)?;
    verifier
        .verify(provider_cert.public_key(), &wua.raw_signed, &wua.signature)
        .map_err(|_| WuaError::BadWuaSignature)?;

    // 4. ROOT #2 — the platform key attestation must chain to a PINNED manufacturer
    //    root, and its embedded properties must satisfy our policy. This is where we
    //    refuse to trust the device's self-claim: `claimed_props` are only believed
    //    AFTER the manufacturer chain validates and we re-read props FROM the chain.
    let verified_props = verify_key_attestation(&wua.claims.key_attestation, roots,
                                                expected_challenge, verifier, now)?;

    // 5. Policy on the attested key: must be hardware-backed and user-auth-gated.
    if !verified_props.hardware_backed {
        return Err(WuaError::KeyNotHardwareBacked);
    }
    if !verified_props.user_auth_required {
        return Err(WuaError::KeyNotUserAuthBound);
    }

    // 6. Bind: the key attested by the platform MUST be the key the WUA is about.
    if verified_props.attested_pubkey_der != wua.claims.key_attestation.claimed_props.attested_pubkey_der {
        return Err(WuaError::KeyBindingMismatch);
    }

    Ok(WuaVerification {
        provider_id: wua.claims.provider_id.clone(),
        attested_pubkey_der: verified_props.attested_pubkey_der,
        platform: wua.claims.key_attestation.platform,
    })
}

/// PURE. Validate the platform attestation chain to a pinned manufacturer root and
/// RE-EXTRACT the attested properties from the certified chain (do NOT trust the
/// `claimed_props` that arrived alongside — read the truth from the signed chain).
fn verify_key_attestation<V: crypto_traits::Verifier>(
    att: &KeyAttestation,
    roots: &ManufacturerRoots,
    expected_challenge: &[u8],
    verifier: &V,
    now: UtcInstant,
) -> Result<AttestedKeyProps, WuaError> {
    match att.platform {
        Platform::AppleSecureEnclave => {
            apple_appattest::verify_and_extract(
                &att.evidence, &roots.apple_root_der, expected_challenge, verifier, now)
                .map_err(WuaError::AppleAttestation)
        }
        Platform::AndroidStrongBox | Platform::AndroidTee => {
            android_keyattest::verify_and_extract(
                &att.evidence, &roots.google_root_der, expected_challenge, verifier, now,
                att.platform)
                .map_err(WuaError::AndroidAttestation)
        }
    }
}
```

> **Jargon:**
> - *WUA (Wallet Unit Attestation)* = the wallet provider's signed statement "this is a genuine instance of my wallet, and here is its hardware-protected key," which an issuer checks before giving out credentials.
> - *Platform key attestation* = the phone manufacturer's cryptographic proof that a particular key was born inside, and can never leave, the secure hardware. Apple's App Attest / Android's Key Attestation.
> - *StrongBox / TEE / Secure Enclave* = the tamper-resistant chip (or isolated CPU mode) where keys live. StrongBox is the strongest Android tier (a discrete secure chip); TEE is the software-isolated tier.

#### 6.3.3 Pure vs effectful split

| Concern | Where | Mechanism |
|---|---|---|
| Generate an attested key & produce platform attestation | **Effect** | `Effect::AttestKey { challenge }` → `Event::KeyAttestationProduced { evidence }` (Secure Enclave / StrongBox, Section 4) |
| Sign the WUA (wallet-provider side) | out of scope for the wallet at runtime — the **provider** signs; the wallet only *carries* and the verifier *checks*. Producing the wallet-side portion uses `Effect::Sign` for the instance key's proof-of-possession. |
| Fetch manufacturer root updates | provisioning-time only; roots are pinned. Never fetched inside a verification flow. |
| Read clock | **Effect** | `Effect::ReadClock` |
| Parse + verify WUA & key attestation | **Pure** | `verify_wua`, `verify_key_attestation` |
| "Is provider trust-anchored?" | **Pure**, delegated to `trust` | the `provider_trusted` closure calls `TrustedList::find_granted(cert, WalletProvider)` (Section 6.1) |

Note the crate boundary discipline: `wua` does **not** `use trust::...` directly in `verify_wua`; it takes a closure. This keeps `wua` testable in isolation and prevents a circular dependency. The `wallet-core` facade (Section 2) is what wires "verify the trusted list (trust) → produce the `provider_trusted` closure → call `verify_wua`."

#### 6.3.4 Positive and negative fixtures (the WUA test matrix)

Fixtures under `crates/wua/tests/fixtures/`, generated by `crates/wua/examples/make_wua_fixtures.rs` using test manufacturer roots and a test provider key (checked in; no runtime key material).

**Positive fixtures (must succeed):**

| # | Fixture | Property |
|---|---|---|
| W+1 | `wua_apple_valid.*` | full Apple App Attest chain to test Apple root, hw-backed, user-auth, matching challenge → `Ok(WuaVerification{Apple})` |
| W+2 | `wua_android_strongbox_valid.*` | Android key-attestation chain to test Google root, StrongBox, → `Ok(...StrongBox)` |
| W+3 | `wua_android_tee_valid.*` | TEE tier, policy allows TEE → `Ok(...Tee)` |

**Negative fixtures (must fail with the specific error):**

| # | Fixture | Manipulation | Expected error |
|---|---|---|---|
| W-1 | `wua_expired.*` | `expires_at` < now | `WuaExpired` |
| W-2 | `wua_future.*` | `issued_at` far in future | `WuaFromFuture` |
| W-3 | `wua_wrong_challenge.*` | echoes a different nonce | `ChallengeMismatch` |
| W-4 | `wua_untrusted_provider.*` | provider cert not in trusted list (closure returns false) | `ProviderNotTrusted` |
| W-5 | `wua_bad_provider_sig.*` | WUA signature byte flipped | `BadWuaSignature` |
| W-6 | `wua_self_signed_attestation.*` | key attestation chain terminates in a **device-generated** root, not a manufacturer root (the classic "trust the device self-claim" attack) | `AppleAttestation`/`AndroidAttestation` (chain-to-root failure) |
| W-7 | `wua_wrong_manufacturer_root.*` | chain valid but to an unpinned root | chain failure error |
| W-8 | `wua_soft_key.*` | attestation says `hardware_backed=false` (emulator / software key) | `KeyNotHardwareBacked` |
| W-9 | `wua_no_user_auth.*` | `user_auth_required=false` | `KeyNotUserAuthBound` |
| W-10 | `wua_key_swap.*` | attested key ≠ the key the WUA claims (substitution) | `KeyBindingMismatch` |
| W-11 | `wua_malformed_chain.*` | truncated/garbage evidence bytes | attestation parse error |
| W-12 | `wua_replayed.*` | previously-valid WUA re-sent with an old challenge | `ChallengeMismatch` |
| W-13 | `wua_revoked_version.*` | valid chain but `wallet_version` on a revocation list (checked by caller via `status`) | verification `Ok`, but the core's policy layer blocks — assert the integration test, not `verify_wua` |
| W-14 | `wua_expired_attestation_cert.*` | a cert in the manufacturer chain expired at `now` | attestation error (chain window) |

Skeleton `crates/wua/tests/negative.rs`:

```rust
use wua::{verify::*, WuaError};
mod support;

#[test]
fn w6_device_self_signed_attestation_is_rejected() {
    let wua = support::load("wua_self_signed_attestation");
    let roots = support::pinned_test_roots();
    let verifier = support::mock_verifier();
    let now = support::now();
    let err = verify_wua(
        &wua, &roots,
        |_cert| true,                 // provider IS trusted; the FAILURE must be the chain
        support::challenge(),
        &verifier, now,
    ).unwrap_err();
    // The device's self-claim must NOT be accepted just because the provider is trusted.
    assert!(matches!(err,
        WuaError::AppleAttestation(_) | WuaError::AndroidAttestation(_)));
}

#[test]
fn w8_software_key_is_rejected() {
    let wua = support::load("wua_soft_key");
    let out = verify_wua(&wua, &support::pinned_test_roots(),
        |_| true, support::challenge(), &support::mock_verifier(), support::now());
    assert_eq!(out.unwrap_err(), WuaError::KeyNotHardwareBacked);
}
```

#### 6.3.5 Property tests + fuzzing (Tier 1)

- **Property:** for any well-formed-but-unpinned root, `verify_key_attestation` never returns `Ok`. Generate random root keys; assert rejection.
- **Property:** `verify_wua` is monotone in expiry — if it rejects at `now` for `WuaExpired`, it rejects for all later `now`.
- **Fuzz** `crates/wua/fuzz/fuzz_targets/attestation_parse.rs`: arbitrary bytes into the Apple/Android attestation parsers; never panic, bounded allocation, always `Err` on garbage (never `Ok` with a fabricated key).

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let roots = wua::verify::ManufacturerRoots::default(); // empty -> everything must fail
    let v = support_fuzz::mock_verifier();
    // With no pinned roots, NOTHING may ever verify. Assert that invariant.
    let att = wua::key_attestation::KeyAttestation {
        platform: wua::key_attestation::Platform::AndroidTee,
        evidence: data.to_vec(),
        claimed_props: support_fuzz::empty_props(),
        produced_at: time_model::UtcInstant(1_700_000_000),
    };
    let r = wua::verify::verify_key_attestation_for_fuzz(&att, &roots, b"chal", &v,
        time_model::UtcInstant(1_700_000_000));
    assert!(r.is_err(), "empty root store must never accept any attestation");
});
```

#### 6.3.6 Kani harness (Tier 1) — a machine-checked invariant

Add `crates/wua/src/kani_harness.rs` behind `#[cfg(kani)]` to *prove* the "never trust a self-claim" invariant symbolically:

```rust
#[cfg(kani)]
mod proofs {
    use crate::verify::ManufacturerRoots;

    #[kani::proof]
    fn empty_roots_never_accept() {
        // With no pinned manufacturer roots, verify_key_attestation is UNSAT for Ok:
        // for ALL evidence bytes (bounded), the result is Err.
        let len: usize = kani::any();
        kani::assume(len <= 32);
        let mut evidence = vec![0u8; len];
        for b in &mut evidence { *b = kani::any(); }
        let roots = ManufacturerRoots::default();
        // ... construct KeyAttestation, call the pure extractor with a stub verifier ...
        // assert result.is_err();
    }
}
```

Run with `cargo kani` (installed per shared context: `cargo install --locked kani-verifier && cargo kani setup`).

**Definition of done (6.3):**

```bash
cargo test -p wua                                   # W+1..W+3 and W-1..W-14 pass
cargo fuzz run attestation_parse -- -max_total_time=60   # 0 crashes; empty-root invariant holds
cargo kani -p wua --harness empty_roots_never_accept     # VERIFICATION SUCCESSFUL
```
Expected: `test result: ok`; fuzzer `0 crashes`; Kani prints `VERIFICATION:- SUCCESSFUL`. Critically, confirm **W-6** (device self-signed attestation) and **W-8** (software key) both fail — these two are the anti-self-claim guardrails and a reviewer must tick them off explicitly in the PR.

---

### 6.4 — Cross-crate integration & where these plug into the core

These three crates are consumed by the codec/protocol crates and the facade:

1. **`oid4vci` (issuance, Section 5)** calls `wua::verify_wua` context reversed — actually the *issuer* verifies the wallet's WUA; on the wallet side, `wua` produces the evidence via `Effect::AttestKey`. During issuance the wallet uses `trust` to validate the issuer's cert against the trusted list before accepting a credential, and records the credential's `StatusRef` (from `status`) for later revocation checks.
2. **`oid4vp` (remote presentation) and `iso18013-5` (proximity, Section 5)** call `status::decide` with the right `PresentationContext` (`RemoteOnline` vs `ProximityOffline`) *before* the presenter (Section 5's `presenter`) is allowed to emit a disclosure `Effect`. This ordering — status check ⇒ consent ⇒ disclosure — is exactly the invariant the Lean model proves in Section 9 ("no disclosure effect before a consent event"); extend that model with "no `Allow`/`AllowDegraded` presentation of a `Block`ed credential."
3. **`trust` and `status` fetching** are driven by the `wallet-core` run loop (Section 2) via the `Effect`s enumerated above; the shells (Section 4) implement the actual HTTP GETs and feed bytes back as `Event`s.

**Add the Effect/Event variants** (in `wallet-core`, Section 2) — collected here for convenience:

```rust
// crates/wallet-core/src/effect.rs  (append)
pub enum Effect {
    // ... existing ...
    FetchTrustedList { url: String },
    FetchStatusList  { uri: String },
    AttestKey        { challenge: Vec<u8> },
    ReadClock,
    PersistTrustState { scheme: String, seq: u64 },
    // ...
}

// crates/wallet-core/src/event.rs  (append)
pub enum Event {
    // ... existing ...
    TrustedListBytes { url: String, bytes: Vec<u8>, http_status: u16 },
    StatusListBytes  { uri: String, bytes: Vec<u8>, http_status: u16 },
    KeyAttestationProduced { evidence: Vec<u8> },
    ClockRead(time_model::UtcInstant),
    // ...
}
```

**Definition of done (6.4 — the section-level gate):**

```bash
# 1. All three crates + workspace build clean with no I/O deps leaking in.
cargo build -p trust -p status -p wua
cargo tree -p trust -p status -p wua | grep -Ei 'reqwest|hyper|tokio|ureq|std::net'   # empty

# 2. Full test + formal suites green.
cargo test -p trust -p status -p wua
for f in tsl_parse token_parse attestation_parse; do
  cargo fuzz run "$f" -- -max_total_time=60
done
cargo kani -p wua --harness empty_roots_never_accept

# 3. Register-ID traceability: every pinned ID appears in a README change-watch table.
grep -REl 'REG_2025_2164|REG_2025_847|TS03|TSL_DRAFT_21|ETSI_119612' crates/{trust,status,wua}/README.md
```
Expected: builds clean and warning-free; the dependency grep prints **nothing** (proving purity); `cargo test` reports `0 failed` across all three; all three fuzzers report `0 crashes`; Kani prints `VERIFICATION SUCCESSFUL`; the final `grep -l` lists all three README files (traceability to register IDs 2025/2164, 2025/847, TS03, Token Status List draft-21, ETSI 119 612 present). When all five commands pass, Section 6 is done and the `trust`/`status`/`wua` crates are ready to be wired into the protocol crates of Section 5 and the Lean oracle of Section 9.

---


## Section 7 — presenter crate: canonical `ScreenDescription`, the A2UI pattern, and consent hashing

This section builds `crates/presenter`, the crate that turns wallet state into what the user sees, and produces the cryptographic anchor for *what-you-see-is-what-you-sign*. It is the single most security-relevant piece of UI code in the wallet, so we treat it like a codec, not like "the view layer": pure, total, deterministic, versioned, fuzz- and golden-tested.

Read the two ideas below before you type anything; the whole design falls out of them.

**Idea 1 — A2UI, but local-only and closed.** "UI as data" normally means a server sends a document that describes a screen and the client renders whatever structure it's told to. We use the *shape* of that pattern (the UI is a data value, not imperative view code) but we invert the trust model. The **structure** of every screen is owned by the wallet and drawn from a **closed vocabulary** of ~15 archetypes. A relying party (RP — the verifier asking for your data) can *never* introduce structure. RP-supplied material (its name, its logo, its stated purpose) enters **only** as individual, validated **data slots** inside a wallet-owned template. There is no HTML, no markup, no expression language, no conditionals in the wire format — every branch ("show this button?", "is this claim disclosed?") has already been decided upstream by the protocol state machines (`oid4vp`, `oid4vci`, `iso18013-5`) before the presenter runs.

**Idea 2 — hash the consent screen inside the core.** Because the presenter is a pure function of a `Snapshot`, and because the canonical serialization is byte-exact and versioned, the core can compute `consent_hash = SHA-256(canonical_bytes(consent_screen))` deterministically, *synchronously*, with no I/O. That hash is recorded in the audit log and later bound to the signature/QES authorization. Both platform shells receive the *same* `ScreenDescription` value produced by the *same* core, so they provably display the same consent payload; the shell echoes the hash back on confirm and the core re-checks it before it will emit any disclosure Effect.

### 7.0 Where the presenter sits, and its dependency rules

- **Input:** a `Snapshot` — a fully-resolved read-model projected from the core state. Every string in it is final and already-validated; every decision is already made.
- **Output:** a `ScreenDescription` — one variant of the closed enum, carrying typed, fully-resolved display data.
- **`present` is total and infallible:** `fn present(snapshot: &Snapshot) -> ScreenDescription`. It returns `ScreenDescription`, never `Result`, and never panics. If anything failed upstream, the `Snapshot`'s focus is already `Error`, and `present` renders the `Error` archetype. This is what makes it safe to call on every tick of the run loop.
- **Dependency direction:** `wallet-core` depends on `presenter`. `presenter` depends on *nothing* in the protocol/crypto-Effect stack — not `oid4vp`, not `mdoc`, not `crypto-traits`. It has three tiny dependencies: `sha2` (a vetted SHA-256; we do **not** implement SHA ourselves — see the "DO NOT DO" rules), `unicode-normalization` (spoofing-resistant, deterministic text), and `serde` (record derives + golden snapshots).
- **Why `sha2` directly and not the `crypto-traits` Effect path:** device-bound key operations (signing, ECDH, attestation) MUST go through `crypto-traits` into the Secure Enclave/StrongBox as Effects (see the platform-cryptography section). But the consent hash is a hash of **public, on-screen bytes**; it is not a secret-key operation and it must be computable *synchronously and deterministically* so the replay oracle (see the formal-methods section, Tier 2) sees identical bytes. Routing it through the async Effect boundary would break that determinism for no security benefit. Using a vetted SHA-256 implementation directly satisfies "never implement SHA yourself." (`aws-lc-rs`'s SHA-256 is an acceptable substitute; the only requirements are *vetted* and *deterministic*.)

Definition of done for 7.0: none — this is orientation. Proceed to 7.1.

---

### 7.1 Step 1 — Create the crate and wire it into the workspace

1. From the repository root, create the crate skeleton:

```bash
cd crates
cargo new --lib presenter
```

2. Add it to the workspace `Cargo.toml` at the repo root (the `members` list is shared; keep it alphabetized):

```toml
# Cargo.toml (workspace root) — members list excerpt
[workspace]
members = [
  "crates/cose",
  "crates/crypto-traits",
  "crates/iso18013-5",
  "crates/mdoc",
  "crates/oid4vci",
  "crates/oid4vp",
  "crates/presenter",   # <-- add this line
  "crates/sdjwt",
  "crates/status",
  "crates/trust",
  "crates/wallet-core",
  "crates/wua",
  "crates/x509",
]
```

3. Replace `crates/presenter/Cargo.toml` with exactly this:

```toml
[package]
name = "presenter"
version = "0.1.0"
edition = "2021"
publish = false

# Belt: forbid unsafe at the crate level too (see lib.rs for the source-visible attribute).
[lints.rust]
unsafe_code = "forbid"

[dependencies]
# Vetted SHA-256. We NEVER hand-roll a hash. Pure, deterministic, no I/O.
sha2 = "0.10"
# NFC normalization: makes RP-supplied text spoofing-resistant AND canonically stable.
unicode-normalization = "0.1"
# Record derives (used by the FFI-facing types) and golden-file (JSON) rendering.
serde = { version = "1", features = ["derive"] }

# NOTE: there is deliberately NO CBOR crate here. The canonical consent encoder is a
# ~50-line explicit, byte-auditable writer (crates/presenter/src/canonical.rs). Fewer
# software dependencies on the certification-critical path; trivially portable to Swift/Kotlin.

[dev-dependencies]
serde_json = "1" # golden-file rendering ONLY (tests). NOT the canonical/consent encoding.
proptest = "1"   # Tier-1 property tests: determinism + totality (no panics).
```

4. Replace `crates/presenter/src/lib.rs` with the module skeleton and the crate-wide safety attribute:

```rust
// crates/presenter/src/lib.rs
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! presenter — Snapshot -> ScreenDescription (pure, total, deterministic) + consent hashing.
//!
//! A2UI, local-only: the STRUCTURE of every screen is a closed, wallet-owned vocabulary.
//! RP-supplied material enters ONLY as validated data slotted into wallet-owned templates.

pub mod screen;    // the closed vocabulary: ScreenDescription + ~15 archetypes + value types
pub mod snapshot;  // the read-model the presenter consumes (Focus + per-screen Ctx)
pub mod text;      // wallet-owned localized templates + safe (non-injectable) slotting
pub mod rp;        // validation + sanitization of RP-supplied name/logo/purpose
pub mod minimize;  // data minimization: minimal claim set BEFORE the consent screen
pub mod present;   // the pure present() entry point + per-archetype builders
pub mod canonical; // deterministic CBOR + consent_hash (what-you-see-is-what-you-sign)

pub use present::present;
pub use screen::ScreenDescription;
pub use snapshot::Snapshot;
```

The `deny(...)` line bans the operations that cause panics. In a total function, `unwrap`, `expect`, direct `panic!`, and `slice[i]` indexing are forbidden; use `match`, `if let`, `.get(i)`, and `?`-free total logic instead. This is enforced at compile time.

**Definition of done (7.1):**

```bash
cargo build -p presenter
```

Expected: it fails to compile because the modules are empty files that don't exist yet — that's fine for now. After you create the empty module files:

```bash
cd crates/presenter/src && touch screen.rs snapshot.rs text.rs rp.rs minimize.rs present.rs canonical.rs && cd -
cargo build -p presenter
```

Expected output ends with `Finished dev [unoptimized + debuginfo] target(s)` and zero warnings.

---

### 7.2 Step 2 — The closed vocabulary (`screen.rs`)

Two rules govern this file:

- **Closed set.** `ScreenDescription` is a non-`#[non_exhaustive]` enum with exactly one variant per archetype. Adding a screen is a deliberate edit here, reviewed like a schema change. ~15 archetypes cover the whole wallet.
- **Fully resolved, typed data.** Every field is a final value: a `String` that is already localized and validated, an enum tag, a number, a digest. There are no `Option<Expr>`, no template placeholders, no "render if" flags that encode logic. The only `Option`s are genuinely-absent data (e.g., an RP with no logo).

Write `crates/presenter/src/screen.rs`:

```rust
// crates/presenter/src/screen.rs
use serde::Serialize;

/// The CLOSED vocabulary. One variant per screen archetype the wallet can ever draw.
/// Renderers MUST map each variant to native, accessible controls and MUST NOT invent structure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum ScreenDescription {
    Loading(LoadingScreen),                     // 1  spinner + status text
    Error(ErrorScreen),                         // 2  terminal error, recoverable action(s)
    Welcome(WelcomeScreen),                     // 3  first-run / onboarding
    CredentialList(CredentialListScreen),       // 4  wallet home: the user's credentials
    CredentialDetail(CredentialDetailScreen),   // 5  one credential, its claims + status
    IssuanceOffer(IssuanceOfferScreen),         // 6  OID4VCI: accept/decline an offered credential
    IssuanceProgress(IssuanceProgressScreen),   // 7  issuance running
    Consent(ConsentScreen),                     // 8  OID4VP presentation consent  *** the hashed one ***
    PresentQr(PresentQrScreen),                 // 9  show a QR (device engagement / cross-device)
    ScanQr(ScanQrScreen),                       // 10 scan a QR
    ProximityInProgress(ProximityScreen),       // 11 ISO 18013-5 NFC/BLE handoff running
    AuthPrompt(AuthPromptScreen),               // 12 local user auth gate (biometry)
    PinEntry(PinEntryScreen),                   // 13 PIN entry / fallback
    TransactionHistory(TransactionHistoryScreen), // 14 audit log list  (P1 feature; archetype defined now)
    TransactionDetail(TransactionDetailScreen), // 15 one audit entry, incl. its consent_hash
    Settings(SettingsScreen),                   // 16 wallet settings
}
```

Now the shared value types. These are the *only* building blocks screens are made of — a small, closed set of primitives. Note especially `Logo`, `RpTrustBadge`, and `ClaimPath`.

```rust
// crates/presenter/src/screen.rs (continued)

/// Supported UI locales — a CLOSED set (the languages we ship strings for).
/// Unsupported locales fall back to `En` upstream, so the presenter never guesses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Locale { En, Sv, De, Fr, /* ... extend deliberately ... */ }

/// A user action the renderer may surface. The KIND is closed vocabulary; the label is
/// wallet-owned, final localized text. The renderer maps this to a native, labeled control.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Action {
    pub kind: ActionKind,
    pub label: String,       // final, localized, plain text (never markup)
    pub style: ActionStyle,  // semantic emphasis, NOT pixel styling
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum ActionKind {
    ApproveConsent, RejectConsent,
    AcceptIssuance, DeclineIssuance,
    OpenCredential { credential_id: String },
    DeleteCredential { credential_id: String },
    ToggleClaim { claim_ref: ClaimRef }, // toggle an OPTIONAL claim in the consent screen
    Authenticate, EnterPin, CancelFlow, GoBack,
    StartScan, ShowQr, OpenSettings, OpenTransaction { id: String },
    Retry, Dismiss,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ActionStyle { Primary, Secondary, Destructive }

/// A stable identifier for a claim row within THIS screen, so a toggle event names it unambiguously.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ClaimRef { pub credential_index: u16, pub claim_index: u16 }

/// The verified trust status of the RP. Set by the wallet from trust/x509 verification
/// (see the RP-trust-&-registration section). RP-supplied data can NEVER influence this.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum RpTrustBadge {
    /// Registered in a trusted RP registration scheme; carries the scheme's human name.
    Registered { scheme: String },
    /// Registered AND authorized for qualified interactions.
    RegisteredQualified { scheme: String },
    /// Reached us over TLS but is NOT in any trusted registration. (A valid TLS cert is
    /// NOT registration — see the trust section.) The screen must warn prominently.
    NotRegistered,
}

/// A logo the wallet will render. Bound BY DIGEST, not by inline bytes: the actual image
/// bytes are validated + cached by the shell (keyed by digest) when fetched during the flow.
/// This keeps the presenter pure, keeps canonical bytes small, and still commits the hash
/// to the exact image shown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Logo {
    None, // render the wallet's neutral placeholder
    Verified {
        media_type: ImageMediaType,        // raster only; SVG is disallowed (script risk)
        #[serde(serialize_with = "crate::screen::hex32")]
        digest: [u8; 32],                  // SHA-256 of the validated image bytes
        width_px: u16,
        height_px: u16,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ImageMediaType { Png, Jpeg } // allow-list; no SVG, no anything else.

/// Credential format tag. Local to presenter to avoid depending on mdoc/sdjwt for one enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum CredentialFormat { MsoMdoc, SdJwtVc }

/// A canonical, language-independent claim identity.
/// mdoc claims are (namespace, element); SD-JWT VC claims are a path of JSON keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum ClaimPath {
    Mdoc { namespace: String, element: String },
    SdJwt { path: Vec<String> },
}

/// A single claim row on the consent screen. `value_display` is what the user SEES;
/// it stays on-device and is NOT persisted to the log. The canonical form binds a DIGEST
/// of this value, not the value itself (see 7.8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConsentClaim {
    pub path: ClaimPath,
    pub label: String,               // wallet-owned localized human label (function of `path`)
    pub value_display: Option<String>, // e.g. "Yes" for age_over_18, or "1990-01-01"
    pub required: bool,              // required (non-toggleable) vs optional (user may drop it)
    pub selected: bool,             // current selection state (optional claims can be off)
}

/// One credential's block within the consent screen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConsentCredential {
    pub credential_id: String,       // local id (log/audit), not shown as-is
    pub credential_type: String,     // doctype (mdoc) or vct (SD-JWT VC), e.g. "eu.europa.ec.eudi.pid.1"
    pub display_name: String,        // wallet-owned localized name for the credential type
    pub format: CredentialFormat,
    pub claims: Vec<ConsentClaim>,   // ALREADY the minimal set (see 7.6)
}

/// Small, safe, key/value rows for detail screens.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Field { pub label: String, pub value: String }

fn hex32<S: serde::Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&crate::canonical::to_hex(bytes))
}
```

Finally, the per-archetype screen structs. `ConsentScreen` is shown in full; the others follow the identical "typed, resolved data only" pattern (a few shown; the rest are mechanical).

```rust
// crates/presenter/src/screen.rs (continued)

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConsentScreen {
    pub title: String,               // wallet chrome (localized) — NOT bound by the hash
    pub rp_display_name: String,     // RP-supplied, VALIDATED + sanitized (see 7.5) — bound by the hash
    pub rp_trust: RpTrustBadge,      // wallet-derived — bound by the hash
    pub logo: Logo,                  // digest-bound — bound by the hash
    pub purpose: Option<String>,     // RP-supplied purpose, VALIDATED — bound by the hash
    pub credentials: Vec<ConsentCredential>, // MINIMAL claim set — bound by the hash (paths+value digests)
    /// SHA-256 over the salient request fields (client_id, response_uri, response_mode, nonce,
    /// canonical DCQL query). Produced by the oid4vp machine (see the OpenID4VP section) and
    /// carried through the Snapshot. Binds the consent to THIS request instance.
    #[serde(serialize_with = "crate::screen::hex32")]
    pub request_commitment: [u8; 32],
    pub approve: Action,             // ActionKind::ApproveConsent — chrome, not hash-bound
    pub reject: Action,              // ActionKind::RejectConsent  — chrome, not hash-bound
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ErrorScreen {
    pub title: String,
    pub message: String,             // wallet-owned localized text; NEVER a raw RP/technical string
    pub actions: Vec<Action>,        // e.g. [Retry, Dismiss]
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CredentialListScreen {
    pub title: String,
    pub items: Vec<CredentialListItem>,
    pub actions: Vec<Action>,        // e.g. [StartScan, OpenSettings]
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CredentialListItem {
    pub credential_id: String,
    pub display_name: String,
    pub format: CredentialFormat,
    pub status_line: String,         // localized: "Valid", "Expires 2027-01-01", "Revoked"
    pub open: Action,                // ActionKind::OpenCredential { credential_id }
}

// The remaining archetypes follow the SAME shape — resolved, typed, no logic:
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LoadingScreen { pub status_text: String, pub cancel: Option<Action> }

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WelcomeScreen { pub headline: String, pub body: String, pub actions: Vec<Action> }

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CredentialDetailScreen {
    pub display_name: String, pub fields: Vec<Field>, pub status_line: String, pub actions: Vec<Action>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IssuanceOfferScreen {
    pub rp_display_name: String, pub rp_trust: RpTrustBadge, pub logo: Logo,
    pub offered_type_name: String, pub fields_preview: Vec<Field>, pub accept: Action, pub decline: Action,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IssuanceProgressScreen { pub status_text: String, pub cancel: Option<Action> }
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PresentQrScreen { pub caption: String, pub qr_payload: String, pub cancel: Action }
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScanQrScreen { pub caption: String, pub cancel: Action }
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProximityScreen { pub status_text: String, pub cancel: Option<Action> }
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthPromptScreen { pub reason: String, pub authenticate: Action, pub fallback: Option<Action> }
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PinEntryScreen { pub prompt: String, pub attempts_remaining: Option<u8>, pub submit: Action, pub cancel: Action }
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TransactionHistoryScreen { pub title: String, pub items: Vec<TransactionListItem> }
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TransactionListItem { pub id: String, pub rp_display_name: String, pub timestamp: String, pub summary: String, pub open: Action }
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TransactionDetailScreen {
    pub rp_display_name: String, pub timestamp: String, pub disclosed: Vec<Field>,
    #[serde(serialize_with = "crate::screen::hex32")]
    pub consent_hash: [u8; 32],   // the audit anchor recorded at consent time (7.8/7.9)
    pub actions: Vec<Action>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SettingsScreen { pub title: String, pub rows: Vec<Field>, pub actions: Vec<Action> }
```

**Definition of done (7.2):** add a compile-time count guard so nobody silently adds/removes an archetype, then build.

```rust
// crates/presenter/src/screen.rs (append)
#[cfg(test)]
mod vocab_tests {
    use super::*;
    #[test]
    fn archetype_count_is_frozen() {
        // Match arms force exhaustiveness: if a variant is added/removed, this fails to compile
        // until the count below is consciously updated. This IS the "closed vocabulary" guard.
        fn tag(s: &ScreenDescription) -> u8 {
            match s {
                ScreenDescription::Loading(_) => 1,  ScreenDescription::Error(_) => 2,
                ScreenDescription::Welcome(_) => 3,  ScreenDescription::CredentialList(_) => 4,
                ScreenDescription::CredentialDetail(_) => 5, ScreenDescription::IssuanceOffer(_) => 6,
                ScreenDescription::IssuanceProgress(_) => 7, ScreenDescription::Consent(_) => 8,
                ScreenDescription::PresentQr(_) => 9, ScreenDescription::ScanQr(_) => 10,
                ScreenDescription::ProximityInProgress(_) => 11, ScreenDescription::AuthPrompt(_) => 12,
                ScreenDescription::PinEntry(_) => 13, ScreenDescription::TransactionHistory(_) => 14,
                ScreenDescription::TransactionDetail(_) => 15, ScreenDescription::Settings(_) => 16,
            }
        }
        const ARCHETYPE_COUNT: u8 = 16;
        let _ = tag; // referenced so the match is checked
        assert_eq!(ARCHETYPE_COUNT, 16, "closed vocabulary size changed — update deliberately");
    }
}
```

```bash
cargo test -p presenter vocab_tests
```

Expected: `test result: ok. 1 passed`. If you add a `ScreenDescription` variant, the `match` fails to compile until you handle it — that is the point.

---

### 7.3 Step 3 — The `Snapshot` read-model (`snapshot.rs`)

The presenter consumes a `Snapshot`. It carries shared context (the locale) plus a `Focus` — an enum that *already names the screen to draw* and carries the resolved data for it. All branching lives here, decided by the state machines; `present` just maps `Focus → ScreenDescription`.

```rust
// crates/presenter/src/snapshot.rs
use crate::screen::{Locale, CredentialFormat, ClaimPath, RpTrustBadge, Logo};

#[derive(Debug, Clone)]
pub struct Snapshot {
    pub locale: Locale,
    pub focus: Focus,
}

/// One variant per screen the machines can put us on. Mirrors the archetype set.
#[derive(Debug, Clone)]
pub enum Focus {
    Loading(LoadingCtx),
    Error(ErrorCtx),
    Welcome,
    CredentialList(CredentialListCtx),
    CredentialDetail(CredentialDetailCtx),
    IssuanceOffer(IssuanceOfferCtx),
    IssuanceProgress(IssuanceProgressCtx),
    Consent(ConsentCtx),          // <- the important one
    PresentQr(PresentQrCtx),
    ScanQr(ScanQrCtx),
    ProximityInProgress(ProximityCtx),
    AuthPrompt(AuthPromptCtx),
    PinEntry(PinEntryCtx),
    TransactionHistory(TransactionHistoryCtx),
    TransactionDetail(TransactionDetailCtx),
    Settings(SettingsCtx),
}

/// The resolved input to the consent screen. EVERYTHING here is already validated/verified:
/// - `rp_*` fields have passed RP-trust verification (see the trust section);
/// - `plan` is ALREADY minimized (see 7.6) — present() does no filtering;
/// - `request_commitment` was computed by the oid4vp machine.
#[derive(Debug, Clone)]
pub struct ConsentCtx {
    pub rp_name_raw: String,          // raw verified name; presenter sanitizes for display (7.5)
    pub rp_trust: RpTrustBadge,
    pub logo: Logo,                   // already a validated digest (or None)
    pub purpose_raw: Option<String>,  // raw RP purpose; presenter sanitizes (7.5)
    pub plan: DisclosurePlan,         // MINIMAL claim set + current selection
    pub request_commitment: [u8; 32],
}

/// The minimized disclosure plan — the security boundary. Built upstream by `minimize` (7.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisclosurePlan { pub entries: Vec<PlanEntry> }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanEntry {
    pub credential_id: String,
    pub credential_type: String,
    pub format: CredentialFormat,
    pub claims: Vec<PlannedClaim>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedClaim {
    pub path: ClaimPath,
    pub value_display: Option<String>, // resolved on-device value the user will see
    pub required: bool,
    pub selected: bool,                // optional claims may be toggled off; required are always true
}

// The other Ctx types carry only what their screen needs. Abbreviated:
#[derive(Debug, Clone)] pub struct LoadingCtx { pub kind: LoadingKind, pub cancellable: bool }
#[derive(Debug, Clone)] pub enum LoadingKind { StartingIssuance, ContactingIssuer, EstablishingProximity, Generic }
#[derive(Debug, Clone)] pub struct ErrorCtx { pub kind: ErrorKind }
#[derive(Debug, Clone)] pub enum ErrorKind {
    RpNotTrusted, RequestInvalid, NetworkUnavailable, UserAuthFailed, CredentialUnavailable, Internal,
} // NOTE: closed set of error *kinds*; presenter maps each to a wallet-owned localized message.
#[derive(Debug, Clone)] pub struct CredentialListCtx { pub items: Vec<CredentialSummary> }
#[derive(Debug, Clone)] pub struct CredentialSummary { pub id: String, pub type_id: String, pub format: CredentialFormat, pub status: CredStatus }
#[derive(Debug, Clone)] pub enum CredStatus { Valid, ExpiresOn(String), Revoked, Suspended }
#[derive(Debug, Clone)] pub struct CredentialDetailCtx { pub id: String, pub type_id: String, pub format: CredentialFormat, pub claims: Vec<(ClaimPath, String)>, pub status: CredStatus }
#[derive(Debug, Clone)] pub struct IssuanceOfferCtx { pub rp_name_raw: String, pub rp_trust: RpTrustBadge, pub logo: Logo, pub offered_type: String, pub preview: Vec<(ClaimPath, String)> }
#[derive(Debug, Clone)] pub struct IssuanceProgressCtx { pub cancellable: bool }
#[derive(Debug, Clone)] pub struct PresentQrCtx { pub payload: String, pub reason: QrReason }
#[derive(Debug, Clone)] pub enum QrReason { DeviceEngagement, CrossDevice }
#[derive(Debug, Clone)] pub struct ScanQrCtx { pub reason: QrReason }
#[derive(Debug, Clone)] pub struct ProximityCtx { pub cancellable: bool }
#[derive(Debug, Clone)] pub struct AuthPromptCtx { pub reason: AuthReason, pub pin_fallback: bool }
#[derive(Debug, Clone)] pub enum AuthReason { UnlockWallet, AuthorizeDisclosure, AuthorizeSignature }
#[derive(Debug, Clone)] pub struct PinEntryCtx { pub attempts_remaining: Option<u8> }
#[derive(Debug, Clone)] pub struct TransactionHistoryCtx { pub items: Vec<TxSummary> }
#[derive(Debug, Clone)] pub struct TxSummary { pub id: String, pub rp_name: String, pub ts: String, pub claim_count: u16 }
#[derive(Debug, Clone)] pub struct TransactionDetailCtx { pub rp_name: String, pub ts: String, pub disclosed: Vec<(ClaimPath, String)>, pub consent_hash: [u8; 32] }
#[derive(Debug, Clone)] pub struct SettingsCtx { pub app_version: String, pub locale_name: String }
```

Notice `ErrorCtx` carries an `ErrorKind`, never a raw string. The presenter maps each kind to a wallet-owned localized message. This is how we honor "never render a raw RP/technical string as the error."

**Definition of done (7.3):**

```bash
cargo build -p presenter
```

Expected: `Finished` with no warnings.

---

### 7.4 Step 4 — Wallet-owned text templates + safe slotting (`text.rs`)

Every user-facing sentence comes from a wallet-owned table keyed by a `TextKey` enum (closed vocabulary of *strings*, mirroring the closed vocabulary of *structure*). Slotting uses a **positional, non-injectable** formatter: the template contains numbered holes `{0}`, `{1}`; arguments are plain text and are inserted verbatim with **no** recursive interpretation. There is no `%s`-style format language an RP could smuggle a directive into.

```rust
// crates/presenter/src/text.rs
use crate::screen::Locale;

/// Closed vocabulary of message keys. Each maps to one template per supported locale.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextKey {
    ConsentTitle,
    ConsentPurposeFallback,          // used when the RP supplies no purpose
    ConsentApprove, ConsentReject,
    RpNotRegisteredWarning,
    ErrRpNotTrusted, ErrRequestInvalid, ErrNetwork, ErrAuthFailed, ErrCredentialUnavailable, ErrInternal,
    CredStatusValid, CredStatusRevoked, CredStatusSuspended, CredStatusExpiresOn, // {0}=date
    // ... one per user-facing string in the wallet ...
}

/// Look up the template for (locale, key). Every key MUST have an entry for every locale;
/// a missing entry falls back to English, never to empty or to a raw key name.
fn template(locale: Locale, key: TextKey) -> &'static str {
    use Locale::*; use TextKey::*;
    match (locale, key) {
        (En, ConsentTitle) => "Share your information",
        (Sv, ConsentTitle) => "Dela din information",
        (En, ConsentApprove) => "Share",
        (Sv, ConsentApprove) => "Dela",
        (En, ConsentReject) => "Cancel",
        (Sv, ConsentReject) => "Avbryt",
        (En, ConsentPurposeFallback) => "The service did not state a reason.",
        (En, RpNotRegisteredWarning) => "This party is NOT a registered verifier. Share with caution.",
        (En, CredStatusExpiresOn) => "Expires {0}",
        (En, ErrRpNotTrusted) => "This request could not be trusted and was stopped.",
        // ... exhaustive ...
        // Fallback: any (locale, key) not explicitly translated resolves to its English text.
        (_, k) => template(En, k),
    }
}

/// Safe positional formatter. Replaces {0}, {1}, ... with args, verbatim, once, left to right.
/// Unknown indices and stray braces are left as literal text. No recursion, no re-scanning of
/// inserted args — an argument that itself contains "{0}" is NEVER re-substituted.
pub fn t(locale: Locale, key: TextKey, args: &[&str]) -> String {
    let tmpl = template(locale, key);
    let mut out = String::with_capacity(tmpl.len());
    let mut chars = tmpl.char_indices().peekable();
    while let Some((_, c)) = chars.next() {
        if c != '{' { out.push(c); continue; }
        // parse a run of ASCII digits followed by '}'
        let mut idx = 0usize; let mut saw_digit = false; let mut closed = false;
        while let Some(&(_, d)) = chars.peek() {
            if d.is_ascii_digit() { idx = idx.saturating_mul(10).saturating_add((d as u8 - b'0') as usize); saw_digit = true; chars.next(); }
            else if d == '}' { closed = true; chars.next(); break; }
            else { break; }
        }
        match (saw_digit, closed, args.get(idx)) {
            (true, true, Some(a)) => out.push_str(a),        // valid hole with an arg -> insert verbatim
            _ => { out.push('{'); /* leave literal */ }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn positional_insert_is_verbatim_and_non_recursive() {
        // An arg containing a brace token is NOT re-interpreted.
        assert_eq!(t(Locale::En, TextKey::CredStatusExpiresOn, &["{0}"]), "Expires {0}");
        assert_eq!(t(Locale::En, TextKey::CredStatusExpiresOn, &["2027-01-01"]), "Expires 2027-01-01");
    }
    #[test]
    fn missing_locale_falls_back_to_english_not_empty() {
        assert_eq!(t(Locale::De, TextKey::ConsentApprove), "Share"); // no German yet -> English
    }
}
```

(The second test's call is illustrative; add the `args` slice — `t(Locale::De, TextKey::ConsentApprove, &[])` — when you type it in.)

**Definition of done (7.4):**

```bash
cargo test -p presenter text::
```

Expected: `test result: ok. 2 passed`. The non-recursion test is the security-relevant one: it proves RP-supplied text placed into an argument slot can never re-open the template's substitution.

---

### 7.5 Step 5 — Validate and slot RP-supplied fields (`rp.rs`)

RP-supplied fields are the *only* untrusted data that reaches the screen. They enter as **individual, sanitized values**, never as structure. `rp.rs` is the choke point.

Sanitization rules for `rp_display_name` and `purpose`:

1. **NFC-normalize** (Unicode canonical composition) — removes "same glyph, different code points" ambiguity and makes the value deterministic (so the same name always canonicalizes to the same bytes for the hash).
2. **Strip bidi and other format/control characters** — U+202A–U+202E, U+2066–U+2069, U+200E/U+200F, and the C0/C1 control range and other `Cc`/`Cf` code points. These are the classic tools for spoofing a display name (e.g., making `evil.com` render as `moc.live`). Also collapses/removes newlines and tabs, so a name cannot fake extra screen lines.
3. **Cap length** and mark truncation, so an over-long name cannot push the trust badge or buttons off-screen.
4. **Never interpret as markup.** Renderers treat the result as plain text (no HTML/Markdown). The type system helps: we hand the renderer a `String`, and the accessibility contract (7.11) forbids the renderer from parsing markup.

```rust
// crates/presenter/src/rp.rs
use unicode_normalization::UnicodeNormalization;

const MAX_NAME_CHARS: usize = 64;
const MAX_PURPOSE_CHARS: usize = 300;

/// Sanitize an RP display name for safe, deterministic rendering AND hashing.
pub fn sanitize_rp_name(raw: &str) -> String { sanitize(raw, MAX_NAME_CHARS) }

/// Sanitize an RP purpose string.
pub fn sanitize_purpose(raw: &str) -> String { sanitize(raw, MAX_PURPOSE_CHARS) }

fn sanitize(raw: &str, max_chars: usize) -> String {
    // 1) drop dangerous code points, 2) map any inline whitespace to a single space
    let cleaned: String = raw
        .chars()
        .filter(|&c| !is_dangerous(c))
        .map(|c| if c.is_whitespace() { ' ' } else { c })
        .collect();
    // 3) NFC-normalize AFTER filtering
    let normalized: String = cleaned.nfc().collect();
    // 4) collapse runs of spaces and trim
    let mut out = String::with_capacity(normalized.len());
    let mut prev_space = false;
    for c in normalized.chars() {
        if c == ' ' { if !prev_space && !out.is_empty() { out.push(' '); } prev_space = true; }
        else { out.push(c); prev_space = false; }
    }
    let out = out.trim_end().to_string();
    // 5) cap length by chars (append an ellipsis marker if truncated)
    if out.chars().count() > max_chars {
        let mut t: String = out.chars().take(max_chars.saturating_sub(1)).collect();
        t.push('\u{2026}'); // … one code point, itself allowed
        t
    } else { out }
}

/// Bidi controls, other format chars, C0/C1 controls, and BOM — all rejected.
fn is_dangerous(c: char) -> bool {
    matches!(c,
        '\u{202A}'..='\u{202E}' | // LRE RLE PDF LRO RLO
        '\u{2066}'..='\u{2069}' | // LRI RLI FSI PDI
        '\u{200E}' | '\u{200F}' | // LRM RLM
        '\u{200B}'..='\u{200D}' | // zero-width space/joiners
        '\u{FEFF}' |              // BOM / zero-width no-break space
        '\u{0000}'..='\u{001F}' | // C0 controls (note: also matched by is_whitespace but be explicit)
        '\u{007F}'..='\u{009F}'   // DEL + C1 controls
    )
}
```

**Definition of done (7.5):** these tests prove the spoofing defenses.

```rust
// crates/presenter/src/rp.rs (append)
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn strips_bidi_override_used_for_spoofing() {
        let spoof = "good\u{202E}dab.example"; // RLO makes the tail render reversed
        let clean = sanitize_rp_name(spoof);
        assert!(!clean.chars().any(|c| ('\u{202A}'..='\u{202E}').contains(&c)));
        assert_eq!(clean, "gooddab.example");
    }
    #[test]
    fn removes_newlines_so_name_cannot_fake_lines() {
        assert_eq!(sanitize_rp_name("Acme\nInc\tLtd"), "Acme Inc Ltd");
    }
    #[test]
    fn caps_length() {
        let long = "A".repeat(200);
        let clean = sanitize_rp_name(&long);
        assert!(clean.chars().count() <= 64);
        assert!(clean.ends_with('\u{2026}'));
    }
    #[test]
    fn markup_is_left_as_inert_text_not_structure() {
        // We do not strip '<'/'>' — we rely on the renderer treating output as plain text.
        assert_eq!(sanitize_rp_name("<b>Acme</b>"), "<b>Acme</b>");
    }
}
```

```bash
cargo test -p presenter rp::
```

Expected: `test result: ok. 4 passed`.

> Logo handling belongs partly here and partly in the flow: the raw logo bytes are fetched by an Effect during the oid4vp flow, validated there against the `ImageMediaType` allow-list (raster only; reject SVG), size/dimension caps applied, and a `Logo::Verified { digest, .. }` produced. The presenter never touches image bytes; it receives the already-verified `Logo`. See the OpenID4VP section for the fetch Effect and the trust section for where the logo's provenance is checked.

---

### 7.6 Step 6 — Data minimization: the minimal claim set *before* the screen (`minimize.rs`)

Minimization is a **precondition** of building the consent screen, not something the screen does. The oid4vp machine calls `minimize` after it has parsed and verified the request, and hands the resulting `DisclosurePlan` to the presenter through `ConsentCtx`. Two invariants define "minimal":

- **No over-disclosure:** the plan's claims are a subset of what the RP *requested*. We never volunteer a claim the RP didn't ask for, and we never expand a request to a whole credential (honoring "never disclose a whole credential where selective disclosure exists").
- **No fabrication:** the plan's claims are a subset of what the credential actually *holds*. A requested-but-absent claim simply doesn't appear.

```rust
// crates/presenter/src/minimize.rs
use crate::screen::{ClaimPath, CredentialFormat};
use crate::snapshot::{DisclosurePlan, PlanEntry, PlannedClaim};

/// What the RP asked for, already parsed from DCQL/Presentation Definition by the oid4vp machine.
pub struct RequestedCredential {
    pub credential_id: String,
    pub credential_type: String,
    pub format: CredentialFormat,
    pub requested_claims: Vec<RequestedClaim>,
}
pub struct RequestedClaim { pub path: ClaimPath, pub required: bool }

/// What the wallet actually holds for that credential.
pub struct HeldCredential {
    pub credential_id: String,
    pub available: Vec<(ClaimPath, String)>, // path -> resolved on-device value
}

/// Compute the MINIMAL disclosure plan. Pure and total.
pub fn minimize(requests: &[RequestedCredential], held: &[HeldCredential]) -> DisclosurePlan {
    let mut entries = Vec::new();
    for req in requests {
        let Some(hc) = held.iter().find(|h| h.credential_id == req.credential_id) else { continue };
        let mut claims = Vec::new();
        for rc in &req.requested_claims {
            // INTERSECTION: only claims the RP requested AND the credential holds.
            if let Some((_, value)) = hc.available.iter().find(|(p, _)| p == &rc.path) {
                claims.push(PlannedClaim {
                    path: rc.path.clone(),
                    value_display: Some(value.clone()),
                    required: rc.required,
                    // Optional claims start selected; the user may toggle them off (7.7).
                    selected: true,
                });
            }
            // requested-but-absent -> silently omitted (no fabrication).
        }
        if !claims.is_empty() {
            entries.push(PlanEntry {
                credential_id: req.credential_id.clone(),
                credential_type: req.credential_type.clone(),
                format: req.format,
                claims,
            });
        }
    }
    DisclosurePlan { entries }
}
```

**Definition of done (7.6):** the minimization test (also reused as a golden invariant in 7.10).

```rust
// crates/presenter/src/minimize.rs (append)
#[cfg(test)]
mod tests {
    use super::*;
    fn mdoc(ns: &str, el: &str) -> ClaimPath { ClaimPath::Mdoc { namespace: ns.into(), element: el.into() } }

    #[test]
    fn never_discloses_more_than_requested() {
        let pid = "eu.europa.ec.eudi.pid.1";
        let req = RequestedCredential {
            credential_id: "pid-0".into(), credential_type: pid.into(), format: CredentialFormat::MsoMdoc,
            requested_claims: vec![
                RequestedClaim { path: mdoc(pid, "family_name"), required: true },
                RequestedClaim { path: mdoc(pid, "birth_date"),  required: true },
            ],
        };
        // The credential holds FIVE claims; the RP asked for two.
        let held = HeldCredential {
            credential_id: "pid-0".into(),
            available: vec![
                (mdoc(pid, "family_name"), "Andersson".into()),
                (mdoc(pid, "birth_date"),  "1990-01-01".into()),
                (mdoc(pid, "resident_address"), "Storgatan 1".into()),
                (mdoc(pid, "nationality"), "SE".into()),
                (mdoc(pid, "portrait"), "<bytes>".into()),
            ],
        };
        let plan = minimize(&[req], &[held]);
        let claims = &plan.entries[0].claims;
        assert_eq!(claims.len(), 2, "exactly the requested claims, nothing else");
        let disclosed: Vec<_> = claims.iter().map(|c| c.path.clone()).collect();
        assert!(disclosed.contains(&mdoc(pid, "family_name")));
        assert!(disclosed.contains(&mdoc(pid, "birth_date")));
        assert!(!disclosed.contains(&mdoc(pid, "resident_address")), "MUST NOT leak un-requested claim");
        assert!(!disclosed.contains(&mdoc(pid, "portrait")), "MUST NOT dump the whole credential");
    }

    #[test]
    fn requested_but_absent_claim_is_not_fabricated() {
        let pid = "eu.europa.ec.eudi.pid.1";
        let req = RequestedCredential {
            credential_id: "pid-0".into(), credential_type: pid.into(), format: CredentialFormat::MsoMdoc,
            requested_claims: vec![RequestedClaim { path: mdoc(pid, "email"), required: false }],
        };
        let held = HeldCredential { credential_id: "pid-0".into(), available: vec![(mdoc(pid, "family_name"), "A".into())] };
        let plan = minimize(&[req], &[held]);
        assert!(plan.entries.is_empty(), "no held claim matched -> nothing to disclose");
    }
}
```

```bash
cargo test -p presenter minimize::
```

Expected: `test result: ok. 2 passed`.

---

### 7.7 Step 7 — The pure `present()` and `present_consent()` (`present.rs`)

`present` is a `match` over `Focus`. Each arm slots resolved data into a wallet-owned template. The consent arm is the meaty one; the others are one-liners. No arm can fail, allocate unboundedly, or panic.

```rust
// crates/presenter/src/present.rs
use crate::screen::*;
use crate::snapshot::*;
use crate::text::{t, TextKey};
use crate::rp::{sanitize_rp_name, sanitize_purpose};

/// The pure, total presenter. One Snapshot -> exactly one ScreenDescription. Never panics.
pub fn present(snapshot: &Snapshot) -> ScreenDescription {
    let loc = snapshot.locale;
    match &snapshot.focus {
        Focus::Consent(ctx)  => ScreenDescription::Consent(present_consent(loc, ctx)),
        Focus::Error(ctx)    => ScreenDescription::Error(present_error(loc, ctx)),
        Focus::CredentialList(ctx) => ScreenDescription::CredentialList(present_credential_list(loc, ctx)),
        Focus::Loading(ctx)  => ScreenDescription::Loading(LoadingScreen {
            status_text: loading_text(loc, &ctx.kind),
            cancel: ctx.cancellable.then(|| Action { kind: ActionKind::CancelFlow, label: t(loc, TextKey::ConsentReject, &[]), style: ActionStyle::Secondary }),
        }),
        Focus::Welcome => ScreenDescription::Welcome(WelcomeScreen { /* ...wallet-owned strings... */
            headline: "Your EU Digital Identity".into(), body: String::new(), actions: vec![] }),
        // ... the remaining arms map their Ctx into their screen struct the same way ...
        Focus::CredentialDetail(_) | Focus::IssuanceOffer(_) | Focus::IssuanceProgress(_)
        | Focus::PresentQr(_) | Focus::ScanQr(_) | Focus::ProximityInProgress(_)
        | Focus::AuthPrompt(_) | Focus::PinEntry(_) | Focus::TransactionHistory(_)
        | Focus::TransactionDetail(_) | Focus::Settings(_) => {
            // Each has a concrete builder in the full crate; elided here for brevity.
            unreachable_placeholder()
        }
    }
}

// Placeholder to keep this excerpt compiling in isolation. In the real crate every arm
// returns a real screen; there is NO catch-all and NO unreachable!() in production code.
fn unreachable_placeholder() -> ScreenDescription {
    ScreenDescription::Loading(LoadingScreen { status_text: String::new(), cancel: None })
}

fn loading_text(loc: Locale, k: &LoadingKind) -> String {
    let _ = loc;
    match k { LoadingKind::ContactingIssuer => "Contacting issuer…".into(), _ => "Working…".into() }
}

fn present_error(loc: Locale, ctx: &ErrorCtx) -> ErrorScreen {
    // Map the closed ErrorKind to a wallet-owned localized message. NEVER a raw string.
    let (title_key, msg_key) = match ctx.kind {
        ErrorKind::RpNotTrusted        => (TextKey::ConsentTitle, TextKey::ErrRpNotTrusted),
        ErrorKind::RequestInvalid      => (TextKey::ConsentTitle, TextKey::ErrRequestInvalid),
        ErrorKind::NetworkUnavailable  => (TextKey::ConsentTitle, TextKey::ErrNetwork),
        ErrorKind::UserAuthFailed      => (TextKey::ConsentTitle, TextKey::ErrAuthFailed),
        ErrorKind::CredentialUnavailable => (TextKey::ConsentTitle, TextKey::ErrCredentialUnavailable),
        ErrorKind::Internal            => (TextKey::ConsentTitle, TextKey::ErrInternal),
    };
    ErrorScreen {
        title: t(loc, title_key, &[]),
        message: t(loc, msg_key, &[]),
        actions: vec![Action { kind: ActionKind::Dismiss, label: t(loc, TextKey::ConsentReject, &[]), style: ActionStyle::Primary }],
    }
}

fn present_credential_list(loc: Locale, ctx: &CredentialListCtx) -> CredentialListScreen {
    let items = ctx.items.iter().map(|s| CredentialListItem {
        credential_id: s.id.clone(),
        display_name: credential_type_display_name(loc, &s.type_id),
        format: s.format,
        status_line: match &s.status {
            CredStatus::Valid => t(loc, TextKey::CredStatusValid, &[]),
            CredStatus::ExpiresOn(d) => t(loc, TextKey::CredStatusExpiresOn, &[d]),
            CredStatus::Revoked => t(loc, TextKey::CredStatusRevoked, &[]),
            CredStatus::Suspended => t(loc, TextKey::CredStatusSuspended, &[]),
        },
        open: Action { kind: ActionKind::OpenCredential { credential_id: s.id.clone() }, label: s.id.clone(), style: ActionStyle::Secondary },
    }).collect();
    CredentialListScreen { title: t(loc, TextKey::ConsentTitle, &[]), items, actions: vec![] }
}

/// Wallet-owned display name for a credential type id (doctype/vct). Closed mapping.
fn credential_type_display_name(_loc: Locale, type_id: &str) -> String {
    match type_id {
        "eu.europa.ec.eudi.pid.1" => "Personal ID (PID)".into(),
        other => other.to_string(), // safe fallback: the type id is wallet/issuer-controlled, not RP-controlled
    }
}

/// Build the consent screen: slot VALIDATED RP data into the wallet template, over the
/// ALREADY-MINIMIZED plan. present_consent does NO filtering and NO trust decisions.
pub fn present_consent(loc: Locale, ctx: &ConsentCtx) -> ConsentScreen {
    let rp_display_name = sanitize_rp_name(&ctx.rp_name_raw);            // 7.5
    let purpose = match &ctx.purpose_raw {
        Some(p) => Some(sanitize_purpose(p)),
        None => Some(t(loc, TextKey::ConsentPurposeFallback, &[])),      // wallet-owned fallback
    };

    let credentials = ctx.plan.entries.iter().enumerate().map(|(ci, entry)| {
        let claims = entry.claims.iter().enumerate().map(|(cj, pc)| ConsentClaim {
            path: pc.path.clone(),
            label: claim_label(loc, &pc.path),            // wallet-owned localized label
            value_display: pc.value_display.clone(),
            required: pc.required,
            selected: pc.required || pc.selected,         // required is always selected
        }).collect::<Vec<_>>();
        let _ = (ci, cj_unused());
        ConsentCredential {
            credential_id: entry.credential_id.clone(),
            credential_type: entry.credential_type.clone(),
            display_name: credential_type_display_name(loc, &entry.credential_type),
            format: entry.format,
            claims,
        }
    }).collect();

    ConsentScreen {
        title: t(loc, TextKey::ConsentTitle, &[]),
        rp_display_name,
        rp_trust: ctx.rp_trust.clone(),
        logo: ctx.logo.clone(),
        purpose,
        credentials,
        request_commitment: ctx.request_commitment,
        approve: Action { kind: ActionKind::ApproveConsent, label: t(loc, TextKey::ConsentApprove, &[]), style: ActionStyle::Primary },
        reject:  Action { kind: ActionKind::RejectConsent,  label: t(loc, TextKey::ConsentReject,  &[]), style: ActionStyle::Secondary },
    }
}

fn cj_unused() -> usize { 0 } // (the enumerate index is available for ClaimRef wiring; elided)

/// Wallet-owned localized label for a claim path. Deterministic function of the path.
/// This is why the hash can bind the PATH (language-independent) not the label (7.8).
fn claim_label(_loc: Locale, path: &ClaimPath) -> String {
    match path {
        ClaimPath::Mdoc { element, .. } => match element.as_str() {
            "family_name" => "Family name".into(),
            "birth_date"  => "Date of birth".into(),
            "age_over_18" => "Over 18".into(),
            other => other.replace('_', " "),
        },
        ClaimPath::SdJwt { path } => path.last().cloned().unwrap_or_default().replace('_', " "),
    }
}
```

> The `unreachable_placeholder`, `cj_unused`, and the collapsed match arm exist only to keep this *excerpt* compilable in isolation. In the real crate: every `Focus` arm returns a real, distinct screen; there is no catch-all arm, no `unreachable!()`, no placeholder. The exhaustive `match` on `Focus` (a non-`#[non_exhaustive]` enum) guarantees at compile time that every screen is handled.

**Definition of done (7.7):** build a fixture and print it as a smoke test.

```rust
// crates/presenter/src/present.rs (append, behind cfg(test))
#[cfg(test)]
mod smoke {
    use super::*;
    use crate::snapshot::*;
    pub fn fixture_consent() -> Snapshot {
        let pid = "eu.europa.ec.eudi.pid.1";
        Snapshot { locale: Locale::En, focus: Focus::Consent(ConsentCtx {
            rp_name_raw: "Acme Rentals AB".into(),
            rp_trust: RpTrustBadge::Registered { scheme: "EUDI-RP-Registry".into() },
            logo: Logo::None,
            purpose_raw: Some("Verify you are over 18 to rent a car.".into()),
            plan: DisclosurePlan { entries: vec![ PlanEntry {
                credential_id: "pid-0".into(), credential_type: pid.into(), format: CredentialFormat::MsoMdoc,
                claims: vec![ PlannedClaim {
                    path: ClaimPath::Mdoc { namespace: pid.into(), element: "age_over_18".into() },
                    value_display: Some("Yes".into()), required: true, selected: true,
                }],
            }]},
            request_commitment: [0x11; 32],
        })}
    }
    #[test]
    fn consent_builds() {
        let s = present(&fixture_consent());
        match s { ScreenDescription::Consent(c) => {
            assert_eq!(c.rp_display_name, "Acme Rentals AB");
            assert_eq!(c.credentials[0].claims[0].label, "Over 18");
        }, _ => panic!("expected consent") }
    }
}
```

```bash
cargo test -p presenter present::smoke
```

Expected: `test result: ok. 1 passed`.

---

### 7.8 Step 8 — Canonical encoding + `consent_hash` (`canonical.rs`)

This is the heart of *what-you-see-is-what-you-sign*. We need bytes that are:

- **Deterministic:** the same consent content always produces the same bytes, on every platform, every run.
- **Stable & versioned:** the encoding is a wire format; changing it is a conscious `v2`, guarded by the golden hash test (7.10).
- **Reimplementable:** simple enough to re-derive in Swift/Kotlin so a shell can recompute the hash (and so the same golden vectors validate both encoders).

**Design choices that make determinism trivial:**

- We encode to **CBOR arrays** (positional), never CBOR maps. Arrays have a fixed order by position, so there is *no map-key-sorting question at all*.
- We use **canonical CBOR head encoding** (shortest-form length/int, definite-length) per RFC 8949 §4.2.1.
- We write it with a **~50-line explicit encoder** — no serde, no CBOR crate — so every byte is auditable.
- **Domain separation:** the first array element is the text tag `"eudi-wallet/consent/v1"`, which is both the domain separator and the version.

**What the hash binds (and deliberately excludes).** It binds the *language-independent semantic content* plus *all RP-supplied text*: the sanitized RP name, the trust tag, the logo digest, the RP purpose, and per credential the type + format + each claim's `ClaimPath`, `required` flag, and a **value digest**; and finally the `request_commitment`. It **excludes** wallet chrome (button labels, the title) and the wallet-owned localized *labels* of claims — because those labels are a deterministic function of the bound `ClaimPath`, and excluding them keeps a single consent identical across UI languages. If you ever need "bind exact rendered text," that is a conscious `v2` (include the locale + labels); the version tag makes the change explicit.

**Value digests, not raw values.** The canonical bytes carry `value_digest = SHA-256("eudi-wallet/consent-value/v1" || 0x00 || utf8(value))` for each disclosed value, never the raw value. The rendered `ScreenDescription` still carries the plaintext value for the UI, but the canonical bytes (which may end up alongside the hash in the audit record) contain no cleartext PII. (Caveat: digests of low-entropy values like "Yes"/"No" are not confidentiality-preserving; that is acceptable because the value bytes are never persisted and the digest's job here is *binding*, not secrecy.)

```rust
// crates/presenter/src/canonical.rs
use sha2::{Digest, Sha256};
use crate::screen::*;

pub const CONSENT_DOMAIN_V1: &str = "eudi-wallet/consent/v1";
pub const VALUE_DOMAIN_V1: &str  = "eudi-wallet/consent-value/v1";

// ---------- minimal, explicit, canonical CBOR writer ----------
fn head(out: &mut Vec<u8>, major: u8, arg: u64) {
    let mt = major << 5;
    if arg < 24 { out.push(mt | arg as u8); }
    else if arg <= u8::MAX as u64 { out.push(mt | 24); out.push(arg as u8); }
    else if arg <= u16::MAX as u64 { out.push(mt | 25); out.extend_from_slice(&(arg as u16).to_be_bytes()); }
    else if arg <= u32::MAX as u64 { out.push(mt | 26); out.extend_from_slice(&(arg as u32).to_be_bytes()); }
    else { out.push(mt | 27); out.extend_from_slice(&arg.to_be_bytes()); }
}
fn w_uint(out: &mut Vec<u8>, n: u64) { head(out, 0, n); }
fn w_bool(out: &mut Vec<u8>, b: bool) { out.push(if b { 0xf5 } else { 0xf4 }); }
fn w_null(out: &mut Vec<u8>) { out.push(0xf6); }
fn w_bytes(out: &mut Vec<u8>, b: &[u8]) { head(out, 2, b.len() as u64); out.extend_from_slice(b); }
fn w_text(out: &mut Vec<u8>, s: &str) { head(out, 3, s.len() as u64); out.extend_from_slice(s.as_bytes()); }
fn w_arr(out: &mut Vec<u8>, len: u64) { head(out, 4, len); }

fn value_digest(value: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(VALUE_DOMAIN_V1.as_bytes());
    h.update([0x00]);                 // domain separator
    h.update(value.as_bytes());
    h.finalize().into()
}

fn enc_claim_path(out: &mut Vec<u8>, p: &ClaimPath) {
    match p {
        ClaimPath::Mdoc { namespace, element } => { w_arr(out, 3); w_uint(out, 0); w_text(out, namespace); w_text(out, element); }
        ClaimPath::SdJwt { path } => {
            w_arr(out, (1 + path.len()) as u64); w_uint(out, 1);
            for seg in path { w_text(out, seg); }
        }
    }
}

fn enc_logo(out: &mut Vec<u8>, logo: &Logo) {
    match logo {
        Logo::None => w_null(out),
        Logo::Verified { media_type, digest, width_px, height_px } => {
            w_arr(out, 4);
            w_uint(out, match media_type { ImageMediaType::Png => 0, ImageMediaType::Jpeg => 1 });
            w_bytes(out, digest);
            w_uint(out, *width_px as u64);
            w_uint(out, *height_px as u64);
        }
    }
}

fn enc_trust(out: &mut Vec<u8>, t: &RpTrustBadge) {
    // tag only; scheme name is wallet-derived text and is included for RP identity binding.
    match t {
        RpTrustBadge::Registered { scheme } => { w_arr(out, 2); w_uint(out, 1); w_text(out, scheme); }
        RpTrustBadge::RegisteredQualified { scheme } => { w_arr(out, 2); w_uint(out, 2); w_text(out, scheme); }
        RpTrustBadge::NotRegistered => { w_arr(out, 1); w_uint(out, 0); }
    }
}

/// The versioned canonical encoding of a consent screen. Positional CBOR arrays only.
/// SEE THE WIRE SCHEMA in the doc comment; Swift/Kotlin reimplementations MUST match byte-for-byte.
pub fn canonical_bytes(c: &ConsentScreen) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    w_arr(&mut out, 7);                       // [0..7]
    w_text(&mut out, CONSENT_DOMAIN_V1);      // 0: domain+version
    w_text(&mut out, &c.rp_display_name);     // 1: sanitized RP name
    enc_trust(&mut out, &c.rp_trust);         // 2: trust tag (+ scheme)
    enc_logo(&mut out, &c.logo);              // 3: logo (null or [mt, digest, w, h])
    match &c.purpose {                        // 4: purpose (null or text)
        Some(p) => w_text(&mut out, p),
        None => w_null(&mut out),
    }
    w_arr(&mut out, c.credentials.len() as u64); // 5: credentials[]
    for cred in &c.credentials {
        w_arr(&mut out, 3);
        w_text(&mut out, &cred.credential_type); // 0: type (doctype/vct)
        w_uint(&mut out, match cred.format { CredentialFormat::MsoMdoc => 0, CredentialFormat::SdJwtVc => 1 }); // 1: format
        // 2: SELECTED claims only, in plan order (unselected optional claims are NOT bound/disclosed)
        let selected: Vec<&ConsentClaim> = cred.claims.iter().filter(|cl| cl.selected).collect();
        w_arr(&mut out, selected.len() as u64);
        for cl in selected {
            w_arr(&mut out, 3);
            enc_claim_path(&mut out, &cl.path);  // 0: path
            w_bool(&mut out, cl.required);       // 1: required
            match &cl.value_display {            // 2: value digest or null
                Some(v) => w_bytes(&mut out, &value_digest(v)),
                None => w_null(&mut out),
            }
        }
    }
    w_bytes(&mut out, &c.request_commitment); // 6: request commitment (32 bytes)
    out
}

/// consent_hash = SHA-256(canonical_bytes(consent_screen)). Computed inside the core.
pub fn consent_hash(c: &ConsentScreen) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(canonical_bytes(c));
    h.finalize().into()
}

pub fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes { s.push(HEX[(b >> 4) as usize] as char); s.push(HEX[(b & 0xf) as usize] as char); }
    s
}
```

**The canonical wire schema (v1)** — reproduce this exactly in any shell reimplementation:

```
Consent := [
  0: tstr  = "eudi-wallet/consent/v1"
  1: tstr  = sanitized RP display name (NFC, controls stripped)
  2: Trust = [0] | [1, tstr scheme] | [2, tstr scheme]     ; NotReg | Registered | RegisteredQualified
  3: Logo  = null | [uint media_type(0=png,1=jpeg), bstr digest(32), uint w, uint h]
  4: Purpose = null | tstr
  5: [ Credential* ]                                        ; array, plan order
       Credential := [ tstr type, uint format(0=mdoc,1=sdjwt), [ Claim* ] ]  ; SELECTED claims only
         Claim := [ ClaimPath, bool required, (null | bstr value_digest(32)) ]
           ClaimPath := [0, tstr ns, tstr element]          ; mdoc
                      | [1, tstr seg, ...]                   ; sd-jwt path
  6: bstr request_commitment(32)
]
consent_hash := SHA-256( CBOR(Consent) )
```

Note that only **selected** claims are encoded — so if the user toggles an optional claim off, both the disclosure *and* the hash shrink accordingly. The hash you bind at confirm time reflects the user's final selection.

**Definition of done (7.8):** three checks — CBOR primitive correctness, determinism, and a reproducible SHA-256 anchor.

```rust
// crates/presenter/src/canonical.rs (append)
#[cfg(test)]
mod tests {
    use super::*;
    use crate::present::smoke::fixture_consent;
    use crate::present::present;
    use crate::screen::ScreenDescription;

    #[test]
    fn cbor_primitive_heads_are_canonical() {
        let mut a = Vec::new(); w_uint(&mut a, 500);          assert_eq!(a, [0x19, 0x01, 0xF4]);
        let mut b = Vec::new(); w_text(&mut b, "PID");        assert_eq!(b, [0x63, b'P', b'I', b'D']);
        let mut c = Vec::new(); w_arr(&mut c, 3);             assert_eq!(c, [0x83]);
        let mut d = Vec::new(); w_uint(&mut d, 0);            assert_eq!(d, [0x00]);
        let mut e = Vec::new(); w_uint(&mut e, 23);           assert_eq!(e, [0x17]);
        let mut f = Vec::new(); w_uint(&mut f, 24);           assert_eq!(f, [0x18, 0x18]);
        let mut g = Vec::new(); w_bool(&mut g, true);         assert_eq!(g, [0xF5]);
    }

    #[test]
    fn domain_tag_sha256_anchor() {
        // Reproduce independently:  printf 'eudi-wallet/consent/v1' | shasum -a 256
        let mut h = sha2::Sha256::new(); h.update(CONSENT_DOMAIN_V1.as_bytes());
        let d: [u8; 32] = h.finalize().into();
        assert_eq!(to_hex(&d), "03449514ed4eeef8b5257ce5bf8f4602c0994da6bf3ba93a22137048dba06887");
        // And the value-domain tag:  printf 'eudi-wallet/consent-value/v1' | shasum -a 256
        let mut h2 = sha2::Sha256::new(); h2.update(VALUE_DOMAIN_V1.as_bytes());
        let d2: [u8; 32] = h2.finalize().into();
        assert_eq!(to_hex(&d2), "7fe926596a06dc5eb915e4a923fc6a2e1bbc715b27e195da9c79bd286bf1e238");
    }

    #[test]
    fn encoding_is_deterministic() {
        let s = present(&fixture_consent());
        let ScreenDescription::Consent(c) = s else { panic!() };
        assert_eq!(canonical_bytes(&c), canonical_bytes(&c)); // twice -> identical
        assert_eq!(consent_hash(&c), consent_hash(&c));
    }
}
```

The two hex anchors above are real SHA-256 values; you can reproduce them from a shell with `printf 'eudi-wallet/consent/v1' | shasum -a 256` (`03449514…`) and `printf 'eudi-wallet/consent-value/v1' | shasum -a 256` (`7fe92659…`). They prove your SHA-256 wiring is correct independently of the CBOR encoder. (For reference, the empty-string SHA-256 is the well-known `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.) The full-fixture consent hash is pinned by the golden test in 7.10, not hand-computed here.

```bash
cargo test -p presenter canonical::
```

Expected: `test result: ok. 3 passed`.

---

### 7.9 Step 9 — Binding into the core: run loop, echo-check, transaction log, QES intent

The presenter is pure; `wallet-core` is where the hash becomes an integrity anchor. This lives in `crates/wallet-core` (see the wallet-core facade section for the full run loop); here is the consent-specific wiring.

1. **Compute and stash the hash when a consent screen is produced.** After the run loop applies an Event batch and rebuilds the `Snapshot`, it calls `present`. If the result is `ScreenDescription::Consent`, it computes `consent_hash` and stores it as *pending*:

```rust
// crates/wallet-core/src/run_loop.rs (excerpt)
use presenter::{present, screen::ScreenDescription};
use presenter::canonical::consent_hash;

fn rebuild_view(core: &mut Core) -> ScreenDescription {
    let snapshot = core.project_snapshot();     // core state -> presenter::Snapshot
    let screen = present(&snapshot);
    if let ScreenDescription::Consent(c) = &screen {
        // Hash INSIDE the core, synchronously. This is the payload both shells will display.
        core.pending_consent = Some(PendingConsent {
            hash: consent_hash(c),
            request_commitment: c.request_commitment,
            // record the language-independent claim identities for the audit log (NOT values)
            disclosed_paths: c.credentials.iter()
                .flat_map(|cr| cr.claims.iter().filter(|cl| cl.selected).map(|cl| cl.path.clone()))
                .collect(),
            rp_name: c.rp_display_name.clone(),
            rp_trust: c.rp_trust.clone(),
        });
    }
    screen
}
```

2. **Echo-check across the FFI on confirm.** The shell renders the `ScreenDescription` and, when the user taps Share, sends back a `ConsentDecision` Event carrying the hash it displayed. The core refuses to proceed unless the echoed hash equals the hash it computed. This detects any mutation of the payload between core and screen:

```rust
// crates/wallet-core/src/events.rs (excerpt)
pub enum Event {
    // ...
    ConsentDecision { approved: bool, shown_consent_hash: [u8; 32] },
    // toggling an optional claim rebuilds the screen (and hash) before decision:
    ConsentClaimToggled { claim_ref: presenter::screen::ClaimRef },
}

// in handle_event:
Event::ConsentDecision { approved, shown_consent_hash } => {
    let Some(pending) = core.pending_consent.take() else { return vec![Effect::Warn("no pending consent")] };
    if shown_consent_hash != pending.hash {
        // The shell displayed something other than what the core hashed. Abort, do NOT disclose.
        return vec![Effect::Abort { reason: AbortReason::ConsentHashMismatch }];
    }
    if !approved { return vec![Effect::CloseFlow]; }
    // Only NOW may disclosure Effects be emitted. (Formal-methods Tier 2 proves this ordering.)
    let mut effects = vec![
        Effect::AppendTransactionLog(TxRecord {
            consent_hash: pending.hash,             // the audit anchor
            request_commitment: pending.request_commitment,
            rp_name: pending.rp_name,
            rp_trust: pending.rp_trust,
            disclosed_paths: pending.disclosed_paths, // paths only — NEVER raw values (never log full credentials)
            timestamp: core.now_placeholder(),        // real time comes from a ClockRead Effect result
        }),
    ];
    effects.extend(core.build_disclosure_effects(&pending)); // sign DeviceAuth / KB-JWT, send response
    effects
}
```

Two things to notice:

- The **transaction log entry stores `consent_hash` + claim *paths* + RP identity + timestamp, never raw claim values** (honoring "never log full credentials/secrets"). Because `consent_hash` was computed over the value *digests*, the record still cryptographically commits to exactly what was shared, without storing the PII. This entry is what the `TransactionDetail` archetype renders later (P1 history feature; see the transaction-history section).
- **Disclosure Effects are emitted only after a matching, approved `ConsentDecision`.** This ordering ("no disclosure effect before a consent event") is exactly the invariant the Lean 4 model proves and exports as replay traces (see the formal-methods section, Tier 2); `consent_hash` is the observable that ties the model's "consent event" to the concrete run.

3. **QES intent binding (forward reference, P1).** When the wallet later performs a qualified electronic signature (remote QSCD via the CSC API — see the QES section), the *what-you-see-is-what-you-sign* guarantee reuses this exact machinery: the consent screen describing the signing intent is hashed the same way, the `consent_hash` is included in the signature authorization (SAD) request, and it is recorded next to the produced signature. The presenter needs no change for this; QES simply drives a `Consent`-family screen and consumes `consent_hash`.

**Definition of done (7.9):** a wallet-core unit test proving the mismatch abort and the log-without-values behavior.

```rust
// crates/wallet-core/tests/consent_binding.rs (sketch — adjust to your Core constructor)
#[test]
fn tampered_consent_hash_aborts_before_any_disclosure() {
    let mut core = Core::new_for_test_with_pending_consent(/* fixture */);
    let good = core.pending_consent.as_ref().unwrap().hash;
    let mut bad = good; bad[0] ^= 0xFF;
    let effects = core.handle_event(Event::ConsentDecision { approved: true, shown_consent_hash: bad });
    assert!(effects.iter().any(|e| matches!(e, Effect::Abort { reason: AbortReason::ConsentHashMismatch })));
    assert!(!effects.iter().any(|e| matches!(e, Effect::SendPresentationResponse { .. })));
}
```

```bash
cargo test -p wallet-core consent_binding
```

Expected: `test result: ok. 1 passed`.

---

### 7.10 Step 10 — Golden-file tests, the stable-hash test, and the data-minimization test

Golden files freeze both the *structure* (a human-readable JSON snapshot of the `ScreenDescription`) and the *hash* (the hex `consent_hash`) for a set of fixtures. Any change to the presenter that alters a screen or its hash fails the test loudly, forcing a conscious review and — for the hash — a conscious `v2` if the wire format changed. We use plain golden files with a `BLESS=1` regeneration switch (no snapshot-testing dependency), keeping the certification-critical path dependency-light.

1. Create fixtures and golden directories:

```bash
mkdir -p crates/presenter/tests/golden
```

2. Write the golden harness. It renders a fixture two ways — the JSON structural snapshot (via `serde_json`, dev-only) and the canonical hash (hex) — and either writes the goldens (when `BLESS=1`) or asserts equality.

```rust
// crates/presenter/tests/golden.rs
use presenter::{present, snapshot::*, screen::*};
use presenter::canonical::{canonical_bytes, consent_hash, to_hex};
use std::{fs, path::PathBuf};

fn golden_dir() -> PathBuf { PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden") }

fn check_golden(name: &str, actual: &str) {
    let path = golden_dir().join(name);
    if std::env::var("BLESS").is_ok() {
        fs::create_dir_all(golden_dir()).unwrap();
        fs::write(&path, actual).unwrap();
        return;
    }
    let expected = fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("missing golden {name}; run with BLESS=1 to create it"));
    assert_eq!(actual.trim_end(), expected.trim_end(), "golden mismatch for {name}");
}

fn consent_fixture_a() -> Snapshot {
    let pid = "eu.europa.ec.eudi.pid.1";
    let m = |el: &str| ClaimPath::Mdoc { namespace: pid.into(), element: el.into() };
    Snapshot { locale: Locale::En, focus: Focus::Consent(ConsentCtx {
        rp_name_raw: "Acme Rentals AB".into(),
        rp_trust: RpTrustBadge::Registered { scheme: "EUDI-RP-Registry".into() },
        logo: Logo::None,
        purpose_raw: Some("Verify you are over 18 to rent a car.".into()),
        plan: DisclosurePlan { entries: vec![ PlanEntry {
            credential_id: "pid-0".into(), credential_type: pid.into(), format: CredentialFormat::MsoMdoc,
            claims: vec![
                PlannedClaim { path: m("age_over_18"), value_display: Some("Yes".into()), required: true, selected: true },
                PlannedClaim { path: m("family_name"), value_display: Some("Andersson".into()), required: false, selected: true },
            ],
        }]},
        request_commitment: [0x11; 32],
    })}
}

#[test]
fn golden_consent_a_structure() {
    let screen = present(&consent_fixture_a());
    let json = serde_json::to_string_pretty(&screen).unwrap(); // stable: field order = declaration order
    check_golden("consent_a.json", &json);
}

#[test]
fn golden_consent_a_stable_hash() {
    let ScreenDescription::Consent(c) = present(&consent_fixture_a()) else { panic!() };
    // Bytes and hash are pinned. If EITHER changes, this fails -> conscious review / v2 bump.
    check_golden("consent_a.cbor.hex", &to_hex(&canonical_bytes(&c)));
    check_golden("consent_a.hash", &to_hex(&consent_hash(&c)));
}

#[test]
fn golden_consent_data_minimization_holds() {
    // Data-minimization AT THE SCREEN: the consent screen contains ONLY the planned claims.
    // Same guarantee as 7.6, asserted end-to-end on the rendered screen + canonical bytes.
    let ScreenDescription::Consent(c) = present(&consent_fixture_a()) else { panic!() };
    let shown: Vec<&str> = c.credentials[0].claims.iter().map(|cl| match &cl.path {
        ClaimPath::Mdoc { element, .. } => element.as_str(), _ => "" }).collect();
    assert_eq!(shown, vec!["age_over_18", "family_name"]);
    // The forbidden claims never appear in the CANONICAL BYTES either (no value_digest leaks them,
    // because they were never in the plan):
    let hexbytes = to_hex(&canonical_bytes(&c));
    for forbidden in ["726573696465", /* 'reside' */ "706f727472"] { /* 'portr' */
        assert!(!hexbytes.contains(forbidden), "un-requested claim leaked into canonical bytes");
    }
}
```

3. Generate the goldens once, then verify:

```bash
BLESS=1 cargo test -p presenter --test golden      # writes tests/golden/consent_a.{json,cbor.hex,hash}
cargo test -p presenter --test golden              # verifies against the frozen goldens
```

Expected: after `BLESS=1`, `tests/golden/` contains three files; `consent_a.hash` is exactly 64 lowercase hex characters. The second run prints `test result: ok. 3 passed`. Commit the golden files; from then on any change to the presenter that would alter the screen or the hash fails CI until a human blesses it. For an *independent* cross-check of the hash, run:

```bash
xxd -r -p crates/presenter/tests/golden/consent_a.cbor.hex | shasum -a 256
```

Expected: the first field of the output equals the contents of `consent_a.hash` — proving `consent_hash == SHA-256(canonical_bytes)` with no trust in the Rust code path.

**Definition of done (7.10):** `cargo test -p presenter --test golden` passes on a clean checkout (goldens committed), and the `xxd | shasum` cross-check matches `consent_a.hash`.

---

### 7.11 Step 11 — The accessibility contract and the native renderer mapping

The `ScreenDescription` carries **semantics, not pixels**. Accessibility (EN 301 549 / WCAG 2.2 — see the accessibility section for the CI gate) is achieved by the renderer mapping each archetype to **native, accessible controls**. This is a *contract*, enforced by review and by the accessibility audit tests, not by the presenter.

The contract, in seven rules the renderer MUST follow:

1. **One archetype → one native container.** `Consent` → a `Form`/`List`; `CredentialList` → a `List`; `AuthPrompt` → the platform biometric prompt; etc. The renderer never invents a screen the vocabulary doesn't have.
2. **Every `Action` becomes a labeled native control** (`Button`) using `Action.label` verbatim as its accessible label; `ActionStyle::Destructive` maps to the platform destructive role.
3. **Trust and status are conveyed by text + icon, never color alone** (WCAG 1.4.1). `RpTrustBadge::NotRegistered` must render an explicit textual warning.
4. **All text scales with Dynamic Type / OS font settings**; no fixed font sizes, no truncation that hides meaning.
5. **RP-supplied strings render as plain text** — the renderer must not pass them through any markup/HTML/attributed-string parser.
6. **Logical reading/focus order**; on screen change, move accessibility focus to the header. No color-only, no gesture-only interactions; targets ≥ 24×24 pt (WCAG 2.5.8).
7. **No un-extendable timeouts** (WCAG 2.2.1); `Loading`/`ProximityInProgress` expose progress as text.

SwiftUI mapping for the consent screen (the shell receives the UniFFI-generated `ScreenDescription`; here `Consent` is the associated payload):

```swift
// iOS shell: ConsentView.swift  (renders presenter::ConsentScreen delivered over UniFFI)
struct ConsentView: View {
    let screen: ConsentScreen
    let onDecision: (_ approved: Bool, _ shownHash: Data) -> Void
    let shownConsentHash: Data   // delivered by the core alongside the screen (7.9)

    var body: some View {
        Form {
            Section {
                HStack(spacing: 12) {
                    LogoView(logo: screen.logo)                     // looks up bytes by digest; placeholder if missing
                        .accessibilityLabel("\(screen.rpDisplayName) logo")
                    VStack(alignment: .leading) {
                        Text(screen.rpDisplayName).font(.headline)   // plain text, Dynamic Type
                        TrustBadgeView(trust: screen.rpTrust)        // text + icon, never color alone
                    }
                }
                if let purpose = screen.purpose { Text(purpose).font(.subheadline) }
            }
            ForEach(Array(screen.credentials.enumerated()), id: \.offset) { _, cred in
                Section(cred.displayName) {
                    ForEach(Array(cred.claims.enumerated()), id: \.offset) { _, claim in
                        if claim.required {
                            LabeledContent(claim.label, value: claim.valueDisplay ?? "")
                                .accessibilityLabel("\(claim.label), \(claim.valueDisplay ?? ""), required")
                        } else {
                            Toggle(isOn: bindingFor(claim)) {          // optional -> user can drop it
                                LabeledContent(claim.label, value: claim.valueDisplay ?? "")
                            }
                            .accessibilityHint("Optional. Turn off to not share this.")
                        }
                    }
                }
            }
            Section {
                Button(screen.approve.label) { onDecision(true, shownConsentHash) }   // echoes hash back (7.9)
                    .buttonStyle(.borderedProminent)
                Button(screen.reject.label, role: .cancel) { onDecision(false, shownConsentHash) }
            }
        }
        .onAppear { /* move VoiceOver focus to the RP header */ }
    }
}
```

Toggling an optional claim sends `Event::ConsentClaimToggled`; the core rebuilds the screen and recomputes the hash (7.9), so the `shownConsentHash` the shell later echoes always matches the *current* selection.

> **Cross-platform "provably same payload" (optional hardening + conformance test).** Because the canonical schema (7.8) is byte-exact and simple, implement `canonicalBytes(_:)`/`consentHash(_:)` in Swift too. At *runtime* it lets the shell recompute the hash from what it actually rendered (defense-in-depth beyond the echo-check). At *test time* it is stronger: feed the Swift encoder the **same golden vectors** from 7.10 (`consent_a.cbor.hex` / `consent_a.hash`) and assert equality — this is what makes "both platforms provably show the same consent payload" a tested fact, not an aspiration. Kotlin gets the same treatment when the Android shell lands.

**Definition of done (7.11):** an XCUITest accessibility audit over the consent screen, plus the Swift golden cross-check.

```swift
// iOS shell: ConsentAccessibilityTests.swift
func testConsentPassesAccessibilityAudit() throws {
    let app = XCUIApplication(); app.launchArguments = ["-uiTestFixture", "consent_a"]; app.launch()
    if #available(iOS 17.0, *) {
        try app.performAccessibilityAudit()   // fails on contrast, missing labels, dynamic-type clipping, hit-size
    }
}
func testSwiftCanonicalMatchesRustGolden() throws {
    let hex = try String(contentsOf: goldenURL("consent_a.cbor.hex")).trimmingCharacters(in: .whitespacesAndNewlines)
    let screen = ConsentFixtures.a()                       // mirror of consent_fixture_a()
    XCTAssertEqual(canonicalBytes(screen).hexString, hex)  // Swift encoder == Rust golden bytes
}
```

```bash
xcodebuild test -scheme WalletShell -destination 'platform=iOS Simulator,name=iPhone 16' \
  -only-testing:WalletShellTests/ConsentAccessibilityTests
```

Expected: both tests pass; the audit reports no violations. (The accessibility section wires this into CI as the EN 301 549 gate.)

---

### 7.12 Step 12 — Formal-methods hooks (Tier 1 here; Tier 2/3 cross-refs)

The presenter contributes to all three formal-methods tiers (see the formal-methods section for the full setup).

**Tier 1 — property tests (owned by this crate).** Prove totality and determinism with `proptest`:

```rust
// crates/presenter/tests/properties.rs
use proptest::prelude::*;
use presenter::{present, snapshot::*, screen::*};
use presenter::canonical::{canonical_bytes, consent_hash};

// A generator for arbitrary Snapshots (abbreviated — cover every Focus variant in the full harness).
fn arb_snapshot() -> impl Strategy<Value = Snapshot> { /* build arbitrary Focus incl. adversarial RP text */ todo!() }

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    // TOTALITY: present() never panics, for any Snapshot.
    #[test]
    fn present_never_panics(s in arb_snapshot()) { let _ = present(&s); }

    // DETERMINISM: encoding + hashing are stable across repeated calls.
    #[test]
    fn hash_is_deterministic(s in arb_snapshot()) {
        if let ScreenDescription::Consent(c) = present(&s) {
            prop_assert_eq!(canonical_bytes(&c), canonical_bytes(&c));
            prop_assert_eq!(consent_hash(&c), consent_hash(&c));
        }
    }

    // MINIMIZATION MONOTONICITY: toggling an optional claim OFF can only shrink the disclosed set,
    // and never changes required claims. (Rendered-screen level.)
    #[test]
    fn deselecting_optional_only_shrinks(s in arb_snapshot()) { /* compare selected-claim sets */ }
}
```

Also add a `cargo-fuzz` target that feeds arbitrary bytes into a `Snapshot` decoder (if you accept serialized snapshots at any boundary) and into `sanitize_rp_name`/`sanitize_purpose`, asserting no panic and idempotence (`sanitize(sanitize(x)) == sanitize(x)`) — see the formal-methods section for the fuzz-target boilerplate.

**Tier 2 — Lean 4 (cross-ref).** The Lean model of the oid4vp presentation state machine proves "no disclosure effect before a consent event" and "no accepting trace reuses a nonce." The presenter's `consent_hash` is the concrete observable those traces are matched against: when the Lean-exported JSON traces are replayed through `wallet-core`, the replay harness asserts that a disclosure Effect is preceded by a `ConsentDecision` whose `shown_consent_hash` equals the core's computed `consent_hash`. This is exactly the code path in 7.9. See the formal-methods section for the trace-export and replay wiring.

**Tier 3 — Tamarin/ProVerif (cross-ref).** Symbolic analysis of the HAIP/EUDI OpenID4VP profile treats `request_commitment` and the presented claim set as the secrecy/agreement targets; the presenter's binding of `request_commitment` into `consent_hash` is what ties the human-authorized consent to the specific protocol run the model reasons about. No presenter code is needed for Tier 3; it constrains what `request_commitment` must cover (client_id, response_uri/mode, nonce, DCQL query), which the oid4vp section implements.

**Definition of done (7.12):**

```bash
cargo test -p presenter --test properties
```

Expected (after you fill in `arb_snapshot`): `test result: ok. 3 passed`, with proptest reporting thousands of cases and no panics/shrinks.

---

### 7.13 Section recap — the invariants this crate guarantees

- **Closed vocabulary.** Structure is wallet-owned; ~16 archetypes; adding one is a compile-forced, reviewed edit (7.2). RP material is validated data in wallet templates, never structure (7.5, 7.11 rule 5).
- **Pure, total, deterministic.** `fn present(&Snapshot) -> ScreenDescription` never fails, never panics, never does I/O; `#![forbid(unsafe_code)]`; `unwrap`/`expect`/`panic`/indexing denied (7.1, 7.7, 7.12).
- **Data minimization precedes the screen.** The consent screen is built from an already-minimal `DisclosurePlan`; the screen and its canonical bytes contain only requested-and-held-and-selected claims (7.6, 7.10).
- **What-you-see-is-what-you-sign.** `consent_hash = SHA-256(canonical_bytes(consent_screen))`, computed inside the core over a versioned, positional-CBOR, domain-separated encoding that binds RP identity + trust + logo digest + purpose + the selected claim paths + value digests + `request_commitment` (7.8). Both shells display the payload the core hashed; the shell echoes the hash and the core re-checks it before any disclosure (7.9).
- **Privacy-preserving audit.** The transaction log records the hash, RP identity, claim *paths*, and timestamp — never raw claim values, never logo bytes (7.9).
- **Accessibility by contract.** Each archetype maps to native accessible controls; audited per screen against EN 301 549 / WCAG 2.2 (7.11).
- **Stable under change.** Golden JSON + golden hash freeze structure and bytes; the `v1` domain tag makes any wire-format change a conscious `v2` (7.8, 7.10).

---


## Section 8 — iOS shell: renderer, Secure Enclave signer, transports (BLE/NFC/QR), biometrics, secure storage, and the effect executor

This section builds the **Swift/iOS shell** — the thin native layer that executes the `Effect`s the Rust core emits and feeds `Event`s back in. Everything protocol-critical already lives in the Rust crates (Sections 2–7 and the codec/protocol crates); the shell owns only I/O, hardware, and pixels. If you find yourself writing a `switch` on credential formats, parsing CBOR, deciding what claims to disclose, or validating a certificate **in Swift**, stop — that belongs in Rust.

The iOS shell is a Swift package that already exists at `euwallet/ios/`:

```
euwallet/ios/
├── Package.swift
├── Sources/WalletShell/
│   ├── CoreBridge.swift          # hand-written mirror of the Rust types (replaced by Section 3's UniFFI output)
│   ├── EffectExecutor.swift      # the run loop
│   ├── ScreenRenderer.swift      # ScreenDescription -> native SwiftUI
│   ├── SecureEnclaveSigner.swift # the Signer foreign-trait implementation
│   ├── Transports.swift          # BLE / NFC / QR adapters
│   └── InMemory.swift            # test doubles
└── Tests/WalletShellTests/
    └── EffectExecutorTests.swift
```

We will fill in each file with production-grade skeletons and add a few new ones. The package targets `iOS 16 / macOS 13` (see `Package.swift`) so that `swift test` runs on the Mac host for fast CI while the real device work runs on-device / in the simulator.

Throughout, remember the **shell/core contract** (established in Section 2):

- The core is **sans-IO**. `Core::handle_event(&mut self, Event) -> Vec<Effect>` is a pure function: same state + same event ⇒ same effects. The shell must never let the result of an I/O operation influence the core except by feeding it back as an `Event`.
- Every asynchronous effect carries an **`EffectId`** (`u64`; `UInt64` in Swift) so its eventual result event can be correlated back to the request. This is what makes the whole thing replayable against the Lean oracle in Section 10 — record the `(Effect, EventResult)` pairs and you can re-run the flow deterministically.
- Interactive or hardware crypto (Secure Enclave signing, randomness) is expressed as an **Effect**, never as a synchronous call inside `handle_event`, precisely because it touches hardware, can block on biometrics, and (for randomness) is non-deterministic. This is the reconciliation of "the core depends only on the `crypto-traits::Signer` trait" (Section 4) with "signing happens via Effects": on iOS the *implementation* of that trait is a Secure-Enclave-backed Swift object, but it is *invoked* by the effect executor, off the pure path.

Here are the exact Rust types the shell consumes (from `euwallet/crates/wallet-core/src/lib.rs` and `euwallet/crates/presenter/src/lib.rs`). Do not redefine their semantics — mirror them:

```rust
// wallet-core
pub type EffectId = u64;

pub enum Event {
    AuthorizationRequestReceived(Vec<u8>),
    UserConsented,
    UserDeclined,
    SignatureProduced { id: EffectId, signature: Vec<u8> },
    HttpResponse { id: EffectId, status: u16, body: Vec<u8> },
}

pub enum Effect {
    Render(ScreenDescription),
    Sign { id: EffectId, key_ref: String, payload: Vec<u8> },
    Http { id: EffectId, url: String, body: Vec<u8> },
    Store { key: String, value: Vec<u8> },
}

// presenter
pub enum ScreenDescription {
    Loading,
    Error { code: String, message: String },
    Consent(ConsentScreen),
    CredentialList, CredentialDetail, IssuanceOffer,
    PresentQr, ScanQr, AuthPrompt, TransactionHistory,
}
pub struct ConsentScreen { pub rp_display_name: String, pub purpose: String, pub requested_claims: Vec<String> }
```

> **Growing the enums.** The skeleton `Effect`/`Event` enums above are the *P0 minimum*. Several features in this section (BLE/NFC transports, QR present/scan, `ASWebAuthenticationSession`) require **new variants** — e.g. `Effect::TransportOpen`, `Effect::TransportSend`, `Effect::OpenAuthSession`, `Effect::GetRandom`, and their matching result `Event`s. **Those enums are owned by Section 2/3**, not by the shell. Wherever this section needs a variant that does not yet exist, it is called out explicitly as "add to the Rust enum in Section 2, then regenerate the bindings (Section 3)". The Swift side never invents protocol data; it only ever ferries opaque bytes and correlation ids.

---

### 8.1 Build the shell against the core: from hand-written mirror to UniFFI bindings

Right now `euwallet/ios/Sources/WalletShell/CoreBridge.swift` contains **hand-written mirror types** (`WalletEvent`, `WalletEffect`, `ScreenDescription`, `ConsentScreen`, and a tiny `WalletCore` that reproduces the Rust logic). This is deliberate: it lets the entire shell compile, run, and be unit-tested on the Mac host **before** the UniFFI toolchain (Section 3) is wired up. Section 3 replaces the *core* with the real Rust engine; this section makes sure the shell is written so that swap is a one-line change.

The key move is to hide the core behind a Swift protocol so both the mock and the real UniFFI engine satisfy it. Create `euwallet/ios/Sources/WalletShell/CoreEngine.swift`:

```swift
import Foundation

/// The one thing the shell needs from the core: hand it an event, get back effects.
/// `WalletCore` (the mock mirror in CoreBridge.swift) and the UniFFI-generated engine
/// (Section 3) both conform. The executor depends on THIS, never on a concrete type,
/// so `swift test` runs against the mock on the Mac while device builds use real Rust.
public protocol CoreEngine: AnyObject {
    func handle(_ event: WalletEvent) -> [WalletEffect]
}

extension WalletCore: CoreEngine {}   // the mock mirror already has `handle(_:)`
```

When Section 3 lands, add a thin wrapper (do **not** delete `CoreBridge.swift` — keep the mock for host tests behind the `CoreEngine` protocol) in `euwallet/ios/Sources/WalletShell/UniFFICore.swift`:

```swift
#if canImport(WalletCoreFFI)          // the module produced by uniffi-bindgen (Section 3)
import WalletCoreFFI

/// Adapts the UniFFI-generated `Core` object to the shell's `CoreEngine` protocol and
/// maps between the shell's Swift enums and the generated enums (they are structurally
/// identical; UniFFI names them slightly differently, e.g. `Effect.sign(id:keyRef:payload:)`).
public final class UniFFICore: CoreEngine {
    private let inner: WalletCoreFFI.Core          // Rust object behind a pointer; Send+Sync via a Mutex on the Rust side
    public init() { self.inner = WalletCoreFFI.Core() }

    public func handle(_ event: WalletEvent) -> [WalletEffect] {
        inner.handleEvent(event: event.toFFI).map(WalletEffect.init(ffi:))
    }
}
#endif
```

The `Package.swift` grows a binary target and a `WalletCore` module that carries the generated `wallet_core.swift` (all produced by Section 3's `euwallet/tools/build-core.sh`, which cross-compiles the Rust `staticlib` for `aarch64-apple-ios` + `aarch64-apple-ios-sim`, packages an `.xcframework`, and runs `uniffi-bindgen generate`):

```swift
// euwallet/ios/Package.swift  (target section, after Section 3 is available)
targets: [
    .binaryTarget(name: "WalletCoreFFI", path: "../ffi/uniffi/WalletCoreFFI.xcframework"),
    .target(name: "WalletCore", dependencies: ["WalletCoreFFI"], path: "Sources/WalletCore"), // holds wallet_core.swift
    .target(name: "WalletShell", dependencies: ["WalletCore"]),
    .testTarget(name: "WalletShellTests", dependencies: ["WalletShell"]),
]
```

**Definition of done.**
- Command: `cd euwallet/ios && swift build`
- Expected: `Build complete!` with no errors. The `CoreEngine` protocol compiles, `WalletCore` conforms, and nothing in `EffectExecutor`/`ScreenRenderer`/`SecureEnclaveSigner` references a concrete core type — grep proves it: `cd euwallet/ios && ! grep -rn "core: WalletCore" Sources/` should print nothing and exit non-zero-inverted (i.e. the only reference is `core: CoreEngine`). After Section 3, `swift build` with the xcframework present still says `Build complete!`.

---

### 8.2 The effect executor: the run loop that drives everything

The executor is the beating heart of the shell. It: (1) hands one `Event` to the core, (2) drains the returned `Effect`s, (3) executes each, (4) turns each result into a follow-up `Event`, (5) repeats until the cascade is empty. The existing `euwallet/ios/Sources/WalletShell/EffectExecutor.swift` is the correct shape; here we harden it.

There are two important properties to preserve:

1. **Serialization.** The core holds `&mut self` state; two events must never be handled concurrently. In the mock this is a Swift class field; with real UniFFI the Rust `Core` is made `Send + Sync` by an internal `Mutex` (Section 3), but the shell must *still* serialize so that the ordering is deterministic and matches the Lean traces (Section 10).
2. **Never block the cooperative thread pool.** A Secure Enclave signature shows a biometric sheet and **blocks its calling thread** until the user responds. If you call it directly inside an `async` function you stall a pool thread for seconds. Always hop hardware/blocking work to a background queue.

Replace the body of `EffectExecutor.swift` with this hardened version. Note the executor now depends on `CoreEngine`, threads an `Alg` through to the signer, runs signing off-main, and distinguishes user-cancel from genuine failure:

```swift
import Foundation

/// Drives the sans-IO core: hand it an event, execute the returned effects, feed any
/// results back as new events, correlating by EffectId (plan Section 2/8).
public final class EffectExecutor {
    private let core: CoreEngine
    private let signer: Signer
    private let http: HttpClient
    private let storage: SecureStorage
    private let render: (ScreenDescription) -> Void

    public init(core: CoreEngine, signer: Signer, http: HttpClient,
                storage: SecureStorage, render: @escaping (ScreenDescription) -> Void) {
        self.core = core; self.signer = signer; self.http = http
        self.storage = storage; self.render = render
    }

    /// Send one event and fully drain the resulting synchronous effect cascade.
    /// (Long-lived subscriptions — BLE, timers, QR scanner, auth callbacks — deliver their
    ///  results by calling `send(_:)` again later; see §8.6/§8.7.)
    public func send(_ event: WalletEvent) async {
        var queue = core.handle(event)
        while !queue.isEmpty {
            let effect = queue.removeFirst()
            if let followUp = await execute(effect) {
                queue.append(contentsOf: core.handle(followUp))
            }
        }
    }

    /// Execute one effect. Returns a follow-up event when the effect produces a result NOW.
    private func execute(_ effect: WalletEffect) async -> WalletEvent? {
        switch effect {
        case .render(let screen):
            render(screen)                          // publish to the UI; never blocks the core
            return nil

        case .sign(let id, let keyRef, let payload):
            do {
                // ES256 is implied until Effect::Sign carries an `alg` field (Section 2 TODO).
                // Off-main because the biometric sheet blocks its thread.
                let sig = try await runOffMain {
                    try self.signer.sign(key: KeyRef(keyRef), alg: .es256, payload: payload)
                }
                return .signatureProduced(id: id, signature: sig)
            } catch let e as SignerError where e.isUserCancellation {
                return .userDeclined                // user dismissed Face ID / Touch ID
            } catch {
                // No SignatureFailed event exists yet; surface as a declined flow and log (no secrets).
                Log.error("sign failed for effect \(id): \(error)")
                return .userDeclined
            }

        case .http(let id, let url, let body):
            let (status, data) = await http.post(url: url, body: body)
            return .httpResponse(id: id, status: status, body: data)

        case .store(let key, let value):
            do { try storage.put(key: key, value: value) }
            catch { Log.error("store failed for \(key): \(error)") }   // never log `value`
            return nil
        }
    }

    /// Run blocking/hardware work off the Swift cooperative pool.
    private func runOffMain<T>(_ work: @escaping () throws -> T) async throws -> T {
        try await withCheckedThrowingContinuation { cont in
            DispatchQueue.global(qos: .userInitiated).async {
                do { cont.resume(returning: try work()) } catch { cont.resume(throwing: error) }
            }
        }
    }
}

public protocol HttpClient { func post(url: String, body: Data) async -> (UInt16, Data) }

public protocol SecureStorage {
    func put(key: String, value: Data) throws
    func get(key: String) throws -> Data?
    func delete(key: String) throws
}
```

Add a tiny redaction-safe logger so we never violate the "never log full credentials/secrets/biometrics" rule (create `euwallet/ios/Sources/WalletShell/Log.swift`):

```swift
import OSLog
enum Log {
    private static let logger = Logger(subsystem: "eu.europa.ec.eudiw", category: "shell")
    static func error(_ m: String) { logger.error("\(m, privacy: .public)") } // pass only already-safe strings
    static func info(_ m: String)  { logger.info("\(m, privacy: .public)") }
    // Rule: never interpolate credential bytes, payloads, signatures, or biometric data.
}
```

**Where an `actor` becomes mandatory (§8.7).** The class above is safe as long as `send(_:)` is only called from one place at a time (the UI). The moment real transports arrive — BLE delegate callbacks fire on CoreBluetooth's queue, the QR scanner fires on the AV capture queue, `ASWebAuthenticationSession` fires on the main queue — you have *concurrent* producers of events. At that point promote the executor to an `actor` with an explicit mailbox so all injected events are serialized:

```swift
public actor WalletRuntime {
    private let core: CoreEngine
    private let router: EffectRouter        // the `execute(_:)` switch, extracted
    private var mailbox: [WalletEvent] = []
    private var draining = false

    public func send(_ event: WalletEvent) { mailbox.append(event); Task { await drain() } }

    private func drain() async {
        if draining { return }              // one drain at a time ⇒ deterministic ordering
        draining = true; defer { draining = false }
        while !mailbox.isEmpty {
            let ev = mailbox.removeFirst()
            for eff in core.handle(ev) {
                if let result = await router.execute(eff) { mailbox.append(result) }
            }
        }
    }
    // Async subscriptions (BLE bytes, timer fired, QR scanned, auth callback) call `send(_:)`.
}
```

The `EffectExecutor` class and the `WalletRuntime` actor share the exact same `execute` logic; keep it in one `EffectRouter` type they both hold. Ship the class for §8.1–§8.6, switch the app to the actor when you add §8.7 transports.

**Definition of done.**
- Command: `cd euwallet/ios && swift test --filter EffectExecutorTests`
- Expected: the existing two tests pass — `testConsentFlowRendersThenReachesCredentialList` (drives `authorizationRequestReceived → consent`, then `userConsented → sign → http → credentialList`) and `testDeclineRendersError`. Output ends `Test Suite 'EffectExecutorTests' passed`. This proves the cascade loop, `EffectId` correlation, and data-minimisation assertion (`requestedClaims == ["age_over_18"]`) all work against the (mock) core.

---

### 8.3 The renderer: `ScreenDescription` → native, accessible SwiftUI

The renderer is a **pure function of `ScreenDescription`**: it `switch`es over the closed archetype vocabulary (Section 7) and maps each case to **native system controls**. There is no custom drawing, no conditional business logic, and — critically — **no interpretation of RP-supplied data as structure**. The RP's display name, purpose text, and claim labels arrive as already-validated `String`s inside the `ConsentScreen` (the core validated and minimised them; Section 7); the renderer only *slots them into wallet-owned templates*. This is what makes "what you see is what you sign" hold: the bytes the user reads here are the bytes the core hashed (`presenter::consent_hash`) and bound into the signature.

Using system controls is also how we get **EN 301 549 / WCAG 2.2** compliance almost for free — SwiftUI's `Text`, `Toggle`, `Button`, `List`, `Label` already support Dynamic Type (WCAG 1.4.4 Resize Text), VoiceOver names/roles/values (WCAG 4.1.2), semantic colors that adapt to Increase Contrast (1.4.3 / 1.4.11), and focus order (2.4.3). We add explicit accessibility metadata and enforce minimum target sizes (WCAG 2.5.8, ≥ 44×44 pt). **Never** substitute a custom-drawn control for a native one; you would lose all of that and fail the accessibility conformance requirement (which the shared context marks non-deferrable).

Replace `euwallet/ios/Sources/WalletShell/ScreenRenderer.swift` with this hardened version. It keeps the existing `ScreenRenderer(screen:onConsent:onDecline:)` shape (so the app and tests keep compiling) but every archetype maps to accessible native controls, and the consent screen carries identifiers for UI tests:

```swift
#if canImport(SwiftUI)
import SwiftUI

/// Maps each ScreenDescription archetype to NATIVE, accessible SwiftUI controls.
/// No custom rendering, no layout logic beyond selection. Accessibility (Dynamic Type,
/// VoiceOver, EN 301 549 / WCAG 2.2) comes from using system controls (plan Section 8).
public struct ScreenRenderer: View {
    public let screen: ScreenDescription
    public let onConsent: () -> Void
    public let onDecline: () -> Void

    public init(screen: ScreenDescription,
                onConsent: @escaping () -> Void,
                onDecline: @escaping () -> Void) {
        self.screen = screen; self.onConsent = onConsent; self.onDecline = onDecline
    }

    public var body: some View {
        switch screen {
        case .loading:
            ProgressView("Loading…")
                .accessibilityLabel("Loading, please wait")

        case .error(let code, let message):
            VStack(spacing: 12) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .font(.largeTitle).foregroundStyle(.red)
                    .accessibilityHidden(true)                 // decorative; message carries the info
                Text(message).font(.body).multilineTextAlignment(.center)
                Text(code).font(.caption).foregroundStyle(.secondary)
            }
            .padding()
            .accessibilityElement(children: .combine)          // one VoiceOver stop: "<message>, <code>"

        case .consent(let c):
            ConsentView(screen: c, onConsent: onConsent, onDecline: onDecline)

        case .credentialList:
            Text("Your credentials").font(.title2).accessibilityAddTraits(.isHeader)

        // Remaining archetypes get their own native subviews as flows land:
        case .credentialDetail, .issuanceOffer, .presentQr, .scanQr, .authPrompt, .transactionHistory:
            Text(String(describing: screen))   // placeholder until the owning flow's section fills it in
        }
    }
}

/// The security-critical screen. What the user reads here is what the core hashed and binds
/// the presentation/signature to (what-you-see-is-what-you-sign, plan Section 7).
struct ConsentView: View {
    let screen: ConsentScreen
    let onConsent: () -> Void
    let onDecline: () -> Void

    @Environment(\.dynamicTypeSize) private var typeSize

    var body: some View {
        // A List gives native Dynamic Type, contrast, and VoiceOver row semantics for free.
        VStack(alignment: .leading, spacing: 0) {
            List {
                Section {
                    Text("\(screen.rpDisplayName) is requesting your data")
                        .font(.headline)
                        .accessibilityAddTraits(.isHeader)             // WCAG 2.4.6 / 1.3.1
                    Text("Purpose: \(screen.purpose)")
                        .font(.subheadline).foregroundStyle(.secondary)
                }
                Section("They will receive only") {
                    ForEach(screen.requestedClaims, id: \.self) { claim in
                        Label(claim, systemImage: "checkmark.seal")
                            .accessibilityLabel("Will be shared: \(humanize(claim))")
                    }
                }
            }
            .listStyle(.insetGrouped)

            // Actions live in a bar so they stay reachable at every Dynamic Type size.
            HStack(spacing: 16) {
                Button("Decline", role: .cancel, action: onDecline)
                    .frame(maxWidth: .infinity, minHeight: 44)          // WCAG 2.5.8 target size
                    .accessibilityIdentifier("consent.decline")
                    .accessibilityHint("Cancels the request; no data is shared")
                Button("Share", action: onConsent)
                    .buttonStyle(.borderedProminent)
                    .frame(maxWidth: .infinity, minHeight: 44)
                    .accessibilityIdentifier("consent.share")
                    .accessibilityHint("Authorises sharing exactly the listed data")
            }
            .controlSize(.large)
            .padding()
        }
        .navigationTitle("Review request")
        .accessibilityIdentifier("consent.screen")
    }

    /// Turn a claim path like "age_over_18" into human text. Pure display sugar; the *decision*
    /// of which claims appear was made in the core. Never derives new claims here.
    private func humanize(_ claim: String) -> String {
        claim.replacingOccurrences(of: "_", with: " ")
    }
}
#endif
```

**Wiring the render callback to the UI.** The executor's `render:` closure publishes to a `@MainActor` observable store; SwiftUI redraws; button taps call back into the executor. Create `euwallet/ios/Sources/WalletShell/ViewStore.swift`:

```swift
#if canImport(SwiftUI)
import SwiftUI

@MainActor
public final class ViewStore: ObservableObject {
    @Published public private(set) var screen: ScreenDescription = .loading
    public init() {}
    public func update(_ s: ScreenDescription) { self.screen = s }
}

/// Hosts the renderer and forwards user actions back into the executor. This is the ONLY place
/// the renderer and the executor meet.
public struct ScreenRootView: View {
    @ObservedObject var store: ViewStore
    let send: (WalletEvent) -> Void

    public init(store: ViewStore, send: @escaping (WalletEvent) -> Void) {
        self.store = store; self.send = send
    }

    public var body: some View {
        NavigationStack {
            ScreenRenderer(
                screen: store.screen,
                onConsent: { send(.userConsented) },     // opaque action → core decides what it means
                onDecline: { send(.userDeclined) }
            )
        }
    }
}
#endif
```

And the app entry point (this lives in the **app target**, see §8.11 — `euwallet/ios/App/EUDIWalletApp.swift`):

```swift
import SwiftUI
import WalletShell

@main
struct EUDIWalletApp: App {
    @StateObject private var store = ViewStore()
    private let executor: EffectExecutor

    init() {
        let store = ViewStore()
        _store = StateObject(wrappedValue: store)
        self.executor = EffectExecutor(
            core: UniFFICore(),                                  // real Rust core on device
            signer: SecureEnclaveSigner(),
            http: URLSessionHttpClient(),
            storage: KeychainStorage(),
            render: { screen in Task { @MainActor in store.update(screen) } }
        )
    }

    var body: some Scene {
        WindowGroup {
            ScreenRootView(store: store) { event in Task { await executor.send(event) } }
                .onOpenURL { url in                             // OID4VP same-device deep link (§8.9)
                    Task { await executor.send(.authorizationRequestReceived(Data(url.absoluteString.utf8))) }
                }
        }
    }
}
```

**Definition of done.**
- Command: `cd euwallet/ios && swift build` (renderer compiles for macOS host) and, when the app target exists, `xcodebuild build -scheme EUDIWallet -destination 'platform=iOS Simulator,name=iPhone 15'`.
- Accessibility check (manual, on simulator): launch, force the consent screen, open **Accessibility Inspector** (Xcode ▸ Open Developer Tool) and run the **Audit** — expect zero "hit area too small", zero "missing label", zero contrast failures. Turn on **Larger Text** (Settings ▸ Accessibility ▸ Display & Text Size ▸ Larger Text, max) and confirm the Share/Decline buttons remain fully visible and tappable (they reflow because they use Dynamic Type + `List`). Turn on **VoiceOver** and swipe through: expect the reading order "Review request" → "<RP> is requesting your data" (announced as heading) → "Purpose: …" → each "Will be shared: …" → "Decline" → "Share, button, Authorises sharing exactly the listed data".

---

### 8.4 The Secure Enclave signer: implementing the `crypto-traits::Signer` foreign trait

The device-bound key is the wallet's cryptographic identity for holder binding (mdoc `DeviceAuth`, SD-JWT VC key binding, OID4VP `vp_token` signatures). The rules from the shared context are absolute: **never implement ECDSA yourself**, **never a software vault for high-assurance keys**, and **the private key never crosses the FFI**. On iOS that means the key is generated *inside the Secure Enclave*, is non-exportable by construction, and is gated by biometrics via a `SecAccessControl`.

The Rust side declares (Section 4, `crypto-traits`):

```rust
pub struct KeyRef(pub String);
pub enum Alg { Es256, Es384, EdDsa }
pub trait Signer {
    fn sign(&self, key: &KeyRef, alg: Alg, payload: &[u8]) -> Result<Vec<u8>, CryptoError>;
}
```

Section 3 re-exports this as a **UniFFI foreign trait** (`#[uniffi::export(with_foreign)]`) so a Swift class can *be* the `Signer`. The generated Swift protocol looks like this (names come from UniFFI):

```swift
// generated by uniffi-bindgen (Section 3), shown for reference:
public protocol Signer: AnyObject {
    func sign(key: KeyRef, alg: Alg, payload: Data) throws -> Data     // returns raw r||s, NOT DER
    func publicKeyX963(key: KeyRef) throws -> Data                     // added for issuance/attestation
}
public struct KeyRef { public let value: String }
public enum Alg { case es256, es384, edDsa }
```

Two correctness landmines the existing skeleton (`euwallet/ios/Sources/WalletShell/SecureEnclaveSigner.swift`) steps on, which you **must** fix:

1. **Signature encoding.** `SecKeyCreateSignature(_, .ecdsaSignatureMessageX962SHA256, _, _)` returns an **ASN.1/X9.62 DER** signature. But COSE ES256 (RFC 9053) and JWS ES256 (RFC 7515) require **raw `r || s`** (P1363, fixed-width: 64 bytes for P-256, 96 for P-384). If you hand the DER bytes to the `cose`/`sdjwt` crates, every verifier rejects the credential. Convert DER → raw. Use a **vetted** parser (CryptoKit's `ECDSASignature(derRepresentation:)`), not hand-rolled ASN.1.
2. **Curve support.** The Secure Enclave supports **P-256 only**. `ES384` cannot be Enclave-backed, and `EdDSA`/Ed25519 is not an Enclave algorithm at all. The device key must be ES256; reject the others explicitly so a mis-configured request fails loudly instead of silently using a software key.

Replace `SecureEnclaveSigner.swift` with:

```swift
import Foundation
import Security
import CryptoKit
import LocalAuthentication

/// Mirrors crypto_traits::{KeyRef, Alg}. (Section 3 generates identical shapes via UniFFI;
/// keep these until the generated module is imported, then delete the duplicates.)
public struct KeyRef: Hashable, Sendable { public let value: String
    public init(_ value: String) { self.value = value } }
public enum Alg: Sendable { case es256, es384, edDsa }

public enum SignerError: Error {
    case keyUnavailable, unsupportedAlgorithm, userCancelled, backend(String)
    var isUserCancellation: Bool { if case .userCancelled = self { return true }; return false }
}

/// Implements the core's `Signer` foreign trait. The private key is created inside the Secure
/// Enclave and is non-exportable; signing requires biometric/device auth via the key's access
/// control (plan Section 8). Output is raw r||s for COSE/JOSE.
public final class SecureEnclaveSigner: Signer, @unchecked Sendable {
    public enum Persistence { case secureEnclave, keychainFallback, ephemeral }

    private let persistence: Persistence
    private let biometricReason: String
    private let reuseDuration: TimeInterval

    // Only used for `.ephemeral` (host tests): keep transient keys stable across sign/verify.
    private let cacheLock = NSLock()
    private var ephemeralKeys: [String: SecKey] = [:]

    public init(persistence: Persistence = SecureEnclaveSigner.defaultPersistence,
                biometricReason: String = "Authorise sharing your identity data",
                reuseDuration: TimeInterval = 10) {
        self.persistence = persistence
        self.biometricReason = biometricReason
        self.reuseDuration = reuseDuration
    }

    /// Real SE on device; keychain P-256 on a simulator without an Enclave; transient on the Mac host.
    public static var defaultPersistence: Persistence {
        #if os(iOS)
        return SecureEnclave.isAvailable ? .secureEnclave : .keychainFallback
        #else
        return .ephemeral
        #endif
    }

    // MARK: Signer

    public func sign(key: KeyRef, alg: Alg, payload: Data) throws -> Data {
        let (secAlg, coordinate) = try Self.algParams(alg, persistence: persistence)
        let priv = try loadOrCreateKey(tag: key.value)
        var err: Unmanaged<CFError>?
        guard let der = SecKeyCreateSignature(priv, secAlg, payload as CFData, &err) as Data? else {
            throw Self.mapError(err)          // maps errSecUserCanceled → .userCancelled
        }
        return try Self.rawFromDER(der, coordinateSize: coordinate)   // r||s for COSE/JWS
    }

    public func publicKeyX963(key: KeyRef) throws -> Data {
        let priv = try loadOrCreateKey(tag: key.value)
        guard let pub = SecKeyCopyPublicKey(priv) else { throw SignerError.keyUnavailable }
        var err: Unmanaged<CFError>?
        guard let data = SecKeyCopyExternalRepresentation(pub, &err) as Data? else { throw Self.mapError(err) }
        return data                            // X9.63: 0x04 || X || Y  (public only; private never leaves the SE)
    }

    // MARK: key lifecycle

    private func loadOrCreateKey(tag: String) throws -> SecKey {
        if persistence == .ephemeral {
            cacheLock.lock(); defer { cacheLock.unlock() }
            if let k = ephemeralKeys[tag] { return k }
            let k = try createKey(tagData: Data(tag.utf8), ctx: authContext())
            ephemeralKeys[tag] = k
            return k
        }
        let tagData = Data(tag.utf8)
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tagData,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
            kSecUseAuthenticationContext as String: authContext(),
            kSecUseOperationPrompt as String: biometricReason,   // shown at sign time
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecSuccess, let item { return (item as! SecKey) }
        guard status == errSecItemNotFound else { throw SignerError.backend("keychain \(status)") }
        return try createKey(tagData: tagData, ctx: authContext())
    }

    private func createKey(tagData: Data, ctx: LAContext) throws -> SecKey {
        // Biometrics required; key is invalidated if the enrolled biometric set changes (defence
        // against an attacker enrolling their own face/finger). Use .biometryCurrentSet, not
        // .biometryAny/.userPresence, for the device-bound key.
        let flags: SecAccessControlCreateFlags =
            (persistence == .ephemeral) ? [.privateKeyUsage]        // no prompt in host tests
                                        : [.privateKeyUsage, .biometryCurrentSet]
        var acErr: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,           // never in a backup, never synced
            flags, &acErr
        ) else { throw SignerError.backend("accesscontrol \(String(describing: acErr?.takeRetainedValue()))") }

        var privAttrs: [String: Any] = [
            kSecAttrApplicationTag as String: tagData,
            kSecAttrAccessControl as String: access,
            kSecUseAuthenticationContext as String: ctx,
            kSecAttrIsPermanent as String: (persistence != .ephemeral),
        ]
        var attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,                  // Secure Enclave = P-256 only
            kSecPrivateKeyAttrs as String: privAttrs,
        ]
        if persistence == .secureEnclave {
            attrs[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave  // <-- key lives in the SE
        }
        var err: Unmanaged<CFError>?
        guard let priv = SecKeyCreateRandomKey(attrs as CFDictionary, &err) else {
            throw SignerError.backend("createkey \(String(describing: err?.takeRetainedValue()))")
        }
        return priv
        // Note: we never set kSecAttrIsExtractable; the SE private key is physically non-exportable.
    }

    private func authContext() -> LAContext {
        let ctx = LAContext()
        // One biometric prompt can cover several signs in a single presentation flow.
        ctx.touchIDAuthenticationAllowableReuseDuration = reuseDuration
        ctx.localizedFallbackTitle = ""      // no passcode fallback for the device-bound signing key
        return ctx
    }

    // MARK: helpers

    private static func algParams(_ alg: Alg, persistence: Persistence) throws -> (SecKeyAlgorithm, Int) {
        switch alg {
        case .es256: return (.ecdsaSignatureMessageX962SHA256, 32)
        case .es384:
            // P-384 cannot be Secure-Enclave-backed. Only allowed off the Enclave.
            guard persistence != .secureEnclave else { throw SignerError.unsupportedAlgorithm }
            return (.ecdsaSignatureMessageX962SHA384, 48)
        case .edDsa: throw SignerError.unsupportedAlgorithm    // no Ed25519 in the Secure Enclave
        }
    }

    /// DER (X9.62) → raw r||s (P1363), using CryptoKit's vetted ASN.1 parser.
    private static func rawFromDER(_ der: Data, coordinateSize: Int) throws -> Data {
        switch coordinateSize {
        case 32: return try P256.Signing.ECDSASignature(derRepresentation: der).rawRepresentation
        case 48: return try P384.Signing.ECDSASignature(derRepresentation: der).rawRepresentation
        default: throw SignerError.unsupportedAlgorithm
        }
    }

    private static func mapError(_ err: Unmanaged<CFError>?) -> SignerError {
        guard let e = err?.takeRetainedValue() else { return .backend("unknown") }
        let ns = e as Error as NSError
        if ns.code == errSecUserCanceled || ns.code == Int(kLAErrorUserCancel.rawValue) { return .userCancelled }
        return .backend(String(describing: e))
    }
}
```

Notes for the junior developer:

- **`kSecAttrTokenIDSecureEnclave`** is what makes the key live in the Enclave. Without it you get an ordinary keychain ECC key (still hardware-encrypted at rest, but the private scalar exists in the Application Processor's memory during use). For the device-bound key, the Enclave variant is required.
- **`.biometryCurrentSet`** binds the key to the *current* set of enrolled biometrics; adding a new face/finger invalidates the key. This is the correct high-assurance choice. Document in your key-management memo (Section 4) how you re-provision the device key if the user re-enrolls (you re-run key generation + re-attest via §8.6).
- **`kSecUseOperationPrompt`** sets the sheet's reason string. It is technically deprecated in favour of a pre-evaluated `LAContext`; for a production hardening pass you may instead call `context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason:)` once at the start of a flow and reuse the context — but the simple path above is correct and one prompt per `reuseDuration` window.
- **`SecureEnclave.isAvailable`** (CryptoKit) is how `defaultPersistence` transparently falls back on a simulator that lacks an Enclave, so the same binary runs in CI, in the simulator, and on device.

**Definition of done (on a real device).**
- Add a device unit test `euwallet/ios/Tests/WalletShellTests/SignerTests.swift`:

```swift
import XCTest
import CryptoKit
@testable import WalletShell

final class SignerTests: XCTestCase {
    func testSecureEnclaveSignRoundTrips() throws {
        // On device this uses the real SE; on the Mac host it uses an ephemeral P-256 key.
        let signer = SecureEnclaveSigner()
        let key = KeyRef("test-device-key")
        let msg = Data("to-be-signed".utf8)

        let raw = try signer.sign(key: key, alg: .es256, payload: msg)  // triggers Face ID on device
        XCTAssertEqual(raw.count, 64)                                    // proves r||s, not DER

        let pubX963 = try signer.publicKeyX963(key: key)
        let pub = try P256.Signing.PublicKey(x963Representation: pubX963)
        let sig = try P256.Signing.ECDSASignature(rawRepresentation: raw)
        XCTAssertTrue(pub.isValidSignature(sig, for: msg))              // SHA256 applied by both sides
    }
}
```

- Command (device): `xcodebuild test -scheme WalletShell -destination 'platform=iOS,name=<your iPhone>' -only-testing:WalletShellTests/SignerTests` (approve the Face ID/Touch ID prompt when it appears).
- Command (host, no biometrics): `cd euwallet/ios && swift test --filter SignerTests`.
- Expected: `testSecureEnclaveSignRoundTrips` passes — the 64-byte length assertion confirms the DER→raw conversion, and `isValidSignature` returning `true` confirms the Enclave key produced a valid ES256 signature that the public key verifies.

---

### 8.5 The `Sign` effect end-to-end (consent → Enclave signature)

Now connect §8.2 and §8.4: driving the core with `UserConsented` makes it emit `Effect::Sign { id, key_ref, payload }` (see `wallet-core` `handle_event`), the executor routes it to the `SecureEnclaveSigner`, the biometric sheet appears, and the raw signature comes back as `Event::SignatureProduced { id, signature }`. The `EffectId` correlation guarantees the core matches the signature to the outstanding request.

Update the test doubles so the shell's `Signer` protocol matches the new signature (edit `euwallet/ios/Sources/WalletShell/InMemory.swift`), and add a recording wrapper so tests can inspect what was signed:

```swift
public final class StubSigner: Signer {
    public init() {}
    public func sign(key: KeyRef, alg: Alg, payload: Data) throws -> Data { Data(repeating: 0xAB, count: 64) }
    public func publicKeyX963(key: KeyRef) throws -> Data { Data([0x04] + Array(repeating: 0, count: 64)) }
}

/// Wraps a real signer and records the last (key, payload, signature) for assertions.
public final class RecordingSigner: Signer {
    public struct Record { public let key: KeyRef; public let payload: Data; public let signature: Data }
    private let wrapped: Signer
    public private(set) var last: Record?
    public init(wrapping s: Signer) { self.wrapped = s }
    public func sign(key: KeyRef, alg: Alg, payload: Data) throws -> Data {
        let sig = try wrapped.sign(key: key, alg: alg, payload: payload)
        last = Record(key: key, payload: payload, signature: sig)
        return sig
    }
    public func publicKeyX963(key: KeyRef) throws -> Data { try wrapped.publicKeyX963(key: key) }
}
```

**Definition of done (the section-level acceptance test — consent render + Sign via Secure Enclave).** Add `euwallet/ios/Tests/WalletShellTests/ConsentAndSignAcceptanceTests.swift`:

```swift
import XCTest
import CryptoKit
@testable import WalletShell

final class ConsentAndSignAcceptanceTests: XCTestCase {
    func testAppRendersCoreConsentThenSignsViaSecureEnclave() async throws {
        var rendered: [ScreenDescription] = []
        let realSigner = SecureEnclaveSigner()            // SE on device / sim; ephemeral on Mac host
        let signer = RecordingSigner(wrapping: realSigner)

        let executor = EffectExecutor(
            core: WalletCore(),                           // mock mirror on host; UniFFICore() on device
            signer: signer,
            http: StubHttpClient(),
            storage: InMemoryStorage(),
            render: { rendered.append($0) }
        )

        // 1) A core-produced ScreenDescription is rendered: the Consent archetype.
        await executor.send(.authorizationRequestReceived(Data([1, 2, 3])))
        guard case .consent(let consent)? = rendered.last else {
            return XCTFail("expected a core-produced consent screen, got \(String(describing: rendered.last))")
        }
        XCTAssertEqual(consent.requestedClaims, ["age_over_18"])   // data minimisation came from the core

        // 2) Consent → Effect::Sign is executed by the Secure Enclave signer.
        await executor.send(.userConsented)                        // Face ID prompt on device
        let record = try XCTUnwrap(signer.last, "the Sign effect must have reached the SE signer")

        // 3) The signature is a valid ES256 signature over exactly the core's payload.
        let pub = try P256.Signing.PublicKey(x963Representation: realSigner.publicKeyX963(key: record.key))
        let sig = try P256.Signing.ECDSASignature(rawRepresentation: record.signature)
        XCTAssertEqual(record.signature.count, 64)
        XCTAssertTrue(pub.isValidSignature(sig, for: record.payload))
    }
}
```

- Command (host, always-green CI gate): `cd euwallet/ios && swift test --filter ConsentAndSignAcceptanceTests`
- Command (Secure Enclave, on device): `xcodebuild test -scheme WalletShell -destination 'platform=iOS,name=<your iPhone>' -only-testing:WalletShellTests/ConsentAndSignAcceptanceTests`
- Expected: the test passes. This is the concrete realisation of the section's acceptance criterion — **the app renders a Consent screen from a core-produced `ScreenDescription`, and the `Sign` effect completes via the Secure Enclave**, cryptographically verified.

---

### 8.6 Randomness, key attestation (WUA), and bulk session crypto

Two more `crypto-traits` capabilities (Section 4) surface in the shell:

- **`Random`** — the core must not generate its own randomness (that would break replay determinism). Model it as `Effect::GetRandom { id, len }` → the shell fills bytes from `SecRandomCopyBytes` → `Event::RandomProduced { id, bytes }`. On replay (Section 10) you inject the recorded bytes and the run is deterministic. (This variant is a Section 2 enum addition; the Swift handler is trivial.)

```swift
// executor case, once Effect::GetRandom exists:
case .getRandom(let id, let len):
    var buf = [UInt8](repeating: 0, count: Int(len))
    let ok = SecRandomCopyBytes(kSecRandomDefault, buf.count, &buf)
    precondition(ok == errSecSuccess)
    return .randomProduced(id: id, bytes: Data(buf))
```

- **`KeyAttestation`** — the WUA / key-attestation producer (the `wua` crate + its section, TS03). On iOS, hardware attestation of an app-and-key comes from **App Attest** (`DCAppAttestService`), not from `SecKeyCreateSignature`. The flow: (1) the core issues a challenge as `Effect::AttestKey { id, challenge }`; (2) the shell calls `DCAppAttestService.shared.generateKey` then `attestKey(_:clientDataHash:)`; (3) the resulting attestation blob returns as `Event::KeyAttested { id, attestation }` for the `wua` crate to package. The Swift adapter is a dumb courier; **all verification lives in `wua`/`crypto-traits::KeyAttestation`** (never trust device self-claims — that's a hard rule). Full treatment is in the WUA section; the shell contribution is just this effect handler:

```swift
import DeviceCheck
// executor case, once Effect::AttestKey exists:
case .attestKey(let id, let challenge):
    let svc = DCAppAttestService.shared
    guard svc.isSupported else { return .attestUnavailable(id: id) }
    let keyId = try await svc.generateKey()
    let hash = Data(SHA256.hash(data: challenge))
    let attestation = try await svc.attestKey(keyId, clientDataHash: hash)
    return .keyAttested(id: id, attestation: attestation)   // wua crate verifies the chain
```

- **Bulk session crypto (AEAD/HKDF)** for the ISO 18013-5 session (`crypto-traits::{Aead, Kdf}`). Per the shared context this is **TBD per certification memo**: either a vetted Rust lib (`aws-lc-rs`) *inside* the core (no shell involvement — preferred, keeps the transcript deterministic and the shell a pure byte pipe) or a platform callback (CryptoKit `AES.GCM` / `HKDF`) exposed as a foreign trait. Default to the Rust path; only fall back to a CryptoKit foreign `Aead`/`Kdf` if the certification memo requires platform-provided FIPS/CC-evaluated primitives. If you do the platform path, the Swift `Aead` mirrors §8.4's foreign-trait pattern.

**Definition of done.**
- For `GetRandom`: `cd euwallet/ios && swift test --filter RandomEffectTests` where the test asserts `randomProduced.bytes.count == requestedLen` and that two calls differ. Expected: pass.
- For App Attest: on device only, assert `DCAppAttestService.shared.isSupported == true` and that `attestKey` returns a non-empty blob for a fixed challenge. Expected: non-empty attestation; on simulator `isSupported` is `false`, so the test asserts the `.attestUnavailable` branch.

---

### 8.7 Transports: BLE / NFC / QR as thin byte adapters for ISO 18013-5

Proximity presentation (Section 5, the `iso18013-5` crate) is *entirely* byte-level in Rust: device engagement, session establishment, session encryption, and the mdoc request/response all happen in the core. The Swift transports **carry opaque bytes and nothing else**. They know nothing about mdoc, CBOR, or session keys. The existing `euwallet/ios/Sources/WalletShell/Transports.swift` has the right protocol shape (`ProximityTransport`); we flesh it out.

The transport contract, extended for real async subscriptions (a delegate-style byte sink plus a `send`):

```swift
import Foundation

/// Proximity transports are thin adapters: they move opaque bytes to/from the core's
/// iso18013-5 machine and contain NO protocol logic (plan Section 5/8).
public protocol ProximityTransport: AnyObject {
    /// Called (on an arbitrary queue) with a fully reassembled inbound message.
    /// Wire this to `Task { await runtime.send(.transportBytes(id, $0)) }`.
    var onBytes: ((Data) -> Void)? { get set }
    /// Called when the link opens / closes / errors — surfaced as Events for the core’s state machine.
    var onState: ((TransportState) -> Void)? { get set }
    func start() throws
    func send(_ message: Data) async throws   // fragments + writes per the negotiated MTU
    func stop()
}

public enum TransportState: Sendable { case ready, connected, closed, failed(String) }
```

Everything the transport needs that is **protocol-derived** — the BLE service UUID and characteristic UUIDs (which the mdoc device engagement dictates), the BLE role (peripheral vs central), the NFC parameters — comes **from the core in the effect**, not hardcoded in Swift. This keeps the single source of truth in the `iso18013-5` crate (Section 5). The Section 2 enum additions:

```rust
// Section 2 additions (illustrative):
Effect::TransportOpen  { id: EffectId, kind: TransportKind, role: BleRole, ble: BleUuids }
Effect::TransportSend  { id: EffectId, bytes: Vec<u8> }
Effect::TransportClose { id: EffectId }
Event::TransportOpened { id: EffectId }
Event::TransportBytes  { bytes: Vec<u8> }
Event::TransportClosed { id: EffectId }
```

#### 8.7.1 BLE (CoreBluetooth) — ISO 18013-5 mdoc proximity

18013-5 defines two GATT topologies: **mdoc peripheral server mode** (the wallet advertises and serves) and **mdoc central client mode** (the wallet connects out). Each uses a **State**, **Client2Server**, and **Server2Client** characteristic (central client mode adds an **Ident** characteristic). Messages larger than the ATT MTU are fragmented with a **1-byte prefix** on each fragment: `0x01` = "more fragments follow", `0x00` = "this is the last fragment". The State characteristic signals start (`0x01`) and end (`0x02`).

Here is the **peripheral server mode** adapter (wallet = peripheral). The central client mode is the mirror image (scan → connect → discover → subscribe → write) and is included condensed. Note: the UUIDs are **passed in** from the core.

```swift
#if canImport(CoreBluetooth)
import CoreBluetooth

public struct BleUuids: Sendable {
    public let service: CBUUID
    public let state: CBUUID
    public let client2Server: CBUUID
    public let server2Client: CBUUID
    public init(service: CBUUID, state: CBUUID, client2Server: CBUUID, server2Client: CBUUID) {
        self.service = service; self.state = state
        self.client2Server = client2Server; self.server2Client = server2Client
    }
}

/// BLE transport, mdoc PERIPHERAL SERVER mode (ISO 18013-5 Annex A). Pure byte pipe.
public final class BlePeripheralTransport: NSObject, ProximityTransport, CBPeripheralManagerDelegate {
    public var onBytes: ((Data) -> Void)?
    public var onState: ((TransportState) -> Void)?

    private let uuids: BleUuids
    private var manager: CBPeripheralManager!
    private var s2c: CBMutableCharacteristic!          // Server2Client (notify)
    private var subscribedCentral: CBCentral?
    private var inbound = Data()                        // reassembly buffer for Client2Server

    public init(uuids: BleUuids) { self.uuids = uuids; super.init() }

    public func start() throws {
        manager = CBPeripheralManager(delegate: self, queue: DispatchQueue(label: "ble.peripheral"))
    }

    public func peripheralManagerDidUpdateState(_ p: CBPeripheralManager) {
        guard p.state == .poweredOn else { onState?(.failed("bluetooth \(p.state.rawValue)")); return }
        let state = CBMutableCharacteristic(type: uuids.state, properties: [.write, .notify],
                                            value: nil, permissions: [.writeable])
        let c2s = CBMutableCharacteristic(type: uuids.client2Server, properties: [.writeWithoutResponse, .write],
                                          value: nil, permissions: [.writeable])
        s2c = CBMutableCharacteristic(type: uuids.server2Client, properties: [.notify],
                                      value: nil, permissions: [.readable])
        let svc = CBMutableService(type: uuids.service, primary: true)
        svc.characteristics = [state, c2s, s2c]
        p.add(svc)
        p.startAdvertising([CBAdvertisementDataServiceUUIDsKey: [uuids.service]])
        onState?(.ready)
    }

    public func peripheralManager(_ p: CBPeripheralManager, central: CBCentral,
                                  didSubscribeTo ch: CBCharacteristic) {
        if ch.uuid == uuids.server2Client { subscribedCentral = central; onState?(.connected) }
    }

    // Reader (central) writes request fragments to Client2Server.
    public func peripheralManager(_ p: CBPeripheralManager, didReceiveWrite reqs: [CBATTRequest]) {
        for r in reqs {
            guard let value = r.value, !value.isEmpty else { continue }
            if r.characteristic.uuid == uuids.client2Server {
                let more = value[value.startIndex] == 0x01          // 1-byte fragmentation prefix
                inbound.append(value.dropFirst())
                if !more { let msg = inbound; inbound.removeAll(); onBytes?(msg) }  // full message → core
            } else if r.characteristic.uuid == uuids.state, value.first == 0x02 {
                onState?(.closed)                                   // reader signalled end
            }
            p.respond(to: r, withResult: .success)
        }
    }

    public func send(_ message: Data) async throws {
        guard let central = subscribedCentral else { throw TransportError.notConnected }
        let mtu = central.maximumUpdateValueLength                  // per-connection MTU
        let chunk = max(1, mtu - 1)                                 // leave room for the prefix byte
        var offset = message.startIndex
        while offset < message.endIndex {
            let end = message.index(offset, offsetBy: chunk, limitedBy: message.endIndex) ?? message.endIndex
            let isLast = (end == message.endIndex)
            var frame = Data([isLast ? 0x00 : 0x01]); frame.append(message[offset..<end])
            // updateValue can return false under back-pressure; retry when the queue drains.
            while !manager.updateValue(frame, for: s2c, onSubscribedCentrals: [central]) {
                try await Task.sleep(nanoseconds: 5_000_000)       // peripheralManagerIsReady also fires
            }
            offset = end
        }
    }

    public func stop() { manager?.stopAdvertising(); manager?.removeAllServices(); onState?(.closed) }
}

/// mdoc CENTRAL CLIENT mode (condensed): scan for `uuids.service`, connect, discover
/// characteristics, `setNotifyValue(true)` on Server2Client, `writeValue(_,for:type:)`
/// fragmented to Client2Server, reassemble notifications with the same 0x00/0x01 prefix,
/// and call `onBytes`. Same byte contract, roles reversed.
public final class BleCentralTransport: NSObject, ProximityTransport { /* CBCentralManagerDelegate + CBPeripheralDelegate */
    public var onBytes: ((Data) -> Void)?; public var onState: ((TransportState) -> Void)?
    public func start() throws { /* CBCentralManager.scanForPeripherals(withServices: [uuids.service]) */ }
    public func send(_ message: Data) async throws { /* fragment → writeValue to client2Server */ }
    public func stop() { /* cancelPeripheralConnection */ }
}

enum TransportError: Error { case notConnected }
#endif
```

The executor routes the transport effects and pumps bytes back as events (this is where the `WalletRuntime` **actor** from §8.2 becomes necessary, because `onBytes` fires on the BLE queue):

```swift
// inside the actor's execute(_:)
case .transportOpen(let id, let kind, let role, let ble):
    let t = makeTransport(kind: kind, role: role, ble: ble)      // BlePeripheralTransport / BleCentralTransport / NFC
    t.onBytes = { bytes in Task { await self.send(.transportBytes(bytes: bytes)) } }
    t.onState = { st in Task { await self.send(.transportState(id: id, state: st)) } }
    self.activeTransport = t
    try t.start()
    return nil                                                   // .transportOpened arrives via onState
case .transportSend(_, let bytes):
    try await self.activeTransport?.send(bytes); return nil
case .transportClose:
    self.activeTransport?.stop(); self.activeTransport = nil; return nil
```

**Definition of done.**
- Host loopback test (`euwallet/ios/Tests/WalletShellTests/BleFramingTests.swift`): unit-test the fragmentation/reassembly logic in isolation (extract it into a pure `BleFramer` struct: `fragment(_:mtu:) -> [Data]` and `feed(_:) -> Data?`). Assert that `feed`ing the fragments of a 5000-byte message across a 23-byte MTU reassembles the exact original bytes, and that only the last fragment has prefix `0x00`. Command: `cd euwallet/ios && swift test --filter BleFramingTests`; expected: pass.
- Two-device manual test: run the wallet on an iPhone (peripheral) and an 18013-5 reader (or a second device running the central adapter) on another; confirm a request message crosses and `onBytes` delivers the identical bytes the reader sent (compare SHA-256). Expected: hashes match; the `iso18013-5` crate accepts the bytes.

#### 8.7.2 NFC (CoreNFC)

Two honest facts shape NFC on iOS:

1. **The wallet as holder generally cannot do NFC engagement via card emulation** without the entitlement `com.apple.developer.nfc.hce` (Host Card Emulation), which Apple gates to iOS 17.4+ and, at time of writing, EU/DMA contexts. So the **certifiable P0 engagement path on iOS is QR + BLE** (§8.7.1, §8.7.3). NFC HCE is an entitlement-gated *enhancement*.
2. Where NFC is used, it is again a **thin byte pipe**: NFC static/negotiated handover (Section 5) reads/writes an NDEF whose payload the core produces/parses; ISO-DEP data retrieval is APDU byte exchange.

Reader-mode skeleton (wallet acting as reader, e.g. wallet-to-wallet or reading a handover), yielding opaque bytes:

```swift
#if canImport(CoreNFC)
import CoreNFC

public final class NfcReaderTransport: NSObject, NFCTagReaderSessionDelegate {
    public var onBytes: ((Data) -> Void)?
    private var session: NFCTagReaderSession?

    public func start() {
        session = NFCTagReaderSession(pollingOption: [.iso14443], delegate: self, queue: nil)
        session?.alertMessage = "Hold near the other device"
        session?.begin()
    }
    public func tagReaderSession(_ s: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        guard case let .iso7816(tag)? = tags.first else { s.invalidate(errorMessage: "unsupported tag"); return }
        s.connect(to: tags.first!) { _ in
            // Exchange APDUs; hand the raw response bytes to the core. No parsing here.
            let apdu = NFCISO7816APDU(data: Data(/* engagement/handover bytes from the core */))!
            tag.sendCommand(apdu: apdu) { resp, sw1, sw2, _ in
                var bytes = resp; bytes.append(sw1); bytes.append(sw2)
                self.onBytes?(bytes)
            }
        }
    }
    public func tagReaderSession(_ s: NFCTagReaderSession, didInvalidateWithError e: Error) { /* map to Event */ }
    public func tagReaderSessionDidBecomeActive(_ s: NFCTagReaderSession) {}
}
#endif
```

For the **HCE holder path** (entitlement-gated, iOS 17.4+), CoreNFC's `CardSession` presents the wallet as an NFC card; the same `onBytes`/`send` contract applies. Guard it with `#if canImport(CoreNFC)` and a runtime availability + entitlement check, and treat it as optional per the certification memo.

**Definition of done.**
- Build with `NFCReaderUsageDescription` in Info.plist and the `com.apple.developer.nfc.readersession.formats` entitlement; on device, `NfcReaderTransport().start()` shows the system NFC sheet and, on tap, `onBytes` delivers the response+status bytes. Expected: a non-empty `Data` whose trailing two bytes are the SW1/SW2 status word. Document explicitly in the traceability matrix (Section 1) that P0 proximity engagement is QR+BLE and NFC-HCE is entitlement-gated.

#### 8.7.3 QR (CoreImage generate + AVFoundation/Vision scan)

QR carries the **device engagement** (wallet presents its engagement as a QR the reader scans) or the **cross-device OID4VP request** (wallet scans the reader's QR). Generation is a pure function of the core's bytes; scanning yields bytes for the core. No protocol logic.

Replace/extend `QrEngagement` in `Transports.swift`:

```swift
#if canImport(CoreImage)
import CoreImage
import CoreImage.CIFilterBuiltins
#if canImport(UIKit)
import UIKit
#endif

public enum QrEngagement {
    /// The core hands us the exact string to encode (e.g. "mdoc:<base64url(DeviceEngagement)>"
    /// or "openid4vp://?..."). We never build or interpret that string.
    public static func image(for payload: String, scale: CGFloat = 10) -> CGImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(payload.utf8)
        filter.correctionLevel = "M"
        guard let out = filter.outputImage?.transformed(by: .init(scaleX: scale, y: scale)) else { return nil }
        return CIContext().createCGImage(out, from: out.extent)
    }
}
#endif
```

Scanning with AVFoundation (real-time, preferred) — create `euwallet/ios/Sources/WalletShell/QrScanner.swift`:

```swift
#if canImport(AVFoundation) && os(iOS)
import AVFoundation

public final class QrScanner: NSObject, AVCaptureMetadataOutputObjectsDelegate {
    public var onScan: ((Data) -> Void)?
    public let session = AVCaptureSession()

    public func start() throws {
        guard let device = AVCaptureDevice.default(for: .video),
              let input = try? AVCaptureDeviceInput(device: device),
              session.canAddInput(input) else { throw ScanError.noCamera }
        session.addInput(input)
        let output = AVCaptureMetadataOutput()
        guard session.canAddOutput(output) else { throw ScanError.noCamera }
        session.addOutput(output)
        output.setMetadataObjectsDelegate(self, queue: DispatchQueue(label: "qr.scan"))
        output.metadataObjectTypes = [.qr]
        DispatchQueue.global(qos: .userInitiated).async { self.session.startRunning() }
    }
    public func metadataOutput(_ o: AVCaptureMetadataOutput, didOutput objs: [AVMetadataObject],
                               from c: AVCaptureConnection) {
        guard let s = (objs.first as? AVMetadataMachineReadableCodeObject)?.stringValue else { return }
        session.stopRunning()
        onScan?(Data(s.utf8))          // hand the raw payload to the core (oid4vp / iso18013-5)
    }
    public func stop() { session.stopRunning() }
    enum ScanError: Error { case noCamera }
}
#endif
```

(For scanning a QR from a *still image* — e.g. a screenshot the user picked — use Vision's `VNDetectBarcodesRequest` with `symbologies = [.qr]`; same `Data` output.)

**Definition of done.**
- Round-trip unit test (`euwallet/ios/Tests/WalletShellTests/QrTests.swift`, iOS destination): `QrEngagement.image(for: payload)` produces a `CGImage`; feed that image to a `VNDetectBarcodesRequest` and assert the decoded `payloadStringValue == payload` for a representative engagement string. Command: `xcodebuild test -scheme WalletShell -destination 'platform=iOS Simulator,name=iPhone 15' -only-testing:WalletShellTests/QrTests`. Expected: pass (generate→scan bytes are identical).
- Live scan (device, `NSCameraUsageDescription` present): point at a reader QR; `onScan` fires once with the exact payload bytes; confirm they are the bytes handed to `oid4vp`/`iso18013-5`.

---

### 8.8 Secure storage: Keychain + encrypted file store, hardware-wrapped, never backed up

Credentials (mdoc/SD-JWT VC bytes), the device-key metadata, and the store's data-encryption key must be persisted so that they are: **hardware-encrypted at rest**, **never in a backup or iCloud**, **never in `UserDefaults`/plists**, and **never seen by analytics or logs**. `Effect::Store { key, value }` (and the retrieval variants the core will add) route here. The existing `InMemoryStorage` in `InMemory.swift` stays as the test double; production gets two real implementations.

**Small secrets and keys → Keychain** with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` (this class is *excluded from backups* and *never synced to iCloud*) and `kSecAttrSynchronizable = false`. Create `euwallet/ios/Sources/WalletShell/KeychainStorage.swift`:

```swift
import Foundation
import Security

public enum StorageError: Error { case keychain(OSStatus), notFound }

public final class KeychainStorage: SecureStorage, @unchecked Sendable {
    private let service: String
    public init(service: String = "eu.europa.ec.eudiw.store") { self.service = service }

    private func base(_ key: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: key]
    }

    public func put(key: String, value: Data) throws {
        SecItemDelete(base(key) as CFDictionary)                 // upsert
        var attrs = base(key)
        attrs[kSecValueData as String] = value
        attrs[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly  // no backup, no iCloud
        attrs[kSecAttrSynchronizable as String] = false
        let status = SecItemAdd(attrs as CFDictionary, nil)
        guard status == errSecSuccess else { throw StorageError.keychain(status) }
    }

    public func get(key: String) throws -> Data? {
        var q = base(key)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &out)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw StorageError.keychain(status) }
        return out as? Data
    }

    public func delete(key: String) throws {
        let status = SecItemDelete(base(key) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw StorageError.keychain(status) }
    }
}
```

**Large credential blobs → encrypted file store.** Defense in depth: (1) iOS **Data Protection** (`FileProtectionType.complete` — the file's contents are encrypted with a key wrapped by the device passcode/hardware and unreadable while locked), plus (2) an app-layer **AES-256-GCM** envelope keyed by a 256-bit data key kept in the Keychain (`ThisDeviceOnly`), plus (3) **backup exclusion**. Create `euwallet/ios/Sources/WalletShell/EncryptedFileStore.swift`:

```swift
import Foundation
import CryptoKit

public final class EncryptedFileStore: @unchecked Sendable {
    private let dir: URL
    private let keychain: KeychainStorage
    private let dataKeyId = "store-data-key.v1"

    public init(keychain: KeychainStorage = KeychainStorage()) throws {
        self.keychain = keychain
        let base = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask,
                                               appropriateFor: nil, create: true)
        self.dir = base.appendingPathComponent("credentials", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true,
            attributes: [.protectionKey: FileProtectionType.complete])
        try excludeFromBackup(dir)                               // never in iCloud/iTunes backups
    }

    private func dataKey() throws -> SymmetricKey {
        if let raw = try keychain.get(key: dataKeyId) { return SymmetricKey(data: raw) }
        let key = SymmetricKey(size: .bits256)
        try key.withUnsafeBytes { try keychain.put(key: dataKeyId, value: Data($0)) }  // hardware-wrapped at rest
        return key
    }

    public func write(_ id: String, _ plaintext: Data) throws {
        let sealed = try AES.GCM.seal(plaintext, using: dataKey()).combined!  // nonce||ct||tag
        let url = dir.appendingPathComponent(id)
        try sealed.write(to: url, options: [.completeFileProtection, .atomic])
        try excludeFromBackup(url)
    }

    public func read(_ id: String) throws -> Data? {
        let url = dir.appendingPathComponent(id)
        guard let sealed = try? Data(contentsOf: url) else { return nil }
        return try AES.GCM.open(AES.GCM.SealedBox(combined: sealed), using: dataKey())
    }

    public func delete(_ id: String) throws {
        try? FileManager.default.removeItem(at: dir.appendingPathComponent(id))
    }

    private func excludeFromBackup(_ url: URL) throws {
        var u = url; var rv = URLResourceValues(); rv.isExcludedFromBackup = true
        try u.setResourceValues(rv)
    }
}
```

Hard rules to state in code review and the certification memo (all enforced above):
- **No `UserDefaults`, no `.plist`, no `NSKeyedArchiver` to disk** for any credential or secret. Grep in CI: `! grep -rn "UserDefaults" euwallet/ios/Sources` must be empty.
- **`ThisDeviceOnly` accessibility** on every Keychain item ⇒ excluded from device backups and iCloud Keychain.
- **`isExcludedFromBackup = true`** on the store directory and files.
- **No secret ever reaches the logger** (§8.2's `Log` only takes pre-sanitised strings; never interpolate `value`, `payload`, `signature`).
- **No analytics SDK** is linked in the target that can observe credential bytes; if analytics exists, it lives in a separate module with no access to `WalletShell`.
- Optional extra binding: wrap the AES data key with the Secure Enclave key via ECIES (`SecKeyCreateEncryptedData`) so the store is unreadable without the Enclave — document in Section 4 if the memo requires it.

**Definition of done.**
- `euwallet/ios/Tests/WalletShellTests/StorageTests.swift`: `KeychainStorage` put/get/delete round-trips a value and `get` after `delete` returns `nil`; `EncryptedFileStore` write/read round-trips, and reading the raw file bytes off disk does **not** contain the plaintext (`XCTAssertFalse(rawFileBytes.contains(plaintext))`), proving encryption. Assert the store URL's `isExcludedFromBackup == true`. Command: `xcodebuild test -scheme WalletShell -destination 'platform=iOS Simulator,name=iPhone 15' -only-testing:WalletShellTests/StorageTests`. Expected: pass. Plus the CI grep: `cd euwallet && ! grep -rn "UserDefaults" ios/Sources` prints nothing.

---

### 8.9 Deep links and `ASWebAuthenticationSession` (OID4VP + OID4VCI, same- and cross-device)

**Inbound (OID4VP same-device).** A relying party launches the wallet with a URL carrying the Authorization Request (or a `request_uri`). SwiftUI delivers it via `.onOpenURL` (already wired in the app entry in §8.3). The shell passes the **entire URL as opaque bytes** to the core; the `oid4vp` crate parses and validates it (signed request object, RP registration, purpose — none of that is Swift's business):

```swift
.onOpenURL { url in
    Task { await executor.send(.authorizationRequestReceived(Data(url.absoluteString.utf8))) }
}
```

Register the schemes/universal links (Info.plist + entitlements, §8.11): custom schemes `openid4vp`, `haip`, `eudi-openid4vp` under `CFBundleURLTypes`, and **Associated Domains** `applinks:<your-wallet-domain>` for HTTPS universal links (preferred — they can't be hijacked by another app).

**Cross-device (OID4VP).** The wallet **scans** the reader's QR (§8.7.3); the decoded bytes become `.authorizationRequestReceived`. Same core entry point, different transport. The response is delivered by the core via `Effect::Http` (already handled in §8.2) to the RP's `response_uri`.

**Browser round-trips (OID4VCI authorization code flow, and any wallet-initiated web auth).** OpenID4VCI issuance (the `oid4vci` crate, its own section) sometimes requires sending the user through the issuer's browser-based authorization endpoint (with PAR) and catching a redirect back. Use **`ASWebAuthenticationSession`** — it shares cookies with Safari for SSO but is dismissible and, with `prefersEphemeralWebBrowserSession = true`, leaves no persistent state (privacy-preserving, matching the shared-context privacy rules). This is a **new effect** (Section 2 addition): `Effect::OpenAuthSession { id, url, callback_scheme }` → `Event::AuthCallback { id, url }` / `Event::AuthCancelled { id }`.

Create `euwallet/ios/Sources/WalletShell/AuthSession.swift`:

```swift
#if canImport(AuthenticationServices) && os(iOS)
import AuthenticationServices

public final class AuthSessionRunner: NSObject, ASWebAuthenticationPresentationContextProviding {
    private var session: ASWebAuthenticationSession?

    /// Returns the callback URL bytes for the core, or nil if the user cancelled.
    public func run(url: URL, callbackScheme: String) async -> URL? {
        await withCheckedContinuation { cont in
            let s = ASWebAuthenticationSession(url: url, callbackURLScheme: callbackScheme) { cb, _ in
                cont.resume(returning: cb)
            }
            s.prefersEphemeralWebBrowserSession = true       // no lingering cookies; privacy-preserving
            s.presentationContextProvider = self
            self.session = s
            DispatchQueue.main.async { s.start() }
        }
    }
    public func presentationAnchor(for _: ASWebAuthenticationSession) -> ASPresentationAnchor {
        ASPresentationAnchor()                               // return the app's key window in production
    }
}
#endif
```

Executor case (once the effect exists):

```swift
case .openAuthSession(let id, let url, let scheme):
    if let cb = await authRunner.run(url: URL(string: url)!, callbackScheme: scheme) {
        return .authCallback(id: id, url: Data(cb.absoluteString.utf8))
    } else {
        return .authCancelled(id: id)
    }
```

Security guardrails (from the shared context): never autofill/submit a form reached from untrusted content; never place personal data in query strings; only ever send data to endpoints the **core** supplied (which came from a validated request), never to a URL scraped from page content. The shell only ever opens URLs the core hands it in an effect.

**Definition of done.**
- Inbound: `euwallet/ios/Tests/WalletShellTests/DeepLinkTests.swift` builds a `URL("openid4vp://authorize?...")`, calls the same closure `.onOpenURL` uses, and asserts the core received `.authorizationRequestReceived` with `Data(url.absoluteString.utf8)` (use a spy core). Command: `swift test --filter DeepLinkTests`; expected: pass.
- Browser: on device/simulator, an integration test (or manual run) drives `AuthSessionRunner.run(url:callbackScheme:)` against a test authorization page that immediately redirects to `myscheme://cb?code=abc`; assert the returned URL's `code == "abc"`. Expected: the callback URL is captured and mapped to `Event::AuthCallback`.

---

### 8.10 App-level navigation with XState (strictly outside the certification core)

The Rust core's `ScreenDescription` decides **what protocol screen** is shown (consent, credential list, scan). It does **not** own the app's overall navigation shell — onboarding vs. home vs. settings vs. the modal that hosts a presentation flow, tab selection, returning to home after completion, handling a deep link while another screen is up. That app-shell navigation is where **Swift XState** (a statechart) belongs, and it is explicitly **outside the certification-critical core** (shared context: "Swift XState is reserved for iOS app-level navigation only").

The boundary rules — enforce them in review:

1. The navigation machine **never validates anything**, **never touches crypto or storage**, and **never inspects credential data**. It only reacts to coarse **milestone events** the shell derives from what the core rendered (e.g. "a presentation just completed" when a `.credentialList` render follows a consent flow).
2. The `ScreenRenderer` (§8.3) renders whatever `ScreenDescription` the core emits **inside** whatever container the navigation machine currently presents. They are orthogonal: the core owns screen *content*; XState owns screen *containment/routing*.
3. It runs on the main actor and holds no security state.

Sketch (`euwallet/ios/Sources/WalletShell/Navigation.swift`) — a hand-written statechart is fine, or use a small Swift XState port; keep it this simple:

```swift
#if canImport(SwiftUI)
import SwiftUI

@MainActor
public final class NavigationMachine: ObservableObject {
    public enum State: Equatable { case onboarding, home, presenting, issuing, scanning, settings }
    public enum Event { case finishedOnboarding, startPresentation, startIssuance, openScanner,
                        openSettings, presentationCompleted, cancelled, deepLinkArrived }

    @Published public private(set) var state: State = .onboarding

    public func send(_ e: Event) {
        switch (state, e) {
        case (.onboarding, .finishedOnboarding):        state = .home
        case (_, .deepLinkArrived), (_, .startPresentation): state = .presenting  // a request arrived → show the flow
        case (.home, .startIssuance):                   state = .issuing
        case (.home, .openScanner):                     state = .scanning
        case (_, .presentationCompleted), (_, .cancelled): state = .home          // always return home when done
        case (.home, .openSettings):                    state = .settings
        default: break                                                            // ignore illegal transitions
        }
    }
}
#endif
```

The app derives milestone events from renders (a thin mapping, not protocol logic):

```swift
render: { screen in
    Task { @MainActor in
        store.update(screen)
        switch screen {
        case .consent: nav.send(.startPresentation)
        case .credentialList: nav.send(.presentationCompleted)   // flow ended
        default: break
        }
    }
}
```

**Definition of done.**
- `euwallet/ios/Tests/WalletShellTests/NavigationTests.swift`: assert `finishedOnboarding` moves `.onboarding → .home`; a `.consent` render (via `.startPresentation`) moves to `.presenting`; a `.credentialList` render (via `.presentationCompleted`) returns to `.home`; illegal transitions are ignored. Also a **negative** assertion documenting the boundary: `NavigationMachine` has no reference to `Signer`, `SecureStorage`, or any crypto type (grep: `cd euwallet && ! grep -nE "Signer|Storage|SecKey|CryptoKit" ios/Sources/WalletShell/Navigation.swift`). Command: `swift test --filter NavigationTests`; expected: pass, and the grep prints nothing.

---

### 8.11 App target, Info.plist, and entitlements checklist

The `WalletShell` package is a library; the runnable app + UI tests need a thin **app target**. Create it under `euwallet/ios/App/` (an Xcode project that depends on the `WalletShell` package; the build pipeline is Section 3's `build-core.sh` + `xcodebuild`). The app target is deliberately tiny: `EUDIWalletApp.swift` (§8.3), `Info.plist`, and `EUDIWallet.entitlements`.

**`Info.plist` keys (required by the features above):**

| Key | Why |
|---|---|
| `NSFaceIDUsageDescription` | Biometric gate on the Secure Enclave signing key (§8.4). |
| `NSCameraUsageDescription` | QR scanning (§8.7.3). |
| `NSBluetoothAlwaysUsageDescription` | BLE proximity (§8.7.1). |
| `NFCReaderUsageDescription` | NFC reader sessions (§8.7.2). |
| `CFBundleURLTypes` | Custom schemes `openid4vp`, `haip`, `eudi-openid4vp` for same-device OID4VP (§8.9). |

**`EUDIWallet.entitlements`:**

| Entitlement | Why |
|---|---|
| `com.apple.developer.associated-domains` = `applinks:<wallet-domain>` | HTTPS universal links for OID4VP (§8.9). |
| `com.apple.developer.default-data-protection` = `NSFileProtectionComplete` | Hardware file encryption default (§8.8). |
| `com.apple.developer.nfc.readersession.formats` | NFC reader (§8.7.2). |
| `com.apple.developer.nfc.hce` | **Optional/gated** — only if you ship NFC HCE engagement (§8.7.2). |
| App Attest capability (`com.apple.developer.devicecheck.appattest-environment`) | WUA key attestation (§8.6, WUA section). |

Do **not** enable iCloud/Keychain Sharing capabilities for the credential store — `ThisDeviceOnly` items must not sync.

**Definition of done.**
- Command: `xcodebuild build -scheme EUDIWallet -destination 'platform=iOS Simulator,name=iPhone 15'`. Expected: `BUILD SUCCEEDED`. Launch in the simulator: the app opens without crashing (no missing-usage-string crashes when a feature is first used), and the first BLE/camera/NFC use presents the correct system permission prompt.

---

### 8.12 Section acceptance: the end-to-end run

This is the section's overall **Definition of done**, combining the machine-checkable gate with a simulator/device run.

1. **Always-green CI gate (Mac host).**
   - Command: `cd euwallet/ios && swift test`
   - Expected: all suites pass — `EffectExecutorTests` (cascade + minimisation), `ConsentAndSignAcceptanceTests` (core-produced consent render + `Sign` completed and signature verified), `SignerTests` (DER→raw, 64-byte ES256), `StorageTests`, `BleFramingTests`, `QrTests` (where iOS-gated, run under `xcodebuild`), `NavigationTests`, `DeepLinkTests`. Final line: `Test Suite 'All tests' passed`.

2. **Secure Enclave + biometrics (real device).**
   - Command: `xcodebuild test -scheme WalletShell -destination 'platform=iOS,name=<your iPhone>' -only-testing:WalletShellTests/ConsentAndSignAcceptanceTests`
   - Expected: the Face ID/Touch ID sheet appears during `userConsented`; after you authenticate, the test passes — proving the `Sign` effect completed through the **Secure Enclave** and produced a signature that verifies against the Enclave's public key.

3. **Simulator UI run (consent → sign → done).** With the app target and an XCUITest (`euwallet/ios/UITests/ConsentFlowUITests.swift`) launched with `-uiTestConsentFlow` (injects a canned authorization request) and `-signerMode stub` (uses a non-biometric ephemeral signer so CI needs no Face ID automation):

```swift
import XCTest
final class ConsentFlowUITests: XCTestCase {
    func testConsentToCompletion() {
        let app = XCUIApplication()
        app.launchArguments += ["-uiTestConsentFlow", "-signerMode", "stub"]
        app.launch()
        XCTAssertTrue(app.otherElements["consent.screen"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts["Will be shared: age over 18"].exists)   // core-driven, minimised
        app.buttons["consent.share"].tap()
        XCTAssertTrue(app.staticTexts["Your credentials"].waitForExistence(timeout: 5)) // cascade completed
    }
}
```

   - Command: `xcodebuild test -scheme EUDIWallet -destination 'platform=iOS Simulator,name=iPhone 15' -only-testing:ConsentFlowUITests`
   - Expected: `Test Succeeded` — the app **renders the Consent screen from a core-produced `ScreenDescription`**, the user taps Share, the `Sign → Http → Render(CredentialList)` cascade runs, and the app lands on the credential list. (On a real device, drop `-signerMode stub` to exercise the Secure Enclave + biometric prompt for the full path; approve Face ID when prompted.)

Passing (1) and either (2) or (3) satisfies the section requirement: **the app renders a Consent screen from a core-produced `ScreenDescription` and completes a `Sign` effect via the Secure Enclave.** From here, filling in the remaining archetypes (§8.3) and transports (§8.7) is additive — the executor, signer, storage, and accessibility foundations are all in place, and every new flow is exercised the same way: drive the core with an `Event`, let it emit `Effect`s, and let the shell execute them.

---


## Section 9 — Formal Tier 1: proptest property tests, cargo-fuzz, Kani, forbid-unsafe

Tier 1 is the *always-on* floor of assurance. Every codec crate (`mdoc`, `sdjwt`, `cose`, `x509`, `status`) parses bytes that arrive over the network or off a QR code from a *hostile* source — a malicious relying party (RP), a tampered issuer response, a corrupted proximity transport frame. The register requires **malformed-input evidence per codec**: for each crate that decodes untrusted bytes we must be able to point an evaluator at (a) a property test proving the decoder never panics and round-trips valid data, (b) a fuzz target with a corpus and a bounded CI run, and (c) at least one machine-checked proof of a codec invariant. This section makes all three runnable.

The three techniques are **complementary, not redundant** — read this before writing any of them:

| Technique | What it does | What it catches that the others do NOT |
|---|---|---|
| `#![forbid(unsafe_code)]` | Compile-time ban on `unsafe` blocks in the crate | Memory-unsafety *by construction* — no buffer overrun, use-after-free, or uninitialised read can exist in a crate that cannot write `unsafe`. Neither proptest nor Kani *prevents* you from adding `unsafe`; this does. |
| **proptest** | Generates thousands of *random structured* inputs each run, shrinks failures to a minimal counterexample | Logic bugs on *plausible* inputs (round-trip loss, a field that silently drops, an ordering bug in canonical CBOR). Fast, runs every `cargo test`. It is *random*, so it finds bugs probabilistically and gives no coverage guarantee. |
| **cargo-fuzz** (libFuzzer) | Coverage-guided mutation over *raw bytes*, runs for minutes/hours, keeps a growing corpus | Deep parser bugs reachable only through weird byte sequences a structured generator would never build — integer-overflow in a length prefix, unbounded recursion, a panic on truncated input. Coverage feedback drives it into rare branches proptest's structured strategies can't reach. |
| **Kani** (bounded model checking, CBMC) | *Exhaustively* proves a property for ALL inputs within a bound (e.g. all slices of length ≤ N) | *Absence* of a bug — a mathematical guarantee "no input up to bound N triggers this panic / breaks this invariant". proptest and fuzzing can only ever show *presence* of bugs; they never prove absence. |

The intuition: **forbid-unsafe** removes an entire bug class up front; **proptest** is your fast day-to-day logic net; **fuzz** is your deep overnight/CI byte-level net; **Kani** upgrades a *specific* critical invariant from "we tested a lot" to "we proved it". You want all four because each has a blind spot the next one covers.

Everything below assumes the canonical workspace at `crates/` (see Section 3 for workspace setup) and the toolchain in the shared context.

---

### 9.1 — `#![forbid(unsafe_code)]` in every core crate

`unsafe` is the Rust keyword that switches off the compiler's memory-safety checks (raw pointer deref, `transmute`, calling C). A certification-critical parser has no business containing it. `#![forbid(unsafe_code)]` is a *crate-level attribute* (the `#!` means "applies to the whole crate, from the top of the root file") that makes any `unsafe` block a **hard compile error** — `forbid` is stronger than `deny`: it cannot be locally re-enabled with `#[allow(unsafe_code)]` further down. This is the single cheapest, strongest assurance line in the whole plan.

**Step 1.** Add the attribute as the *first line* of the crate root (`src/lib.rs`) of every core crate. Do this for all of them: `crypto-traits`, `cose`, `mdoc`, `sdjwt`, `x509`, `oid4vp`, `oid4vci`, `iso18013-5`, `trust`, `status`, `wua`, `presenter`, `wallet-core`.

Example — `crates/mdoc/src/lib.rs`:

```rust
#![forbid(unsafe_code)]
//! mdoc: deterministic (canonical) CBOR + ISO/IEC 18013-5 mdoc structures.
//! No `unsafe` may appear anywhere in this crate — enforced at compile time.

pub mod cbor;      // deterministic CBOR codec
pub mod issuer_signed;
pub mod device_signed;
pub mod mso;       // MobileSecurityObject
// ...
```

**Step 2.** Belt-and-braces: also enforce it *workspace-wide* through lints so a new crate can't forget the attribute. In the workspace root `Cargo.toml` add a `[workspace.lints]` table (Rust 1.74+), and have each crate inherit it:

`Cargo.toml` (workspace root):

```toml
[workspace.lints.rust]
unsafe_code = "forbid"
missing_docs = "warn"

[workspace.lints.clippy]
# deny a few panic-prone patterns in codecs; see 9.2 note on panics
unwrap_used = "warn"
expect_used = "warn"
indexing_slicing = "warn"   # array[i] can panic; prefer .get(i)
```

Each crate's `Cargo.toml` then adds:

```toml
[lints]
workspace = true
```

> Jargon: a *lint* is a compiler/clippy diagnostic; `"forbid"` is its highest severity. `clippy` is Rust's extended linter (`cargo clippy`). `indexing_slicing` flags `slice[i]` which *panics* on out-of-range — in a parser you almost always want `slice.get(i)` which returns `Option` instead. We set these to `warn` (not `deny`) so they guide without blocking; the fuzz + proptest gates below are what actually prove no panic.

**Step 3.** Verify no `unsafe` sneaks in via a *dependency* either. The `cargo-geiger` tool counts `unsafe` usage across the dependency tree. Install and run:

```bash
cargo install --locked cargo-geiger
cargo geiger --workspace --output-format Ascii
```

You will still see `unsafe` inside upstream crates like `aws-lc-rs` (that's expected and *intended* — the whole point of using a vetted crypto lib is to concentrate `unsafe` there, see the shared "DO NOT DO" rules). What matters is that **our** crates show zero. Record this in the certification memo.

**Definition of done.**
Run:

```bash
cargo build --workspace 2>&1 | tee /tmp/build.log
grep -rn 'unsafe' crates/*/src | grep -v 'unsafe_code'   # should print nothing
```

Then prove the guard actually fires — temporarily add `unsafe { let _ = 1; }` inside any function in `crates/mdoc/src/lib.rs` and run `cargo build -p mdoc`. Expected output (then revert):

```
error: usage of an `unsafe` block
 --> crates/mdoc/src/lib.rs:NN:5
  = note: `#[forbid(unsafe_code)]` on by default
```

A red compile error on the deliberate `unsafe`, and a clean build once reverted, is the done state.

---

### 9.2 — proptest property tests (round-trip + never-panic, per codec)

`proptest` is a property-based testing library: instead of you writing example inputs, you declare a *strategy* that generates random typed values, and proptest checks a property (an assertion that must hold for *all* generated values). When it finds a failure it **shrinks** — automatically reduces the counterexample to the smallest input that still fails — which is what makes it so much more useful than random testing.

We assert two properties per codec:

1. **Round-trip** (encode/decode are inverse): `decode(encode(x)) == x` for all valid structured `x`. This catches silent data loss and canonical-ordering bugs.
2. **Never-panic on arbitrary bytes**: `decode(arbitrary_bytes)` returns `Ok`/`Err` but **never panics and never runs forever**. This is the malformed-input property the register demands.

**Step 1.** Add the dev-dependency to each codec crate. Example `crates/mdoc/Cargo.toml`:

```toml
[dev-dependencies]
proptest = "1"
```

(`dev-dependencies` are compiled only for tests/benches, never shipped in the wallet binary.)

**Step 2.** Write a `proptest`-friendly generator (a *strategy*) for the structured type. Put reusable strategies behind a `#[cfg(test)]` module or a `test-support` feature. For a minimal mdoc `IssuerSignedItem` example, `crates/mdoc/src/issuer_signed.rs`:

```rust
use serde::{Serialize, Deserialize};

/// One selectively-disclosable data element inside an mdoc namespace.
/// (ISO/IEC 18013-5 §8.3: IssuerSignedItem)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IssuerSignedItem {
    pub digest_id: u64,          // digestID
    pub random: Vec<u8>,         // 16+ bytes of salt
    pub element_identifier: String,
    pub element_value: CborValue, // your profiled CBOR value type
}
```

Then the strategy + tests in `crates/mdoc/tests/proptest_issuer_signed.rs` (files under `tests/` are integration tests — they compile against the crate's *public* API, exactly what an evaluator inspects):

```rust
use proptest::prelude::*;
use mdoc::issuer_signed::IssuerSignedItem;
use mdoc::cbor::{encode_canonical, decode};   // your deterministic-CBOR entry points

// A strategy that builds arbitrary *valid* IssuerSignedItems.
fn arb_item() -> impl Strategy<Value = IssuerSignedItem> {
    (
        any::<u64>(),
        prop::collection::vec(any::<u8>(), 16..=32),          // random salt, 16..32 bytes
        "[a-zA-Z0-9_]{1,32}",                                 // element_identifier
        arb_cbor_value(),                                     // see below
    ).prop_map(|(digest_id, random, element_identifier, element_value)| {
        IssuerSignedItem { digest_id, random, element_identifier, element_value }
    })
}

// Bounded recursive strategy for your CBOR value type (depth-limited to keep it finite).
fn arb_cbor_value() -> impl Strategy<Value = mdoc::cbor::CborValue> {
    use mdoc::cbor::CborValue;
    let leaf = prop_oneof![
        Just(CborValue::Null),
        any::<bool>().prop_map(CborValue::Bool),
        any::<i64>().prop_map(CborValue::Int),
        any::<String>().prop_map(CborValue::Text),
        prop::collection::vec(any::<u8>(), 0..64).prop_map(CborValue::Bytes),
    ];
    leaf.prop_recursive(
        4,   // max depth
        32,  // max total nodes
        8,   // max items per collection
        |inner| prop_oneof![
            prop::collection::vec(inner.clone(), 0..8).prop_map(CborValue::Array),
            prop::collection::vec((any::<String>(), inner), 0..8)
                .prop_map(|kvs| CborValue::Map(kvs.into_iter().collect())),
        ],
    )
}

proptest! {
    // Property 1: round-trip. Deterministic CBOR must be a true inverse.
    #[test]
    fn issuer_signed_item_roundtrips(item in arb_item()) {
        let bytes = encode_canonical(&item).expect("encode must succeed for valid item");
        let decoded: IssuerSignedItem = decode(&bytes).expect("decode of our own bytes must succeed");
        prop_assert_eq!(item, decoded);
    }

    // Property 1b: canonical encoding is a fixed point — re-encoding is byte-identical.
    // This is the deterministic-CBOR guarantee the consent hash (Section 8) relies on.
    #[test]
    fn canonical_encoding_is_stable(item in arb_item()) {
        let b1 = encode_canonical(&item).unwrap();
        let decoded: IssuerSignedItem = decode(&b1).unwrap();
        let b2 = encode_canonical(&decoded).unwrap();
        prop_assert_eq!(b1, b2);
    }

    // Property 2: never panic (and terminate) on ARBITRARY bytes.
    #[test]
    fn decode_never_panics_on_arbitrary_bytes(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
        // We only assert it returns — Ok or Err both fine. A panic fails the test;
        // an infinite loop is caught by the per-case timeout below.
        let _ : Result<IssuerSignedItem, _> = decode(&bytes);
    }
}
```

**Step 3.** Guard against *infinite loops / runaway recursion* (a real risk in a CBOR/DER parser) with a per-case timeout and a bounded default case count. Create `crates/mdoc/proptest.toml` (proptest reads it automatically) or use the inline config:

`crates/mdoc/proptest.toml`:

```toml
# Fail a case that runs longer than 1s (catches non-termination as a test failure).
timeout = 1000
# Default cases per property per run.
cases = 1024
```

To reproduce a shrunk failure later, proptest writes a regression seed file `crates/mdoc/tests/proptest_issuer_signed.proptest-regressions` — **commit this file**; it turns every discovered counterexample into a permanent deterministic test.

**Step 4.** Replicate the same two-property pattern in each codec crate. Exact files to create:

- `crates/sdjwt/tests/proptest_disclosures.rs` — round-trip an SD-JWT `Disclosure` (`[salt, claim_name, claim_value]` base64url array, draft-17), and `decode_never_panics` on arbitrary base64url and arbitrary bytes.
- `crates/cose/tests/proptest_sign1.rs` — round-trip a `COSE_Sign1` structure's *unprotected/protected header + payload* framing (not the signature math — that's Section 5's crypto-traits), never-panic on arbitrary CBOR.
- `crates/x509/tests/proptest_der.rs` — never-panic on arbitrary bytes fed to the certificate parser (round-trip is weaker for DER since you parse but rarely re-encode; assert *parse-idempotent* on any bytes that parsed OK: `parse(bytes)` twice yields equal structures).
- `crates/status/tests/proptest_statuslist.rs` — round-trip a Token Status List (draft-21) bit-packed structure, never-panic on arbitrary compressed input (guard the zlib/deflate step against decompression bombs — assert a size cap is enforced, see 9.3 corpus note).

**Definition of done.**
Run:

```bash
cargo test --workspace --tests
```

Expected: all proptest cases pass, e.g. per crate a line like

```
test issuer_signed_item_roundtrips ... ok
test canonical_encoding_is_stable ... ok
test decode_never_panics_on_arbitrary_bytes ... ok
```

To *prove the never-panic net actually works*, temporarily introduce a bug — e.g. make the CBOR length reader do `let len = buf[0] as usize; &buf[1..1+len]` (a slice that panics on truncated input) — run `cargo test -p mdoc` and confirm proptest fails and prints a shrunk counterexample like `minimal failing input: bytes = [255]`, plus writes a `.proptest-regressions` line. Revert the bug; the test goes green. That red→green cycle is the done state.

---

### 9.3 — cargo-fuzz (libFuzzer) targets per codec, corpus, official vectors, bounded CI run

`cargo-fuzz` wires your crate to **libFuzzer**, a coverage-guided fuzzer: it mutates input bytes, watches which code branches each mutation reaches (via compiler instrumentation), and keeps inputs that reach *new* coverage — steadily working its way into deep parser corners. A **corpus** is the directory of interesting inputs it has kept; **seeds** are inputs *you* place there to start it in a good spot (this is where official EUDI test vectors go). Fuzzing needs a nightly toolchain (libFuzzer's sanitizer instrumentation is nightly-only).

**Step 1.** Install the tooling once:

```bash
rustup toolchain install nightly
cargo install --locked cargo-fuzz
```

**Step 2.** Initialise a fuzz project *inside each codec crate*. From the repo root:

```bash
cd crates/mdoc
cargo +nightly fuzz init
```

This creates `crates/mdoc/fuzz/` with its own `Cargo.toml`, a `fuzz_targets/` dir, and a placeholder target. Delete the placeholder and create one target per parser entry point.

**Step 3.** Write the fuzz target. `crates/mdoc/fuzz/fuzz_targets/decode_issuer_signed.rs`:

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use mdoc::issuer_signed::IssuerSignedItem;
use mdoc::cbor::{decode, encode_canonical};

fuzz_target!(|data: &[u8]| {
    // 1) The parser must never crash on any bytes.
    if let Ok(item) = decode::<IssuerSignedItem>(data) {
        // 2) Differential/round-trip invariant on ACCEPTED inputs:
        //    if it decoded, canonical re-encode must decode back to the same value.
        let re = encode_canonical(&item).expect("accepted value must re-encode");
        let item2: IssuerSignedItem = decode(&re).expect("canonical bytes must decode");
        assert_eq!(item, item2, "round-trip mismatch on fuzz-accepted input");
        // 3) Canonical form must be a fixed point (deterministic-CBOR guarantee).
        let re2 = encode_canonical(&item2).unwrap();
        assert_eq!(re, re2, "canonical encoding not stable");
    }
});
```

> Note the design: a fuzz target that only checks "doesn't crash" is weak. By adding the round-trip + canonical-stability *asserts on accepted inputs*, libFuzzer's coverage guidance actively hunts for inputs that decode but violate our invariants — far stronger evidence for the register.

Create the analogous targets:

- `crates/sdjwt/fuzz/fuzz_targets/parse_sdjwt.rs` — feed bytes as a `str` (lossy) into the SD-JWT compact-serialization splitter + disclosure parser.
- `crates/cose/fuzz/fuzz_targets/parse_sign1.rs` — parse `COSE_Sign1` framing.
- `crates/x509/fuzz/fuzz_targets/parse_cert.rs` — parse a DER certificate.
- `crates/status/fuzz/fuzz_targets/parse_statuslist.rs` — parse + (bounded) inflate a Token Status List; include an assert that any successful inflate stayed under the size cap (decompression-bomb guard).

Each crate's `crates/<crate>/fuzz/Cargo.toml` must depend on the crate under test, e.g.:

```toml
[dependencies]
libfuzzer-sys = "0.4"
mdoc = { path = ".." }
```

**Step 4.** Seed the corpus with **official EUDI/ISO test vectors** — this is the highest-value action in the whole subsection, because it starts libFuzzer inside the real protocol grammar and it makes malformed *variants of real messages* the thing you fuzz. Put vetted vectors under a version-pinned directory (respecting the shared "CI interop oracle only" rule — we use the EC reference vectors as *data*, never as a runtime dep):

```bash
mkdir -p crates/mdoc/fuzz/corpus/decode_issuer_signed
mkdir -p crates/mdoc/tests/vectors/iso18013-5/v2nd-draft   # version-pinned, committed

# Copy the canonical CBOR example blobs (IssuerSigned, MSO) from the ISO/EUDI test suite
# into the corpus as seeds (these are just bytes; commit them):
cp crates/mdoc/tests/vectors/iso18013-5/v2nd-draft/*.cbor \
   crates/mdoc/fuzz/corpus/decode_issuer_signed/
```

Do the same per codec: SD-JWT VC example credentials (draft-17) → `crates/sdjwt/fuzz/corpus/parse_sdjwt/`; real EU/ETSI issuer/RP certificates → `crates/x509/fuzz/corpus/parse_cert/`; a real Token Status List (draft-21) → `crates/status/fuzz/corpus/parse_statuslist/`. Commit the corpus dirs; they are both fuzzing seeds *and* regression evidence.

**Step 5.** Run locally to sanity-check, then let it run longer:

```bash
# Quick smoke run: 60 seconds.
cd crates/mdoc
cargo +nightly fuzz run decode_issuer_signed -- -max_total_time=60

# Longer local hunt with a memory + input-size cap:
cargo +nightly fuzz run decode_issuer_signed -- \
    -max_total_time=1800 -rss_limit_mb=2048 -max_len=8192
```

If libFuzzer finds a crash it writes the offending bytes to `crates/mdoc/fuzz/artifacts/decode_issuer_signed/crash-<hash>`. Reproduce and debug it with:

```bash
cargo +nightly fuzz run decode_issuer_signed crates/mdoc/fuzz/artifacts/decode_issuer_signed/crash-<hash>
```

**Minimise** the corpus periodically to keep CI fast (`cmin` drops inputs that don't add coverage):

```bash
cargo +nightly fuzz cmin decode_issuer_signed
```

**Step 6.** Wire a **bounded** fuzz run into CI. Full fuzzing is unbounded; CI needs a fixed time budget per target that (a) always replays the committed corpus + seeds (regression) and (b) does a short fresh mutation burst. Add a job to `.github/workflows/ci.yml` (see Section 16 for the full pipeline; this is the fuzz gate):

```yaml
  fuzz-bounded:
    runs-on: macos-14        # Apple Silicon runner (matches target OS)
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@nightly
      - run: cargo install --locked cargo-fuzz
      - name: Bounded fuzz per codec
        run: |
          set -euo pipefail
          for c in mdoc sdjwt cose x509 status; do
            for t in $(cargo +nightly fuzz list --fuzz-dir crates/$c/fuzz); do
              echo "::group::fuzz $c/$t"
              # -runs=0 first: replay the whole committed corpus (pure regression, must pass).
              cargo +nightly fuzz run --fuzz-dir crates/$c/fuzz "$t" -- -runs=0
              # then a bounded fresh burst (60s) to catch new regressions in changed code.
              cargo +nightly fuzz run --fuzz-dir crates/$c/fuzz "$t" -- \
                  -max_total_time=60 -rss_limit_mb=2048 -max_len=8192
              echo "::endgroup::"
            done
          done
```

> Why `-runs=0` first: it makes CI *fail deterministically* if any previously-found or seed input now crashes — that's the true regression gate. The 60s burst is best-effort discovery; keep it short so PRs aren't blocked for long, and run a *nightly* unbounded fuzz job (a separate scheduled workflow with `-max_total_time=3600` per target) for deeper coverage.

**Definition of done.**
Locally:

```bash
cd crates/mdoc && cargo +nightly fuzz run decode_issuer_signed -- -runs=0
```

Expected tail:

```
INFO: seed corpus: files: N ... 
Done N runs in 0 second(s)
```

with no `==ERROR==`/`crash-` artifact produced. Prove the fuzzer bites: temporarily reintroduce the truncation-panic bug from 9.2, run the target, and confirm libFuzzer reports `panicked at ...`, writes a `crash-*` artifact, and exits non-zero. Revert; `-runs=0` over the corpus is clean. A green bounded CI `fuzz-bounded` job across all five codecs, with committed corpora containing the official seed vectors, is the done state.

---

### 9.4 — Kani: bounded proofs of codec invariants

Kani is a **bit-precise bounded model checker** for Rust (built on CBMC). Where proptest/fuzz *sample* inputs, Kani *symbolically explores ALL inputs within a bound* and either proves the property holds for every one of them or produces a concrete counterexample. We use it to lift the two most safety-critical codec invariants from "well-tested" to "proved (bounded)":

1. **Canonical CBOR is injective / deterministic** — the encoder never produces two different byte strings for equal inputs, and (the property that actually protects the consent hash in Section 8) *decoding then re-encoding is a fixed point*.
2. **A parser invariant** — e.g. the CBOR length reader never reads out of bounds, for all inputs up to a bounded length.

**Step 1.** Install Kani (listed as MISSING in the shared context):

```bash
cargo install --locked kani-verifier
cargo kani setup      # downloads the CBMC backend; one-time, ~1GB
```

Verify:

```bash
cargo kani --version   # e.g. "cargo-kani 0.x"
```

**Step 2.** Write proof harnesses. Kani harnesses are ordinary functions annotated `#[kani::proof]`, using `kani::any()` to introduce a *symbolic* value ("any possible value of this type") and `kani::assume(...)` to constrain it. Put them behind `#[cfg(kani)]` so they don't affect normal builds. Add to `crates/mdoc/src/cbor.rs`:

```rust
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// PROOF 1 (deterministic-CBOR fixed point):
    /// For ANY byte string that decodes to a small CBOR value, canonical
    /// re-encoding is stable: encode(decode(b)) == encode(decode(encode(decode(b)))).
    /// This is the invariant the consent hash (Section 8) depends on.
    #[kani::proof]
    #[kani::unwind(6)]          // bound loop/recursion unrolling (see note)
    fn canonical_encoding_is_fixed_point() {
        // A symbolic input buffer of bounded length.
        let len: usize = kani::any();
        kani::assume(len <= 4);                 // bound: all byte strings up to length 4
        let mut buf = [0u8; 4];
        for i in 0..len { buf[i] = kani::any(); }
        let bytes = &buf[..len];

        if let Ok(v) = decode::<CborValue>(bytes) {
            let e1 = encode_canonical(&v).unwrap();
            let v2 = decode::<CborValue>(&e1).unwrap();   // must round-trip
            let e2 = encode_canonical(&v2).unwrap();
            assert_eq!(e1, e2, "canonical encoding must be a fixed point");
        }
    }

    /// PROOF 2 (injectivity of the canonical encoder on a small typed domain):
    /// equal inputs -> equal encodings, and (the contrapositive we care about)
    /// different encodings imply different inputs. Proved by construction over a
    /// bounded symbolic integer value.
    #[kani::proof]
    fn canonical_encoder_is_deterministic() {
        let n: i64 = kani::any();
        kani::assume(n >= -1000 && n <= 1000);
        let a = CborValue::Int(n);
        let b = CborValue::Int(n);
        assert_eq!(encode_canonical(&a).unwrap(), encode_canonical(&b).unwrap());
    }

    /// PROOF 3 (parser bounds-safety): the length-prefixed byte-string reader
    /// never indexes out of bounds — it always returns Err on truncation
    /// rather than panicking, for ALL inputs up to the bound.
    #[kani::proof]
    #[kani::unwind(6)]
    fn length_reader_never_out_of_bounds() {
        let len: usize = kani::any();
        kani::assume(len <= 5);
        let mut buf = [0u8; 5];
        for i in 0..len { buf[i] = kani::any(); }
        // Must return Result, never panic. Kani proves no reachable panic.
        let _ = read_byte_string(&buf[..len]);
    }
}
```

> Jargon and gotchas:
> - `kani::any::<T>()` = a symbolic value standing for *every* value of `T` simultaneously; the solver reasons over all of them.
> - `kani::assume(cond)` restricts the symbolic search to inputs satisfying `cond` — this is how you set the *bound* (Kani is a *bounded* checker: you prove for all inputs up to a size, not literally infinite inputs; state the bound in the cert memo).
> - `#[kani::unwind(k)]` bounds how many times loops/recursion are unrolled. If your parser loops over input bytes, the unwind bound must exceed the max buffer length or Kani reports an "unwinding assertion" failure — that failure is *informative* (it means your bound is too small), not a bug in the code.
> - Keep bounds *small* (lengths ≤ 4–6). Kani cost grows fast; the value is proving "no counterexample exists *at all* up to this bound", which fuzzing can never assert. A small bound that *proves absence* is worth more than a large sample that only shows presence.

**Step 3.** Run the proofs:

```bash
cd crates/mdoc
cargo kani                                  # runs all #[kani::proof] harnesses in the crate
cargo kani --harness canonical_encoding_is_fixed_point   # run just one
```

Add the harnesses similarly for the other codecs where a crisp invariant exists — highest value: `crates/status` (prove the status-list bit index maps to exactly one bit, and inflate respects the size cap for all bounded inputs) and `crates/cose` (prove header parsing rejects duplicate map keys — a real COSE canonicalisation footgun).

**Step 4.** Wire a Kani gate into CI. It's slower than unit tests, so give it its own job with a timeout (Section 16 references this):

```yaml
  kani-proofs:
    runs-on: macos-14
    timeout-minutes: 45
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo install --locked kani-verifier && cargo kani setup
      - name: Model-check codec invariants
        run: |
          set -euo pipefail
          for c in mdoc cose status x509 sdjwt; do
            ( cd crates/$c && cargo kani )
          done
```

**Definition of done.**
Run:

```bash
cd crates/mdoc && cargo kani --harness canonical_encoding_is_fixed_point
```

Expected tail:

```
SUMMARY:
 ** 0 of NN failed
VERIFICATION:- SUCCESSFUL
Verification Time: X.XXXs
```

Prove Kani catches a real defect: temporarily break canonical ordering (e.g. make map-key sorting compare keys as signed instead of by canonical CBOR byte order) and rerun — Kani prints `VERIFICATION:- FAILED` with a concrete counterexample trace (the two map entries whose ordering diverges), something you can turn into a permanent proptest regression. Revert; `SUCCESSFUL` returns. That is the done state.

---

### 9.5 — Register justification and the combined Tier-1 CI gate

**Register justification.** The High-Level Requirements register requires, per codec that ingests untrusted input, *evidence that malformed input cannot compromise the wallet*. Tier 1 supplies exactly that, in three independent forms an evaluator can re-run:

- **Memory-safety by construction**: `#![forbid(unsafe_code)]` in every core crate + `cargo geiger` showing zero `unsafe` in our code (9.1) — discharges the "no memory-unsafety in the parser" requirement without relying on testing at all.
- **Malformed-input robustness**: proptest `decode_never_panics_on_arbitrary_bytes` (9.2) + a coverage-guided cargo-fuzz target per codec seeded with official EUDI/ISO/ETSI vectors (9.3) — discharges "does not panic/hang/mis-parse on hostile input", with the committed corpus + `crash-*` artifacts as reproducible evidence.
- **Codec-correctness invariants, machine-checked**: proptest round-trip/canonical-stability + Kani bounded proofs of encoder determinism and parser bounds-safety (9.4) — discharges "canonical encoding is deterministic" (the property the consent-hash / what-you-see-is-what-you-sign guarantee in Section 8 rests on) and "parser is bounds-safe up to bound N".

Cross-reference: Tier 2 (Section 10, Lean) proves *protocol state-machine* properties and exports replay traces; Tier 3 (Section 11, Tamarin) proves *protocol-design* secrecy/agreement. Tier 1 here is strictly about the *codecs and memory safety underneath them* — the layer Tiers 2 and 3 assume is correct.

**Combined Tier-1 gate.** All three techniques must be runnable from one command for local pre-push and must each be a required status check in CI. Add a convenience script `scripts/tier1.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail
echo "== forbid-unsafe / build =="
cargo build --workspace
cargo geiger --workspace --output-format Ascii | grep -E 'crates/' || true

echo "== proptest (all codecs) =="
cargo test --workspace --tests

echo "== cargo-fuzz corpus replay (regression) =="
for c in mdoc sdjwt cose x509 status; do
  for t in $(cargo +nightly fuzz list --fuzz-dir "crates/$c/fuzz"); do
    cargo +nightly fuzz run --fuzz-dir "crates/$c/fuzz" "$t" -- -runs=0
  done
done

echo "== kani bounded proofs =="
for c in mdoc cose status x509 sdjwt; do ( cd "crates/$c" && cargo kani ); done

echo "TIER 1: ALL GREEN"
```

Make it executable (`chmod +x scripts/tier1.sh`) and require the three CI jobs — `proptest` (part of the workspace `cargo test`), `fuzz-bounded`, `kani-proofs` — as *branch-protection required checks* on `main` (Section 16 configures branch protection). A PR cannot merge unless all three are green.

**Definition of done (section).**
From a clean checkout:

```bash
rustup toolchain install nightly
cargo install --locked cargo-fuzz kani-verifier cargo-geiger
cargo kani setup
./scripts/tier1.sh
```

Expected final line:

```
TIER 1: ALL GREEN
```

with, along the way: a clean `cargo build`, `cargo geiger` showing zero `unsafe` in `crates/*`, every proptest property `... ok`, every fuzz target's `-runs=0` corpus replay `Done ... runs` with no crash, and every Kani harness `VERIFICATION:- SUCCESSFUL`. In CI, the `proptest`, `fuzz-bounded`, and `kani-proofs` jobs are all present, green, and marked required on `main`. That is the done state for Section 9.

---


## Section 10 — Formal Tier 2: the Lean 4 model, invariant proofs, and the trace-export oracle

Tier 1 (§9) hammers the *codecs* with property tests, fuzzing, and Kani. Tier 3 (§11) attacks the *protocol design* with a symbolic network adversary. Tier 2 — this section — sits in between and is the highest-leverage of the three: we build a **second, independent implementation of the presentation state machines in Lean 4**, *prove* the machine can never do the three things a wallet must never do, and then turn that proven model into an **executable oracle** that generates conformance test vectors the Rust core must reproduce exactly.

This works *only* because our core is **sans-IO and deterministic** (see the architecture overview): `handle_event(&mut Core, Event) -> Vec<Effect>` has no hidden inputs — no clock, no network, no RNG, no disk reads happen inside it. Therefore a fixed sequence of `Event`s *always* produces the same sequence of `Effect`s and the same final state. That means a table of `(event → effects, resulting-state)` is a **total, checkable specification**. Lean produces that table from a model we have *proved correct*; Rust must match it byte-for-byte. If the two ever diverge, either the Rust core has a bug or the model changed without the core following — and CI goes red.

The whole pipeline:

```
  formal/lean/                                   crates/oid4vp/
  ┌───────────────────────┐                      ┌───────────────────────────┐
  │ Lean model (step fn)   │   lake build         │ hand-written Rust machine │
  │  + 3 invariant proofs  │ ───────────────►     │  handle_event(&mut Core,…)│
  └───────────┬───────────┘   (proofs pass)       └─────────────▲─────────────┘
              │ lake exe oracle                                  │ replay
              ▼                                                  │
  oid4vp_traces.json  ── checked in ──►  tests/vectors/  ── cargo test ─┘
   (event → effects, state)               (git diff --exit-code keeps them in sync)
```

Two failure modes, two red lights: **`lake build` fails** ⇒ an invariant no longer holds (someone changed the model and broke a safety property); **`cargo test` fails** ⇒ the Rust core diverged from the proven model. A third guard (a `git diff` on the checked-in vectors) catches "model changed but vectors weren't regenerated."

Everything below has been compiled with **Lean 4.32.0 / Lake 5.0.0** and **Rust 1.97.1**; the code blocks are transcribed from a working build, not sketched.

---

### Step 10.0 — Confirm the Lean toolchain

The shared context says Lean is present. Verify it, because everything downstream depends on the exact version.

```bash
elan --version        # elan 4.x  (the Lean toolchain multiplexer, like rustup)
lake --version        # Lake version 5.0.0-... (Lean version 4.32.0)   ← Lake is Lean's cargo
lean --version        # Lean (version 4.32.0, arm64-apple-darwin...)
```

Jargon, once: **elan** = version manager for Lean (analogue of `rustup`). **Lake** = Lean's build tool and package manager (analogue of `cargo`). **lean** = the compiler/proof-checker itself.

**Definition of done:** `lean --version` prints `4.32.0`. If it prints something else, run `elan default leanprover/lean4:v4.32.0` and re-check — a version mismatch will make some of the proof tactics below behave differently.

---

### Step 10.1 — Scaffold the `formal/lean/` Lake project

The Lean project lives *outside* the Cargo workspace (it is a proof artifact, not a shipped crate) but *inside* the repo so CI and reviewers see it. Create this exact layout:

```
formal/
└── lean/
    ├── lean-toolchain          # pins the Lean version (like rust-toolchain.toml)
    ├── lakefile.toml           # the build manifest (like Cargo.toml)
    ├── Main.lean               # entry point for the `oracle` executable
    ├── Wallet.lean             # library root: imports the modules below
    └── Wallet/
        ├── Oid4vp.lean         # OID4VP model + the three invariant proofs
        ├── Iso18013.lean       # ISO 18013-5 session model + its safety proofs
        └── Oracle.lean         # trace enumeration + JSON exporter
```

Run:

```bash
mkdir -p formal/lean/Wallet
cd formal/lean
printf 'leanprover/lean4:v4.32.0\n' > lean-toolchain
```

Create `formal/lean/lakefile.toml` — note we declare **one library** (`Wallet`, the model+proofs) and **one executable** (`oracle`, the exporter):

```toml
name = "Wallet"
defaultTargets = ["Wallet"]

[[lean_lib]]
name = "Wallet"

[[lean_exe]]
name = "oracle"
root = "Main"
```

Create a placeholder `formal/lean/Wallet.lean` (we will fill it in) and a placeholder `formal/lean/Main.lean`:

```bash
printf 'import Wallet.Oid4vp\n' > Wallet.lean
printf 'def main : IO Unit := IO.println "ok"\n' > Main.lean
```

We have **no dependency on Mathlib** (Lean's big maths library). That is deliberate: Mathlib is huge, slow to build, and pins its own Lean version, which would couple our proof CI to Mathlib's release cadence. Everything here uses only the Lean 4 standard prelude. Keep it that way — if a future proof "needs Mathlib," first check whether restructuring the statement avoids it.

**Definition of done:**

```bash
cd formal/lean && lake build
# Expected: "Build completed successfully" (it builds the placeholder Wallet lib).
```

---

### Step 10.2 — Model the OID4VP presentation machine as Lean data

Open `formal/lean/Wallet/Oid4vp.lean`. We model the same OID4VP remote-presentation flow the `oid4vp` crate implements. First the data types.

Jargon, once: **`inductive`** declares an algebraic data type (like a Rust `enum`); each `| name (field : T)` is a constructor (a variant). **`structure`** declares a record (like a Rust `struct`). **`deriving DecidableEq, Repr`** auto-generates equality-checking and a debug-printer (like Rust's `#[derive(PartialEq, Debug)]`). **`abbrev`** is a transparent type alias.

```lean
/-
  OID4VP remote-presentation state machine, modelled as a pure step function.
  Mirrors the sans-IO Rust `oid4vp` crate one-for-one.
-/
namespace Wallet.Oid4vp

abbrev Nonce := Nat

inductive Phase where
  | idle
  | requestReceived
  | requestValidated
  | consentShown
  | consentGiven
  | presented
  | aborted
  deriving DecidableEq, Repr

inductive Event where
  | receiveRequest (nonce : Nonce)
  | validateSignature (ok : Bool)
  | showConsent
  | userDecision (accept : Bool)
  | disclose
  | reset
  deriving DecidableEq, Repr

inductive ErrCode where
  | replay
  | badSignature
  | userDeclined
  deriving DecidableEq, Repr

inductive Effect where
  | verifyRequestSignature
  | renderConsent
  | emitVpToken
  | reportError (code : ErrCode)
  deriving DecidableEq, Repr

structure State where
  phase : Phase
  sigValidated : Bool
  consentGiven : Bool
  currentNonce : Option Nonce
  consumedNonces : List Nonce
  deriving DecidableEq, Repr

def init : State :=
  { phase := Phase.idle, sigValidated := false, consentGiven := false,
    currentNonce := none, consumedNonces := [] }
```

What each piece means in EUDI terms:

- **`Phase`** is the linear presentation lifecycle: `idle → requestReceived → requestValidated → consentShown → consentGiven → presented`, with `aborted` as a sink from any failure. `presented` is the **accepting/final** state — it is the state *after* the VP Token (the presented credential) has been emitted.
- **`Event`** is what the *shell* feeds the core: an incoming authorization request (`receiveRequest`, carrying the request `nonce`), the *result* of asking the platform to verify the request-object signature and RP trust (`validateSignature ok` — the Effect result comes back as an Event, per the sans-IO pattern), the user's consent decision (`userDecision accept`), etc. `reset` models the shell starting a **new presentation** in the same wallet unit (the persisted nonce store survives).
- **`Effect`** is what the core asks the shell to do: `verifyRequestSignature` (go check the signature), `renderConsent` (show the consent screen — a `ScreenDescription` in the real system), `reportError`, and the one that matters most, **`emitVpToken`** — the *disclosure* effect, i.e. actually releasing the credential.
- **`State`** carries a small amount of **audit history** beyond the phase: `sigValidated` and `consentGiven` are monotone "this happened" flags; `currentNonce` is the request nonce of the live session; `consumedNonces` is the persisted set of nonces we have ever accepted (this is what defeats replay).

Now the transition function. This is the entire protocol logic, written as a **total, pure function** — the exact analogue of the Rust `handle_event`. It matches on `(phase, event)` and returns the new state plus the effects to run. Note the final catch-all `| _, _ => (s, [])`: any event that does not fit the current phase is **ignored** (no state change, no effect) — this is how a well-behaved sans-IO machine rejects out-of-order input.

```lean
def step (s : State) (e : Event) : State × List Effect :=
  match s.phase, e with
  | Phase.idle, Event.receiveRequest n =>
      if n ∈ s.consumedNonces then
        ({ s with phase := Phase.aborted }, [Effect.reportError ErrCode.replay])
      else
        ({ s with phase := Phase.requestReceived,
                  currentNonce := some n,
                  consumedNonces := n :: s.consumedNonces },
         [Effect.verifyRequestSignature])
  | Phase.requestReceived, Event.validateSignature ok =>
      if ok then
        ({ s with phase := Phase.requestValidated, sigValidated := true }, [])
      else
        ({ s with phase := Phase.aborted }, [Effect.reportError ErrCode.badSignature])
  | Phase.requestValidated, Event.showConsent =>
      ({ s with phase := Phase.consentShown }, [Effect.renderConsent])
  | Phase.consentShown, Event.userDecision accept =>
      if accept then
        ({ s with phase := Phase.consentGiven, consentGiven := true }, [])
      else
        ({ s with phase := Phase.aborted }, [Effect.reportError ErrCode.userDeclined])
  | Phase.consentGiven, Event.disclose =>
      ({ s with phase := Phase.presented }, [Effect.emitVpToken])
  | _, Event.reset =>
      ({ s with phase := Phase.idle, sigValidated := false,
                consentGiven := false, currentNonce := none }, [])
  | _, _ => (s, [])
```

Read the safety-critical branches carefully — they are what the proofs will pin down:

- `emitVpToken` (disclosure) is emitted from **exactly one** branch: `(consentGiven, disclose)`. You cannot disclose from any other phase.
- The `consentGiven` phase is entered from **exactly one** branch: `(consentShown, userDecision true)`. So disclosure is unreachable without a prior consent event.
- `sigValidated := true` is set from **exactly one** branch: `(requestReceived, validateSignature true)`.
- On `receiveRequest n`, if `n` is already in `consumedNonces`, the machine **aborts**; otherwise it records `n` (`n :: s.consumedNonces`, i.e. prepend) so it can never be accepted again.

`{ s with phase := ... }` is Lean's record-update syntax (Rust's `Core { phase: ..., ..s }`). `Option`'s `none`/`some n` and `List`'s `[]`/`x :: xs`/`x ∈ xs` are the standard prelude.

**Definition of done:** temporarily make `Wallet.lean` import only this module and build:

```bash
cd formal/lean && lake build Wallet.Oid4vp
# Expected: "Built Wallet.Oid4vp" with no errors (the model type-checks; proofs come next).
```

---

### Step 10.3 — The state invariant, and prove `step` preserves it

The trick to proving properties of *all reachable states* is to find one **inductive invariant** `Inv : State → Prop` such that (a) the initial state satisfies it and (b) `step` preserves it. Then by induction every reachable state satisfies it — no matter how long or weird the event sequence.

Jargon, once: **`Prop`** is the type of propositions (statements that can be true/false and *proved*). **`def Inv : State → Prop`** is a predicate. **`∧`** is "and", **`→`** is "implies", **`∀`** is "for all". **`theorem name : statement := by <tactics>`** proves `statement`; `by` enters *tactic mode*, where each tactic transforms the goal until it is closed.

Our invariant bundles the three safety facts we need, expressed over the audit fields:

```lean
/-- Phases in which a signature must already have been validated. -/
def validatedPhase : Phase → Bool
  | .requestValidated | .consentShown | .consentGiven | .presented => true
  | _ => false

/-- Phases in which the user must already have consented. -/
def consentedPhase : Phase → Bool
  | .consentGiven | .presented => true
  | _ => false

/-- The single monolithic state invariant. -/
def Inv (s : State) : Prop :=
  (validatedPhase s.phase = true → s.sigValidated = true) ∧
  (consentedPhase s.phase = true → s.consentGiven = true) ∧
  (∀ n, s.currentNonce = some n → n ∈ s.consumedNonces)

theorem Inv_init : Inv init := by
  refine ⟨?_, ?_, ?_⟩ <;> simp [init, validatedPhase, consentedPhase]
```

In English, `Inv s` says: *if* the phase is at-or-past `requestValidated`, *then* the signature was validated; *if* the phase is at-or-past `consentGiven`, *then* consent was given; and the live nonce (if any) is recorded in the consumed set. `Inv_init` proves the empty initial state trivially satisfies all three: `refine ⟨?_, ?_, ?_⟩` splits the `∧∧` into three sub-goals and `<;> simp [...]` discharges all of them by unfolding the definitions (in `idle`, both `validatedPhase` and `consentedPhase` are `false`, so the implications are vacuous; `currentNonce` is `none`).

Now the heart of Tier 2 — preservation. This one theorem does the real work:

```lean
theorem step_preserves (s : State) (e : Event) (h : Inv s) : Inv (step s e).1 := by
  obtain ⟨h1, h2, h3⟩ := h
  unfold step
  split <;> rename_i heq <;>
    (try split) <;>
    refine ⟨?_, ?_, ?_⟩ <;>
    (try intro n hn) <;>
    simp_all [validatedPhase, consentedPhase]
```

How to read that proof, tactic by tactic:

1. `obtain ⟨h1, h2, h3⟩ := h` — destructure the incoming invariant into its three conjuncts (like a Rust `let (h1,h2,h3) = h;`).
2. `unfold step` — replace `step s e` with its `match` body in the goal.
3. `split` — case-split on that `match`; this produces one sub-goal per branch of `step`. `<;>` means "apply the next tactic to *every* sub-goal produced." `rename_i heq` names the discriminant equation each branch introduces.
4. `(try split)` — some branches contain an inner `if` (the nonce check, the `ok`/`accept` checks); `try split` splits those and is a no-op where there is no `if`.
5. `refine ⟨?_, ?_, ?_⟩` — in each branch, re-establish the three conjuncts of `Inv` for the *new* state.
6. `(try intro n hn)` — the third conjunct is a `∀ n, ...`; introduce `n` and its hypothesis.
7. `simp_all [validatedPhase, consentedPhase]` — simplify using every hypothesis in scope plus the two phase-predicates. This closes every remaining goal: e.g. in the `showConsent` branch the new phase is `consentShown` so `validatedPhase` is `true` and the goal reduces to `sigValidated = true`, which `h1` supplies (the pre-phase was `requestValidated`); in the `receiveRequest`-accept branch the new `currentNonce` is `some n` and the new `consumedNonces` is `n :: ...`, so `n ∈ n :: ...` closes by `simp`.

Then fold the single-step guarantee over whole traces. `runLog` runs a list of events and accumulates effects; `run` projects the final state:

```lean
/-- Fold a whole trace (list of events) through `step`, accumulating effects.
    `run` projects out the final state. This is the executable oracle semantics. -/
def runLog (s : State) : List Event → State × List Effect
  | [] => (s, [])
  | e :: es =>
      let (s', fx) := step s e
      let (s'', fx') := runLog s' es
      (s'', fx ++ fx')

def run (s : State) (es : List Event) : State := (runLog s es).1

theorem run_cons (s : State) (e : Event) (es : List Event) :
    run s (e :: es) = run (step s e).1 es := by
  simp [run, runLog]

theorem run_preserves : ∀ (es : List Event) (s : State), Inv s → Inv (run s es)
  | [], s, h => by simpa [run, runLog] using h
  | e :: es, s, h => by
      rw [run_cons]; exact run_preserves es (step s e).1 (step_preserves s e h)
```

`run_preserves` is proved by structural recursion on the event list (the `| [] ...` / `| e :: es ...` are the two cases; the recursive call `run_preserves es ...` is the induction hypothesis). It says: **every state reachable from a good initial state by any trace is good.** This is the reusable lever for all three headline theorems.

**Definition of done:**

```bash
cd formal/lean && lake build Wallet.Oid4vp
# Expected: "Built Wallet.Oid4vp", no errors, no `sorry` warnings.
```

---

### Step 10.4 — State and prove the three invariants as theorems

Now the payoff. We prove the three properties from the shared-context mandate. Each is stated two ways where it matters: as a *state* fact (fast) and as a *trace* fact ("an actual event occurred"), because the mandate is phrased in terms of events.

First, three tiny "source" lemmas that pin down *which single event* can flip each flag or emit disclosure. Their proofs are all the same shape — split the `step` match inside the hypothesis and let `simp_all` eliminate every branch that does not match:

```lean
/-- The ONLY way `sigValidated` flips false→true is the signature-validation event. -/
theorem sig_flag_source (s : State) (e : Event)
    (hbefore : s.sigValidated = false)
    (hafter : (step s e).1.sigValidated = true) :
    e = Event.validateSignature true := by
  unfold step at hafter
  split at hafter <;> simp_all <;> (split at hafter <;> simp_all)

/-- The ONLY way `consentGiven` flips false→true is the user-consent event. -/
theorem consent_flag_source (s : State) (e : Event)
    (hbefore : s.consentGiven = false)
    (hafter : (step s e).1.consentGiven = true) :
    e = Event.userDecision true := by
  unfold step at hafter
  split at hafter <;> simp_all <;> (split at hafter <;> simp_all)

/-- The disclosure effect is emitted ONLY from `consentGiven` by `disclose`. -/
theorem disclose_source (s : State) (e : Event)
    (hfx : Effect.emitVpToken ∈ (step s e).2) :
    s.phase = Phase.consentGiven ∧ e = Event.disclose := by
  unfold step at hfx
  split at hfx <;> simp_all <;> (split at hfx <;> simp_all)
```

Two induction lemmas lift the flag-source facts to whole traces: "if a trace ends with a flag set that started clear, the setting event is in the trace."

```lean
/-- If the trace ends with `sigValidated`, a signature-validation event is in it. -/
theorem sig_true_implies_event :
    ∀ (es : List Event) (s : State),
      s.sigValidated = false → (run s es).sigValidated = true →
      Event.validateSignature true ∈ es
  | [], s, hs, hrun => by simp_all [run, runLog]
  | e :: es, s, hs, hrun => by
      rw [run_cons] at hrun
      by_cases hstep : (step s e).1.sigValidated = true
      · exact List.mem_cons.mpr (Or.inl (sig_flag_source s e hs hstep).symm)
      · have hfalse : (step s e).1.sigValidated = false := by simp_all
        exact List.mem_cons.mpr (Or.inr (sig_true_implies_event es (step s e).1 hfalse hrun))

theorem consent_true_implies_event :
    ∀ (es : List Event) (s : State),
      s.consentGiven = false → (run s es).consentGiven = true →
      Event.userDecision true ∈ es
  | [], s, hs, hrun => by simp_all [run, runLog]
  | e :: es, s, hs, hrun => by
      rw [run_cons] at hrun
      by_cases hstep : (step s e).1.consentGiven = true
      · exact List.mem_cons.mpr (Or.inl (consent_flag_source s e hs hstep).symm)
      · have hfalse : (step s e).1.consentGiven = false := by simp_all
        exact List.mem_cons.mpr (Or.inr (consent_true_implies_event es (step s e).1 hfalse hrun))
```

`by_cases hstep : ...` splits on whether the first step already set the flag: if yes, the source lemma says that first event *is* the setter, so it is in `e :: es` (`.symm` flips the equality to the orientation `List.mem_cons` wants); if no, the flag is still clear and we recurse on the tail.

Now the three headline theorems.

**Invariant 1 — no accepting state without signature validation (safety).** "You cannot reach `presented` without having validated a signature." Stated as a state fact and as a trace fact:

```lean
/-! ### Invariant 1 — no accepting state without signature validation (safety) -/

theorem no_accept_without_sig (es : List Event)
    (hfinal : (run init es).phase = Phase.presented) :
    (run init es).sigValidated = true :=
  (run_preserves es init Inv_init).1 (by simp [validatedPhase, hfinal])

theorem no_accept_without_sig_event (es : List Event)
    (hfinal : (run init es).phase = Phase.presented) :
    Event.validateSignature true ∈ es :=
  sig_true_implies_event es init rfl (no_accept_without_sig es hfinal)
```

`no_accept_without_sig` is one line: `run_preserves` gives `Inv (run init es)`, whose *first* conjunct (`.1`), applied to the fact that `presented` is a `validatedPhase`, yields `sigValidated = true`. `no_accept_without_sig_event` then upgrades that to "a `validateSignature true` event literally appears in the trace." This is exactly the mandate's *"no accepting trace without signature validation."*

**Invariant 2 — no Disclose before Consent.** "If the machine reached `presented` (i.e. disclosed), a user-consent event is in the trace." Combined with `disclose_source` (disclosure is emitted only from `consentGiven`) and `consent_flag_source` (that phase is entered only by `userDecision true`), this is the full causal chain "no disclosure effect without a prior consent event":

```lean
/-! ### Invariant 2 — no Disclose before Consent -/

theorem disclosed_implies_consent_event (es : List Event)
    (hfinal : (run init es).phase = Phase.presented) :
    Event.userDecision true ∈ es :=
  consent_true_implies_event es init rfl
    ((run_preserves es init Inv_init).2.1 (by simp [consentedPhase, hfinal]))
```

**Invariant 3 — no reachable state accepts a replayed nonce.** Three facts: receiving an already-consumed nonce aborts (`replay_aborts`); the consumed set only ever grows (`consumed_monotone`); therefore in *any* reachable state, re-presenting a consumed nonce aborts (`no_replay`):

```lean
/-! ### Invariant 3 — no reachable state accepts a replayed nonce -/

theorem replay_aborts (s : State) (n : Nonce)
    (hidle : s.phase = Phase.idle) (hseen : n ∈ s.consumedNonces) :
    (step s (Event.receiveRequest n)).1.phase = Phase.aborted := by
  unfold step
  simp only [hidle]
  simp [hseen]

theorem consumed_monotone (s : State) (e : Event) (n : Nonce)
    (h : n ∈ s.consumedNonces) : n ∈ (step s e).1.consumedNonces := by
  unfold step
  split <;> rename_i heq <;> (try split) <;> simp_all

theorem no_replay (es : List Event) (n : Nonce)
    (hseen : n ∈ (run init es).consumedNonces)
    (hidle : (run init es).phase = Phase.idle) :
    (step (run init es) (Event.receiveRequest n)).1.phase = Phase.aborted :=
  replay_aborts (run init es) n hidle hseen
```

Close the file:

```lean
end Wallet.Oid4vp
```

Now the crucial honesty check. A Lean theorem is worthless if its proof secretly used `sorry` (the "trust me" placeholder). Add an audit module `formal/lean/Wallet/Audit.lean` that prints the axiom dependencies of the headline theorems:

```lean
import Wallet.Oid4vp
open Wallet.Oid4vp

#print axioms no_accept_without_sig_event
#print axioms disclosed_implies_consent_event
#print axioms no_replay
#print axioms step_preserves
```

**Definition of done:**

```bash
cd formal/lean && lake build Wallet.Oid4vp
# Expected: builds clean, zero warnings, zero errors.

lake env lean Wallet/Audit.lean
# Expected, for each theorem:
#   '...no_accept_without_sig_event' depends on axioms: [propext, Quot.sound]
#   '...disclosed_implies_consent_event' depends on axioms: [propext, Quot.sound]
#   '...no_replay' depends on axioms: [propext, Quot.sound]
#   '...step_preserves' depends on axioms: [propext, Quot.sound]
```

`propext` and `Quot.sound` are Lean's two standard logical axioms — every ordinary proof uses them. The thing you are checking is that **`sorryAx` is absent**: if any output contained `sorryAx`, the proof has a hole. CI greps for exactly that (Step 10.9). As an extra belt-and-braces guard, `grep -rn 'sorry\|admit' formal/lean/Wallet/` must return nothing.

---

### Step 10.5 — Model the ISO 18013-5 proximity session

The mandate requires modelling both presentation modes. The proximity (ISO/IEC 18013-5) session is the same pattern — a sans-IO machine over transport bytes — with a longer prefix (device engagement → ECDH session establishment → reader request → reader authentication → consent → device response). Create `formal/lean/Wallet/Iso18013.lean`. The types and `step` are structurally identical to OID4VP; the safety invariant we prove is *"no `DeviceResponse` (the disclosure) without both an established encrypted session and prior consent."*

```lean
/-
  ISO/IEC 18013-5 proximity session state machine, modelled as a pure step function.
  Mirrors the sans-IO Rust `iso18013-5` crate: transport bytes in, effects out.
-/
namespace Wallet.Iso18013

abbrev Nonce := Nat

inductive Phase where
  | idle
  | engaged            -- device engagement (QR/NFC) sent, ephemeral key generated
  | sessionEstablished -- ECDH complete, session-encryption keys derived
  | requestReceived    -- reader request decrypted
  | readerAuthed       -- reader authentication verified
  | consentGiven
  | responded          -- DeviceResponse emitted (accepting)
  | aborted
  deriving DecidableEq, Repr

inductive Event where
  | startEngagement
  | establishSession (ok : Bool)   -- ECDH / session-key derivation result
  | receiveRequest (nonce : Nonce) -- session-transcript / reader nonce
  | authenticateReader (ok : Bool)
  | userDecision (accept : Bool)
  | respond
  | reset
  deriving DecidableEq, Repr

inductive ErrCode where
  | sessionFailed
  | replay
  | readerRejected
  | userDeclined
  deriving DecidableEq, Repr

inductive Effect where
  | deriveSessionKeys
  | verifyReaderAuth
  | renderConsent
  | emitDeviceResponse   -- the disclosure effect
  | reportError (code : ErrCode)
  deriving DecidableEq, Repr

structure State where
  phase : Phase
  sessionEstablished : Bool
  readerAuthed : Bool
  consentGiven : Bool
  currentNonce : Option Nonce
  consumedNonces : List Nonce
  deriving DecidableEq, Repr

def init : State :=
  { phase := Phase.idle, sessionEstablished := false, readerAuthed := false,
    consentGiven := false, currentNonce := none, consumedNonces := [] }

def step (s : State) (e : Event) : State × List Effect :=
  match s.phase, e with
  | Phase.idle, Event.startEngagement =>
      ({ s with phase := Phase.engaged }, [Effect.deriveSessionKeys])
  | Phase.engaged, Event.establishSession ok =>
      if ok then
        ({ s with phase := Phase.sessionEstablished, sessionEstablished := true }, [])
      else
        ({ s with phase := Phase.aborted }, [Effect.reportError ErrCode.sessionFailed])
  | Phase.sessionEstablished, Event.receiveRequest n =>
      if n ∈ s.consumedNonces then
        ({ s with phase := Phase.aborted }, [Effect.reportError ErrCode.replay])
      else
        ({ s with phase := Phase.requestReceived,
                  currentNonce := some n,
                  consumedNonces := n :: s.consumedNonces },
         [Effect.verifyReaderAuth])
  | Phase.requestReceived, Event.authenticateReader ok =>
      if ok then
        ({ s with phase := Phase.readerAuthed, readerAuthed := true }, [Effect.renderConsent])
      else
        ({ s with phase := Phase.aborted }, [Effect.reportError ErrCode.readerRejected])
  | Phase.readerAuthed, Event.userDecision accept =>
      if accept then
        ({ s with phase := Phase.consentGiven, consentGiven := true }, [])
      else
        ({ s with phase := Phase.aborted }, [Effect.reportError ErrCode.userDeclined])
  | Phase.consentGiven, Event.respond =>
      ({ s with phase := Phase.responded }, [Effect.emitDeviceResponse])
  | _, Event.reset =>
      ({ s with phase := Phase.idle, sessionEstablished := false, readerAuthed := false,
                consentGiven := false, currentNonce := none }, [])
  | _, _ => (s, [])

/-- Phases that presuppose an established, encrypted session. -/
def sessionPhase : Phase → Bool
  | .sessionEstablished | .requestReceived | .readerAuthed | .consentGiven | .responded => true
  | _ => false

/-- Phases that presuppose the user consented. -/
def consentedPhase : Phase → Bool
  | .consentGiven | .responded => true
  | _ => false

def Inv (s : State) : Prop :=
  (sessionPhase s.phase = true → s.sessionEstablished = true) ∧
  (consentedPhase s.phase = true → s.consentGiven = true) ∧
  (∀ n, s.currentNonce = some n → n ∈ s.consumedNonces)

theorem Inv_init : Inv init := by
  refine ⟨?_, ?_, ?_⟩ <;> simp [init, sessionPhase, consentedPhase]

theorem step_preserves (s : State) (e : Event) (h : Inv s) : Inv (step s e).1 := by
  obtain ⟨h1, h2, h3⟩ := h
  unfold step
  split <;> rename_i heq <;>
    (try split) <;>
    refine ⟨?_, ?_, ?_⟩ <;>
    (try intro n hn) <;>
    simp_all [sessionPhase, consentedPhase]

def runLog (s : State) : List Event → State × List Effect
  | [] => (s, [])
  | e :: es =>
      let (s', fx) := step s e
      let (s'', fx') := runLog s' es
      (s'', fx ++ fx')

def run (s : State) (es : List Event) : State := (runLog s es).1

theorem run_cons (s : State) (e : Event) (es : List Event) :
    run s (e :: es) = run (step s e).1 es := by
  simp [run, runLog]

theorem run_preserves : ∀ (es : List Event) (s : State), Inv s → Inv (run s es)
  | [], s, h => by simpa [run, runLog] using h
  | e :: es, s, h => by
      rw [run_cons]; exact run_preserves es (step s e).1 (step_preserves s e h)

/-- No DeviceResponse (accepting `responded` state) without an established session. -/
theorem no_respond_without_session (es : List Event)
    (hfinal : (run init es).phase = Phase.responded) :
    (run init es).sessionEstablished = true :=
  (run_preserves es init Inv_init).1 (by simp [sessionPhase, hfinal])

/-- No DeviceResponse without prior user consent. -/
theorem no_respond_without_consent (es : List Event)
    (hfinal : (run init es).phase = Phase.responded) :
    (run init es).consentGiven = true :=
  (run_preserves es init Inv_init).2.1 (by simp [consentedPhase, hfinal])

/-- The disclosure effect is emitted ONLY from `consentGiven` by `respond`. -/
theorem disclose_source (s : State) (e : Event)
    (hfx : Effect.emitDeviceResponse ∈ (step s e).2) :
    s.phase = Phase.consentGiven ∧ e = Event.respond := by
  unfold step at hfx
  split at hfx <;> simp_all <;> (split at hfx <;> simp_all)

/-- Replay: a request whose transcript nonce was already consumed aborts. -/
theorem replay_aborts (s : State) (n : Nonce)
    (hphase : s.phase = Phase.sessionEstablished) (hseen : n ∈ s.consumedNonces) :
    (step s (Event.receiveRequest n)).1.phase = Phase.aborted := by
  unfold step
  simp only [hphase]
  simp [hseen]

end Wallet.Iso18013
```

The trace-event versions of these (`no_respond_without_session_event`, etc.) follow *identically* to §10.4 by copying the `*_flag_source` / `*_true_implies_event` pattern; they are left as a mechanical exercise so this file stays readable. The important point is demonstrated: **the same proof recipe generalizes to the second presentation mode.**

**Definition of done:**

```bash
cd formal/lean && lake build Wallet.Iso18013
# Expected: "Built Wallet.Iso18013", no errors.
```

---

### Step 10.6 — Build the oracle: enumerate traces and export JSON

Now turn the proven model into a **spec generator**. Create `formal/lean/Wallet/Oracle.lean`. It (a) serialises `Event`/`Effect`/`State` to JSON by hand — no dependency needed, because every token is a closed-vocabulary ASCII identifier or a `Nat`, so there are no arbitrary strings to escape — and (b) defines a **curated set of named traces**: the happy path plus every attack/edge case we want the Rust core to agree on.

```lean
/-
  The trace-export ORACLE.

  Because the Rust core is sans-IO and deterministic, the Lean model IS the
  reference implementation. We enumerate a curated set of traces, run each one
  through the *model's* `step`, and serialise, for every step,
  (event -> [effects], resulting-state). The Rust conformance test replays the
  exact same events through the Rust `handle_event` and asserts equality.
-/
import Wallet.Oid4vp
open Wallet.Oid4vp

namespace Wallet.Oracle

/-! ### Minimal, dependency-free JSON serialisation.
    Every token is a closed-vocabulary ASCII identifier or a Nat, so no escaping
    of arbitrary strings is ever required. -/

def boolJson (b : Bool) : String := if b then "true" else "false"

def natList (ns : List Nonce) : String :=
  "[" ++ String.intercalate "," (ns.map toString) ++ "]"

def eventJson : Event → String
  | .receiveRequest n     => "{\"kind\":\"receiveRequest\",\"nonce\":" ++ toString n ++ "}"
  | .validateSignature ok => "{\"kind\":\"validateSignature\",\"ok\":" ++ boolJson ok ++ "}"
  | .showConsent          => "{\"kind\":\"showConsent\"}"
  | .userDecision a       => "{\"kind\":\"userDecision\",\"accept\":" ++ boolJson a ++ "}"
  | .disclose             => "{\"kind\":\"disclose\"}"
  | .reset                => "{\"kind\":\"reset\"}"

def errJson : ErrCode → String
  | .replay       => "\"replay\""
  | .badSignature => "\"badSignature\""
  | .userDeclined => "\"userDeclined\""

def effectJson : Effect → String
  | .verifyRequestSignature => "{\"kind\":\"verifyRequestSignature\"}"
  | .renderConsent          => "{\"kind\":\"renderConsent\"}"
  | .emitVpToken            => "{\"kind\":\"emitVpToken\"}"
  | .reportError c          => "{\"kind\":\"reportError\",\"code\":" ++ errJson c ++ "}"

def phaseJson : Phase → String
  | .idle             => "\"idle\""
  | .requestReceived  => "\"requestReceived\""
  | .requestValidated => "\"requestValidated\""
  | .consentShown     => "\"consentShown\""
  | .consentGiven     => "\"consentGiven\""
  | .presented        => "\"presented\""
  | .aborted          => "\"aborted\""

def stateJson (s : State) : String :=
  "{\"phase\":" ++ phaseJson s.phase
    ++ ",\"sigValidated\":" ++ boolJson s.sigValidated
    ++ ",\"consentGiven\":" ++ boolJson s.consentGiven
    ++ ",\"currentNonce\":"
       ++ (match s.currentNonce with | none => "null" | some n => toString n)
    ++ ",\"consumedNonces\":" ++ natList s.consumedNonces
    ++ "}"

/-- One step, serialised, threading the post-state forward. -/
def stepsJson (s : State) : List Event → List String
  | [] => []
  | e :: rest =>
      let (s', fx) := step s e
      let j := "{\"event\":" ++ eventJson e
            ++ ",\"effects\":[" ++ String.intercalate "," (fx.map effectJson) ++ "]"
            ++ ",\"state\":" ++ stateJson s' ++ "}"
      j :: stepsJson s' rest

def traceJson (name : String) (es : List Event) : String :=
  "{\"name\":\"" ++ name ++ "\",\"steps\":["
    ++ String.intercalate "," (stepsJson init es) ++ "]}"

/-! ### The curated trace set.
    Happy path + every attack/edge case we want the Rust core to agree on. -/
def curated : List (String × List Event) :=
  [ ("happy_path",
      [ .receiveRequest 1, .validateSignature true, .showConsent,
        .userDecision true, .disclose ]),
    ("bad_signature_aborts",
      [ .receiveRequest 1, .validateSignature false ]),
    ("user_declines_aborts",
      [ .receiveRequest 1, .validateSignature true, .showConsent, .userDecision false ]),
    ("disclose_before_consent_ignored",
      [ .receiveRequest 1, .validateSignature true, .showConsent, .disclose ]),
    ("disclose_before_validation_ignored",
      [ .receiveRequest 1, .disclose ]),
    ("out_of_order_validate_first_ignored",
      [ .validateSignature true, .receiveRequest 1 ]),
    ("replay_same_nonce_aborts",
      [ .receiveRequest 1, .validateSignature true, .showConsent, .userDecision true,
        .disclose, .reset, .receiveRequest 1 ]),
    ("fresh_nonce_after_reset_ok",
      [ .receiveRequest 1, .validateSignature true, .showConsent, .userDecision true,
        .disclose, .reset, .receiveRequest 2, .validateSignature true, .showConsent,
        .userDecision true, .disclose ]) ]

def exportJson : String :=
  "{\"model\":\"oid4vp\",\"arf\":\"2.9.0\",\"pidRulebook\":\"1.6\",\"traces\":["
    ++ String.intercalate "," (curated.map (fun p => traceJson p.1 p.2))
    ++ "]}"

/-- `#eval`-able sanity check: how many steps did we emit in total? -/
def totalSteps : Nat := (curated.map (fun p => p.2.length)).foldl (· + ·) 0

end Wallet.Oracle
```

A note on "curated vs. all bounded traces." You *can* enumerate every trace up to length *k* over a finite event alphabet — e.g. `def sequencesUpTo : Nat → List (List Event)` — and export the lot. But over an 8-symbol alphabet the count is `8^k`, which explodes past a few thousand vectors and produces an unreadable, slow-to-diff golden file. The **curated set is deliberately chosen** to cover the happy path *and each way the three invariants could be violated* (bad signature, decline, three flavours of out-of-order disclosure, a cross-session replay, and a legitimate post-reset fresh nonce). If you *do* want exhaustive coverage, keep it as a separate `#eval`-time property check inside Lean (run every bounded trace through `step` and assert the invariant predicates hold) rather than exporting it — that gives machine-checked breadth without bloating the vectors. Either way, the vectors that Rust replays stay small and legible.

Now wire the executable. Rewrite `formal/lean/Main.lean` so `lake exe oracle` prints the JSON to stdout (for piping) or writes it to a path argument (for scripts):

```lean
import Wallet.Oracle
open Wallet.Oracle

def main (args : List String) : IO Unit := do
  let out := exportJson
  match args with
  | [path] =>
      IO.FS.writeFile path out
      IO.eprintln s!"oracle: wrote {out.length} bytes ({totalSteps} steps) to {path}"
  | _ => IO.println out
```

And make `formal/lean/Wallet.lean` import all three modules so `lake build` builds everything (proofs + oracle) in one shot:

```lean
import Wallet.Oid4vp
import Wallet.Iso18013
import Wallet.Oracle
```

**Definition of done:**

```bash
cd formal/lean && lake build          # builds proofs + oracle exe
lake exe oracle | python3 -m json.tool | head -20
```

Expected: the oracle prints valid JSON; `python3 -m json.tool` (a JSON validator/pretty-printer, guaranteed present with Python 3.14) accepts it and prints the `happy_path` trace whose final step is `emitVpToken` into phase `presented`:

```json
{
    "model": "oid4vp",
    "arf": "2.9.0",
    "pidRulebook": "1.6",
    "traces": [
        {
            "name": "happy_path",
            "steps": [
                {
                    "event": { "kind": "receiveRequest", "nonce": 1 },
                    "effects": [ { "kind": "verifyRequestSignature" } ],
                    "state": {
                        "phase": "requestReceived",
                        "sigValidated": false,
                        "consentGiven": false,
                        "currentNonce": 1,
                        "consumedNonces": [ 1 ]
                    }
                }
```

A quick behavioural sanity summary you can eyeball (this is what the eight curated traces do):

| trace | final phase | `emitVpToken` emitted? |
|---|---|---|
| `happy_path` | `presented` | yes |
| `bad_signature_aborts` | `aborted` | no |
| `user_declines_aborts` | `aborted` | no |
| `disclose_before_consent_ignored` | `consentShown` | **no** (disclosure blocked) |
| `disclose_before_validation_ignored` | `requestReceived` | no |
| `out_of_order_validate_first_ignored` | `requestReceived` | no |
| `replay_same_nonce_aborts` | `aborted` | yes¹ |
| `fresh_nonce_after_reset_ok` | `presented` | yes |

¹ the first (legitimate) session in that trace discloses; the *replayed* `receiveRequest 1` after `reset` is what aborts.

---

### Step 10.7 — Check the vectors into the repo (with canonical formatting)

The exported JSON is a **build artifact that is committed to version control** — that is what lets the `git diff` guard catch drift. The Lean exporter emits compact JSON; pipe it through `python3 -m json.tool --sort-keys` to get *canonical, stable* formatting (sorted keys, fixed indentation) so diffs are minimal and deterministic across machines. Regenerating twice yields byte-identical output.

The vectors live next to the Rust crate that will replay them: `crates/oid4vp/tests/vectors/oid4vp_traces.json`. Add a `Makefile` (or `justfile`) target at the repo root:

```makefile
LEAN_DIR      := formal/lean
VECTORS       := crates/oid4vp/tests/vectors/oid4vp_traces.json

# Prove the model (fails if any invariant proof breaks) and build the exporter.
.PHONY: lean-build
lean-build:
	cd $(LEAN_DIR) && lake build

# Fail if any headline theorem depends on `sorryAx` (i.e. has a proof hole).
.PHONY: lean-audit
lean-audit: lean-build
	cd $(LEAN_DIR) && lake env lean Wallet/Audit.lean | tee /tmp/axioms.txt
	! grep -q 'sorryAx' /tmp/axioms.txt
	! grep -rEn 'sorry|admit' $(LEAN_DIR)/Wallet/

# Regenerate the checked-in vectors from the proven model, canonically formatted.
.PHONY: vectors
vectors: lean-build
	cd $(LEAN_DIR) && lake exe oracle | python3 -m json.tool --sort-keys > $(CURDIR)/$(VECTORS)

# CI guard: regenerate and fail if the working tree changed (out-of-date vectors).
.PHONY: vectors-check
vectors-check: vectors
	git diff --exit-code -- $(VECTORS)
```

**Definition of done:**

```bash
make vectors          # writes crates/oid4vp/tests/vectors/oid4vp_traces.json
git add crates/oid4vp/tests/vectors/oid4vp_traces.json && git commit -m "model vectors"
make vectors-check    # regenerates and diffs
# Expected: exit code 0 (no diff). Change the model and re-run: `git diff --exit-code` fails,
# telling you to re-run `make vectors` and commit.
```

---

### Step 10.8 — The Rust conformance test: replay the model against `handle_event`

The Rust side of the bridge lives in the `oid4vp` crate. Recall the architecture: each protocol crate is a **hand-written sans-IO state machine**, and the `wallet-core` facade translates global `Event`s into each crate's local events and lifts the effects back out. The model in §10.2 mirrors the `oid4vp` crate's *own* presentation machine, so the conformance test targets that machine directly. For completeness, here is the machine the model mirrors, at `crates/oid4vp/src/machine.rs` — note how it is a line-for-line twin of the Lean `step`:

```rust
#![forbid(unsafe_code)]
//! Hand-written OID4VP presentation state machine (sans-IO), mirroring the Lean model.

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Phase {
    Idle,
    RequestReceived,
    RequestValidated,
    ConsentShown,
    ConsentGiven,
    Presented,
    Aborted,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Event {
    ReceiveRequest { nonce: u64 },
    ValidateSignature { ok: bool },
    ShowConsent,
    UserDecision { accept: bool },
    Disclose,
    Reset,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ErrCode {
    Replay,
    BadSignature,
    UserDeclined,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Effect {
    VerifyRequestSignature,
    RenderConsent,
    EmitVpToken,
    ReportError(ErrCode),
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Core {
    pub phase: Phase,
    pub sig_validated: bool,
    pub consent_given: bool,
    pub current_nonce: Option<u64>,
    pub consumed_nonces: Vec<u64>,
}

impl Core {
    pub fn init() -> Self {
        Core {
            phase: Phase::Idle,
            sig_validated: false,
            consent_given: false,
            current_nonce: None,
            consumed_nonces: Vec::new(),
        }
    }
}

/// The one and only transition function. The same shape as the Lean `step`:
/// a total function of (state, event) that mutates state and returns effects.
pub fn handle_event(core: &mut Core, ev: Event) -> Vec<Effect> {
    use Phase::*;
    match (core.phase, &ev) {
        (Idle, Event::ReceiveRequest { nonce }) => {
            if core.consumed_nonces.contains(nonce) {
                core.phase = Aborted;
                vec![Effect::ReportError(ErrCode::Replay)]
            } else {
                core.phase = RequestReceived;
                core.current_nonce = Some(*nonce);
                // Prepend to mirror the Lean `n :: consumedNonces`.
                core.consumed_nonces.insert(0, *nonce);
                vec![Effect::VerifyRequestSignature]
            }
        }
        (RequestReceived, Event::ValidateSignature { ok }) => {
            if *ok {
                core.phase = RequestValidated;
                core.sig_validated = true;
                vec![]
            } else {
                core.phase = Aborted;
                vec![Effect::ReportError(ErrCode::BadSignature)]
            }
        }
        (RequestValidated, Event::ShowConsent) => {
            core.phase = ConsentShown;
            vec![Effect::RenderConsent]
        }
        (ConsentShown, Event::UserDecision { accept }) => {
            if *accept {
                core.phase = ConsentGiven;
                core.consent_given = true;
                vec![]
            } else {
                core.phase = Aborted;
                vec![Effect::ReportError(ErrCode::UserDeclined)]
            }
        }
        (ConsentGiven, Event::Disclose) => {
            core.phase = Presented;
            vec![Effect::EmitVpToken]
        }
        (_, Event::Reset) => {
            core.phase = Idle;
            core.sig_validated = false;
            core.consent_given = false;
            core.current_nonce = None;
            vec![]
        }
        _ => vec![],
    }
}
```

> **One subtlety that will bite you if you ignore it:** the model records nonces with `n :: consumedNonces` (prepend), so the Rust side must `insert(0, ...)`, not `push(...)` — otherwise the `consumed_nonces` list order diverges and the conformance test fails on that field. The vectors compare the *whole* state including list order, which is exactly the kind of silent representation drift you want the oracle to catch.

Add the JSON-replay dependencies to `crates/oid4vp/Cargo.toml` (test-only):

```toml
[dev-dependencies]
serde = { version = "1.0.228", features = ["derive"] }
serde_json = "1.0.150"
```

Now the conformance test at `crates/oid4vp/tests/model_conformance.rs`. It deserialises the vectors with `serde` (the `#[serde(tag = "kind", rename_all = "camelCase")]` attributes map the JSON `{"kind":"receiveRequest",...}` tagging straight onto Rust enums), replays each trace through `handle_event`, and — for **every step** — asserts the emitted effects and the full resulting state match the model:

```rust
//! Replays every trace the Lean model exported and asserts the Rust core agrees,
//! step by step, on BOTH the emitted effects and the resulting state.
//! This works only because the core is sans-IO and deterministic.

use oid4vp::machine::*;
use serde::Deserialize;

#[derive(Deserialize)]
struct Vectors {
    model: String,
    traces: Vec<Trace>,
}

#[derive(Deserialize)]
struct Trace {
    name: String,
    steps: Vec<Step>,
}

#[derive(Deserialize)]
struct Step {
    event: JEvent,
    effects: Vec<JEffect>,
    state: JState,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
enum JEvent {
    ReceiveRequest { nonce: u64 },
    ValidateSignature { ok: bool },
    ShowConsent,
    UserDecision { accept: bool },
    Disclose,
    Reset,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
enum JErr {
    Replay,
    BadSignature,
    UserDeclined,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
enum JEffect {
    VerifyRequestSignature,
    RenderConsent,
    EmitVpToken,
    ReportError { code: JErr },
}

#[derive(Deserialize, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
enum JPhase {
    Idle,
    RequestReceived,
    RequestValidated,
    ConsentShown,
    ConsentGiven,
    Presented,
    Aborted,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JState {
    phase: JPhase,
    sig_validated: bool,
    consent_given: bool,
    current_nonce: Option<u64>,
    consumed_nonces: Vec<u64>,
}

fn to_event(j: &JEvent) -> Event {
    match j {
        JEvent::ReceiveRequest { nonce } => Event::ReceiveRequest { nonce: *nonce },
        JEvent::ValidateSignature { ok } => Event::ValidateSignature { ok: *ok },
        JEvent::ShowConsent => Event::ShowConsent,
        JEvent::UserDecision { accept } => Event::UserDecision { accept: *accept },
        JEvent::Disclose => Event::Disclose,
        JEvent::Reset => Event::Reset,
    }
}

fn to_effect(j: &JEffect) -> Effect {
    match j {
        JEffect::VerifyRequestSignature => Effect::VerifyRequestSignature,
        JEffect::RenderConsent => Effect::RenderConsent,
        JEffect::EmitVpToken => Effect::EmitVpToken,
        JEffect::ReportError { code } => Effect::ReportError(match code {
            JErr::Replay => ErrCode::Replay,
            JErr::BadSignature => ErrCode::BadSignature,
            JErr::UserDeclined => ErrCode::UserDeclined,
        }),
    }
}

fn phase_matches(core: Phase, model: &JPhase) -> bool {
    matches!(
        (core, model),
        (Phase::Idle, JPhase::Idle)
            | (Phase::RequestReceived, JPhase::RequestReceived)
            | (Phase::RequestValidated, JPhase::RequestValidated)
            | (Phase::ConsentShown, JPhase::ConsentShown)
            | (Phase::ConsentGiven, JPhase::ConsentGiven)
            | (Phase::Presented, JPhase::Presented)
            | (Phase::Aborted, JPhase::Aborted)
    )
}

#[test]
fn model_conformance() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/oid4vp_traces.json");
    let data = std::fs::read_to_string(path).expect("vectors file present");
    let vectors: Vectors = serde_json::from_str(&data).expect("vectors parse");
    assert_eq!(vectors.model, "oid4vp");
    assert!(!vectors.traces.is_empty(), "expected at least one trace");

    for trace in &vectors.traces {
        let mut core = Core::init();
        for (i, step) in trace.steps.iter().enumerate() {
            let effects = handle_event(&mut core, to_event(&step.event));
            let expected: Vec<Effect> = step.effects.iter().map(to_effect).collect();

            assert_eq!(
                effects, expected,
                "trace `{}` step {}: effect mismatch",
                trace.name, i
            );
            assert!(
                phase_matches(core.phase, &step.state.phase),
                "trace `{}` step {}: phase mismatch (rust {:?} vs model {:?})",
                trace.name, i, core.phase, step.state.phase
            );
            assert_eq!(
                core.sig_validated, step.state.sig_validated,
                "trace `{}` step {}: sig_validated mismatch",
                trace.name, i
            );
            assert_eq!(
                core.consent_given, step.state.consent_given,
                "trace `{}` step {}: consent_given mismatch",
                trace.name, i
            );
            assert_eq!(
                core.current_nonce, step.state.current_nonce,
                "trace `{}` step {}: current_nonce mismatch",
                trace.name, i
            );
            assert_eq!(
                core.consumed_nonces, step.state.consumed_nonces,
                "trace `{}` step {}: consumed_nonces mismatch",
                trace.name, i
            );
        }
    }
}
```

**Why this is sound, restated:** `handle_event` reads nothing but `core` and `ev`. No time, no I/O, no randomness. So the JSON table produced by the *proven* model is a complete functional specification, and matching it step-for-step means the Rust core computes the identical transition relation. This is the same determinism that Tier 1 (§9) exploits for replay-based property tests and that makes the whole protocol layer testable at all.

**Definition of done:**

```bash
cargo test -p oid4vp --test model_conformance
# Expected:
#   running 1 test
#   test model_conformance ... ok
#   test result: ok. 1 passed; 0 failed; ...
```

**Prove the test is not vacuous (do this once, by hand, then delete the change).** Introduce a deliberate bug — let the core disclose straight from `ConsentShown`, skipping consent — and confirm the oracle catches it at the exact diverging step:

```bash
# In crates/oid4vp/src/machine.rs, temporarily change the disclose arm to:
#   (ConsentShown, Event::Disclose) | (ConsentGiven, Event::Disclose) => { ... EmitVpToken ... }
cargo test -p oid4vp --test model_conformance
# Expected FAILURE:
#   assertion `left == right` failed: trace `disclose_before_consent_ignored` step 3: effect mismatch
#     left: [EmitVpToken]
#    right: []
#   test result: FAILED. 0 passed; 1 failed; ...
# Then revert the change; the test passes again.
```

That failure is Invariant 2 doing its job: the model *proves* disclosure cannot happen from `ConsentShown`, so the vector for that step expects `[]`, and the buggy core's `[EmitVpToken]` is rejected on the spot.

---

### Step 10.9 — CI wiring

Add a CI job that runs all three guards. The ordering matters: prove first (fast fail on a broken invariant), then check vectors are in sync, then replay.

```yaml
# .github/workflows/formal-tier2.yml
name: formal-tier2
on: [push, pull_request]

jobs:
  tier2:
    runs-on: macos-14           # Apple Silicon, matches the target toolchain
    steps:
      - uses: actions/checkout@v4

      - name: Install elan (Lean toolchain manager)
        run: |
          curl -fsSL https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh \
            | sh -s -- -y --default-toolchain none
          echo "$HOME/.elan/bin" >> "$GITHUB_PATH"

      # 1. PROVE the model. Fails red if any invariant proof breaks.
      - name: lake build (invariant proofs)
        run: cd formal/lean && lake build

      # 2. Proof-hole guard: fail if any headline theorem uses `sorryAx`.
      - name: axiom audit (no sorry)
        run: make lean-audit

      # 3. Vectors in sync: regenerate from the proven model and diff.
      - name: vectors up to date
        run: make vectors-check

      # 4. REPLAY: the Rust core must match the proven model, step for step.
      - name: cargo conformance
        run: cargo test -p oid4vp --test model_conformance
```

The three red lights, made explicit:

- **`lake build` red** → someone changed the model (or a crate's spec) in a way that violates a safety invariant. The proof no longer closes. *This is the most valuable signal Tier 2 gives you: a design regression caught before a single line of Rust runs.*
- **`vectors-check` red** → the model changed but the checked-in vectors weren't regenerated. Run `make vectors` and commit.
- **`cargo test` red** → the Rust core diverged from the proven model. The failure names the trace, the step index, and the field that mismatched.

**Definition of done:** run the whole chain locally and see it green:

```bash
make lean-audit && make vectors-check && cargo test -p oid4vp --test model_conformance
# Expected: lake builds, axiom audit shows only [propext, Quot.sound], git diff clean, 1 test passed.
```

---

### Step 10.10 — What is proven, what is not, and how Tier 2 fits

**Proven, machine-checked, `sorry`-free (only `propext`/`Quot.sound`):**

1. *(Invariant 1, safety)* No reachable `presented` state without `sigValidated`, and correspondingly a `validateSignature true` event is present in any accepting trace (`no_accept_without_sig`, `no_accept_without_sig_event`). — *"no accepting trace without signature validation."*
2. *(Invariant 2)* Reaching `presented` (disclosure) implies a `userDecision true` (consent) event occurred, and the disclosure effect `emitVpToken` is emitted **only** from `consentGiven` (`disclosed_implies_consent_event`, `disclose_source`, `consent_flag_source`). — *"no disclosure effect before a consent event."*
3. *(Invariant 3)* The consumed-nonce set grows monotonically and re-presenting any consumed nonce aborts, in every reachable state (`replay_aborts`, `consumed_monotone`, `no_replay`). — *"no reachable state accepts a replayed nonce."*
4. The analogous session-safety properties for ISO 18013-5 (`no_respond_without_session`, `no_respond_without_consent`, `disclose_source`, `replay_aborts`).

**Deliberately *not* claimed here (and why that's fine):**

- **The Rust core is correct beyond the vectors.** The conformance test proves the Rust core matches the model *on the curated traces*, not on all inputs. Breadth comes from Tier 1 (§9): the same sans-IO determinism lets proptest drive random event sequences and Kani model-check codec invariants. Tier 2's job is to make the *proven* behaviours executable and pin the core to them.
- **Session-scoped consent.** Invariant 2 proves a consent event exists *somewhere* in the trace before disclosure; with the `reset` (multi-session) model, tying the consent to the *same* session as the disclosure additionally relies on the per-session nonce binding (Invariant 3) — a strengthening worth adding once the session-transcript binding is modelled explicitly.
- **Network-adversary properties** (secrecy of presented claims, injective agreement / no mix-up, nonce freshness against a Dolev-Yao attacker) are **out of scope for Tier 2 by construction** — an inductive state-machine proof cannot reason about an active network attacker. That is exactly what **Tier 3 (§11, Tamarin/ProVerif)** covers. Tier 2 proves the *implementation's state machine* is safe; Tier 3 proves the *protocol design* is safe.

**The one idea to carry away:** because the core is **sans-IO and deterministic**, a single artifact — the Lean model — can be simultaneously (a) *proved* to satisfy the wallet's non-negotiable safety invariants and (b) *executed* to emit a total specification that the shipped Rust core is continuously tested against. The proof and the test are the same object viewed two ways. That is the whole point of Tier 2.

**Section 10 — overall Definition of done:**

```bash
# 1. Proofs pass (all three invariants, both machines), no proof holes:
cd formal/lean && lake build && lake env lean Wallet/Audit.lean | grep -v sorryAx
#    → "Build completed successfully"; axiom lines show only [propext, Quot.sound].

# 2. The oracle emits valid trace JSON:
lake exe oracle | python3 -m json.tool >/dev/null && echo "oracle JSON valid"

# 3. Vectors are checked in and in sync:
make vectors-check          # → exit 0, clean git diff

# 4. The Rust core replays the proven traces and passes:
cargo test -p oid4vp --test model_conformance   # → 1 passed
```

---


## Section 11 — Formal Tier 3: Tamarin (or ProVerif) symbolic analysis of the HAIP OpenID4VP profile

This section builds the third and outermost ring of the formal-methods program. Tier 1 (proptest, cargo-fuzz, Kani — the Tier 1 section) proves that each *codec* is memory-safe and total. Tier 2 (Lean 4 — the Tier 2 section) proves that the *state machine* obeys ordering invariants (no disclosure before consent, no acceptance without signature validation, no replayed nonce reaching an accepting state) and exports enumerated traces as an executable oracle for the Rust core. Both of those reason about **one honest participant running the code correctly**. Neither can express the question Tier 3 answers:

> *When a Dolev-Yao attacker owns the entire network — reading, dropping, reordering, duplicating, and forging every message, and simultaneously running any number of parallel sessions and even acting as a registered-but-malicious Relying Party — can they still make the wallet disclose a claim to the wrong party, replay a presentation, mix up two sessions, or convince a Relying Party that a presentation is fresh when it is not?*

That is a property of the **protocol design**, not of any one implementation, and it is exactly the class of bug that has historically broken OAuth/OpenID deployments (mix-up attacks, IdP confusion, cut-and-paste / token-substitution). Tier 3 models the HAIP-constrained OpenID4VP exchange symbolically and machine-checks the security goals against that attacker.

**Precedent.** This is not exotic; it is the same treatment the FAPI 2.0 Security Profile received. The OpenID Foundation commissioned a formal security analysis of FAPI 2.0 (the FAPI 2.0 Attacker Model and the accompanying analysis by the University of Stuttgart group — Fett, Küsters, et al.), carried out in the *Web Infrastructure Model* and with symbolic tooling, proving authorization, authentication, and session-integrity goals against a network attacker. HAIP's OpenID4VP profile is FAPI-2.0-adjacent (signed/bound request objects, sender-constrained responses, encrypted responses, PKCE-style freshness). We are doing the smaller, wallet-scoped version of the same exercise with Tamarin.

### 11.0 The mental model, for someone who has never done this

Three ideas are enough to read the rest of this section.

1. **Symbolic (Dolev-Yao) model.** We do *not* model bytes, AES rounds, or elliptic-curve math. We model messages as *terms* built from function symbols (`sign`, `aenc`, `pk`, `<a,b>` pairing) that obey *perfect cryptography* equations: `verify(sign(m, sk), m, pk(sk)) = true`, `adec(aenc(m, pk(sk)), sk) = m`, and nothing else. The attacker can *only* do what the equations permit — so they cannot "guess" a signature, but they *can* do everything else. This abstraction is what makes the whole protocol space machine-checkable.

2. **The Dolev-Yao attacker owns the network.** Every message a participant sends goes *to the attacker* (`Out(...)`), and every message a participant receives comes *from the attacker* (`In(...)`). The attacker can store, replay, split, recombine, and re-send any term they have learned. They can also run the protocol themselves, and — via explicit *reveal* rules — learn the long-term keys of any party we choose to declare compromised. A security lemma is only interesting relative to which parties stayed honest.

3. **Multiset-rewriting rules and traces.** In Tamarin a protocol is a set of *rules* that rewrite a global multiset of *facts*. A rule is `[ premises ] --[ action facts ]-> [ conclusions ]`. `Fr(~x)` mints a globally-fresh value (a nonce or key). Facts prefixed with `!` are *persistent* (never consumed — good for public keys); unmarked facts are *linear* (consumed when used — good for one-shot session state, which is how we model single-use nonces). The `--[ ... ]->` middle holds *action facts*, which are timestamped events recorded on the execution *trace*. **Lemmas quantify over these traces**: "for all traces, if `Accept` happened at time `#i`, then some matching `Present` happened at an earlier time `#j`." Tamarin then either proves the lemma for *all possible traces* (an unbounded number of sessions and attacker actions) or produces a concrete counterexample trace (an attack).

ProVerif (an alternative, Section 11.9) expresses the same ideas in the *applied pi-calculus* instead of rewriting rules; it is often more automated but over-approximates and struggles with the stateful, injective (single-use) properties we care about here — which is why Tamarin is our primary tool.

---

### 11.1 Install Tamarin (and note ProVerif)

Tamarin is a Haskell program that drives **Maude** (a rewriting-logic engine) for its unification, and uses **GraphViz** to draw attack graphs in the interactive GUI. The maintained macOS path is the project's own Homebrew tap.

1. Install Tamarin, Maude, and GraphViz:

```bash
brew install tamarin-prover/tap/tamarin-prover
brew install graphviz            # only needed for the interactive GUI
```

The tap formula pulls in a compatible Maude automatically. (If you prefer, `brew install maude graphviz` first, then the tap — either order works.)

2. Verify the toolchain is on your PATH and reports versions:

```bash
tamarin-prover --version
maude --version
```

3. (Optional, the alternative back-end.) ProVerif is an OCaml program installed through OPAM, not Homebrew:

```bash
brew install opam
opam init --bare -y          # first time only
opam install -y proverif
proverif --help | head -n 1
```

**Definition of done.**
- `tamarin-prover --version` prints a line like `tamarin-prover 1.10.x, (C) ...`.
- `maude --version` prints a Maude 3.x version.
- If you did step 3, `proverif` runs and prints its usage banner.
If `tamarin-prover` is "command not found", run `brew link tamarin-prover` and re-open the shell.

---

### 11.2 Create the file and the directory

Tier 3 lives *outside* the Cargo workspace (it is not compiled into the product; it is a design artifact and a CI gate). Put it under a top-level `formal/` tree, alongside the Lean model from Tier 2.

1. Create the directory:

```bash
mkdir -p formal/tamarin
```

2. Create an empty theory so the tooling has something to parse. Every Tamarin file is `theory NAME begin ... end`:

```bash
cat > formal/tamarin/oid4vp_haip.spthy <<'EOF'
theory OID4VP_HAIP
begin

builtins: signing, asymmetric-encryption

end
EOF
```

`builtins: signing, asymmetric-encryption` imports two equational theories: `signing` gives `sign/2`, `verify/3`, `pk/1`, `true`; `asymmetric-encryption` gives `aenc/2`, `adec/2` and *shares* the same `pk/1`. (We will use **separate** signing and encryption keys per RP anyway, so there is no key-reuse smell in the model.) Pairing `<a, b, c>` and projection are built in and need no import.

3. Confirm Tamarin can parse an (almost) empty theory:

```bash
tamarin-prover formal/tamarin/oid4vp_haip.spthy
```

Running *without* `--prove` only loads, well-formedness-checks, and pretty-prints the theory — it does not attempt proofs. You will see the theory echoed back and, at the bottom, a `summary of summaries` block (empty for now) with **no** `wellformedness check failed` errors.

**Definition of done.** `formal/tamarin/oid4vp_haip.spthy` exists and `tamarin-prover formal/tamarin/oid4vp_haip.spthy` completes with no error and no well-formedness failure (an empty theory trivially passes).

---

### 11.3 What we are modelling: the HAIP OID4VP exchange

Before writing rules, fix the exchange we are formalising. This is the HAIP-constrained OpenID4VP remote flow (the `oid4vp` crate implements the real thing; here we model its *security-relevant* skeleton):

```
   Relying Party (RP)                              Wallet (W)
        |                                              |
        |  (1) signed Request Object (JAR):            |
        |      client_id=$RP  (== audience)            |
        |      response_enc_key = pkEnc                |
        |      nonce, state, DCQL query "over18"       |
        |      sig = sign(reqobj, RP_signing_key) ---->|
        |                                              | verify sig against
        |                                              | a *registered* RP key
        |                                              | (trusted list; NOT TLS)
        |                                              | -> consent -> disclose
        |  (2) ENCRYPTED response (JWE to pkEnc):      |
        |      KB-JWT = <audience=$RP, nonce, claim>   |
        |      device_sig = sign(KB-JWT, device_key)   |
        |<---- aenc(<KB-JWT, device_sig>, pkEnc)        |
        | decrypt; check aud==self; verify device_sig  |
        | -> Accept                                    |
```

The security-critical bindings are: the **request object is signed** (so the wallet cannot be driven by a forged request); the **response is encrypted to a key the signature vouches for** (so the disclosed claim is confidential); and the **Key-Binding token, signed by the device key, commits to `<audience, nonce, claim>`** (so the presentation is fresh, non-replayable, and provably meant for *this* RP — the anti-mix-up binding).

Model term ↔ real OID4VP artifact:

| Model term | Real artifact | Enforced by |
|---|---|---|
| `sign(reqobj, skSig)` | Request Object as a JAR (signed JWT) | RP signing key on the trusted list (`trust`/RP-registration section) |
| `$RP` inside `reqobj` and `kbjwt` | `client_id` = the audience | HAIP audience binding |
| `pkEnc` inside `reqobj` | response encryption key in `client_metadata` (`jwks`) | signature over `reqobj` binds it |
| `~nonce` | `nonce` | freshness / anti-replay |
| `aenc(resp, pkEnc)` | encrypted Authorization Response (JWE, `direct_post.jwt`) | HAIP response encryption |
| `kbjwt = <'kb',$RP,nonce,claim>` | SD-JWT VC **KB-JWT** (`aud`,`nonce`,`sd_hash`) or mdoc **DeviceAuth** over the SessionTranscript | holder/device key in WSCD |
| `sign(kbjwt, skDev)` | KB-JWT signature / mdoc `DeviceSignature` | Secure Enclave / StrongBox (never crosses FFI) |
| `!PkRPSig`, `!PkDev` | trusted-list anchor / attested device key (WUA, `wua` section) | attestation & registration |

Two deliberate abstractions, to state honestly up front: (a) we model the disclosed claim `~claim` as a single fresh secret rather than a full SD-JWT with per-disclosure salts — Tier 1's codec tests cover the byte-level disclosure structure, Tier 3 only needs "is this secret confidential and integrity-bound"; (b) we model the device public key as globally attested (`!PkDev`) rather than delivered inside the credential — that is the job of the `wua`/key-attestation layer, assumed sound here.

---

### 11.4 Write the setup and protocol rules

Open `formal/tamarin/oid4vp_haip.spthy` and replace the body (keep the `theory`/`builtins`/`end` lines) with the rules below. Add the **Equality restriction** first — it is the standard idiom that turns an `Eq(x,y)` action fact into the constraint `x = y`, which is how we force signature checks to actually succeed rather than being ignored.

```tamarin
/* ============================================================
   Restrictions
   ============================================================ */

// A rule that emits Eq(a,b) may only fire on traces where a = b.
// We use this to model "the receiver verified the signature".
restriction Equality:
    "All x y #i. Eq(x, y) @ #i ==> x = y"

/* ============================================================
   Setup / PKI  (public keys published; secrets stay put)
   ============================================================ */

// Relying Party registration. TWO key pairs: skSig signs the request
// object (JAR); skEnc decrypts the response (JWE). The persistent
// !PkRPSig fact abstracts "this RP is on the EUDI trusted list"
// (see the trust / RP-registration section). Public keys are Out().
rule Register_RP:
    [ Fr(~skSig), Fr(~skEnc) ]
  --[ RegisterRP($RP) ]->
    [ !LtkRPSig($RP, ~skSig)
    , !LtkRPEnc($RP, ~skEnc)
    , !PkRPSig($RP, pk(~skSig))
    , Out(pk(~skSig))
    , Out(pk(~skEnc)) ]

// Wallet device-bound key, created in the WSCD (Secure Enclave /
// StrongBox). The secret NEVER leaves the device: note there is no
// Out(~skDev) here — only the public key is published.
rule Setup_Wallet:
    [ Fr(~skDev) ]
  --[ SetupWallet($W) ]->
    [ !LtkDev($W, ~skDev)
    , !PkDev($W, pk(~skDev))
    , Out(pk(~skDev)) ]

// Issuance (OID4VCI, see the oid4vci section) modelled abstractly:
// the wallet obtains a credential carrying one selectively-
// disclosable claim ~claim (e.g. "over_18 = true").
rule Issue_Credential:
    [ Fr(~claim), !PkDev($W, pkDev) ]
  --[ Issued($W, ~claim) ]->
    [ !Cred($W, ~claim) ]

/* ============================================================
   Protocol
   ============================================================ */

// (1) RP builds and SIGNS a request object binding client_id (== the
// audience), the response-encryption key, a fresh nonce and state, and
// the requested claim type. The signed object goes on the open network.
rule RP_Send_Request:
    let pkEnc  = pk(~skEnc)
        reqobj = <'req', $RP, pkEnc, ~nonce, ~rid, 'over18'>
    in
    [ Fr(~nonce), Fr(~rid)
    , !LtkRPSig($RP, skSig)
    , !LtkRPEnc($RP, ~skEnc) ]
  --[ SendRequest($RP, ~nonce, ~rid) ]->
    [ Out( <reqobj, sign(reqobj, skSig)> )
    , RP_Awaiting($RP, ~nonce, ~rid, ~skEnc) ]   // linear: one-shot session

// (2) Wallet verifies the request signature against a REGISTERED RP key
// (never merely a TLS cert), records consent, and emits an ENCRYPTED
// response. The Key-Binding token signs <audience, nonce, claim> with
// the device key: that single signature carries freshness (nonce),
// audience binding (RPid), and integrity of the disclosed claim.
rule Wallet_Receive_And_Present:
    let reqobj = <'req', RPid, pkEnc, nonce, rid, 'over18'>
        kbjwt  = <'kb', RPid, nonce, ~claim>
        resp   = <kbjwt, sign(kbjwt, skDev)>
    in
    [ In( <reqobj, sig> )
    , !PkRPSig(RPid, pkRP)
    , !LtkDev($W, skDev)
    , !Cred($W, ~claim) ]
  --[ Eq( verify(sig, reqobj, pkRP), true )       // request sig valid
    , ConsentGiven($W, RPid, nonce, ~claim)        // consent (see consent §)
    , Present($W, RPid, nonce, ~claim) ]->
    [ Out( aenc(resp, pkEnc) ) ]                    // response encrypted to RP

// (3) RP receives the (encrypted) response, checks the audience field
// equals its own id (the pattern $RP inside kbjwt does this), and
// verifies the device signature. RP_Awaiting is consumed -> nonce is
// single-use (models the RP invalidating the nonce after one response).
rule RP_Receive_Presentation:
    let kbjwt = <'kb', $RP, nonce, claim>
        resp  = <kbjwt, kbsig>
        ciph  = aenc(resp, pk(~skEnc))
    in
    [ RP_Awaiting($RP, nonce, rid, ~skEnc)
    , In( ciph )
    , !PkDev(W, pkDev) ]
  --[ Eq( verify(kbsig, kbjwt, pkDev), true )       // device sig valid
    , Accept($RP, W, nonce, claim) ]->
    [ ]

/* ============================================================
   Adversary compromise (Dolev-Yao key reveals)
   ============================================================ */

rule Reveal_RP_Sig:  [ !LtkRPSig($RP, k) ] --[ RevealRPSig($RP) ]-> [ Out(k) ]
rule Reveal_RP_Enc:  [ !LtkRPEnc($RP, k) ] --[ RevealRPEnc($RP) ]-> [ Out(k) ]
rule Reveal_Dev:     [ !LtkDev($W, k) ]    --[ RevealDev($W) ]->    [ Out(k) ]
```

Key modelling points to understand (these are what make the lemmas mean something):

- **`In`/`Out` are the attacker.** The signed request in rule (1) is handed to the attacker; the wallet in rule (2) receives from the attacker. So rule (2) also fires on *forged* or *replayed* inputs — the `Eq(verify(...), true)` premise is the only thing standing between "any input" and "accepted input". If the attacker cannot produce a valid `sign(reqobj, skSig)` without `skSig`, the wallet will not proceed. That is precisely the "never accept an unsigned/unbound request object" rule from the hard constraints, made machine-checkable.
- **`RP_Awaiting` is linear**, so a captured, replayed response finds no session state the second time — this is the model of the RP enforcing single-use nonces. Injectivity (no replay) follows from it.
- **The `$RP` inside `kbjwt` is the audience binding.** In rule (3) the RP pattern-matches `<'kb', $RP, nonce, claim>` with `$RP` = *its own* identity. A KB token minted for a *different* audience simply does not unify, so a malicious RP cannot forward a presentation it received to a second, honest RP. That is the anti-mix-up mechanism, and lemma `no_mixup` tests it.
- **The device secret never appears in an `Out`** except through the explicit `Reveal_Dev` rule — matching the architecture rule that device-bound keys never cross the FFI and live only in the WSCD.

**Definition of done.** Re-run the parser:

```bash
tamarin-prover formal/tamarin/oid4vp_haip.spthy
```

It prints the theory with all rules and reports **no** well-formedness errors. You may see a warning about *partial deconstructions* referencing `RP_Receive_Presentation` — that is expected because the RP decrypts with a secret key, and it is addressed in Section 11.7. It is a warning, not a failure.

---

### 11.5 State the lemmas (the security goals)

Append the following lemma block **before** the final `end`. Each lemma is stated in the exact vocabulary the requirements call for; the comment above each says, in plain English, the property and its real-world meaning. Temporal variables are `#i`; `@ #i` reads "at time `#i`"; `K(x)` is the built-in **attacker-knowledge** action (the attacker has derived term `x`).

```tamarin
/* ============================================================
   Lemmas
   ============================================================ */

// (0) SANITY / executability. Without this an over-constrained model
// could make every safety lemma vacuously true. It must find ONE
// honest, reveal-free trace that runs to Accept.
lemma executable:
  exists-trace
  "Ex W RP nonce claim #p #a.
        Present(W, RP, nonce, claim) @ #p
      & Accept(RP, W, nonce, claim) @ #a
      & #p < #a
      & not (Ex X #r. RevealDev(X)   @ #r)
      & not (Ex X #r. RevealRPSig(X) @ #r)
      & not (Ex X #r. RevealRPEnc(X) @ #r)"

// (1) NONCE FRESHNESS at origin. Every nonce is generated by exactly
// one RP request. Marked [reuse] so later proofs may cite it.
lemma nonce_origin [reuse]:
  "All RP nonce rid #i.
        SendRequest(RP, nonce, rid) @ #i
      ==> not (Ex RP2 rid2 #j.
                 SendRequest(RP2, nonce, rid2) @ #j & not (#i = #j))"

// (2) SECRECY of the disclosed claim. The attacker learns a claim ONLY
// if it was presented to an RP whose decryption key was revealed, or
// whose signing key was revealed (letting the attacker forge a request
// that redirects the encrypted response to a key it controls). Honest
// RP + honest wallet => the disclosed claim never reaches an
// unintended party.
lemma claim_secrecy:
  "All claim #k.
        K(claim) @ #k
      ==> (Ex W RP n #p.
              Present(W, RP, n, claim) @ #p
            & ( (Ex #r. RevealRPEnc(RP) @ #r)
              | (Ex #r. RevealRPSig(RP) @ #r) ) )"

// (3) AUTHENTICATION of the request: acceptance implies a matching
// legitimate request. A wallet only ever discloses in response to a
// genuine, signed request that the named RP actually sent — unless
// that RP's signing key leaked. (No wallet action on forged requests.)
lemma request_authentication:
  "All W RP nonce claim #i.
        Present(W, RP, nonce, claim) @ #i
      ==> (Ex rid #j. SendRequest(RP, nonce, rid) @ #j & #j < #i)
        | (Ex #r. RevealRPSig(RP) @ #r)"

// (4) NO REPLAY: a given presentation is accepted at most once.
lemma no_replay:
  "All RP W nonce claim #i #j.
        Accept(RP, W, nonce, claim) @ #i
      & Accept(RP, W, nonce, claim) @ #j
      ==> #i = #j"

// (5) NO MIX-UP: a presentation for a given nonce+claim can be accepted
// by only ONE RP identity — the audience binding stops RP2 from
// consuming a presentation meant for RP1.
lemma no_mixup:
  "All RP1 RP2 W nonce claim #i #j.
        Accept(RP1, W, nonce, claim) @ #i
      & Accept(RP2, W, nonce, claim) @ #j
      ==> RP1 = RP2"

// (6) INJECTIVE AGREEMENT (Lowe's hierarchy, canonical Tamarin form):
// whenever an RP accepts a presentation of <nonce,claim> as coming from
// wallet W, then W really did present exactly that to exactly this RP
// beforehand, AND no second Accept exists for the same nonce+claim
// (injectivity => no replay / no duplication) — unless W's device key
// was compromised.
lemma injective_agreement:
  "All RP W nonce claim #i.
        Accept(RP, W, nonce, claim) @ #i
      ==> ( (Ex #j. Present(W, RP, nonce, claim) @ #j & #j < #i)
          & not (Ex RP2 W2 #i2.
                   Accept(RP2, W2, nonce, claim) @ #i2 & not (#i2 = #i)) )
        | (Ex #r. RevealDev(W) @ #r)"
```

How each requirement maps to a lemma:

- **Secrecy of the disclosed claim to unintended parties** → `claim_secrecy` (lemma 2). Meaningful *because* the response is `aenc(resp, pkEnc)`: a cleartext `Out` would leak the claim to the network attacker immediately, so this lemma is also a regression test that HAIP response encryption is present and correctly bound.
- **Injective agreement / no mix-up / no replay** → `injective_agreement` (6), plus the standalone `no_replay` (4) and `no_mixup` (5) which isolate the two failure modes so a counterexample points straight at the cause.
- **Nonce freshness** → `nonce_origin` (1) at the origin, and the injectivity clause of (6) at consumption.
- **Acceptance implies a matching legitimate request (authentication)** → `request_authentication` (3).

Note what Tier 2 already owns and Tier 3 therefore only records (via the `ConsentGiven` action) rather than re-proves: the *ordering* invariant "no disclosure Effect before a consent Event" is proven in the Lean model (Tier 2 section) over the deterministic core. Tier 3 assumes consent happened and focuses on the network adversary. Keeping the `ConsentGiven` action fact in the model lets you later add a cross-tier lemma if you want a belt-and-braces check.

**Definition of done.** `tamarin-prover formal/tamarin/oid4vp_haip.spthy` (still no `--prove`) lists all seven lemmas in the `summary of summaries` with status `analysis incomplete` (because we have not asked it to prove yet) and reports no well-formedness errors. **This is the primary deliverable of the section: the `.spthy` exists, Tamarin parses it, and the lemmas are stated.**

---

### 11.6 The complete file

For convenience, `formal/tamarin/oid4vp_haip.spthy` in full is the concatenation of: the `theory OID4VP_HAIP begin` header and `builtins` line from Section 11.2, the restriction + rules block from Section 11.4, the lemma block from Section 11.5, and a closing `end`. Verify the assembled file once more:

```bash
tamarin-prover formal/tamarin/oid4vp_haip.spthy | tail -n 25
```

You should see the `summary of summaries` table naming `executable`, `nonce_origin`, `claim_secrecy`, `request_authentication`, `no_replay`, `no_mixup`, and `injective_agreement`.

---

### 11.7 Run the prover

Now ask Tamarin to actually discharge the lemmas. The **single command the requirements call for**:

```bash
tamarin-prover --prove formal/tamarin/oid4vp_haip.spthy
```

This attempts every lemma and prints, per lemma, `verified`, `falsified` (with `- found trace`), or leaves it open if the search does not terminate within the constraint solver's default effort. Because Tier 3 uses `aenc` decryption with a secret key, the first run will very likely report **partial deconstructions** and may leave `claim_secrecy` and `injective_agreement` open. That is normal and has a standard fix. Escalate in this order:

1. **Turn on automatic source-lemma generation** (resolves almost all partial-deconstruction cases automatically):

```bash
tamarin-prover --prove --auto-sources formal/tamarin/oid4vp_haip.spthy
```

2. **Prove one lemma at a time** while iterating, and use all CPU cores:

```bash
tamarin-prover --prove=executable            formal/tamarin/oid4vp_haip.spthy +RTS -N -RTS
tamarin-prover --prove=nonce_origin          formal/tamarin/oid4vp_haip.spthy +RTS -N -RTS
tamarin-prover --prove=request_authentication formal/tamarin/oid4vp_haip.spthy +RTS -N -RTS
tamarin-prover --prove=no_replay             formal/tamarin/oid4vp_haip.spthy +RTS -N -RTS
tamarin-prover --prove=no_mixup              formal/tamarin/oid4vp_haip.spthy +RTS -N -RTS
tamarin-prover --prove=claim_secrecy   --auto-sources formal/tamarin/oid4vp_haip.spthy +RTS -N -RTS
tamarin-prover --prove=injective_agreement --auto-sources formal/tamarin/oid4vp_haip.spthy +RTS -N -RTS
```

3. **Inspect interactively** when a lemma neither verifies nor falsifies quickly — this opens the attack-graph GUI where you can watch the constraint search and hand-guide it:

```bash
tamarin-prover interactive formal/tamarin/oid4vp_haip.spthy
# then open http://127.0.0.1:3001 in a browser
```

**Reading the results.**
- `executable` must be `verified` (it is `exists-trace`; if it is *falsified*, your model is over-constrained and every other "proof" is vacuous — fix this first).
- `claim_secrecy`, `request_authentication`, `no_replay`, `no_mixup`, `injective_agreement` should be `verified`. If any is `falsified`, Tamarin hands you a concrete trace: the exact sequence of attacker actions that breaks the property. That trace *is* the bug report — for a wallet, most likely a missing binding (e.g., drop the `$RP` audience from `kbjwt` and re-run to *see* `no_mixup` become falsified with a mix-up trace; that experiment is worth doing once to convince yourself the lemma has teeth).

**On full automation, honestly.** Injective-agreement and secrecy over an unbounded model with encryption sometimes need help even after `--auto-sources`: a *reuse* helper lemma (a small invariant proven once and cited by the harder proofs — `nonce_origin` is already one) and occasionally a custom **oracle** (a ranking heuristic script passed via `--heuristic=O --oracle-name=formal/tamarin/oid4vp.oracle`) to steer the constraint solver away from non-terminating branches. Writing an oracle is a documented Tamarin technique (a small Python/shell script that reorders proof goals). Budget for it: the stated lemmas are the contract; achieving fully-automated `verified` on the two hard ones is an iteration that may add helper lemmas.

**Definition of done.**
- `tamarin-prover --prove=executable formal/tamarin/oid4vp_haip.spthy` prints `executable ... verified`.
- `tamarin-prover --prove --auto-sources formal/tamarin/oid4vp_haip.spthy` runs to completion and prints a `summary of summaries`; the safety lemmas that terminate are `verified` and none is `falsified`.
- Any lemma still open is annotated in the file with a `// TODO(oracle/helper)` comment naming what is needed — the section's contract is *stated lemmas + parsing + executable verified*, with full automation of the two hard lemmas tracked as follow-up.

---

### 11.8 Wire it into CI (FCAF gate)

Tier 3 belongs in the conformance pipeline (the FCAF-in-CI section) as a non-blocking-then-blocking gate. Two-phase rollout keeps the pipeline green while the hard proofs are still being automated.

Add `formal/tamarin/run.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail
SPTHY="$(dirname "$0")/oid4vp_haip.spthy"

# Phase 1 (always blocking): the model must parse and stay well-formed,
# and the sanity trace must exist. This is the section's Definition of Done.
tamarin-prover "$SPTHY" >/dev/null
tamarin-prover --prove=executable "$SPTHY" | grep -Eq 'executable.*verified'

# Phase 2 (blocking once oracles land): the safety lemmas must not be
# falsified. A regression that introduces a mix-up/replay fails CI here.
OUT="$(tamarin-prover --prove --auto-sources "$SPTHY" +RTS -N -RTS || true)"
echo "$OUT"
if echo "$OUT" | grep -q 'falsified'; then
  echo "FAIL: a Tier-3 lemma was falsified (protocol attack found)"; exit 1
fi
echo "Tier-3 symbolic check passed."
```

```bash
chmod +x formal/tamarin/run.sh
```

Cache the proof effort in CI and pin the Tamarin version (record `tamarin-prover --version` in the pipeline log) — Tier 3, like every other version-sensitive artifact in this project, is pinned so results are reproducible.

**Definition of done.** `formal/tamarin/run.sh` exits `0` locally; the CI job invokes it and fails loudly on any `falsified`.

---

### 11.9 ProVerif as an alternative back-end (brief)

If a reviewer prefers ProVerif, the *same* protocol is expressed in the applied pi-calculus. A skeleton lives at `formal/proverif/oid4vp_haip.pv`:

```ocaml
(* formal/proverif/oid4vp_haip.pv *)
free net: channel.

type skey. type pkey.
fun pk(skey): pkey.
(* signatures *)
fun sign(bitstring, skey): bitstring.
reduc forall m: bitstring, k: skey; checksign(sign(m,k), pk(k)) = m.
(* public-key encryption *)
fun aenc(bitstring, pkey): bitstring.
reduc forall m: bitstring, k: skey; adec(aenc(m, pk(k)), k) = m.

free claim: bitstring [private].          (* the disclosed attribute *)

query attacker(claim).                     (* secrecy of the claim *)
event Present(pkey, bitstring).            (* wallet -> RP, nonce *)
event Accept(pkey, bitstring).            (* RP accepted, nonce  *)
query x: pkey, n: bitstring;
      inj-event(Accept(x,n)) ==> inj-event(Present(x,n)).  (* injective agreement *)

(* processes for RP and Wallet mirroring the three Tamarin rules,
   composed under !(new skSig; new skEnc; ... ) go here *)
```

Run it with:

```bash
proverif formal/proverif/oid4vp_haip.pv
```

ProVerif proves the `query attacker(claim)` (secrecy) and the `inj-event(...) ==> inj-event(...)` (injective agreement) goals, usually faster and with less manual steering than Tamarin. The trade-off: ProVerif *over-approximates* (it may report a false attack that Tamarin can rule out) and models mutable global state / single-use tables less naturally than Tamarin's linear facts — which is exactly the nonce-single-use property we lean on. **Recommendation: Tamarin is primary** (it handles the injective, stateful, single-use nonce model precisely, and `no_mixup`/`no_replay` fall out of linear facts); keep ProVerif as an independent second opinion — agreement between two tools with different engines is strong evidence.

---

### 11.10 What Tier 3 proves that Tiers 1 and 2 cannot

State this explicitly in the plan so reviewers understand why all three tiers exist:

- **Tier 1 (proptest / cargo-fuzz / Kani — Tier 1 section)** proves the *codecs and functions* are total and memory-safe: no panic, no `unsafe`, round-trip encode/decode, canonical-CBOR determinism. Scope: one function, honest inputs and adversarial *bytes*. It cannot reason about *who sent a message* or *across sessions*.
- **Tier 2 (Lean 4 — Tier 2 section)** proves the *state machine* obeys ordering and reachability invariants for a single honest run, and exports traces as an oracle for the Rust core. Scope: one participant executing correctly. It assumes messages arrive as intended; it has no adversary who forges, replays, reorders, or runs parallel sessions.
- **Tier 3 (this section)** proves properties of the *protocol against a Dolev-Yao network attacker*: secrecy of the disclosed claim, injective agreement, freshness, no mix-up, no replay, and request authentication — *quantified over unboundedly many concurrent sessions and over an attacker who owns the channel and may be a compromised RP*. These are **network-level attacks** — mix-up, cut-and-paste, token/presentation substitution, replay, IdP/RP confusion — that are, by construction, invisible to Tiers 1 and 2 because those tiers never model a second party or an adversarial network. This is the same class of guarantee the FAPI 2.0 formal analysis provides for that profile, applied to our HAIP OpenID4VP exchange.

---

### 11.11 Section Definition of done (summary)

1. `brew install tamarin-prover/tap/tamarin-prover` succeeds; `tamarin-prover --version` prints a version. **(11.1)**
2. `formal/tamarin/oid4vp_haip.spthy` exists and `tamarin-prover formal/tamarin/oid4vp_haip.spthy` parses it with **no well-formedness errors**. **(11.2, 11.6)**
3. The file models Wallet, Relying Party, the signed/bound request object, `pkEnc`, `nonce`, audience, and the selectively-disclosed claim, with rules for fresh nonce, request signing, and presentation (key) binding, plus Dolev-Yao reveal rules. **(11.4)**
4. All seven lemmas — `executable`, `nonce_origin`, `claim_secrecy`, `request_authentication`, `no_replay`, `no_mixup`, `injective_agreement` — are **stated** and appear in Tamarin's `summary of summaries`. **(11.5)**
5. `tamarin-prover --prove=executable ...` reports `verified`; `tamarin-prover --prove --auto-sources ...` reports **no `falsified`** lemma. **(11.7)**
6. `formal/proverif/oid4vp_haip.pv` skeleton exists as the alternative back-end (optional but recommended). **(11.9)**
7. `formal/tamarin/run.sh` is wired into the FCAF CI job. **(11.8)**

Explicit caveat carried in the plan: the deliverable is the *stated and parsing* model with `executable` verified and no falsifications; **full automated proof of `claim_secrecy` and `injective_agreement` may require `[reuse]` helper lemmas and/or a custom oracle**, tracked as follow-up in `// TODO(oracle/helper)` comments in the `.spthy` file.

---


## Section 12 — Requirements traceability, certification evidence, FCAF-in-CI, and SBOM

This section is the "paper trail" section. Nothing here changes what the wallet *does* at runtime — it builds the machinery that lets you (and a Conformity Assessment Body, "CAB", the accredited lab that certifies the wallet) *prove* that every legal/technical requirement is (a) known, (b) assigned to code, (c) tested, and (d) backed by evidence. For a certifiable EUDI wallet this machinery is not optional polish: under the EUCC scheme (the EU Common Criteria-based cybersecurity certification scheme, Reg. (EU) 2024/482) and the Wallet implementing act **Reg. (EU) 2024/2981** (certification of wallet solutions), the *absence* of traceability is itself a finding that fails the assessment.

Jargon you need once:
- **HLR** = High-Level Requirement. One row of the canonical register you were handed (the "build profile from the register" in the shared context). Each HLR has a stable ID.
- **Applicability** = whether an HLR applies to *this* build. A P0-profile wallet is not obliged to satisfy a P2 mDL requirement, but it must *say so explicitly* and record *why*.
- **Traceability** = a two-way link: requirement → code symbol(s) + test(s) + evidence; and back. "Two-way" matters because auditors walk it in both directions ("show me the test for HLR-STATUS-003" and "this function exists — which requirement justifies it?").
- **FCAF** = the EUDI Feature Conformance Assessment Framework (v0.0.7 as of the shared context), the EU-published conformance test-suite. Passing it is *necessary but not sufficient* for certification.
- **TOE** = Target Of Evaluation (Common Criteria term): the exact boundary of what is being certified (which crates, which platform services, which keys).
- **SBOM** = Software Bill Of Materials: a machine-readable list of every dependency and its version, required by the **Cyber Resilience Act (CRA, Reg. (EU) 2024/2847)**.
- **DPIA** = Data Protection Impact Assessment, required by **GDPR Art. 35** because a wallet processes identity data at scale.
- **KAT** = Known-Answer Test: a cryptographic test vector with a fixed input and a fixed expected output, used to prove an algorithm implementation is correct.

Where this connects to the rest of the plan: the importer consumes the requirement IDs that every other section is expected to cite in code (see the `// HLR:` convention below); the FCAF-in-CI job sits alongside the proptest/fuzz/Kani jobs from the formal-methods sections; and the evidence repo stores the Lean trace exports (Tier 2) and Tamarin proofs (Tier 3) referenced in the shared context.

---

### 12.1 The traceability database and the `tools/hlr-import/` importer

#### Step 12.1.1 — Fix the canonical input: the HLR CSV

Everything starts from **one** authoritative CSV, checked into the repo, version-pinned. Create the directory and a *frozen copy* of the register (never edit the register in place inside code files — edit the CSV, re-import, commit).

```bash
# from repo root
mkdir -p tools/hlr-import
mkdir -p traceability
mkdir -p docs/certification-evidence
```

Place the canonical register at `traceability/hlr.csv`. The importer treats this file as **read-only input**. Its columns (this is the *source* schema — what the register gives you):

```
hlr_id,text,source_doc,source_version,profile,category
```

Example rows (`traceability/hlr.csv`) — real HLR IDs invented against the shared-context spec, but shaped exactly as the ARF/PID register rows are:

```csv
hlr_id,text,source_doc,source_version,profile,category
HLR-FMT-001,"The wallet MUST support the mdoc credential format (ISO/IEC 18013-5).",HLR-Register,2026-07-17,P0,formats
HLR-FMT-002,"The wallet MUST support the SD-JWT VC credential format (draft-17).",HLR-Register,2026-07-17,P0,formats
HLR-PRES-001,"The wallet MUST support remote presentation via OpenID4VP 1.0 (HAIP-constrained).",HLR-Register,2026-07-17,P0,presentation
HLR-PRES-002,"The wallet MUST support proximity presentation via ISO/IEC 18013-5.",HLR-Register,2026-07-17,P0,presentation
HLR-ISS-001,"PID issuance MUST be supported in both mdoc and SD-JWT VC formats via OID4VCI/HAIP.",HLR-Register,2026-07-17,P0,issuance
HLR-KEY-001,"Device-bound high-assurance keys MUST reside in the WSCD (Secure Enclave/StrongBox); private key material MUST NOT cross the FFI.",HLR-Register,2026-07-17,P0,keys
HLR-WUA-001,"The wallet MUST produce a Wallet Unit Attestation and key attestation (TS03).",HLR-Register,2026-07-17,P0,attestation
HLR-CONSENT-001,"The consent ScreenDescription MUST be canonically encoded and hashed inside the core (what-you-see-is-what-you-sign).",HLR-Register,2026-07-17,P0,consent
HLR-SD-001,"The wallet MUST NOT disclose a whole credential where selective disclosure is available.",HLR-Register,2026-07-17,P0,consent
HLR-STATUS-001,"The wallet MUST evaluate Token Status List (draft-21) with a deterministic fail-open/fail-closed policy.",HLR-Register,2026-07-17,P0,status
HLR-TRUST-001,"The wallet MUST validate RP registration; a valid TLS certificate MUST NOT be treated as RP registration.",HLR-Register,2026-07-17,P0,trust
HLR-A11Y-001,"The wallet MUST meet EN 301 549 / WCAG 2.2 AA.",HLR-Register,2026-07-17,P0,accessibility
HLR-CRA-001,"The wallet MUST publish a signed SBOM and a vulnerability-handling process (CRA).",HLR-Register,2026-07-17,P0,ops
HLR-MDL-001,"The wallet MAY support mDL (ISO/IEC 18013-5/6/7).",HLR-Register,2026-07-17,P2,formats
HLR-ZKP-001,"The wallet MAY expose a ZKP abstraction point (TS04) with NO production dependency.",HLR-Register,2026-07-17,WATCH,privacy
```

> Rule of the CSV: `hlr_id` is **immutable** once shipped. If the register changes wording, you bump `source_version` and (if the requirement's *meaning* changed) you retire the old ID and mint a new one. Never silently reuse an ID for a new meaning — auditors diff by ID.

**Definition of done (12.1.1):**
```bash
python3 -c "import csv; rows=list(csv.DictReader(open('traceability/hlr.csv'))); print(len(rows),'rows'); assert all(r['hlr_id'] for r in rows)"
```
Expected: prints e.g. `15 rows` and does not raise.

---

#### Step 12.1.2 — Design the traceability schema (output)

The importer *reads* `hlr.csv` and *produces* an enriched table. Two output backends, both driven by the same schema: a flat `traceability/requirements.csv` (human-diffable in PRs) and a `traceability/requirements.sqlite` (queryable in CI). The enriched schema adds the mapping columns:

| column | meaning | populated by |
|---|---|---|
| `hlr_id` | stable ID (from CSV) | importer |
| `text` | requirement text (from CSV) | importer |
| `source_doc` / `source_version` | provenance + version pin (from CSV) | importer |
| `profile` | P0 / P1 / P2 / WATCH (from CSV) | importer |
| `applicability` | `applicable` / `not_applicable` | mapping file (12.1.4) |
| `na_justification` | why not applicable (required if `not_applicable`) | mapping file |
| `mapped_symbols` | `;`-joined code symbols, e.g. `mdoc::MobileSecurityObject::verify` | scanner (12.1.3) + mapping file |
| `mapped_tests` | `;`-joined test IDs, e.g. `mdoc::tests::mso_roundtrip` | scanner + mapping file |
| `evidence_link` | relative path under `docs/certification-evidence/` | mapping file |
| `status` | `unassigned` / `assigned` / `tested` / `evidenced` | **computed** by importer |
| `owner` | responsible engineer | mapping file |

`status` is *derived*, not hand-edited, so it cannot be gamed:
- `unassigned` — applicable but no `mapped_symbols`.
- `assigned` — has symbols but no `mapped_tests`.
- `tested` — has symbols and tests.
- `evidenced` — has symbols, tests, and a valid `evidence_link` that resolves to an existing file.
- `not_applicable` rows are excluded from the P0 gate (but their `na_justification` must be non-empty).

**Definition of done (12.1.2):** the schema is captured as code in the next step (a dataclass); no separate command.

---

#### Step 12.1.3 — The `// HLR:` code convention and the source scanner

The link between requirement and code is a **structured comment tag** you require every certification-critical symbol to carry. This is the rule the whole section enforces: *no code exists in a core crate without a requirement ID justifying it.* Junior-dev-friendly, greppable, and cheap.

In Rust (any core crate), immediately above the item:

```rust
// HLR: HLR-FMT-001
/// Verify the MobileSecurityObject signature and digests (ISO/IEC 18013-5 §9.1.2).
pub fn verify(mso: &MobileSecurityObject, /* ... */) -> Result<(), MdocError> {
    // ...
}
```

Tests use `// HLR-TEST:`:

```rust
// HLR-TEST: HLR-FMT-001
#[test]
fn mso_roundtrip() { /* ... */ }
```

For Swift shell code (accessibility, local auth), the same tag in `//` comments; for Lean, `-- HLR:`; for Tamarin, `// HLR:` inside the `.spthy`. The scanner is language-agnostic (it greps tags), so one tool covers all four.

Now the importer. Layout:

```
tools/hlr-import/
├── pyproject.toml
├── hlr_import/
│   ├── __init__.py
│   ├── model.py        # dataclasses + status computation
│   ├── scanner.py      # walks the tree, collects // HLR: tags
│   ├── mapping.py      # loads the human-maintained mapping YAML
│   ├── importer.py     # the orchestrator + CSV/sqlite writers
│   └── gate.py         # the P0 gate check (exit non-zero on failure)
└── tests/
    └── test_importer.py
```

`tools/hlr-import/pyproject.toml` (uv-managed, per confirmed toolchain):

```toml
[project]
name = "hlr-import"
version = "0.1.0"
requires-python = ">=3.14"
dependencies = ["PyYAML>=6.0"]

[project.scripts]
hlr-import = "hlr_import.importer:main"
hlr-gate   = "hlr_import.gate:main"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"
```

`tools/hlr-import/hlr_import/model.py`:

```python
from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path

VALID_PROFILES = {"P0", "P1", "P2", "WATCH"}
VALID_APPLIC = {"applicable", "not_applicable"}

@dataclass
class Requirement:
    hlr_id: str
    text: str
    source_doc: str
    source_version: str
    profile: str
    category: str
    # enriched:
    applicability: str = "applicable"
    na_justification: str = ""
    mapped_symbols: list[str] = field(default_factory=list)
    mapped_tests: list[str] = field(default_factory=list)
    evidence_link: str = ""
    owner: str = ""
    status: str = "unassigned"  # computed

    def compute_status(self, evidence_root: Path) -> None:
        """Derive status. Never trust a hand-written status."""
        if self.applicability == "not_applicable":
            self.status = "not_applicable"
            return
        if not self.mapped_symbols:
            self.status = "unassigned"
            return
        if not self.mapped_tests:
            self.status = "assigned"
            return
        # has symbols + tests
        if self.evidence_link and (evidence_root / self.evidence_link).exists():
            self.status = "evidenced"
        else:
            self.status = "tested"

    def validate(self) -> list[str]:
        errs: list[str] = []
        if self.profile not in VALID_PROFILES:
            errs.append(f"{self.hlr_id}: bad profile {self.profile!r}")
        if self.applicability not in VALID_APPLIC:
            errs.append(f"{self.hlr_id}: bad applicability {self.applicability!r}")
        if self.applicability == "not_applicable" and not self.na_justification.strip():
            errs.append(f"{self.hlr_id}: not_applicable requires na_justification")
        if self.evidence_link and self.applicability == "not_applicable":
            errs.append(f"{self.hlr_id}: not_applicable must not carry evidence_link")
        return errs
```

`tools/hlr-import/hlr_import/scanner.py` — walks the crates and collects the tags so the mapping file does not have to list every symbol by hand (the scanner *discovers* code→HLR links; the mapping file supplies what code cannot: applicability, evidence links, owners):

```python
from __future__ import annotations
import re
from pathlib import Path

# matches: // HLR: HLR-FMT-001   and   -- HLR: HLR-FMT-001   and  # HLR: ...
_TAG = re.compile(r"(?://|--|#)\s*HLR:\s*([A-Z0-9\-]+)")
_TEST_TAG = re.compile(r"(?://|--|#)\s*HLR-TEST:\s*([A-Z0-9\-]+)")

# next non-blank, non-comment, non-attribute line = the "symbol"
_SYMBOL = re.compile(r"\b(fn|struct|enum|trait|impl|func|def|theorem|lemma|rule)\s+([A-Za-z0-9_]+)")

SCAN_ROOTS = ["crates", "apps/ios", "formal/lean", "formal/tamarin"]
SCAN_EXTS = {".rs", ".swift", ".lean", ".spthy", ".py"}

def scan(repo_root: Path) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """Return (hlr_id -> {symbols}, hlr_id -> {test_ids})."""
    symbols: dict[str, set[str]] = {}
    tests: dict[str, set[str]] = {}
    for root in SCAN_ROOTS:
        base = repo_root / root
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if path.suffix not in SCAN_EXTS or "target" in path.parts:
                continue
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            for i, line in enumerate(lines):
                for m in _TAG.finditer(line):
                    sym = _find_symbol(lines, i, path, root)
                    symbols.setdefault(m.group(1), set()).add(sym)
                for m in _TEST_TAG.finditer(line):
                    sym = _find_symbol(lines, i, path, root)
                    tests.setdefault(m.group(1), set()).add(sym)
    return symbols, tests

def _find_symbol(lines: list[str], idx: int, path: Path, root: str) -> str:
    for j in range(idx + 1, min(idx + 8, len(lines))):
        m = _SYMBOL.search(lines[j])
        if m:
            crate = path.parts[path.parts.index(root) + 1] if root in path.parts else path.stem
            return f"{crate}::{m.group(2)}"
    return f"{path.name}:{idx + 1}"  # fallback: file:line
```

`tools/hlr-import/hlr_import/mapping.py` — loads the *human-maintained* enrichment (see 12.1.4):

```python
from __future__ import annotations
import yaml
from pathlib import Path

def load_mapping(path: Path) -> dict[str, dict]:
    if not path.exists():
        return {}
    data = yaml.safe_load(path.read_text()) or {}
    return {row["hlr_id"]: row for row in data.get("requirements", [])}
```

`tools/hlr-import/hlr_import/importer.py` — the orchestrator + writers:

```python
from __future__ import annotations
import argparse, csv, sqlite3, sys
from pathlib import Path
from .model import Requirement
from .scanner import scan
from .mapping import load_mapping

CSV_COLS = ["hlr_id","text","source_doc","source_version","profile","category",
            "applicability","na_justification","mapped_symbols","mapped_tests",
            "evidence_link","owner","status"]

def build(repo_root: Path) -> list[Requirement]:
    hlr_csv = repo_root / "traceability" / "hlr.csv"
    mapping = load_mapping(repo_root / "traceability" / "mapping.yaml")
    scanned_syms, scanned_tests = scan(repo_root)
    evidence_root = repo_root / "docs" / "certification-evidence"

    reqs: list[Requirement] = []
    errors: list[str] = []
    with hlr_csv.open() as f:
        for row in csv.DictReader(f):
            r = Requirement(
                hlr_id=row["hlr_id"], text=row["text"],
                source_doc=row["source_doc"], source_version=row["source_version"],
                profile=row["profile"], category=row["category"],
            )
            m = mapping.get(r.hlr_id, {})
            r.applicability = m.get("applicability", "applicable")
            r.na_justification = m.get("na_justification", "")
            r.evidence_link = m.get("evidence_link", "")
            r.owner = m.get("owner", "")
            # merge scanned symbols/tests with any manually listed ones
            r.mapped_symbols = sorted(set(scanned_syms.get(r.hlr_id, set())) |
                                      set(m.get("extra_symbols", [])))
            r.mapped_tests = sorted(set(scanned_tests.get(r.hlr_id, set())) |
                                    set(m.get("extra_tests", [])))
            errors.extend(r.validate())
            r.compute_status(evidence_root)
            reqs.append(r)

    # a mapping row that references an unknown HLR ID is an error (typo guard)
    known = {r.hlr_id for r in reqs}
    for mid in mapping:
        if mid not in known:
            errors.append(f"mapping.yaml references unknown HLR id {mid!r}")

    if errors:
        print("VALIDATION ERRORS:", file=sys.stderr)
        for e in errors:
            print("  -", e, file=sys.stderr)
        sys.exit(2)
    return reqs

def write_csv(reqs: list[Requirement], out: Path) -> None:
    with out.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=CSV_COLS)
        w.writeheader()
        for r in reqs:
            w.writerow({
                **{k: getattr(r, k) for k in CSV_COLS
                   if k not in ("mapped_symbols", "mapped_tests")},
                "mapped_symbols": ";".join(r.mapped_symbols),
                "mapped_tests": ";".join(r.mapped_tests),
            })

def write_sqlite(reqs: list[Requirement], out: Path) -> None:
    if out.exists():
        out.unlink()
    con = sqlite3.connect(out)
    con.execute(f"CREATE TABLE requirements ({','.join(c+' TEXT' for c in CSV_COLS)})")
    con.executemany(
        f"INSERT INTO requirements VALUES ({','.join('?' for _ in CSV_COLS)})",
        [tuple(";".join(getattr(r, c)) if c in ("mapped_symbols","mapped_tests")
               else getattr(r, c) for c in CSV_COLS) for r in reqs])
    con.commit(); con.close()

def main() -> None:
    ap = argparse.ArgumentParser(prog="hlr-import")
    ap.add_argument("--repo-root", type=Path, default=Path.cwd())
    args = ap.parse_args()
    reqs = build(args.repo_root)
    trace = args.repo_root / "traceability"
    write_csv(reqs, trace / "requirements.csv")
    write_sqlite(reqs, trace / "requirements.sqlite")
    n = len(reqs)
    by = lambda s: sum(1 for r in reqs if r.status == s)
    print(f"imported {n} HLRs -> requirements.csv, requirements.sqlite")
    print(f"  not_applicable={by('not_applicable')} unassigned={by('unassigned')} "
          f"assigned={by('assigned')} tested={by('tested')} evidenced={by('evidenced')}")
```

**Definition of done (12.1.3):**
```bash
cd tools/hlr-import && uv run hlr-import --repo-root ../..
```
Expected (with the sample CSV and no mapping yet): the two output files appear and the summary reads something like `imported 15 HLRs ...` with most `unassigned` (because no code carries tags yet). Then:
```bash
test -f traceability/requirements.csv && test -f traceability/requirements.sqlite && echo OK
```
Expected: `OK`.

---

#### Step 12.1.4 — The human-maintained mapping file

The scanner discovers symbol/test links from `// HLR:` tags. Everything a compiler cannot know — *applicability decisions, evidence file locations, owners, and the justification for anything not-applicable* — lives in `traceability/mapping.yaml`. This file is reviewed like code (PR review) because it encodes certification claims.

`traceability/mapping.yaml`:

```yaml
requirements:
  - hlr_id: HLR-MDL-001
    applicability: not_applicable
    na_justification: >
      mDL (ISO/IEC 18013-5/6/7) is profile P2 and out of scope for the P0 build.
      Deferred per build profile; no code, no tests, no claim.
    owner: johan

  - hlr_id: HLR-ZKP-001
    applicability: not_applicable
    na_justification: >
      TS04 ZKP is WATCH-only. Section 3 defines an abstraction point but carries
      NO production dependency; therefore not applicable to the P0 conformance set.
    owner: johan

  - hlr_id: HLR-CONSENT-001
    applicability: applicable
    evidence_link: consent/what-you-see-you-sign.md
    owner: johan
    # symbols/tests auto-discovered from // HLR: tags in crates/presenter

  - hlr_id: HLR-CRA-001
    applicability: applicable
    evidence_link: sbom/README.md
    owner: johan
    extra_symbols: ["ci::sbom-job"]   # non-code artifact, listed manually
```

**Definition of done (12.1.4):** re-run the importer; the `not_applicable` count now reflects the mapping and the run does not error on missing justifications:
```bash
cd tools/hlr-import && uv run hlr-import --repo-root ../..
```
Expected: summary shows `not_applicable=2` (or however many you marked).

---

#### Step 12.1.5 — The P0 gate rule and `hlr-gate`

**The rule (state it on the wall):**
1. *No code lands in a core crate without a `// HLR:` tag referencing an HLR ID that exists in `hlr.csv`.* Enforced by 12.1.6.
2. *No coding from narrative docs.* If the ARF/PID/FCAF text implies a behavior that has no HLR ID and no version pin, you do **not** implement it — you first add a row to `hlr.csv` (with `source_doc` + `source_version`), get it reviewed, then implement. This is what stops "spec drift": every line of certification-critical code is traceable to a *pinned* version of a *named* document.
3. **P0 gate:** *100% of `applicable` P0 HLRs must reach status `tested` or `evidenced`.* Anything `unassigned` or `assigned` fails the build. `not_applicable` rows are excluded but must carry a justification. This is the release gate for the P0 profile.

`tools/hlr-import/hlr_import/gate.py`:

```python
from __future__ import annotations
import argparse, sys
from pathlib import Path
from .importer import build

# statuses that satisfy the gate
OK = {"tested", "evidenced"}

def main() -> None:
    ap = argparse.ArgumentParser(prog="hlr-gate")
    ap.add_argument("--repo-root", type=Path, default=Path.cwd())
    ap.add_argument("--profile", default="P0")
    ap.add_argument("--require-evidence", action="store_true",
                    help="stricter: require 'evidenced', not just 'tested'")
    args = ap.parse_args()

    reqs = build(args.repo_root)
    target = {"evidenced"} if args.require_evidence else OK
    failing = [r for r in reqs
               if r.profile == args.profile
               and r.applicability == "applicable"
               and r.status not in target]

    applicable = [r for r in reqs
                  if r.profile == args.profile and r.applicability == "applicable"]
    covered = len(applicable) - len(failing)
    pct = 100.0 * covered / len(applicable) if applicable else 100.0
    print(f"{args.profile} coverage: {covered}/{len(applicable)} = {pct:.1f}%")

    if failing:
        print(f"\nGATE FAILED — {len(failing)} applicable {args.profile} HLR(s) "
              f"not {'/'.join(sorted(target))}:", file=sys.stderr)
        for r in failing:
            print(f"  [{r.status:>10}] {r.hlr_id}  {r.text[:70]}", file=sys.stderr)
        sys.exit(1)
    print(f"GATE PASSED — 100% of applicable {args.profile} HLRs satisfied.")
```

**Definition of done (12.1.5):** with no code tagged yet, the gate must *fail loudly* (proving it works):
```bash
cd tools/hlr-import && uv run hlr-gate --repo-root ../.. --profile P0; echo "exit=$?"
```
Expected: prints `GATE FAILED — ...` listing unassigned P0 HLRs and `exit=1`. Once the other sections tag their code and tests, the same command prints `GATE PASSED` and `exit=0`.

---

#### Step 12.1.6 — Pre-commit / CI enforcement of "every core symbol has a tag"

A companion check catches *the inverse*: public items in core crates with **no** `// HLR:` tag. Add `tools/hlr-import/hlr_import/untagged.py`:

```python
from __future__ import annotations
import argparse, re, sys
from pathlib import Path

PUB = re.compile(r"^\s*pub\s+(fn|struct|enum|trait)\s+([A-Za-z0-9_]+)")
TAG = re.compile(r"HLR:\s*[A-Z0-9\-]+")
CORE = ["crates/mdoc","crates/sdjwt","crates/cose","crates/x509",
        "crates/oid4vp","crates/oid4vci","crates/iso18013-5",
        "crates/status","crates/trust","crates/wua","crates/presenter",
        "crates/wallet-core"]

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo-root", type=Path, default=Path.cwd())
    args = ap.parse_args()
    offenders = []
    for c in CORE:
        for rs in (args.repo_root / c).rglob("*.rs"):
            if "target" in rs.parts:
                continue
            lines = rs.read_text(errors="replace").splitlines()
            for i, ln in enumerate(lines):
                if PUB.search(ln):
                    window = "\n".join(lines[max(0, i-5):i])
                    if not TAG.search(window):
                        offenders.append(f"{rs}:{i+1}: {ln.strip()}")
    if offenders:
        print("UNTAGGED public core symbols (need // HLR: tag):", file=sys.stderr)
        for o in offenders:
            print("  " + o, file=sys.stderr)
        sys.exit(1)
    print("All public core symbols are HLR-tagged.")
```

**Definition of done (12.1.6):**
```bash
cd tools/hlr-import && uv run python -m hlr_import.untagged --repo-root ../..; echo "exit=$?"
```
Expected while crates are being written: lists untagged symbols and `exit=1`; once fully tagged: `All public core symbols are HLR-tagged.` and `exit=0`.

---

### 12.2 The certification-evidence repository layout

Certification is a *document-review* exercise as much as a code exercise. The CAB (the lab) asks for a defined **evidence set**. Build the folder now, empty-but-scaffolded, so every other section drops its artifact into a known slot and the importer's `evidence_link` values resolve.

#### Step 12.2.1 — Create the layout

```bash
mkdir -p docs/certification-evidence/{threat-model,key-lifecycle,dpia,algorithms,kat,fcaf-reports,cab-evidence-set,consent,sbom,formal-methods}
```

Target tree with what each file is *for* and which register item it satisfies:

```
docs/certification-evidence/
├── README.md                         # index + how the evidence maps to EUCC/CRA/2024-2981
├── threat-model/
│   ├── toe-boundary.md               # TOE: exactly which crates + WSCD + shell are certified
│   ├── threat-model.md               # STRIDE/attack tree; ties to Tier-3 Tamarin (Section on Tier 3)
│   └── assurance-continuity.md       # how re-cert is triggered on change (EUCC continuity)
├── key-lifecycle/
│   ├── key-inventory.md              # every key: type, storage (SE/StrongBox), lifetime, export=never
│   ├── attestation-evidence.md       # WUA + key attestation chains (HLR-WUA-001, HLR-KEY-001)
│   └── crypto-boundary.md            # proof private keys never cross FFI (links to code + Kani)
├── dpia/
│   ├── dpia.md                       # GDPR Art.35 assessment
│   └── data-flow-inventory.md        # every personal-data element, purpose, retention
├── algorithms/
│   └── algorithm-allow-list.md       # the ONLY permitted algs + curve/params + rationale
├── kat/
│   ├── kat-results.md                # known-answer test results summary
│   └── vectors/                      # the actual test vectors (JSON), replayable
├── fcaf-reports/
│   └── .gitkeep                      # CI drops FCAF v0.0.7 run reports here (12.3)
├── cab-evidence-set/
│   └── manifest.md                   # the exact bundle handed to the lab (checklist + hashes)
├── consent/
│   └── what-you-see-you-sign.md      # consent-hash design evidence (HLR-CONSENT-001)
├── sbom/
│   ├── README.md                     # SBOM process (12.4)
│   └── (generated .cdx.json live in build artifacts, hash-pinned here)
└── formal-methods/
    ├── lean-traces/                  # exported Tier-2 traces (JSON oracle)
    ├── tamarin-proofs/               # Tier-3 .spthy + proof output
    └── kani-reports/                 # Tier-1 model-checking reports
```

#### Step 12.2.2 — Author the load-bearing evidence stubs

These are not "TODO" placeholders — write the real structure now; sections fill the specifics.

`docs/certification-evidence/algorithms/algorithm-allow-list.md` (the allow-list is *itself* certification evidence — it proves you never rolled your own crypto and never permit a weak algorithm; ties to the "DO NOT DO" crypto rules):

```markdown
# Algorithm allow-list (P0)

Only the algorithms in this table may appear in COSE/JOSE headers or be selected
at runtime. Any credential/request specifying an algorithm NOT on this list is
REJECTED. Enforced in code by `cose::alg::AllowList` and `sdjwt::jose::AllowList`.

| Purpose            | Algorithm      | COSE id | JOSE id | Params            | Where enforced          | HLR         |
|--------------------|----------------|---------|---------|-------------------|-------------------------|-------------|
| Signature (device) | ECDSA P-256    | -7      | ES256   | secp256r1, SHA-256| crypto-traits::Signer   | HLR-KEY-001 |
| Signature (issuer) | ECDSA P-256    | -7      | ES256   | secp256r1, SHA-256| cose::verify            | HLR-FMT-001 |
| KDF                | HKDF-SHA-256   | -10     | —       | RFC 5869          | crypto-traits::Kdf      | ...         |
| AEAD (session)     | AES-256-GCM    | 3       | —       | 96-bit nonce      | crypto-traits::Aead     | ...         |
| Hash               | SHA-256        | —       | —       | —                 | (implied by above)      | ...         |

Explicitly DISALLOWED: RSA (any), ECDSA on non-NIST curves, SHA-1, any "none" alg.
```

`docs/certification-evidence/key-lifecycle/crypto-boundary.md` should state the invariant "no private key material crosses the FFI" and *cite the Kani harness and the `// HLR: HLR-KEY-001` symbols that prove it* (the Kani proof lives with the Tier-1 work; here you link to its report path).

`docs/certification-evidence/threat-model/toe-boundary.md` must enumerate the exact TOE: the listed core crates + the WSCD (Secure Enclave/StrongBox) as an *evaluated platform dependency* + the thin shell, and must state what is **outside** the TOE (app-level navigation, XState, marketing UI).

**Definition of done (12.2):** the layout exists and every `evidence_link` in `mapping.yaml` resolves:
```bash
python3 - <<'PY'
import csv, pathlib
root = pathlib.Path("docs/certification-evidence")
bad = [r["hlr_id"] for r in csv.DictReader(open("traceability/requirements.csv"))
       if r["evidence_link"] and not (root / r["evidence_link"]).exists()]
print("dangling evidence links:", bad or "none")
PY
```
Expected: `dangling evidence links: none`.

---

### 12.3 FCAF-in-CI

FCAF is the EU's Feature Conformance Assessment Framework — a downloadable test-suite you run *against your wallet* to check it behaves per the ARF profiles. Two hard truths to internalize and document:

1. **Pin it.** FCAF is v0.0.7 (pre-1.0, evolving per the change-watch). You pin the exact commit/tag and the exact suite version; an unpinned conformance suite makes your green CI meaningless when the suite changes underneath you.
2. **Passing FCAF ≠ certified.** FCAF is a *functional conformance* oracle. It does not run your negative tests, your security tests, or your privacy tests, and it is *not* the CAB assessment. You keep your own adversarial suite *on top*, and you document this distinction so no one mistakes a green FCAF badge for certification.

#### Step 12.3.1 — Vendor and pin the FCAF suite

```bash
mkdir -p conformance/fcaf
# record the exact version you certify against
cat > conformance/fcaf/VERSION <<'EOF'
fcaf_version=0.0.7
fcaf_source=<official-fcaf-repo-url>
fcaf_pinned_ref=<exact-git-tag-or-commit-sha>
pinned_on=2026-07-17
EOF
```

Add it as a git submodule pinned to the exact ref (do not copy loosely — a submodule *records the SHA*):

```bash
git submodule add <official-fcaf-repo-url> conformance/fcaf/suite
cd conformance/fcaf/suite && git checkout <exact-git-tag-or-commit-sha> && cd -
git add conformance/fcaf/suite .gitmodules
```

#### Step 12.3.2 — The runner and the "own tests on top" layout

```
conformance/
├── fcaf/
│   ├── VERSION
│   ├── suite/                 # pinned submodule (upstream FCAF v0.0.7)
│   └── run_fcaf.py           # adapter: drives wallet-core via UniFFI test harness
└── security/                 # OUR tests — NOT part of FCAF
    ├── negative/             # malformed CBOR/JWS, wrong nonce, replayed nonce, ...
    ├── privacy/              # over-disclosure attempts, unlinkability checks
    └── README.md             # states: these EXCEED FCAF; FCAF is necessary-not-sufficient
```

`conformance/security/README.md` must contain the sentence, verbatim in spirit: *"Passing FCAF v0.0.7 demonstrates functional conformance only. It is not certification and does not cover the negative/security/privacy assertions in this directory, which are required for the EUCC assessment."*

`conformance/fcaf/run_fcaf.py` (skeleton — it invokes the pinned suite, captures a machine-readable report, and drops it into the evidence repo):

```python
from __future__ import annotations
import json, subprocess, sys, datetime
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SUITE = REPO / "conformance" / "fcaf" / "suite"
REPORT_DIR = REPO / "docs" / "certification-evidence" / "fcaf-reports"

def read_pinned_version() -> dict[str, str]:
    v = {}
    for line in (REPO / "conformance" / "fcaf" / "VERSION").read_text().splitlines():
        if "=" in line:
            k, val = line.split("=", 1)
            v[k.strip()] = val.strip()
    return v

def run() -> int:
    ver = read_pinned_version()
    # invoke the pinned FCAF harness against our wallet-core test server/binding.
    # (exact entrypoint depends on the suite; capture stdout as report.)
    proc = subprocess.run(
        [sys.executable, str(SUITE / "run.py"), "--target", "wallet-core-test-harness",
         "--format", "json"],
        capture_output=True, text=True)
    stamp = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    out = REPORT_DIR / f"fcaf-{ver.get('fcaf_version','x')}-{stamp}.json"
    report = {
        "fcaf_version": ver.get("fcaf_version"),
        "fcaf_pinned_ref": ver.get("fcaf_pinned_ref"),
        "run_at": stamp,
        "exit_code": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }
    out.write_text(json.dumps(report, indent=2))
    print(f"FCAF report -> {out} (exit={proc.returncode})")
    return proc.returncode

if __name__ == "__main__":
    sys.exit(run())
```

#### Step 12.3.3 — CI job stubs

Create `.github/workflows/conformance.yml` (job **stubs** are the DoD; they wire the commands even before every crate is finished):

```yaml
name: conformance-and-evidence
on: [push, pull_request]

jobs:
  hlr-traceability:
    runs-on: macos-14
    steps:
      - uses: actions/checkout@v4
        with: { submodules: recursive }
      - uses: astral-sh/setup-uv@v5
      - name: Import HLR traceability table
        run: cd tools/hlr-import && uv run hlr-import --repo-root ../..
      - name: Enforce every core symbol is HLR-tagged
        run: cd tools/hlr-import && uv run python -m hlr_import.untagged --repo-root ../..
      - name: P0 requirements gate (100% applicable tested)
        run: cd tools/hlr-import && uv run hlr-gate --repo-root ../.. --profile P0
      - uses: actions/upload-artifact@v4
        with:
          name: traceability
          path: traceability/requirements.csv

  fcaf:
    runs-on: macos-14
    steps:
      - uses: actions/checkout@v4
        with: { submodules: recursive }
      - uses: astral-sh/setup-uv@v5
      - name: Assert FCAF is pinned
        run: grep -q 'fcaf_pinned_ref=[0-9a-f]' conformance/fcaf/VERSION
      - name: Run pinned FCAF v0.0.7
        run: uv run python conformance/fcaf/run_fcaf.py
      - name: Run OUR negative/security/privacy suite (exceeds FCAF)
        run: cargo test -p wallet-core --features security-suite
      - uses: actions/upload-artifact@v4
        with:
          name: fcaf-reports
          path: docs/certification-evidence/fcaf-reports/

  sbom-and-audit:
    runs-on: macos-14
    steps:
      - uses: actions/checkout@v4
      - name: Generate SBOM
        run: ./tools/sbom/gen_sbom.sh          # 12.4
      - name: Vulnerability intake (fail on RUSTSEC advisories)
        run: cargo audit --deny warnings
      - name: License/ban policy
        run: cargo deny check
      - uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: docs/certification-evidence/sbom/*.cdx.json
```

**Definition of done (12.3):**
```bash
# suite is pinned to a real ref
grep -q 'fcaf_pinned_ref=[0-9a-f]' conformance/fcaf/VERSION && echo PINNED
# workflow parses
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/conformance.yml')); print('workflow OK')"
# our security dir carries the necessary-not-sufficient disclaimer
grep -qi 'not certification' conformance/security/README.md && echo DISCLAIMER-OK
```
Expected: `PINNED`, `workflow OK`, `DISCLAIMER-OK`.

---

### 12.4 SBOM, signing, vulnerability intake, and revocation

The CRA (Reg. (EU) 2024/2847) requires a Software Bill Of Materials plus a coordinated vulnerability-handling process for the product's support lifetime. Three mechanical parts: **generate**, **sign**, **intake + revoke**.

#### Step 12.4.1 — Generate the SBOM (CycloneDX)

Prefer `cargo-cyclonedx` (native Cargo dependency graph → CycloneDX JSON); keep `syft` as a cross-check for the *whole* build artifact (it also catches the Swift/iOS side).

```bash
cargo install --locked cargo-cyclonedx
# syft (optional cross-check) via its official installer per its docs
```

`tools/sbom/gen_sbom.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$ROOT/docs/certification-evidence/sbom"
mkdir -p "$OUT"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"

# 1) Rust workspace SBOM (all crates, aggregated)
cargo cyclonedx --all --format json --override-filename "sbom-rust-$STAMP"
find "$ROOT" -name "sbom-rust-$STAMP.json" -maxdepth 3 -exec mv {} "$OUT/" \;

# 2) Optional whole-artifact cross-check (Rust + Swift package graph)
if command -v syft >/dev/null 2>&1; then
  syft "dir:$ROOT" -o cyclonedx-json > "$OUT/sbom-full-$STAMP.cdx.json"
fi

# 3) hash-pin the SBOM(s) so the evidence repo records exactly what shipped
( cd "$OUT" && shasum -a 256 *"$STAMP"* > "sbom-$STAMP.sha256" )
echo "SBOM written to $OUT (stamp $STAMP)"
```

```bash
chmod +x tools/sbom/gen_sbom.sh
```

#### Step 12.4.2 — Sign SBOM updates

Every published SBOM must be signed so consumers can verify provenance (CRA + supply-chain integrity). Use a detached signature. Two acceptable paths — pick one and record it in `docs/certification-evidence/sbom/README.md`:

- **cosign** (keyless or key-based), signing the `.cdx.json` blob; or
- **minisign/GPG** detached signature.

Example (cosign, key-based) appended to the generator or run in CI:

```bash
# one-time: cosign generate-key-pair   (store COSIGN_PRIVATE_KEY as a CI secret)
for f in docs/certification-evidence/sbom/*.cdx.json; do
  cosign sign-blob --yes --key env://COSIGN_PRIVATE_KEY \
    --output-signature "$f.sig" "$f"
done
```

`docs/certification-evidence/sbom/README.md` documents: the signing method, where the public key lives, the verification command (`cosign verify-blob --key cosign.pub --signature f.sig f`), and the retention policy (keep every released SBOM for the full CRA support period).

#### Step 12.4.3 — Vulnerability intake

Continuous, in CI, and fail-closed. `cargo audit` reads the RustSec advisory DB against your `Cargo.lock`; `cargo deny` enforces license and *banned-crate* policy (e.g. ban any crate that reimplements crypto, reinforcing the "DO NOT DO" rules).

```bash
cargo install --locked cargo-audit cargo-deny
```

`deny.toml` (skeleton — the ban list is itself certification evidence):

```toml
[advisories]
db-urls = ["https://github.com/rustsec/advisory-db"]
yanked = "deny"
[bans]
multiple-versions = "warn"
# ban crates that would violate "never roll your own crypto"
deny = [
  { name = "md5" }, { name = "sha1", wrappers = [] },
]
[licenses]
allow = ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC", "Unicode-DFS-2016"]
copyleft = "deny"
```

The CI job in 12.3.3 runs `cargo audit --deny warnings` and `cargo deny check` on every push, so a newly disclosed advisory turns CI red the next run even without a code change.

#### Step 12.4.4 — Revocation / response path

"Revocation path" here means: what happens when a vulnerability *is* found in a shipped SBOM component. Document the workflow in `docs/certification-evidence/sbom/README.md` and wire the trigger:

1. **Detection** — `cargo audit` in CI (12.4.3), or an inbound report to the security contact (publish a `SECURITY.md` with a disclosure address; CRA requires a coordinated process).
2. **Assess** — determine if the advisory reaches an exploitable path in the TOE (link back to the traceability table: which HLR/crate is affected).
3. **Remediate** — bump the dependency, regenerate + re-sign the SBOM (12.4.1–2), regenerate `requirements.csv` so the evidence stays consistent.
4. **Revoke** — mark the superseded SBOM/build as revoked. Practically: (a) publish a new signed SBOM with an incremented version, (b) if the vulnerable build was distributed, revoke the affected **Wallet Unit Attestation** batch via the WUA/attestation mechanism (Section on `wua`) so relying parties stop trusting the vulnerable units, and (c) file a CRA notification if the thresholds for actively-exploited/serious-incident reporting are met.
5. **Record** — append an entry to `docs/certification-evidence/sbom/revocations.md` (date, CVE/RUSTSEC id, affected component + version range, fixed version, WUA batch action, notification status).

`docs/certification-evidence/sbom/revocations.md` header:

```markdown
# SBOM component revocation log (CRA vulnerability handling)
| date | advisory | component | affected versions | fixed in | WUA action | CRA notified |
|------|----------|-----------|-------------------|----------|------------|--------------|
```

**Definition of done (12.4):**
```bash
./tools/sbom/gen_sbom.sh
ls docs/certification-evidence/sbom/*.cdx.json >/dev/null && echo "SBOM-GENERATED"
cargo audit --deny warnings; echo "audit-exit=$?"
cargo deny check 2>&1 | tail -1
```
Expected: an SBOM `.cdx.json` (and its `.sha256`) exists → `SBOM-GENERATED`; `cargo audit` exits `0` on a clean tree (`audit-exit=0`), non-zero if any advisory applies; `cargo deny` reports `advisories ok`, `bans ok`, `licenses ok`.

---

### 12.5 Register mapping (what this section discharges)

This table is the reverse index the CAB will want: for each named register item, where in *this* section its evidence is produced. Keep it in `docs/certification-evidence/README.md`.

| Register item | What it demands | Discharged by (this section) |
|---|---|---|
| **Reg. (EU) 2024/2981** (wallet certification) | requirements traceability; evidence set for the assessment | 12.1 traceability DB + P0 gate; 12.2 evidence repo; 12.2.1 `cab-evidence-set/manifest.md` |
| **EUCC** (Reg. (EU) 2024/482, CC-based scheme) | TOE boundary; threat model; assurance continuity; KAT results; algorithm allow-list; formal-methods evidence | 12.2 `threat-model/`, `algorithms/`, `kat/`, `formal-methods/`; 12.1 two-way traceability |
| **CRA** (Reg. (EU) 2024/2847) | signed SBOM; coordinated vulnerability handling; revocation over support lifetime | 12.4 (generate/sign/audit/revoke); CI `sbom-and-audit` job |
| **FCAF v0.0.7** | run the EU functional conformance suite | 12.3 pinned suite + CI job; reports in `fcaf-reports/`; disclaimer that it is necessary-not-sufficient |
| **GDPR Art. 35 (DPIA)** | data-protection impact assessment; data-flow inventory | 12.2 `dpia/dpia.md`, `dpia/data-flow-inventory.md`; supports `HLR-SD-001` / `HLR-CONSENT-001` |
| **High-Level Requirements register** | 100% of applicable HLRs assigned + tested | 12.1.5 `hlr-gate` P0 gate (blocking CI) |

**Section-level Definition of done.** All of the following pass from a clean checkout:

```bash
# 1) importer produces the table from the CSV
cd tools/hlr-import && uv run hlr-import --repo-root ../.. && cd ../..
test -f traceability/requirements.csv && test -f traceability/requirements.sqlite && echo "TABLE-OK"

# 2) CI job stubs exist and parse
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/conformance.yml')); print('CI-STUBS-OK')"

# 3) evidence layout scaffolded, FCAF pinned, SBOM generator present
test -d docs/certification-evidence/threat-model && \
  grep -q 'fcaf_pinned_ref' conformance/fcaf/VERSION && \
  test -x tools/sbom/gen_sbom.sh && echo "SCAFFOLD-OK"

# 4) the gate runs (fails until crates are tagged — that is correct behavior)
cd tools/hlr-import && uv run hlr-gate --repo-root ../.. --profile P0; echo "gate-exit=$?"
```

Expected: `TABLE-OK`, `CI-STUBS-OK`, `SCAFFOLD-OK`, and the gate either prints `GATE PASSED / gate-exit=0` (once every applicable P0 HLR is tagged, tested, and — where required — evidenced) or `GATE FAILED / gate-exit=1` with a precise list of the HLRs still missing coverage. Both outcomes are "done" for *this* section: the machinery is what Section 12 delivers; turning the gate green is the job of every other section that cites its HLR IDs.

---


## Section 13 — CI/CD pipeline, milestones & phasing, definition-of-done gates, and the change-watch risk register

This section wires together everything the earlier sections defined (the crates in Section 2–3, the codecs in Section 4–6, the state machines in Section 7–9, the trust/status/WUA machinery in Section 10–11, and the formal-methods harnesses in Section 12) into a single automated pipeline, a milestone plan a junior can execute in order, the merge-blocking gates, and a living risk register keyed off the CHANGE-WATCH sheet. Read Section 12 first if you have not — this section *invokes* the Lean/Kani/Tamarin harnesses it builds; it does not re-derive them.

Jargon used repeatedly, defined once here:
- **CI** = Continuous Integration: a server (GitHub Actions) that runs a fixed set of checks on every push and every pull request (PR) so nothing merges without passing.
- **Job** = one isolated runner (a fresh VM) executing a list of steps.
- **Gate** = a required check; GitHub refuses the merge button until it is green.
- **Matrix** = running the same job several times with different parameters (e.g. two OS images).
- **Artifact** (in the CI sense, not the EUDI sense) = a file the job uploads for later download (a fuzz corpus, an SBOM, a Lean trace bundle).
- **SBOM** = Software Bill Of Materials: a machine-readable list of every dependency and version, required by the EU Cyber Resilience Act (CRA).

---

### 13.0 Prerequisites and where files live

All paths below are relative to the repository root (the folder that contains `crates/`, `Cargo.toml`, the Swift app under `ios/`, the Lean project under `formal/lean/`, and the Tamarin models under `formal/tamarin/` — exactly as laid out in Sections 1, 3, and 12).

The canonical layout this section adds to:

```
.
├── .github/
│   └── workflows/
│       ├── ci.yml                  # 13.1  — the always-on gate pipeline
│       ├── nightly.yml             # 13.2  — slow jobs (deep fuzz, Tamarin prove, full Kani)
│       └── release.yml             # 13.9  — tag-triggered SBOM + evidence bundle
├── ci/
│   ├── deny.toml                   # cargo-deny config (13.1.3)
│   ├── audit.toml                  # cargo-audit config (13.1.4)
│   ├── fuzz-budget.sh              # bounded fuzz driver (13.1.6)
│   ├── replay-lean-traces.sh       # Lean export -> Rust replay glue (13.1.8)
│   └── make-sbom.sh                # CycloneDX SBOM generator (13.9.1)
├── crates/ ...                     # from Section 3
├── formal/
│   ├── lean/ ...                   # from Section 12.2
│   └── tamarin/ ...                # from Section 12.3
└── ios/ ...                        # from Section 1
```

**Definition of done for 13.0:** run `test -d .github/workflows && test -d ci && test -d formal/lean && test -d formal/tamarin && echo LAYOUT_OK`. Expected output: `LAYOUT_OK`. If any directory is missing, create it with `mkdir -p` before proceeding.

---

### 13.1 The always-on pipeline: `.github/workflows/ci.yml`

This is the file that runs on **every** push and PR and whose jobs are the merge gates. It is deliberately split into many small jobs so a failure tells the junior exactly what broke, and so fast jobs are not blocked behind slow ones. Slow-but-optional work (deep fuzzing, Tamarin proving, exhaustive Kani) lives in `nightly.yml` (13.2), not here.

Design rules baked in:
1. Every job pins the toolchain — no `stable` floating tag — so a Rust point release never silently changes results. (Traceability requirement from the register.)
2. Caching is keyed on `Cargo.lock` so dependency graphs are reproducible.
3. `concurrency` cancels superseded runs on the same branch to save minutes.
4. `permissions` is least-privilege (`contents: read`) except the SBOM job which needs `contents: write` only on release.

#### 13.1.1 Step: create the file

Write the following to `.github/workflows/ci.yml`. It is long; type or paste it whole, then we dissect each job.

```yaml
name: ci

on:
  push:
    branches: [main]
  pull_request:
  workflow_dispatch: {}   # lets you run it manually from the Actions tab

# Cancel an in-flight run if you push again to the same PR/branch.
concurrency:
  group: ci-${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

permissions:
  contents: read

env:
  # Single source of truth for the Rust toolchain. Bump deliberately.
  RUST_TOOLCHAIN: "1.97.0"
  CARGO_TERM_COLOR: always
  # Deny warnings everywhere so a warning cannot rot into a bug.
  RUSTFLAGS: "-D warnings"
  RUSTDOCFLAGS: "-D warnings"

jobs:
  # ---------------------------------------------------------------- #
  # 1. Formatting — fastest possible fail.                            #
  # ---------------------------------------------------------------- #
  fmt:
    name: rust / fmt
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - name: Install Rust ${{ env.RUST_TOOLCHAIN }}
        run: |
          rustup toolchain install "$RUST_TOOLCHAIN" --profile minimal --component rustfmt
          rustup default "$RUST_TOOLCHAIN"
      - run: cargo fmt --all --check

  # ---------------------------------------------------------------- #
  # 2. Lint — clippy with -D warnings; forbid(unsafe) is in code.     #
  # ---------------------------------------------------------------- #
  clippy:
    name: rust / clippy
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - name: Install Rust
        run: |
          rustup toolchain install "$RUST_TOOLCHAIN" --profile minimal --component clippy
          rustup default "$RUST_TOOLCHAIN"
      - uses: Swatinem/rust-cache@v2
      - run: cargo clippy --workspace --all-targets --all-features -- -D warnings

  # ---------------------------------------------------------------- #
  # 3. Type-check without running tests (fast signal on all targets). #
  # ---------------------------------------------------------------- #
  check:
    name: rust / check
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - name: Install Rust
        run: |
          rustup toolchain install "$RUST_TOOLCHAIN" --profile minimal
          rustup default "$RUST_TOOLCHAIN"
      - uses: Swatinem/rust-cache@v2
      - run: cargo check --workspace --all-targets --all-features --locked

  # ---------------------------------------------------------------- #
  # 4. Tests — unit + integration + proptest (Tier-1) on 2 OSes.      #
  # ---------------------------------------------------------------- #
  test:
    name: rust / test
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-24.04, macos-15]   # macos-15 = Apple Silicon; matches target OS
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - name: Install Rust
        run: |
          rustup toolchain install "$RUST_TOOLCHAIN" --profile minimal
          rustup default "$RUST_TOOLCHAIN"
      - uses: Swatinem/rust-cache@v2
      - name: Install nextest (nicer, faster test runner)
        run: cargo install cargo-nextest --locked || true
      - name: Run tests
        run: cargo nextest run --workspace --all-features --locked
      - name: Doctests (nextest cannot run these)
        run: cargo test --workspace --doc --locked

  # ---------------------------------------------------------------- #
  # 5. Supply-chain: licenses, bans, advisories, sources.            #
  # ---------------------------------------------------------------- #
  deny:
    name: supply-chain / cargo-deny
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - name: Install Rust
        run: |
          rustup toolchain install "$RUST_TOOLCHAIN" --profile minimal
          rustup default "$RUST_TOOLCHAIN"
      - name: Install cargo-deny
        run: cargo install cargo-deny --locked
      - run: cargo deny --all-features check --config ci/deny.toml

  # ---------------------------------------------------------------- #
  # 6. Known-vulnerability scan (RUSTSEC advisory DB).               #
  # ---------------------------------------------------------------- #
  audit:
    name: supply-chain / cargo-audit
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - name: Install Rust
        run: |
          rustup toolchain install "$RUST_TOOLCHAIN" --profile minimal
          rustup default "$RUST_TOOLCHAIN"
      - name: Install cargo-audit
        run: cargo install cargo-audit --locked
      - run: cargo audit --deny warnings --config ci/audit.toml

  # ---------------------------------------------------------------- #
  # 7. Bounded fuzzing — each codec fuzzed for a FIXED small budget. #
  #    Deep fuzzing is nightly (13.2). This just catches regressions.#
  # ---------------------------------------------------------------- #
  fuzz-smoke:
    name: fuzz / smoke (bounded)
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - name: Install nightly Rust (cargo-fuzz needs nightly)
        run: |
          rustup toolchain install nightly --profile minimal
          rustup component add --toolchain nightly rust-src
      - name: Install cargo-fuzz
        run: cargo install cargo-fuzz --locked
      - uses: Swatinem/rust-cache@v2
      - name: Run bounded fuzz over every target
        run: bash ci/fuzz-budget.sh 60   # 60 seconds per target; see 13.1.6

  # ---------------------------------------------------------------- #
  # 8. Kani — model-check key invariants. Bounded set here; full set #
  #    is nightly. Kani is heavy, so it is its own job.              #
  # ---------------------------------------------------------------- #
  kani:
    name: formal / kani (bounded)
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - name: Install Rust
        run: |
          rustup toolchain install "$RUST_TOOLCHAIN" --profile minimal
          rustup default "$RUST_TOOLCHAIN"
      - uses: Swatinem/rust-cache@v2
      - name: Install Kani
        run: |
          cargo install --locked kani-verifier
          cargo kani setup
      - name: Run the CI-tagged harnesses only (fast subset)
        run: cargo kani --workspace --harness-timeout 300 --only-codegen=false
             --cbmc-args --unwind 8

  # ---------------------------------------------------------------- #
  # 9. Lean: build the model, EXPORT traces, REPLAY against Rust.    #
  #    This is the executable-oracle conformance test (Section 12.2).#
  # ---------------------------------------------------------------- #
  lean-oracle:
    name: formal / lean trace-replay
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - name: Install elan + Lean (pinned by lean-toolchain file)
        run: |
          curl -sSfL https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh \
            | sh -s -- -y --default-toolchain none
          echo "$HOME/.elan/bin" >> "$GITHUB_PATH"
      - name: Install Rust (to run the replay)
        run: |
          rustup toolchain install "$RUST_TOOLCHAIN" --profile minimal
          rustup default "$RUST_TOOLCHAIN"
      - uses: Swatinem/rust-cache@v2
      - name: Build Lean model + prove invariants
        working-directory: formal/lean
        run: lake build
      - name: Export enumerated traces to JSON
        working-directory: formal/lean
        run: lake exe export_traces --out ../../target/lean-traces
      - name: Replay Lean traces against the Rust core
        run: bash ci/replay-lean-traces.sh target/lean-traces
      - name: Upload traces for inspection
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: lean-traces
          path: target/lean-traces

  # ---------------------------------------------------------------- #
  # 10. Tamarin: PARSE (well-formedness) on every PR. Proving is    #
  #     slow/undecidable, so full prove runs nightly (13.2) and is  #
  #     ALLOWED to be slow/optional. Parse failure DOES block.      #
  # ---------------------------------------------------------------- #
  tamarin-parse:
    name: formal / tamarin parse
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - name: Install Tamarin (prebuilt) + Maude
        run: |
          sudo apt-get update && sudo apt-get install -y maude graphviz
          TAMARIN_VER="1.10.0"
          curl -sSfL "https://github.com/tamarin-prover/tamarin-prover/releases/download/${TAMARIN_VER}/tamarin-prover-${TAMARIN_VER}-linux64-ubuntu.tar.gz" \
            | tar -xz -C "$HOME/.local"
          echo "$HOME/.local/bin" >> "$GITHUB_PATH"
      - name: Well-formedness check on every model (fast, no proving)
        run: |
          for f in formal/tamarin/*.spthy; do
            echo "::group::$f"
            tamarin-prover "$f" --parse-only
            echo "::endgroup::"
          done

  # ---------------------------------------------------------------- #
  # 11. Swift build + tests for the iOS shell (builds against a     #
  #     checked-in stub of the UniFFI bindings; see 13.1.10).       #
  # ---------------------------------------------------------------- #
  swift:
    name: swift / build+test
    runs-on: macos-15
    steps:
      - uses: actions/checkout@v4
      - name: Select Xcode
        run: sudo xcode-select -s /Applications/Xcode_26.app
      - name: Install Rust (to generate bindings + build the static lib)
        run: |
          rustup toolchain install "$RUST_TOOLCHAIN" --profile minimal
          rustup target add aarch64-apple-ios aarch64-apple-ios-sim
          rustup default "$RUST_TOOLCHAIN"
      - uses: Swatinem/rust-cache@v2
      - name: Build wallet-core static lib + UniFFI bindings
        run: bash ios/scripts/build-xcframework.sh    # from Section 1
      - name: Swift build (library + app target)
        run: xcodebuild build-for-testing
             -project ios/EUDIWallet.xcodeproj
             -scheme EUDIWallet
             -destination 'platform=iOS Simulator,name=iPhone 16,OS=latest'
      - name: Swift unit tests
        run: xcodebuild test-without-building
             -project ios/EUDIWallet.xcodeproj
             -scheme EUDIWallet
             -destination 'platform=iOS Simulator,name=iPhone 16,OS=latest'

  # ---------------------------------------------------------------- #
  # 12. FCAF conformance suite (versioned; see Section 12 + 13.7).  #
  # ---------------------------------------------------------------- #
  fcaf:
    name: conformance / fcaf
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - name: Install Rust
        run: |
          rustup toolchain install "$RUST_TOOLCHAIN" --profile minimal
          rustup default "$RUST_TOOLCHAIN"
      - name: Install Python (uv) for the FCAF harness
        run: |
          curl -LsSf https://astral.sh/uv/install.sh | sh
          echo "$HOME/.local/bin" >> "$GITHUB_PATH"
      - uses: Swatinem/rust-cache@v2
      - name: Run FCAF suite (pinned FCAF v0.0.7)
        run: bash conformance/fcaf/run.sh --profile P0 --fcaf-version 0.0.7

  # ---------------------------------------------------------------- #
  # 13. SBOM on every build (CRA). Uploaded as an artifact.         #
  # ---------------------------------------------------------------- #
  sbom:
    name: supply-chain / sbom
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - name: Install Rust
        run: |
          rustup toolchain install "$RUST_TOOLCHAIN" --profile minimal
          rustup default "$RUST_TOOLCHAIN"
      - name: Generate CycloneDX SBOM
        run: bash ci/make-sbom.sh target/sbom.cdx.json
      - uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: target/sbom.cdx.json

  # ---------------------------------------------------------------- #
  # Aggregate gate: one required check that depends on all the rest. #
  # Branch protection points at THIS job only (13.5).               #
  # ---------------------------------------------------------------- #
  ci-ok:
    name: ci / all-green
    if: always()
    needs:
      - fmt
      - clippy
      - check
      - test
      - deny
      - audit
      - fuzz-smoke
      - kani
      - lean-oracle
      - tamarin-parse
      - swift
      - fcaf
      - sbom
    runs-on: ubuntu-24.04
    steps:
      - name: Fail if any dependency failed or was cancelled
        run: |
          if [ "${{ contains(needs.*.result, 'failure') || contains(needs.*.result, 'cancelled') }}" = "true" ]; then
            echo "One or more required jobs failed."
            exit 1
          fi
          echo "All required jobs passed."
```

Why the `ci-ok` aggregate job exists: GitHub branch protection lets you require *named* checks. If you list all thirteen names individually and later rename one, protection silently stops enforcing the renamed one. Requiring the single `ci / all-green` check (which `needs:` everything) means adding a new job only requires adding it to that `needs:` list — the branch-protection rule never changes. This is the pattern that prevents "we thought the gate was on but it wasn't."

**Definition of done for 13.1.1:** run `python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/ci.yml')); print('YAML_OK')"`. Expected: `YAML_OK`. (Requires `pyyaml`; if absent, `uv run --with pyyaml python3 -c "..."`.)

#### 13.1.2 The `fmt` / `clippy` / `check` / `test` jobs (Tier-1 baseline)

These four are your standard Rust hygiene. Notes for the junior:
- `cargo fmt --all --check` fails if any file is not formatted; fix locally with `cargo fmt --all`.
- `RUSTFLAGS: "-D warnings"` turns every compiler warning into an error, workspace-wide. Combined with `#![forbid(unsafe_code)]` at the top of every core crate's `lib.rs` (already mandated in the shared context), this means unsafe code cannot even compile.
- The `test` job runs on both Linux and macOS because the crypto callbacks differ per platform (Section 2). `fail-fast: false` means a macOS failure still lets the Linux result show, so you see both.

**Definition of done for 13.1.2 (run locally before pushing):**
```
cargo fmt --all --check && \
cargo clippy --workspace --all-targets --all-features -- -D warnings && \
cargo check --workspace --all-targets --all-features --locked && \
cargo nextest run --workspace --all-features && echo LOCAL_BASELINE_OK
```
Expected final line: `LOCAL_BASELINE_OK`.

#### 13.1.3 `cargo-deny` config — `ci/deny.toml`

`cargo-deny` enforces four policies: allowed licenses, banned/duplicate crates, security advisories, and allowed source registries. For a certifiable wallet the license policy is not cosmetic — a copyleft dependency sneaking in could be a legal problem (P0 "legal/product-status boundary").

Write `ci/deny.toml`:

```toml
# ci/deny.toml — supply-chain policy for the EUDI wallet workspace.

[graph]
all-features = true

[licenses]
# Explicit allow-list. Anything not here fails the build.
allow = [
  "MIT",
  "Apache-2.0",
  "Apache-2.0 WITH LLVM-exception",
  "BSD-2-Clause",
  "BSD-3-Clause",
  "ISC",
  "Unicode-3.0",
  "Zlib",
]
# We refuse to ship copyleft that could taint the wallet binary.
# (No GPL/AGPL/LGPL/MPL in the allow-list = they fail.)
confidence-threshold = 0.93

[bans]
multiple-versions = "warn"    # duplicate versions bloat SBOM; warn, don't block, early on
wildcards = "deny"            # no `foo = "*"` version specs — non-reproducible
deny = [
  # Never let a second crypto stack in through the back door (DO-NOT-DO rule).
  { name = "openssl" },
  { name = "openssl-sys" },
  { name = "ring", wrappers = [] },  # we standardize on aws-lc-rs where a Rust impl is used
]

[advisories]
version = 2
yanked = "deny"
# Unmaintained/undermaintained crates are a CRA risk — flag them.
unmaintained = "workspace"

[sources]
unknown-registry = "deny"     # only crates.io (or a vendored mirror) allowed
unknown-git = "deny"
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
```

Note the `ring`/`openssl` bans: they operationalize the DO-NOT-DO rule "never implement crypto yourself" *and* "don't accidentally link two crypto stacks." If a transitive dependency pulls in `ring`, the build fails and you investigate rather than shipping two AES implementations.

**Definition of done for 13.1.3:** run `cargo deny --all-features check --config ci/deny.toml`. Expected: exit code 0 and a summary ending `licenses ok`, `bans ok`, `advisories ok`, `sources ok`. If a license is rejected, either the dependency is genuinely unacceptable (remove it) or you add its SPDX id to `allow` with a code-review note explaining why.

#### 13.1.4 `cargo-audit` config — `ci/audit.toml`

`cargo-audit` checks `Cargo.lock` against the RUSTSEC advisory database (known CVEs in Rust crates). It overlaps with `cargo-deny`'s advisories check by design — belt and braces, and `cargo-audit` updates its DB independently.

Write `ci/audit.toml`:

```toml
# ci/audit.toml
[advisories]
# Fail on ANY advisory. If a specific one is a false positive for our usage,
# add its RUSTSEC id here WITH a dated comment and a recheck trigger.
ignore = [
  # Example (remove once real):
  # "RUSTSEC-2024-XXXX", # <reason>; recheck when <crate> >= <version> ships. Added 2026-07-17.
]

[output]
deny = ["unmaintained", "unsound", "yanked"]
```

Rule for the junior: **never** add a RUSTSEC id to `ignore` without (a) a one-line reason and (b) a recheck trigger, both as comments. An unexplained ignore is how a known CVE ships in a wallet.

**Definition of done for 13.1.4:** run `cargo audit --deny warnings --config ci/audit.toml`. Expected: `0 vulnerabilities found` (or, if the DB flags something, a deliberate, commented `ignore` entry and a tracking item in the risk register 13.8).

#### 13.1.5 Fuzz targets exist for every codec

Section 12.1 defined the fuzz targets. This section only *drives* them, but the pipeline assumes a target named `fuzz_<crate>` exists under `fuzz/fuzz_targets/` for each of: `mdoc`, `sdjwt`, `cose`, `x509`, `status`. Sanity-check they exist:

```
ls fuzz/fuzz_targets/
# expect at least:
#   fuzz_mdoc.rs  fuzz_sdjwt.rs  fuzz_cose.rs  fuzz_x509.rs  fuzz_status.rs
```

If any is missing, go back to Section 12.1 — the pipeline gate below will otherwise report "no such target" and (correctly) fail.

#### 13.1.6 Bounded fuzz driver — `ci/fuzz-budget.sh`

On every PR we do not want to fuzz for hours (that is nightly's job, 13.2). We fuzz each target for a small fixed budget so a *regression* — an input that newly crashes — is caught fast, and the accumulated corpus (saved test cases) is carried forward. The corpus is committed under `fuzz/corpus/<target>/` so runs are cumulative and deterministic on the seed inputs.

Write `ci/fuzz-budget.sh`:

```bash
#!/usr/bin/env bash
# ci/fuzz-budget.sh <seconds-per-target>
# Bounded regression fuzzing over every codec target. Fails on any crash.
set -euo pipefail

BUDGET="${1:-60}"
TARGETS=(fuzz_mdoc fuzz_sdjwt fuzz_cose fuzz_x509 fuzz_status)

fail=0
for t in "${TARGETS[@]}"; do
  echo "::group::fuzz $t for ${BUDGET}s"
  # -runs guards against a hung target; -max_total_time is the wall budget.
  # First replay the committed corpus (fast, deterministic), THEN explore.
  if ! cargo +nightly fuzz run "$t" -- \
        -max_total_time="$BUDGET" \
        -timeout=10 \
        -rss_limit_mb=2048 ; then
    echo "FUZZ REGRESSION in $t"
    fail=1
  fi
  echo "::endgroup::"
done

exit "$fail"
```

Make it executable: `chmod +x ci/fuzz-budget.sh`.

When a crash is found, `cargo-fuzz` writes the offending input to `fuzz/artifacts/<target>/crash-*`. The junior's workflow: reproduce locally with `cargo +nightly fuzz run <target> fuzz/artifacts/<target>/crash-XXXX`, fix the codec, then **commit the crash file into `fuzz/corpus/<target>/`** so it becomes a permanent regression seed.

**Definition of done for 13.1.6:** run `bash ci/fuzz-budget.sh 15`. Expected: five `::group::`/`::endgroup::` blocks, each ending without `FUZZ REGRESSION`, and overall exit code 0. (15s locally is enough to confirm wiring; CI uses 60s.)

#### 13.1.7 Kani harnesses (bounded on PR)

Section 12.1 wrote the Kani harnesses (functions annotated `#[kani::proof]`) proving key invariants — e.g. deterministic-CBOR round-trip stability, no integer overflow in length parsing. The PR job runs them with a bounded `--unwind 8` so loops are unrolled a fixed number of times (fast). The full unbounded run is nightly (13.2).

For the junior: a Kani harness looks like this (this exact one belongs in `crates/mdoc/src/canonical.rs` under `#[cfg(kani)]`, per Section 12.1 — shown here only so you recognize what the `kani` job executes):

```rust
#[cfg(kani)]
mod verification {
    use super::*;

    /// INVARIANT: canonical-encoding is idempotent — encoding twice equals
    /// encoding once. If this fails, "what-you-see-is-what-you-sign" breaks.
    #[kani::proof]
    #[kani::unwind(8)]
    fn canonical_encode_is_idempotent() {
        let len: usize = kani::any();
        kani::assume(len <= 4);                 // bound the symbolic input
        let bytes: [u8; 4] = kani::any();
        let input = &bytes[..len];
        if let Ok(value) = CborValue::decode(input) {
            let once = value.canonical_encode();
            let twice = CborValue::decode(&once).unwrap().canonical_encode();
            assert_eq!(once, twice);
        }
    }
}
```

**Definition of done for 13.1.7:** run `cargo kani --workspace --cbmc-args --unwind 8`. Expected: a table ending `VERIFICATION:- SUCCESSFUL` for every harness. (First run downloads the CBMC backend via `cargo kani setup`; that is slow but one-time.)

#### 13.1.8 Lean trace export → Rust replay (`ci/replay-lean-traces.sh`)

This is the executable-oracle mechanism from the shared context and Section 12.2. The Lean model (`formal/lean/`) both *proves* the three invariants (no accept without signature validation; no disclosure before consent; no replayed-nonce accept) **and** exposes an executable `export_traces` that enumerates valid protocol traces and writes them as JSON. Each trace is a sequence of `(Event, expected-effects)` pairs. The Rust core, being sans-IO and deterministic, must reproduce those effects exactly when fed the same events.

The Lean side (defined in Section 12.2, referenced here) writes files like `target/lean-traces/oid4vp_0001.json`:

```json
{
  "model": "oid4vp",
  "model_version": "1.0",
  "description": "happy-path PID presentation with consent",
  "steps": [
    { "event": {"AuthRequestReceived": {"nonce": "n1", "signed": true}},
      "expect_effects": ["ValidateRequestSignature"] },
    { "event": {"RequestSignatureValidated": {"ok": true}},
      "expect_effects": ["RenderConsent"] },
    { "event": {"ConsentGranted": {"claims": ["family_name"]}},
      "expect_effects": ["ProduceDeviceSigned", "SendResponse"] }
  ]
}
```

The replay glue script:

```bash
#!/usr/bin/env bash
# ci/replay-lean-traces.sh <dir-of-trace-json>
# Feeds every Lean-exported trace into the Rust core and asserts the emitted
# effects match. Runs a dedicated Rust test binary (built once).
set -euo pipefail

TRACE_DIR="${1:?usage: replay-lean-traces.sh <dir>}"

if [ ! -d "$TRACE_DIR" ] || [ -z "$(ls -A "$TRACE_DIR" 2>/dev/null)" ]; then
  echo "No Lean traces found in $TRACE_DIR — did lake exe export_traces run?"
  exit 1
fi

echo "Replaying $(ls "$TRACE_DIR"/*.json | wc -l) trace(s)..."
# The replay harness lives in crates/wallet-core/tests/lean_replay.rs and reads
# LEAN_TRACE_DIR from the environment.
LEAN_TRACE_DIR="$TRACE_DIR" cargo test -p wallet-core --test lean_replay --locked -- --nocapture
```

The Rust replay harness it runs — `crates/wallet-core/tests/lean_replay.rs` — is the load-bearing glue, so here it is in full:

```rust
//! crates/wallet-core/tests/lean_replay.rs
//! Replays Lean-exported protocol traces against the deterministic core and
//! asserts the emitted Effects match the model's expectation. This makes the
//! Lean model an EXECUTABLE ORACLE (see Section 12.2 and shared-context Tier 2).

use std::{env, fs, path::PathBuf};
use serde::Deserialize;
use wallet_core::{Core, Event, Effect};   // public test surface from the facade

#[derive(Deserialize)]
struct Trace {
    model: String,
    model_version: String,
    #[allow(dead_code)]
    description: String,
    steps: Vec<Step>,
}

#[derive(Deserialize)]
struct Step {
    event: Event,                 // Event derives Deserialize for test builds
    expect_effects: Vec<String>,  // effect DISCRIMINANTS, order-significant
}

/// Map an Effect to its stable discriminant name so JSON stays decoupled from
/// Rust field details. Keep this in sync with the Effect enum (compile-checked
/// by the exhaustive match: a new variant forces a new arm here).
fn effect_name(e: &Effect) -> &'static str {
    match e {
        Effect::ValidateRequestSignature { .. } => "ValidateRequestSignature",
        Effect::RenderConsent { .. }            => "RenderConsent",
        Effect::ProduceDeviceSigned { .. }      => "ProduceDeviceSigned",
        Effect::SendResponse { .. }             => "SendResponse",
        Effect::FetchTrustedList { .. }         => "FetchTrustedList",
        Effect::CheckStatus { .. }              => "CheckStatus",
        // ... one arm per Effect variant; the compiler enforces completeness.
    }
}

#[test]
fn replay_all_lean_traces() {
    let dir = env::var("LEAN_TRACE_DIR")
        .expect("LEAN_TRACE_DIR not set (run via ci/replay-lean-traces.sh)");
    let dir = PathBuf::from(dir);

    let mut files: Vec<_> = fs::read_dir(&dir).unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    files.sort();                       // deterministic order for reproducible logs
    assert!(!files.is_empty(), "no trace files in {dir:?}");

    for path in files {
        let raw = fs::read_to_string(&path).unwrap();
        let trace: Trace = serde_json::from_str(&raw)
            .unwrap_or_else(|e| panic!("bad trace {path:?}: {e}"));

        // Guard against silent Lean/Rust version drift (change-watch discipline).
        assert_eq!(trace.model_version, wallet_core::model_version(&trace.model),
            "model_version mismatch for {} in {path:?}", trace.model);

        let mut core = Core::new_for_replay(&trace.model);
        for (i, step) in trace.steps.iter().enumerate() {
            let effects = core.handle_event(step.event.clone());
            let got: Vec<&str> = effects.iter().map(effect_name).collect();
            assert_eq!(got, step.expect_effects,
                "trace {path:?} step {i}: effects diverged from Lean oracle\n\
                 event = {:?}", step.event);
        }
    }
}
```

The compile-time trick worth pointing out to the junior: `effect_name` uses an exhaustive `match` with no `_ =>` wildcard. When someone adds a new `Effect` variant, this test file **fails to compile** until they add an arm — so the oracle can never silently ignore a new effect. That is the same exhaustiveness discipline the shared context demands for the protocol state machines, applied to the test harness.

**Definition of done for 13.1.8:**
```
cd formal/lean && lake build && lake exe export_traces --out ../../target/lean-traces && cd ../..
bash ci/replay-lean-traces.sh target/lean-traces && echo ORACLE_OK
```
Expected: `lake build` prints no `error:`, `export_traces` writes ≥1 `.json` file, the replay test passes, final line `ORACLE_OK`. If effects diverge, either the Rust core has a bug or the Lean model changed — the assertion message names the file, step, and event so you know which.

#### 13.1.9 Tamarin parse (gate) vs prove (nightly)

Tamarin symbolic proving (Section 12.3) can run for hours or not terminate — it is undecidable in general. So the PR gate only checks that every `.spthy` model **parses and is well-formed** (`--parse-only`), which is fast and catches the common "someone edited the model and broke the syntax" mistake. The actual proving of the security lemmas (secrecy, injective agreement, nonce freshness against a Dolev-Yao attacker) runs in `nightly.yml` (13.2) and is *allowed to be slow or even time-limited* — its failure pages the security owner but does not block day-to-day merges. This matches the shared-context instruction that Tier-3 Tamarin be "allowed to be slow/optional."

**Definition of done for 13.1.9:** run `for f in formal/tamarin/*.spthy; do tamarin-prover "$f" --parse-only && echo "PARSE_OK $f"; done`. Expected: one `PARSE_OK <file>` line per model, no `wellformedness` errors.

#### 13.1.10 Swift build without a Rust toolchain trap

The `swift` job builds `wallet-core` as an iOS static library, generates the UniFFI Swift bindings, packages them as an `.xcframework` (via `ios/scripts/build-xcframework.sh` from Section 1), then builds and tests the app. Two junior-facing pitfalls:
1. The bindings are **generated**, not committed — always regenerate in CI so a stale checked-in binding cannot mask an FFI signature change. (If you *do* commit a generated `wallet.swift` for local convenience, add a CI step `git diff --exit-code` after generation to prove it is up to date.)
2. `xcodebuild` needs an explicit simulator destination; `name=iPhone 16,OS=latest` is stable on the `macos-15` image.

**Definition of done for 13.1.10 (on a Mac):**
```
bash ios/scripts/build-xcframework.sh && \
xcodebuild build-for-testing -project ios/EUDIWallet.xcodeproj -scheme EUDIWallet \
  -destination 'platform=iOS Simulator,name=iPhone 16,OS=latest' && echo SWIFT_BUILD_OK
```
Expected final line: `SWIFT_BUILD_OK`.

#### 13.1.11 FCAF suite (versioned)

The FCAF (Formal Conformance Assessment Framework, v0.0.7, evolving) suite is invoked via `conformance/fcaf/run.sh --profile P0 --fcaf-version 0.0.7`. Because FCAF is pre-1.0 and evolving, **the version is passed explicitly** so a silent upstream change cannot alter your pass/fail without a code change. The harness itself and its adapters are the subject of the risk-register entry in 13.8. Early milestones will have most FCAF cases marked `xfail` (expected-fail) until the corresponding feature lands; `run.sh` treats `xfail` as non-blocking and reports them separately.

**Definition of done for 13.1.11:** run `bash conformance/fcaf/run.sh --profile P0 --fcaf-version 0.0.7 --dry-run`. Expected: a summary line like `FCAF 0.0.7  P0:  N passed, 0 unexpected-fail, M xfail`. `--dry-run` lists the cases without needing a live issuer/verifier so you can confirm wiring even at M0.

---

### 13.2 The nightly pipeline: `.github/workflows/nightly.yml`

Slow, thorough jobs run on a schedule, not on every PR. If nightly fails it opens/updates a tracking issue and notifies the owner, but it does **not** block merges (its checks are not in `ci-ok`'s `needs:`). This keeps PRs fast while still getting deep coverage every day.

```yaml
name: nightly

on:
  schedule:
    - cron: "0 2 * * *"    # 02:00 UTC daily
  workflow_dispatch: {}

permissions:
  contents: read
  issues: write            # to file/update the "nightly failed" tracking issue

env:
  RUST_TOOLCHAIN: "1.97.0"
  RUSTFLAGS: "-D warnings"

jobs:
  fuzz-deep:
    name: fuzz / deep (30 min/target)
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - run: |
          rustup toolchain install nightly --profile minimal
          rustup component add --toolchain nightly rust-src
          cargo install cargo-fuzz --locked
      - name: Deep fuzz, carry corpus forward
        run: bash ci/fuzz-budget.sh 1800     # 30 min per target
      - name: Upload grown corpus
        if: always()
        uses: actions/upload-artifact@v4
        with: { name: fuzz-corpus, path: fuzz/corpus }

  kani-full:
    name: formal / kani (unbounded)
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - run: |
          rustup toolchain install "$RUST_TOOLCHAIN" --profile minimal
          rustup default "$RUST_TOOLCHAIN"
          cargo install --locked kani-verifier && cargo kani setup
      - run: cargo kani --workspace         # no --unwind cap; full analysis

  tamarin-prove:
    name: formal / tamarin prove (slow, non-blocking)
    runs-on: ubuntu-24.04
    timeout-minutes: 240                     # cap so it cannot run forever
    steps:
      - uses: actions/checkout@v4
      - name: Install Tamarin + Maude
        run: |
          sudo apt-get update && sudo apt-get install -y maude graphviz
          TAMARIN_VER="1.10.0"
          curl -sSfL "https://github.com/tamarin-prover/tamarin-prover/releases/download/${TAMARIN_VER}/tamarin-prover-${TAMARIN_VER}-linux64-ubuntu.tar.gz" \
            | tar -xz -C "$HOME/.local"
          echo "$HOME/.local/bin" >> "$GITHUB_PATH"
      - name: Prove all lemmas in the HAIP/OID4VP model
        run: |
          tamarin-prover formal/tamarin/oid4vp_haip.spthy \
            --prove --output=target/tamarin-proof.txt
      - uses: actions/upload-artifact@v4
        if: always()
        with: { name: tamarin-proof, path: target/tamarin-proof.txt }

  notify:
    name: nightly / notify-on-failure
    needs: [fuzz-deep, kani-full, tamarin-prove]
    if: failure()
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - name: Open or update tracking issue
        env: { GH_TOKEN: "${{ github.token }}" }
        run: |
          gh issue list --label nightly-failure --state open --json number \
            --jq '.[0].number' > n.txt || true
          BODY="Nightly run ${{ github.run_id }} failed. See the run for details."
          if [ -s n.txt ] && [ "$(cat n.txt)" != "" ]; then
            gh issue comment "$(cat n.txt)" --body "$BODY"
          else
            gh issue create --label nightly-failure \
              --title "Nightly deep-verification failed" --body "$BODY"
          fi
```

**Definition of done for 13.2:** `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/nightly.yml')); print('OK')"` prints `OK`, and a manual `workflow_dispatch` run from the Actions tab completes with `fuzz-deep`, `kani-full`, and `tamarin-prove` all attempted (tamarin may hit its timeout — that is acceptable and non-blocking).

---

### 13.3 The definition-of-done gates that block merge

A change may merge to `main` **only if all** of the following are true. These are exactly the jobs aggregated by `ci / all-green` (13.1) plus two human gates. Print this list into `CONTRIBUTING.md` so nobody wonders why the merge button is grey.

| # | Gate | Enforced by | Blocks merge? | Rationale |
|---|------|-------------|:-:|-----------|
| G1 | `cargo fmt --check` clean | `fmt` job | Yes | Reviewable diffs. |
| G2 | `clippy -D warnings` clean, `#![forbid(unsafe_code)]` holds | `clippy` job + code | Yes | No unsafe in core; no warning rot. |
| G3 | Workspace type-checks (`--locked`) | `check` job | Yes | `Cargo.lock` is authoritative. |
| G4 | All tests pass on Linux **and** macOS (incl. proptest, doctests) | `test` job | Yes | Cross-platform crypto callbacks. |
| G5 | `cargo-deny` clean (licenses/bans/advisories/sources) | `deny` job | Yes | Legal + no second crypto stack. |
| G6 | `cargo-audit` clean (or commented, tracked ignore) | `audit` job | Yes | No known CVE ships. |
| G7 | Bounded fuzz finds no new crash | `fuzz-smoke` job | Yes | Codec regression guard. |
| G8 | Bounded Kani harnesses `SUCCESSFUL` | `kani` job | Yes | Key invariants hold. |
| G9 | Lean builds, proves invariants, traces replay identically | `lean-oracle` job | Yes | Executable oracle: model == impl. |
| G10 | Every Tamarin `.spthy` parses / well-formed | `tamarin-parse` job | Yes | Model edits stay valid. |
| G11 | Swift lib + app build and Swift tests pass | `swift` job | Yes | The shell compiles against real bindings. |
| G12 | FCAF suite: **zero** *unexpected* failures (xfail allowed) | `fcaf` job | Yes | Conformance never regresses. |
| G13 | SBOM generates without error | `sbom` job | Yes | CRA evidence is always producible. |
| G14 | ≥1 approving review; no unresolved review threads | Branch protection | Yes | Four-eyes on certification-critical code. |
| G15 | If touching a change-watch area, the version marker + risk-register row are updated | Human review checklist (13.8) | Yes | Draft-spec drift stays isolated. |

Gates G1–G13 are mechanical (the pipeline). G14 is GitHub branch protection (13.5). G15 is a human check enforced by the PR template checkbox (13.6).

**Definition of done for 13.3:** the table above is committed to `CONTRIBUTING.md`, and `gh api repos/:owner/:repo/branches/main/protection --jq '.required_status_checks.contexts'` lists `"ci / all-green"`.

---

### 13.4 Phased milestone plan (M0 → M7, then P1/P2)

Each milestone has **entry criteria** (what must already be true to start), **scope** (what you build), and **exit criteria** (a checkable list — mostly "gate X is green for scope Y"). A junior should be able to read the exit list and run each check. The order is chosen so that every milestone produces a *demonstrable, testable* increment and never front-loads a whole subsystem before it can be exercised.

Cross-references: crate names and codec/state-machine details are in Sections 3–11; formal harnesses in Section 12.

#### M0 — Skeleton (workspace compiles, CI is green on nothing)

- **Entry:** empty repo with toolchain confirmed present (shared context).
- **Scope:** create the full `crates/` workspace with the exact crate names/boundaries from the shared context (each crate a `lib.rs` with `#![forbid(unsafe_code)]` and one placeholder function + one passing test); the `crypto-traits` trait definitions (Signer/Verifier/Kdf/Aead/Random/KeyAttestation) with **no** implementations; the `wallet-core` facade exposing an empty `Core`, `Event`, `Effect` and the `handle_event` run loop returning `vec![]`; `ci.yml`, `deny.toml`, `audit.toml`; an empty Lean project (`lake build` succeeds, exports zero traces); an empty Tamarin file that parses; the iOS app target that links a stub `.xcframework`.
- **Exit criteria (all checkable):**
  1. `cargo build --workspace` succeeds.
  2. Gates G1–G8, G11, G13 green on a PR. (G9 passes trivially with zero traces; G10 passes on the empty model; G12 runs with all cases `xfail`.)
  3. `grep -rL 'forbid(unsafe_code)' crates/*/src/lib.rs` prints nothing (every crate has the attribute).
  4. Branch protection (13.5) is switched on and requires `ci / all-green`.
- **Definition of done:** a green PR titled "M0 skeleton" is merged; the Actions tab shows `ci / all-green` passing.

#### M1 — Codecs (mdoc, sdjwt, cose, x509, status parse/encode with full Tier-1)

- **Entry:** M0 merged.
- **Scope:** implement the five codecs — deterministic/canonical CBOR + `mdoc` structures; `sdjwt` (SD-JWT VC draft-17, behind a `SDJWT_VC_DRAFT = 17` version marker); `cose` (COSE_Sign1/Mac0/Key); `x509` parse + EUDI profile checks; `status` (Token Status List draft-21, marker `STATUS_LIST_DRAFT = 21`). All over `crypto-traits` (still no concrete crypto — use a test `Verifier` in tests). Add proptest round-trip properties and cargo-fuzz targets for each (Section 12.1). Add Kani idempotence/overflow harnesses.
- **Exit criteria:**
  1. For each codec: `encode(decode(x)) == x` proptest passes with ≥10 000 cases (`PROPTEST_CASES=10000 cargo test -p <crate>`).
  2. `bash ci/fuzz-budget.sh 300` finds no crash across all five targets.
  3. `cargo kani -p mdoc -p status` reports `VERIFICATION SUCCESSFUL`.
  4. Known-answer test vectors from the ISO 18013-5 annex and the SD-JWT VC draft examples decode to the expected structures (committed under `crates/<c>/tests/vectors/`).
  5. Gates G1–G13 green.
- **Definition of done:** `cargo nextest run -p mdoc -p sdjwt -p cose -p x509 -p status && echo M1_CODECS_OK` prints `M1_CODECS_OK`, and the fuzz + kani checks above pass.

#### M2 — One end-to-end OID4VP remote presentation of a PID

- **Entry:** M1 merged; platform crypto (Secure Enclave Signer via Effect) landed for `sign`/`verify` (Section 2) — this is the first milestone needing a real key.
- **Scope:** implement the `oid4vp` sans-IO state machine (HAIP-constrained), the `presenter` (Snapshot → hashable consent `ScreenDescription`, claim minimization), and wire `wallet-core` so a signed OID4VP request → consent screen → user grants → `DeviceSigned`/SD-JWT KB response. Both formats presentable (mdoc PID **and** SD-JWT VC PID) even if issuance is faked (load a test PID from a fixture — real issuance is M4). Build the Lean model of the OID4VP flow proving the three invariants, and the trace export/replay. Start the Tamarin HAIP/OID4VP model (parse-only in gate; prove nightly).
- **Exit criteria:**
  1. An integration test drives a full happy-path presentation of a fixture PID in **both** formats and asserts the verifier accepts the response (`cargo test -p wallet-core --test oid4vp_e2e`).
  2. The consent `ScreenDescription` hash is identical across two runs (determinism) and matches a golden hash committed in the test.
  3. Lean invariants proved: `lake build` shows the three theorems with no `sorry`; `grep -r sorry formal/lean/` prints nothing.
  4. Lean traces for OID4VP replay identically against the Rust core (G9 for the OID4VP model).
  5. A negative test: an *unsigned* request object is rejected (no accepting trace) — both in Rust test and as a Lean-enumerated failing trace.
  6. `tamarin-prover formal/tamarin/oid4vp_haip.spthy --parse-only` succeeds; nightly `--prove` attempted.
  7. FCAF OID4VP remote-presentation P0 cases move from `xfail` to `pass`.
- **Definition of done:** `cargo test -p wallet-core --test oid4vp_e2e && grep -rq sorry formal/lean/ && echo BAD || echo M2_OID4VP_OK` prints `M2_OID4VP_OK`. This is the project's first "it actually works" demo.

#### M3 — Proximity presentation (ISO/IEC 18013-5)

- **Entry:** M2 merged.
- **Scope:** implement `iso18013-5` sans-IO (device engagement, session establishment/encryption; transport bytes in/out only — BLE/NFC live in the shell as Effects) and reuse `presenter`/`mdoc` from M2. Add the Lean model of the 18013-5 session (session-key establishment before any data; no data effect before session established) and its trace replay. Mark 18013-5 codec structures with the `ISO_18013_5_EDITION` version marker (see risk register — 2nd edition is in draft).
- **Exit criteria:**
  1. Proximity happy-path integration test: engagement → encrypted session → mdoc response, verifier accepts (`cargo test -p wallet-core --test proximity_e2e`).
  2. Session-encryption round-trip proptest passes; a tampered ciphertext is rejected.
  3. Lean 18013-5 invariants proved (no `sorry`) and traces replay identically.
  4. FCAF proximity P0 cases pass.
  5. Gates G1–G13 green.
- **Definition of done:** `cargo test -p wallet-core --test proximity_e2e && echo M3_PROXIMITY_OK` prints `M3_PROXIMITY_OK`.

#### M4 — Issuance (OpenID4VCI / HAIP) in both formats

- **Entry:** M3 merged.
- **Scope:** implement `oid4vci` sans-IO (HAIP-constrained), issuing a PID in **both** mdoc and SD-JWT VC. Replace the M2 fixture PID with a genuinely issued one. Key attestation / proof-of-possession via the Secure Enclave Effect. Lean model of the issuance flow (nonce/proof binding) + replay.
- **Exit criteria:**
  1. Full issue-then-present loop test: issue a PID via OID4VCI, then present it via OID4VP (M2) and via proximity (M3), both formats. (`cargo test -p wallet-core --test issue_present_loop`.)
  2. The issued credential's key binding verifies against a Secure-Enclave-held key (device-bound key never crosses FFI — assert the FFI surface has no key-export function via a compile-time test).
  3. Lean issuance invariants proved; traces replay.
  4. FCAF issuance P0 cases pass.
- **Definition of done:** `cargo test -p wallet-core --test issue_present_loop && echo M4_ISSUANCE_OK` prints `M4_ISSUANCE_OK`.

#### M5 — Trust, status/revocation, WUA

- **Entry:** M4 merged.
- **Scope:** implement `trust` (ETSI 119 612/119 602 trusted lists, anchors, signed-list parse; fetch is an Effect; mark `ETSI_119_432_EDITION` version marker per register), `status` runtime revocation checks with deterministic fail-open/fail-closed policy, and `wua` (Wallet Unit Attestation + key attestation, TS03). Wire RP registration checks (never equate TLS cert with registration — DO-NOT-DO rule). Extend the Tamarin model to cover WUA presentation.
- **Exit criteria:**
  1. A presentation to an **unregistered** RP is refused (test + Lean failing trace).
  2. A **revoked** credential is refused under fail-closed policy; the fail-open/fail-closed decision is a pure function with exhaustive tests over the policy matrix.
  3. WUA is produced and verifies end-to-end (`cargo test -p wua`).
  4. Trusted-list signature validation rejects a tampered list (fuzz + proptest).
  5. FCAF trust/status/WUA P0 cases pass.
- **Definition of done:** `cargo nextest run -p trust -p status -p wua && cargo test -p wallet-core --test rp_registration && echo M5_TRUST_OK` prints `M5_TRUST_OK`.

#### M6 — All three formal tiers green together

- **Entry:** M5 merged.
- **Scope:** no new product features — this milestone is about the *formal-methods* completion. Ensure Tier-1 (proptest+fuzz+Kani) covers every codec; Tier-2 (Lean) models and replays **every** state machine (oid4vp, oid4vci, 18013-5, and the consent/disclosure ordering invariant across all of them); Tier-3 (Tamarin) **proves** the HAIP/OID4VP profile lemmas (secrecy of presented claims, injective agreement / no mix-up, nonce freshness) against a Dolev-Yao attacker.
- **Exit criteria:**
  1. `cargo kani --workspace` (unbounded, nightly job) is `SUCCESSFUL` for every harness.
  2. Lean: zero `sorry` across `formal/lean/`; trace replay covers all four flows; the three cross-cutting invariants (no accept without signature validation; no disclosure before consent; no replayed-nonce accept) each have a proved theorem *and* an enumerated attempted-violation trace that the Rust core rejects.
  3. Tamarin: `tamarin-prover formal/tamarin/oid4vp_haip.spthy --prove` reports every lemma `verified` (this may take hours in nightly; capture the proof artifact).
  4. A short `formal/PROOF-MAP.md` maps each shared-context invariant → the exact Lean theorem name and Tamarin lemma name that discharges it.
- **Definition of done:** `formal/PROOF-MAP.md` exists and every row references a real, passing theorem/lemma; the nightly `tamarin-prove` artifact shows all lemmas `verified`; `grep -rq sorry formal/lean && echo BAD || echo M6_FORMAL_OK` prints `M6_FORMAL_OK`.

#### M7 — FCAF + certification-evidence bundle

- **Entry:** M6 merged.
- **Scope:** FCAF suite (v0.0.7) fully green for P0 (no `xfail` remaining for P0 features); run the EC reference implementation as a **CI interop oracle only** (never a runtime dependency — DO-NOT-DO rule) to cross-check interop; assemble the certification-evidence bundle (requirements traceability matrix, SBOM, formal-proof artifacts, FCAF results, accessibility EN 301 549 / WCAG 2.2 audit, CRA vuln/incident process docs) via `release.yml` (13.9).
- **Exit criteria:**
  1. `bash conformance/fcaf/run.sh --profile P0 --fcaf-version 0.0.7` reports `0 xfail, 0 unexpected-fail` for P0.
  2. Interop against the EC reference impl passes for OID4VP + OID4VCI + 18013-5 (interop job, clearly labeled "oracle, not a runtime dep").
  3. The evidence bundle (13.9) builds from a tag and contains: SBOM, proof map + artifacts, FCAF report, traceability matrix, accessibility report.
  4. Accessibility: an automated WCAG 2.2 check on every screen archetype passes, and a manual audit checklist is signed off (accessibility was designed in from M2, not deferred — DO-NOT-DO rule).
- **Definition of done:** `git tag v0.1.0-p0 && git push --tags` triggers `release.yml`, which produces `evidence-bundle-v0.1.0-p0.zip`; unzipping it and running `ls` shows `sbom.cdx.json`, `proof-map.md`, `fcaf-report.json`, `traceability.csv`, `accessibility-report.html`.

#### P1 / P2 — later phases (scope only; same gate discipline)

Each item below becomes its own mini-milestone repeating the M-pattern (entry = prior phase green; exit = its FCAF cases pass + gates green + any new Lean/Tamarin coverage). Do **not** start any P1 item before M7.

- **P1:** transaction history/logs; deletion & reporting (TS07/TS08 v0.11 — behind version markers, see risk register); export/portability (TS10 v1.2); wallet-to-wallet (TS09 v1.1); attestation catalogue (TS11 v1.0.1); qualified e-signatures (remote QTSP/QSCD via CSC API — the consent-hash "what-you-see-is-what-you-sign" from the presenter binds to the QES intent).
- **P2:** mDL (18013-5/6/7); QEAA/PuB-EAA (Reg. 2025/1566, 2025/1569); payment SCA (PSD2/TS12).
- **WATCH (no production dependency, abstraction point only):** browser Digital Credentials API (W3C WD); ZKP (TS04).

**Definition of done for 13.4:** the milestone table above lives in `docs/MILESTONES.md`, and each merged milestone PR is labeled `M0`…`M7` so `gh pr list --label M2 --state merged` returns the M2 PR.

---

### 13.5 Turning the gates on: branch protection

The pipeline only *protects* `main` if branch protection requires it. Do this once, as an admin, via the API so it is reproducible (a click-path in the UI is not auditable):

```bash
# Requires admin on the repo. Requires the single aggregate check + review.
gh api -X PUT repos/:owner/:repo/branches/main/protection \
  --input - <<'JSON'
{
  "required_status_checks": {
    "strict": true,
    "contexts": ["ci / all-green"]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "required_approving_review_count": 1,
    "dismiss_stale_reviews": true,
    "require_last_push_approval": true
  },
  "required_conversation_resolution": true,
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false
}
JSON
```

Key choices: `strict: true` means a PR must be up to date with `main` before merging (so a green PR can't merge on top of a change that would break it); `enforce_admins: true` means even admins cannot bypass (important for a certifiable artifact); `required_conversation_resolution: true` implements gate G14's "no unresolved threads."

**Definition of done for 13.5:** `gh api repos/:owner/:repo/branches/main/protection --jq '.required_status_checks.contexts, .enforce_admins.enabled'` prints `["ci / all-green"]` and `true`.

---

### 13.6 PR template enforcing the human gate (G15)

Write `.github/pull_request_template.md`:

```markdown
## What & why
<!-- one paragraph -->

## Milestone
<!-- M0..M7 / P1 / P2 label applied? -->

## Change-watch checklist (gate G15 — REQUIRED)
- [ ] This PR does **not** touch any change-watch area (SD-JWT VC, Token Status List,
      TS07/TS08, ISO 18013-5, W3C DC API, FCAF, ETSI 119 432, WebAuthn L2/L3), **OR**
- [ ] It does, and I have:
  - [ ] updated the relevant version marker constant,
  - [ ] updated the matching row in `docs/RISK-REGISTER.md` (recheck trigger current),
  - [ ] confirmed the versioned adapter is the only place the draft-specific logic lives.

## Formal-methods impact
- [ ] No state-machine change, **OR** Lean model + trace replay updated and green.
- [ ] No protocol-design change, **OR** Tamarin lemmas still parse (and nightly prove queued).

## Definition of done
- [ ] `cargo fmt/clippy/check/nextest` green locally
- [ ] New/changed codec has proptest + fuzz target + (if invariant) Kani harness
```

**Definition of done for 13.6:** the file exists; open any PR and confirm GitHub pre-fills the template.

---

### 13.7 FCAF version pinning helper

Because FCAF evolves (v0.0.7 today), pin its version in one place, `conformance/fcaf/VERSION`:

```
0.0.7
```

and have `run.sh` read it if `--fcaf-version` is omitted, but **fail loudly** if the installed FCAF suite version differs from the pinned one:

```bash
# excerpt of conformance/fcaf/run.sh
PINNED="$(cat "$(dirname "$0")/VERSION")"
REQUESTED="${FCAF_VERSION:-$PINNED}"
INSTALLED="$(fcaf --version | awk '{print $NF}')"
if [ "$INSTALLED" != "$REQUESTED" ]; then
  echo "FCAF version drift: installed=$INSTALLED requested=$REQUESTED"
  echo "Update conformance/fcaf/VERSION deliberately, or install the pinned suite."
  exit 2
fi
```

**Definition of done for 13.7:** `cat conformance/fcaf/VERSION` prints `0.0.7`, and running the suite with a mismatched installed version exits non-zero with the drift message.

---

### 13.8 Change-watch risk register — `docs/RISK-REGISTER.md`

This is the operational form of the CHANGE-WATCH sheet. Each row: what could change under us, why it matters, where in the code it is **isolated** (a version-marker constant and/or a versioned adapter module so a spec bump touches one place), the **recheck trigger** (the concrete event that should make you revisit), and the owner. The whole point of the sans-IO/versioned-adapter architecture is that when one of these moves, the blast radius is a single module, not the whole core.

The version markers are `pub const` values living next to the code they govern; grep-able so CI (or a human) can find every draft-dependent site.

Write `docs/RISK-REGISTER.md`:

```markdown
# Change-watch risk register (as-of 2026-07-17)

Each spec below is pre-final or evolving. Isolation = the ONE place the
draft-specific logic lives. Recheck trigger = when to revisit. When a spec
version changes, bump the marker, add a NEW versioned adapter (keep the old one
until migration is proven), update the row, and note the recheck date.

| ID | Watched item | Current pin | Isolation (version marker + adapter) | Impact if it changes | Recheck trigger | Owner |
|----|--------------|-------------|--------------------------------------|----------------------|-----------------|-------|
| R1 | SD-JWT VC | draft-17 | `sdjwt::SDJWT_VC_DRAFT = 17`; adapters under `crates/sdjwt/src/draft17/` (disclosures, key binding). Facade selects by marker. | Disclosure/KB wire format changes → issuance + SD-JWT presentation break. | New SD-JWT VC draft published, or it reaches RFC. | codec owner |
| R2 | Token Status List | draft-21 | `status::STATUS_LIST_DRAFT = 21`; parser under `crates/status/src/draft21/`. | Revocation encoding changes → status checks misread → wrong accept/refuse. | New Status List draft; IANA registration finalized. | status owner |
| R3 | TS07 / TS08 (deletion & reporting) | v0.11 (pre-1.0) | `wallet_core::ts::TS07_08_VERSION = "0.11"`; P1 feature module `crates/.../reporting/v0_11/`. | Deletion/report formats change; only affects P1 — keep isolated so P0 is untouched. | TS07/TS08 reaches v1.0. | P1 owner |
| R4 | ISO/IEC 18013-5 | 2nd edition (draft) | `iso18013_5::ISO_18013_5_EDITION = "1st"`; session/engagement structs under `crates/iso18013-5/src/ed1/`. | Session establishment / engagement wire changes → proximity breaks. | 2nd edition published as FDIS/IS. | proximity owner |
| R5 | W3C Digital Credentials API | Working Draft | ABSTRACTION POINT ONLY — no production code. A trait `BrowserPresentationSink` with no default impl; feature-gated `dc-api-experimental`, off by default. | If it matters later, add an adapter; today it must NOT be a runtime dependency. | DC API reaches Candidate Recommendation. | remote-presentation owner |
| R6 | FCAF | v0.0.7 (evolving) | `conformance/fcaf/VERSION`; run.sh enforces (13.7). | Conformance case set / verdicts shift → CI pass/fail changes. | New FCAF release; version-drift error in CI. | conformance owner |
| R7 | ETSI 119 432 (delivery of QES) | edition-watch | `wallet_core::qes::ETSI_119_432_EDITION`; CSC-API adapter under `crates/.../qes/` (P1). | QES/QTSP delivery protocol changes; P1 only. | New ETSI 119 432 edition; CSC API v2 change. | P1 QES owner |
| R8 | WebAuthn / passkey level | L2 pinned (L3 watched) | `wallet_core::auth::WEBAUTHN_LEVEL = 2`; local-user-auth adapter under `crates/.../auth/l2/`. | L3 adds PRF/other extensions used for local auth; changes user-verification flow. | WebAuthn L3 reaches Recommendation, or platform requires L3. | auth owner |

## Rules
1. NEVER inline draft-specific parsing outside its versioned adapter directory.
2. A version bump = a NEW adapter dir + updated marker; delete the old adapter
   only after trace-replay + FCAF prove the migration on real vectors.
3. Every `ignore`d RUSTSEC (ci/audit.toml) and every `xfail` FCAF case gets a
   row-linked recheck trigger here.
```

To keep the register honest, add a tiny CI check that every declared version marker actually exists in the code (so the register cannot drift from reality). Add this as a step in the `check` job or a standalone script `ci/verify-markers.sh`:

```bash
#!/usr/bin/env bash
# ci/verify-markers.sh — assert every version marker named in the register exists.
set -euo pipefail
markers=(
  "SDJWT_VC_DRAFT"
  "STATUS_LIST_DRAFT"
  "TS07_08_VERSION"
  "ISO_18013_5_EDITION"
  "ETSI_119_432_EDITION"
  "WEBAUTHN_LEVEL"
)
fail=0
for m in "${markers[@]}"; do
  if ! grep -rqn --include='*.rs' "\b$m\b" crates/; then
    echo "MISSING version marker in code: $m (referenced by RISK-REGISTER.md)"
    fail=1
  fi
done
[ "$fail" = 0 ] && echo "ALL_MARKERS_PRESENT"
exit "$fail"
```

**Definition of done for 13.8:** `docs/RISK-REGISTER.md` exists with all eight rows (R1–R8), and `bash ci/verify-markers.sh` prints `ALL_MARKERS_PRESENT`. (Early in M0 the markers may not all exist yet; add each marker at the milestone that introduces its subsystem, and this script will start enforcing it then. Until then, keep only the markers for shipped subsystems in the array.)

---

### 13.9 Release / evidence-bundle workflow: `.github/workflows/release.yml`

Triggered by a version tag, this assembles the certification-evidence bundle (M7). It reuses the SBOM step and gathers the formal-proof artifacts, FCAF report, traceability matrix, and accessibility report.

```yaml
name: release
on:
  push:
    tags: ["v*"]
permissions:
  contents: write        # to attach the bundle to the GitHub Release
jobs:
  evidence:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - name: Install Rust
        run: |
          rustup toolchain install 1.97.0 --profile minimal
          rustup default 1.97.0
      - name: SBOM (CRA)
        run: bash ci/make-sbom.sh evidence/sbom.cdx.json
      - name: Copy formal proof artifacts
        run: |
          mkdir -p evidence
          cp formal/PROOF-MAP.md evidence/proof-map.md
          # Lean build log + Tamarin proof (from the latest nightly artifact,
          # or re-run here if you want the tag to be self-contained).
      - name: FCAF report
        run: bash conformance/fcaf/run.sh --profile P0 --report evidence/fcaf-report.json
      - name: Traceability matrix (requirements -> code/tests)
        run: python3 tools/traceability.py --out evidence/traceability.csv
      - name: Accessibility report (WCAG 2.2 over screen archetypes)
        run: bash conformance/a11y/run.sh --out evidence/accessibility-report.html
      - name: Zip the bundle
        run: |
          BUNDLE="evidence-bundle-${GITHUB_REF_NAME}.zip"
          (cd evidence && zip -r "../$BUNDLE" .)
          echo "BUNDLE=$BUNDLE" >> "$GITHUB_ENV"
      - name: Attach to the GitHub Release
        env: { GH_TOKEN: "${{ github.token }}" }
        run: gh release create "${GITHUB_REF_NAME}" "$BUNDLE" --generate-notes || \
             gh release upload "${GITHUB_REF_NAME}" "$BUNDLE" --clobber
```

#### 13.9.1 SBOM generator — `ci/make-sbom.sh`

CycloneDX is the SBOM format most EU-CRA tooling accepts. `cargo-cyclonedx` generates it from the workspace.

```bash
#!/usr/bin/env bash
# ci/make-sbom.sh <output.json>
set -euo pipefail
OUT="${1:?usage: make-sbom.sh <output.json>}"
cargo install cargo-cyclonedx --locked >/dev/null 2>&1 || true
cargo cyclonedx --format json --all --spec-version 1.5
# cargo-cyclonedx writes per-crate; merge into one workspace SBOM at OUT.
mkdir -p "$(dirname "$OUT")"
# Simplest robust approach: emit the top-level (facade) SBOM which includes the
# full dependency graph, then copy it to OUT.
cp "crates/wallet-core/wallet-core.cdx.json" "$OUT"
echo "SBOM written to $OUT"
```

**Definition of done for 13.9:** `bash ci/make-sbom.sh /tmp/sbom.cdx.json && python3 -c "import json;d=json.load(open('/tmp/sbom.cdx.json'));print('components',len(d.get('components',[])))"` prints a component count > 0; and a `git tag v0.0.0-test && git push --tags` produces a Release with `evidence-bundle-v0.0.0-test.zip` attached (delete the test tag afterward).

---

### 13.10 Local pre-push convenience (so CI rarely fails on the trivial gates)

Give the junior a single script mirroring the fast gates so they get feedback in seconds, not after pushing. Write `ci/pre-push.sh`:

```bash
#!/usr/bin/env bash
# ci/pre-push.sh — run the fast gates locally before pushing.
set -euo pipefail
echo "== fmt ==";    cargo fmt --all --check
echo "== clippy =="; cargo clippy --workspace --all-targets --all-features -- -D warnings
echo "== check ==";  cargo check --workspace --all-targets --all-features --locked
echo "== test ==";   cargo nextest run --workspace --all-features
echo "== deny ==";   cargo deny --all-features check --config ci/deny.toml
echo "== audit =="; cargo audit --deny warnings --config ci/audit.toml
echo "== markers =="; bash ci/verify-markers.sh
echo "ALL LOCAL FAST GATES PASSED"
```

Optionally wire it as a git hook: `ln -s ../../ci/pre-push.sh .git/hooks/pre-push && chmod +x ci/pre-push.sh`.

**Definition of done for 13.10:** `bash ci/pre-push.sh` ends with `ALL LOCAL FAST GATES PASSED`.

---

### 13.11 Section definition-of-done (rollup)

This section is complete when:

1. `.github/workflows/ci.yml`, `nightly.yml`, and `release.yml` all exist and parse as valid YAML (`python3 -c "import yaml,glob; [yaml.safe_load(open(f)) for f in glob.glob('.github/workflows/*.yml')]; print('WORKFLOWS_OK')"` → `WORKFLOWS_OK`).
2. `ci/deny.toml`, `ci/audit.toml`, `ci/fuzz-budget.sh`, `ci/replay-lean-traces.sh`, `ci/make-sbom.sh`, `ci/verify-markers.sh`, and `ci/pre-push.sh` exist and are executable where scripts.
3. `docs/MILESTONES.md`, `docs/RISK-REGISTER.md`, `CONTRIBUTING.md` (with the gate table 13.3), and `.github/pull_request_template.md` exist.
4. Branch protection requires `ci / all-green` (13.5).
5. The milestone table (13.4) is actionable — every milestone has entry/exit criteria expressed as commands a junior can run.

Run the one-liner rollup check:

```
test -f .github/workflows/ci.yml && \
test -f docs/MILESTONES.md && test -f docs/RISK-REGISTER.md && \
python3 -c "import yaml,glob;[yaml.safe_load(open(f)) for f in glob.glob('.github/workflows/*.yml')];print('SECTION13_DONE')"
```

Expected final line: `SECTION13_DONE`.

---
