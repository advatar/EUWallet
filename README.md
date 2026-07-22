# euwallet — EUDI Wallet (Rust core · Swift shell · formally verified)

## Security status

EUWallet is not yet production-certified. An independent pre-launch security
review remains a launch gate; see [`docs/SECURITY_AUDIT.md`](docs/SECURITY_AUDIT.md).

A from-scratch European Digital Identity Wallet, built as a **sans-IO Rust behaviour core**
with **thin native shells** (Swift/iOS now, Kotlin/Android later), and verified across **three
formal tiers** (property/fuzz/Kani → Lean state-machine proofs → Tamarin protocol analysis).

Grounded in the EUDI specification register (as of 2026-07-17): ARF v2.9.0, PID Rulebook v1.7,
FCAF v0.0.7. See [`docs/IMPLEMENTATION_PLAN.md`](docs/IMPLEMENTATION_PLAN.md) — the full,
junior-developer-followable build plan.

## Layout

| Path | What |
|---|---|
| `crates/` | The Rust workspace (21 crates, all `#![forbid(unsafe_code)]`, + a `benches` micro-benchmark crate). `wallet-core` is the sans-IO facade; the rest are codecs, protocol machines, trust/status/wua, and the presenter. |
| `ios/` | `WalletShell` Swift package + app: renderer, effect executor, Secure Enclave signer, real URLSession transport, VisionKit QR scanning. |
| `LandingPage/` | Evidence-led technical landing page (submodule; TanStack Start). Every claim traces to a repo artifact. |
| `docs/certification-evidence/` | The living evidence set: verification report, SBOM, benchmarks, mutation testing, interop probe, payment-SCA traceability. |
| `formal/lean/` | **Tier 2** — Lean 4 model with machine-checked invariant proofs and the trace-export oracle. |
| `formal/tamarin/` | **Tier 3** — Tamarin symbolic model of the HAIP OpenID4VP profile. |
| `fuzz/` | **Tier 1** — cargo-fuzz targets. (Kani harnesses live in-crate behind `#[cfg(kani)]`.) |
| `tools/hlr-import/` | Imports the canonical HLR CSV into the traceability table. |
| `traceability/` | `requirements.csv` — every HLR mapped to code + tests + evidence. |
| `docs/` | The implementation plan and supporting design docs. |
| `.github/workflows/ci.yml` | The definition-of-done gates for every layer. |

## Evidence portal

Start at **`LandingPage/`** — an evidence-led technical portal where every security, verification,
conformance, and testing claim names its scope, tool, version, result, date, source revision, and
supporting artifact (`cd LandingPage && bun install && bun run dev`). It reads from
`docs/certification-evidence/`, which is regenerated from a clean checkout by
[`tools/evidence/generate.sh`](tools/evidence/generate.sh):

| Evidence | Where |
|---|---|
| Reproducible Tier 0–3 report (198 tests · 6 Lean models/37 theorems · 23 Tamarin lemmas · clippy) | [`verification-report.md`](docs/certification-evidence/verification-report.md) |
| Published CycloneDX SBOM (21 crates) | [`sbom/`](docs/certification-evidence/sbom/) |
| Hot-path performance benchmarks | [`perf-benchmarks.md`](docs/certification-evidence/perf-benchmarks.md) |
| Mutation testing (oid4vp: 73/73 viable caught) | [`mutation-testing.md`](docs/certification-evidence/mutation-testing.md) |
| Reference-environment interop probe | [`interop.md`](docs/certification-evidence/interop.md) · [`tools/interop/probe.sh`](tools/interop/probe.sh) |
| PSD2 SCA dynamic-linking traceability | [`payment-sca.md`](docs/certification-evidence/payment-sca.md) |
| PID Rulebook 1.7 portrait profile | [`pid-portrait-profile.md`](docs/certification-evidence/pid-portrait-profile.md) |

## Quick verify (what already works)

```bash
# Rust core: 21 crates compile; 198 workspace tests pass with real aws-lc-rs crypto
cd euwallet && cargo test --workspace

# Tier 2: Lean proves the invariants, exports traces, Rust replays them
cd formal/lean && lake build && lake exe traces > ../../crates/oid4vp/tests/model_traces.json
cd ../.. && cargo test -p oid4vp --test conformance

# iOS shell: builds and its effect-executor tests pass
cd ios && swift test

# Traceability: import the 684 High-Level Requirements
cd tools/hlr-import && python3 import_hlr.py high-level-requirements.csv ../../traceability/requirements.csv
```

## Status

This is a **verified skeleton**: every layer compiles and its example tests pass, the three
formal tiers are wired end-to-end, and the module boundaries match the register's P0 build
profile. Each module is a documented stub to be filled per the implementation plan. It is
**not** a certified wallet — a prototype is not an official EUDI Wallet until the applicable
Member State certification and listing are complete (register: *legal/product-status boundary*).
