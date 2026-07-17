# euwallet — EUDI Wallet (Rust core · Swift shell · formally verified)

A from-scratch European Digital Identity Wallet, built as a **sans-IO Rust behaviour core**
with **thin native shells** (Swift/iOS now, Kotlin/Android later), and verified across **three
formal tiers** (property/fuzz/Kani → Lean state-machine proofs → Tamarin protocol analysis).

Grounded in the EUDI specification register (as of 2026-07-17): ARF v2.9.0, PID Rulebook v1.6,
FCAF v0.0.7. See [`docs/IMPLEMENTATION_PLAN.md`](docs/IMPLEMENTATION_PLAN.md) — the full,
junior-developer-followable build plan.

## Layout

| Path | What |
|---|---|
| `crates/` | The Rust workspace (13 crates). `wallet-core` is the sans-IO facade; the rest are codecs, protocol machines, trust/status/wua, and the presenter. |
| `ios/` | `WalletShell` Swift package: renderer, effect executor, Secure Enclave signer, transports, storage. |
| `formal/lean/` | **Tier 2** — Lean 4 model with machine-checked invariant proofs and the trace-export oracle. |
| `formal/tamarin/` | **Tier 3** — Tamarin symbolic model of the HAIP OpenID4VP profile. |
| `fuzz/` | **Tier 1** — cargo-fuzz targets. (Kani harnesses live in-crate behind `#[cfg(kani)]`.) |
| `tools/hlr-import/` | Imports the canonical HLR CSV into the traceability table. |
| `traceability/` | `requirements.csv` — every HLR mapped to code + tests + evidence. |
| `docs/` | The implementation plan and supporting design docs. |
| `.github/workflows/ci.yml` | The definition-of-done gates for every layer. |

## Quick verify (what already works in this skeleton)

```bash
# Rust core: 13 crates compile, sans-IO run-loop + CBOR property tests pass
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
