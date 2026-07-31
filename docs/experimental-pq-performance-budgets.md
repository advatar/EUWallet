# Experimental hybrid-PQ performance and resource budgets

Issue #93 (plan section 16). Budgets cap the operational impact of ML-DSA-65 and ML-KEM-768 on
the wallet. Measurements come from `cargo run -p benches --release --features experimental-pq`
against the real RustCrypto backends (`experimental-pq-primitives`); the bench prints the same
tables so numbers stay reproducible.

## Measured baseline (Apple Silicon, macOS, release, single-threaded, 2026-07-31)

| Operation | Mean latency | Throughput (ops/sec) |
|---|---|---|
| ML-DSA-65 keygen | 262 µs | 3 811 |
| ML-DSA-65 sign (64 B) | 156 µs | 6 391 |
| ML-DSA-65 verify (64 B) | 179 µs | 5 600 |
| ML-KEM-768 keygen | 51 µs | 19 498 |
| ML-KEM-768 encapsulate | 50 µs | 20 065 |
| ML-KEM-768 decapsulate | 51 µs | 19 492 |
| Hybrid signature envelope encode | 142 ns | ~7.0 M |
| Hybrid signature envelope decode | 236 ns | ~4.2 M |

Process-level resource use for the complete PQ bench binary: peak memory footprint ≈ 2.2 MB,
maximum RSS ≈ 3.7 MB (`/usr/bin/time -l`). Release binary size delta for compiling the PQ
surface (`ml-dsa` + `ml-kem` + `zeroize` + envelope wiring): ≈ 257 KiB.

## Budgets (hard ceilings, enforced at review; regression = investigate before merge)

| Budget | Ceiling | Headroom vs. measured |
|---|---|---|
| Any single ML-DSA-65 operation | ≤ 5 ms | ≈ 20× |
| Any single ML-KEM-768 operation | ≤ 2 ms | ≈ 40× |
| Envelope encode/decode | ≤ 50 µs | ≥ 200× |
| One full hybrid sign or verify (both components + codec) | ≤ 10 ms | ≥ 10× |
| Added peak memory for any hybrid operation | ≤ 8 MiB | ≥ 2× the whole bench process |
| Added binary size for the PQ surface | ≤ 512 KiB | ≈ 2× |
| Durable storage per hybrid artifact | ≤ 8 KiB | envelope cap, exact |

The generous ceilings are deliberate: they must hold on the slowest supported physical iPhone,
not only on desktop Apple Silicon; the headroom column shows current margin. Interactive flows
stay dominated by TLS round-trips and user interaction, not PQ computation.

## Hard input limits (enforced in code, fail-closed)

| Limit | Value | Where |
|---|---|---|
| Envelope size cap | 8 192 B | `hybrid_pq::envelope::MAX_ENVELOPE_BYTES` |
| Envelope text field cap | 64 B | `envelope::MAX_TEXT_BYTES` |
| Exact component sizes (pk 65/1952, sig 64/3309, KEM 1184/1088/32) | frozen | `hybrid_pq` crate constants |
| TBS field cap | 4 096 B | `tbs::MAX_FIELD_BYTES` |
| TBS nonce bounds | 16–64 B | `tbs::MIN_NONCE_BYTES..=MAX_NONCE_BYTES` |
| Key-reference identity cap | 128 B | `HybridKeyRef::MAX_IDENTITY_BYTES` |

Message sizes and fragmentation: the largest single hybrid artifact is the signature envelope at
3 473 B (largest purpose identifier; ≈ 100 B codec overhead over the raw components), under the 8 KiB cap and small
enough for a single QR-less transport frame; no fragmentation scheme is required or defined.

A budget regression test in `crates/benches` pins the maximal envelope wire size against the cap
so a codec change that breaks the storage/message budget fails CI.

## Remaining hardware-gated evidence

Physical-device benchmarks (supported iPhone hardware), battery cost, and concurrency behavior
under thermal constraints remain an explicit #86-dependent closure gate: they require the
connected passcode/biometric-enabled device runs recorded there. Simulator XCTests remain serial
under repository hygiene rules, with disposable clone sets cleaned only after runs finish.
