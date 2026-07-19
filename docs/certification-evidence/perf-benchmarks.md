# Performance benchmarks

Micro-benchmarks of the wallet's hot paths, measured against the **real `aws-lc-rs` backend**
(no mock crypto). The harness is dependency-free (`std::time` + `std::hint::black_box`) so it adds
nothing to the dependency budget. Reproduce with:

```
cargo run -p benches --release
```

- **Source:** `crates/benches/src/main.rs`
- **Method:** 2 000-iteration warmup, then ~350 ms auto-sized sample per operation, single-threaded.
- **Machine:** Apple Silicon (arm64), macOS, `--release`. Latency is machine-dependent; treat these
  as order-of-magnitude, not a guarantee. Run the command above on your target hardware.
- **Run date:** 2026-07-19.

| Operation | Mean latency | Throughput (ops/sec) |
|---|---|---|
| SHA-256 (32 B) | 58 ns | 17,321,921 |
| SHA-256 (1 KiB) | 699 ns | 1,430,080 |
| ES256 sign (P-256) | 28.72 µs | 34,822 |
| ES256 verify (P-256) | 83.57 µs | 11,965 |
| Canonical CBOR encode (IssuerSignedItem-shaped map) | 1.28 µs | 782,679 |
| SD-JWT VC parse (2 disclosures) | 430 ns | 2,325,094 |

## Reading these numbers

- **A presentation or issuance is dominated by one or two ES256 operations plus a single TLS round
  trip** (the network, on the platform's stack — not measured here). Parsing and CBOR encoding are
  three-to-four orders of magnitude cheaper than the signature work, so they are not the
  bottleneck; the wallet spends its on-device time in the Secure Enclave / crypto backend.
- Verify is slower than sign for P-256, as expected.
- These are **core-operation** benchmarks. They are not an endurance/soak test and not an
  end-to-end wall-clock measurement of a full issuance or presentation against a live server —
  those depend on the counterparty and network and are covered by the interop harness, not here.

## Not covered (honest scope)

- No sustained-load / endurance (hours-long) run yet.
- No device-hardware numbers (Secure Enclave signing latency differs from the software signer used
  in this harness).
- No memory/allocation profiling.
