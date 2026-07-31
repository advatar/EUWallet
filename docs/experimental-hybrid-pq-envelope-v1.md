# Experimental hybrid PQ envelope v1

Status: **implemented and frozen for experimental use**

Tracking: [#83](https://github.com/advatar/EUWallet/issues/83)

Every envelope begins with the exact bytes:

```text
ASCII("EUWALLET-EXPERIMENTAL-HYBRID-PQ-V1") || 0x00
```

The remaining bytes are one RFC 8949 Core Deterministic Encoding CBOR map. Integer keys are closed,
critical and emitted in ascending order. Decoders reject unknown keys rather than ignoring them.

## Closed schemas

| Key | Meaning | Public-key envelope | Signature envelope |
| --- | --- | --- | --- |
| `1` | version, unsigned integer `1` | required | required |
| `2` | kind | unsigned integer `1` | unsigned integer `2` |
| `3` | profile text `euwallet-hybrid-pq-v1` | required | required |
| `4` | classical component bytes | 65-byte uncompressed P-256 key | 64-byte ES256 `r || s` |
| `5` | post-quantum component bytes | 1,952-byte ML-DSA-65 key | 3,309-byte ML-DSA-65 signature |
| `6` | closed purpose identifier | forbidden | required |

Both signature components are mandatory members of one map. No empty, absent, optional or
classical-only representation exists. The public constructors additionally require the classical
public key to begin with SEC 1's uncompressed-point marker `0x04`.

## Decoder rules and limits

The complete prefixed envelope is limited to 8 KiB before parsing or allocation. Text values are
limited to 64 bytes. Component constructors then enforce the exact frozen algorithm sizes.

Decoders reject:

- a missing or altered magic prefix;
- non-map top-level CBOR;
- indefinite lengths, reserved additional-information values and non-shortest integer/length forms;
- duplicate, out-of-order or unknown keys;
- missing or unexpected fields and wrong CBOR value types;
- invalid UTF-8, unknown profile/purpose, unsupported version/kind and malformed components;
- truncated input, trailing bytes and aggregate oversize.

The implementation is [`crates/hybrid-pq/src/envelope.rs`](../crates/hybrid-pq/src/envelope.rs).
Its encoder has no production dependencies. Tests independently decode emitted maps with
`ciborium`, property-test decode/re-encode stability, and exercise every negative class. The
`hybrid_pq_envelopes` libFuzzer target passes arbitrary bytes to both decoder entry points.
