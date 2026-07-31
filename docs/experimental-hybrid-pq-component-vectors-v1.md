# Shared hybrid-PQ component vectors v1

Status: **experimental cross-repository evidence; not production key material**

Tracking: [#105](https://github.com/advatar/EUWallet/issues/105)

These files are copied byte-for-byte into EUWallet and VCIssuer:

- `hybrid-pq-v1-component-tbs.hex` — canonical `test-sd-jwt-wrapper-v1` TBS;
- `hybrid-pq-v1-public-key-envelope.hex` — the PR #103 public-key container;
- `hybrid-pq-v1-signature-envelope.hex` — the PR #103 atomic dual-signature container;
- `hybrid-pq-v1-component-mutations.json` — deterministic patch operations for twelve rejection
  cases.

The P-256 private scalar is 32 bytes of `0x07`. The ML-DSA-65 key-generation seed is 32 bytes of
`0x42`, and its signing randomness is 32 bytes of `0x24`. These values are public fixtures and MUST
NOT be used by production code. VCIssuer generates both real signatures with `p256` and
`libcrux-ml-dsa`; EUWallet independently verifies them with AWS-LC and RustCrypto `ml-dsa`.

SHA-256 of the decoded binary vectors:

| Artifact | SHA-256 |
| --- | --- |
| TBS | `ebdf4ddf9bdd7f72172f623ae94fa19dad62023574d1d68c62aff6a52c2b2805` |
| public-key envelope | `6f252c80edfb3a902ea26abe6eabd98e883f4828238810a07be165653e4eb42c` |
| signature envelope | `ff348f5a043989ee5f2fb329bc25f5778f8750b5685041eaf8753db90eb386a7` |

This corpus proves component-codec parity and cross-implementation verification over one common
TBS. It does not freeze the credential wrapper carrying payload, disclosures, key identifiers,
generation and issuance context; that remains gated by issues #90 and #91.
