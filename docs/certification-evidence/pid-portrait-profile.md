# PID portrait profile evidence

## Profile baseline

This wallet adopts the European Commission PID Rulebook version 1.7 (17 July 2026) portrait
profile ahead of the Rulebook's transitional enforcement deadline. The PID attribute is therefore
required at the authenticated credential-ingestion boundary for both supported production
representations:

- ISO/IEC 18013-5 mdoc: `portrait` in namespace and document type
  `eu.europa.ec.eudi.pid.1`, encoded as a CBOR byte string.
- SD-JWT VC: `picture` in VCT `urn:eudi:pid:1`, encoded as a
  `data:image/jpeg;base64,...` URL.

The authoritative sources are the [PID Rulebook 1.7][pid-rulebook] and its [ARF 2.9.0 published
copy][arf-copy]. The Rulebook permits an explicit holder opt-out, represented by an empty byte
string for mdoc or an empty JSON string for SD-JWT. Absence is not opt-out and is rejected.

The Rulebook makes mandatory inclusion effective 24 months after the amending Implementing
Regulation enters into force. Enforcing presence now is an intentional, fail-closed wallet profile;
it does not assert that the legal transition period has already elapsed.

## Enforced properties

The Rust core performs this check only after issuer signature, certificate path, trust service,
credential type, and device-binding checks have succeeded. A rejected credential is not partially
stored.

- the PID namespace, document type, or VCT must be exact;
- the representation-specific portrait attribute must be present exactly once;
- explicit empty opt-out values are accepted;
- non-empty data must use the required representation and be at most 2 MiB;
- non-empty data must carry JPEG start and end markers.

JPEG marker validation establishes a bounded JPEG container, not ISO/IEC 19794-5 Full Frontal
Image biometric quality. That quality assessment requires issuer capture and conformance evidence
and remains an issuer responsibility. The wallet does not make an unsupported biometric-quality
claim.

## Verification

- `crates/oid4vci/tests/pid_profile.rs` covers accepted JPEG and explicit opt-out values plus
  missing, duplicate, wrong-type, wrong-media, malformed-base64, malformed-JPEG, and oversized
  inputs.
- `crates/wallet-core/tests/verified_ingestion.rs` proves the policy is applied at the
  authenticated and atomic storage boundary for both credential formats.
- `formal/lean/IssuanceModel.lean` proves `issued_requires_valid_portrait_profile`: the issuance
  state cannot reach `credentialIssued` unless the portrait-profile gate succeeded. Generated Lean
  traces are replayed against the Rust reference transition system.
- The iOS and Android shells do not parse or bypass this policy. They consume the same Rust core
  effect and error contract. Native build and adapter tests complement the core proof because
  platform APIs themselves are outside the Lean model's trusted boundary.

[pid-rulebook]: https://github.com/eu-digital-identity-wallet/eudi-doc-attestation-rulebooks-catalog/blob/main/rulebooks/pid/pid-rulebook.md
[arf-copy]: https://eudi.dev/2.9.0/annexes/annex-3/annex-3.01-pid-rulebook/
