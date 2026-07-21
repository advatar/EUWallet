# EU/EUDI conformance run — 2026-07-21

This is an engineering evidence record, not a certification claim.

## Passed locally

- `cargo test --workspace --all-targets` — passed (all workspace unit,
  transition, model-oracle, conformance, and end-to-end tests).
- `ios`: `swift test` — passed, 137 tests, 0 failures.
- `tools/interop/probe.sh` — passed: EUDI reference issuer metadata returned
  HTTP 200 with 27 credential configurations (including wallet-supported
  SD-JWT VC profiles), and the reference verifier was reachable.

## Blocked or external

- `android`: `./gradlew :wallet-shell:testDebugUnitTest` could not start because
  this runner has no Java runtime (`Unable to locate a Java Runtime`). Re-run on
  a pinned JDK/Android SDK image before treating Android evidence as complete.
- OpenID Foundation Conformance Suite: not installed or submitted; the local
  tests and metadata probe do not replace the official OIDF run.
- EU FCAF, German sandbox, cross-border, physical eID, CAB/BSI and provider
  interoperability suites require external harnesses, credentials, trust
  anchors, devices, or an accredited assessment process.

No external certification or self-certification result is claimed by this
record.
