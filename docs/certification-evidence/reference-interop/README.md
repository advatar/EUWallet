# EU reference-wallet interoperability evidence

`tools/reference-interop/run.sh` produces a local or CI report probing the
configured EU reference issuer and verifier endpoints. Reports are reachability
and metadata-shape evidence only; they are not an EU conformance or
self-certification result.

Set `REFERENCE_ISSUER`, `REFERENCE_VERIFIER`, and `REFERENCE_INTEROP_OUT` for
the environment under test. Keep endpoint responses and reports redacted and
append-only when used for certification evidence.
