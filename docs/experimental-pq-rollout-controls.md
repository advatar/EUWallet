# Experimental hybrid-PQ rollout controls

Issue #94 (plan section 17) adds the compile-time feature `experimental-hybrid-pq` on the
`hybrid-pq` crate and the runtime policy in `hybrid_pq::rollout`.

## Compile-time gate

`HYBRID_PQ_COMPILED` is true only when the crate is built with `--features experimental-hybrid-pq`.
Release builds omit the feature, so `HybridRolloutPolicy::effective_mode()` is `Disabled`
regardless of any configured value and every new experimental operation is denied.

## Runtime modes

```text
Disabled                 (release default)
ExperimentalLocalOnly    local test/experiment operations only
PrivateProfileAllowed    allow-listed private-provider hybrid negotiation
HybridRequired           hybrid mandatory; classical fallback is DowngradeDetected
```

Modes are strictly ordered. Each new-operation class requires a minimum mode; opening an existing
artifact requires none.

## Configuration provenance

`request_mode` records who asked. A `Remote` origin may only lower the configured mode; any remote
request above the current mode fails with `PolicyDenied` and changes nothing. Only a
`LocalOperator` origin can raise the mode, so remote configuration alone can never enable PQ.

## Kill switch

Any origin (including remote) may activate the kill switch; only a local operator may clear it.
An active kill switch denies every new experimental operation but `OpenExistingArtifact` remains
authorized and `plan_export_read` still resolves stored versions, so already-created user
artifacts stay accessible. Under `HybridRequired`, the kill switch does not soften downgrade:
`classical_fallback()` still fails with `DowngradeDetected` rather than continuing classically.

## Telemetry

`HybridTelemetryRecord` is constructed only from the frozen profile identifier, an artifact
version, a `TelemetryOutcome` (success or a bounded `HybridErrorClass`) and a `LatencyBucket`.
Keys, payloads, signatures and ciphertext bodies are structurally unrepresentable; the canonical
emission is a fixed low-cardinality string.

## Versioned decoders

`plan_export_read` maps version 1 to the existing production reader and version 2 to the hybrid
decoder; every other version is rejected explicitly. Migration from version 1 is a separate,
explicit operation (`plan_export_migration`) that requires an authorizing policy and never runs
implicitly during read.
