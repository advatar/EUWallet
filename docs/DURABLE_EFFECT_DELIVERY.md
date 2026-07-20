# Durable effect delivery contract

Status: the bounded ledger state machine is implemented but deliberately dormant; checkpoint-v2,
aggregate continuity, FFI/coordinator integration and adapter enablement remain design targets.

This document defines the crash-safety boundary required before the wallet may describe native
effect delivery as durable. It supplements `DURABLE_LIFECYCLE.md`; it does not change that
document's current statement that pending effects and protocol continuation are memory-only.

The design provides durable local intent and deterministic recovery. It does **not** make generic
external I/O exactly once. Exactly-once remote behavior requires an effect-specific provider or OS
contract that supports idempotency, reconciliation or durable callback reattachment, plus evidence
that the adapter uses that contract correctly.

Normative terms such as MUST, MUST NOT and MAY describe the target contract, not current behavior.

## Safety invariant

Checkpoint schema v2 MUST persist these values atomically in the same authenticated platform CAS
record:

1. the complete resumable production protocol aggregate;
2. every live native-effect ledger entry;
3. bounded terminal tombstones; and
4. the existing durable credential, replay, audit, clock, trust and wallet-context state.

Persisting an effect without its aggregate is unsafe. Checkpoint v1 deliberately drops active
protocol machines, sessions, pending callbacks and their correlation table. After a v1 restart,
Core therefore cannot reliably validate or consume the result of a replayed effect. A native-only
outbox wrapped around v1 would preserve work that Core is unable to resume and MUST NOT be used.

The aggregate portion of v2 MUST contain every value needed to validate the next event or effect
result: the active flow and typed state, expected effect identifiers and kinds, protocol/session
correlation, consent and authorization bindings, reserved nonces, retry counters, and any bounded
secret needed for continuation. Derived caches MAY be reconstructed. Private key bytes MUST NOT be
serialized; the aggregate stores only stable hardware/keystore references and their public
bindings. Unsupported, unknown or internally inconsistent aggregate variants fail restore
atomically.

No effect payload, dispatch permit, result, successor effect or completion acknowledgement may
cross the Core/coordinator boundary until the state that authorizes that next action is committed.

## Checkpoint-v2 model and bounds

The canonical v2 payload adds one continuation partition to the authenticated checkpoint:

```text
Continuation {
  aggregate: Idle | Issuance(...) | Presentation(...) | Payment(...) |
             Qes(...) | WalletTransfer(...),
  live_effects: EffectEntry[0..32],
  tombstones: EffectTombstone[0..64]
}

EffectEntry {
  effect_id: [u8; 32],
  effect_kind,
  bounded_payload,
  recovery_policy,
  state: Queued | Dispatching | ResultReady | Ambiguous,
  created_sequence,
  attempt,
  adapter_contract_version,
  optional_bounded_result
}
```

The exact wire schema MUST use fixed numeric tags, canonical ordering and checked integer
conversions. Decoders MUST reject duplicate map keys, unknown mandatory variants, trailing data,
non-canonical encodings and lengths above their declared bounds before allocating those lengths.

The following limits are hard admission limits:

- at most 32 live entries across all effects and flows;
- exactly 32 bytes per effect identifier;
- at most 64 tombstones;
- at most 4 MiB (`4 * 1024 * 1024` bytes) across live request payloads plus their reserved maximum
  result capacities; and
- the existing 33,554,312-byte authenticated checkpoint plaintext ceiling.

The v2 codec MUST additionally set and test an exact encoded-continuation bound covering aggregate
state, entry metadata, tombstones and CBOR overhead. That bound has not been selected by the dormant
ledger model and MUST fit, together with the 4 MiB delivery reservation and all other state, under
the unchanged checkpoint ceiling. Admission of credentials, evidence, replay values, transaction
history, aggregate transitions, effects and results MUST pre-encode or exactly project the complete
checkpoint. If any live-count, tombstone, reservation, encoded-section, field or total bound would
overflow, Core returns a typed capacity error without changing the aggregate, ledger, audit log,
callback correlation, generation or next effect identifier. Partial live-entry eviction is not an
acceptable recovery action.

Tombstones contain only the effect identifier, terminal disposition, terminal sequence and bounded
digests needed to recognize duplicate callbacks; they do not retain full payloads or results. When
the 65th terminal record is committed, Core deterministically evicts the oldest tombstone by
terminal sequence in that same mutation. A callback for an identifier older than the retained
window is rejected as unknown and cannot mutate the aggregate.

## Stable effect identifiers

Core creates a cryptographically random 32-byte ledger namespace. Each stable identifier is the
SHA-256 output of a fixed domain tag, that secret namespace, a non-zero monotonic sequence, the
closed effect/recovery tags, the bounded request digest and the reserved result capacity. The
identifier is immutable through dispatch, recovery and terminal handling and is persisted before
native code sees it. Its eventual FFI representation is canonical unpadded base64url; native code
treats it as an opaque value.

An identifier MUST NOT be a bare payload, credential, subject, transaction-data or predictable
counter digest. The random namespace remains encrypted inside the checkpoint and is redacted from
diagnostics; binding the request digest detects substitution without publishing that digest. Core
MUST reject duplicate live or retained-tombstone identifiers, and the monotonic sequence is never
reused even after tombstone rotation. A deterministic namespace is permitted only in tests. If
intent commit fails, the identifier was never released and MAY be discarded; CAS retry of a
retained mutation MUST reuse the exact identifier and checkpoint bytes.

An adapter MAY send the identifier as an idempotency or correlation key only where its reviewed
protocol contract permits it. The existence of the identifier alone is not evidence that a remote
party deduplicates requests.

## Ledger state machine and commit barriers

`Queued`, `Dispatching`, `ResultReady` and `Ambiguous` are live states. `consume` is the terminal
mutation that atomically replaces a live entry with a tombstone. An effect with no protocol payload
still records a typed, empty acknowledgement as `ResultReady` before consumption; it is never
deleted directly from `Dispatching`.

```text
new aggregate transition -> Queued
Queued                  -> Dispatching
Dispatching             -> ResultReady | Ambiguous
ResultReady             -> consume -> tombstone (+ zero or more Queued successors)
Ambiguous               -> Queued | ResultReady, but only through its declared policy
```

Every arrow is a Core mutation followed by canonical checkpoint export and authenticated CAS. The
coordinator serializes mutations and applies these barriers:

1. **Intent:** commit `Queued` before exposing an effect identifier or payload to native code.
2. **Claim:** commit `Dispatching`, attempt and adapter contract before returning a dispatch permit
   or invoking the adapter.
3. **Result:** commit the bounded adapter outcome as `ResultReady` before presenting it to the
   protocol aggregate.
4. **Consume:** atomically validate the result, advance the aggregate, tombstone the consumed entry
   and enqueue successors; commit before exposing any successor.
5. **Acknowledge:** for an effect with no protocol result, first record its typed empty successful
   acknowledgement as `ResultReady`, then consume and tombstone it under the same aggregate rules;
   commit before reporting completion or reclaiming capacity.

A malformed result, wrong effect kind, stale attempt, duplicate callback or result for an
unexpected aggregate state fails before mutation. A duplicate consume or acknowledgement matching
a retained tombstone is an idempotent terminal response; it never advances Core twice.

`Dispatching` means the adapter may have observed the permit. It is therefore never automatically
changed back to `Queued` merely because a process, lease or timeout ended. On restart, Core and the
coordinator commit it as `Ambiguous` before any recovery action. The entry remains ambiguous until
the effect's fixed recovery policy produces durable resolution.

## Adapter recovery policies

Every effect kind is assigned one reviewed policy in Core. Native callers cannot weaken or replace
the policy at runtime.

- **Idempotency:** re-dispatch the same semantic request with the same stable idempotency key only
  when the provider contract guarantees duplicate suppression for the required retention window.
  The decision to requeue and increment the attempt is committed first.
- **Reconcile:** query a provider's authoritative status by durable correlation, then commit either
  a recovered result, a proven-not-executed requeue, or a terminal failure. An inconclusive answer
  remains `Ambiguous`.
- **Await:** reattach to a documented durable OS/provider callback using the original correlation.
  Do not initiate the operation again. A callback is persisted as `ResultReady` before consumption.
- **Never replay:** do not invoke the operation again when completion cannot be established safely.
  Commit a typed terminal failure or retain the ambiguity for explicit recovery UX.

Policy is effect- and adapter-specific. For example, an HTTP method is not replay-safe merely
because it is nominally idempotent, and a local signing call is not safe to repeat merely because
the resulting signature may be deterministic. Provider retention windows, body equivalence,
authentication rotation, OS callback behavior and timeout semantics require explicit evidence.

An adapter lacking one of these proven contracts MUST use `Never replay`. Generic retries after an
ambiguous dispatch are forbidden, and project documentation MUST NOT claim exactly-once external
network, signing, storage, browser, push or UI behavior.

## Proposed Core and native APIs

These APIs are a target shape. Names may follow language conventions, but their authority and
barriers are mandatory.

Core/FFI owns all ledger transitions:

```text
submit_event(event) -> queued effect summaries
list_effects() -> read-only bounded summaries
claim_effect(effect_id, adapter_contract) -> dispatch permit
record_effect_result(effect_id, attempt, result) -> result-ready receipt
consume_effect_result(effect_id) -> queued successor summaries
record_effect_acknowledgement(effect_id, attempt) -> result-ready receipt
mark_dispatch_ambiguous(effect_id, attempt, reason) -> recovery summary
resolve_ambiguous_effect(effect_id, policy_evidence) -> recovery transition
export_durable_checkpoint(next_generation) -> canonical checkpoint v2
restore_durable_checkpoint(checkpoint, authenticated_generation) -> atomic restore
```

The native `DurableLifecycleCoordinator` remains the only production mutation path. It MUST:

- serialize event and ledger commands;
- retain the exact Core mutation output and checkpoint across retry without invoking Core twice;
- CAS the checkpoint before returning the corresponding summary, permit, result receipt,
  successors or terminal receipt;
- reconcile an ambiguous CAS by loading and comparing exact generation and plaintext;
- bootstrap by preparing the current trusted environment, restoring Core, listing the ledger and
  committing any `Dispatching` entries as `Ambiguous`; and
- reject all other events while a mutation or its CAS reconciliation is pending.

Native executors accept only a committed `DispatchPermit`; they do not accept raw effects returned
directly by `submit_event`. Adapter callbacks contain the effect identifier and attempt and return
through the same coordinator. Platform stores continue to expose bounded `load` and
`compareAndSwap(expectedGeneration, nextGeneration, plaintext)` operations; no second native
outbox file or database may become an independent source of truth.

Read-only diagnostics expose only low-cardinality state, effect kind, age bucket and recovery
policy. String/debug output, logs, metrics and crash reports MUST redact effect identifiers,
payloads, results, tokens, authorization material, credential data, checkpoint bytes and key
references.

## Restart and crash recovery matrix

| Durable state at restart | What may have happened | Required recovery before action |
| --- | --- | --- |
| No entry | Intent was never committed, or entry is terminal beyond the tombstone window | Do not dispatch; a new user/protocol event is required |
| `Queued` | Intent committed; no dispatch claim committed | Claim by CAS, then dispatch once |
| `Dispatching` | Adapter may or may not have started or completed | Commit `Ambiguous`; apply only the declared recovery policy |
| `Ambiguous` | Completion is unresolved | Idempotency, reconcile, await or never-replay handling; no generic retry |
| `ResultReady` | Result committed; aggregate has not consumed it | Consume by CAS without invoking the adapter |
| Consumed tombstone | Aggregate consumed result; successors are in the same checkpoint | Treat duplicate callback as terminal; dispatch any queued successors normally |
| Consumed acknowledgement tombstone | Result-free effect acknowledgement was recorded and consumed | Treat duplicate acknowledgement as terminal; do not execute again |

Crash-point obligations are equally strict:

- after intent commit but before release: restart finds `Queued`;
- after claim commit but before/during/after adapter invocation: restart treats it as ambiguous;
- after adapter completion but before result/ack commit: restart uses the declared ambiguity policy;
- after result commit but before consume: restart consumes `ResultReady`;
- after consume commit but before successor release: restart finds the queued successors; and
- after acknowledgement consumption commits but before completion is reported: restart finds the
  tombstone.

An in-process CAS timeout follows the existing exact-byte reconciliation rule. Process death must
not turn an uncertain commit into a second Core mutation.

## V1 migration and downgrade

V1 has no evidence that an omitted flow or callback did not exist. An arbitrary v1 checkpoint MUST
NOT be interpreted as a resumable empty v2 aggregate merely because restore initializes those
fields to empty.

Migration is allowed only at a proven idle-and-empty boundary: no active protocol aggregate, no
pending operation/callback, no retained native batch and no live effect. The proof must be written
under the existing authenticated CAS boundary by a migration-capable release, or the wallet must be
new/empty. Without that proof, automatic migration fails closed and routes to documented recovery
or a legacy release that can establish the marker. No effect may dispatch during migration.

The v1 record and migration proof are read once, validated against the current trusted environment,
then converted to an idle aggregate and empty ledger in one v2 CAS generation. Once v2 is committed,
older code must reject the unknown schema instead of rewriting it. Release engineering must prevent
application downgrade from becoming a checkpoint downgrade path.

## Threats and non-goals

The design addresses:

- process death at every local commit/dispatch boundary;
- duplicate, stale, out-of-order and wrong-kind callbacks;
- checkpoint substitution, corruption and cross-wallet restore through the existing authenticated
  envelope and context binding;
- parser and storage exhaustion through canonical bounded decoding and pre-mutation admission;
- predictable correlation and identifier reuse;
- silent loss of a committed effect; and
- accidental secret disclosure through typed redacted diagnostics.

It does not by itself address a compromised OS, hardware keystore, platform store implementation,
native adapter or remote provider. It also does not provide a trusted external monotonic anchor,
prove remote idempotency, guarantee provider status availability, or make physical-world actions
reversible. Those require separate platform, provider, operational and certification evidence.

## Phased rollout

1. **Model and codec, non-dispatching:** add v2 types, canonical codecs, limits, transition tests and
   read-only projections behind a disabled capability. Production effects continue to have the
   documented v1 semantics. The initial code slice MUST NOT enqueue, claim or dispatch a production
   effect and MUST NOT advertise crash-safe delivery.
2. **Aggregate continuity:** serialize and restore the production aggregate for each supported flow,
   prove callback correlation and atomic failure, enforce the continuation reserve, and implement
   the idle-and-empty migration gate. Durable delivery remains disabled for any incomplete flow.
3. **Coordinator integration:** implement commit-gated Core/FFI commands, restart recovery and
   native CAS orchestration on iOS and Android. Run in shadow/read-only recovery mode first.
4. **Adapter enablement:** classify every effect, document its contract, add idempotency,
   reconciliation, await or never-replay behavior, and enable dispatch per effect behind an
   allowlist only after its crash evidence passes.
5. **Release evidence:** complete cross-platform physical-device restart tests, provider sandbox and
   retention-window tests, fuzz/negative testing, security review, observability/UX review and
   conformance evidence before changing launch claims.

Production aggregate continuity is therefore a hard prerequisite, not a later optimization. A
ledger-only foundation may be useful for tests and review, but it is deliberately non-dispatching.

## Required test and evidence matrix

| Area | Minimum evidence before enablement |
| --- | --- |
| V2 codec | Canonical golden vectors, exact round trips, unknown/duplicate/trailing rejection, hostile length tests and fuzzing |
| Atomic restore | Every malformed aggregate/ledger variant leaves the prior Core state byte-for-byte exportable |
| Bounds | 32/33 live entries, 64/65 tombstones, exact/over 4 MiB delivery reservation, exact/over encoded-continuation bound once selected, and exact/over total checkpoint tests |
| Capacity | Every rejected event/result leaves aggregate, ledger, audit, generation and identifier source unchanged |
| Identifiers | 32-byte shape, collision rejection, retry stability, canonical FFI encoding and log-redaction tests |
| State machine | Every legal transition and every illegal, duplicate, stale-attempt and wrong-kind transition |
| Crash points | Deterministic restart injection before and after intent, claim, adapter result, result commit, consume, successor release and ack |
| Aggregate continuity | Restart at every state of issuance, presentation, payment, QES and wallet transfer, then accept only the originally correlated result |
| Migration | Proven idle+empty succeeds; active, pending, unproven, corrupt and downgrade cases fail closed without dispatch |
| Key handling | Serialized-form inspection and tests proving private key bytes never enter checkpoint, diagnostics or fixtures |
| Native CAS | iOS and Android persistent-store tests for exact-byte ambiguous-commit reconciliation, generation divergence and process restart |
| Architecture | CI guards that production executors receive only committed permits and cannot call raw generated mutators |
| Adapter contract | Per-effect provider/OS documentation, sandbox tests, idempotency retention evidence, reconciliation negatives and never-replay UX |
| Devices and operations | Physical-device kill/reboot/update tests, capacity/recovery UX, redacted telemetry and incident runbooks |

Passing local ledger tests is necessary but insufficient. Enablement is per flow and per adapter;
one proven adapter does not justify a wallet-wide exactly-once claim.
