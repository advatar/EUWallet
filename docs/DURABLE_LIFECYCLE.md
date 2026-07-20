# Durable Core lifecycle contract

This document describes the crash boundary implemented by the Rust Core checkpoint API and the
native `DurableLifecycleCoordinator` seams. It is a local persistence contract, not a claim of
exactly-once protocol delivery or complete national-wallet lifecycle integration.

## Bootstrap and restore order

A new process must construct a fresh Core and coordinator, then:

1. obtain the current trusted clock, signed trust list, device public key and high-assurance WUA
   independently of the saved checkpoint;
2. call the one-shot durable environment preparation API, which stages and validates all four
   inputs atomically;
3. load the authenticated platform-store record; and
4. if a non-zero generation exists, restore that exact generation into Core.

Checkpoint bytes are never used to supply or weaken the current environment. A preparation, load
or restore failure poisons that coordinator; callers must create a fresh Core/coordinator and must
not continue with a partially initialized wallet.

## Event commit boundary

The coordinator serializes Core events. For every successful JSON effect-array response it:

1. reserves `current generation + 1` with checked arithmetic;
2. handles the event exactly once in Core;
3. decodes and validates every individual effect with the exact native executor contract;
4. exports a non-empty, bounded checkpoint embedding that exact next generation;
5. compare-and-swap commits the bytes from the current to the next platform-store generation; and
6. returns the retained effect array only after the store returns the exact generation and bytes.

A Core error envelope is returned without advancing the generation. A malformed individual effect
poisons the coordinator before checkpoint export or commit. Generation mismatch and oversized state
also fail closed and never release effects.

Core and both native stores share a 33,554,312-byte checkpoint plaintext ceiling, derived from the
32 MiB Android envelope and its 120-byte fixed overhead. Replay-set cardinality is admitted before
each flow and again at the exact reservation transition; exhaustion resets the typed flow, clears
its callbacks and leaves the prior durable checkpoint exportable. Direct and OID4VCI credential
ingestion also project authenticated record count, each evidence component and aggregate evidence
before the successful storage transition. The projection follows exact upsert semantics, including
replacement and test-fixture promotion; rejection leaves the prior checkpoint and audit unchanged.

Transaction redaction and full history wipe are Core events under the same commit boundary. Core
admits them only when no protocol flow or native callback is pending, and the native shells report a
blocked mutation as an error rather than an idle success. Successful and aborted terminal issuance,
presentation, payment, QES and wallet-to-wallet transitions release their active marker and pending
callbacks before a later history event can be admitted.

## Failure and retry semantics

An export or commit failure retains the exact event and effect batch in process memory. A retry is
accepted only for byte-for-byte identical event JSON. Export may be retried when no checkpoint was
produced; once produced, the exact checkpoint is reused. Core is never called a second time.
While either export or commit remains pending, every other event is rejected before Core is called;
the pending event cannot be overwritten even by a replacement executor. The coordinator state is
authoritative, and native callers receive the original typed lifecycle failure rather than a
generic Core error.

After an ambiguous commit error, retry first repeats the exact compare-and-swap. If that fails, the
coordinator loads the store and accepts success only when both the next generation and plaintext
match the retained checkpoint. The old generation remains retryable; every other generation is a
divergence. Effects are released once and the retained batch is then discarded, so another retry
cannot duplicate their execution through the coordinator.

## Process death

Pending event, checkpoint and effect values are memory-only. Process death discards them. Restart
restores only the last authenticated platform-store generation, while Core deliberately leaves all
protocol machines, sessions, callbacks, pending operations and effect batches empty. An event whose
commit did not anchor must therefore be initiated again by the user or protocol after restart.

This provides **at-most-once effect release after local checkpoint persistence**. It is not a
durable outbox and does not provide exactly-once network, signing, storage or UI delivery. In
particular, process death after the checkpoint commit but before an external effect completes loses
that pending effect by design.

## Diagnostics and remaining integration

FFI and coordinator failures are stable, low-cardinality codes without source errors, identifiers,
generations, events, effects, credential material or checkpoint bytes. Native environment and
checkpoint wrappers have redacted string/debug representations and defensively copy byte arrays.

Both native effect executors now require a concrete coordinator, and their public behavior is tested
through coordinator-backed engines. The current iOS application routes protocol and history events
through that coordinator; a file-private adapter owns generated-engine mutation, and a CI
architecture test guards the current application sources against direct construction or known raw
mutators. The generated binding remains a public compatibility surface, so this is source-level
composition enforcement rather than proof that arbitrary future client code cannot bypass it.

The iOS demo deliberately uses a process-local CAS store because its fixture identities rotate on
every launch. Production composition must instead inject `AppleDurableStateStore` with stable,
device-bound installation identities. Android still needs generated Rust bindings, a durable-engine
adapter and an application entry point, so the cross-platform sole-event-path parent remains open.
Both clients also need migration/recovery UX, physical-device evidence and a provider monotonic
receipt (or evaluated platform monotonic anchor) before stronger rollback or delivery claims are
justified.
