# Delivery checkpoint

Updated: 2026-07-27

This is the short, durable resume point for work on the wallet. `STATUS.md` remains the detailed
source of truth for scope and evidence.

## Repository state at checkpoint creation

- Baseline: `main` at `0750fe5` (`Merge pull request #74 from
  advatar/feat/tlsn-evidence-custody`).
- Local `main` and `origin/main` were identical and the worktree was clean.
- No local or remote topic branch existed after `git fetch --prune origin`; therefore no commits
  were waiting to be merged or branches waiting to be deleted.
- The checkpoint commit itself advances `main`; use `git pull --ff-only` and inspect the current
  tip before resuming.

## Current product state

- Generic acquisition and authenticated custody are no longer PID-only. A typed policy binds the
  credential configuration, format/type, issuer trust, mandatory claims, holder proof, lifecycle
  checks, display class and assurance boundary.
- The TLSNotary profile is the first generic development-attestation profile. It is explicitly
  development evidence and cannot be promoted to PID, EAA, QEAA, KYC or accredited identity
  evidence.
- The live Swift authorization-code coordinator, issuer trust resolution, system browser callback
  and wallet refresh path are present on `main`.
- PID eligibility is a policy prerequisite independent of credential assurance. A policy may
  require no PID, a current valid PID, or a PID-bound proof; satisfying the prerequisite never
  changes the acquired credential's classification.

## Immediate blockers

The latest `main` CI run at baseline, [run 30206800451](https://github.com/advatar/EUWallet/actions/runs/30206800451),
is red in three concrete places:

1. Rust: `crates/crypto-backend/tests/e2e_issuance.rs` has two `oid4vci::Env` initializers missing
   the required `device_public_key` field.
2. Android: the committed generated Kotlin UniFFI binding is stale; regeneration adds the
   `DemoWallet.developmentTrustList` and `developmentWuaJwt` API and checksums.
3. iOS: the native consumer UI test build cannot import `IdentityDocumentServicesUI` in
   `ios/DocumentProvider/EUWalletDocumentProvider.swift` on its selected test SDK/destination.

Do not claim TestFlight readiness until these gates are green and the signed archive/upload work
in #57 is complete.

## Exact resume order

1. Fix the three current CI regressions together as binding/platform fallout from the merged live
   issuance work; regenerate bindings from the same Rust revision and run the Rust, Android and
   iOS gates locally before pushing.
2. Finish #67 custody admission for exact
   `vct=dev.advatar.tlsn.evidence.1`, including status/expiry/deletion, then add the live VCIssuer
   acquisition-to-deletion interoperability test.
3. Complete the remaining generic-policy work in #69: configurable PID prerequisites, lifecycle
   parity, native decoders and formal assurance non-promotion correspondence.
4. Continue release work in #55, #58 and #57: official German eID/deferred recovery, full native
   visual fidelity and a reproducible signed TestFlight archive.
5. Keep the independent conformance, security-audit, operational and release-signing gates in
   `STATUS.md` honest; a green development suite is necessary but not certification.

## Safe resumption commands

```sh
git fetch --prune origin
git switch main
git pull --ff-only origin main
git status --short --branch
gh run list --repo advatar/EUWallet --branch main --limit 5
```

Before implementation, update the relevant `STATUS.md` item and GitHub issue. Work directly from
the current `main`, verify locally, commit and push, and delete a topic branch immediately after its
verified merge if a branch is required by repository policy.
