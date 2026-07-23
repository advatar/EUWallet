# Branch reconciliation — 2026-07-23

Issue: [#59](https://github.com/advatar/EUWallet/issues/59)

Baseline: `origin/main` at `5db42d0`.

## Decision

No topic branch contains functionality that still needs to be merged. Raw
ahead/behind counts were misleading for four branches:

- `agent/live-pid-probe` contains four patch-equivalent commits:
  `7556fc0` → `4342583`, `346f1f7` → `adb44b0`, `eb0d01b` → `d04d36d`,
  and `a983985` → `3201a35`.
- `agent/x509-rfc5280-residual` contains two patch-equivalent commits:
  `69a06f5` → `d04d36d` and `52cb184` → `3201a35`. Stable patch IDs match.
- `chore/protocol-revalidation` was squash-landed by `64fb903` (PR #45).
  Its effective `AGENTS.md` rules and status evidence are already on `main`.
- `fix/oidc-conformance-followup` was corrected and landed by `4590e78`
  (PR #47). The functional Rust, tests, Lean model, and evidence files at
  `c6a5c4a` and `4590e78` are identical. Merging the old branch would only
  restore stale status text.

The remote `fix/ios-durable-uniffi-contract` branch is an ancestor of `main`
through `ccd2552`. There are no open pull requests and
`git branch -r --no-merged origin/main` is empty.

## Ancestor-merged branches

The following local branches are direct ancestors of `main`:

- `agent/android-durable-store`
- `agent/android-ingress`
- `agent/dcql-global-plan`
- `agent/dcql-planner`
- `agent/durable-core-checkpoint`
- `agent/durable-lifecycle-wiring`
- `agent/full-wallet-foundation`
- `agent/ios-durable-store`
- `agent/oid4vci-authorization`
- `agent/oid4vci-credential-endpoint`
- `agent/oid4vci-foundation`
- `agent/p0-android`
- `agent/p0-ci`
- `agent/p0-flow-recovery`
- `agent/p0-ios`
- `agent/p0-issuer-binding`
- `agent/p0-mdoc-production`
- `agent/p0-mdoc-x5chain`
- `agent/p0-presentation-validity`
- `agent/p0-sdjwt-holdings`
- `agent/p0-vp`
- `agent/p0-x509-strict`
- `agent/txnlog-restore`
- `agent/typed-post-contract`
- `agent/x509-hardening-2`
- `chore/complete-branch-audit`
- `feat/pid-portrait-profile`
- `feat/prelaunch-security-audit`
- `feat/reference-wallet-interop`
- `fix/android-ingress-compilation`
- `fix/dcql-multiple-return`
- `fix/dcql-retention-intent`
- `fix/ios-durable-uniffi-contract`
- `fix/playwright-cve-2025-59288`
- `fix/release-ci-gates`
- `fix/uniffi-durable-symbols`
- `integrate/ahead-branches`
- `land/oidc-arf-conformance`

## Regression evidence

All checks were run on `main` before branch deletion:

- evidence-gate unit tests: 13 passed;
- `cargo fmt --all --check`: passed;
- `cargo clippy --workspace --all-targets --locked -- -D warnings`: passed;
- `cargo test --workspace --locked`: passed;
- all seven Lean targets built and all six regenerated oracle traces matched;
- every Tamarin model had verified lemmas and zero falsified lemmas;
- regenerated UniFFI bindings and `WalletCore.xcframework` verified with no
  tracked binding drift;
- Swift build and 141 Swift tests passed;
- Android clean, unit tests, lint, debug assembly, and release assembly passed;
- PID Playwright dependency install, high-severity audit, and syntax check
  passed with zero vulnerabilities;
- `cargo deny check` and `cargo audit` passed; the audit emitted only the two
  policy-allowed unmaintained warnings for `bincode` and `paste`;
- CycloneDX generation completed for 23 crates;
- Xcode simulator build passed and its bundle phase verified
  `CFBundleExecutable=EUWallet`.

All clean temporary worktrees and every reconciled local/remote topic branch
may therefore be removed. `main` remains the sole development branch.
