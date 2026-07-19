# Mutation testing

Mutation testing measures **test adequacy**: it mutates the source (e.g. flips a comparison,
deletes a match arm, replaces a return value) and checks the test suite *fails* — i.e. that the
tests actually constrain behaviour, not merely execute it. A surviving ("missed") mutant is code a
test should have caught but didn't.

- **Tool:** `cargo-mutants` v27.1.0
- **Target:** `crates/oid4vp` — the security-critical OpenID4VP presentation machine (guards,
  request parsing, DCQL, response assembly).
- **Test scope:** the crate's own suite (`cargo mutants -p oid4vp --cargo-test-arg=-p
  --cargo-test-arg=oid4vp`). Restricting the test command to the crate is a deliberately *stricter*
  bar than running the whole workspace, and keeps the run fast (~4 min).
- **Run date:** 2026-07-19.

## Result

| Run | Caught | Missed | Unviable | Viable | Score (caught / viable) |
|---|---|---|---|---|---|
| Initial | 52 | 21 | 8 | 73 | 71% |
| After test-hardening | **73** | **0** | 8 | 73 | **100%** |

"Unviable" mutants are ones that do not compile (e.g. replacing a `&str` return with `()`); they
are excluded from the score, as is standard.

## What the initial run found — and how it was closed

The first run surfaced 21 missed mutants: the DCQL selection accessors
(`first_credential_id`, `requested_vcts`, `requested_doctypes`), the request-object alg parsing
(ES256 / ES384 / EdDSA arms and the JWS part-count check), the `redirect_uri_is_registered` guard's
comparison, and the `base64url` / `kb_jwt_signing_input` helpers — all reachable by the crate's
public surface but only exercised end-to-end by `wallet-core` integration tests, out of this
crate-local scope.

Rather than widen the scope to hide them, the gaps were **closed by adding crate-local tests**
(`crates/oid4vp/src/dcql.rs` and `crates/oid4vp/src/lib.rs` `internal_tests`) that pin each
behaviour: alg round-trips, malformed-JWS rejection, the redirect-registration comparison, the
KB-JWT nonce/aud binding, and DCQL accessor/dedup results. The re-run then caught every viable
mutant.

## Scope & honesty

- This covers **`oid4vp`** only — the highest-value protocol crate. The other crates
  (`oid4vci`, `payment`, `mdoc`, `sdjwt`, `trust`, …) have not yet been mutation-tested; extending
  the run workspace-wide is planned (it is slow, so it will run as a scheduled CI job, not per-PR).
- A 100% crate-local mutation score means the crate's own tests are adequate against the generated
  mutation operators — it is **not** a proof of correctness (that is the Lean/Tamarin tiers) and
  not a statement about crates not yet measured.

Reproduce:

```
cargo install cargo-mutants --locked
cargo mutants -p oid4vp --cargo-test-arg=-p --cargo-test-arg=oid4vp --timeout 60
```
