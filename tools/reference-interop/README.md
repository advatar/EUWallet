# EU reference-wallet interoperability harness

This harness treats the EU Digital Identity reference implementation and its
issuer/verifier environments as external interoperability oracles. It never
links their code into the wallet core and never turns a reference pass into a
certification claim.

## Run

```sh
tools/reference-interop/run.sh
```

The run records pinned repository metadata, endpoint reachability, supported
credential formats, and a redacted report under
`docs/certification-evidence/reference-interop/`. Set `REFERENCE_INTEROP_OUT`
to write elsewhere in CI. Real issuance/presentation runs are enabled only when
the corresponding endpoint and test credentials are supplied by the EU
environment.

## Expansion points

- `vectors/` holds shared, non-secret protocol vectors.
- `run.sh` is the stable entry point for local runners and scheduled CI.
- The report format is deliberately append-only and excludes tokens, claims,
  private keys, and user data.
- Add EU repository commits to `pinned-components.json` before consuming a new
  reference build.
