# Official OIDF conformance runner

`run-local-suite.sh` starts the OpenID Foundation’s own conformance suite from
the pinned `release-v5.2.1` tag (`932b46f1e507871eb0b34621aaef65ff04442e6f`).
It uses the upstream Docker images and does not substitute repository tests for
official conformance results.

```sh
tools/oidf/run-local-suite.sh
open https://localhost:8443
```

Create and run the applicable plans in the suite UI/API:

- `oid4vci-1_0-issuer-test-plan`
- `oid4vci-1_0-issuer-haip-test-plan`
- `oid4vci-1_0-wallet-test-credential-issuance`
- `oid4vp-1final-verifier-happy-flow` and its negative verifier modules

The issuer or verifier under test must be reachable by the suite over an
HTTPS endpoint with a stable externally resolvable issuer/client URL. Local
Docker startup alone is not a conformance run. Exported results belong under
`docs/certification-evidence/oidf/<release>/` and are accepted only when
`tools/oidf/validate_evidence.py` verifies the pinned suite, source revision,
checksums, and official submission identifier.
