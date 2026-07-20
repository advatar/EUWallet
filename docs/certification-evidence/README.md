# Certification evidence set

Passing FCAF (functional conformance) is **not** full wallet certification (register:
*certification & conformance* module). Certification under CIR 2024/2981 + EUCC also requires
cybersecurity evaluation, privacy assurance, and operational assurance — handled by separate
processes. This directory is the living evidence repository the Conformity Assessment Body
(CAB) and the certification scheme will draw on. Populate each file as the corresponding
module reaches its definition-of-done (plan Section 12).

| File | Purpose | Register anchor |
|---|---|---|
| `threat-model.md` | TOE boundary, assets, attacker model, mitigations | EUCC / ISO 15408 |
| `key-lifecycle.md` | Key generation, non-exportability, attestation, rotation, destruction | 2024/2979, TS03 |
| `algorithm-allow-list.md` | Exact algorithms + parameters the wallet uses | ENISA crypto guidance |
| `dpia.md` | Data Protection Impact Assessment | GDPR |
| `known-answer-tests.md` | KAT results for every crypto operation (via crypto-traits backend) | EUCC |
| `fcaf-reports/` | Pinned FCAF v0.0.7 run outputs from CI | FCAF |
| `sbom/` | **Published** CycloneDX 1.3 SBOMs (21 crates; regen via `tools/evidence/sbom.sh`) | CRA |
| `verification-report.md` | Reproducible Tier 0–3 results (`tools/evidence/generate.sh`) | EUCC |
| `perf-benchmarks.md` | Hot-path latency/throughput vs. the real backend (`crates/benches`) | — |
| `mutation-testing.md` | cargo-mutants score for the presentation machine | EUCC (test adequacy) |
| `interop.md` | Reference-environment reachability + wire-shape probe (`tools/interop/probe.sh`) | interoperability |
| `openid-self-certification.md` | OpenID Foundation profile matrix, evidence retention, submission and renewal gate | OIDF self-certification |
| `conformance-run-2026-07-21.md` | Reproducible local EU/EUDI test run and explicit external blockers | engineering evidence |
| `hybrid-pq-boundary.md` | ARF-preserving hybrid post-quantum design boundary and approval gates | crypto/certification |
| `payment-sca.md` | PSD2 RTS Art. 4–5 dynamic-linking traceability | 2018/389 |

## External conformance suites (where to run real interop/certification tests)

Our in-repo `tools/evidence/generate.sh` covers Tiers 0–3 (traceability, implementation tests,
machine-checked proofs, symbolic protocol analysis). Full conformance/certification is run against
these EXTERNAL, official suites. The sans-IO core and `shell-io` exercise the local OpenID4VP
socket path, but the issuance harness still uses a synthetic token/credential contract. It is not
an OpenID4VCI 1.0 or HAIP 1.0 conformance adapter; that production work is tracked in
[#18](https://github.com/advatar/EUWallet/issues/18):

| Suite | Covers | Access | Maps to our crates |
|---|---|---|---|
| **OpenID Foundation Conformance Suite** — open source (GitLab), free, run locally or on OIDF servers; **self-certification opens Feb 2026** | OpenID4VP 1.0, OpenID4VCI 1.0, HAIP 1.0 (SD-JWT VC + ISO mdoc profiles) | Free/open — https://openid.net/certification/about-conformance-suite/ | `oid4vp`, `oid4vci`, `sdjwt`, `presenter`, `shell-io` |
| **EU reference test app** `eu-digital-identity-wallet/eudi-doc-testing-application` | Functional E2E wallet tests | Open — GitHub | end-to-end via `wallet-core` + `shell-io` |
| **Fime EUDI Wallet Test Suite** | ISO/IEC 18013-5, 18013-7, OpenID4VP, OpenID4VCI, SD-JWT, ETSI; simulates RP + issuer | Commercial | `iso18013-5`, `mdoc`, `oid4vp`, `oid4vci`, `sdjwt` |
| **EBSI-VECTOR** wallet conformance | Holder-wallet conformance & interoperability method | EU project | presentation/issuance flows |
| **National CAB** (FCAF-based functional testing) | Functional conformance under CIR 2024/2981 + EUCC, before a Member State issues the Wallet Solution | Accredited Conformity Assessment Body | whole wallet |

Note: passing FCAF/OIDF conformance is functional interop, not full certification — EUCC
cybersecurity evaluation, the DPIA, and operational assurance are separate (see the table above).
