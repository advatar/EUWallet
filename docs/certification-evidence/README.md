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
| `sbom/` | CycloneDX SBOMs per release + cargo-audit results | CRA |
