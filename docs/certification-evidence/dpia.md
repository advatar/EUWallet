# Data-protection impact assessment — engineering baseline

## Purpose and status

This document records the repository's current data-flow and minimization controls. It is an
engineering input to, not a substitute for, the controller's GDPR DPIA, legal-basis decision,
records of processing, consultation, or supervisory-authority process. The deploying wallet
provider must complete those organizational decisions before production processing.

## Data and flows

| Data | Source and destination | Repository control |
|---|---|---|
| PID, mdoc, SD-JWT VC, and disclosed attributes | Authenticated issuer → local wallet; selected subset → authenticated verifier | Central verified ingestion, exact credential policy/type checks, DCQL minimization, holder-visible consent |
| Holder keys and wrapped PQ seeds | Generated on device; used by platform custody adapter | Non-exportable classical keys where supported; biometric-gated, device-only wrapping; plaintext PQ seed remains inside the Rust/native custody operation |
| Status and trust evidence | Trusted issuer/list/provider → wallet | Bounded fetch, issuer/list binding, freshness and rollback checks; no credential values are sent as status-query metadata by the core |
| Transaction history | Wallet operation → local audit log/export | Claim paths and committing hashes rather than claim values; chain-preserving redaction and complete wipe APIs |
| Protocol metadata | Issuer/verifier and wallet | Bounded retention necessary for replay, authorization, trust, and incident evidence; no analytics dependency or telemetry endpoint in the core |

## Necessity, proportionality, and rights controls

- Disclosure selection is dependency-closed and request-scoped; a request fails atomically when
  its required set cannot be satisfied without unsupported behavior.
- Consent displays authenticated resolved values and retention intent before authorization.
- Export integrity checking, per-document deletion, transaction-log redaction, and full wipe are
  implemented core capabilities. Shipping clients must expose, authenticate, and test these flows.
- Experimental credentials and telemetry classifications are separated from certified catalogue
  behavior and are default-off.
- The core does not emit analytics. Deployments must inventory any telemetry, crash reporting,
  backups, push services, provider logs, and support systems added outside this repository.

## Risks and mitigations

High-impact risks are over-disclosure, issuer/verifier correlation, device compromise, coerced or
misleading consent, stale status/trust, recovery/export leakage, and operational log leakage.
Implemented mitigations include selective disclosure, exact consent hashing, authenticated
ingestion, secure custody interfaces, freshness/replay checks, bounded redacted audit data, and
encrypted experimental recovery. Residual correlation remains possible through verifier-visible
attributes, network metadata, credential identifiers, device/platform services, and ecosystem
behavior; the experimental ZK work is not a production mitigation.

## Required controller closure

Before launch, the controller must document legal bases and roles, purposes and retention periods,
data-subject request handling, child/vulnerable-user considerations, international transfers,
processor contracts, breach response, backup deletion, support access, and residual-risk approval.
The accessibility, production persistence, provider operations, independent security review, and
certification gates in `STATUS.md` also remain prerequisites where applicable.

Review this baseline whenever data categories, recipients, telemetry, backup/recovery, provider
services, or credential policies change.
