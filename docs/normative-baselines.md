# Normative protocol baselines

Snapshot date: 2026-07-20. Certification-critical behavior is reviewed against these immutable
sources; a newer `main` revision does not silently change the implemented profile.

| Document | Version | Immutable source |
|---|---:|---|
| Natural-person PID Rulebook | 1.7 (2026-07-17) | Commit [`6d8f7f8422e5bf6c48186005b6835c078f762a67`](https://github.com/eu-digital-identity-wallet/eudi-doc-attestation-rulebooks-catalog/blob/6d8f7f8422e5bf6c48186005b6835c078f762a67/rulebooks/pid/pid-rulebook.md) |
| TS3 Wallet Unit Attestation | 1.5.2 (2026-05-26) | Reviewed release commit [`5924eb77ab4495d4dc0a874e54ac3e5de1fbd5b1`](https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/blob/5924eb77ab4495d4dc0a874e54ac3e5de1fbd5b1/docs/technical-specifications/ts3-wallet-unit-attestation.md) |

The protocol foundation also targets [OpenID4VCI 1.0 Final](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html)
and [HAIP 1.0 Final](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html).
Its current PID profile is only `mso_mdoc` with doctype `eu.europa.ec.eudi.pid.1`, or
`dc+sd-jwt` with VCT `urn:eudi:pid:1`.

These documents specify protocol and credential behavior; they do not by themselves authorize a
provider to issue German PID. PID-provider authorization remains a separate trusted-list and
governance input, distinct from WebPKI and successful metadata parsing.
