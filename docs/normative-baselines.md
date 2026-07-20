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

The isolated authorization transport implements the authorization-code path only. HAIP client
authentication is represented as fresh, externally acquired `OAuth-Client-Attestation` and
`OAuth-Client-Attestation-PoP` headers at both PAR and token endpoints; it is not replaced by DPoP.
RFC 9449 DPoP is emitted for the token request, with a PAR-supplied nonce allowed to seed the token
proof and bounded token-endpoint nonce retries. A PAR handle is exposed with its dispatch deadline
(`expires_in` is restricted to 1–599 seconds), after which the native shell must not open it.
OpenID4VCI 1.0 Final obtains `c_nonce` from the separate Nonce Endpoint, so legacy token-response
`c_nonce` values are not promoted into credential-proof state. Trusted Wallet Attestation minting,
the Nonce/Credential Endpoints, native transport and provider trust remain open launch work.

These documents specify protocol and credential behavior; they do not by themselves authorize a
provider to issue German PID. PID-provider authorization remains a separate trusted-list and
governance input, distinct from WebPKI and successful metadata parsing.
