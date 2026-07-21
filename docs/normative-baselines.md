# Normative protocol baselines

Snapshot date: 2026-07-20. Certification-critical behavior is reviewed against these immutable
sources; a newer `main` revision does not silently change the implemented profile.

| Document | Version | Immutable source |
|---|---:|---|
| Natural-person PID Rulebook | 1.7 (2026-07-17) | Commit [`6d8f7f8422e5bf6c48186005b6835c078f762a67`](https://github.com/eu-digital-identity-wallet/eudi-doc-attestation-rulebooks-catalog/blob/6d8f7f8422e5bf6c48186005b6835c078f762a67/rulebooks/pid/pid-rulebook.md) |
| TS3 Wallet Unit Attestation | 1.5.2 (2026-05-26) | Reviewed release commit [`5924eb77ab4495d4dc0a874e54ac3e5de1fbd5b1`](https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/blob/5924eb77ab4495d4dc0a874e54ac3e5de1fbd5b1/docs/technical-specifications/ts3-wallet-unit-attestation.md) |
| OAuth Attestation-Based Client Authentication | draft-07 (2025-09-15) | [`draft-ietf-oauth-attestation-based-client-auth-07`](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-attestation-based-client-auth-07) as pinned by OpenID4VCI 1.0 Final |
| SD-JWT VC for the HAIP profile | draft-13 (2025-11-06) | [`draft-ietf-oauth-sd-jwt-vc-13`](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-13) as superseded and pinned by HAIP 1.0 Final |

The protocol foundation also targets [OpenID4VCI 1.0 Final](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html)
and [HAIP 1.0 Final](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html).
Its current PID profile is only `mso_mdoc` with doctype `eu.europa.ec.eudi.pid.1`, or
`dc+sd-jwt` with VCT `urn:eudi:pid:1`.

HAIP 1.0 Final explicitly supersedes OpenID4VCI's SD-JWT VC draft-11 reference with draft-13.
The shared `sdjwt` crate is independently pinned to draft-17, so draft-17 processing is not treated
as proof of German HAIP compatibility. A `dc+sd-jwt` PID returned by the transport remains
unverified and must not enter holdings until a versioned draft-13-compatible ingestion path has
validated the protected `x5c` issuer mechanism, signature/path and ecosystem authorization, holder
binding, validity, disclosures and status. No compatibility between the two drafts is inferred.

The isolated authorization transport implements the authorization-code path only. It requires
`attest_jwt_client_auth` plus ES256 Client Attestation and PoP metadata, scopes each Client Instance
Key to the selected Authorization Server, implements draft-07 challenge retrieval/rotation, and
constructs a fresh `OAuth-Client-Attestation-PoP` locally for PAR and token requests. Returned WSCD
signatures are verified before use. A backend supplies only the Wallet Attestation and does not see
the local key reference, Authorization Server, endpoint, challenge or PoP signing input. The
transport accepts TS3's `x5c`-derived Wallet Provider identity without requiring a non-standard
`iss`, verifies the compact ES256 WIA against its leaf certificate, requires the TS3 wallet,
solution-certification and client-status claims, enforces a lifetime below 24 hours and applies the
effective PID client-status maintenance period. It supports the privacy-safe TS3 single-issuance
policy; optional provider-scoped status-entry reuse requires a durable provider/status mapping and
is not implemented. External PKI path construction, revocation, trust-anchor exclusion, live
status resolution and ecosystem authorization remain mandatory before the boundary is trusted.

RFC 9449 DPoP remains separate and is emitted for the token and Credential requests. A PAR handle
is exposed with its dispatch deadline (`expires_in` is restricted to 1–599 seconds), after which the
native shell must not open it. OpenID4VCI 1.0 Final obtains `c_nonce` from the separate Nonce
Endpoint, so legacy token-response `c_nonce` values are not promoted into credential-proof state.
The credential machine atomically reserves each `c_nonce` before proof signing and globally burns
the holder public-key thumbprint before requesting a KA. The attestation provider sees neither the
local key reference nor `c_nonce`. The returned compact KA is ES256-verified against its `x5c` leaf,
bound to the requested JWK, checked for required certification, exact status-list shape, effective
PID status-maintenance period and high key-storage/user-authentication assurance, then globally
reserved before proof signing. These are external durable transaction contracts, not a claim that
either native client already implements their ledgers.

TS3 permits a KA and its attested public key to be used at most once. Consequently the Credential
request is never re-dispatched after either `invalid_nonce` or a Credential Endpoint DPoP nonce
challenge: the isolated flow returns `CredentialKeyRotationRequired`. Production orchestration
must destroy/rotate the holder key, acquire a genuinely new KA and safely restart the issuance.
Client Instance, DPoP and credential-holder keys must be pairwise distinct by both key reference
and canonical public JWK; signer results are verified locally.

Successful Credential transport yields only an `UnverifiedCredential`, including any bounded
`notification_id`. WIA/KA ecosystem trust, draft-13 SD-JWT VC or mdoc verified ingestion, native
streaming/redirect/deadline enforcement, durable reservation storage, fresh-key rotation,
notification delivery and PID Provider trust all remain open launch work.

These documents specify protocol and credential behavior; they do not by themselves authorize a
provider to issue German PID. PID-provider authorization remains a separate trusted-list and
governance input, distinct from WebPKI and successful metadata parsing.
