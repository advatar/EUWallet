# Live PID authorization probe — EU reference issuer (`issuer.eudiw.dev`)

Reproducible, dated evidence for the **machine-to-machine legs of a real OpenID4VCI authorization-code
PID issuance** against the production EU reference issuer, driven to the point where a human must
authenticate with an eID in a browser. Run:

```
tools/interop/pid-auth-probe.sh
```

- **Run date:** 2026-07-21
- **Result:** the probe reaches a **live PAR success** (HTTP 200, real `request_uri`) and emits the
  exact authorization URL for the eID step. **No completed issuance round-trip is claimed** — the
  eID authentication is interactive and outside this environment.

> No result here implies a conformance or certification pass. The external OpenID Foundation
> conformance run (separate harness) has still not been performed — see `interop.md`.

## Discovered facts (from the live service)

- `authorization_servers` is absent → the credential issuer **is** its own authorization server.
- **No `pre-authorized_code` grant** is offered. A real PID therefore *requires* the interactive
  `authorization_code` + eID flow; there is no automatable pre-auth shortcut.
- `token_endpoint_auth_methods_supported = ["public","attest_jwt_client_auth"]`,
  `code_challenge_methods_supported = ["S256"]`, `dpop_signing_alg_values_supported` includes `ES256`.
- Endpoints: PAR `…/pushed_authorization`, authorization `…/oidc/authorization`,
  token `…/oidc/token`, JWKS `…/oidc/static/jwks.json`, credential
  `https://backend.issuer.eudiw.dev/credential`, plus `nonce`/`notification`; `batch_size = 100`.

## The six remaining integration items — status against the live service

| # | Item | Status | Evidence |
|---|------|--------|----------|
| 1 | Register/configure wallet client metadata | **Confirmed (public client)** — the issuer accepts an unregistered **public** client; `attest_jwt_client_auth` (HAIP wallet attestation) is also available and is what a production build should use. | PAR `HTTP 200` for `client_id=advatar-eudi-wallet`. |
| 2 | Permitted redirect / deep-link / HTTPS callback | **Confirmed** — a custom-scheme deep link `eudi-openid4vci://authorize` is accepted at PAR. | PAR accepted the `redirect_uri`. |
| 3 | Complete browser/eID authorization round trip | **Blocked here (interactive).** Needs a human at a browser with an eID. The probe prints the exact authorization URL to open. | Authorization URL emitted; redirect target `eudi-openid4vci://authorize?code&state`. |
| 4 | Bind the raw callback exactly once into the Rust coordinator | **Owned by the core lifecycle coordinator**, not a probe concern: the `code` from the deep-link callback must enter the coordinator exactly once (idempotent, single-use), then drive token + credential. | `docs/DURABLE_LIFECYCLE.md`; STATUS.md #16. |
| 5 | Pin & validate EU trust anchors | **Closed (ingestion).** EU PID issuer CAs (`UT`, `EU`, ECDSA) and the staging reader CA (GlobalSign R45, RSA) validate under the x509 profile. Full leaf-to-anchor path validation for issued credentials = M2. | `crates/x509/tests/eudiw_anchors.rs` (2 tests PASS); anchors in `crates/x509/tests/vectors/eudiw/`. |
| 6 | Capture issuance + presentation evidence | **Partial.** The live PAR leg is captured + reproducible here. Full issuance evidence awaits the eID step + the token/credential legs; presentation evidence awaits a verifier round-trip. | this doc + `tools/interop/pid-auth-probe.sh`. |

## What remains for a completed live issuance (honest)

1. **The eID step (human).** Open the emitted authorization URL, authenticate, receive
   `code` + `state` at the wallet's deep-link.
2. **Token + credential legs (code, already built).** These are owned by the Rust core's
   OID4VCI 1.0 / HAIP transport (PAR/PKCE/RFC 9207/DPoP + nonce, WIA/KA per TS3 1.5.2, atomic
   `c_nonce` reservation, ES256 proof signing) — built and hardened *in isolation* (STATUS.md #18).
   Wiring them to the native browser callback + durable outbox is milestone **M1**; this probe
   deliberately does not reimplement them in shell.
3. **Then** verified ingestion of the returned PID (`eu.europa.ec.eudi.pid_vc_sd_jwt` /
   `eu.europa.ec.eudi.pid.1`) and a presentation to `verifier.eudiw.dev`.

**Bottom line:** we are *not* "ready for certification." We have now proven the first live wire leg
against the production issuer, established the client/redirect policy as fact, and pinned+validated
the EU trust anchors. The remaining round-trip is gated on the interactive eID step and on M1
(wiring the already-built token/credential transports to the native callback), and OIDF conformance
remains a separate, not-yet-run external gate.
