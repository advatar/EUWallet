# Interoperability — reference environment

Reproducible probe of the EU Digital Identity Wallet **reference environment**, over the
platform's TLS stack (`curl`; Rust-side TLS is deliberately out of the dependency budget — TLS is
the platform's job). Run:

```
tools/interop/probe.sh
```

- **Source:** `tools/interop/probe.sh`
- **Run date:** 2026-07-19
- **Result:** **PASS** (reachability + wire-shape).

## Latest run

```
[issuer]   GET https://issuer.eudiw.dev/.well-known/openid-credential-issuer -> HTTP 200
           credential_issuer = https://issuer.eudiw.dev
           configurations    = 27  (sd-jwt: 11, mso_mdoc: 16)
           wallet-supported SD-JWT VC configs present: yes
           e.g. eu.europa.ec.eudi.diploma_vc_sd_jwt, eu.europa.ec.eudi.ehic_sd_jwt_vc,
                eu.europa.ec.eudi.hiid_sd_jwt_vc, eu.europa.ec.eudi.pid_vc_sd_jwt
[verifier] GET https://verifier.eudiw.dev/ -> HTTP 200
```

The iOS app independently performs the same live fetch on its real URLSession stack (the Connect
screen's "Probe issuer.eudiw.dev" action), confirming HTTP 200 and the 27 configurations from the
device/simulator networking path — see `ios/App/ConnectView.swift`.

## What this covers — and what it does NOT

**Covers (coded, dated, reproducible):**

- The reference issuer's OpenID4VCI metadata endpoint is live and well-formed.
- It offers credentials in the SD-JWT VC format this wallet implements (11 configurations,
  including `eu.europa.ec.eudi.pid_vc_sd_jwt`).
- The reference verifier is reachable.

**Does NOT cover (requires an external assessment — NOT closeable by our code alone):**

- A full **OpenID Foundation conformance** run. The OIDF suite is the objective interop bar; its
  self-certification program opened 2026-02-26 and runs against the Foundation's own harness. No
  conformance pass is claimed here.
- A completed **issuance or presentation round trip against the live reference issuer/verifier**.
  The reference issuer's PID issuance requires a browser/eID authorization step, and a live
  presentation requires pinning the reference trust anchors — both are integration work beyond
  metadata reachability. Tracked as the next milestone; not claimed as done.

No result on this page implies a conformance or certification pass.
