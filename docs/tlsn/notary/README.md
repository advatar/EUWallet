# Deploying the TLSNotary notary gateway (`notary.euwallet.advatar.systems`)

This stands up the **real** (non‑demo) TLSNotary notary so the wallet's "Add web evidence"
produces genuine, notary‑signed web‑evidence credentials — not the `ENABLE_TLSN_DEMO` shortcut.

The notary gateway is the `tlsn-browser-demo` binary from `advatar/tlsn` (branch
`feat/tls12-real-notarization`). Despite the name it **is** the signing notary + proxy: it serves
`/ws/notary/{id}` (runs the MPC‑TLS verifier and signs a portable `SignedArtifact`),
`/api/sessions/{id}` (poll for the artifact), and `/ws/tcp?host=&port=` (a WebSocket→TCP bridge to
the target server, gated by a host allowlist).

> **TLS 1.2 only.** TLSNotary's MPC‑TLS supports TLS 1.2 (upstream limitation). The prover is pinned
> to offer TLS 1.2 so dual‑stack servers negotiate the supported protocol. Targets that are
> TLS‑1.3‑only will not notarize until upstream TLS 1.3 support lands.

## 1. Build the notary binary (on the host, or cross‑build and copy)

```bash
git clone -b feat/tls12-real-notarization git@github.com:advatar/tlsn.git
cd tlsn
~/.cargo/bin/cargo build --release -p tlsn-browser-demo
# → target/release/tlsn-browser-demo
install -m 0755 target/release/tlsn-browser-demo /Users/johansellstrom/services/tlsn-notary/tlsn-browser-demo
```

## 2. Generate the notary signing key (once) and derive the public key

The signing key is a 32‑byte P‑256 secret scalar (64 hex). Keep it secret, on the host only.

```bash
# secret (hex) — store in the file referenced by the plist, chmod 600, never commit:
openssl rand -hex 32 > /Users/johansellstrom/services/tlsn-notary/notary-signing-key.hex
chmod 600 /Users/johansellstrom/services/tlsn-notary/notary-signing-key.hex

# derive the SEC1 public key in the two encodings the rest of the system needs:
python3 - "$(cat /Users/johansellstrom/services/tlsn-notary/notary-signing-key.hex)" <<'PY'
import sys, base64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
k = int(sys.argv[1], 16)
pub = ec.derive_private_key(k, ec.SECP256R1()).public_key().public_bytes(
    serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
print("VCIssuer TLSN_TRUSTED_NOTARY_KEY (hex):", pub.hex())
print("wallet tlsn.notaryKeyB64u (base64url):", base64.urlsafe_b64encode(pub).rstrip(b'=').decode())
PY
```

## 3. Run it under launchd

Copy [`systems.advatar.tlsn-notary.plist`](systems.advatar.tlsn-notary.plist) to
`~/Library/LaunchAgents/` (or `/Library/LaunchDaemons/` for a system service), edit the
`--allow-host` entries to the domains you will notarize, then:

```bash
launchctl load ~/Library/LaunchAgents/systems.advatar.tlsn-notary.plist
```

It listens on `127.0.0.1:7047` (loopback only — Caddy terminates TLS in front).

## 4. TLS + WebSocket reverse proxy (Caddy)

Add the block from [`Caddyfile`](Caddyfile) to the host Caddyfile. Caddy obtains a certificate for
`notary.euwallet.advatar.systems` and reverse‑proxies to `127.0.0.1:7047`, upgrading WebSockets.

## 5. Wire the rest of the system

- **VCIssuer**: set `TLSN_TRUSTED_NOTARY_KEY` = the **hex** public key from step 2 (host env /
  launchd plist — see `VCIssuer/rust/.env.example`). VCIssuer then verifies real artifacts and mints
  the `dev.advatar.tlsn.evidence` credential.
- **Wallet**: set `tlsn.notaryURL` = `https://notary.euwallet.advatar.systems/` and
  `tlsn.notaryKeyB64u` = the **base64url** public key (both are `@AppStorage` defaults in
  `AddWebEvidenceView.swift`). This requires the wallet to ship an xcframework rebuilt from the
  `feat/tls12-real-notarization` fork (see `docs/tlsn/notary/xcframework.md`).

## Verifying end‑to‑end (no device required)

The headless prover CLI in the fork reproduces the whole flow against the running notary:

```bash
cargo run -p tlsn-ios --example notarize_cli -- \
  https://example.com/ https://notary.euwallet.advatar.systems/ <base64url-public-key>
# → OK http_status=200 … signature verified against the pinned notary key
```

## Allowlist / SSRF note

`--allow-host` restricts which origins the `/ws/tcp` proxy will connect to; `--allow-loopback` and
`--allow-private-ips` are OFF by default. Keep the allowlist tight — the proxy makes outbound TLS
connections on the notary's behalf.
