# OIDC + EU ARF conformance review — 2026-07-22

Full conformance review of the wallet behaviour core against the pinned normative baselines. Method:
a multi-agent audit (77 agents) — 11 dimension reviewers reading the real production source, each
non-conformant finding **adversarially verified** by an independent skeptic that tried to refute it
against the code and `STATUS.md`. **14 findings were refuted** (false positives / demo-vs-production
confusion / not-required-at-this-version) and dropped. Surviving: **4 blocker, 7 high, 7 medium,
25 low, 4 info**.

Baselines (see `docs/normative-baselines.md`): OpenID4VCI 1.0 Final; HAIP 1.0 Final; OpenID4VP 1.0;
SD-JWT VC + IETF SD-JWT; ISO/IEC 18013-5 (+ 18013-7 mdoc-over-OID4VP); EU ARF 1.x; PID Rulebook 1.7;
TS3 WUA 1.5.2. PID profile = `mso_mdoc:eu.europa.ec.eudi.pid.1` or `dc+sd-jwt:urn:eudi:pid:1`.

> Scope note: production behaviour-core paths were judged. Demo/test scaffolding (`demo.rs`, `tests/`,
> `*_for_testing`) was excluded from conformance credit. This review is an engineering assessment, not
> an official certification; the OpenID Foundation conformance run remains a separate, not-yet-run gate.

## Verdict

**Substantially sound, not yet interoperable/certification-ready.** The security-critical mechanics are
engineered to an unusually high standard, but a small number of concrete defects block live interop
across every presentation transport and root the trust hierarchy in an unpinned key. Most are fixable
without architectural upheaval; one (the nonce model) is architectural but high-leverage — one fix
unblocks four dimensions.

## Conformance matrix

### OIDC / protocol layer
| Standard | Status | Note |
|---|---|---|
| OpenID4VP 1.0 (presentation) | **partial** | Excellent security ordering + response-mode/uri hardening; broken by u64 nonce (blocker), mandatory non-standard `purpose` (high), missing client_id-prefix binding (high). |
| OpenID4VCI 1.0 + HAIP 1.0 (issuance) | **partial** | Spec-complete PAR+PKCE-S256+DPoP+Nonce-Endpoint+key-attestation transport exists but has **zero production callers**; wired driver runs a simplified abstract model. Tracked STATUS.md:165. |
| SD-JWT VC + KB-JWT | **partial** | Strong codec/disclosure/decoy/`_sd_alg`/`crit`/`alg:none`/`cnf` handling; KB-JWT nonce emitted as a JSON number, not the verifier's opaque string (shared nonce blocker). |
| ISO 18013-5 mdoc + mdoc-over-OID4VP | **partial** | Canonical CBOR, IssuerSigned/MSO/DeviceAuth + OID4VP SessionTranscript correct; u64 nonce corrupts the OID4VPHandover (blocker); proximity transport is skeleton (medium, tracked). |
| DCQL (OpenID4VP §6) | **substantially-conformant** | Atomic privacy-preserving credential_sets, claim_sets, values/type selection, intent_to_retain, cardinality budgets. |
| Crypto suite (JOSE/COSE; JWE) | **substantially-conformant** | Asymmetric-only alg enum, RSA/`none` structurally excluded, correct ECDH-ES(P-256)+A256GCM fail-closed JWE; COSE accepts DER ECDSA (low). |
| X.509 / RFC 5280 path validation | **substantially-conformant** | Genuine bounded path building, algorithm-confusion prevention, **enforced** name-constraints + certificate-policy trees; missing revocation/issuer-EKU/RSASSA-PSS (tracked/low). |

### EU ARF / framework layer
| Standard | Status | Note |
|---|---|---|
| ARF trust model (LOTL/TSL; ETSI TS 119 612) | **partial** | Real JWS/validity/rollback checks, but the list-operator root is a **host-supplied FFI key** with no pinned LOTL/TSL anchor. |
| Token Status List — revocation/suspension | **partial** | SD-JWT status fully gated; presentation gate **skips every mdoc source** → revoked/suspended mso_mdoc PID accepted. |
| ARF privacy — minimisation & selective disclosure | **conformant** | Enforced by construction on both paths; WYSIWYS consent-hash binding; PII-free tamper-evident audit log with GDPR erasure. |
| ARF privacy — unlinkability (Topic G) | **gap** | Single long-lived credential + reused device key; no batch/one-time-use; ZKP interface-only. Tracked STATUS.md:168. |
| PID Rulebook 1.7 — identity/format/binding | **conformant** | Exact doctype/VCT/format, namespace-bound claim paths, fail-closed cnf/deviceKey binding. |
| PID Rulebook 1.7 — mandatory attribute set | **partial** | Default catalogue omits `nationality` and `place_of_birth`; enforcement gate is correct, seed data incomplete. |
| eIDAS LoA High / WSCD key binding | **conformant** | sans-IO core never signs; iOS Secure Enclave + Android StrongBox-first non-exportable P-256; TEE downgrade opt-in, default-off. |
| TS3 WUA 1.5.2 | **partial** | Wallet-side use correct; WUA verification depth (nbf/iat, provider/WSCD claims) + issuer anchoring bounded. Tracked. |
| Extended: payment (PSD2 SCA) / QES / w2w / ZKP | **partial / honestly-scoped** | Real sans-IO cores; PSP/QTSP adapters + w2w hardening + ZKP proof-provider all fail-closed and tracked open. |

## Blockers & highs (verified)

### BLOCKER 1 — OpenID4VP nonce modelled as `u64` *(not tracked)*
Opaque string nonces are rejected before consent (`crates/oid4vp/src/lib.rs:829-835`); the nonce is
`u64` end-to-end (`:178`, SessionInfo, seen_nonces, `crates/sdjwt/src/lib.rs:71-72,591-597`). Even a
degenerate numeric nonce is emitted as a JSON number in the KB-JWT (`:752-759`), as `to_string()` in
the mdoc OID4VPHandover (`crates/wallet-core/src/lib.rs:4012`), and as a decimal string in the JWE
`apv` (`:4548`) — none reproduce the verifier's bytes. **Every conformant verifier (incl. the EUDI
reference) sends a high-entropy opaque string**, so the wallet fails closed on essentially all real
presentation requests. Breaks SD-JWT-VC, mdoc, and encrypted `direct_post.jwt` simultaneously.
**Fix:** model the nonce as an opaque `String` end to end; echo it byte-for-byte in the KB-JWT `nonce`,
the OID4VPHandover nonce, and the JWE `apv`.

### BLOCKER 2 — mso_mdoc PID presented without revocation/suspension check *(not tracked; STATUS.md:43 over-claims status as done)*
`presentation_status_gate` silently skips every mdoc source (`crates/wallet-core/src/lib.rs:1653`), so
a revoked/suspended `eu.europa.ec.eudi.pid.1` — a first-class pinned profile — is presented with no
status check. **Fix:** parse/persist the ISO 18013-5 MSO `status`/StatusList into `MdocHolding`; route
mdoc status through the same fail-closed `StatusProvider` path as SD-JWT (revoked/suspended must abort).

### HIGH 3 — mandatory non-standard top-level `purpose` rejects conformant requests *(not tracked)*
`purpose_is_declared` requires a non-empty top-level `purpose` (`crates/oid4vp/src/lib.rs:311-316,846`)
and aborts `PurposeUndeclared` before consent (`:491-493`). A conformant verifier never sends this.
**Fix:** remove the gate; derive purpose from DCQL `credential_sets.purpose` (which `dcql.rs` does not
yet parse) and/or RP registration metadata.

### HIGH 4 — no Client Identifier Prefix / client_id↔RP-key binding *(not tracked)*
`client_id` is taken opaque (`crates/oid4vp/src/lib.rs:822-826`) and `resolve_rp`/`check_relying_party`
ignore it (`crates/wallet-core/src/lib.rs:2248-2262`; `crates/x509/src/lib.rs:2001-2023`), permitting RP
impersonation within the RP-CA trust domain. **Fix (OpenID4VP §5.10 / HAIP `x509_san_dns`):** require the
leaf DNS SAN to equal the `client_id` host before accepting the request-object signature; bind client_id
to the authenticated leaf.

### HIGH 5 — spec-complete OID4VCI/HAIP transport is dead code *(tracked STATUS.md:165)*
The bounded `AuthorizationFlow`/`CredentialFlow` (`crates/oid4vci/src/{authorization,credential,foundation}.rs`)
is well-tested but unwired; wallet-core drives an abstract bool/u64 step model. **Fix:** wire the real
transport into the production issuance path so PAR/DPoP/dedicated-Nonce-Endpoint c_nonce/key-attestation
are constructed and verified in-core.

### HIGH 6 — trusted-list root is a host-supplied key (no pinned LOTL/TSL anchor) *(not tracked)*
The list-operator root is a wire/FFI-learned key (`crates/wallet-core/src/lib.rs:4693`); runtime key
substitution defeats the rollback protection. **Fix:** compile-in / provision the scheme-operator (LOTL)
root out of band and require the trusted list to chain to that pinned anchor.

### HIGH 7 — no unlinkability *(tracked STATUS.md:168)*
Single long-lived issuer credential + one reused device key per type. **Fix:** adopt OpenID4VCI batch
issuance for one-time-use pools and rotate/pairwise the holder key across verifiers (no ZKP dependency).

## Notable mediums
- **No CRL/OCSP revocation** for CA/issuer certs in path validation (RFC 5280 §6.3) — tracked.
- **Issuer leaf accepted without EKU/issuer key-purpose** (ISO 18013-5 §9.1.2) — tracked, gated on final issuer cert profile (#11).
- **In-person proximity transport emits placeholder CBOR** (ISO 18013-5 §8.2/§9.1) — tracked.
- **PID default catalogue omits `nationality` + `place_of_birth`** (PID Rulebook 1.7) — *not tracked*; enforcement is correct, seed data incomplete. Quick fix.
- **WUA verification depth bounded vs TS3 1.5.2** — tracked.

## Genuine strengths (verified, not marketing)
- **Correct OpenID4VP security ordering:** no disclosure before request-object signature verification; closed response-mode set; HTTPS response_uri exact-matched to a registered endpoint; durable nonce-replay set; audience mix-up defence (`crates/oid4vp/src/lib.rs:441-512`).
- **Asymmetric-only JOSE/COSE:** alg enum admits only ES256/384/EdDSA with a `compile_fail` proof RSA cannot exist; RSA confined to cert-only verification; `alg:none` hard-rejected everywhere.
- **Deterministic canonical CBOR** (shortest-form, definite-length, ordered keys, duplicate rejection, depth cap) — credentials round-trip to identical bytes.
- **Draft-17 SD-JWT VC** processor with recursive disclosure resolution, decoy/duplicate/unknown fail-closed, `_sd_alg` pinned, `cnf` pinned to a local EC key rejecting private material/`jku`/`x5u`.
- **Hardened DCQL planner** — atomic credential_sets with no partial-required leak, claim_sets in verifier order, values constraints, cardinality/depth/byte budgets.
- **Genuine RFC 5280 path validation** — bounded path building, algorithm-confusion prevention with a key-strength floor, **enforced** name-constraints + certificate-policy trees; type-level TLS-cert vs registered-RP distinction (reader-auth EKU).
- **WYSIWYS consent + PII-free tamper-evident audit log** with domain-separated hash chain + GDPR erasure.
- **Correct sans-IO/WSCD split** — core emits `Effect::Sign`, never holds keys; Secure Enclave / StrongBox-first non-exportable P-256, software fallback compiled out of device builds.
- **Honest scoping** of extended services — no overclaim; ZKP is interface-only with no proprietary scheme.

## Prioritised remediation roadmap
1. **BLOCKER 1 — nonce → opaque String** end to end (unblocks SD-JWT-VC + mdoc + encrypted `direct_post.jwt`). Highest leverage. Touches oid4vp, wallet-core, sdjwt + the Lean/Tamarin models + tests.
2. **BLOCKER 2 — mdoc presentation status gate** (revocation/suspension for mso_mdoc PID). Also correct the STATUS.md:43 over-claim.
3. **HIGH 3 + HIGH 4** — drop mandatory `purpose`; add Client Identifier Prefix + client_id↔leaf-SAN binding.
4. **HIGH 6** — pin the LOTL/scheme-operator trust root.
5. **HIGH 5 + HIGH 7** — wire the real OID4VCI/HAIP transport; adopt batch issuance for unlinkability.
6. **Quick wins** — PID mandatory attributes (`nationality`, `place_of_birth`); randomise `mdoc_generated_nonce`; validate `response_type`/request-object `typ`; reject `redirect_uri` co-present with `direct_post`.

## Tracking honesty
NOT tracked in STATUS.md (new findings): Blocker 1 (nonce), Blocker 2 (mdoc status — and STATUS.md:43
currently over-claims credential status as complete), High 3 (`purpose`), High 4 (client_id prefix),
High 6 (LOTL rooting), PID mandatory attributes. Already tracked: issuance wiring (165), unlinkability
(168), CRL/OCSP + issuer-EKU + proximity + WUA depth (11/21/22/163/166/169).
