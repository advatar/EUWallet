# Full-wallet delivery status

Tracking issue: [#1 — Build an independent full German EUDI Wallet solution](https://github.com/advatar/EUWallet/issues/1)

## Product direction

Build an independent, competing German EUDI Wallet solution. The certification object includes
the native clients, Rust core, wallet-provider services, trust/status/WUA infrastructure, secure
cryptographic components, release pipeline, and operating processes. Demo-only behavior is not part
of the production target.

Government provision, mandate or recognition; accredited certification; and Commission
notification remain external launch gates. Engineering must produce the complete evidence and
operational solution needed to enter those processes.

## Active phase — P0 trustworthy foundation

- [x] Repair CI paths and make every claimed assurance gate fail closed.
- [x] Make OpenID4VP response delivery HTTPS-only, endpoint-bound, mode-strict, and fail closed when
      `direct_post.jwt` encryption metadata is absent or invalid.
- [x] Propagate typed transport/signing failures through the Swift effect executor.
- [x] Make Secure Enclave key creation fail closed on physical devices.
- [x] Introduce a single verified credential-ingestion path for SD-JWT VC and mdoc.
- [x] Route OpenID4VCI-issued credentials through verified ingestion and reject untrusted,
      expired, wrongly typed, unbound, malformed, or revoked credentials.
- [x] Remove or test-gate unchecked credential-loading APIs from production FFI.
- [ ] Bind the rendered consent contract to holder authorization across core and FFI.
- [x] Make credential status per-credential, issuer/list-bound, fresh, and resource-bounded.
- [x] [#5](https://github.com/advatar/EUWallet/issues/5): freeze and revalidate selected credential
      provenance/validity plus RP, issuer and status trust before consent, signing and delivery;
      reject clock rollback, and recheck WUA time when it authorizes issuance proofs.
- [ ] Bind the credential issuer identity and EUDI service type to the authenticated certificate
      path instead of caller-provided metadata.
- [ ] Replace the incomplete X.509 path validator with strict RFC 5280 and EUDI profile validation.
- [ ] Implement recursive RFC 9901 disclosures, reject invalid issued SD-JWT+KB/control claims,
      and include permanently visible PII in consent.
- [ ] Accept genuine mdoc tagged dates and `x5chain`, and enforce exact doctype/namespace paths.
- [ ] Add flow operation IDs, explicit terminal outcomes and recoverable failure/cancel transitions.

## Next phase — production clients and provider platform

- [ ] Separate production and demo iOS targets; add encrypted persistence and lifecycle flows.
- [ ] Build the Android client with equivalent StrongBox/KeyMint security behavior.
- [ ] Implement German eID/eAT onboarding, live PID issuance, RP registration, trust, WIA/WUA,
      status and revocation integration.
- [ ] Implement final OpenID4VCI/OpenID4VP/HAIP profiles and ISO 18013-5 proximity transports.
- [ ] Build wallet-provider, remote WSCA/WSCD/HSM, WUA/WTE, status/revocation and device-management
      services.
- [ ] Complete pseudonyms, unlinkability, wallet-to-wallet, dashboard, reporting, erasure,
      portability and QTSP-backed QES.
- [ ] Complete German localization, EN 301 549/BITV accessibility and GDPR product controls.

## Assurance and launch phase

- [ ] Replace keyword traceability with reviewed applicability and behavior-level evidence.
- [ ] Bind formal oracle tests to production state machines.
- [ ] Complete the TOE, threat model, DPIA, key lifecycle, algorithm profile and KAT evidence.
- [ ] Pass OIDF, FCAF, German sandbox and cross-border interoperability suites.
- [ ] Complete independent review, penetration testing, red team and bug bounty.
- [ ] Establish signed reproducible releases, SBOM/provenance, incident response, revocation,
      support, monitoring, rollback and disaster recovery.
- [ ] Obtain the applicable German authority, CAB/BSI certification and Commission listing.

## Completed

- [x] Extensive architecture, security, compliance, interoperability, mobile, assurance and
      operational readiness review completed on 2026-07-20.
- [x] Full-wallet engineering epic opened as GitHub issue #1.
- [x] Android production-shell foundation added with a closed effect contract, StrongBox-first
      P-256 signing, HTTPS transport policy and release-artifact tests.
