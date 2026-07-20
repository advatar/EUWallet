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
- [x] Restore hosted Swift, Kani and Tamarin CI compatibility with pinned/scoped tooling
      ([#13](https://github.com/advatar/EUWallet/issues/13)).
- [x] Make OpenID4VP response delivery HTTPS-only, endpoint-bound, mode-strict, and fail closed when
      `direct_post.jwt` encryption metadata is absent or invalid.
- [x] Propagate typed transport/signing failures through the Swift effect executor.
- [x] Make Secure Enclave key creation fail closed on physical devices.
- [x] Introduce a single verified credential-ingestion path for SD-JWT VC and mdoc.
- [x] Route OpenID4VCI-issued credentials through verified ingestion and reject untrusted,
      expired, wrongly typed, unbound, malformed, or revoked credentials.
- [x] Remove or test-gate unchecked credential-loading APIs from production FFI.
- [x] Bind the rendered consent/payment/QES contract to holder authorization across core and FFI
      ([#12](https://github.com/advatar/EUWallet/issues/12)).
  - [x] Attach the core-computed canonical authorization hash to each interactive render and
        require the exact operation ID and hash on approval before signing or disclosure.
  - [x] Mirror the closed contract in Swift and Android with stale, mismatched and cross-screen
        negative tests while preserving the same hash in audit/signing bindings.
- [x] Make credential status per-credential, issuer/list-bound, fresh, and resource-bounded.
- [x] [#5](https://github.com/advatar/EUWallet/issues/5): freeze and revalidate selected credential
      provenance/validity plus RP, issuer and status trust before consent, signing and delivery;
      reject clock rollback, and recheck WUA time when it authorizes issuance proofs.
- [x] Bind the credential issuer identity and EUDI service type to the authenticated certificate
      path instead of caller-provided metadata ([#8](https://github.com/advatar/EUWallet/issues/8)).
  - [x] Return a typed issuer-path result and preserve its authenticated leaf identity/service.
  - [x] Bind SD-JWT `iss` and mdoc catalogue authorization to that identity, treating shell
        `issuerId` only as a checked compatibility assertion.
  - [x] Reject issuer impersonation, cross-service paths, and CA issuer leaves with negative tests.
  - [x] Integrate service-scoped issuer identity/key/path evidence with presentation-time
        reauthentication while preserving atomic DCQL selection and missing-claim rejection.
  - The interim identity profile accepts one canonical HTTPS-origin URI SAN. Complete RFC 5280,
    extension processing and final EUDI certificate policy remain tracked by the next task.
- [ ] Replace the incomplete X.509 path validator with strict RFC 5280 and EUDI profile validation
      ([#11](https://github.com/advatar/EUWallet/issues/11)).
  - [x] Land the bounded first strict slice: deterministically construct leaf-to-anchor paths from
        unordered inputs with explicit budgets; reject ambiguous/looped/duplicate paths, unknown
        critical extensions and AKI/SKI mismatches; enforce BasicConstraints/pathLen and KeyUsage.
  - [ ] Enforce name constraints, certificate policies, algorithm constraints and service-specific
        EUDI PID, attestation/mdoc, RP, status and WUA/WIA profiles.
  - [x] Authenticate bounded mdoc `x5chain` evidence through the current strict service-scoped
        path at ingestion and presentation-time revalidation.
- [x] [#10](https://github.com/advatar/EUWallet/issues/10): complete RFC 9901 SD-JWT holding,
      presentation and consent integration without flattening authenticated disclosure structure.
  - [x] Verify recursive object/array disclosures with exact paths, parent dependencies, collision
        checks and fixed processing budgets in the `sdjwt` crate.
  - [x] Reject issuer-provided key-binding JWTs and require all SD-JWT VC protocol-control claims
        to be permanent issuer-payload values.
  - [x] Retain authenticated processed claims, exact paths and disclosure dependencies in private
        production storage while preserving the public fixture API.
  - [x] Select a minimal dependency-closed disclosure set for exact DCQL object/array paths and
        fail the complete request atomically when any path is unavailable.
  - [x] Include permanent PII and every incidental value revealed by selected dependencies in the
        holder-visible consent contract.
- [x] Bound DCQL request/query/path/value cardinality and fail closed on malformed queries or
      unsupported selection, trust and transaction-data modifiers.
- [ ] [#14](https://github.com/advatar/EUWallet/issues/14): implement final DCQL
      `credential_sets`, `claim_sets`, `trusted_authorities`, multiple-return, retention-intent and
      `transaction_data` semantics; they are rejected until enforceable end to end.
- [x] Accept genuine mdoc tagged dates and `x5chain`, and enforce exact doctype/namespace paths
      ([#6](https://github.com/advatar/EUWallet/issues/6)).
  - [x] Require and emit canonical CBOR tag-0 RFC 3339 `tdate` validity values, with malformed
        date/tag rejection and genuine-style fixtures.
  - [x] Bind mandatory mdoc catalogue claims to the exact doctype, namespace and element.
  - [x] Preserve structurally validated COSE label 33 `x5chain` header values without treating
        them as trust.
  - [x] Route bounded embedded `issuerAuth` `x5chain` evidence through the current strict,
        service-scoped validator at ingestion and presentation-time revalidation; caller-supplied
        paths and identities cannot override it.
  - Final approved EUDI issuer certificate/service profiles remain tracked by
    [#11](https://github.com/advatar/EUWallet/issues/11); the current profile stays deliberately
    bounded until those rules are normative and implemented.
- [x] [#7](https://github.com/advatar/EUWallet/issues/7): add CSPRNG-seeded monotonic operation IDs,
      exact result types, explicit terminal outcomes and reusable failure/cancel transitions across
      the Rust core, Swift shell and Android shell.
  - [x] Reject missing, stale, cross-flow, wrong-result and wrong-resource callbacks before a state
        transition; cap pending operations and stage effect batches atomically.
  - [x] Require presentation, payment and QES remote acknowledgements before success, and route
        every native infrastructure failure/cancellation back into a typed core reset.
  - Durable restoration of in-flight operations after process death remains part of encrypted
    persistence/lifecycle work; restart ID collision is mitigated with a 62-bit random namespace.
- [ ] [#9](https://github.com/advatar/EUWallet/issues/9): harden QR/deep-link and protocol
      networking against downgrade, redirect, resource-exhaustion and SSRF attacks.
  - [x] Reject HTTP, URL credentials/fragments/invalid ports, unsafe literal addresses and mixed
        public/private DNS answers; keep redirects disabled, stream responses under fixed caps and
        expose loopback only through an iOS debug-build factory.
  - [x] Enforce the same canonical host, reserved-address and bounded-DNS policy on iOS and Android,
        including ambiguous numeric/single-label hosts and current IPv6 allocation boundaries.
  - [x] Add protocol-specific bounded GET coverage and response media-type enforcement for issuer
        metadata, status lists, credential offers and presentation requests fetched by reference.
  - [x] Reject unregistered origins plus duplicate, conflicting, dropped and oversized security
        inputs in the iOS QR/deep-link parser.
  - [x] Add an Android Intent/QR ingress layer with the same scheme/verified-origin and ambiguity
        policy without inventing an application entry point in the current AAR-only module.
    - [x] Add a bounded pure parser for exact registered wallet schemes, explicitly allowlisted
          HTTPS origins and by-reference OpenID4VCI/OpenID4VP inputs, with hostile ambiguity tests.
    - [x] Expose a narrow Android `Intent` adapter without inventing an Activity or app manifest;
          the AAR host remains responsible for verified-link declarations and platform routing.
  - [ ] Split the generic POST effect into typed protocol response contracts before enforcing MIME;
        the shared OpenID4VP/payment/QES effect intentionally advertises `*/*` today.
  - [ ] Eliminate DNS validation-to-connect TOCTOU by binding the validated address to the TLS
        socket; URLSession and HttpsURLConnection currently perform their own second DNS lookup.

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
