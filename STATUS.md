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

## Planned milestone — pre-launch security review

- [ ] Run documented Claude/Codex adversarial review for each release candidate.
- [ ] Select an independent external auditor and freeze audited inputs.
- [ ] Complete the scope in `docs/SECURITY_AUDIT.md`.
- [ ] Remediate critical/high findings with regression tests.
- [ ] Obtain independent re-review and publish a sanitized report.

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
- [x] Make credential status per-credential, issuer/list-bound, fresh, and resource-bounded,
      for **both** SD-JWT VC (`status` claim) and mso_mdoc (signed MSO `status` element). The mdoc
      presentation status gate is wired (`crates/wallet-core/tests/e2e_mdoc_status.rs`); a revoked or
      suspended mso_mdoc PID is refused before any device signature.
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
  - [x] Land the bounded second strict slice with checked positive/adversarial vectors:
    - [x] Process critical RFC 5280 name constraints for DNS, URI-host and IP GeneralNames across
          the whole constructed path, and fail closed on unsupported forms, distances or syntax.
    - [x] Enforce explicit certificate signature/SPKI compatibility and key-strength policy;
          support strong RSA PKCS#1 certificate verification without enabling RSA in JOSE/COSE.
  - [ ] Complete the residual RFC 5280 surface: canonical DN chaining, `directoryName` and
        `rfc822Name` constraints, policy tree/mappings/constraints/`anyPolicy`, and RSASSA-PSS.
    - [x] [#21](https://github.com/advatar/EUWallet/issues/21): implement bounded canonical DN
          chaining plus `directoryName` and `rfc822Name` constraint processing with positive and
          adversarial vectors; policy-tree processing and RSASSA-PSS remain separate work.
    - [x] [#22](https://github.com/advatar/EUWallet/issues/22): implement bounded RFC 5280
          certificate policy processing across the path, including mappings, constraints and
          `anyPolicy`; RSASSA-PSS and final EUDI service policy profiles remain separate work.
  - [ ] Freeze and enforce the normative algorithm and certificate profiles for EUDI PID,
        (Q)EAA/mdoc, RP, status and WUA/WIA services.
  - [ ] Prove those final profiles against official EUDI/PKITS suites and production certificate
        chains, including the applicable revocation and operational-validation rules.
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
      holder choice/optional-set opt-in, `trusted_authorities`, retention-intent and
      `transaction_data` semantics; unsupported modifiers remain rejected until enforceable.
  - [x] [#29](https://github.com/advatar/EUWallet/issues/29): implement bounded `multiple:true`
        selection and per-query VP Token arrays across authenticated holdings without partial
        required-set responses or silent single-credential downgrade. Selection is capped at 16
        eligible holdings per query and fails atomically above the cap; absent/false stays singular.
  - [x] [#31](https://github.com/advatar/EUWallet/issues/31): bind selected mdoc
        `intent_to_retain` declarations into holder-visible consent, authorization hashing and the
        transaction audit record; malformed and unsupported retention requests fail atomically.
        Retained elements use a canonical `[retained]` consent/audit label while absent/false stays
        transient, with no expansion of the minimized mdoc disclosure sent on the wire.
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
  - [x] Replace the generic POST effect with an explicit delivery profile and reject every
        result/profile mismatch across the Rust wire contract, Swift shell and Android shell.
    - [x] Enforce the bounded OpenID4VP 1.0 `direct_post` form/JSON/redirect contract end to end.
    - [x] Keep payment and QES delivery distinguishable but fail closed in the shared transport
          until dedicated, explicitly contracted PSP and CSC adapters are integrated.
  - [ ] Eliminate DNS validation-to-connect TOCTOU by binding the validated address to the TLS
        socket; URLSession and HttpsURLConnection currently perform their own second DNS lookup.

## Next phase — production clients and provider platform

- [x] [#50](https://github.com/advatar/EUWallet/issues/50): compute the canonical held-but-not-shared
      claim complement in the Rust core, bind it into the consent authorization hash, and enforce
      correspondence through Rust, Swift, Android, and formal-model tests before rendering it.
- [x] [#48](https://github.com/advatar/EUWallet/issues/48): replace the iOS developer demo shell
      with a consumer-grade, accessible wallet experience for non-technical and older users, hide
      protocol/diagnostic detail from release UI, preserve core-bound consent semantics, and add
      the app presentation/configuration needed for a controlled TestFlight beta. Release UI uses
      plain language and native Dynamic Type/VoiceOver controls; debug detail is compile-time
      gated; destructive history actions require confirmation; the app has icon/accent assets and
      an accurate privacy manifest. Swift package tests (137), on-simulator core tests (3), the
      regenerated UniFFI/XCFramework contract, and an unsigned Release device archive pass.
- [x] [#26](https://github.com/advatar/EUWallet/issues/26): restore the typed durable-checkpoint
      UniFFI boundary dropped during consolidation, enforce its required Swift/C/archive symbols,
      and prove a clean regenerated XCFramework and Xcode build. The regenerated arm64 device and
      Simulator slices pass explicit symbol verification; the app builds cleanly and both on-device
      simulator tests pass under Xcode 26.5.
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
  - [x] [#33](https://github.com/advatar/EUWallet/issues/33): restored green release CI by enforcing
        coordinator-only durable native composition, byte-stable UniFFI regeneration and narrowly
        trusted Tamarin installation dependencies; all required gates passed in
        [CI run 29901869421](https://github.com/advatar/EUWallet/actions/runs/29901869421).
  - [x] [#35](https://github.com/advatar/EUWallet/issues/35): remediated high-severity
        CVE-2025-59288 in the PID interoperability UI test, locked and audited the Node dependency
        graph, and verified that the live harness still classifies the issuer's `/dynamic/form`
        HTTP 500 without confusing it with a browser failure; all required gates passed in
        [CI run 29917911998](https://github.com/advatar/EUWallet/actions/runs/29917911998).
  - [x] [#36](https://github.com/advatar/EUWallet/issues/36): aligned SD-JWT and mdoc PID portrait
        validation with PID Rulebook 1.7, including explicit opt-out semantics, bounded JPEG
        validation, formal policy coverage and native adapter verification; all required gates
        passed in [CI run 29919838280](https://github.com/advatar/EUWallet/actions/runs/29919838280).
  - [x] [#39](https://github.com/advatar/EUWallet/issues/39): restored Android debug and release
        compilation, repaired the shared canonical ingress URL-validation contract, and added a
        permanent unit-test, lint, debug and release CI gate; all required gates passed in
        [CI run 29922532177](https://github.com/advatar/EUWallet/actions/runs/29922532177).
  - [x] [#41](https://github.com/advatar/EUWallet/issues/41): reconciled branches ahead of main,
        integrated the valid RFC 5280 residual work, rejected and reopened the unsourced PID-bound
        issuance implementation, and deleted all four merged or superseded remote branches; all
        required gates passed in
        [CI run 29924091658](https://github.com/advatar/EUWallet/actions/runs/29924091658).
  - [x] [#44](https://github.com/advatar/EUWallet/issues/44): revalidated every protocol and native
        release gate after branch reconciliation, and enforced a one-issue/one-branch lifecycle
        with ancestry verification and immediate post-merge cleanup in `AGENTS.md`; focused
        protocol conformance and wallet end-to-end suites, the RFC 5280 suite, all Lean models and
        oracle traces, all six Tamarin models, Android unit/lint/debug/release gates, regenerated
        UniFFI/XCFramework consistency, 134 Swift tests, and clean Xcode simulator build plus three
        on-simulator core tests all passed locally on 2026-07-22.
  - [x] [#46](https://github.com/advatar/EUWallet/issues/46): closed the residual OpenID4VP
        conformance gaps after `cd988a6`: the production boundary now accepts only bounded,
        non-empty ASCII URL-safe string nonces; the non-standard `credential_sets[].purpose`
        extension and conformance claim are removed; Lean proves the combined status and
        client-certificate admission policy while the evidence explicitly assigns concrete wire
        parsing/serialization to Rust tests. Formatting, warning-free clippy, the full Rust
        workspace suite, focused SD-JWT/mdoc/JWE/status tests and `WalletModel` all pass locally.
- [ ] Obtain the applicable German authority, CAB/BSI certification and Commission listing.

## Completed

- [x] Extensive architecture, security, compliance, interoperability, mobile, assurance and
      operational readiness review completed on 2026-07-20.
- [x] Full-wallet engineering epic opened as GitHub issue #1.
- [x] Android production-shell foundation added with a closed effect contract, StrongBox-first
      P-256 signing, HTTPS transport policy and release-artifact tests.
