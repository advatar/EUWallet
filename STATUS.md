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
- [x] [#17](https://github.com/advatar/EUWallet/issues/17): pin current reviewed GitHub Actions,
      declare least-privilege workflow permissions and reject mutable/deprecated CI dependencies.
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
  - [x] Land the bounded second strict slice with checked positive/adversarial vectors:
    - [x] Process critical RFC 5280 name constraints for DNS, URI-host and IP GeneralNames across
          the whole constructed path, and fail closed on unsupported forms, distances or syntax.
    - [x] Enforce explicit certificate signature/SPKI compatibility and key-strength policy;
          support strong RSA PKCS#1 certificate verification without enabling RSA in JOSE/COSE.
  - [ ] Complete the residual RFC 5280 surface: canonical DN chaining, `directoryName` and
        `rfc822Name` constraints, policy tree/mappings/constraints/`anyPolicy`, and RSASSA-PSS.
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
- [ ] [#14](https://github.com/advatar/EUWallet/issues/14): implement final DCQL selection and
      transaction binding semantics without over-disclosure or partial responses.
  - [x] Replace opaque `claim_sets` and `credential_sets` with bounded OpenID4VP 1.0 types; ignore
        bounded unknown extensions; select the first satisfiable claim option; and integrate atomic,
        globally minimised required Credential Set planning, minimised consent and per-query VP
        arrays for supported SD-JWT VC and mdoc holdings; omit optional sets until the holder
        explicitly opts in.
  - [ ] Add holder-driven opt-in for optional sets and choice when several Credential Set options
        remain equally minimal after deterministic planning; implement authenticated
        `trusted_authorities`, `multiple=true`, mdoc retention intent and typed `transaction_data`.
        These modifiers remain rejected until each is bound end to end.
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
- [ ] [#15](https://github.com/advatar/EUWallet/issues/15): make Android a first-class,
      independently shippable wallet client with the same core contract and assurance gates as iOS.
  - [x] Require hosted Android unit tests, lint and release assembly on every pull request.
  - [ ] Integrate generated UniFFI bindings plus production networking, trust, issuance and
        lifecycle adapters; demo/test doubles must not be reachable from release builds.
  - [ ] Add the production app, StrongBox/KeyMint capability policy, encrypted rollback-resistant
        persistence, process-death recovery, accessibility and physical-device release evidence.

## Next phase — production clients and provider platform

- [ ] [#16](https://github.com/advatar/EUWallet/issues/16): implement versioned encrypted durable
      wallet state and crash-safe lifecycle recovery across the Rust core, iOS and Android.
  - [x] Make transaction-log append and restoration bounded and fallible; atomically reject
        non-canonical chains unless they match an externally anchored head before any durable
        wallet-state schema can import audit history.
  - [x] Add the iOS WalletShell encrypted dual-slot storage primitive with strict bounded envelopes,
        a Keychain generation/digest anchor, compare-and-swap commits, backup/file-protection policy
        and crash/tamper tests; Core serialization and lifecycle wiring remain separate work.
  - [x] Restore only bounded authenticated holdings, replay state and audit data through current
        trust/WUA/device-key revalidation; never revive pending operations or protocol sessions.
    - [x] Add a migration-ready canonical CBOR checkpoint v1 with explicit magic, version and
          authenticated-envelope generation; hard 32 MiB and structural allocation budgets; and
          deterministic rejection of duplicate, non-canonical, unknown, trailing or future data.
    - [x] Export only production credential source evidence, sorted replay memberships and the
          externally anchored transaction log; document the legacy numeric issuance nonce in v1
          and exclude every active protocol machine, pending operation, callback and fixture.
    - [x] Restore into a staged core only after current clock, trust-list sequence, device key and
          high-assurance WUA checks; reauthenticate every credential and atomically retain the
          current environment while replacing only authenticated durable state.
    - [x] Prove exact resource boundaries, deterministic encoding, context/tamper/corruption
          rejection, credential and transaction revalidation, zero partial mutation, and that
          process-death restoration cannot revive stale callbacks or operation identifiers.
  - [ ] Complete atomic, rollback-detecting, device-bound platform storage and lifecycle wiring
        with backup exclusion, corruption/migration/process-death tests and no release-build
        fallback to demo storage.
    - [x] Add the bounded, authenticated and encrypted iOS storage primitive.
    - [ ] Add the equivalent Android Keystore-backed storage primitive.
    - [ ] Wire both stores to the Core checkpoint boundary and prove crash-safe effect delivery.
- [ ] Build the Android client with equivalent StrongBox/KeyMint security behavior.
- [ ] [#18](https://github.com/advatar/EUWallet/issues/18): implement German eID/eAT onboarding and
      HAIP-compliant live PID issuance through an accepted German PID Provider.
  - [ ] Pin OpenID4VCI 1.0 Final, HAIP 1.0 Final, ARF 2.9.0, PID Rulebook 1.7, TS3 1.5.2,
        AusweisApp SDK 2.5.4 and applicable CIR/BSI baselines, including exact source commits for
        EU documents maintained on `main`.
    - [x] Record final OpenID4VCI/HAIP sources and immutable PID Rulebook 1.7 and TS3 1.5.2 source
          commits in `docs/normative-baselines.md`; remaining German/ARF/SDK baselines stay open.
  - [ ] Replace the synthetic issuance model with bounded real offers, issuer and AS metadata,
        distinct PID-provider trust, current PID configuration selection and fail-closed feature
        negotiation.
    - [x] Add an isolated final-1.0 foundation with a hard-bounded duplicate-aware JSON boundary,
          canonical HTTPS discovery, typed offers/metadata and authorization-code-only German PID
          profile selection; legacy state-machine/native-effect rewiring remains open.
  - [ ] Implement authorization-code issuance with PAR, PKCE S256, RFC 9207 issuer binding, exact
        redirect/state correlation, DPoP and DPoP-Nonce, final token/nonce/proofs/credentials wire
        models and typed native effects.
  - [ ] Replace the custom WUA gate with TS3 1.5.2 WIA + KA transport, Wallet Provider trust,
        one-use/privacy rules, WSCD key binding and client/key-storage status maintenance.
  - [ ] Add and test a secret-safe native `GermanEidClient` seam; then integrate the official
        AusweisApp SDK on iOS and Android against the accepted PID Provider's authenticated TcToken
        and secure-return contract, with identity attributes available only at the provider backend.
  - [ ] Authenticate and ingest both `eu.europa.ec.eudi.pid.1` mdoc and `urn:eudi:pid:1` SD-JWT VC;
        explicitly reject deferred/batch/encrypted/notification modes until separately implemented.
  - [ ] Pass hostile local vectors, fake-provider end-to-end tests, official AusweisApp simulator and
        physical-card/device tests, OIDF/EU functional conformance and German sandbox interoperability.
  - External launch gates: accepted German PID Provider/eID-service relationship and sandbox; BVA
    authorization/technical certificates where applicable; Wallet Provider WIA/KA/status service and
    trust-list inclusion; certified WSCA/WSCD and Wallet Solution; German recognition/notification.
- [ ] Implement ISO 18013-5 proximity transports and remaining non-PID OpenID profile extensions.
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
