# Experimental hybrid-PQ use-case isolation

Issue #90 introduces policy and artifact types in `hybrid_pq::use_cases`. All six delivery slices
are default-off and independently reversible. Disabling a slice prevents new use without mutating
or reinterpreting an existing artifact.

| Slice | Enablement boundary | Rollback behavior |
|---|---|---|
| Test primitives | `TestPrimitives` gate | Stop invoking private test APIs |
| Hybrid wallet export | `HybridWalletExport` gate and exact version 2 | Stop creating v2; retain the existing version-1 reader |
| Hybrid recovery | `HybridRecovery` gate and exact recovery schema | Stop creating/restoring experimental recovery artifacts |
| Private provider link | `PrivateProviderLink` gate, HTTPS-origin allow-list, exact hybrid offer | Disable link; never retry classically |
| Experimental credentials | `ExperimentalCredentials` gate and private catalogue prefix | Hide private wrappers; production matching remains impossible |
| Production adoption | `ProductionAdoption` gate plus external approval record | Remains compile-time blocked for this private profile |

## Artifact migration rules

Hybrid-signed exports use a strict, canonical version-2 binary artifact. It carries the actual
durable Core checkpoint, logical key identity/generation, checkpoint generation, validity window,
nonce, public-key envelope and atomic signature envelope. Both algorithms sign the same bounded
commitment containing the checkpoint generation, exact byte length and SHA-256 digest. Import
recomputes the digest, requires an independently trusted public-key envelope, applies freshness,
and restores Core only after atomic verification. Embedded keys never self-authorize. The hybrid
codec rejects version 1 rather than reinterpreting it; the existing production export reader
retains ownership of legacy artifacts. Recovery AAD
length-prefixes and authenticates the key-agreement profile, exact schema identifier, and key
generation. A generation or schema change therefore cannot decrypt under old AAD.

No automatic migration is defined. Rollback stops producing an experimental version but retains
the bytes for a later explicitly enabled reader.

## Provider and credential boundaries

A private provider must match a configured canonical HTTPS origin and offer exactly
`euwallet-p256-mlkem768-v1`. Missing, duplicate, mixed, unknown, or classical-only offers are
downgrade failures. The allow-list does not accept URL paths, queries, fragments, or trailing
slashes.

Experimental credential types are prefixed with `urn:advatar:experimental:pq:`. Their wrapper's
production-match operation is unconditionally false, including when a request repeats the private
identifier. They are never inserted into the production attestation catalogue.

## Production block

The private profile has a compile-time false production-approval constant. Even a record stating
that standards-profile, CAB/profile, and conformance approvals exist cannot enable production.
Adoption requires an explicit reviewed code change and, if the frozen construction changes, a new
profile identifier.
