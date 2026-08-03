# The mandate attestation — shared schema (D1)

**Status:** pinned across repos in code; this document is the human-readable authority.
The power-of-representation *mandate* is a distinct SD-JWT VC issued by VCIssuer, held and presented
by an agent through EUWallet, and verified by VCVerifier. It is the interoperable, verifiable face of
a Mandamus/WAUTH mandate. See [agent-delegation-design.md](agent-delegation-design.md) for the
cross-repo design.

## Credential type

```
vct = "urn:eudi:mandate:1"
format = dc+sd-jwt   (mdoc optional, later)
```

Pinned identically in three repos (no shared crate across repo boundaries):

| Repo | Symbol |
|---|---|
| VCIssuer | `issuer_core::MANDATE_VCT` |
| VCVerifier | the verifier's mandate `vct` (delegation-verifier adapter) |
| EUWallet | `wallet_core::delegation::MANDATE_VCT` |

## Claims

| Claim | Disclosure | Meaning |
|---|---|---|
| `iss` | always | the mandate issuer (VCIssuer) |
| `iat` / `nbf` / `exp` | always | short validity (dev: 15 min) — ARF Topic 29 RP_02 "short-lived or revocable" |
| `vct` | always | `urn:eudi:mandate:1` |
| `cnf` (`{ "jwk": … }`) | always | **the agent (delegate) key** the mandate is holder-bound to |
| `cryptographically_bound_to` | always | the delegator's PID/LPID vct (e.g. `eu.europa.ec.eudi.pid.1`) |
| `mandator` | selective | the delegator the mandate represents |
| `scope` | selective | **array of power URNs** — the specific operations authorised |
| `mandate_jti` | selective | link to the governing Mandamus mandate/capability |
| `status` (Token Status List) | always | revocation reference (reuses EUWallet `status`) — issuer status endpoint is a follow-up |

## Power / scope model

Scope is a set of **power URNs** on the wire. It is decidably subset-checkable: a verifier accepts
iff `required ⊆ granted` (set containment). The pinned taxonomy maps one URN to one bit of the
issuer/verifier kernels' `Powers(u64)` bitmask, so URN-set containment agrees exactly with
`Powers::subset_of` — proven exhaustively in `issuer-core` (`taxonomy_bridges_subset_exhaustively`).
This is the property the whole delegation design rests on (design brief §8).

Pinned taxonomy (`issuer_core::POWER_TAXONOMY`; mirrored in the verifier adapter and
`wallet_core::delegation`):

| bit | URN |
|---|---|
| 0 | `urn:eudi:mandate:power:present-identity` |
| 1 | `urn:eudi:mandate:power:sign-document` |
| 2 | `urn:eudi:mandate:power:authorise-payment` |
| 3 | `urn:eudi:mandate:power:manage-subscription` |
| 4 | `urn:eudi:mandate:power:access-records` |
| 5 | `urn:eudi:mandate:power:administer-account` |

Adding a power = append one row (append-only; never renumber an existing bit).

## The one aligned property (proved on both stacks)

A delegate can only ever exercise a **subset** of the granted powers, only while the mandate is
**valid and non-revoked**, only with the **bound agent key** — and, for high-assurance actions, only
with **fresh HAPP** evidence. The issuer proves it cannot mint a widening mandate
(`issuer-core` / `EudiIssuer/Model.lean`); the verifier proves it cannot accept an out-of-scope,
revoked, or wrong-key delegated request (`verifier-core` / `EudiVerifier/Model.lean`); the wallet
never over-claims beyond the grant (`wallet_core::delegation`) and the agent shell enforces scope +
HAPP + tamper-evident receipts (`wallet_core::agent`).

## Rulebook pin (open)

`standards.lock.toml` in each repo should add an entry for the pinned power-of-representation
rulebook + this schema once the schema stabilises. Until an official EU Representation Rulebook
exists (ARF Topic 29 has none yet), this is an explicit, honest **designed extension**, converging
when the EU rulebook lands.
