# BankID Swedish identity bootstrap assessment

Status: public-interface assessment, 2026-07-23. Tracked by
[issue #56](https://github.com/advatar/EUWallet/issues/56).

## Decision

BankID may be evaluated as an optional Swedish identity bootstrap or step-up
signal. It must not be treated as:

- an authoritative EUDI PID issuer;
- an interface for exporting passport or national-ID chip contents;
- a source of a PID portrait, MRZ, document number, nationality or validity
  dates; or
- a substitute for issuer authentication, PID profile validation or wallet
  evidence binding.

This optional integration is not a TestFlight launch blocker.

## Public interface boundary

BankID's RP API allows an authentication request to require MRTD-based extra
control. A completed authentication returns the ordinary authenticated-user
identity and records `completionData.stepUp.mrtd=true`. The public RP API does
not document returning the underlying identity-document attributes or image.

BankID also offers businesses verification of its digital ID card. Production
access is a contracted/entitled service. Its exact production response schema,
permitted use and assurance evidence must therefore be confirmed directly with
BankID before this wallet relies on it.

BankID's privacy information says that document data such as document type,
MRZ and source image is processed by BankID. That processing statement is not
an API grant to third-party relying parties.

| Capability | Publicly supported conclusion | Wallet treatment |
| --- | --- | --- |
| BankID authentication | Returns the authenticated user's ordinary BankID identity | Optional bootstrap only |
| MRTD extra control | Confirms a passport/national-ID step-up occurred | Optional assurance signal |
| Raw chip/MRZ/document export | Not exposed by the public RP API | Do not design or claim |
| Portrait acquisition | Not exposed by the public RP API | Obtain only through an authorised PID issuer flow |
| Digital ID card verification | Business/contract-gated | Evaluate after BankID confirms access and schema |
| EUDI PID issuance | BankID is not documented as the wallet's PID issuer | Use an authorised PID issuer |

## Conditions before implementation

1. Obtain written confirmation from BankID of commercial eligibility, the
   current production API schema, permitted data uses and retention terms.
2. Map the returned evidence to the applicable Swedish/EUDI assurance and
   privacy requirements; do not infer PID attributes from successful step-up.
3. Define a core-first typed result that distinguishes authentication,
   MRTD-step-up and digital-ID-card verification.
4. Bind any accepted evidence into the relevant authorization/audit record,
   add formal admission properties, and test both native adapters.
5. Keep the feature optional and fail closed without weakening the existing
   issuer-authenticated PID path.

## Primary sources

- [BankID RP API — auth](https://developers.bankid.com/api-references/auth--sign/auth)
- [BankID RP API — collect](https://developers.bankid.com/api-references/auth--sign/collect)
- [BankID digital ID card for businesses](https://www.bankid.com/en/business/about-the-service/digital-id-card)
- [BankID extra control](https://www.bankid.com/en/business/about-the-service/extra-control)
- [BankID privacy policy](https://www.bankid.com/integritetspolicy)
