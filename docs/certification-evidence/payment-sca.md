# Payment SCA — regulatory completion evidence

The register's Payment SCA module lists its completion evidence as *"dynamic-linking and SCA
regulatory test cases."* This document traces each PSD2 Strong Customer Authentication requirement
(Commission Delegated Regulation (EU) 2018/389 — the RTS) to a passing test, run with real
cryptography (aws-lc-rs). The suite lives in
`crates/crypto-backend/tests/regulatory_sca.rs`; run it with:

```
cargo test -p crypto-backend --test regulatory_sca
```

## RTS → test traceability

| RTS requirement | What it demands | Test |
|---|---|---|
| **Art. 4(1)** | SCA generates an authentication code the payment service can verify | `rts_art4_authentication_code_is_produced_and_verifiable` |
| **Art. 4(3)(b)** | The code cannot be forged (no unauthorised party can generate it) | `rts_art4_code_cannot_be_forged` |
| **Art. 5(1)(a)(b)** | The payer is made aware of the amount and the payee | `rts_art5_1_payer_is_made_aware_of_amount_and_payee` |
| **Art. 5(1)(c) / 5(3)** | The code is specific to the **amount**; a change invalidates it | `rts_art5_dynamic_linking_amount` |
| **Art. 5(1) / 5(3)** | The code is specific to the **payee name**; a change invalidates it | `rts_art5_dynamic_linking_payee_name` |
| **Art. 5(1) / 5(3)** | The code is specific to the **payee account (IBAN)** — redirecting funds invalidates it | `rts_art5_dynamic_linking_payee_account` |
| **Art. 5(3)** | A change to any linked field (currency) invalidates the code | `rts_art5_dynamic_linking_currency` |
| **Art. 5(2)** | Integrity/authenticity of the code | `rts_art5_2_integrity_of_authentication_code` |
| **Art. 4 / 5** | Transaction uniqueness — a replayed transaction is rejected | `rts_transaction_uniqueness_replay_rejected` |
| **SCA (possession)** | The code requires the hardware key; it cannot be derived from the request alone | `sca_possession_factor_required` |

## Design notes

- **Dynamic linking** is realised by signing a canonical CBOR binding over
  `(creditor_name, creditor_account, amount_minor, currency, transaction_id, nonce)` with the
  device key. The authentication code *is* that signature, so it is inseparable from the amount and
  payee (Art. 5). The verifying payment service recomputes the binding from the true transaction and
  checks the signature; any tampering yields a different binding and the check fails.
- **Two SCA factors:** possession (the Secure Enclave device key) and inherence (the signing
  operation is gated by biometric/device-credential access control in the shell). The private key
  never crosses the FFI.
- **Isolation:** payment authorisation uses a dedicated `PaymentConfirmation` screen, separate from
  the identity consent screen, per the register's instruction not to mix payment transaction data
  with identity consent.

## Not yet covered (honest gaps)

- Confidentiality of the amount/payee *in transit* (Art. 5(2)) is a transport concern (TLS in the
  shell), not exercised here.
- The full TS12 wire envelope (exact field names/encodings of the EUDI payment request/response)
  is approximated; align with the published TS12 schema before conformance testing.
- SCA exemptions (RTS Arts. 10–18, e.g. low-value/TRA) are out of scope for the wallet's
  authentication role.
