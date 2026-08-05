# Post-Quantum Web-Evidence Issuance with TLSNotary

`pq-web-evidence-issuance.pdf` — technical overview of how the EU Wallet notarises a real HTTPS
session with a **post-quantum** TLSNotary notary, lets the holder pick which JSON fields to disclose,
and issues an SD-JWT web-evidence VC (`vct dev.advatar.tlsn.evidence.1`) over OpenID4VCI.

PQ: hybrid **P-256 + ML-KEM-768** key agreement (`P256MlKem768V1`) + hybrid **ES256 + ML-DSA-65**
notary attestation, over TLS 1.2. Selective disclosure = RFC 6901 JSON Pointers recorded in
`credentialSubject.disclosedFields` (see the honest-scope note in §3/§6 re: transcript redaction).

## Regenerate
```bash
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
  --headless=new --disable-gpu --no-pdf-header-footer \
  --virtual-time-budget=25000 --run-all-compositor-stages-before-draw \
  --print-to-pdf=pq-web-evidence-issuance.pdf file://$PWD/pq-web-evidence-issuance.html
```
Device screens are faithful representative mockups (the flow needs a live notary + prover); swap in
real device screenshots and re-render for a production version.
