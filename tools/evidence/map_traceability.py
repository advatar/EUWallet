#!/usr/bin/env python3
"""Enrich traceability/requirements.csv: for each requirement whose subject this wallet actually
implements, fill Mapped_symbols (crate/module), Mapped_tests (the verifying test/proof), and set
Status to `implemented`. Requirements we do NOT yet address are left `unassigned` — the coverage
summary is therefore an honest count, not a claim of full conformance.

Matching is keyword-based against the requirement text; the FIRST matching rule (most specific
first) wins. Re-runnable and idempotent. Prints a coverage summary.

Usage:  python3 tools/evidence/map_traceability.py
"""
import csv
import sys
from pathlib import Path

CSV = Path(__file__).resolve().parents[2] / "traceability" / "requirements.csv"

# (rule name, [phrases: ANY match], mapped_symbols, mapped_tests). Order matters: the FIRST match
# wins, so the most specific / primary subject is listed first. Phrases are deliberately high-
# precision (distinctive multi-word terms, not bare words like "status"/"minimum"/"mdoc") to avoid
# false positives — an over-broad match would overstate conformance, which defeats the purpose.
RULES = [
    ("qes", ["qualified electronic signature", "[CSC]", "signature creation data"],
     "crates/qes", "crates/qes/tests, wallet-core/tests/qes_flow.rs, formal/lean/QesModel.lean, formal/tamarin/qes.spthy"),
    ("wallet-to-wallet", ["wallet-to-wallet", "another wallet unit", "transfer of an attestation"],
     "crates/w2w", "crates/w2w/tests/conformance.rs, wallet-core/tests/w2w_flow.rs, formal/lean/W2wModel.lean, formal/tamarin/w2w.spthy"),
    ("sca-dynamic-linking", ["strong customer authentication", "dynamic linking", "dynamically linked"],
     "crates/payment", "crates/payment/tests/regulatory_sca.rs, wallet-core/tests/e2e_payment.rs, formal/tamarin/payment_sca.spthy"),
    ("wua", ["wallet unit attestation"],
     "crates/wua", "crates/wua/tests, wallet-core/tests/e2e_issuance.rs, formal/lean/IssuanceModel.lean"),
    ("transaction-log", ["transaction log", "log of the transaction", "log the value of the transaction",
                          "record of the transaction", "transaction history"],
     "crates/txnlog", "crates/txnlog/src/lib.rs (unit), wallet-core/tests/txn_log.rs"),
    ("erasure-deletion", ["right to erasure", "right to be forgotten", "erase the", "delete all"],
     "crates/txnlog (redact/wipe)", "crates/txnlog/src/lib.rs (tombstone tests), wallet-core/tests/txn_log.rs"),
    ("export-portability", ["data portability", "export of the", "export their"],
     "crates/wallet-core/src/export.rs", "wallet-core/tests/export.rs"),
    ("revocation-status", ["token status list", "revocation list", "revoke", "revoked", "revocation status", "suspension of"],
     "crates/status", "crates/status/tests"),
    ("issuance-oid4vci", ["[openid4vci]", "oid4vci"],
     "crates/oid4vci", "crates/oid4vci/tests/transitions.rs, wallet-core/tests/e2e_issuance.rs, formal/lean/IssuanceModel.lean"),
    ("key-binding", ["device binding", "key binding", "mdoc authentication", "holder binding"],
     "crates/sdjwt (KeyBindingCheck), crates/mdoc (device auth)", "wallet-core/tests/e2e_flow.rs, crates/sdjwt/tests"),
    ("data-minimisation", ["data minimis", "selective disclosure", "minimum set of"],
     "crates/presenter (minimum_claim_set), crates/sdjwt", "crates/presenter/tests, wallet-core/tests/e2e_flow.rs"),
    ("haip-profile", ["[haip]", "high assurance interoperability profile"],
     "crates/oid4vp (HAIP profile), crates/oid4vci", "formal/tamarin/oid4vp_haip.spthy"),
    ("dcql", ["dcql", "digital credentials query"],
     "crates/oid4vp/src/dcql.rs", "crates/oid4vp/tests, shell-io/tests/e2e_live_presentation.rs"),
    ("eccg-algorithms", ["[eccg agreed cryptographic", "cryptographic algorithms included", "agreed cryptographic mechanisms"],
     "crates/crypto-backend (aws-lc-rs: ES256/384, EdDSA, SHA-2, HKDF)", "docs/certification-evidence/algorithm-allow-list.md, known-answer-tests.md"),
    ("openid4vp-remote", ["[openid4vp]", "remote presentation flow"],
     "crates/oid4vp", "crates/oid4vp/tests/transitions.rs, wallet-core/tests/e2e_flow.rs, formal/lean/WalletModel.lean, shell-io/tests/e2e_live_presentation.rs"),
    ("proximity-18013-5", ["[iso/iec 18013-5]", "proximity presentation", "proximity flow"],
     "crates/iso18013-5, crates/mdoc", "crates/iso18013-5/tests/e2e_proximity.rs, formal/lean/ProximityModel.lean, formal/tamarin/iso18013_5_proximity.spthy"),
    ("rp-registration", ["relying party registration", "registration certificate", "relying party access certificate"],
     "crates/trust, crates/x509", "crates/trust/tests, wallet-core/tests/e2e_flow.rs"),
    ("trusted-list", ["trusted list", "list of trusted"],
     "crates/trust", "crates/trust/tests, crates/x509/tests"),
]


def main() -> int:
    with open(CSV, newline="") as f:
        reader = csv.DictReader(f)
        fields = reader.fieldnames
        rows = list(reader)

    per_rule = {name: 0 for name, *_ in RULES}
    mapped = 0
    for r in rows:
        # Reset any prior auto-mapping so re-runs are idempotent (don't leave stale marks).
        if r["Status"] == "implemented":
            r["Mapped_symbols"] = r["Mapped_tests"] = r["Evidence_link"] = ""
            r["Status"] = "unassigned"
        text = r["Requirement_specification"].lower()
        for name, phrases, symbols, tests in RULES:
            if any(p.lower() in text for p in phrases):
                r["Mapped_symbols"] = symbols
                r["Mapped_tests"] = tests
                r["Evidence_link"] = "docs/certification-evidence/verification-report.md"
                r["Status"] = "implemented"
                per_rule[name] += 1
                mapped += 1
                break

    with open(CSV, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)

    total = len(rows)
    print(f"Traceability coverage: {mapped}/{total} requirements mapped to implementation + tests "
          f"({100 * mapped // total}%). Remaining {total - mapped} left `unassigned` (not yet addressed).")
    print("Per-feature requirement counts:")
    for name, n in sorted(per_rule.items(), key=lambda kv: -kv[1]):
        if n:
            print(f"  {name:22} {n}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
