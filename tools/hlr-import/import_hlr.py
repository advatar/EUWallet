#!/usr/bin/env python3
"""Import the canonical EUDI High-Level Requirements (HLR) CSV into a lightweight
traceability table (plan Section 12).

The register's rule: *never code from narrative documents without a requirement ID and a
version pin*, and the P0 gate is *100% of applicable HLRs assigned to code and a test*.
This tool creates the table that tracks that; you then fill the mapping columns as you
implement each module.

Download the source CSV (pin the commit in production!):
  curl -sSL -o high-level-requirements.csv \
    https://raw.githubusercontent.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework/refs/heads/main/hltr/high-level-requirements.csv

Usage:
  python3 import_hlr.py high-level-requirements.csv ../../traceability/requirements.csv
"""
from __future__ import annotations
import csv
import sys
from collections import Counter
from pathlib import Path

# Columns we add for traceability. These are what an engineer fills in.
TRACE_COLUMNS = ["Mapped_symbols", "Mapped_tests", "Evidence_link", "Status"]


def load_hlrs(src: Path) -> tuple[list[str], list[dict[str, str]]]:
    # The canonical CSV is semicolon-delimited and UTF-8 with a BOM.
    with src.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f, delimiter=";")
        rows = [row for row in reader if (row.get("Harmonized_ID") or "").strip()]
        return (reader.fieldnames or []), rows


def merge_existing(out: Path, rows: list[dict[str, str]]) -> None:
    """Preserve any mapping columns already filled in a previous run (idempotent import)."""
    if not out.exists():
        return
    with out.open("r", encoding="utf-8", newline="") as f:
        prev = {r["Harmonized_ID"]: r for r in csv.DictReader(f)}
    for row in rows:
        old = prev.get(row["Harmonized_ID"])
        if old:
            for col in TRACE_COLUMNS:
                if old.get(col):
                    row[col] = old[col]


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__)
        return 2
    src, out = Path(argv[1]), Path(argv[2])
    fieldnames, rows = load_hlrs(src)

    for row in rows:
        for col in TRACE_COLUMNS:
            row.setdefault(col, "")
        if not row["Status"]:
            row["Status"] = "unassigned"

    merge_existing(out, rows)

    out.parent.mkdir(parents=True, exist_ok=True)
    all_cols = list(fieldnames) + [c for c in TRACE_COLUMNS if c not in fieldnames]
    with out.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=all_cols)
        writer.writeheader()
        writer.writerows(rows)

    # Coverage summary — this is the number the P0 gate watches.
    total = len(rows)
    assigned = sum(1 for r in rows if r["Status"] != "unassigned")
    by_part = Counter(r.get("Part", "?") for r in rows)
    print(f"Imported {total} HLRs -> {out}")
    print(f"Assigned to code+test: {assigned}/{total} ({100 * assigned // max(total, 1)}%)")
    print("By part:")
    for part, n in by_part.most_common():
        print(f"  {n:4d}  {part}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
