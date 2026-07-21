#!/usr/bin/env python3
"""Fail-closed validator for a release's OIDF self-certification evidence."""
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path


def fail(message: str) -> None:
    print(f"OIDF EVIDENCE BLOCKED: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--release", required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    matrix_path = root / "tools/oidf/profile-matrix.json"
    evidence = root / "docs/certification-evidence/oidf" / args.release
    matrix_bytes = matrix_path.read_bytes()
    matrix = json.loads(matrix_bytes)
    if matrix["suite_version"] == "PIN_REQUIRED_BEFORE_SUBMISSION":
        fail("profile matrix has no pinned OIDF suite version")
    for name in matrix["required_evidence"]:
        if not (evidence / name).is_file():
            fail(f"missing {evidence / name}")
    result = json.loads((evidence / "result.json").read_text())
    if result.get("status") != "PASS":
        fail("result.json status is not PASS")
    try:
        revision = subprocess.check_output(
            ["git", "-C", str(root), "rev-parse", "HEAD"], text=True
        ).strip()
    except subprocess.CalledProcessError:
        fail("cannot resolve release source revision")
    if result.get("source_revision") != revision:
        fail("result source_revision does not match shipped revision")
    expected_hash = hashlib.sha256(matrix_bytes).hexdigest()
    if result.get("profile_matrix_sha256") != expected_hash:
        fail("result profile_matrix_sha256 does not match profile matrix")
    recorded_hash = (evidence / "result.json.sha256").read_text().strip().split()[0]
    actual_hash = hashlib.sha256((evidence / "result.json").read_bytes()).hexdigest()
    if recorded_hash != actual_hash:
        fail("result.json checksum mismatch")
    submission = (evidence / "submission.txt").read_text().strip()
    if not submission.startswith("https://"):
        fail("submission.txt must contain the official HTTPS submission URL/identifier")
    print(f"OIDF EVIDENCE PASS: {args.release} matches {revision}")


if __name__ == "__main__":
    main()
