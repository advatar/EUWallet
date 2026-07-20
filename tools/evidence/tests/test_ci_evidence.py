import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
WORKFLOW = (ROOT / ".github/workflows/ci.yml").read_text()
ROOT_MANIFEST = (ROOT / "Cargo.toml").read_text()
COSE_MANIFEST = (ROOT / "crates/cose/Cargo.toml").read_text()
CRYPTO_TRAITS_MANIFEST = (ROOT / "crates/crypto-traits/Cargo.toml").read_text()
EVIDENCE_SCRIPT = ROOT / "tools/evidence/generate.sh"
EVIDENCE_TEXT = EVIDENCE_SCRIPT.read_text()
SBOM_SCRIPT = ROOT / "tools/evidence/sbom.sh"
SBOM_TEXT = SBOM_SCRIPT.read_text()


class CiEvidenceConfigurationTests(unittest.TestCase):
    def test_workflow_uses_repository_root_paths(self):
        self.assertNotIn("working-directory: euwallet", WORKFLOW)
        self.assertNotIn("euwallet/", WORKFLOW)

    def test_workflow_does_not_mask_required_failures(self):
        self.assertNotIn("continue-on-error: true", WORKFLOW)
        self.assertNotIn("|| true", WORKFLOW)
        self.assertIn("tools/evidence/sbom.sh", WORKFLOW)
        self.assertIn(
            "actions/upload-artifact@330a01c490aca151604b8cf639adc76d48f6c5d4 # v5",
            WORKFLOW,
        )
        self.assertIn("if-no-files-found: error", WORKFLOW)
        self.assertIn("test \"$falsified\" -eq 0", WORKFLOW)

    def test_workflow_runs_all_formal_models_and_correct_kani_package(self):
        for model in (
            "WalletModel",
            "PaymentModel",
            "ProximityModel",
            "IssuanceModel",
            "QesModel",
            "W2wModel",
            "NavigationModel",
        ):
            self.assertIn(model, WORKFLOW)
        for executable in (
            "payment_traces",
            "proximity_traces",
            "issuance_traces",
            "qes_traces",
            "w2w_traces",
        ):
            self.assertIn(executable, WORKFLOW)
        self.assertIn("formal/tamarin/*.spthy", WORKFLOW)
        self.assertIn(
            "model-checking/kani-github-action@"
            "f838096619a707b0f6b2118cf435eaccfa33e51f",
            WORKFLOW,
        )
        self.assertIn('kani-version: "0.67.0"', WORKFLOW)
        self.assertIn('args: "-p cose"', WORKFLOW)
        self.assertNotIn("cargo install kani-verifier", WORKFLOW)
        self.assertNotIn("cargo kani -p mdoc", WORKFLOW)

    def test_workflow_actions_are_reviewed_immutable_and_read_only(self):
        self.assertIn("permissions:\n  contents: read", WORKFLOW)
        action_lines = [
            line.strip()
            for line in WORKFLOW.splitlines()
            if re.match(r"(?:-\s+)?uses:", line.strip())
        ]
        self.assertGreater(len(action_lines), 0)
        action_pattern = re.compile(
            r"(?:-\s+)?uses:\s+"
            r"([A-Za-z0-9_.-]+)/"
            r"([A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*)@([0-9a-f]{40})"
            r"\s+#\s+v[^\s]+"
        )
        for line in action_lines:
            match = action_pattern.fullmatch(line)
            self.assertIsNotNone(match, f"mutable or undocumented action reference: {line}")
            self.assertIn(match.group(1), {"actions", "gradle", "model-checking"})

    def test_android_shell_is_a_required_release_gate(self):
        android_job = WORKFLOW.split("  android-shell:", 1)[1].split(
            "  traceability:", 1
        )[0]
        self.assertIn("runs-on: ubuntu-24.04", android_job)
        self.assertIn(
            "actions/setup-java@03ad4de0992f5dab5e18fcb136590ce7c4a0ac95",
            android_job,
        )
        self.assertIn(
            "gradle/actions/setup-gradle@3f131e8634966bd73d06cc69884922b02e6faf92",
            android_job,
        )
        self.assertIn("validate-wrappers: true", android_job)
        self.assertIn(":wallet-shell:test", android_job)
        self.assertIn(":wallet-shell:lint", android_job)
        self.assertIn(":wallet-shell:assembleRelease", android_job)

    def test_kani_proof_closure_has_a_verified_compatible_msrv(self):
        self.assertIn('rust-version = "1.97"', ROOT_MANIFEST)
        self.assertIn('rust-version = "1.93"', COSE_MANIFEST)
        self.assertIn('rust-version = "1.93"', CRYPTO_TRAITS_MANIFEST)
        self.assertNotIn("--ignore-rust-version", WORKFLOW)

    def test_swift_runner_and_tamarin_release_are_pinned(self):
        ios_job = WORKFLOW.split("  ios-shell:", 1)[1].split("  traceability:", 1)[0]
        self.assertIn("runs-on: macos-15", ios_job)
        self.assertIn("Verify Swift 6 toolchain", ios_job)
        self.assertIn("grep -Eq 'Swift version", ios_job)

        tamarin_job = WORKFLOW.split("  tier3-tamarin:", 1)[1].split("  ios-shell:", 1)[0]
        self.assertIn("runs-on: ubuntu-latest", tamarin_job)
        self.assertIn("graphviz maude", tamarin_job)
        self.assertIn("tamarin-prover-1.12.0-linux64-ubuntu.tar.gz", tamarin_job)
        self.assertIn(
            "201be06f469e47cff554df6ca93db8366fc2c69d70c61fcbd1370a1074b469c6",
            tamarin_job,
        )
        self.assertIn("sha256sum --check --strict", tamarin_job)
        self.assertIn("tamarin-prover --version", tamarin_job)
        self.assertNotIn("brew trust", WORKFLOW)
        self.assertNotIn("HOMEBREW_NO_REQUIRE_TAP_TRUST", WORKFLOW)

    def test_evidence_script_is_syntax_valid_and_fail_closed(self):
        subprocess.run(["bash", "-n", EVIDENCE_SCRIPT], check=True)
        self.assertNotIn("$(fail)", EVIDENCE_TEXT)
        self.assertNotIn("Tier 3 skipped", EVIDENCE_TEXT)
        self.assertIn("required tool missing: tamarin-prover", EVIDENCE_TEXT)
        self.assertIn("NavigationModel", EVIDENCE_TEXT)

    def test_sbom_script_is_syntax_valid_and_pinned(self):
        subprocess.run(["bash", "-n", SBOM_SCRIPT], check=True)
        self.assertNotIn("|| true", SBOM_TEXT)
        self.assertIn("CARGO_CYCLONEDX_VERSION=0.5.9", SBOM_TEXT)

    def test_evidence_script_fails_when_required_tools_are_missing(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            tool_directory = temporary_path / "bin"
            tool_directory.mkdir()
            for tool in ("dirname", "mkdir", "mktemp", "rm"):
                tool_path = shutil.which(tool)
                self.assertIsNotNone(tool_path)
                (tool_directory / tool).symlink_to(tool_path)

            report = temporary_path / "verification-report.md"
            environment = os.environ.copy()
            environment.update(
                {
                    "EVIDENCE_PATH_PREFIX": "",
                    "HOME": str(temporary_path),
                    "PATH": str(tool_directory),
                    "REPORT": str(report),
                }
            )
            result = subprocess.run(
                ["/bin/bash", EVIDENCE_SCRIPT],
                cwd=ROOT,
                env=environment,
                capture_output=True,
                text=True,
            )

            self.assertEqual(1, result.returncode, result.stdout + result.stderr)
            report_text = report.read_text()
            self.assertIn("Required tool missing: python3", report_text)
            self.assertIn("required tool missing: lake", report_text)
            self.assertIn("required tool missing: tamarin-prover", report_text)
            self.assertIn("Automated verification result: FAIL", report_text)


if __name__ == "__main__":
    unittest.main()
