import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
WORKFLOW = (ROOT / ".github/workflows/ci.yml").read_text()
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
        self.assertIn("actions/upload-artifact@v4", WORKFLOW)
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
        self.assertIn("cargo kani -p cose", WORKFLOW)
        self.assertNotIn("cargo kani -p mdoc", WORKFLOW)

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
