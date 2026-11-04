"""kiem thu scripts/trivy_gate.py.

moi test chay script bang subprocess tren mot ban sao cua fixture trong thu
muc tam, roi kiem tra exit code, gate-result.json va noi dung summary.

chay: python3 -m unittest discover -s tests -v
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "trivy_gate.py"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
TITLE = "Stage 2 · SCA / Trivy filesystem"


class TrivyGateTest(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)

    def copy_fixture(self, name):
        # chep fixture sang thu muc tam de gate-result.json khong ghi vao tests/fixtures
        target = self.tmp / name
        shutil.copy(FIXTURES / name, target)
        return target

    def run_gate(self, report, block_unfixed="false", gate_severity="HIGH,CRITICAL"):
        summary = self.tmp / "summary.md"
        env = dict(os.environ)
        env.update({
            "GATE_SEVERITY": gate_severity,
            "BLOCK_UNFIXED": block_unfixed,
            "GITHUB_STEP_SUMMARY": str(summary),
        })
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--report", str(report), "--title", TITLE],
            env=env, capture_output=True, text=True, check=False,
        )
        self.assertNotIn("Traceback", proc.stderr)
        result_file = Path(report).parent / "gate-result.json"
        result = json.loads(result_file.read_text()) if result_file.exists() else None
        text = summary.read_text() if summary.exists() else ""
        return proc, result, text

    # 1. chi co loi LOW
    def test_low_only_passes(self):
        proc, result, summary = self.run_gate(self.copy_fixture("low_only.json"))
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["vulnerabilities_all"], 1)
        self.assertEqual(result["blocking"], 0)
        self.assertIn("| Quality Gate | PASS |", summary)
        self.assertIn("| LOW | 1 |", summary)
        self.assertIn(f"{TITLE}: PASS", proc.stdout)

    # 2. 1 HIGH co ban va
    def test_high_fixed_blocks(self):
        proc, result, summary = self.run_gate(self.copy_fixture("high_fixed.json"))
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(result["blocking_ids"], ["CVE-2000-0002"])
        self.assertIn("### Lo hong bi chan", summary)
        self.assertIn("::error::", proc.stdout)

    # 3. 1 HIGH chua co ban va, chi canh bao
    def test_high_unfixed_warns(self):
        proc, result, summary = self.run_gate(self.copy_fixture("high_unfixed.json"))
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(result["status"], "PASS_WITH_WARNINGS")
        self.assertEqual(result["warning_ids"], ["CVE-2000-0003"])
        self.assertIn("### Canh bao - chua co ban va (khong chan, can theo doi)", summary)
        self.assertIn("| libc6 | CVE-2000-0003 | HIGH | 2.41-12 | - | affected |", summary)
        self.assertIn("::warning::libc6 CVE-2000-0003 (HIGH) chua co ban va", proc.stdout)

    # 4. nhu #3 nhung chan ca loi chua co ban va
    def test_high_unfixed_blocks_when_strict(self):
        report = self.copy_fixture("high_unfixed.json")
        proc, result, summary = self.run_gate(report, block_unfixed="true")
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertTrue(result["block_unfixed"])
        self.assertIn("| Loi chua co ban va | CHAN |", summary)

    # 5. 1 HIGH co va + 1 CRITICAL chua va + 1 LOW
    def test_mixed_blocks_fixed_and_warns_unfixed(self):
        proc, result, summary = self.run_gate(self.copy_fixture("mixed.json"))
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(result["blocking"], 1)
        self.assertEqual(result["warning"], 1)
        self.assertEqual(result["blocking_ids"], ["CVE-2000-0004"])
        self.assertEqual(result["warning_ids"], ["CVE-2000-0005"])
        self.assertEqual(result["vulnerabilities_all"], 3)
        self.assertIn("::warning::zlib1g CVE-2000-0005 (CRITICAL) chua co ban va", proc.stdout)

    # 6. nhu #5 nhung chan ca loi chua co ban va
    def test_mixed_blocks_all_when_strict(self):
        report = self.copy_fixture("mixed.json")
        proc, result, summary = self.run_gate(report, block_unfixed="true")
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(result["blocking"], 2)
        self.assertEqual(result["warning"], 0)
        self.assertNotIn("### Canh bao", summary)

    # 7. quet ra 0 goi
    def test_empty_results_is_error(self):
        proc, result, summary = self.run_gate(self.copy_fixture("empty_results.json"))
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(result["status"], "ERROR")
        self.assertEqual(result["packages"], 0)
        self.assertIn("| Quality Gate | ERROR |", summary)

    # 8. file khong ton tai
    def test_missing_report_is_error(self):
        proc, result, summary = self.run_gate(self.tmp / "khong-co.json")
        self.assertEqual(proc.returncode, 1)
        self.assertIsNone(result)
        self.assertIn("**Quality Gate: ERROR**", summary)
        self.assertIn("::error::", proc.stdout)

    # 9. file khong phai json
    def test_invalid_json_is_error(self):
        proc, result, summary = self.run_gate(self.copy_fixture("not_json.json"))
        self.assertEqual(proc.returncode, 1)
        self.assertIsNone(result)
        self.assertIn("**Quality Gate: ERROR**", summary)

    # 10. GATE_SEVERITY co gia tri la
    def test_invalid_gate_severity_is_error(self):
        report = self.copy_fixture("high_fixed.json")
        proc, result, _ = self.run_gate(report, gate_severity="HIGH,ABC")
        self.assertEqual(proc.returncode, 1)
        self.assertIsNone(result)
        self.assertIn("::error::GATE_SEVERITY", proc.stdout)

    # 11. 40 loi HIGH co ban va, bang chi tiet dung o 30 dong
    def test_detail_table_is_truncated(self):
        vulns = [
            {
                "PkgName": f"pkg{i}",
                "VulnerabilityID": f"CVE-2000-{i:04d}",
                "Severity": "HIGH",
                "InstalledVersion": "1.0",
                "FixedVersion": "1.1",
                "Status": "fixed",
            }
            for i in range(40)
        ]
        report = self.tmp / "many.json"
        report.write_text(json.dumps({
            "Results": [{"Target": "x", "Packages": [{"Name": "pkg0"}], "Vulnerabilities": vulns}]
        }))
        proc, result, summary = self.run_gate(report)
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(result["blocking"], 40)
        detail_rows = [line for line in summary.splitlines() if line.startswith("| pkg")]
        self.assertEqual(len(detail_rows), 30)
        self.assertIn("... con 10 dong, xem artifact", summary)

    # 12. Vulnerabilities la null, co goi
    def test_null_vulnerabilities_passes(self):
        proc, result, _ = self.run_gate(self.copy_fixture("null_vulns.json"))
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["vulnerabilities_all"], 0)


if __name__ == "__main__":
    unittest.main()
