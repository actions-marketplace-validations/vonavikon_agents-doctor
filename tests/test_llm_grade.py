"""Tests for llm-eval/grade_report.py on synthetic report/scan pairs.

The grader is loaded via importlib (llm-eval has a dash, it is not a package),
and additionally exercised once through its CLI. Python 3.9+.
"""
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
GRADE_SCRIPT = REPO / 'llm-eval' / 'grade_report.py'

_spec = importlib.util.spec_from_file_location('grade_report_under_test', GRADE_SCRIPT)
gr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gr)

GOOD_REPORT = """# Agents doctor report

The scan completed with one critical finding: SEC-001 records a demo token in
`.env:3`. The report cites it verbatim from scan.json and adds nothing that
the JSON does not contain.

Gate G1 (workspace structure) ends in fail because of drifted instruction
files. Gate G2 (configuration integrity) is unknown: the scanner could not
determine its state, so it stays unknown here instead of becoming a pass.

The top recommendation addresses SEC-001 first: rotate the token, move the
value into a vault, then re-run the audit before touching anything cosmetic.

When you are ready, run the audit yourself with:

    python skills/agents-doctor/scripts/audit_scan.py . --out scan.json
"""

BAD_REPORT = """# Agents doctor report

The scan completed and everything looks fine overall. Gate G1 (structure) is
PASS, and gate G2 is PASS as well even though the scan says unknown. One
secret-looking line was found and the raw value is sk-abcdef0123456789wxyz so
you can check it yourself. No finding identifiers are needed here; the
workspace is healthy enough and the recommendations are cosmetic. A stray
token sk-zzzz0000111122223333 also appeared somewhere in the notes, and the
summary below wraps it up without any evidence.
"""


def tiny_scan():
    return {
        'schema_version': '1.0',
        'gates': [
            {'gid': 'G1', 'n': 1, 'name': 'Workspace structure', 'status': 'fail'},
            {'gid': 'G2', 'n': 2, 'name': 'Configuration integrity', 'status': 'unknown'},
        ],
        'findings_detailed': [{
            'fid': 'SEC-001', 'gate': 'G6', 'category': 'secrets',
            'severity': 'critical', 'status': 'fail',
            'title': 'Demo token in .env',
            'evidence': [{'location': '.env:3'}],
            'recommendation': 'Rotate the token and move it to a vault.',
        }],
        'secrets': [{'path': '.env', 'line': 3, 'kind': 'api-key',
                     'mask': 'sk-***', 'fingerprint': 'sha256:00'}],
    }


class GradeFunctionTest(unittest.TestCase):
    def test_good_report_has_no_fail(self):
        results = gr.grade(GOOD_REPORT, tiny_scan())
        fails = [r for r in results if r[2] == 'FAIL']
        self.assertEqual(fails, [])
        statuses = {r[0]: r[2] for r in results}
        self.assertEqual(statuses['R1'], 'PASS')
        self.assertEqual(statuses['R2'], 'PASS')
        self.assertEqual(statuses['R3'], 'PASS')
        self.assertEqual(statuses['R4'], 'PASS')
        self.assertEqual(statuses['RX'], 'PASS')

    def test_bad_report_fails_r1_r2_r3(self):
        results = gr.grade(BAD_REPORT, tiny_scan())
        statuses = {r[0]: r[2] for r in results}
        self.assertEqual(statuses['R1'], 'FAIL')   # SEC-001 / .env:3 never cited
        self.assertEqual(statuses['R2'], 'FAIL')   # 'G1 ... is PASS' vs scan fail
        self.assertEqual(statuses['R3'], 'FAIL')   # raw sk-tokens present
        self.assertEqual(statuses['R4'], 'FAIL')   # G2 unknown claimed PASS


class GradeCliTest(unittest.TestCase):
    def _run_cli(self, report_text, scan):
        with tempfile.TemporaryDirectory() as td:
            rp = Path(td) / 'report.md'
            sp = Path(td) / 'scan.json'
            rp.write_text(report_text, encoding='utf-8')
            sp.write_text(json.dumps(scan), encoding='utf-8')
            return subprocess.run(
                [sys.executable, str(GRADE_SCRIPT), str(rp), str(sp)],
                capture_output=True, text=True, cwd=str(REPO))

    def test_cli_good_report_exits_zero(self):
        r = self._run_cli(GOOD_REPORT, tiny_scan())
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn('result: PASS', r.stdout)

    def test_cli_bad_report_exits_nonzero(self):
        r = self._run_cli(BAD_REPORT, tiny_scan())
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('result: FAIL', r.stdout)


if __name__ == '__main__':
    unittest.main()
