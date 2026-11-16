"""Tests for tools/validate_manifest.py and tools/validate_schema.py.

Both tools run as subprocesses (the way CI would call them). Python 3.9+.
"""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

try:
    import jsonschema  # noqa: F401
    HAVE_JSONSCHEMA = True
except ImportError:
    HAVE_JSONSCHEMA = False


def run_tool(script, *args):
    return subprocess.run(
        [sys.executable, str(REPO / 'tools' / script), *[str(a) for a in args]],
        capture_output=True, text=True, cwd=str(REPO))


def minimal_report():
    """The smallest dict that satisfies docs/schema/report-schema.json."""
    return {
        'schema_version': '1.0',
        'root': 'C:/tmp/ws',
        'home': 'C:/tmp/home',
        'generated_at': '2026-11-16T12:00:00+03:00',
        'rules_version': '0.4.0',
        'stats': {'total_files': 3, 'total_size_bytes': 100,
                  'skipped_symlinks_outside': 0, 'duration_sec': 0.01},
        'gates': [{'gid': 'G1', 'n': 1, 'name': 'Workspace structure',
                   'status': 'pass', 'checks': [], 'evidence': []}],
        'findings_detailed': [{
            'fid': 'SEC-001', 'gate': 'G6', 'category': 'secrets',
            'severity': 'high', 'status': 'fail', 'title': 'demo token',
            'description': 'demo token in .env', 'evidence': [],
            'confidence': 0.9, 'recommendation': 'rotate the token',
            'autofix_available': False, 'schema_version': '1.0'}],
        'secrets': [{'path': '.env', 'line': 2, 'kind': 'api-key',
                     'mask': 'sk-***', 'fingerprint': 'sha256:ab',
                     'confidence': 0.9}],
        'top_level': [{'name': 'repo', 'kind': 'repo', 'git': None,
                       'size_bytes': 10}],
        'junk': {'files': [], 'dirs': [], 'empty_dirs': []},
        'findings': [{'fp': 'x:1', 'severity': 'high'}],
    }


class ValidateManifestTest(unittest.TestCase):
    def test_real_repo_passes(self):
        r = run_tool('validate_manifest.py')
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn('[OK] manifest', r.stdout)


class ValidateSchemaTest(unittest.TestCase):
    def _write(self, report):
        f = tempfile.NamedTemporaryFile('w', suffix='.json', delete=False,
                                        encoding='utf-8')
        json.dump(report, f)
        f.close()
        self.addCleanup(Path(f.name).unlink)
        return f.name

    def test_minimal_report_passes(self):
        r = run_tool('validate_schema.py', self._write(minimal_report()))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn('[OK] schema', r.stdout)

    @unittest.skipIf(not HAVE_JSONSCHEMA,
                     'jsonschema not installed; fallback path also checks enums, '
                     'but the invalid-enum half is only asserted under jsonschema')
    def test_bad_gate_status_rejected(self):
        bad = minimal_report()
        bad['gates'][0]['status'] = 'green'
        r = run_tool('validate_schema.py', self._write(bad))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('[FAIL]', r.stdout)

    @unittest.skipIf(not HAVE_JSONSCHEMA, 'jsonschema not installed')
    def test_secret_value_key_rejected(self):
        bad = minimal_report()
        bad['secrets'][0]['value'] = 'sk-supersecret-raw-value'
        r = run_tool('validate_schema.py', self._write(bad))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('value', r.stdout)


if __name__ == '__main__':
    unittest.main()
