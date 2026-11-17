"""Coverage for the new CLI features: sarif subcommand and --baseline."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1] / 'skills' / 'agents-doctor' / 'scripts'
sys.path.insert(0, str(SCRIPTS))

import agents_doctor  # noqa: E402


class SarifSubcommandTest(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__('shutil').rmtree(self.base, ignore_errors=True))
        # minimal valid scan
        self.scan = self.base / 'scan.json'
        self.scan.write_text(json.dumps({
            'schema_version': '1.0', 'root': '/tmp/x', 'home': '/tmp/h',
            'rules_version': '1.0.0',
            'gates': [{'gid': 'G6', 'n': 6, 'name': 'Secrets', 'status': 'fail',
                        'evidence': ['e'], 'checks': [], 'confidence': 0.9,
                        'recommendation': 'r', 'pass_when': '', 'fail_when': '',
                        'warn_when': '', 'description': 'd', 'doc_ref': ''}],
            'findings_detailed': [{'fid': 'SEC-001', 'gate': 'G6',
                                   'category': 'secrets', 'severity': 'critical',
                                   'status': 'fail', 'title': 't', 'description': 'd',
                                   'evidence': [{'file': 'f', 'line': 1}],
                                   'confidence': 0.9, 'recommendation': 'r',
                                   'autofix_available': False, 'schema_version': '1.0'}],
            'stats': {}, 'secrets': [], 'top_level': [], 'junk': {},
            'duplicates': [], 'large_files': [], 'findings': [],
        }), encoding='utf-8')

    def test_sarif_writes_file(self):
        out = self.base / 'out.sarif'
        rc = agents_doctor.main(['sarif', str(self.scan), '--out', str(out)])
        self.assertEqual(rc, 0)
        data = json.loads(out.read_text(encoding='utf-8'))
        self.assertEqual(data['version'], '2.1.0')
        self.assertTrue(len(data['runs'][0]['results']) >= 1)

    def test_sarif_bad_input(self):
        rc = agents_doctor.main(['sarif', str(self.base / 'missing.json')])
        self.assertEqual(rc, 1)

    def test_sarif_help_exits_zero(self):
        with mock.patch.object(sys, 'argv', ['agents_doctor.py', 'sarif', '--help']):
            with self.assertRaises(SystemExit) as ctx:
                agents_doctor.build_parser().parse_args(['sarif', '--help'])
            self.assertEqual(ctx.exception.code, 0)


class BaselineAuditTest(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__('shutil').rmtree(self.base, ignore_errors=True))
        self.ws = self.base / 'ws'
        self.ws.mkdir()
        (self.ws / 'README.md').write_text('# test\n', encoding='utf-8')

    def test_baseline_adds_diff(self):
        out1 = self.base / 'first.json'
        rc = agents_doctor.main(['audit', str(self.ws), '--out', str(out1)])
        self.assertEqual(rc, 0)
        rep1 = json.loads(out1.read_text(encoding='utf-8'))
        # add a file to create a new finding
        (self.ws / 'temp-junk.txt').write_text('junk\n', encoding='utf-8')
        out2 = self.base / 'second.json'
        rc = agents_doctor.main(['audit', str(self.ws), '--out', str(out2),
                                 '--baseline', str(out1)])
        self.assertEqual(rc, 0)
        rep2 = json.loads(out2.read_text(encoding='utf-8'))
        self.assertIn('diff', rep2)

    def test_baseline_missing_file_warning(self):
        out = self.base / 'out.json'
        rc = agents_doctor.main(['audit', str(self.ws), '--out', str(out),
                                 '--baseline', str(self.base / 'nope.json')])
        self.assertEqual(rc, 0)  # warning, not error

    def test_load_baseline_valid(self):
        f = self.base / 'b.json'
        f.write_text('{"findings": [{"fp": "abc"}]}', encoding='utf-8')
        result = agents_doctor._load_baseline(str(f))
        self.assertEqual(result['findings'][0]['fp'], 'abc')

    def test_load_baseline_invalid(self):
        f = self.base / 'b.json'
        f.write_text('not json', encoding='utf-8')
        self.assertIsNone(agents_doctor._load_baseline(str(f)))


if __name__ == '__main__':
    unittest.main()
