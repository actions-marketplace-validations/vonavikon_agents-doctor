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


class SimulateSubcommandTest(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__('shutil').rmtree(self.base,
                                                            ignore_errors=True))
        # isolated home: the default --home would read this machine's
        # real global instruction files and make the test nondeterministic
        self.home = self.base / 'home'
        self.home.mkdir()
        self.ws = self.base / 'ws'
        self.ws.mkdir()
        (self.ws / 'AGENTS.md').write_text('# x\nAlways run tests\n',
                                           encoding='utf-8')

    def test_simulate_root(self):
        rc = agents_doctor.main(['simulate', str(self.ws),
                                 '--home', str(self.home)])
        self.assertEqual(rc, 0)

    def test_simulate_target_inside(self):
        sub = self.ws / 'src'
        sub.mkdir()
        rc = agents_doctor.main(['simulate', str(self.ws),
                                 '--home', str(self.home),
                                 '--target', 'src'])
        self.assertEqual(rc, 0)

    def test_simulate_target_outside_refused(self):
        rc = agents_doctor.main(['simulate', str(self.ws),
                                 '--home', str(self.home),
                                 '--target', '../elsewhere'])
        self.assertEqual(rc, 1)

    def test_simulate_not_a_directory(self):
        rc = agents_doctor.main(['simulate', str(self.base / 'nope')])
        self.assertEqual(rc, 1)


class UiSubcommandTest(unittest.TestCase):
    def test_passthrough_to_server(self):
        import ui.server as srv
        calls = {}
        argv_saved = []

        def fake_main(argv):
            argv_saved.extend(argv)
            return 0

        orig = srv.main
        srv.main = fake_main
        try:
            rc = agents_doctor.main(['ui', 'some-root', '--port', '8123',
                                     '--no-open', '--baseline', 'old.json'])
        finally:
            srv.main = orig
        self.assertEqual(rc, 0)
        self.assertIn('--port', argv_saved)
        self.assertIn('8123', argv_saved)
        self.assertIn('--baseline', argv_saved)
        self.assertIn('--no-open', argv_saved)


class RuntimeFlagTest(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__('shutil').rmtree(self.base,
                                                            ignore_errors=True))
        self.ws = self.base / 'ws'
        self.ws.mkdir()
        (self.ws / 'AGENTS.md').write_text('x\n', encoding='utf-8')

    def test_runtime_section_lands_in_report(self):
        out = self.base / 'scan.json'
        rc = agents_doctor.main(['audit', str(self.ws),
                                 '--out', str(out), '--runtime'])
        self.assertEqual(rc, 0)
        data = json.loads(out.read_text(encoding='utf-8'))
        self.assertIn('runtime', data)
        self.assertIn('checks', data['runtime'])
        self.assertTrue(any(c['id'] == 'RT-PY' for c in data['runtime']['checks']))

    def test_runtime_failure_is_warning_not_error(self):
        out = self.base / 'scan.json'
        import runtime_health
        with mock.patch.object(runtime_health,
                               'check_environment',
                               side_effect=RuntimeError('boom')):
            rc = agents_doctor.main(['audit', str(self.ws),
                                     '--out', str(out), '--runtime'])
        self.assertEqual(rc, 0)
        data = json.loads(out.read_text(encoding='utf-8'))
        self.assertNotIn('runtime', data)


if __name__ == '__main__':
    unittest.main()


class WatchSubcommandTest(unittest.TestCase):
    def _ws(self):
        base = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__('shutil').rmtree(base,
                                                            ignore_errors=True))
        ws = base / 'ws'
        ws.mkdir()
        return base, ws

    def test_watch_passthrough(self):
        import watch as watch_mod
        base, ws = self._ws()
        calls = {}
        orig = watch_mod.watch
        watch_mod.watch = lambda root, **kw: calls.update(kw) or 2
        try:
            rc = agents_doctor.main(['watch', str(ws), '--home', str(base),
                                     '--interval', '5', '--once',
                                     '--deep', '--db', 'x.db'])
        finally:
            watch_mod.watch = orig
        self.assertEqual(rc, 0)
        self.assertEqual(calls['interval'], 5)
        self.assertTrue(calls['once'])
        self.assertTrue(calls['deep'])
        self.assertEqual(calls['db'], 'x.db')

    def test_watch_not_a_directory(self):
        base, ws = self._ws()
        rc = agents_doctor.main(['watch', str(base / 'nope')])
        self.assertEqual(rc, 1)


class PolicySubcommandTest(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__('shutil').rmtree(self.base,
                                                            ignore_errors=True))
        self.ws = self.base / 'ws'
        self.ws.mkdir()
        (self.ws / 'AGENTS.md').write_text('x\n', encoding='utf-8')
        out = self.base / 'scan.json'
        rc = agents_doctor.main(['audit', str(self.ws),
                                 '--home', str(self.base),
                                 '--out', str(out)])
        self.assertEqual(rc, 0)
        self.scan = out

    def _policy(self, text='version: 1\npolicy:\n  name: t\n'):
        p = self.base / 'p.yml'
        p.write_text(text, encoding='utf-8')
        return p

    def test_policy_json_out_file(self):
        out = self.base / 'rep.json'
        rc = agents_doctor.main(['policy', str(self.scan),
                                 '--policy', str(self._policy()),
                                 '--out', str(out)])
        self.assertEqual(rc, 0)
        import json as j
        data = j.loads(out.read_text(encoding='utf-8'))
        self.assertIn('rules_evaluated', data)

    def test_policy_markdown_format(self):
        out = self.base / 'rep.md'
        rc = agents_doctor.main(['policy', str(self.scan),
                                 '--policy', str(self._policy()),
                                 '--out', str(out), '--format', 'md'])
        self.assertEqual(rc, 0)
        text = out.read_text(encoding='utf-8')
        self.assertIn('| Rule | Status |', text)

    def test_policy_broken_yaml_fails(self):
        p = self.base / 'broken.yml'
        p.write_text('policy: [unclosed\n', encoding='utf-8')
        rc = agents_doctor.main(['policy', str(self.scan),
                                 '--policy', str(p)])
        self.assertEqual(rc, 2)   # policy contract: config error

    def test_audit_policy_flag_embeds_report(self):
        out = self.base / 'scan2.json'
        rc = agents_doctor.main(['audit', str(self.ws),
                                 '--home', str(self.base),
                                 '--policy', str(self._policy()),
                                 '--out', str(out)])
        self.assertEqual(rc, 0)
        import json as j
        rep = j.loads(out.read_text(encoding='utf-8'))
        self.assertIn('policy_report', rep)

    def test_audit_policy_missing_file_errors(self):
        out = self.base / 'scan3.json'
        rc = agents_doctor.main(['audit', str(self.ws),
                                 '--home', str(self.base),
                                 '--policy', str(self.base / 'nope.yml'),
                                 '--out', str(out)])
        self.assertEqual(rc, 2)   # policy contract: config error
