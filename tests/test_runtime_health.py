"""Tests for the opt-in runtime environment audit
(skills/agents-doctor/scripts/runtime_health.py).

No real `--version` is ever spawned: shutil.which and subprocess.run
are mocked everywhere a binary probe could fire. The real system facts
used are the interpreter itself (RT-PY, which the scanner requires
anyway) and temp-directory fixtures.
"""
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

SCRIPTS = (Path(__file__).resolve().parents[1] / 'skills'
           / 'agents-doctor' / 'scripts')
sys.path.insert(0, str(SCRIPTS))

import runtime_health  # noqa: E402
from harness import get_adapter  # noqa: E402


def _by_id(report, cid):
    matches = [c for c in report['checks'] if c['id'] == cid]
    assert matches, 'check %s not found among %s' % (
        cid, [c['id'] for c in report['checks']])
    return matches[0]


class RuntimeHealthCase(unittest.TestCase):
    """Fresh temp workspace root and home for every test."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        tmp = Path(self._tmp.name)
        self.root = tmp / 'root'
        self.home = tmp / 'home'
        self.root.mkdir()
        self.home.mkdir()

    def tearDown(self):
        self._tmp.cleanup()

    def run_env(self, **kwargs):
        return runtime_health.check_environment(self.root, self.home,
                                                **kwargs)

    def ctx(self):
        return runtime_health.HarnessContext(root=self.root,
                                             home=self.home)


class TestReportShape(RuntimeHealthCase):
    def test_shape_summary_and_mandatory_ids(self):
        with mock.patch('runtime_health.shutil.which', return_value=None):
            report = self.run_env()
        ids = [c['id'] for c in report['checks']]
        self.assertEqual(len(ids), len(set(ids)), 'ids must be unique')
        for mandatory in ('RT-PY', 'RT-GIT', 'RT-MCP-CONFIG',
                          'RT-PATH', 'RT-LOCK-DIR'):
            self.assertIn(mandatory, ids)
        for check in report['checks']:
            self.assertEqual(set(check),
                             {'id', 'name', 'status', 'detail',
                              'evidence'})
            self.assertIn(check['status'],
                          ('pass', 'fail', 'warn', 'unknown',
                           'not_applicable'))
            self.assertIsInstance(check['evidence'], list)
        summary = report['summary']
        self.assertEqual(set(summary), {'pass', 'fail', 'warn', 'unknown'})
        recount = {s: 0 for s in summary}
        for check in report['checks']:
            if check['status'] in recount:
                recount[check['status']] += 1
        self.assertEqual(summary, recount)

    def test_not_applicable_excluded_from_summary(self):
        # empty workspace: RT-MCP-CONFIG has nothing to work on
        with mock.patch('runtime_health.shutil.which', return_value=None):
            report = self.run_env()
        self.assertEqual(_by_id(report, 'RT-MCP-CONFIG')['status'],
                         'not_applicable')
        counted = sum(report['summary'].values())
        real = len([c for c in report['checks']
                    if c['status'] in report['summary']])
        self.assertEqual(counted, real)

    def test_scan_does_not_import_runtime_health(self):
        # the opt-in contract: the static scanner must not pull this
        # module in as a side effect
        code = ("import sys; sys.path.insert(0, %r); "
                "import audit_scan; "
                "print('runtime_health' in sys.modules)" % str(SCRIPTS))
        out = subprocess.run([sys.executable, '-c', code],
                             capture_output=True, text=True, timeout=120)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.strip(), 'False')


class TestPythonCheck(RuntimeHealthCase):
    def test_passes_on_this_interpreter(self):
        report = self.run_env()
        check = _by_id(report, 'RT-PY')
        self.assertEqual(check['status'], 'pass')
        self.assertIn('%d.%d' % sys.version_info[:2], check['detail'])

    def test_fails_below_3_10(self):
        with mock.patch.object(runtime_health.sys, 'version_info',
                               (3, 9, 1)):
            check = runtime_health._check_python()
        self.assertEqual(check['status'], 'fail')
        self.assertIn('3.10', check['detail'])


class TestGitCheck(RuntimeHealthCase):
    def test_pass_when_git_on_path(self):
        with mock.patch('runtime_health.shutil.which',
                        return_value='X:/fake/bin/git.EXE'):
            check = runtime_health._check_git()
        self.assertEqual(check['status'], 'pass')
        self.assertIn('X:/fake/bin/git.EXE', check['evidence'])

    def test_warn_when_git_missing(self):
        with mock.patch('runtime_health.shutil.which', return_value=None):
            check = runtime_health._check_git()
        self.assertEqual(check['status'], 'warn')
        self.assertIn('not found', check['detail'])


class TestCliChecks(RuntimeHealthCase):
    def test_only_installed_harnesses_get_checks(self):
        (self.home / '.claude').mkdir()
        (self.home / '.zcode').mkdir()
        with mock.patch('runtime_health.shutil.which', return_value=None):
            report = self.run_env()
        ids = [c['id'] for c in report['checks']]
        self.assertIn('RT-CLI-CLAUDE_CODE', ids)
        self.assertIn('RT-CLI-ZCODE', ids)
        self.assertNotIn('RT-CLI-CODEX', ids)

    def test_pass_with_version_output(self):
        (self.home / '.zcode').mkdir()
        fake = 'X:/fake/zcode.EXE'

        def which(name):
            return fake if name == 'zcode' else None

        done = subprocess.CompletedProcess(args=[fake, '--version'],
                                           returncode=0,
                                           stdout='zcode 1.2.3\n')
        with mock.patch('runtime_health.shutil.which', side_effect=which), \
                mock.patch('runtime_health.subprocess.run',
                           return_value=done) as run:
            report = self.run_env()
        check = _by_id(report, 'RT-CLI-ZCODE')
        self.assertEqual(check['status'], 'pass')
        self.assertIn('1.2.3', check['detail'])
        # the only spawned command is `<bin> --version`: list argv,
        # no shell, bounded timeout
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args[0][0], [fake, '--version'])
        self.assertFalse(run.call_args[1].get('shell', False))
        self.assertEqual(run.call_args[1].get('timeout'),
                         runtime_health.VERSION_TIMEOUT_SECONDS)

    def test_warn_on_nonzero_exit(self):
        (self.home / '.zcode').mkdir()
        fake = 'X:/fake/zcode.EXE'

        def which(name):
            return fake if name == 'zcode' else None

        done = subprocess.CompletedProcess(args=[fake, '--version'],
                                           returncode=3, stdout='')
        with mock.patch('runtime_health.shutil.which', side_effect=which), \
                mock.patch('runtime_health.subprocess.run',
                           return_value=done):
            report = self.run_env()
        check = _by_id(report, 'RT-CLI-ZCODE')
        self.assertEqual(check['status'], 'warn')
        self.assertIn('code 3', check['detail'])

    def test_warn_on_timeout(self):
        (self.home / '.zcode').mkdir()
        fake = 'X:/fake/zcode.EXE'

        def which(name):
            return fake if name == 'zcode' else None

        boom = subprocess.TimeoutExpired(cmd=[fake, '--version'],
                                         timeout=10)
        with mock.patch('runtime_health.shutil.which', side_effect=which), \
                mock.patch('runtime_health.subprocess.run',
                           side_effect=boom):
            report = self.run_env()
        check = _by_id(report, 'RT-CLI-ZCODE')
        self.assertEqual(check['status'], 'warn')
        self.assertIn('timed out', check['detail'])

    def test_warn_when_binary_not_on_path(self):
        (self.home / '.zcode').mkdir()
        with mock.patch('runtime_health.shutil.which', return_value=None):
            report = self.run_env()
        check = _by_id(report, 'RT-CLI-ZCODE')
        self.assertEqual(check['status'], 'warn')
        self.assertIn('not on PATH', check['detail'])

    def test_version_skipped_when_subprocess_disabled(self):
        (self.home / '.zcode').mkdir()
        fake = 'X:/fake/zcode.EXE'

        def which(name):
            return fake if name == 'zcode' else None

        with mock.patch('runtime_health.shutil.which', side_effect=which), \
                mock.patch('runtime_health.subprocess.run',
                           side_effect=AssertionError(
                               'must not spawn')) as run:
            report = self.run_env(allow_subprocess=False)
        check = _by_id(report, 'RT-CLI-ZCODE')
        self.assertEqual(check['status'], 'pass')
        self.assertIn('skipped', check['detail'])
        run.assert_not_called()

    def test_not_applicable_for_gui_and_plugin_harnesses(self):
        # cursor / windsurf / github_copilot have no CLI binary; their
        # adapters ship empty home_markers, so the branch is probed
        # through the per-harness check directly
        for hid in ('github_copilot', 'cursor', 'windsurf'):
            adapter = get_adapter(hid)
            check = runtime_health._check_cli(
                adapter, ['%s home marker' % hid], allow_subprocess=True)
            self.assertEqual(check['status'], 'not_applicable', hid)
            self.assertEqual(check['id'], 'RT-CLI-%s' % hid.upper())


class TestMcpConfigChecks(RuntimeHealthCase):
    def test_not_applicable_without_detected_harnesses(self):
        report = self.run_env()
        self.assertEqual(_by_id(report, 'RT-MCP-CONFIG')['status'],
                         'not_applicable')

    def test_invalid_json_fails(self):
        (self.root / '.mcp.json').write_text('{not json',
                                             encoding='utf-8')
        report = self.run_env()
        check = _by_id(report, 'RT-MCP-CONFIG')
        self.assertEqual(check['status'], 'fail')
        self.assertTrue(any('.mcp.json' in e for e in check['evidence']))

    def test_top_level_non_object_fails(self):
        (self.root / '.mcp.json').write_text('[1, 2, 3]',
                                             encoding='utf-8')
        report = self.run_env()
        self.assertEqual(_by_id(report, 'RT-MCP-CONFIG')['status'],
                         'fail')

    def test_valid_claude_map_passes(self):
        # .mcp.json: the whole top-level object IS the server map
        (self.root / '.mcp.json').write_text(
            '{"weather": {"command": "npx"}}', encoding='utf-8')
        report = self.run_env()
        check = _by_id(report, 'RT-MCP-CONFIG')
        self.assertEqual(check['status'], 'pass')
        self.assertTrue(any('server map' in e for e in check['evidence']))

    def test_zcode_nested_mcp_servers_passes(self):
        zdir = self.root / '.zcode'
        zdir.mkdir()
        (zdir / 'config.json').write_text(
            '{"mcp": {"servers": {"weather": {}}}}', encoding='utf-8')
        report = self.run_env()
        check = _by_id(report, 'RT-MCP-CONFIG')
        self.assertEqual(check['status'], 'pass')
        self.assertTrue(any('mcp.servers' in e for e in check['evidence']))

    def test_toml_config(self):
        cdir = self.root / '.codex'
        cdir.mkdir()
        (cdir / 'config.toml').write_text(
            '[mcp_servers.weather]\ncommand = "npx"\n', encoding='utf-8')
        report = self.run_env()
        check = _by_id(report, 'RT-MCP-CONFIG')
        # Python 3.10 has no tomllib: structure stays unknown there
        expected = 'pass' if runtime_health.tomllib else 'unknown'
        self.assertEqual(check['status'], expected)

    def test_invalid_toml(self):
        cdir = self.root / '.codex'
        cdir.mkdir()
        (cdir / 'config.toml').write_text('broken = [', encoding='utf-8')
        report = self.run_env()
        check = _by_id(report, 'RT-MCP-CONFIG')
        if runtime_health.tomllib:
            self.assertEqual(check['status'], 'fail')
        else:
            self.assertEqual(check['status'], 'unknown')

    def test_detected_harness_without_mcp_files_passes(self):
        gh = self.root / '.github'
        gh.mkdir()
        (gh / 'copilot-instructions.md').write_text('rules',
                                                    encoding='utf-8')
        report = self.run_env()
        check = _by_id(report, 'RT-MCP-CONFIG')
        self.assertEqual(check['status'], 'pass')
        self.assertIn('no MCP config files', check['detail'])


class TestPathCheck(RuntimeHealthCase):
    def test_fail_when_path_empty(self):
        with mock.patch.dict(os.environ, {'PATH': ''}):
            check = runtime_health._check_path()
        self.assertEqual(check['status'], 'fail')

    def test_warn_on_single_entry(self):
        with mock.patch.dict(os.environ, {'PATH': '/only/one'}):
            check = runtime_health._check_path()
        self.assertEqual(check['status'], 'warn')

    def test_pass_with_normal_path(self):
        fake_git = self.home / 'git.EXE'
        fake_git.write_text('', encoding='utf-8')
        good = os.pathsep.join([str(self.home), str(self.root)])
        with mock.patch.dict(os.environ, {'PATH': good}), \
                mock.patch('runtime_health.shutil.which',
                           return_value=str(fake_git)):
            check = runtime_health._check_path()
        self.assertEqual(check['status'], 'pass')
        self.assertTrue(any('git directory' in e
                            for e in check['evidence']))


class TestLockDir(RuntimeHealthCase):
    def test_pass_without_trash_dir(self):
        check = runtime_health._check_lock_dir(self.ctx())
        self.assertEqual(check['status'], 'pass')
        self.assertIn(runtime_health.TRASH_DIR_NAME, check['detail'])

    def _make_lock(self):
        run_dir = (self.root / runtime_health.TRASH_DIR_NAME
                   / '20260101-000000-abcd1234')
        run_dir.mkdir(parents=True)
        lock = run_dir / 'ops.lock'
        lock.write_text('', encoding='utf-8')
        return lock

    def test_stale_lock_warns(self):
        lock = self._make_lock()
        old = time.time() - 2 * runtime_health.STALE_LOCK_SECONDS
        os.utime(lock, (old, old))
        check = runtime_health._check_lock_dir(self.ctx())
        self.assertEqual(check['status'], 'warn')
        self.assertIn('ops.lock', check['detail'])

    def test_fresh_lock_passes(self):
        self._make_lock()
        check = runtime_health._check_lock_dir(self.ctx())
        self.assertEqual(check['status'], 'pass')

    def test_trash_without_locks_passes(self):
        run_dir = self.root / runtime_health.TRASH_DIR_NAME / 'run'
        run_dir.mkdir(parents=True)
        (run_dir / 'manifest.json').write_text('{}', encoding='utf-8')
        check = runtime_health._check_lock_dir(self.ctx())
        self.assertEqual(check['status'], 'pass')


if __name__ == '__main__':
    unittest.main()
