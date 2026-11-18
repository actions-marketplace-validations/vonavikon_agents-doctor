"""Tests for the opt-in runtime environment audit
(skills/agents-doctor/scripts/runtime_health.py).

No real `--version` is ever spawned: shutil.which and subprocess.run
are mocked everywhere a binary probe could fire. The real system facts
used are the interpreter itself (RT-PY, which the scanner requires
anyway) and temp-directory fixtures.
"""
import json
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
                          'RT-PATH', 'RT-LOCK-DIR', 'RT-SKILLS-VERSIONS',
                          'RT-SKILLS-CONFLICTS', 'RT-PLUGIN-FRESHNESS',
                          'RT-MCP-COMMANDS', 'RT-CONFIG-VALIDITY'):
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


class TestSkillsVersions(RuntimeHealthCase):
    def _detect_zcode(self):
        # .agents is a zcode project marker
        (self.root / '.agents').mkdir()

    def _skill(self, base, name, files):
        skill = base / name
        skill.mkdir(parents=True)
        for fname, text in files.items():
            (skill / fname).write_text(text, encoding='utf-8')
        return skill

    def test_not_applicable_without_detected_harnesses(self):
        report = self.run_env()
        self.assertEqual(_by_id(report, 'RT-SKILLS-VERSIONS')['status'],
                         'not_applicable')

    def test_version_from_plugin_json(self):
        self._detect_zcode()
        self._skill(self.root / '.agents' / 'skills', 'alpha',
                    {'plugin.json':
                     '{"name": "alpha", "version": "1.2.3"}'})
        report = self.run_env()
        check = _by_id(report, 'RT-SKILLS-VERSIONS')
        self.assertEqual(check['status'], 'pass')
        joined = '\n'.join(check['evidence'])
        self.assertIn('alpha', joined)
        self.assertIn('1.2.3', joined)
        self.assertIn('plugin.json', joined)

    def test_package_json_used_when_no_plugin_json(self):
        self._detect_zcode()
        self._skill(self.home / '.zcode' / 'skills', 'beta',
                    {'package.json': '{"version": "0.9.0"}'})
        with mock.patch('runtime_health.shutil.which', return_value=None):
            report = self.run_env()
        check = _by_id(report, 'RT-SKILLS-VERSIONS')
        self.assertEqual(check['status'], 'pass')
        self.assertTrue(any('beta' in e and '0.9.0' in e
                            and 'package.json' in e
                            for e in check['evidence']))

    def test_version_from_skill_md_frontmatter(self):
        self._detect_zcode()
        self._skill(self.root / '.agents' / 'skills', 'gamma',
                    {'SKILL.md': '---\nname: gamma\nversion: 2.0.0\n'
                                 'description: x\n---\n\nbody\n'})
        report = self.run_env()
        check = _by_id(report, 'RT-SKILLS-VERSIONS')
        self.assertEqual(check['status'], 'pass')
        self.assertTrue(any('gamma' in e and '2.0.0' in e
                            and 'SKILL.md' in e
                            for e in check['evidence']))

    def test_skill_without_version_is_listed_as_such(self):
        self._detect_zcode()
        self._skill(self.root / '.agents' / 'skills', 'bare',
                    {'SKILL.md': '---\nname: bare\ndescription: x\n'
                                 '---\n\nbody\n'})
        report = self.run_env()
        check = _by_id(report, 'RT-SKILLS-VERSIONS')
        self.assertEqual(check['status'], 'pass')
        self.assertTrue(any('bare' in e and 'no version' in e
                            for e in check['evidence']))
        self.assertIn('without', check['detail'])

    def test_container_directories_are_skipped(self):
        # children of a skills location that have none of
        # SKILL.md/plugin.json/package.json are containers (the
        # marketplace level of a plugin cache), not skills
        self._detect_zcode()
        skills = self.root / '.agents' / 'skills'
        self._skill(skills, 'real',
                    {'SKILL.md': '---\nname: real\n---\n'})
        (skills / 'not-a-skill').mkdir()
        (skills / 'not-a-skill' / 'README.md').write_text('x',
                                                          encoding='utf-8')
        market = (self.home / '.zcode' / 'cli' / 'plugins' / 'cache'
                  / 'some-market')
        market.mkdir(parents=True)
        (market / 'some-plugin').mkdir()
        with mock.patch('runtime_health.shutil.which', return_value=None):
            report = self.run_env()
        check = _by_id(report, 'RT-SKILLS-VERSIONS')
        joined = '\n'.join(check['evidence'])
        self.assertIn('real', joined)
        self.assertNotIn('not-a-skill', joined)
        self.assertNotIn('some-market', joined)
        self.assertNotIn('some-plugin', joined)

    def test_inventory_capped_at_limit(self):
        self._detect_zcode()
        skills = self.root / '.agents' / 'skills'
        for i in range(runtime_health.SKILLS_INVENTORY_CAP + 50):
            self._skill(skills, 'skill-%03d' % i,
                        {'plugin.json': '{"version": "1.0.%d"}' % i})
        report = self.run_env()
        check = _by_id(report, 'RT-SKILLS-VERSIONS')
        self.assertEqual(check['status'], 'pass')
        self.assertEqual(len(check['evidence']),
                         runtime_health.SKILLS_INVENTORY_CAP)
        self.assertIn('capped', check['detail'])


class TestSkillsConflicts(RuntimeHealthCase):
    def _detect_zcode(self):
        (self.root / '.agents').mkdir()

    def _skill(self, base, name, version):
        skill = base / name
        skill.mkdir(parents=True)
        if version is None:
            (skill / 'SKILL.md').write_text(
                '---\nname: %s\ndescription: x\n---\n' % name,
                encoding='utf-8')
        else:
            (skill / 'plugin.json').write_text(
                '{"version": "%s"}' % version, encoding='utf-8')

    def _conflicts(self, report):
        return _by_id(report, 'RT-SKILLS-CONFLICTS')

    def test_conflicting_versions_warn(self):
        self._detect_zcode()
        self._skill(self.root / '.agents' / 'skills', 'foo', '1.0.0')
        self._skill(self.home / '.zcode' / 'skills', 'foo', '1.1.0')
        with mock.patch('runtime_health.shutil.which', return_value=None):
            report = self.run_env()
        check = self._conflicts(report)
        self.assertEqual(check['status'], 'warn')
        joined = '\n'.join(check['evidence'])
        self.assertIn('foo', joined)
        self.assertIn('1.0.0', joined)
        self.assertIn('1.1.0', joined)

    def test_same_version_in_two_locations_passes(self):
        self._detect_zcode()
        self._skill(self.root / '.agents' / 'skills', 'foo', '1.0.0')
        self._skill(self.home / '.zcode' / 'skills', 'foo', '1.0.0')
        with mock.patch('runtime_health.shutil.which', return_value=None):
            report = self.run_env()
        check = self._conflicts(report)
        self.assertEqual(check['status'], 'pass')
        self.assertIn('same', check['detail'])
        self.assertTrue(any('foo' in e for e in check['evidence']))

    def test_unknown_version_is_not_a_conflict(self):
        # None + 1.0.0 across locations is a note, not a verdict:
        # an unknown version is not a *different* version
        self._detect_zcode()
        self._skill(self.root / '.agents' / 'skills', 'foo', '1.0.0')
        self._skill(self.home / '.zcode' / 'skills', 'foo', None)
        with mock.patch('runtime_health.shutil.which', return_value=None):
            report = self.run_env()
        check = self._conflicts(report)
        self.assertEqual(check['status'], 'pass')

    def test_single_location_passes(self):
        self._detect_zcode()
        self._skill(self.root / '.agents' / 'skills', 'solo', '1.0.0')
        report = self.run_env()
        check = self._conflicts(report)
        self.assertEqual(check['status'], 'pass')
        self.assertIn('no skill name appears', check['detail'])

    def test_not_applicable_without_skills(self):
        self._detect_zcode()
        report = self.run_env()
        self.assertEqual(_by_id(report, 'RT-SKILLS-CONFLICTS')['status'],
                         'not_applicable')


class TestPluginFreshness(RuntimeHealthCase):
    def _plug(self, harness_parts, market, plugin):
        plug = self.home.joinpath(*harness_parts, market, plugin)
        plug.mkdir(parents=True)
        return plug

    def test_not_applicable_without_cache(self):
        check = runtime_health._check_plugin_freshness(self.home)
        self.assertEqual(check['status'], 'not_applicable')
        self.assertIn('plugin cache', check['detail'])

    def test_empty_cache_not_applicable(self):
        (self.home / '.zcode' / 'cli' / 'plugins' / 'cache').mkdir(
            parents=True)
        check = runtime_health._check_plugin_freshness(self.home)
        self.assertEqual(check['status'], 'not_applicable')

    def test_fresh_plugins_pass(self):
        self._plug(('.zcode', 'cli', 'plugins', 'cache'), 'm1', 'a')
        self._plug(('.claude', 'plugins', 'cache'), 'm2', 'b')
        check = runtime_health._check_plugin_freshness(self.home)
        self.assertEqual(check['status'], 'pass')
        joined = '\n'.join(check['evidence'])
        self.assertIn('within the last %d days'
                      % runtime_health.PLUGIN_FRESHNESS_DAYS, joined)

    def test_old_plugin_is_informational_not_warn(self):
        plug = self._plug(('.zcode', 'cli', 'plugins', 'cache'), 'm1',
                          'ancient')
        age_days = runtime_health.PLUGIN_FRESHNESS_DAYS + 20
        old = time.time() - age_days * 86400
        os.utime(plug, (old, old))
        check = runtime_health._check_plugin_freshness(self.home)
        # a plugin is under no obligation to update: never a warn
        self.assertEqual(check['status'], 'pass')
        self.assertIn('informational', check['detail'])
        self.assertTrue(any('ancient' in e and 'days since last change'
                            in e for e in check['evidence']))


class TestMcpCommands(RuntimeHealthCase):
    def _write_mcp(self, servers):
        (self.root / '.mcp.json').write_text(
            json.dumps({'mcpServers': servers}), encoding='utf-8')

    def test_not_applicable_without_servers(self):
        report = self.run_env()
        self.assertEqual(_by_id(report, 'RT-MCP-COMMANDS')['status'],
                         'not_applicable')

    def test_command_on_path_passes(self):
        self._write_mcp({'srv': {'command': 'npx -y @scope/server-x',
                                 'args': ['--flag']}})
        fake = 'X:/fake/npx.cmd'
        with mock.patch('runtime_health.shutil.which',
                        return_value=fake) as which:
            report = self.run_env()
        check = _by_id(report, 'RT-MCP-COMMANDS')
        self.assertEqual(check['status'], 'pass')
        joined = '\n'.join(check['evidence'])
        self.assertIn('srv', joined)
        self.assertIn(fake, joined)
        # only the command token is looked up, never its arguments
        probed = [c[0][0] for c in which.call_args_list]
        self.assertIn('npx', probed)
        self.assertNotIn('-y', probed)
        self.assertNotIn('@scope/server-x', probed)

    def test_missing_command_warns(self):
        self._write_mcp({'srv': {'command': 'no-such-bin-9x'}})
        with mock.patch('runtime_health.shutil.which', return_value=None):
            report = self.run_env()
        check = _by_id(report, 'RT-MCP-COMMANDS')
        self.assertEqual(check['status'], 'warn')
        self.assertTrue(any("'no-such-bin-9x' not found on PATH" in e
                            for e in check['evidence']))

    def test_whitespace_command_warns(self):
        self._write_mcp({'srv': {'command': '   '}})
        with mock.patch('runtime_health.shutil.which', return_value=None):
            report = self.run_env()
        check = _by_id(report, 'RT-MCP-COMMANDS')
        self.assertEqual(check['status'], 'warn')
        self.assertTrue(any('empty command' in e
                            for e in check['evidence']))

    def test_http_only_servers_not_applicable(self):
        self._write_mcp({'weather': {'url': 'https://example.com/mcp'}})
        report = self.run_env()
        check = _by_id(report, 'RT-MCP-COMMANDS')
        self.assertEqual(check['status'], 'not_applicable')
        self.assertTrue(any('http transport' in e
                            for e in check['evidence']))

    def test_env_values_never_reach_the_report(self):
        canary = 'sk-CANARY-runtime-9f3a'
        self._write_mcp({'srv': {'command': 'npx',
                                 'env': {'API_TOKEN': canary}}})
        with mock.patch('runtime_health.shutil.which',
                        return_value='X:/fake/npx.cmd'):
            report = self.run_env()
        dumped = json.dumps(report)
        self.assertNotIn(canary, dumped)
        self.assertNotIn('API_TOKEN', dumped)


class TestConfigValidity(RuntimeHealthCase):
    def test_not_applicable_without_detected_harnesses(self):
        report = self.run_env()
        self.assertEqual(_by_id(report, 'RT-CONFIG-VALIDITY')['status'],
                         'not_applicable')

    def test_invalid_json_fails(self):
        zdir = self.root / '.zcode'
        zdir.mkdir()
        (zdir / 'config.json').write_text('{not json', encoding='utf-8')
        report = self.run_env()
        check = _by_id(report, 'RT-CONFIG-VALIDITY')
        self.assertEqual(check['status'], 'fail')
        joined = '\n'.join(check['evidence'])
        self.assertIn('config.json', joined)
        self.assertIn('invalid JSON', joined)

    def test_valid_configs_pass(self):
        zdir = self.root / '.zcode'
        zdir.mkdir()
        (zdir / 'config.json').write_text(
            '{"mcp": {"servers": {}}}', encoding='utf-8')
        report = self.run_env()
        check = _by_id(report, 'RT-CONFIG-VALIDITY')
        self.assertEqual(check['status'], 'pass')
        self.assertIn('parse cleanly', check['detail'])

    def test_invalid_toml(self):
        cdir = self.root / '.codex'
        cdir.mkdir()
        (cdir / 'config.toml').write_text('broken = [', encoding='utf-8')
        report = self.run_env()
        check = _by_id(report, 'RT-CONFIG-VALIDITY')
        expected = 'fail' if runtime_health.tomllib else 'unknown'
        self.assertEqual(check['status'], expected)

    def test_detected_without_config_files_passes(self):
        (self.root / 'AGENTS.md').write_text('rules', encoding='utf-8')
        report = self.run_env()
        check = _by_id(report, 'RT-CONFIG-VALIDITY')
        self.assertEqual(check['status'], 'pass')
        self.assertIn('no config files', check['detail'])


if __name__ == '__main__':
    unittest.main()
