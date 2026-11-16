"""Coverage tests for skills/workspace-audit/scripts/audit_scan.py.

Targets the branches the main suite leaves uncovered: OSError guards in
the walk and helpers, repo_extra plumbing (hooks, upstream, nested
repos, remote classification), context/skills/memory checks, the
duplicate hashing stages, and main()'s baseline, profile and exit
paths.

Filesystem states this Windows host cannot produce honestly (symlinks
need a privilege, per-file read denial is not available to the owner)
are simulated with narrow wrappers around pathlib methods: each wrapper
delegates to the real implementation for every name except the one
under test, so only the guard being tested sees the error. git runs
only inside throwaway fixture directories, with GIT_OPTIONAL_LOCKS=0
and a per-command fixture identity.
"""
import errno
import json
import os
import pathlib
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1] / 'skills' / 'workspace-audit' / 'scripts'
sys.path.insert(0, str(SCRIPTS))

import audit_scan  # noqa: E402


def sim_error(message):
    """An OSError pathlib itself tolerates: is_dir()/exists() swallow
    ENOENT, so the simulated failure reaches only the guards that
    catch OSError explicitly."""
    return FileNotFoundError(errno.ENOENT, message)


class ScandirList:
    """A scandir() result built in memory: a one-pass iterator that is
    also a context manager, like the real ScandirIterator os.walk and
    audit_scan both consume."""

    def __init__(self, entries):
        self._iter = iter(entries)

    def __iter__(self):
        return self

    def __next__(self):
        return next(self._iter)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

DEMO_SECRET_LINE = 'password = "DEMO-cov-secret-000000001"'

REPO_A_AGENTS = """# Repo A rules
Keep commits small.
See [background](./missing.md) for history.
The layout is described in `docs/guide.md`.
Run `npm run build` after checkout.
Run `make test` before push.
Use `docker` locally.
Never force-push the main branch.
"""
REPO_A_CLAUDE = """# Repo A claude notes
Always ask before deleting files.
Prefer tiny pull requests.
Update CHANGELOG every release.
Respect the lockfile.
"""
SKILL_ALPHA_1 = ('---\nname: alpha\ndescription: use when testing coverage\n---\n'
                 '# alpha\nbody one\n')
SKILL_ALPHA_2 = ('---\nname: alpha\ndescription: use when asked to test differently\n---\n'
                 '# alpha\nbody two\n')
SKILL_PLUG = ('---\nname: plug\ndescription: use when testing plugins\n---\n'
              '# plug\nbody\n')
SKILL_BETA = '---\nname: beta\ndescription: use when testing project skills\n---\n# beta\n'
SKILL_GAMMA = '---\nname: gamma\ndescription: use when testing claude skills\n---\n# gamma\n'


def force_rmtree(path):
    """rmtree that clears git's read-only flag and tolerates a gone path."""
    def _clear(func, target, _exc):
        try:
            os.chmod(target, stat.S_IWRITE)
            func(target)
        except OSError:
            pass
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=_clear)
    else:
        shutil.rmtree(path, onerror=lambda f, p, e: _clear(f, p, e))


def git_run(repo, *args):
    """git inside a temp fixture; read-only index, fixture identity."""
    env = dict(os.environ, GIT_OPTIONAL_LOCKS='0')
    return subprocess.run(
        ['git', '-C', str(repo),
         '-c', 'user.name=Cov Fixture',
         '-c', 'user.email=cov-fixture@example.com', *args],
        capture_output=True, text=True, encoding='utf-8', errors='replace',
        env=env)


def fake_entry(name, path, *, is_dir_val=False, is_file_val=False,
               stat_result=None):
    """A stand-in DirEntry for branches real directory entries cannot
    reach on this host (an outside-root reparse target, an entry whose
    stat raises, an entry that vanishes mid-walk)."""
    e = mock.Mock()
    e.name = name
    e.path = path
    e.is_symlink.return_value = False
    e.is_dir.side_effect = lambda *a, **k: is_dir_val
    e.is_file.side_effect = lambda *a, **k: is_file_val
    if isinstance(stat_result, Exception):
        e.stat.side_effect = stat_result
    else:
        e.stat.return_value = stat_result
    return e


class AuditScanCase(unittest.TestCase):
    """Temp base + isolated fingerprint key, like the history tests."""

    def setUp(self):
        self.base = Path(tempfile.mkdtemp(prefix='wsa-cov-'))
        self.addCleanup(force_rmtree, self.base)
        os.environ['WORKSPACE_AUDIT_KEY_PATH'] = str(self.base / 'fp_key')
        self.addCleanup(os.environ.pop, 'WORKSPACE_AUDIT_KEY_PATH', None)


# --- small pure helpers ---------------------------------------------------------

class ExistsHelper(AuditScanCase):
    def test_exists_returns_false_when_stat_raises_permission_error(self):
        p = mock.Mock()
        p.exists.side_effect = PermissionError('denied')
        self.assertFalse(audit_scan._exists(p))

    def test_exists_passes_through_for_real_paths(self):
        self.assertTrue(audit_scan._exists(self.base))
        self.assertFalse(audit_scan._exists(self.base / 'nope'))


# --- one rich workspace, scanned once, asserted from several tests --------------

class RichWorkspaceScan(AuditScanCase):
    """A workspace that exercises repo_extra, context checks, skills,
    memory, drift and the duplicate hashing stages in one scan."""

    @classmethod
    def setUpClass(cls):
        cls.base = Path(tempfile.mkdtemp(prefix='wsa-cov-rich-'))
        cls.addClassCleanup(force_rmtree, cls.base)
        os.environ['WORKSPACE_AUDIT_KEY_PATH'] = str(cls.base / 'fp_key')
        cls.addClassCleanup(os.environ.pop, 'WORKSPACE_AUDIT_KEY_PATH', None)
        cls.ws, cls.home = cls._build(cls.base)
        cls.rep = audit_scan.scan(cls.ws, cls.home)

    @staticmethod
    def _build(base):
        ws, home = base / 'ws', base / 'home'
        ws.mkdir()
        home.mkdir()
        # root pair linked by an @AGENTS.md import: no drift expected
        (ws / 'AGENTS.md').write_text('# Root rules\nOne line.\nAnother line.\n')
        (ws / 'CLAUDE.md').write_text('@AGENTS.md\n')
        (ws / 'sub').mkdir()
        (ws / 'sub' / 'AGENTS.md').write_text('# nested\n')

        # repoA: real git repo, github remote, real hook, nested inner repo
        repo_a = ws / 'repoA'
        repo_a.mkdir()
        (repo_a / 'AGENTS.md').write_text(REPO_A_AGENTS)
        (repo_a / 'CLAUDE.md').write_text(REPO_A_CLAUDE)
        (repo_a / 'package.json').write_text('{"scripts": {"start": "echo hi"}}')
        (repo_a / 'inner' / '.git').mkdir(parents=True)
        assert git_run(repo_a, 'init', '-q').returncode == 0
        git_run(repo_a, 'add', 'AGENTS.md', 'CLAUDE.md', 'package.json')
        assert git_run(repo_a, 'commit', '-q', '-m', 'init').returncode == 0
        git_run(repo_a, 'remote', 'add', 'origin',
                'https://github.com/octocat/hello.git')
        (repo_a / '.git' / 'hooks' / 'pre-commit').write_text(
            '#!/bin/sh\ngit add -A\ngit push\nsecret scan\n')

        # seed -> repoB: a clone has an upstream, so ahead/behind parses;
        # eleven nested .git dirs hit the nested_repos cap of 10
        seed = base / 'seed'
        seed.mkdir()
        (seed / 'seed.txt').write_text('seed\n')
        assert git_run(seed, 'init', '-q').returncode == 0
        git_run(seed, 'add', 'seed.txt')
        assert git_run(seed, 'commit', '-q', '-m', 'seed').returncode == 0
        repo_b = ws / 'repoB'
        env = dict(os.environ, GIT_OPTIONAL_LOCKS='0')
        subprocess.run(['git', 'clone', '-q', str(seed), str(repo_b)],
                       check=True, capture_output=True, env=env)
        (repo_b / 'AGENTS.md').write_text(
            '# Repo B rules\nRun npm run start when setup is done.\n')
        (repo_b / 'package.json').write_text('{ nope: broken json')
        for i in range(1, 12):
            (repo_b / ('sub%d' % i) / '.git').mkdir(parents=True)

        # duplicate-size groups: identical 5000-byte pairs (one text, one
        # binary, different content so they stay two groups) and one
        # same-size different-content pair
        dup = ws / 'dup'
        dup.mkdir()
        (dup / 'a.bin').write_text('x' * 5000)
        (dup / 'b.bin').write_text('x' * 5000)
        (dup / 'c.txt').write_text('y' * 5000)
        (dup / 'd.txt').write_text('y' * 5000)
        (dup / 'e1.txt').write_text('a' * 1500)
        (dup / 'e2.txt').write_text('b' * 1500)

        # junk dir subtree accounting
        junk = ws / 'backup_junk'
        junk.mkdir()
        (junk / 'notes.txt').write_text('x' * 100)
        (junk / 'old.zip').write_text('x' * 50)

        # home: harness marker, oversized memory index, diverged skill
        # copies, plugin cache with a SKILL.md that is a directory
        (home / '.zcode' / 'cli' / 'memories').mkdir(parents=True)
        (home / '.zcode' / 'AGENTS.md').write_text('# user rules\n')
        (home / '.zcode' / 'cli' / 'history.jsonl').write_text('{}\n')
        (home / '.zcode' / 'cli' / 'memories' / 'MEMORY.md').write_text(
            'note\n' * 250)
        (home / '.zcode' / 'skills' / 'alpha').mkdir(parents=True)
        (home / '.zcode' / 'skills' / 'alpha' / 'SKILL.md').write_text(SKILL_ALPHA_1)
        (home / '.claude' / 'skills' / 'alpha').mkdir(parents=True)
        (home / '.claude' / 'skills' / 'alpha' / 'SKILL.md').write_text(SKILL_ALPHA_2)
        plug = home / '.zcode' / 'cli' / 'plugins' / 'cache' / 'pkgA' / 'v1'
        plug.mkdir(parents=True)
        (plug / 'SKILL.md').write_text(SKILL_PLUG)
        (home / '.zcode' / 'cli' / 'plugins' / 'cache' / 'pkgB' / 'dirskill'
         / 'SKILL.md').mkdir(parents=True)
        (ws / '.agents' / 'skills' / 'beta').mkdir(parents=True)
        (ws / '.agents' / 'skills' / 'beta' / 'SKILL.md').write_text(SKILL_BETA)
        (ws / '.claude' / 'skills' / 'gamma').mkdir(parents=True)
        (ws / '.claude' / 'skills' / 'gamma' / 'SKILL.md').write_text(SKILL_GAMMA)
        return ws, home

    def top(self, name):
        return next(t for t in self.rep['top_level'] if t['name'] == name)

    def ctx(self, suffix):
        return next(e for e in self.rep['context_files']
                    if e['path'].replace('\\', '/').startswith(suffix))

    def test_repo_extra_hooks_upstream_and_nested_repos(self):
        a = self.top('repoA')
        self.assertEqual(a['kind'], 'repo')
        self.assertEqual(a['git']['remote'], 'https://github.com/octocat/hello.git')
        self.assertEqual(a['extra']['remote_class'], 'external hosting')
        self.assertFalse(a['extra']['credentials_in_remote'])
        self.assertEqual(a['extra']['hooks'],
                         [{'name': 'pre-commit',
                           'flags': {'add_all': True, 'push': True,
                                     'secret_scan': True}}])
        self.assertEqual(a['extra']['nested_repos'], ['inner'])
        self.assertTrue(a['extra']['branch'])

        b = self.top('repoB')
        self.assertEqual(b['extra']['ahead_behind'],
                         {'ahead': 0, 'behind': 0})
        self.assertEqual(len(b['extra']['nested_repos']), 10)  # capped

    def test_context_checks_dead_refs_and_drift(self):
        a = self.ctx('repoA/AGENTS.md')
        self.assertEqual(a['dead_links'], ['./missing.md'])
        self.assertEqual(a['dead_paths'], ['docs/guide.md'])
        self.assertEqual(set(a['dead_commands']),
                         {'npm run build', 'make test'})
        # broken package.json reads as {} -> npm run start is dead
        b = self.ctx('repoB/AGENTS.md')
        self.assertEqual(b['dead_commands'], ['npm run start'])
        # repoA AGENTS/CLAUDE pair diverges; root pair is linked -> no drift
        self.assertEqual([d['path'] for d in self.rep['context_drift']],
                         ['repoA'])
        self.assertLess(self.rep['context_drift'][0]['jaccard'], 0.5)
        self.assertTrue(any(f['section'] == 'context_drift'
                            for f in self.rep['findings']))

    def test_duplicates_full_hash_stages(self):
        groups = {frozenset(p.replace(os.sep, '/') for p in g['files'])
                  for g in self.rep['duplicates']}
        self.assertIn(frozenset(['dup/a.bin', 'dup/b.bin']), groups)
        self.assertIn(frozenset(['dup/c.txt', 'dup/d.txt']), groups)
        self.assertNotIn(frozenset(['dup/e1.txt', 'dup/e2.txt']), groups)

    def test_junk_dir_subtree_accounting(self):
        dirs = {d['path']: d for d in self.rep['junk']['dirs']}
        self.assertIn('backup_junk', dirs)
        self.assertEqual(dirs['backup_junk']['files'], 2)
        self.assertEqual(dirs['backup_junk']['size_bytes'], 150)

    def test_skills_locations_and_diverged_copies(self):
        locs = {e['location'] for e in self.rep['skills']['entries']}
        self.assertEqual(locs, {'user-zcode', 'user-claude', 'project-agents',
                                'project-claude', 'plugins-cache'})
        self.assertTrue(self.rep['skills']['locations_checked'])
        dups = self.rep['skills']['duplicates']
        self.assertEqual(len(dups), 1)
        self.assertEqual((dups[0]['name'], dups[0]['copies'],
                          dups[0]['sync']), ('alpha', 2, 'DIVERGED'))
        self.assertEqual(
            {str(Path(p).resolve()) for p in dups[0]['paths']},
            {str(Path(self.home / '.zcode' / 'skills' / 'alpha'
                                / 'SKILL.md').resolve()),
             str(Path(self.home / '.claude' / 'skills' / 'alpha'
                                / 'SKILL.md').resolve())})
        self.assertTrue(any(f['section'] == 'skills'
                            for f in self.rep['findings']))

    def test_memory_index_over_line_limit(self):
        mem = str(self.home / '.zcode' / 'cli' / 'memories' / 'MEMORY.md')
        tax = self.rep['context_tax']
        self.assertIn(str(Path(mem).resolve()),
                     [f['path'] for f in tax['session_files']
                      if f['role'] == 'memory-index'])
        self.assertEqual(tax['memory_over_lines'],
                         [str(Path(mem).resolve())])
        self.assertEqual(tax['memory_over_limit'], [])  # 250 short lines

    def test_chain_budget_counts_nested_agents_md(self):
        root_agents = (self.ws / 'AGENTS.md').stat().st_size
        expected = root_agents + sum(
            (self.ws / p / 'AGENTS.md').stat().st_size
            for p in ('sub', 'repoA', 'repoB'))
        dot = next(c for c in self.rep['context_budget'] if c['root'] == '.')
        self.assertEqual(dot['total_bytes'], expected)

    def test_harness_marker_mtimes(self):
        zcode = next(t for t in self.rep['harness']['tools']
                     if t['tool'] == 'zcode')
        self.assertTrue(zcode['exists'])
        self.assertEqual(zcode['state'], 'active')  # marker is fresh


# --- filesystem error guards (narrow pathlib/os wrappers) -----------------------

class FsErrorGuards(AuditScanCase):
    """One scan under simulated I/O failures: every guard that catches
    OSError runs, the scan still returns a report."""

    def test_scan_survives_simulated_fs_errors(self):
        ws, home = self.base / 'ws', self.base / 'home'
        repo = ws / 'repoA'
        (repo / '.git' / 'hooks').mkdir(parents=True)  # a plain .git dir is enough
        (repo / '.git' / 'hooks' / 'pre-push').write_text('#!/bin/sh\ngit push\n')
        (repo / 'AGENTS.md').write_text('# repo\n')
        (repo / 'package.json').write_text('{"scripts": {}}')
        dup = ws / 'dup'
        dup.mkdir()
        (dup / 'p.txt').write_text('z' * 1200)
        (dup / 'q.txt').write_text('z' * 1200)
        # big enough to be duplicate candidates (>= 1 KB), so the failed
        # open of locked.env surfaces in the duplicate head stage too
        env_blob = DEMO_SECRET_LINE + '\n' + '#' * 1200 + '\n'
        (dup / 'locked.env').write_text(env_blob)
        (dup / 'open.env').write_text(env_blob)
        junk = ws / 'backup_junk'
        junk.mkdir()
        (junk / 'plain.txt').write_text('x' * 40)
        (junk / 'statfail.bin').write_text('y' * 40)
        (junk / 'link.bin').write_text('y' * 40)
        (ws / 'statfail_top.bin').write_text('y' * 40)
        (ws / 'denied_dir').mkdir()
        (ws / 'mockdir').mkdir()
        (home / '.zcode').mkdir(parents=True)

        fakes = [
            # an existing directory outside the root, spelled with the
            # wrong case: realpath() folds the case back, the boundary
            # check sees an outside target and skips the entry
            fake_entry('outside_link.txt', str(self.base).upper()),
            fake_entry('ghost.bin', str(ws / 'mockdir' / 'ghost.bin'),
                       is_file_val=True, stat_result=OSError('gone')),
            fake_entry('vanish.bin', str(ws / 'mockdir' / 'vanish.bin')),
        ]
        fakes[2].is_dir.side_effect = OSError('entry vanished')

        real_scandir = os.scandir
        # scan() resolves root/home on entry: intercept the resolved forms
        denied = {(ws / 'denied_dir').resolve(), (home / '.zcode').resolve()}

        def scandir_wrap(path=None):
            p = Path(path)
            if p in denied:
                raise OSError('simulated scandir denial')
            it = real_scandir(path)
            if p.name == 'mockdir':
                return ScandirList(list(it) + fakes)
            return it

        real_stat = pathlib.Path.stat

        def stat_wrap(self, *a, **k):
            if self.name.startswith('statfail'):
                raise sim_error('simulated stat failure')
            return real_stat(self, *a, **k)

        real_read_text = pathlib.Path.read_text

        def read_text_wrap(self, *a, **k):
            if self.name in ('package.json', 'pre-push'):
                raise OSError('simulated read failure')
            return real_read_text(self, *a, **k)

        real_open = pathlib.Path.open

        def open_wrap(self, *a, **k):
            if self.name == 'locked.env':
                raise OSError('simulated open failure')
            return real_open(self, *a, **k)

        real_read_bytes = pathlib.Path.read_bytes

        def read_bytes_wrap(self, *a, **k):
            if self.name == 'q.txt':
                raise OSError('simulated read_bytes failure')
            return real_read_bytes(self, *a, **k)

        real_is_symlink = pathlib.Path.is_symlink

        def is_symlink_wrap(self, *a, **k):
            if self.name == 'link.bin':  # the subtree() skip branch
                return True
            return real_is_symlink(self, *a, **k)

        with mock.patch.object(os, 'scandir', scandir_wrap), \
                mock.patch.object(pathlib.Path, 'stat', stat_wrap), \
                mock.patch.object(pathlib.Path, 'read_text', read_text_wrap), \
                mock.patch.object(pathlib.Path, 'open', open_wrap), \
                mock.patch.object(pathlib.Path, 'read_bytes', read_bytes_wrap), \
                mock.patch.object(pathlib.Path, 'is_symlink', is_symlink_wrap):
            rep = audit_scan.scan(ws, home)

        # the outside link is skipped and named; the entry that raised
        # mid-stat and the ghost stat are dropped silently
        self.assertEqual(rep['stats']['skipped_symlinks_outside'], 1)
        self.assertEqual(rep['stats']['skipped_symlink_names'],
                         ['outside_link.txt'])
        # unreadable top-level file keeps its place with metadata only
        top = next(t for t in rep['top_level'] if t['name'] == 'statfail_top.bin')
        self.assertEqual((top['kind'], top['size_bytes']), ('file', 0))
        # both duplicate pairs are broken by the failures
        self.assertEqual(rep['duplicates'], [])
        # locked.env is never read; open.env still reports its secret
        self.assertEqual([s['path'] for s in rep['secrets']],
                         ['dup%sopen.env' % os.sep])
        # junk subtree: link skipped, stat failure skipped, one file left
        dirs = {d['path']: d for d in rep['junk']['dirs']}
        self.assertEqual(dirs['backup_junk']['files'], 1)
        self.assertEqual(dirs['backup_junk']['size_bytes'], 40)
        # directories whose scandir failed or that hold fake entries are
        # never reported empty
        self.assertNotIn('denied_dir', rep['junk']['empty_dirs'])
        self.assertNotIn('mockdir', rep['junk']['empty_dirs'])
        # the unreadable hook was skipped, the harness survived scandir
        repo_top = next(t for t in rep['top_level'] if t['name'] == 'repoA')
        self.assertEqual(repo_top['extra']['hooks'], [])
        zcode = next(t for t in rep['harness']['tools'] if t['tool'] == 'zcode')
        self.assertTrue(zcode['exists'])


# --- enrichment OSError guards ---------------------------------------------------

class EnrichErrorGuards(AuditScanCase):
    def test_scan_survives_enrich_failures(self):
        ws, home = self.base / 'ws', self.base / 'home'
        repo = ws / 'repoC'
        repo.mkdir(parents=True)
        (repo / '.git').mkdir()
        (repo / 'a.txt').write_text('a\n')
        home.mkdir()
        patches = [
            mock.patch.object(audit_scan.enrich, 'harness_states',
                              side_effect=OSError('h1')),
            mock.patch.object(audit_scan.enrich, 'config_integrity',
                              side_effect=OSError('h2')),
            mock.patch.object(audit_scan.enrich, 'heavy_outside_git',
                              side_effect=OSError('h3')),
            mock.patch.object(audit_scan.enrich, 'classify_junk',
                              side_effect=OSError('h4')),
            mock.patch.object(audit_scan.enrich, 'skills_frontmatter',
                              side_effect=OSError('h5')),
        ]
        with patches[0], patches[1], patches[2], patches[3], patches[4]:
            rep = audit_scan.scan(ws, home)
        self.assertEqual(rep['config_integrity'], [])
        self.assertEqual(rep['heavy_outside_git'], [])
        self.assertEqual(rep['junk_classified'], [])
        self.assertEqual(rep['skills_extra'], {})
        self.assertTrue(rep['gates'])  # the scan still produced a report


# --- secret line dedup -----------------------------------------------------------

class SecretDedup(AuditScanCase):
    def test_second_hit_on_the_same_line_is_dropped(self):
        ws, home = self.base / 'ws', self.base / 'home'
        ws.mkdir(parents=True)
        (ws / '.env').write_text(DEMO_SECRET_LINE + '\n')
        two_hits = [
            {'line': 1, 'kind': 'password', 'mask': 'm1',
             'fingerprint': 'f1', 'confidence': 0.9},
            {'line': 1, 'kind': 'token', 'mask': 'm2',
             'fingerprint': 'f2', 'confidence': 0.4},
        ]
        with mock.patch.object(audit_scan.secscan, 'scan_text',
                               return_value=two_hits):
            rep = audit_scan.scan(ws, home)
        self.assertEqual(len(rep['secrets']), 1)
        self.assertEqual(rep['secrets'][0]['kind'], 'password')


# --- git_info porcelain guard ----------------------------------------------------

class GitInfoBlankLines(AuditScanCase):
    def test_git_info_skips_blank_porcelain_lines(self):
        repo = self.base / 'repo'
        repo.mkdir()
        (repo / 'tracked.txt').write_text('t\n')
        assert git_run(repo, 'init', '-q').returncode == 0
        git_run(repo, 'add', 'tracked.txt')
        assert git_run(repo, 'commit', '-q', '-m', 'c1').returncode == 0
        (repo / 'u.txt').write_text('u\n')
        real = audit_scan.run_git

        def with_blank_lines(p, *args):
            rc, out = real(p, *args)
            if args and args[0] == 'status':
                out = out + '\n \n'
            return rc, out

        with mock.patch.object(audit_scan, 'run_git', with_blank_lines):
            info = audit_scan.git_info(repo)
        self.assertEqual(info['untracked'], ['u.txt'])
        self.assertEqual(info['dirty'], [])


# --- history flag plumbing -------------------------------------------------------

class HistoryPlumbing(AuditScanCase):
    def test_history_depth_and_all_refs_reach_repo_extra(self):
        ws, home = self.base / 'ws', self.base / 'home'
        home.mkdir()
        repo = ws / 'hrepo'
        repo.mkdir(parents=True)
        (repo / 'a.txt').write_text('a\n')
        assert git_run(repo, 'init', '-q').returncode == 0
        git_run(repo, 'add', 'a.txt')
        assert git_run(repo, 'commit', '-q', '-m', 'c1').returncode == 0
        (repo / 'b.txt').write_text('b\n')
        git_run(repo, 'add', 'b.txt')
        assert git_run(repo, 'commit', '-q', '-m', 'c2').returncode == 0
        rep = audit_scan.scan(ws, home, deep=True, history_depth=1,
                              history_all_refs=True)
        ex = next(t for t in rep['top_level']
                  if t['name'] == 'hrepo')['extra']
        self.assertIn('history_secrets', ex)
        cov = ex['history_coverage']
        self.assertEqual(cov['max_commits'], 1)
        self.assertEqual(cov['commits_scanned'], 1)
        self.assertEqual(cov['commits_total'], 2)
        self.assertTrue(cov['all_refs'])
        self.assertFalse(cov['complete'])


# --- main() ------------------------------------------------------------------------

class MainCli(AuditScanCase):
    def run_main(self, argv):
        out, err = StringIO(), StringIO()
        with redirect_stdout(out), redirect_stderr(err), \
                mock.patch.object(sys, 'argv', ['audit_scan.py'] + argv):
            code = audit_scan.main()
        return code, out.getvalue(), err.getvalue()

    def tiny_workspace(self):
        ws, home = self.base / 'ws', self.base / 'home'
        ws.mkdir()
        home.mkdir()
        (ws / 'readme.txt').write_text('r\n')
        (ws / 'temp_notes.txt').write_text('t\n')  # junk file -> one finding
        return ws, home

    def test_main_exits_on_not_a_directory(self):
        with self.assertRaises(SystemExit) as cx:
            self.run_main([str(self.base / 'nope'), '--home', str(self.base)])
        self.assertTrue(str(cx.exception).startswith('not a directory'))

    def test_main_exits_on_fingerprint_key_error(self):
        ws, home = self.tiny_workspace()
        (ws / '.env').write_text(DEMO_SECRET_LINE + '\n')
        Path(os.environ['WORKSPACE_AUDIT_KEY_PATH']).write_bytes(b'short')
        out_json = self.base / 'scan.json'
        with self.assertRaises(SystemExit) as cx:
            self.run_main([str(ws), '--home', str(home), '--out', str(out_json)])
        self.assertIn('fingerprint key unavailable', str(cx.exception))
        self.assertIn('fingerprint.py --check', str(cx.exception))

    def test_main_baseline_profile_and_summary(self):
        ws, home = self.tiny_workspace()
        out_json = self.base / 'scan.json'
        self.run_main([str(ws), '--home', str(home), '--out', str(out_json)])
        rep = json.loads(out_json.read_text(encoding='utf-8'))
        kept_fp = rep['findings'][0]['fp']
        old = {'findings': [{'fp': kept_fp, 'section': 'x', 'path': 'y'},
                            {'fp': 'gone-fp', 'section': 'x', 'path': 'z'}]}
        old_json = self.base / 'old.json'
        old_json.write_text(json.dumps(old), encoding='utf-8')

        code, out, err = self.run_main(
            [str(ws), '--home', str(home), '--out', str(out_json),
             '--baseline', str(old_json), '--profile'])
        self.assertIsNone(code)
        rep2 = json.loads(out_json.read_text(encoding='utf-8'))
        self.assertEqual([f['fp'] for f in rep2['diff']['resolved']],
                         ['gone-fp'])
        self.assertNotIn(kept_fp, [f['fp'] for f in rep2['diff']['new']])
        self.assertIn('baseline: ', out)
        self.assertIn('1 resolved', out)
        self.assertTrue(err.startswith('profile '), err)  # per-stage timings
        self.assertTrue(out.startswith('scan: '))  # the summary tally

    def test_main_with_corrupt_baseline_skips_diff(self):
        ws, home = self.tiny_workspace()
        out_json = self.base / 'scan.json'
        bad = self.base / 'bad.json'
        bad.write_text('{ nope', encoding='utf-8')
        _code, out, _err = self.run_main(
            [str(ws), '--home', str(home), '--out', str(out_json),
             '--baseline', str(bad)])
        rep = json.loads(out_json.read_text(encoding='utf-8'))
        self.assertNotIn('diff', rep)
        self.assertNotIn('baseline:', out)

    def test_main_reports_skipped_symlinks(self):
        ws, home = self.tiny_workspace()
        (ws / 'mockdir').mkdir()
        fakes = [fake_entry('outside_link.txt', str(self.base).upper())]
        real_scandir = os.scandir

        def scandir_wrap(path=None):
            it = real_scandir(path)
            if Path(path).name == 'mockdir':
                return ScandirList(list(it) + fakes)
            return it

        out_json = self.base / 'scan.json'
        with mock.patch.object(os, 'scandir', scandir_wrap):
            _code, out, err = self.run_main(
                [str(ws), '--home', str(home), '--out', str(out_json),
                 '--profile'])
        self.assertIn('skipped symlinks pointing outside the root: 1', out)
        self.assertIn("profile symlink/outside skips: 1 ['outside_link.txt']",
                      err)


if __name__ == '__main__':
    unittest.main()
