"""Tests for safe_clean.py: the guided mass-cleanup wizard.

Fixture workspace (temp): one git repo with a committed junk-named file
and an empty dir, plus non-git junk at the workspace root: node_modules,
dist, two old unreferenced junk files (120 days), .env with a secret, a
3-file duplicate group with distinct mtimes, a 600 MB sparse junk file
and two empty dirs. The CLI runs only against these temp fixtures; git
in them uses a per-command local identity.
"""
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / 'skills' / 'workspace-audit' / 'scripts'
sys.path.insert(0, str(SCRIPTS))

import audit_scan  # noqa: E402
import safe_clean  # noqa: E402

OLD = time.time() - 120 * 86400          # junk age: 120 days
BIG_BYTES = 600 * 1024 * 1024            # over the 500 MB per-item cap
TRASH = safe_clean.TRASH_DIR_NAME


def force_rmtree(path):
    """rmtree that clears the read-only flag git puts on some files."""
    def _onexc(func, p, _exc):
        os.chmod(p, stat.S_IWRITE)
        func(p)
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=_onexc)
    else:
        shutil.rmtree(path, onerror=lambda func, p, _ei: _onexc(func, p, _ei))


def git(repo, *args):
    """git in a fixture repo; commit gets a per-command local identity."""
    args = (['-c', 'user.email=t@example.com', '-c', 'user.name=T'] + list(args)
            if args and args[0] == 'commit' else list(args))
    subprocess.run(['git', '-C', str(repo)] + args,
                   check=True, capture_output=True)


def make_fixture(base):
    """Build the workspace; returns (ws, home, repo)."""
    ws, home = base / 'ws', base / 'home'
    repo = ws / 'repo'
    (repo / 'src').mkdir(parents=True)
    home.mkdir(parents=True)

    # git repo with a TRACKED junk-named file and a normal file
    (repo / 'old-report.txt').write_bytes(b'tracked junk-named content v1')
    (repo / 'src' / 'app.js').write_bytes(b'console.log(1)\n')
    git(repo, 'init', '-q')
    git(repo, 'add', 'old-report.txt', 'src/app.js')
    git(repo, 'commit', '-q', '-m', 'init')
    (repo / 'empty_in_repo').mkdir()

    # safe build artifact: aged (not an active install) and lockfile-backed
    nm = ws / 'node_modules' / 'left-pad'
    nm.mkdir(parents=True)
    (nm / 'index.js').write_bytes(b'module.exports = 1\n' * 10)
    (nm / 'package.json').write_bytes(b'{"name": "left-pad"}')
    (ws / 'package-lock.json').write_bytes(b'{"lockfileVersion": 3}\n')
    _old = time.time() - 30 * 86400
    os.utime(ws / 'node_modules', (_old, _old))

    # cautious build artifact (aged too: fresh = active install)
    (ws / 'dist').mkdir()
    (ws / 'dist' / 'bundle.js').write_bytes(b'console.log(2)\n' * 10)
    os.utime(ws / 'dist', (_old, _old))

    # old unreferenced junk files -> confirmed_unused
    for name, blob in (('screenshot_1.png', b'png' * 100),
                       ('temp_notes.txt', b'notes ' * 20)):
        f = ws / name
        f.write_bytes(blob)
        os.utime(str(f), (OLD, OLD))

    # secret file: must never be touched
    (ws / '.env').write_text('API_TOKEN=sk-test-123456\n', encoding='utf-8')

    # duplicate group: identical blobs, distinct mtimes (keep the newest)
    blob = b'z' * 2048
    for name, days in (('data_a.bin', 200), ('data_b.bin', 100),
                       ('data_c.bin', 0)):
        f = ws / name
        f.write_bytes(blob)
        if days:
            t = time.time() - days * 86400
            os.utime(str(f), (t, t))

    # 600 MB sparse junk-named file: over the cap, no real disk use
    big = ws / 'old-huge.bin'
    with big.open('wb') as fh:
        fh.write(b'x')
    os.truncate(str(big), BIG_BYTES)
    os.utime(str(big), (OLD, OLD))

    # empty dirs
    (ws / 'empty1').mkdir()
    (ws / 'empty2').mkdir()
    return ws, home, repo


class SafeCleanCase(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp())
        self.ws, self.home, self.repo = make_fixture(self.base)
        self.rep = audit_scan.scan(self.ws, self.home)

    def tearDown(self):
        force_rmtree(self.base)

    def paths(self, plan):
        return {i['path'] for i in plan['items']}

    def skipped_for(self, plan, path_tail):
        return [s for s in plan['skipped'] if s['path'].endswith(path_tail)]


class DefaultPlan(SafeCleanCase):
    def test_includes_safe_excludes_unsafe_and_cautious(self):
        plan = safe_clean.build_plan(self.rep)
        paths = self.paths(plan)

        # default-safe: node_modules, empty dirs, confirmed junk
        self.assertIn('node_modules', paths)
        self.assertIn('empty1', paths)
        self.assertIn('empty2', paths)
        self.assertIn(str(Path('repo') / 'empty_in_repo'), paths)
        shot = next(i for i in plan['items']
                    if i['path'].endswith('screenshot_1.png'))
        self.assertEqual(shot['action'], 'trash')
        self.assertEqual(shot['category'], safe_clean.CAT_CONFIRMED)
        self.assertEqual(
            next(i for i in plan['items'] if i['path'] == 'node_modules')['category'],
            safe_clean.CAT_BUILD_SAFE)
        self.assertTrue(all(i['action'] == 'rmdir' for i in plan['items']
                            if i['category'] == safe_clean.CAT_EMPTY))

        # tracked junk-named file: excluded, recorded with one word
        self.assertFalse(any(p.endswith('old-report.txt') for p in paths))
        self.assertEqual(self.skipped_for(plan, 'old-report.txt'),
                         [{'path': str(Path('repo') / 'old-report.txt'),
                           'reason': 'tracked'}])

        # cautious items hidden without the flag
        self.assertNotIn('dist', paths)
        self.assertFalse(any(p.startswith('data_') for p in paths))

        # cap: nothing over 500 MB, big file recorded as oversized
        self.assertTrue(all(i['size'] <= safe_clean.DEFAULT_MAX_BYTES
                            for i in plan['items']))
        self.assertEqual(self.skipped_for(plan, 'old-huge.bin')[0]['reason'],
                         'oversized')

        # .env is never a candidate at all
        self.assertNotIn('.env', paths)
        self.assertFalse(any(s['path'] == '.env' for s in plan['skipped']))

    def test_preview_lists_oversized_with_cap_message(self):
        plan = safe_clean.build_plan(self.rep)
        text = safe_clean.preview_text(plan)
        self.assertIn('old-huge.bin', text)
        self.assertIn('handle these by hand', text)
        self.assertIn('Will NOT touch: tracked files, settings with keys, '
                      'anything the audit is unsure about.', text)


class ExecuteYes(SafeCleanCase):
    def test_moves_to_trash_and_rmdirs(self):
        plan = safe_clean.build_plan(self.rep)
        tracked_content = (self.repo / 'old-report.txt').read_bytes()
        summary = safe_clean.execute(plan, self.ws,
                                     confirm=lambda prompt: 'YES')

        self.assertFalse(summary['declined'])
        trash = Path(summary['trash_dir'])
        self.assertTrue(trash.is_dir())
        self.assertEqual(trash.parent.name, TRASH)
        self.assertRegex(trash.name, r'^\d{8}-\d{6}(-\d+)?$')

        # trash preserves relative paths; originals are gone
        for rel in ('node_modules', 'screenshot_1.png', 'temp_notes.txt'):
            self.assertFalse((self.ws / rel).exists(), rel)
            self.assertTrue((trash / rel).exists(), rel)
        self.assertTrue((trash / 'node_modules' / 'left-pad' / 'index.js').is_file())

        # empty dirs removed in place
        self.assertFalse((self.ws / 'empty1').exists())
        self.assertFalse((self.ws / 'empty2').exists())
        self.assertFalse((self.repo / 'empty_in_repo').exists())
        self.assertEqual(len(summary['removed_dirs']), 3)

        # NEVER items intact
        self.assertEqual((self.repo / 'old-report.txt').read_bytes(),
                         tracked_content)
        self.assertTrue((self.ws / '.env').is_file())

        # summary numbers add up: freed == sum of all planned item sizes
        self.assertEqual(summary['freed_bytes'],
                         sum(i['size'] for i in plan['items']))
        self.assertEqual(len(summary['moved']),
                         sum(1 for i in plan['items'] if i['action'] == 'trash'))
        self.assertEqual(summary['failed'], [])
        self.assertEqual(summary['skipped_safety'], [])


class Declined(SafeCleanCase):
    def test_refusal_touches_nothing(self):
        plan = safe_clean.build_plan(self.rep)
        prompts = []

        def say_no(prompt):
            prompts.append(prompt)
            return 'no'

        summary = safe_clean.execute(plan, self.ws, confirm=say_no)

        self.assertTrue(summary['declined'])
        self.assertEqual(prompts, ['Type YES to clean: '])
        self.assertEqual(summary['moved'], [])
        self.assertEqual(summary['removed_dirs'], [])
        self.assertEqual(summary['freed_bytes'], 0)
        self.assertIsNone(summary['trash_dir'])

        # disk untouched
        self.assertTrue((self.ws / 'node_modules').is_dir())
        self.assertTrue((self.ws / 'screenshot_1.png').is_file())
        self.assertTrue((self.ws / 'empty1').is_dir())
        self.assertFalse((self.ws / TRASH).exists())


class Containment(SafeCleanCase):
    def test_escaping_path_refused_item_skipped(self):
        victim = self.base / 'victim.txt'
        victim.write_bytes(b'do not touch')
        evil = os.path.join(os.pardir, 'victim.txt')
        plan = {'root': str(self.ws), 'max_bytes': safe_clean.DEFAULT_MAX_BYTES,
                'items': [{'path': evil, 'size': 5, 'action': 'trash',
                           'category': safe_clean.CAT_CONFIRMED,
                           'reason': 'crafted', 'cautious': False}],
                'categories': {}, 'skipped': [], 'totals': {'count': 1, 'size_bytes': 5}}
        summary = safe_clean.execute(plan, self.ws,
                                     confirm=lambda prompt: 'YES')

        self.assertEqual(summary['moved'], [])
        self.assertEqual(summary['skipped_safety'],
                         [{'path': evil, 'reason': 'escape'}])
        self.assertEqual(summary['freed_bytes'], 0)
        self.assertEqual(victim.read_bytes(), b'do not touch')

    def test_two_level_traversal_detected_at_plan_time(self):
        rel = os.path.join(os.pardir, os.pardir, 'x')
        why = safe_clean._never_reason(self.ws, rel, 1, None)
        self.assertEqual(why, 'escape')


class SymlinkSkip(SafeCleanCase):
    def test_symlink_item_skipped(self):
        if not hasattr(os, 'symlink'):
            self.skipTest('os.symlink unavailable')
        outside = self.base / 'outside'
        outside.mkdir()
        target = outside / 'target.bin'
        target.write_bytes(b'x' * 16)
        link = self.ws / 'old-link.bin'
        try:
            os.symlink(str(target), str(link))
        except (OSError, NotImplementedError):
            self.skipTest('symlink creation unavailable on this system')

        plan = {'root': str(self.ws), 'max_bytes': safe_clean.DEFAULT_MAX_BYTES,
                'items': [{'path': 'old-link.bin', 'size': 16, 'action': 'trash',
                           'category': safe_clean.CAT_CONFIRMED,
                           'reason': 'crafted', 'cautious': False}],
                'categories': {}, 'skipped': [], 'totals': {'count': 1, 'size_bytes': 16}}
        summary = safe_clean.execute(plan, self.ws,
                                     confirm=lambda prompt: 'YES')

        self.assertEqual(summary['moved'], [])
        self.assertEqual(summary['skipped_safety'],
                         [{'path': 'old-link.bin', 'reason': 'symlink'}])
        self.assertTrue(link.is_symlink())
        self.assertEqual(target.read_bytes(), b'x' * 16)


class CautiousPass(SafeCleanCase):
    def test_duplicates_oldest_trashed_newest_kept_and_dist_included(self):
        plan = safe_clean.build_plan(self.rep, include_cautious=True)
        olds = {i['path'] for i in plan['items']
                if i['category'] == safe_clean.CAT_OLD_COPIES}
        self.assertEqual(olds, {'data_a.bin', 'data_b.bin'})
        self.assertIn('dist', self.paths(plan))

        summary = safe_clean.execute(plan, self.ws,
                                     confirm=lambda prompt: 'YES')
        trash = Path(summary['trash_dir'])

        self.assertTrue((self.ws / 'data_c.bin').is_file())   # newest kept
        self.assertFalse((self.ws / 'data_a.bin').exists())   # oldest trashed
        self.assertFalse((self.ws / 'data_b.bin').exists())
        self.assertTrue((trash / 'data_a.bin').is_file())
        self.assertTrue((trash / 'data_b.bin').is_file())
        self.assertFalse((self.ws / 'dist').exists())


class Cli(SafeCleanCase):
    def run_main(self, *args):
        out, err = StringIO(), StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = safe_clean.main([str(a) for a in args])
        return rc, out.getvalue(), err.getvalue()

    def test_full_run_returns_zero_and_creates_trash(self):
        rc, out, err = self.run_main(self.ws, '--home', self.home, '--yes')
        self.assertEqual(rc, 0)
        self.assertNotIn('sk-test-123456', out + err)   # no raw secret content
        self.assertIn('Moved', out)
        trash = self.ws / TRASH
        self.assertTrue(trash.is_dir())
        self.assertTrue(list(trash.iterdir()))
        self.assertTrue((self.ws / '.env').is_file())

    def test_interactive_decline_returns_zero(self):
        # run the CLI as a subprocess with stdin closed: input() hits EOF,
        # the answer is not YES, the run declines without touching anything
        r = subprocess.run(
            [sys.executable, str(SCRIPTS / 'safe_clean.py'),
             str(self.ws), '--home', str(self.home)],
            stdin=subprocess.DEVNULL, capture_output=True, text=True,
            timeout=120)
        self.assertEqual(r.returncode, 0)
        self.assertIn('Nothing was changed.', r.stdout)
        self.assertTrue((self.ws / 'node_modules').is_dir())
        self.assertFalse((self.ws / TRASH).exists())

    def test_bad_root_returns_two(self):
        rc, _, err = self.run_main(self.base / 'nope', '--home', self.home)
        self.assertEqual(rc, 2)
        self.assertIn('not a directory', err)

    def test_git_dir_root_refused_with_three(self):
        rc, _, err = self.run_main(self.repo / '.git', '--home', self.home)
        self.assertEqual(rc, 3)
        self.assertIn('refusing to run', err)

    def test_nothing_to_clean_returns_one(self):
        empty_ws = self.base / 'empty_ws'
        empty_ws.mkdir()
        rc, out, _ = self.run_main(empty_ws, '--home', self.home, '--yes')
        self.assertEqual(rc, 1)
        self.assertIn('Nothing safe to clean', out)


class ResearchGuards(SafeCleanCase):
    """Two industry-pattern guards applied from docs/research-human-layer.md."""

    def test_recent_build_dir_skipped(self):
        # same fixture, but node_modules touched NOW: active install
        os.utime(self.ws / 'node_modules')
        rep = audit_scan.scan(self.ws, self.home)
        plan = safe_clean.build_plan(rep)
        paths = [i['path'] for i in plan['items']]
        self.assertNotIn('node_modules', paths)
        reasons = {s['path']: s['reason'] for s in plan['skipped']}
        self.assertEqual(reasons.get('node_modules'), 'recent')

    def test_node_modules_without_lockfile_is_cautious(self):
        # aged but no lockfile: not reliably regenerable → cautious tier
        (self.ws / 'package-lock.json').unlink()
        rep = audit_scan.scan(self.ws, self.home)
        default = safe_clean.build_plan(rep)
        self.assertNotIn('node_modules', [i['path'] for i in default['items']])
        cautious = safe_clean.build_plan(rep, include_cautious=True)
        item = next(i for i in cautious['items'] if i['path'] == 'node_modules')
        self.assertEqual(item['category'], safe_clean.CAT_BUILD_CAUTIOUS)
        self.assertTrue(item['cautious'])


if __name__ == '__main__':
    unittest.main()
