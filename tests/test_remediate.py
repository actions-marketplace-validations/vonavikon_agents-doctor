"""Stage-5 tests: remediate.py plan / apply_plan / reaudit and safety rails.

Same tiny fixture as test_cli.py: one git repo (dead link in AGENTS.md,
empty dir, no .gitignore) plus, for the trash test, an old untracked
junk file at the workspace root so the classifier marks it
confirmed_unused.
"""
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / 'skills' / 'workspace-audit' / 'scripts'
sys.path.insert(0, str(SCRIPTS))

import audit_scan  # noqa: E402
import remediate  # noqa: E402

AGENTS_MD = ('# Project rules\n'
             '\n'
             'See [docs](./missing.md) for the background.\n'
             '- keep commits small\n')


def force_rmtree(path):
    """rmtree that clears the read-only flag git puts on some files."""
    def _onexc(func, p, _exc):
        os.chmod(p, stat.S_IWRITE)
        func(p)
    shutil.rmtree(path, onexc=_onexc)


def build_workspace(base):
    ws, home = base / 'ws', base / 'home'
    repo = ws / 'repo'
    repo.mkdir(parents=True)
    home.mkdir()
    (repo / 'AGENTS.md').write_text(AGENTS_MD, encoding='utf-8')
    (repo / 'empty').mkdir()
    subprocess.run(['git', '-C', str(repo), 'init', '-q'],
                   check=True, capture_output=True)
    return ws, home, repo


class RemediateCase(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp())
        self.ws, self.home, self.repo = build_workspace(self.base)

    def tearDown(self):
        force_rmtree(self.base)

    def scan(self):
        """Full in-process scan of the fixture, dumped to scan.json."""
        self.scan_path = self.base / 'scan.json'
        self.rep = audit_scan.scan(self.ws, self.home)
        self.scan_path.write_text(
            json.dumps(self.rep, ensure_ascii=False, indent=2), encoding='utf-8')
        return self.rep

    @staticmethod
    def fid_for(rep, needle):
        for f in rep['findings_detailed']:
            if needle in f['title']:
                return f['fid']
        raise AssertionError('no finding titled like %r; got %s'
                             % (needle, [f['title'] for f in rep['findings_detailed']]))

    def apply_quiet(self, steps, root, **kw):
        out = StringIO()
        with redirect_stdout(out):
            report = remediate.apply_plan(steps, str(root), **kw)
        return report


class EmptyDirRmdir(RemediateCase):
    def test_plan_and_apply_removes_empty_dir(self):
        rep = self.scan()
        fid = self.fid_for(rep, 'empty directories')
        steps = remediate.plan(rep, fid)
        self.assertEqual(len(steps), 1)
        self.assertEqual(steps[0]['action'], 'rmdir')
        self.assertEqual(Path(steps[0]['target']),
                         (self.repo / 'empty').resolve())
        self.assertTrue(steps[0]['reversible'])
        report = self.apply_quiet(steps, self.ws, assume_yes=True)
        self.assertEqual(len(report['executed']), 1)
        self.assertEqual(report['failed'], [])
        self.assertEqual(report['skipped'], [])
        self.assertFalse((self.repo / 'empty').exists())


class GitignoreOnce(RemediateCase):
    def test_created_once_then_plan_says_already_exists(self):
        rep = self.scan()
        fid = self.fid_for(rep, 'No .gitignore in repo')
        gi = self.repo / '.gitignore'

        steps = remediate.plan(rep, fid)
        self.assertEqual(steps[0]['action'], 'write_gitignore')
        self.assertNotIn('already exists', steps[0]['note'])
        report = self.apply_quiet(steps, self.ws, assume_yes=True)
        self.assertEqual(len(report['executed']), 1)
        self.assertTrue(gi.is_file())
        content = gi.read_text(encoding='utf-8')
        self.assertIn('.env', content)
        self.assertIn('node_modules', content)

        # stale scan: the finding is still there but the file exists now
        steps2 = remediate.plan(rep, fid)
        self.assertIn('already exists', steps2[0]['note'])
        report2 = self.apply_quiet(steps2, self.ws, assume_yes=True)
        self.assertEqual(report2['executed'], [])
        self.assertEqual(len(report2['skipped']), 1)
        self.assertEqual(gi.read_text(encoding='utf-8'), content)  # no dup write


class TrashMove(RemediateCase):
    def test_confirmed_junk_lands_in_trash_with_relative_path(self):
        junk = self.ws / 'temp-data.txt'   # 'temp' prefix -> junk file rule
        junk.write_text('stale junk\n', encoding='utf-8')
        old = time.time() - 100 * 86400    # older than 90d -> confirmed_unused
        os.utime(junk, (old, old))
        rep = self.scan()
        fid = self.fid_for(rep, 'Unused data (confirmed_unused)')
        steps = remediate.plan(rep, fid)
        self.assertEqual(len(steps), 1)
        self.assertEqual(steps[0]['action'], 'trash_move')
        report = self.apply_quiet(steps, self.ws, assume_yes=True)
        self.assertEqual(len(report['executed']), 1)
        self.assertFalse(junk.exists())

        trash = self.ws / remediate.TRASH_DIR_NAME
        moved = list(trash.rglob('temp-data.txt'))
        self.assertEqual(len(moved), 1)
        self.assertEqual(moved[0].read_text(encoding='utf-8'), 'stale junk\n')
        rel = moved[0].relative_to(trash)
        self.assertEqual(len(rel.parts), 2)          # <timestamp>/temp-data.txt
        self.assertEqual(rel.parts[1], 'temp-data.txt')


class Unsupported(RemediateCase):
    def test_unsupported_fid_raises_naming_the_fid(self):
        rep = self.scan()
        with self.assertRaises(remediate.UnsupportedError) as cm:
            remediate.plan(rep, 'SEC-001')           # exists: no-prevention warn
        self.assertIn('SEC-001', str(cm.exception))
        rul = self.fid_for(rep, 'missing.md')        # dead link: manual fix
        with self.assertRaises(remediate.UnsupportedError) as cm:
            remediate.plan(rep, rul)
        self.assertIn(rul, str(cm.exception))

    def test_unknown_fid_raises(self):
        rep = self.scan()
        with self.assertRaises(remediate.UnsupportedError) as cm:
            remediate.plan(rep, 'NOPE-999')
        self.assertIn('NOPE-999', str(cm.exception))


class Containment(RemediateCase):
    def test_target_outside_root_refused_and_nothing_moves(self):
        outside = self.base / 'escapee.txt'
        outside.write_text('do not touch\n', encoding='utf-8')
        rep = {'root': str(self.ws),
               'findings_detailed': [{
                   'fid': 'HLTH-009', 'gate': 'G9', 'category': 'health',
                   'severity': 'low', 'status': 'warn',
                   'title': 'Unused data (confirmed_unused): ../escapee.txt',
                   'description': 'fabricated', 'confidence': 0.9,
                   'evidence': [{'path': '../escapee.txt'}],
                   'recommendation': 'x', 'autofix_available': True}]}
        with self.assertRaises(ValueError):
            remediate.plan(rep, 'HLTH-009')
        step = {'action': 'trash_move', 'target': str(outside),
                'command': 'move', 'reversible': True, 'note': ''}
        with self.assertRaises(ValueError):
            with redirect_stdout(StringIO()):
                remediate.apply_plan([step], str(self.ws), assume_yes=True)
        self.assertTrue(outside.exists())            # nothing moved
        self.assertFalse((self.ws / remediate.TRASH_DIR_NAME).exists())


class Confirmation(RemediateCase):
    def test_prompt_requires_exactly_yes(self):
        rep = self.scan()
        fid = self.fid_for(rep, 'empty directories')
        steps = remediate.plan(rep, fid)
        for answer in ('no', 'y', 'YES'):
            with mock.patch('builtins.input', return_value=answer):
                report = self.apply_quiet(steps, self.ws)
            self.assertTrue(report['declined'], answer)
            self.assertEqual(report['executed'], [])
            self.assertTrue((self.repo / 'empty').exists())
        with mock.patch('builtins.input', return_value='yes'):
            report = self.apply_quiet(steps, self.ws)
        self.assertFalse(report['declined'])
        self.assertEqual(len(report['executed']), 1)
        self.assertFalse((self.repo / 'empty').exists())

    def test_empty_plan_touches_nothing_and_never_prompts(self):
        with mock.patch('builtins.input',
                        side_effect=AssertionError('prompted on empty plan')):
            report = self.apply_quiet([], self.ws)
        self.assertEqual(report, {'executed': [], 'failed': [],
                                  'skipped': [], 'declined': False})


class Reaudit(RemediateCase):
    def test_reaudit_reports_resolved_empty_dir(self):
        self.scan()
        fid = self.fid_for(self.rep, 'empty directories')
        steps = remediate.plan(self.rep, fid)
        self.apply_quiet(steps, self.ws, assume_yes=True)
        new_rep, diff = remediate.reaudit(self.ws, self.home,
                                          str(self.scan_path))
        self.assertTrue((self.base / 'scan.after.json').is_file())
        self.assertGreaterEqual(len(diff['resolved']), 1)
        self.assertTrue(any('empty' in f['path'] for f in diff['resolved']),
                        diff['resolved'])
        self.assertEqual(new_rep['junk']['empty_dirs'], [])


if __name__ == '__main__':
    unittest.main()
