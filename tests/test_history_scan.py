"""Tests for skills/workspace-audit/scripts/history_scan.py.

Builds throwaway git repositories (per-command fixture identity,
GIT_OPTIONAL_LOCKS=0, DEMO-marked synthetic secrets only). Every scan
pins WORKSPACE_AUDIT_KEY_PATH into the temp directory so fingerprints
never touch the real per-installation key.
"""

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / 'skills' / 'workspace-audit' / 'scripts'
sys.path.insert(0, str(SCRIPTS))

import history_scan  # noqa: E402

HISTORY_SECRET = 'api_key = "DEMO-history-secret-0000000000"'
BRANCH_SECRET = 'password = "DEMO-branch-secret-00000000"'


def force_rmtree(path):
    """rmtree that clears the read-only bit git puts on .git internals."""
    def _clear(func, target, _exc):
        try:
            os.chmod(target, stat.S_IWRITE)
            func(target)
        except OSError:
            pass
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=_clear)
    else:
        shutil.rmtree(path, onerror=lambda func, p, exc: _clear(func, p, exc))


class HistoryScanTest(unittest.TestCase):
    maxDiff = None

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix='wsa-hist-test-')
        self.addCleanup(self._tmp.cleanup)
        self.base = Path(self._tmp.name)
        os.environ['WORKSPACE_AUDIT_KEY_PATH'] = str(self.base / 'secret_key')
        self.addCleanup(os.environ.pop, 'WORKSPACE_AUDIT_KEY_PATH', None)

    # --- fixture plumbing --------------------------------------------------

    def _git(self, repo, *args):
        cmd = ['git', '-C', str(repo),
               '-c', 'user.name=History Scan Fixture',
               '-c', 'user.email=fixture@example.com',
               *args]
        r = subprocess.run(cmd, capture_output=True, text=True,
                           encoding='utf-8', errors='replace',
                           env=dict(os.environ, GIT_OPTIONAL_LOCKS='0'),
                           timeout=60)
        if r.returncode != 0:
            self.fail('fixture git %s failed: %s'
                      % (args[0], (r.stderr or '')[:300]))
        return r.stdout

    def build_repo(self):
        """Twelve commits; commit 3 adds creds.py with a DEMO secret and
        commit 5 rewrites the file clean, so the secret lives only in
        history. Returns (repo, sha_of_commit_3)."""
        repo = self.base / 'repo'
        repo.mkdir()
        self._git(repo, 'init', '-q')
        self.branch = self._git(repo, 'symbolic-ref', '--short', 'HEAD').strip()

        def counter_text(upto):
            lines = []
            for i in range(2, upto + 1):
                lines.extend('tick %d.%d' % (i, j) for j in range(1, 6))
            return ''.join(line + '\n' for line in lines)

        plan = [
            ('c1 init', {'README.md': '# history scan fixture\n'}),
            ('c2 counter', {'counter.txt': counter_text(2)}),
            ('c3 add creds', {'creds.py': HISTORY_SECRET + '\n',
                              'counter.txt': counter_text(3)}),
            ('c4 counter', {'counter.txt': counter_text(4)}),
            ('c5 drop creds',
             {'creds.py': 'api_key = None  # loaded from the vault\n',
              'counter.txt': counter_text(5)}),
        ]
        plan.extend(('c%d counter' % i, {'counter.txt': counter_text(i)})
                    for i in range(6, 13))

        secret_sha = None
        for message, files in plan:
            for rel, text in files.items():
                target = repo / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(text, encoding='utf-8')
            self._git(repo, 'add', '-A')
            self._git(repo, 'commit', '-q', '-m', message)
            sha = self._git(repo, 'rev-parse', 'HEAD').strip()
            if message == 'c3 add creds':
                secret_sha = sha
        self.assertIsNotNone(secret_sha)
        return repo, secret_sha

    # --- full history ------------------------------------------------------

    def test_full_scan_finds_secret_only_in_history(self):
        repo, secret_sha = self.build_repo()
        result = history_scan.scan_history(repo)
        self.assertTrue(result['complete'])
        self.assertEqual(result['commits_total'], 12)
        self.assertEqual(result['commits_scanned'], 12)
        self.assertFalse(result['all_refs'])
        self.assertEqual(len(result['findings']), 1)
        finding = result['findings'][0]
        self.assertEqual(finding['file'], 'creds.py')
        self.assertEqual(finding['line'], 1)
        # the introducing commit is reported as its short sha, matching
        # what git rev-parse prints for that commit
        self.assertEqual(finding['commit'], secret_sha[:7])
        self.assertEqual(finding['rule_id'], 'SEC-005')
        self.assertEqual(finding['value'], '[REDACTED]')
        self.assertTrue(finding['fingerprint'].startswith('hmac256:'))
        self.assertNotIn('DEMO-history-secret', json.dumps(result))
        line = history_scan.describe_coverage(result)
        self.assertIn('12/12', line)
        self.assertIn('complete', line)
        self.assertIn('findings 1', line)

    def test_max_commits_cap_reports_incomplete(self):
        repo, _sha = self.build_repo()
        result = history_scan.scan_history(repo, max_commits=5)
        self.assertFalse(result['complete'])
        self.assertEqual(result['commits_total'], 12)
        self.assertEqual(result['commits_scanned'], 5)
        # the 5 newest commits postdate the removal: nothing in the window
        self.assertEqual(result['findings'], [])
        line = history_scan.describe_coverage(result)
        self.assertIn('incomplete (cap 5)', line)
        self.assertIn('5/12', line)

    def test_all_refs_reaches_commit_unreachable_from_head(self):
        repo, _sha = self.build_repo()
        self._git(repo, 'checkout', '-q', '-b', 'side')
        (repo / 'branch_creds.py').write_text(BRANCH_SECRET + '\n',
                                              encoding='utf-8')
        self._git(repo, 'add', 'branch_creds.py')
        self._git(repo, 'commit', '-q', '-m', 'side secret')
        side_sha = self._git(repo, 'rev-parse', 'HEAD').strip()
        self._git(repo, 'checkout', '-q', self.branch)

        head_only = history_scan.scan_history(repo)
        self.assertEqual(head_only['commits_total'], 12)
        self.assertFalse(any(f['file'] == 'branch_creds.py'
                             for f in head_only['findings']))

        everything = history_scan.scan_history(repo, all_refs=True)
        self.assertTrue(everything['all_refs'])
        self.assertTrue(everything['complete'])
        self.assertEqual(everything['commits_total'], 13)
        self.assertEqual(everything['commits_scanned'], 13)
        self.assertEqual(len(everything['findings']), 2)
        side_hit = [f for f in everything['findings']
                    if f['file'] == 'branch_creds.py']
        self.assertEqual(len(side_hit), 1)
        self.assertEqual(side_hit[0]['commit'], side_sha[:7])
        self.assertNotIn('DEMO-branch-secret', json.dumps(everything))

    def test_match_line_injection_counts_and_caps(self):
        repo, _sha = self.build_repo()
        seen = []

        def count_ticker(line):
            seen.append(line)
            if 'tick' in line:
                return {'rule_id': 'TEST-COUNT', 'kind': 'counter line',
                        'confidence': 1.0, 'matched': line}
            return None

        result = history_scan.scan_history(repo, match_line=count_ticker)
        self.assertTrue(result['complete'])
        self.assertEqual(result['commits_scanned'], 12)
        self.assertGreater(len(seen), 60)  # every ' '/'+' line was offered
        self.assertEqual(len(result['findings']), history_scan.MAX_FINDINGS)
        self.assertIs(result.get('findings_truncated'), True)
        first = result['findings'][0]
        self.assertEqual(first['rule_id'], 'TEST-COUNT')
        self.assertEqual(first['file'], 'counter.txt')
        self.assertIsNotNone(first['commit'])
        self.assertTrue(first['fingerprint'].startswith('hmac256:'))

    def test_stream_cleanup_on_scanner_exception_and_after_scan(self):
        repo, _sha = self.build_repo()

        def boom(line):
            raise RuntimeError('injected matcher failure')

        with self.assertRaises(RuntimeError):
            history_scan.scan_history(repo, match_line=boom)
        # git child and pipes must be gone: the repo deletes cleanly on
        # Windows, where an open handle would make rmtree fail
        force_rmtree(repo)
        self.assertFalse(repo.exists())

        repo2, _sha2 = self.build_repo()
        result = history_scan.scan_history(repo2)
        self.assertTrue(result['complete'])
        force_rmtree(repo2)
        self.assertFalse(repo2.exists())

    def test_non_repo_reports_error_not_crash(self):
        not_a_repo = self.base / 'plain'
        not_a_repo.mkdir()
        result = history_scan.scan_history(not_a_repo)
        self.assertFalse(result['complete'])
        self.assertEqual(result['commits_total'], 0)
        self.assertEqual(result['commits_scanned'], 0)
        self.assertEqual(result['findings'], [])
        self.assertIn('error', result)
        self.assertIn('incomplete', history_scan.describe_coverage(result))


if __name__ == '__main__':
    unittest.main()
