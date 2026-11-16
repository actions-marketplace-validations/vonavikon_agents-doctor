"""Security regression suite for the workspace-audit scanner.

Runs skills/workspace-audit/scripts/audit_scan.py end to end against a
planted fixture workspace and checks four properties from the
production-readiness spec:

A. raw planted secrets never appear in any output artifact
   (scan.json, stdout, stderr); evidence stays redacted;
B. redaction does not weaken detection: gate 6 still FAILs and the
   worktree, staged-index and git-history evidence is still collected;
C. symlinks pointing outside the workspace root are not read;
D. the audit is read-only: the git index and the worktree file set are
   untouched.

The suite encodes the post-integration contract for secret evidence
(dict entries with file/line/kind/commit fields and a redacted value,
plus a skipped_symlinks_outside counter in stats).  Against the current
scanner some tests fail on purpose; that red phase documents exactly
what the integration has to fix.  Do not weaken the assertions to force
a green run.
"""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCANNER = REPO_ROOT / 'skills' / 'workspace-audit' / 'scripts' / 'audit_scan.py'

# Unique literal canaries planted into the fixture.  They live only in
# the fixture tree; every assertion below demands they never show up in
# raw form in any scanner output.
CANARIES = {
    'sk': 'sk-CANARY' + 'qz9' * 8,           # sk-token rule, staged file
    'sk2': 'sk-CANARY' + 'mcp7' * 3,         # second sk variant, .mcp.json
    'password': 'CANARY-PASSWORD-zz7spark',  # quoted password literal, .env
    'aws': 'AKIA' + 'CANARYREGRESSION',      # AKIA + 16 uppercase alnum
    'key': 'CANARY-PRIVATE-KEY-BLOCK',       # inside an OpenSSH key block
    'outside': 'sk-OUTSIDE' + 'wm5' * 8,     # reachable only via symlink
}


class SecurityRegressionTest(unittest.TestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        if not SCANNER.exists():
            raise unittest.SkipTest('scanner not found: %s' % SCANNER)

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix='wsa-sec-regress-')
        self.base = Path(self._tmp.name)
        self.symlinks_available = True

    def tearDown(self):
        # git marks its object files read-only; open everything up so
        # TemporaryDirectory cleanup succeeds on Windows
        for dirpath, dirnames, filenames in os.walk(self.base):
            for name in dirnames + filenames:
                try:
                    os.chmod(os.path.join(dirpath, name), 0o777)
                except OSError:
                    pass
        self._tmp.cleanup()

    # --- fixture helpers -------------------------------------------------

    def _git(self, repo, *args):
        cmd = ['git', '-C', str(repo),
               '-c', 'user.name=Security Regression Fixture',
               '-c', 'user.email=fixture@invalid',
               *args]
        result = subprocess.run(cmd, capture_output=True, text=True,
                                encoding='utf-8', errors='replace', timeout=60)
        self.assertEqual(result.returncode, 0,
                         'fixture git %s failed: %s'
                         % (args[0], (result.stderr or '')[:400]))
        return result.stdout

    def build_workspace(self):
        """Plant the fixture.  Returns (root, home)."""
        root = self.base / 'root'
        home = self.base / 'home'
        root.mkdir()
        (home / '.zcode').mkdir(parents=True)

        repo = root / 'repo'
        repo.mkdir()
        self._git(repo, 'init', '-q')

        # commit 1: .env with the password canary (tracked + worktree)
        (repo / '.env').write_text(
            'DB_PASSWORD="%s"\n' % CANARIES['password'], encoding='utf-8')
        self._git(repo, 'add', '.env')
        self._git(repo, 'commit', '-q', '-m', 'add env config')

        # commits 2 and 3: the AWS canary exists only in git history
        api = repo / 'api.txt'
        api.write_text('aws_key=%s\n' % CANARIES['aws'], encoding='utf-8')
        self._git(repo, 'add', 'api.txt')
        self._git(repo, 'commit', '-q', '-m', 'add api key')
        api.write_text('aws_key=placeholder-not-a-secret\n', encoding='utf-8')
        self._git(repo, 'add', 'api.txt')
        self._git(repo, 'commit', '-q', '-m', 'replace api key')

        # staged, never committed: the sk canary lives in the git index
        (repo / 'config').mkdir()
        (repo / 'config' / 'staged.json').write_text(
            '{"api_key": "%s"}\n' % CANARIES['sk'], encoding='utf-8')
        self._git(repo, 'add', 'config/staged.json')

        # worktree-only OpenSSH private key block
        keys = root / 'keys'
        keys.mkdir()
        (keys / 'id_test').write_text(
            '-----BEGIN OPENSSH PRIVATE KEY-----\n'
            '%s\n'
            '-----END OPENSSH PRIVATE KEY-----\n' % CANARIES['key'],
            encoding='utf-8')

        # worktree-only harness config with the second sk variant
        (root / '.mcp.json').write_text(
            '{\n  "Authorization": "%s"\n}\n' % CANARIES['sk2'],
            encoding='utf-8')

        # sibling directory outside the workspace root, reachable only
        # through symlinks
        outside = self.base / 'outside'
        outside.mkdir()
        (outside / 'canary.txt').write_text(
            'token=%s\n' % CANARIES['outside'], encoding='utf-8')
        try:
            os.symlink(
                Path(os.path.relpath(outside / 'canary.txt', root)).as_posix(),
                str(root / 'link-to-outside.txt'))
        except OSError:
            self.symlinks_available = False
        try:
            os.symlink(Path(os.path.relpath(outside, root)).as_posix(),
                       str(root / 'link-dir'),
                       target_is_directory=True)
        except (OSError, NotImplementedError):
            # nice to have: os.walk never follows directory symlinks, the
            # file symlink is the attack surface under test
            pass

        return root, home

    def run_audit(self, root, home, deep=False):
        """Run the scanner end to end.  Returns (report, combined, out)."""
        out_dir = self.base / 'artifacts'
        out_dir.mkdir(exist_ok=True)
        out = out_dir / 'scan.json'
        cmd = [sys.executable, str(SCANNER), str(root),
               '--home', str(home), '--out', str(out)]
        if deep:
            cmd.append('--deep')
        result = subprocess.run(cmd, capture_output=True, text=True,
                                encoding='utf-8', errors='replace',
                                cwd=str(REPO_ROOT), timeout=120)
        combined = (result.stdout or '') + (result.stderr or '')
        try:
            report = json.loads(out.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            self.fail('scanner produced no parseable report (exit %s): %s'
                      % (result.returncode, combined[:600]))
        return report, combined, out

    # --- report helpers ---------------------------------------------------

    def _collect_secret_entries(self, report):
        """All secret evidence: worktree, staged/index, git history."""
        worktree = list(report.get('secrets') or [])
        tracked, history = [], []
        for item in report.get('top_level') or []:
            extra = item.get('extra') or {}
            tracked.extend(extra.get('tracked_secrets') or [])
            history.extend(extra.get('history_secrets') or [])
        return worktree, tracked, history

    @staticmethod
    def _serialized(entry):
        return entry if isinstance(entry, str) else json.dumps(entry, ensure_ascii=False)

    def _assert_redacted(self, entry, where):
        text = self._serialized(entry)
        for name, value in CANARIES.items():
            self.assertNotIn(value, text,
                             '%s entry leaks the raw %s canary: %r'
                             % (where, name, text[:100]))
        masked = ('REDACT' in text.upper()
                  or '***' in text
                  or (isinstance(entry, dict)
                      and any(isinstance(entry.get(k), str)
                              and entry[k].endswith('...')
                              for k in ('preview', 'value'))))
        self.assertTrue(masked, '%s entry carries no redaction marker: %r'
                        % (where, text[:100]))

    @staticmethod
    def _worktree_files(root):
        names = []
        for dirpath, _dirs, files in os.walk(root):
            for fn in files:
                names.append(
                    Path(os.path.join(dirpath, fn)).relative_to(root).as_posix())
        return sorted(names)

    # --- A: no raw secrets in any artifact --------------------------------

    def test_no_raw_secrets_in_artifacts(self):
        root, home = self.build_workspace()
        report, combined, out = self.run_audit(root, home, deep=True)

        report_text = json.dumps(report, ensure_ascii=False)
        raw_text = out.read_bytes().decode('utf-8', errors='replace')
        artifacts = (('scan.json (parsed report)', report_text),
                     ('scan.json (raw file bytes)', raw_text),
                     ('scanner stdout+stderr', combined))
        for name, value in CANARIES.items():
            for label, text in artifacts:
                self.assertNotIn(value, text,
                                 'raw %s canary leaked into %s' % (name, label))

        # detection survived: each evidence channel still has entries,
        # and every entry is visibly redacted
        worktree, tracked, history = self._collect_secret_entries(report)
        self.assertTrue(worktree,
                        'worktree secret findings disappeared from the report')
        self.assertTrue(tracked,
                        'staged/index secret findings disappeared from the report')
        self.assertTrue(history,
                        'git history secret findings disappeared from the report')
        for entry in worktree:
            self._assert_redacted(entry, 'secrets')
        for entry in tracked:
            self._assert_redacted(entry, 'tracked_secrets')
        for entry in history:
            self._assert_redacted(entry, 'history_secrets')

    # --- B: redaction must not weaken detection ---------------------------

    def test_detection_not_weakened(self):
        root, home = self.build_workspace()
        report, _combined, _out = self.run_audit(root, home, deep=True)

        gate6 = next((g for g in report.get('gates', []) if g.get('n') == 6),
                     None)
        self.assertIsNotNone(gate6, 'gate 6 missing from the report')
        self.assertEqual(gate6.get('status'), 'FAIL',
                         'gate 6 must FAIL while planted secrets exist')

        worktree, tracked, history = self._collect_secret_entries(report)
        self.assertGreaterEqual(
            len(worktree), 2,
            'worktree secret findings were weakened (expected at least '
            '.env, .mcp.json, staged.json and the private key file)')
        self.assertTrue(any('.env' in self._serialized(e) for e in worktree),
                        'the .env password finding disappeared')
        self.assertTrue(any('mcp.json' in self._serialized(e) for e in worktree),
                        'the .mcp.json Authorization finding disappeared')
        self.assertTrue(
            any('staged.json' in self._serialized(e) for e in tracked),
            'the staged config/staged.json finding disappeared from '
            'tracked evidence')
        self.assertTrue(
            any(isinstance(e, dict) and e.get('commit')
                and 'api.txt' in self._serialized(e) for e in history),
            'history evidence must attribute an entry to api.txt with a '
            'commit id (dict schema: file, line, kind, commit, value)')

    # --- C: symlinks outside the root are not read -------------------------

    def test_symlink_boundary(self):
        root, home = self.build_workspace()
        if not self.symlinks_available:
            self.skipTest('symlinks unavailable on this platform')
        report, _combined, _out = self.run_audit(root, home, deep=True)

        stats = report.get('stats') or {}
        self.assertGreaterEqual(
            stats.get('skipped_symlinks_outside', 0), 1,
            "stats['skipped_symlinks_outside'] must count symlinks that "
            'resolve outside the workspace root (key absent before '
            'integration)')

        worktree, _tracked, _history = self._collect_secret_entries(report)
        for entry in worktree:
            text = self._serialized(entry)
            if 'link-to-outside' in text:
                self.assertNotIn(
                    CANARIES['outside'], text,
                    'the scanner read a file through a symlink that '
                    'escapes the workspace root')

    # --- D: the audit is read-only -----------------------------------------

    def test_readonly_git_index(self):
        root, home = self.build_workspace()
        index = root / 'repo' / '.git' / 'index'
        if not index.exists():
            self.skipTest('fixture produced no .git/index')
        before = hashlib.sha256(index.read_bytes()).hexdigest()
        files_before = self._worktree_files(root)

        self.run_audit(root, home, deep=False)

        after = hashlib.sha256(index.read_bytes()).hexdigest()
        self.assertEqual(before, after,
                         'the audit rewrote .git/index (git subprocesses '
                         'must run with GIT_OPTIONAL_LOCKS=0 or equivalent)')
        self.assertEqual(files_before, self._worktree_files(root),
                         'the audit changed the worktree file set')


if __name__ == '__main__':
    unittest.main()
