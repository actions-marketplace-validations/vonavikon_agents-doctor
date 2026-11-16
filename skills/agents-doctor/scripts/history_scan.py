"""history_scan: bounded, honest git-history secret scanning.

Streams `git log -p` through the same diff state machine as
secret_scanner.scan_diff_output (commit header, '+++ b/<path>', hunk
headers @@ -a,b +c,d @@, new-side line counting on ' ' and '+') without
materializing the log in memory, and reports what was actually scanned:

- commits_total: what `git rev-list --count` reports for HEAD, or for
  --all when all_refs=True (--all walks every ref, so the total can
  exceed branch history);
- commits_scanned: 'commit ' headers actually seen in the stream;
- complete=False whenever commits_scanned < commits_total or the stream
  errored - a capped scan is never reported as exhaustive;
- findings capped at MAX_FINDINGS; further hits set
  findings_truncated=True.

Rules are imported lazily (secret_rules first, secret_scanner.RULES as
the fallback) so this module has no hard dependency on a rules module;
tests inject match_line instead. match_line(line) returns None or a dict
{rule_id, kind, confidence, matched}; 'matched' (the raw substring) is
used only to compute the fingerprint and is never stored. When
'matched' is missing or empty, the whole content line feeds the
fingerprint. Both are one-way: raw values never enter the output.

Finding fingerprints use the sibling fingerprint module (per-installation
HMAC key; WORKSPACE_AUDIT_KEY_PATH pins its location). A missing key is
created on first use; a broken one raises FingerprintKeyError and the
caller decides - no silent fallback here either.

Every git subprocess runs with GIT_OPTIONAL_LOCKS=0 and an explicit
`git -C <repo>`: the scan never refreshes the index and never relies on
the caller's cwd.
"""

import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

DEFAULT = object()  # sentinel: resolve the rules module lazily at call time
MAX_FINDINGS = 50
REDACTED = '[REDACTED]'

_COMMIT_RE = re.compile(r'^commit ([0-9a-f]{7,40})')
_DIFF_FILE_RE = re.compile(r'^\+\+\+ (?:b/)?(.+)$')
_HUNK_RE = re.compile(r'^@@ -[0-9]+(?:,[0-9]+)? \+([0-9]+)(?:,[0-9]+)? @@')

_SCRIPTS_DIR = str(Path(__file__).resolve().parent)


class HistoryScanError(Exception):
    """git cannot be run, or no rules/fingerprint backend is importable."""


def _import_sibling(name):
    """Import a module from this script directory (import-time path fix)."""
    if _SCRIPTS_DIR not in sys.path:
        sys.path.insert(0, _SCRIPTS_DIR)
    return __import__(name)


def _load_rules():
    try:
        return _import_sibling('secret_rules').RULES
    except ImportError:
        pass
    try:
        return _import_sibling('secret_scanner').RULES
    except ImportError:
        raise HistoryScanError('no rules module importable: '
                               'tried secret_rules and secret_scanner') from None


def _load_fingerprint():
    try:
        return _import_sibling('fingerprint').fingerprint
    except ImportError:
        pass
    try:
        return _import_sibling('secret_scanner').fingerprint
    except ImportError:
        raise HistoryScanError(
            'no fingerprint implementation importable') from None


def _default_match_line(rules):
    def match(line):
        for rule in rules:
            found = rule['regex'].search(line)
            if found:
                return {'rule_id': rule['id'], 'kind': rule['kind'],
                        'confidence': rule['confidence'],
                        'matched': found.group(0)}
        return None
    return match


class _DiffStream:
    """The secret_scanner.scan_diff_output state machine, fed one decoded
    log line at a time instead of a fully materialized string."""

    def __init__(self, match_line, fingerprint_value,
                 max_findings=MAX_FINDINGS):
        self.match_line = match_line
        self.fingerprint_value = fingerprint_value
        self.max_findings = max_findings
        self.commit = None
        self.path = None
        self.lineno = 0
        self.commits_scanned = 0
        self.findings = []
        self.hits = 0  # candidate hits, counted even past the findings cap

    def feed(self, line):
        m = _COMMIT_RE.match(line)
        if m:
            self.commit = m.group(1)
            self.commits_scanned += 1
            self.path = None
            self.lineno = 0
            return
        m = _DIFF_FILE_RE.match(line)
        if m:
            name = m.group(1).strip()
            self.path = None if name.endswith('/dev/null') else name
            self.lineno = 0
            return
        m = _HUNK_RE.match(line)
        if m:
            self.lineno = int(m.group(1))
            return
        if line.startswith('\\'):  # '\ No newline at end of file'
            return
        if line and line[0] not in ' +':
            return  # '-' line or diff metadata: no scan, no increment
        content = line[1:]
        if self.path is not None:
            hit = self.match_line(content)
            if hit is not None:
                self._record(content, hit)
        self.lineno += 1

    def _record(self, content, hit):
        self.hits += 1
        if len(self.findings) >= self.max_findings:
            return
        matched = hit.get('matched') or content
        self.findings.append({
            'file': self.path,
            'line': self.lineno,
            'kind': hit.get('kind'),
            'rule_id': hit.get('rule_id'),
            'confidence': hit.get('confidence'),
            'value': REDACTED,
            'fingerprint': self.fingerprint_value(matched),
            'commit': self.commit[:7] if self.commit else None,
        })


def scan_history(repo, max_commits=None, all_refs=False, rules=DEFAULT,
                 match_line=None):
    """Stream `git log -p` through the diff scanner without loading it
    into memory.

    repo: repository path; every git call is `git -C repo`.
    max_commits: cap the log with --max-count=<n>. commits_scanned counts
      the headers actually streamed, so the result stays honest when the
      cap is larger than the repository.
    all_refs: scan `--all` (every ref, not just HEAD); commits_total then
      comes from `rev-list --count --all` and can exceed branch history.
    rules: rule list for the default matcher; the DEFAULT sentinel
      resolves secret_rules lazily, falling back to secret_scanner.RULES.
    match_line: callable(line) -> None or {rule_id, kind, confidence,
      matched}; wins over rules when both are given.

    Returns {findings, commits_scanned, commits_total, complete,
    all_refs, max_commits}, plus findings_truncated=True past
    MAX_FINDINGS and 'error' when git failed. complete is False whenever
    commits_scanned < commits_total or the stream errored.
    """
    repo = Path(repo)
    if match_line is None:
        rule_list = rules if rules is not DEFAULT else _load_rules()
        match_line = _default_match_line(rule_list)
    fingerprint_value = _load_fingerprint()

    total, error = _count_commits(repo, all_refs)
    if error is not None:
        return {'findings': [], 'commits_scanned': 0, 'commits_total': total,
                'complete': False, 'all_refs': bool(all_refs),
                'max_commits': None, 'error': error}

    args = ['log', '-p', '--no-color', '--no-decorate']
    if all_refs:
        args.append('--all')
    cap = None
    if max_commits is not None:
        cap = int(max_commits)
        args.append('--max-count=%d' % cap)

    stream = _DiffStream(match_line, fingerprint_value)
    returncode, log_error = _run_log(repo, args, stream)
    result = {'findings': stream.findings,
              'commits_scanned': stream.commits_scanned,
              'commits_total': total,
              'complete': False,
              'all_refs': bool(all_refs),
              'max_commits': cap}
    if stream.hits > len(stream.findings):
        result['findings_truncated'] = True
    if log_error is not None:
        result['error'] = log_error
    elif returncode == 0 and stream.commits_scanned >= total:
        result['complete'] = True
    return result


def describe_coverage(result):
    """One-line human summary, e.g.
    'history: 24/240 commits scanned (10%) - incomplete (cap 24); findings 3'.
    """
    scanned = result.get('commits_scanned', 0)
    total = result.get('commits_total', 0)
    findings = len(result.get('findings') or [])
    head = 'history: %d/%d commits scanned' % (scanned, total)
    if total:
        head += ' (%d%%)' % round(100.0 * scanned / total)
    if result.get('complete'):
        status = 'complete'
    elif result.get('error'):
        status = 'incomplete (%s)' % str(result['error'])[:80]
    elif result.get('max_commits') is not None:
        status = 'incomplete (cap %s)' % result['max_commits']
    else:
        status = 'incomplete'
    tail = 'findings %d' % findings
    if result.get('findings_truncated'):
        tail += ' (truncated)'
    return '%s - %s; %s' % (head, status, tail)


def _count_commits(repo, all_refs):
    """rev-list --count HEAD (or --all). Returns (count, error)."""
    args = ['rev-list', '--count', '--all' if all_refs else 'HEAD']
    env = dict(os.environ, GIT_OPTIONAL_LOCKS='0')
    try:
        r = subprocess.run(['git', '-C', str(repo), *args],
                           capture_output=True, env=env, timeout=60)
    except OSError as exc:
        return 0, 'cannot run git: %s' % exc
    except subprocess.TimeoutExpired:
        return 0, 'git rev-list timed out'
    if r.returncode != 0:
        err = _first_line(r.stderr.decode('utf-8', errors='replace'))
        return 0, err or ('git rev-list exited with code %d' % r.returncode)
    count = r.stdout.decode('utf-8', errors='replace').strip()
    if not count.isdigit():
        return 0, 'unexpected rev-list output: %r' % count[:64]
    return int(count), None


def _run_log(repo, args, stream):
    """Stream `git log` output line by line into the parser.

    stderr goes to a temp file so a chatty git cannot deadlock the pipe;
    the child and its pipes are reaped in a finally block no matter how
    the stream ends.
    """
    env = dict(os.environ, GIT_OPTIONAL_LOCKS='0')
    with tempfile.TemporaryFile() as errfile:
        try:
            proc = subprocess.Popen(['git', '-C', str(repo), *args],
                                    stdout=subprocess.PIPE, stderr=errfile,
                                    env=env)
        except OSError as exc:
            raise HistoryScanError('cannot run git: %s' % exc) from None
        try:
            for raw in proc.stdout:
                stream.feed(raw.decode('utf-8', errors='replace')
                            .rstrip('\r\n'))
            returncode = proc.wait()
        finally:
            _reap(proc)
        errfile.seek(0)
        err = errfile.read(4096).decode('utf-8', errors='replace')
    if returncode != 0:
        first = _first_line(err)
        return returncode, first or ('git log exited with code %d' % returncode)
    return returncode, None


def _reap(proc):
    """Close the pipe and terminate git on any exit path."""
    try:
        if proc.stdout is not None:
            proc.stdout.close()
    except OSError:
        pass
    if proc.poll() is None:
        proc.kill()
    proc.wait()


def _first_line(text):
    for line in (text or '').splitlines():
        line = line.strip()
        if line:
            return line[:200]
    return None
