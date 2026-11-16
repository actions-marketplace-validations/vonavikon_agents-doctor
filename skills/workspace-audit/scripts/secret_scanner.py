"""secret_scanner: secret detection and redaction for workspace-audit.

Contract: raw secret values never leave this module. Every finding carries
only the file, line, kind, rule id, confidence, a rule-derived mask and an
HMAC-SHA256 fingerprint keyed by a per-installation secret (fingerprint.py).
Rules live in secret_rules.py — the single source shared by the file
scanner, the git-grep filter and the history scanner.
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import secret_rules  # noqa: E402  (single source of detection rules)
import fingerprint as fp_key  # noqa: E402  (per-installation HMAC key)

# Single source of truth: secret_rules.RULES. Each rule there carries
# 'py' (python regex) and 'ere' (POSIX ERE); 'regex' is kept as an alias
# for backward compatibility with older callers/tests.
RULES = secret_rules.RULES
for _r in RULES:
    _r.setdefault('regex', _r['py'])

# POSIX ERE for `git grep -i -E` — generated from the same rule table.
GIT_GREP_RE = secret_rules.GIT_GREP_RE_COMBINED

# Kept for import compatibility; no longer used (HMAC replaced salted sha256).
SALT = 'workspace-audit-v1'

REDACTED = '[REDACTED]'

# `git grep -n` line: path:line:content. The non-greedy path group plus a
# numeric line group keeps paths containing colons intact (the split lands
# on the first colon-digits-colon run).
_GREP_LINE_RE = re.compile(r'^(.+?):([0-9]+):(.*)$')
_COMMIT_RE = re.compile(r'^commit ([0-9a-f]{7,40})')
_DIFF_FILE_RE = re.compile(r'^\+\+\+ (?:b/)?(.+)$')
_HUNK_RE = re.compile(r'^@@ -[0-9]+(?:,[0-9]+)? \+([0-9]+)(?:,[0-9]+)? @@')


def fingerprint(value: str) -> str:
    """HMAC-SHA256 with the per-installation key: 'hmac256:' + 32 hex (128 bits).

    Raises FingerprintKeyError when the local key is unavailable or corrupt —
    never silently falls back to public hashing (see fingerprint.py)."""
    return fp_key.fingerprint(value)


def find_in_line(line: str):
    """Return the first matching rule dict or None (single source: secret_rules)."""
    return secret_rules.find_rule(line)


def scan_text(rel_path: str, text: str) -> list:
    """Scan plain text. One finding per line (first matching rule).

    Finding dict: {file, line, kind, rule_id, confidence, value: '[REDACTED]',
    mask, fingerprint}. fingerprint is computed from the matched substring.
    The matched substring must never be stored anywhere in the output.
    """
    findings = []
    for lineno, line in enumerate(text.splitlines(), 1):
        rule = find_in_line(line)
        if rule is None:
            continue
        match = rule['regex'].search(line)
        findings.append(_finding(rel_path, lineno, rule, match.group(0)))
    return findings


def scan_git_grep_output(out: str) -> list:
    """Parse `git grep -n` output lines 'path:line:content'.

    Finding dict: {file, line, kind, rule_id, confidence, value: '[REDACTED]',
    fingerprint}. The content tail is dropped entirely; the fingerprint comes
    from the matched substring inside the content. Paths may contain spaces
    and colons: lines are split with ^(.+?):([0-9]+):(.*)$ (non-greedy path,
    numeric line), not with rsplit, because the path itself may contain
    colons.
    """
    findings = []
    for raw in out.splitlines():
        parsed = _GREP_LINE_RE.match(raw)
        if not parsed:
            continue
        path, lineno, content = parsed.group(1), int(parsed.group(2)), parsed.group(3)
        rule = find_in_line(content)
        if rule is None:
            continue
        match = rule['regex'].search(content)
        findings.append({
            'file': path,
            'line': lineno,
            'kind': rule['kind'],
            'rule_id': rule['id'],
            'confidence': rule['confidence'],
            'value': REDACTED,
            'fingerprint': fingerprint(match.group(0)),
        })
    return findings


def scan_diff_output(out: str, max_hits: int = 10) -> list:
    """Parse `git log -p` unified diff output.

    Tracks the current commit (^commit <sha>), the new-side file from
    ^+++ b/(path) (/dev/null skipped) and the new-side line counter from
    hunk headers @@ -a,b +c,d @@ (starts at c, increments for ' ' and '+'
    lines, not for '-' or '\\ No newline' lines). Scans only ' ' and '+'
    content lines. Finding dicts additionally carry 'commit' (short sha).
    Stops after max_hits findings.
    """
    findings = []
    commit = None
    path = None
    lineno = 0
    for raw in out.splitlines():
        m = _COMMIT_RE.match(raw)
        if m:
            commit, path, lineno = m.group(1), None, 0
            continue
        m = _DIFF_FILE_RE.match(raw)
        if m:
            name = m.group(1).strip()
            path = None if name.endswith('/dev/null') else name
            lineno = 0
            continue
        m = _HUNK_RE.match(raw)
        if m:
            lineno = int(m.group(1))
            continue
        if raw.startswith('\\'):  # '\ No newline at end of file'
            continue
        if raw and raw[0] not in ' +':
            continue  # '-' line or diff metadata: no scan, no increment
        content = raw[1:]  # ' ' and '+' content lines, '' if stripped empty
        if path is not None:
            rule = find_in_line(content)
            if rule is not None:
                match = rule['regex'].search(content)
                finding = _finding(path, lineno, rule, match.group(0))
                finding['commit'] = commit[:7] if commit else None
                findings.append(finding)
                if len(findings) >= max_hits:
                    return findings
        lineno += 1
    return findings


def _finding(path, lineno, rule, matched):
    """Build a redacted finding dict. `matched` never enters the output."""
    return {
        'file': path,
        'line': lineno,
        'kind': rule['kind'],
        'rule_id': rule['id'],
        'confidence': rule['confidence'],
        'value': REDACTED,
        'mask': rule['mask'],
        'fingerprint': fingerprint(matched),
    }
