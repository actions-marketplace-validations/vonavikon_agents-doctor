"""secret_scanner: secret detection and redaction for workspace-audit.

Contract: raw secret values never leave this module. Every finding carries
only the file, line, kind, rule id, confidence, a rule-derived mask and a
salted one-way fingerprint.
"""
import hashlib, re

SALT = 'workspace-audit-v1'

RULES = [
    {'id': 'SEC-001', 'kind': 'api-key', 'mask': 'sk-***',
     'regex': re.compile(r'sk-[A-Za-z0-9_-]{16,}'), 'confidence': 0.95},
    {'id': 'SEC-002', 'kind': 'bearer-token', 'mask': 'Bearer ***',
     'regex': re.compile(r'Bearer\s+[A-Za-z0-9._-]{20,}'), 'confidence': 0.90},
    {'id': 'SEC-003', 'kind': 'aws-access-key', 'mask': 'AKIA***',
     'regex': re.compile(r'\bAKIA[0-9A-Z]{16}\b'), 'confidence': 0.95},
    {'id': 'SEC-004', 'kind': 'private-key', 'mask': 'PRIVATE KEY***',
     'regex': re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----'), 'confidence': 0.99},
    {'id': 'SEC-005', 'kind': 'secret literal', 'mask': '***',
     'regex': re.compile(r'(?i)(?<![a-z0-9])(api[_-]?key|apikey|password|secret|token|authorization)["\']?\s*[:=]\s*["\'][^"\']{8,}'),
     'confidence': 0.70},
]

# POSIX ERE string for `git grep -i -E`: every rule detectable without
# lookbehind/case flags. Used by audit_scan.py.
GIT_GREP_RE = ("sk-[A-Za-z0-9_-]{16,}|Bearer[[:space:]]+[A-Za-z0-9._-]{20,}"
               "|AKIA[0-9A-Z]{16}"
               "|-----BEGIN [A-Z ]*PRIVATE KEY-----"
               "|api[_-]?key[[:space:]]*[:=][[:space:]]*[\"'][^\"']{8,}"
               "|password[[:space:]]*[:=][[:space:]]*[\"'][^\"']{8,}"
               "|token[[:space:]]*[:=][[:space:]]*[\"'][^\"']{8,}")

REDACTED = '[REDACTED]'

# `git grep -n` line: path:line:content. The non-greedy path group plus a
# numeric line group keeps paths containing colons intact (the split lands
# on the first colon-digits-colon run).
_GREP_LINE_RE = re.compile(r'^(.+?):([0-9]+):(.*)$')
_COMMIT_RE = re.compile(r'^commit ([0-9a-f]{7,40})')
_DIFF_FILE_RE = re.compile(r'^\+\+\+ (?:b/)?(.+)$')
_HUNK_RE = re.compile(r'^@@ -[0-9]+(?:,[0-9]+)? \+([0-9]+)(?:,[0-9]+)? @@')


def fingerprint(value: str) -> str:
    """Salted SHA-256, 16 hex chars, 'sha256:' prefix. One-way, rainbow-resistant."""
    return 'sha256:' + hashlib.sha256((SALT + value).encode('utf-8')).hexdigest()[:16]


def find_in_line(line: str):
    """Return the first matching rule dict or None."""
    for rule in RULES:
        if rule['regex'].search(line):
            return rule
    return None


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
