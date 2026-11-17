#!/usr/bin/env python3
r"""Corporate policy engine for agents-doctor (TZ v2.1.0).

A policy is a YAML file that says what a workspace must look like; the
engine checks a finished audit (scan.json) plus the workspace files
against it and writes a compliance report. The audit itself is unchanged:
policies only read facts, they never rescan.

    version: 1

    policy:
      secrets:
        severity: critical
      mcp:
        allowlist:
          - approved-server
      instructions:
        require_agents_md: true
      git:
        prevent_secret_commits: true
      permissions:
        forbid_wildcard: true
      content:
        ban_patterns:
          - 'task\$'

    custom_rules:
      - id: POL-CUSTOM-001
        check: content.regex
        patterns: ['inner-project']
        severity: error
        message: Forbidden project name

Every domain is optional: an absent domain leaves its rule not active.
Several files layer: later files win per domain, conflicting severities
resolve to the strictest with a warning. Rule exceptions live in the
workspace .agents-doctor.toml:

    [policy]
    exceptions = { POL-MCP-ALLOWLIST = "local dev stand" }
    files = ["team.yml"]

Secret values never enter a policy and never enter the report: the
secrets check copies only paths, kinds, masks and fingerprints from the
scan, and MCP evidence carries server names and file paths only.

PyYAML parses the files when installed; without it a bundled fallback
parser covers the subset this format needs (nested mappings, block and
inline lists, quoted scalars, comments). A file that does not parse
raises PolicyError with the file name and line -- never a partial
policy. Unknown domains and fields are reported as warnings because
unknown must not read as safe.

Usage:
    from policies import evaluate_policies, render_markdown, PolicyError
    report = evaluate_policies(rep, root, ['corporate.yml', 'team.yml'])
"""
import json
import re
from pathlib import Path

import config  # .agents-doctor.toml: [policy] exceptions / files

__all__ = ['PolicyError', 'evaluate_policies', 'render_markdown',
           'parse_policy_file', 'SEVERITY_MAP', 'RULE_IDS']

try:
    import yaml  # optional, like skills frontmatter parsing
except ImportError:
    yaml = None

try:
    import tomllib  # Python 3.11+
except ImportError:
    tomllib = None

POLICY_SCHEMA_VERSION = '1.0'

# policy severity -> (finding severity, rule/violation status)
SEVERITY_MAP = {
    'critical': ('critical', 'fail'),
    'error': ('high', 'fail'),
    'warning': ('medium', 'warn'),
    'info': ('low', 'info'),
}
SEVERITY_RANK = {'info': 0, 'warning': 1, 'error': 2, 'critical': 3}

# domain -> known fields; 'severity' is known everywhere, the rest is
# the domain's own knob
KNOWN_DOMAINS = {
    'secrets': ('severity', 'block_on_failure'),
    'mcp': ('severity', 'allowlist'),
    'instructions': ('severity', 'require_agents_md'),
    'git': ('severity', 'prevent_secret_commits'),
    'permissions': ('severity', 'forbid_wildcard'),
    'content': ('severity', 'ban_patterns'),
}
DOMAIN_ORDER = ('secrets', 'mcp', 'instructions', 'git', 'permissions',
                'content')

# metadata keys of the policy mapping itself (the TZ format carries a
# name and a description there); not domains, never active
POLICY_META = ('name', 'description')

DEFAULT_DOMAIN_SEVERITY = {
    'secrets': 'critical',
    'mcp': 'error',
    'instructions': 'warning',
    'git': 'critical',
    'permissions': 'error',
    'content': 'error',
}

RULE_IDS = {
    'secrets': 'POL-SECRETS-EXPOSED',
    'mcp': 'POL-MCP-ALLOWLIST',
    'instructions': 'POL-INSTRUCTIONS-AGENTS-MD',
    'git': 'POL-GIT-SECRET-COMMITS',
    'permissions': 'POL-PERMISSIONS-WILDCARD',
    'content': 'POL-CONTENT-BAN-PATTERNS',
}
RULE_TEXTS = {
    'secrets': 'no secrets with fail status in the scan (rep["secrets"])',
    'mcp': 'every configured MCP server is in the allowlist',
    'instructions': 'AGENTS.md or CLAUDE.md exists in the workspace root',
    'git': 'no tracked secrets and a secret-scan hook in every repository',
    'permissions': 'no wildcard or dangerous permission findings in the scan',
    'content': 'no banned pattern in instruction and config files',
}

PERMISSION_CHECK_IDS = ('CLAUDE_SETTINGS_PERMISSIONS_WILDCARD',
                        'CODEX_SANDBOX_DANGER',
                        'CODEX_APPROVAL_NEVER',
                        'OPENCODE_PERMISSIONS_DANGEROUS')

SECRET_SCAN_HOOKS = ('pre-commit', 'pre-push')

# files the content checks read (root-level only), capped per file
CONTENT_FILE_CAP = 256 * 1024


class PolicyError(Exception):
    """A policy file that cannot be used at all. Carries the file name
    and, when the parser knows it, the line number. Raising beats
    half-applying: the caller must not evaluate a partial policy."""

    def __init__(self, filename, lineno, message):
        self.filename = filename
        self.lineno = lineno
        loc = '%s:%s' % (filename, lineno if lineno else '?')
        super().__init__('%s: %s' % (loc, message))


# --- fallback YAML parser (no PyYAML) --------------------------------------------

class _YamlError(ValueError):
    def __init__(self, lineno, message):
        self.lineno = lineno
        super().__init__('line %d: %s' % (lineno, message))


def _cut_comment(raw):
    """Drop a trailing comment: the first '#' outside quotes that starts
    the line or follows whitespace (the YAML rule, so 'a#b' stays)."""
    quote = None
    for i, ch in enumerate(raw):
        if quote is not None:
            if ch == quote:
                quote = None
        elif ch in ('"', "'"):
            quote = ch
        elif ch == '#' and (i == 0 or raw[i - 1] in ' \t'):
            return raw[:i]
    return raw


def _parse_scalar(token, lineno):
    t = token.strip()
    if t in ('true', 'True'):
        return True
    if t in ('false', 'False'):
        return False
    if t in ('null', '~', 'None', ''):
        return None
    if len(t) >= 2 and t[0] == t[-1] and t[0] in ('"', "'"):
        return t[1:-1]
    if t and t[0] in ('"', "'"):
        raise _YamlError(lineno, 'unterminated quoted string: %s' % t)
    if t.startswith('{'):
        raise _YamlError(lineno, 'inline maps are not supported')
    if t.endswith(':') or re.search(r':\s', t):
        # a plain scalar cannot contain ": " in YAML either
        raise _YamlError(lineno, 'cannot parse value: %r' % t)
    if re.fullmatch(r'-?\d+', t):
        return int(t)
    if re.fullmatch(r'-?\d+\.\d+', t):
        return float(t)
    return t


def _split_inline(body, lineno):
    """Split an inline list body on commas outside quotes."""
    items, buf, quote = [], [], None
    for ch in body:
        if quote is not None:
            buf.append(ch)
            if ch == quote:
                quote = None
        elif ch in ('"', "'"):
            quote = ch
            buf.append(ch)
        elif ch == ',':
            items.append(''.join(buf))
            buf = []
        else:
            buf.append(ch)
    if quote is not None:
        raise _YamlError(lineno, 'unterminated quote in inline list')
    if buf:
        items.append(''.join(buf))
    return [i.strip() for i in items if i.strip()]


def _parse_value(text, lineno):
    t = text.strip()
    if t.startswith('['):
        if not t.endswith(']'):
            raise _YamlError(lineno, 'unterminated inline list: %s' % t)
        return [_parse_scalar(s, lineno)
                for s in _split_inline(t[1:-1], lineno)]
    return _parse_scalar(t, lineno)


def _parse_fallback_yaml(text):
    """Parse the subset the policy format needs. Mappings nest by
    indentation, lists use '- ' items (scalars or flat mappings), values
    are scalars or inline lists. Anything else raises _YamlError with
    the line number. Mirrors config.py's fallback TOML parser in spirit:
    a small loud subset instead of a quiet almost-YAML."""
    root = {}
    # frame: {'indent', 'container', 'flat'} -- flat means members sit
    # AT the frame indent (lists and list-item mappings); normal map
    # frames have members strictly deeper than their key
    frames = [{'indent': -1, 'container': root, 'flat': False}]
    pending = None  # {'indent', 'parent', 'key'} for a 'key:' with no value yet

    def pop_for_item(indent):
        # a list item belongs to a list frame at exactly its indent
        while len(frames) > 1:
            top = frames[-1]
            if top['indent'] > indent or (top['indent'] == indent
                                          and not top['flat']):
                frames.pop()
            else:
                break

    def pop_for_key(indent):
        # keys close same-indent list frames (the "a:\n- x\nb: 1"
        # style) but stay inside a list-item mapping at the same indent
        while len(frames) > 1:
            top = frames[-1]
            if top['indent'] > indent:
                frames.pop()
            elif top['indent'] == indent and (not top['flat']
                                              or isinstance(top['container'],
                                                            list)):
                frames.pop()
            else:
                break

    def close_pending():
        nonlocal pending
        if pending is not None:
            pending['parent'][pending['key']] = {}
            pending = None

    for lineno, raw in enumerate(text.splitlines(), 1):
        line = _cut_comment(raw).rstrip()
        if not line.strip():
            continue
        if '\t' in raw[:len(raw) - len(raw.lstrip())]:
            raise _YamlError(lineno, 'tab in indentation')
        indent = len(line) - len(line.lstrip(' '))
        content = line.strip()

        if content == '-' or content.startswith('- '):
            if pending is not None and indent >= pending['indent']:
                # first item of the pending key's list
                lst = []
                pending['parent'][pending['key']] = lst
                frames.append({'indent': indent, 'container': lst,
                               'flat': True})
                pending = None
            else:
                close_pending()
                pop_for_item(indent)
                top = frames[-1]
                if not top['flat'] or not isinstance(top['container'], list) \
                        or top['indent'] != indent:
                    raise _YamlError(lineno,
                                     'list item outside a list')
            rest = content[1:].lstrip()
            if not rest:
                raise _YamlError(lineno, 'empty list item')
            lst = frames[-1]['container']
            if ': ' in rest or rest.endswith(':'):
                key, _, val = rest.partition(':')
                key = key.strip()
                if not key or re.search(r'\s', key):
                    raise _YamlError(lineno,
                                     'bad key in list item: %r' % rest)
                item = {}
                lst.append(item)
                key_col = indent + 1 + (len(content[1:]) - len(rest))
                val = val.strip()
                if val:
                    item[key] = _parse_value(val, lineno)
                else:
                    item[key] = None
                frames.append({'indent': key_col, 'container': item,
                               'flat': True})
            else:
                lst.append(_parse_scalar(rest, lineno))
            continue

        if ': ' in content or content.endswith(':'):
            key, _, val = content.partition(':')
            key = key.strip()
            if len(key) >= 2 and key[0] == key[-1] and key[0] in ('"', "'"):
                key = key[1:-1]
            if not key or re.search(r'\s', key):
                raise _YamlError(lineno, 'bad key: %r' % key)
            if pending is not None:
                if indent > pending['indent']:
                    # first child of the pending key: a mapping
                    new_map = {}
                    pending['parent'][pending['key']] = new_map
                    frames.append({'indent': pending['indent'],
                                   'container': new_map, 'flat': False})
                    pending = None
                else:
                    close_pending()
            pop_for_key(indent)
            top = frames[-1]
            if not isinstance(top['container'], dict):
                raise _YamlError(lineno, 'key inside a list')
            target = top['container']
            if key in target:
                raise _YamlError(lineno, 'duplicate key: %r' % key)
            val = val.strip()
            if val:
                target[key] = _parse_value(val, lineno)
            else:
                pending = {'indent': indent, 'parent': target, 'key': key}
        else:
            raise _YamlError(lineno, 'cannot parse line: %r' % content)

    close_pending()
    return root


# --- policy file loading ----------------------------------------------------------

def parse_policy_file(path):
    """One policy file -> dict. PyYAML when installed, the fallback
    parser otherwise. Raises PolicyError (with file name and line when
    known) on anything unusable; never returns a partial document."""
    p = Path(path)
    try:
        raw = p.read_bytes()
    except OSError as exc:
        raise PolicyError(p.name, None, 'cannot read: %s' % exc)
    try:
        text = raw.decode('utf-8')
    except UnicodeDecodeError as exc:
        raise PolicyError(p.name, None, 'not valid utf-8: %s' % exc)

    if yaml is not None:
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            mark = (getattr(exc, 'problem_mark', None)
                    or getattr(exc, 'context_mark', None))
            lineno = mark.line + 1 if mark else None
            detail = getattr(exc, 'problem', None) or str(exc).splitlines()[0]
            raise PolicyError(p.name, lineno, 'cannot parse YAML: %s' % detail)
        if not isinstance(data, dict):
            raise PolicyError(p.name, None, 'policy file must be a mapping')
        return data

    try:
        return _parse_fallback_yaml(text)
    except _YamlError as exc:
        raise PolicyError(p.name, exc.lineno, str(exc))


def _unknown_warnings(data, fname, warnings):
    """Unknown is not safe: every unrecognized top-level key, domain or
    field becomes a warning instead of silent behaviour."""
    for key in sorted(data):
        if key not in ('version', 'policy', 'custom_rules'):
            warnings.append("%s: unknown top-level field '%s' ignored"
                            % (fname, key))
    pol = data.get('policy')
    if pol is None:
        return
    if not isinstance(pol, dict):
        warnings.append("%s: 'policy' must be a mapping; ignored" % fname)
        return
    for domain in sorted(pol):
        if domain not in KNOWN_DOMAINS:
            if domain not in POLICY_META:
                warnings.append("%s: unknown policy domain '%s' ignored"
                                % (fname, domain))
            continue
        ddef = pol[domain]
        if not isinstance(ddef, dict):
            warnings.append("%s: domain '%s' must be a mapping; ignored"
                            % (fname, domain))
            continue
        for field in sorted(ddef):
            if field not in KNOWN_DOMAINS[domain]:
                warnings.append("%s: unknown field '%s' in domain '%s' "
                                'ignored' % (fname, field, domain))
        sev = ddef.get('severity')
        if sev is not None and sev not in SEVERITY_MAP:
            warnings.append("%s: invalid severity %r in domain '%s'; "
                            'using the domain default'
                            % (fname, sev, domain))
        if domain == 'mcp':
            allow = ddef.get('allowlist')
            if allow is not None and (not isinstance(allow, list)
                                      or not all(isinstance(x, str)
                                                 for x in allow)):
                warnings.append("%s: mcp.allowlist must be a list of "
                                'strings; rule stays inactive' % fname)
        if domain == 'content':
            ban = ddef.get('ban_patterns')
            if ban is not None and (not isinstance(ban, list)
                                    or not all(isinstance(x, str)
                                               for x in ban)):
                warnings.append("%s: content.ban_patterns must be a list "
                                'of strings; rule stays inactive' % fname)
        for flag in ('block_on_failure', 'require_agents_md',
                     'prevent_secret_commits', 'forbid_wildcard'):
            v = ddef.get(flag)
            if v is not None and not isinstance(v, bool):
                warnings.append("%s: %s.%s must be true or false; ignored"
                                % (fname, domain, flag))


def _merge_policy_files(policy_files, warnings):
    """Layer policy files in order: the last file that defined a domain
    wins that domain wholesale; distinct severities for one domain
    produce a warning and the strictest severity wins. Custom rules
    accumulate, a redefined id keeps the later rule. Returns
    (versions, domains, custom_rules)."""
    versions = []
    domains = {}        # domain -> {'def': dict, 'source': str}
    severity_seen = {}  # domain -> {severity: source}
    customs = []        # {'rule': dict, 'source': str}
    custom_by_id = {}
    meta_name = None

    for path in policy_files:
        data = parse_policy_file(path)
        fname = Path(path).name
        version = data.get('version')
        if version is None:
            warnings.append("%s: no 'version' field; the report carries "
                            'null for this file' % fname)
        versions.append({'file': fname, 'version': version})
        _unknown_warnings(data, fname, warnings)

        pol = data.get('policy') or {}
        if not isinstance(pol, dict):
            pol = {}
        if isinstance(pol.get('name'), str) and pol['name']:
            meta_name = pol['name']
        for domain in sorted(pol):
            if domain not in KNOWN_DOMAINS:
                continue  # already warned
            ddef = pol[domain]
            if not isinstance(ddef, dict):
                continue  # already warned
            domains[domain] = {'def': dict(ddef), 'source': fname}
            sev = ddef.get('severity')
            if sev in SEVERITY_MAP:
                severity_seen.setdefault(domain, {})[sev] = fname

        rules = data.get('custom_rules') or []
        if not isinstance(rules, list):
            warnings.append("%s: custom_rules must be a list; ignored"
                            % fname)
            rules = []
        for rule in rules:
            if not isinstance(rule, dict):
                warnings.append('%s: custom rule must be a mapping; '
                                'skipped' % fname)
                continue
            rid = rule.get('id')
            if not isinstance(rid, str) or not rid:
                warnings.append('%s: custom rule without id; skipped'
                                % fname)
                continue
            entry = {'rule': dict(rule), 'source': fname}
            if rid in custom_by_id:
                warnings.append('%s: custom rule %s redefined; the later '
                                'one wins' % (fname, rid))
                customs[custom_by_id[rid]] = entry
            else:
                customs.append(entry)
                custom_by_id[rid] = len(customs) - 1

    for domain in sorted(severity_seen):
        sevs = severity_seen[domain]
        if len(sevs) > 1:
            strictest = max(sorted(sevs), key=lambda s: SEVERITY_RANK[s])
            warnings.append(
                "conflicting severity for domain '%s': %s; using the "
                'strictest (%s)'
                % (domain,
                   ', '.join('%s in %s' % kv for kv in sorted(sevs.items())),
                   strictest))
            domains[domain]['def'] = dict(domains[domain]['def'],
                                          severity=strictest)
    return versions, domains, customs, meta_name


def _domain_active(domain, ddef):
    if domain == 'secrets':
        return True
    if domain == 'mcp':
        allow = ddef.get('allowlist')
        return (isinstance(allow, list)
                and all(isinstance(x, str) for x in allow))
    if domain == 'instructions':
        return ddef.get('require_agents_md') is True
    if domain == 'git':
        return ddef.get('prevent_secret_commits') is True
    if domain == 'permissions':
        return ddef.get('forbid_wildcard') is True
    if domain == 'content':
        ban = ddef.get('ban_patterns')
        return (isinstance(ban, list) and bool(ban)
                and all(isinstance(x, str) for x in ban))
    return False


# --- domain checks ----------------------------------------------------------------
# Each check returns (status, raw_violations) where status is one of
# pass/fail/warn/info/unknown and a raw violation is
# {'message': str, 'evidence': [dict]}. Severity mapping happens later,
# once the effective domain severity is known.

def _check_secrets(ddef, rep, root, warnings):
    sec = rep.get('secrets')
    if sec is None:
        return 'unknown', []
    v = []
    for s in sec:
        # entries carry metadata only; a 'status' key is honoured when a
        # future scanner emits it, fail is the working default
        if s.get('status', 'fail') != 'fail':
            continue
        v.append({
            'message': 'exposed secret in %s:%s (%s)'
                       % (s.get('path', '?'), s.get('line', '?'),
                          s.get('kind', 'secret')),
            'evidence': [{'file': s.get('path'), 'line': s.get('line'),
                          'kind': s.get('kind'), 'mask': s.get('mask'),
                          'fingerprint': s.get('fingerprint')}],
        })
    return ('fail' if v else 'pass'), v


def _codex_mcp_names(path, warnings):
    """Server names from [mcp_servers.*] in a codex config.toml. Names
    only -- commands and env never leave the file."""
    try:
        text = path.read_text(encoding='utf-8', errors='replace')
    except OSError as exc:
        warnings.append('cannot read %s: %s' % (path, exc))
        return None
    if tomllib is not None:
        try:
            data = tomllib.loads(text)
        except ValueError as exc:
            warnings.append('%s does not parse (%s); servers unchecked'
                            % (path.name, exc))
            return []
        ms = data.get('mcp_servers')
        return sorted(ms) if isinstance(ms, dict) else []
    names = re.findall(r'^\[\s*mcp_servers\.([^\]\s]+)\s*\]', text, re.M)
    return sorted(set(names))


def _collect_mcp_servers(root, warnings):
    """(server, file) pairs from the known MCP config locations, in a
    fixed order. None when nothing could be read at all (unknown)."""
    candidates = []
    for rel in ('.mcp.json', '.cursor/mcp.json'):
        p = root / rel
        if p.is_file():
            candidates.append((rel, p))
    claude = root / '.claude'
    if claude.is_dir():
        for p in sorted(claude.glob('settings*.json')):
            if p.is_file():
                candidates.append(('.claude/%s' % p.name, p))
    codex = root / '.codex' / 'config.toml'
    if codex.is_file():
        candidates.append(('.codex/config.toml', codex))

    found = {}
    parsed_any = False
    for rel, p in candidates:
        if p.suffix == '.toml':
            names = _codex_mcp_names(p, warnings)
            if names is None:
                continue
            parsed_any = True
            for n in names:
                found.setdefault(n, []).append(rel)
        else:
            try:
                data = json.loads(p.read_text(encoding='utf-8'))
            except (OSError, ValueError) as exc:
                warnings.append('cannot read %s: %s; servers in it '
                                'unchecked' % (rel, exc))
                continue
            parsed_any = True
            ms = data.get('mcpServers') if isinstance(data, dict) else None
            if isinstance(ms, dict):
                for n in sorted(ms):
                    found.setdefault(n, []).append(rel)
    if not parsed_any:
        return None
    return found


def _check_mcp(ddef, rep, root, warnings):
    servers = _collect_mcp_servers(root, warnings)
    if servers is None:
        return 'unknown', []
    allow = set(ddef['allowlist'])
    v = []
    for name in sorted(servers):
        if name in allow:
            continue
        v.append({
            'message': "MCP server '%s' is not in the allowlist" % name,
            'evidence': [{'server': name, 'file': rel}
                         for rel in sorted(set(servers[name]))],
        })
    return ('fail' if v else 'pass'), v


def _check_instructions(ddef, rep, root, warnings):
    found = [n for n in ('AGENTS.md', 'CLAUDE.md')
             if (root / n).is_file()]
    if found:
        return 'pass', []
    return 'fail', [{
        'message': 'no AGENTS.md and no CLAUDE.md in the workspace root',
        'evidence': [{'root': str(root),
                      'missing': ['AGENTS.md', 'CLAUDE.md']}],
    }]


def _check_git(ddef, rep, root, warnings):
    top = rep.get('top_level')
    if not isinstance(top, list):
        return 'unknown', []
    repos = [t for t in top
             if isinstance(t, dict) and t.get('kind') == 'repo']
    if not repos:
        return 'unknown', []
    v = []
    for t in sorted(repos, key=lambda t: str(t.get('name'))):
        name = t.get('name')
        ex = t.get('extra') or {}
        for ts in ex.get('tracked_secrets') or []:
            v.append({
                'message': 'secret tracked in git in %s' % name,
                'evidence': [{'repo': name, 'file': ts.get('file'),
                              'line': ts.get('line'),
                              'kind': ts.get('kind'),
                              'fingerprint': ts.get('fingerprint')}],
            })
        hooks = ex.get('hooks') or []
        has_scan = any(h.get('name') in SECRET_SCAN_HOOKS
                       and (h.get('flags') or {}).get('secret_scan')
                       for h in hooks)
        if not has_scan:
            v.append({
                'message': 'no %s secret-scan hook in %s'
                           % ('/'.join(SECRET_SCAN_HOOKS), name),
                'evidence': [{'repo': name,
                              'hooks_found': sorted(str(h.get('name'))
                                                    for h in hooks)}],
            })
    return ('fail' if v else 'pass'), v


def _check_permissions(ddef, rep, root, warnings):
    fd = rep.get('findings_detailed')
    if not isinstance(fd, list) or not fd:
        # an empty list cannot prove wildcards were checked: adapter
        # findings may simply not have been collected
        return 'unknown', []
    v = []
    for f in fd:
        cid = f.get('check_id')
        if cid not in PERMISSION_CHECK_IDS:
            continue
        ev = [{'file': e.get('file'), 'rule': e.get('rule'),
               'detail': e.get('detail')}
              for e in (f.get('evidence') or [])
              if isinstance(e, dict)]
        if not ev:
            ev = [{'check_id': cid}]
        v.append({
            'message': f.get('title') or cid,
            'evidence': ev,
        })
    return ('fail' if v else 'pass'), v


def _content_targets(root):
    names = []
    for n in ('AGENTS.md', 'CLAUDE.md', '.mcp.json'):
        if (root / n).is_file():
            names.append(n)
    claude = root / '.claude'
    if claude.is_dir():
        names.extend('.claude/%s' % p.name
                     for p in sorted(claude.glob('settings*.json'))
                     if p.is_file())
    return names


def _compile_patterns(patterns, rule_id, warnings):
    compiled = []
    for pat in patterns:
        try:
            compiled.append((pat, re.compile(pat)))
        except re.error as exc:
            warnings.append('invalid regex in %s (%r): %s; pattern '
                            'skipped' % (rule_id, pat, exc))
    return compiled


def _scan_content(compiled, root):
    """One raw violation per (file, line, pattern) match. The match text
    is the banned string itself, not a secret."""
    out = []
    for rel in _content_targets(root):
        try:
            text = (root / rel).read_bytes()[:CONTENT_FILE_CAP] \
                .decode('utf-8', errors='replace')
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            for pat, rx in compiled:
                m = rx.search(line)
                if m:
                    out.append({
                        'message': 'banned pattern %r in %s:%d'
                                   % (pat, rel, lineno),
                        'evidence': [{'file': rel, 'line': lineno,
                                      'match': m.group(0), 'pattern': pat}],
                    })
    return out


def _check_content(ddef, rep, root, warnings):
    compiled = _compile_patterns(ddef['ban_patterns'],
                                 RULE_IDS['content'], warnings)
    if not compiled:
        return 'unknown', []
    if not _content_targets(root):
        return 'unknown', []
    v = _scan_content(compiled, root)
    return ('fail' if v else 'pass'), v


CHECKS = {
    'secrets': _check_secrets,
    'mcp': _check_mcp,
    'instructions': _check_instructions,
    'git': _check_git,
    'permissions': _check_permissions,
    'content': _check_content,
}


# --- workspace config (.agents-doctor.toml) ---------------------------------------

def _workspace_policy(root, warnings):
    """[policy] from the workspace config: exceptions (rule id ->
    reason) and extra policy files layered on top of the pack."""
    out = {'exceptions': {}, 'files': []}
    cfg = config.load_config(root)
    pol = cfg.get('policy') or {}
    if not isinstance(pol, dict):
        return out
    exc = pol.get('exceptions') or {}
    if isinstance(exc, dict):
        out['exceptions'] = dict(exc)
    else:
        warnings.warn('.agents-doctor.toml: policy.exceptions must be a '
                      'map of rule id -> reason; ignored')
    files = pol.get('files') or []
    if isinstance(files, list):
        out['files'] = [f for f in files if isinstance(f, str)]
    return out


# --- evaluation -------------------------------------------------------------------

def _effective_severity(domain, ddef):
    sev = ddef.get('severity')
    if sev in SEVERITY_MAP:
        return sev
    return DEFAULT_DOMAIN_SEVERITY[domain]


def evaluate_policies(rep, root, policy_files):
    """Check a finished audit against layered policy files.

    rep is a scan.json dict, root the workspace it was made in (str or
    Path), policy_files an ordered list (later files override earlier
    ones per domain). Extra files from .agents-doctor.toml [policy] ride
    on top; exceptions from the same section suppress whole rules.

    Returns a compliance report dict; deterministic for the same input
    (no timestamps, fixed ordering everywhere). Raises PolicyError when
    a policy file cannot be parsed -- never evaluates a partial policy.
    """
    root = Path(root)
    warnings = []

    files = [str(p) for p in (policy_files or [])]
    ws = _workspace_policy(root, warnings)
    for extra in ws['files']:
        p = Path(extra)
        if not p.is_absolute():
            p = root / p
        if p.is_file():
            files.append(str(p))
        else:
            warnings.append('policy file from .agents-doctor.toml not '
                            'found: %s' % extra)

    versions, domains, customs, policy_name = _merge_policy_files(files,
                                                                  warnings)

    rules = []       # ordered rule rows for the report
    violations = []  # finished violation dicts

    def emit(rule_id, domain, rule_text, severity_policy, raw, source):
        fsev, fstatus = SEVERITY_MAP[severity_policy]
        for rv in raw:
            violations.append({
                'id': rule_id,
                'severity': fsev,
                'status': fstatus,
                'message': rv['message'],
                'rule': rule_text,
                'evidence': rv['evidence'],
            })
        status = fstatus if raw else 'pass'
        rules.append({'id': rule_id, 'domain': domain, 'rule': rule_text,
                      'status': status, 'severity': fsev,
                      'violations': len(raw), 'suppressed': 0,
                      'source': source})

    for domain in DOMAIN_ORDER:
        rule_id = RULE_IDS[domain]
        entry = domains.get(domain)
        if entry is None or not _domain_active(domain, entry['def']):
            rules.append({'id': rule_id, 'domain': domain,
                          'rule': RULE_TEXTS[domain],
                          'status': 'not_applicable', 'severity': None,
                          'violations': 0, 'suppressed': 0, 'source': None})
            continue
        ddef = entry['def']
        status, raw = CHECKS[domain](ddef, rep, root, warnings)
        if status == 'unknown':
            rules.append({'id': rule_id, 'domain': domain,
                          'rule': RULE_TEXTS[domain],
                          'status': 'unknown', 'severity': None,
                          'violations': 0, 'suppressed': 0,
                          'source': entry['source']})
            continue
        emit(rule_id, domain, RULE_TEXTS[domain],
             _effective_severity(domain, ddef), raw, entry['source'])

    for entry in customs:
        rule = entry['rule']
        rid = rule['id']
        source = entry['source']
        check = rule.get('check')
        patterns = rule.get('patterns')
        severity = rule.get('severity')
        if severity is not None and severity not in SEVERITY_MAP:
            warnings.append('%s: invalid severity %r in custom rule %s; '
                            'using error' % (source, severity, rid))
            severity = None
        severity = severity or 'error'
        message = rule.get('message') \
            or '%s matched a forbidden pattern' % rid
        if check != 'content.regex':
            warnings.append('%s: unsupported check %r in %s; rule cannot '
                            'be evaluated' % (source, check, rid))
            rules.append({'id': rid, 'domain': 'custom',
                          'rule': 'custom rule (%s)' % check,
                          'status': 'unknown', 'severity': None,
                          'violations': 0, 'suppressed': 0, 'source': source})
            continue
        if (not isinstance(patterns, list) or not patterns
                or not all(isinstance(x, str) for x in patterns)):
            warnings.append('%s: %s patterns must be a non-empty list of '
                            'strings; rule cannot be evaluated'
                            % (source, rid))
            rules.append({'id': rid, 'domain': 'custom',
                          'rule': 'custom rule (content.regex)',
                          'status': 'unknown', 'severity': None,
                          'violations': 0, 'suppressed': 0, 'source': source})
            continue
        compiled = _compile_patterns(patterns, rid, warnings)
        if not compiled:
            rules.append({'id': rid, 'domain': 'custom',
                          'rule': 'custom rule (content.regex)',
                          'status': 'unknown', 'severity': None,
                          'violations': 0, 'suppressed': 0, 'source': source})
            continue
        raw = _scan_content(compiled, root)
        for rv in raw:
            rv['message'] = '%s (%s)' % (message, rv['message'])
        emit(rid, 'custom', 'custom rule (content.regex)', severity,
             raw, source)

    # exceptions: whole rules, reason mandatory
    by_id = {}
    for r in rules:
        by_id.setdefault(r['id'], []).append(r)
    violations.sort(key=lambda v: (v['id'], v['message'],
                                   json.dumps(v['evidence'],
                                              ensure_ascii=False,
                                              sort_keys=True)))
    exceptions = []
    suppressed = {}
    for rid in sorted(ws['exceptions']):
        reason = ws['exceptions'][rid]
        if not isinstance(reason, str) or not reason.strip():
            warnings.append('policy exception %s has no reason' % rid)
            reason = reason if isinstance(reason, str) else ''
        if rid not in by_id:
            warnings.append('policy exception for unknown rule id: %s' % rid)
        taken = [v for v in violations if v['id'] == rid]
        exceptions.append({'id': rid, 'reason': reason, 'suppressed': taken})
        if taken:
            suppressed[rid] = True
    if suppressed:
        violations = [v for v in violations if v['id'] not in suppressed]
        for r in rules:
            if r['id'] in suppressed and r['violations']:
                r['suppressed'] = r['violations']
                r['violations'] = 0
                r['status'] = 'suppressed'

    summary = {'rules': len(rules)}
    for status in ('pass', 'fail', 'warn', 'info', 'unknown',
                   'suppressed', 'not_applicable'):
        summary[status] = sum(1 for r in rules if r['status'] == status)
    summary['violations'] = len(violations)
    summary['by_severity'] = {
        sev: sum(1 for v in violations if v['severity'] == sev)
        for sev in ('critical', 'high', 'medium', 'low')}

    secrets_def = (domains.get('secrets') or {}).get('def') or {}
    return {
        'schema_version': POLICY_SCHEMA_VERSION,
        'root': str(root),
        'policy_name': policy_name,
        'policy_versions': versions,
        'block_on_failure': bool(secrets_def.get('block_on_failure')),
        'rules_evaluated': rules,
        'violations': violations,
        'exceptions': exceptions,
        'warnings': warnings,
        'summary': summary,
    }


# --- markdown rendering -------------------------------------------------------------

def render_markdown(report):
    """Compliance report as a markdown table: rule, status, violations,
    severity -- plus warnings, exceptions and the violation details."""
    lines = ['# Policy compliance report', '']
    versions = report.get('policy_versions') or []
    if versions:
        lines.append('Policies: ' + ', '.join(
            '%s (version %s)' % (v['file'],
                                 v['version'] if v['version'] is not None
                                 else '?')
            for v in versions))
        lines.append('')
    lines.append('| Rule | Status | Violations | Severity |')
    lines.append('|------|--------|------------|----------|')
    for r in report.get('rules_evaluated') or []:
        sev = r.get('severity') or '-'
        lines.append('| %s | %s | %d | %s |'
                     % (r['id'], r['status'], r['violations'], sev))
    s = report.get('summary', {})
    lines.append('')
    lines.append(
        'Summary: %d rules -- pass %d, fail %d, warn %d, info %d, '
        'unknown %d, suppressed %d, not applicable %d; violations %d.'
        % (s.get('rules', 0), s.get('pass', 0), s.get('fail', 0),
           s.get('warn', 0), s.get('info', 0), s.get('unknown', 0),
           s.get('suppressed', 0), s.get('not_applicable', 0),
           s.get('violations', 0)))
    warns = report.get('warnings') or []
    if warns:
        lines += ['', '## Warnings', '']
        lines += ['- %s' % w for w in warns]
    excs = [e for e in report.get('exceptions') or [] if e['suppressed']]
    if excs:
        lines += ['', '## Exceptions', '']
        for e in excs:
            lines.append('- %s: %s (%d violation(s) suppressed)'
                         % (e['id'], e['reason'] or '(no reason given)',
                            len(e['suppressed'])))
    viols = report.get('violations') or []
    if viols:
        lines += ['', '## Violations', '']
        for v in viols:
            where = ', '.join(
                '%s:%s' % (e.get('file') or e.get('repo') or e.get('root'),
                           e.get('line', ''))
                for e in v['evidence'][:3])
            lines.append('- **%s** [%s/%s] %s (%s)'
                         % (v['id'], v['severity'], v['status'],
                            v['message'], where))
    return '\n'.join(lines) + '\n'


# --- policy-pack discovery (v2.1, distribution without a repo) ---------------

PLUGIN_POLICY_GLOBS = (
    # installed plugin caches across harnesses: a policy pack is any
    # installed package that ships policies/*.yml next to its manifest
    ('.claude/plugins', ('**/policies/*.yml', '**/policies/*.yaml')),
    ('.zcode/cli/plugins/cache', ('**/policies/*.yml', '**/policies/*.yaml')),
    ('.agents/plugins', ('**/policies/*.yml', '**/policies/*.yaml')),
)


def discover_policy_files(root, home=None):
    """Policy files in evaluation order (corporate first, workspace
    level last, so later definitions override earlier ones).

    Sources, in order:
    1. policy packs: policies/*.yml inside installed plugins under the
       known plugin roots (~/.claude/plugins, ~/.zcode/.../cache,
       ~/.agents/plugins) plus every *.yml|*.yaml in the directory
       named by AGENTS_DOCTOR_POLICY_PACKS;
    2. workspace policies: config.load_config(root)['policy']['files']
       (paths relative to the workspace root).
    Callers pass explicit --policy paths on top of this list (they win
    by coming last).
    """
    from pathlib import Path as _P
    import os as _os
    home = _P(home) if home else _P.home()
    root = _P(root)
    found = []

    def _glob_safe(base, pattern):
        try:
            return sorted(base.glob(pattern))
        except OSError:
            return []

    seen = set()
    for rel, patterns in PLUGIN_POLICY_GLOBS:
        base = home / rel
        for pattern in patterns:
            for f in _glob_safe(base, pattern):
                rp = f.resolve()
                if rp not in seen:
                    seen.add(rp)
                    found.append(f)
    env_dir = _os.environ.get('AGENTS_DOCTOR_POLICY_PACKS')
    if env_dir:
        for f in sorted(_P(env_dir).glob('*.yml'))                 + sorted(_P(env_dir).glob('*.yaml')):
            rp = f.resolve()
            if rp not in seen:
                seen.add(rp)
                found.append(f)

    try:
        import config as _config
        cfg = _config.load_config(root)
        for rel in (cfg.get('policy') or {}).get('files') or []:
            f = (root / rel) if not _P(rel).is_absolute() else _P(rel)
            rp = f.resolve()
            if rp not in seen:
                seen.add(rp)
                found.append(f)
    except Exception:
        pass
    return found
