#!/usr/bin/env python3
"""workspace-audit: deterministic agent workspace scanner.

Called from the skill:
    python scripts/audit_scan.py <root> [--home <home>] [--deep] --out scan.json

Read-only: reads files and git metadata, never changes or deletes anything.
home is scanned selectively (harnesses, global instructions, memory, skills);
the full walk covers only the workspace root.
Output: JSON to --out plus a short summary to stdout.
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

# secret detection and redaction live in one module: raw values never leave it
sys.path.insert(0, str(Path(__file__).resolve().parent))
import secret_scanner as secscan  # noqa: E402

# --- thresholds and heuristics from the audit protocol ------------------------
PROJECT_BENCH = 16 * 1024        # project instruction file: up to ~16 KB is achievable
MEMORY_LIMIT = 24985             # memory index load limit (24.4 KB)
MEMORY_LINE_LIMIT = 200          # memory loads up to 200 lines or 25 KB, whichever comes first
CHAIN_BUDGET = 32768             # Codex budget for the root + nested AGENTS.md chain
SKILL_DESC_LIMIT = 1024          # Z Code skill description limit
RULES_VERSION = '0.3.0'          # rule set version, goes into the report
HARNESS_STALE_DAYS = 90          # older: harness counts as abandoned
HARNESS_FRESH_DAYS = 30          # newer: active

HARNESS = {
    'zcode':  {'dir': '.zcode',  'markers': ['cli/history.jsonl', 'history.jsonl', 'cli/artifacts'],
               'reads': ['AGENTS.md']},
    'claude': {'dir': '.claude', 'markers': ['projects', 'history.jsonl'],
               'reads': ['CLAUDE.md', 'AGENTS.md']},
    'codex':  {'dir': '.codex',  'markers': ['config.toml', 'sessions', 'history.jsonl'],
               'reads': ['AGENTS.md']},
}
GENERIC_MARKERS = [
    'drop this file into your project', 'next-move-theory-rules',
    'структура репозитория', 'как устроен этот', 'обзор репозитория', '## overview',
    'repository structure', 'repository overview',
]

BUILD_DIRS = {'node_modules', '__pycache__', '.venv', 'venv', 'dist',
              'build', 'target', '.cache', '.idea', '.pytest_cache'}
BIG_FILE_BYTES = 5 * 1024 * 1024
DUP_MIN_BYTES = 1024
DUP_MAX_BYTES = 50 * 1024 * 1024
TEXT_EXTS = {'.json', '.md', '.yml', '.yaml', '.toml', '.env', '.txt',
             '.py', '.js', '.ts', '.cfg', '.ini', '.sh'}
SECRET_FILENAMES = {'.mcp.json', '.env', 'settings.json'}
# key-like names are scanned for secrets even without a text extension
NAME_SECRET_RX = re.compile(r'(id_rsa|id_dsa|id_ecdsa|id_ed25519|\.pem$|\.key$|^id_)', re.I)

JUNK_FILE_RULES = [
    (re.compile(r'^temp', re.I), 'temp file'),
    (re.compile(r'^~\$', re.I), 'office lock file'),
    (re.compile(r'^untitled', re.I), 'untitled'),
    (re.compile(r'^img_', re.I), 'screenshot or photo'),
    (re.compile(r'скриншот', re.I), 'screenshot'),
    (re.compile(r'screenshot', re.I), 'screenshot'),
    (re.compile(r'^новая папка', re.I), 'new folder'),
    (re.compile(r'^new folder', re.I), 'new folder'),
    (re.compile(r'финал', re.I), '"final" version marker'),
    (re.compile(r'\bfinal\b', re.I), '"final" version marker'),
    (re.compile(r'версия', re.I), 'version marker'),
    (re.compile(r'\bversion\b', re.I), 'version marker'),
    (re.compile(r'копия', re.I), 'copy'),
    (re.compile(r'\bcopy\b', re.I), 'copy'),
    (re.compile(r'^backup', re.I), 'backup'),
    (re.compile(r'стар', re.I), '"old" leftover'),
    (re.compile(r'\bold\b', re.I), '"old" leftover'),
    (re.compile(r'времен', re.I), 'temp file'),
    (re.compile(r'^scratch', re.I), 'scratch/draft'),
    (re.compile(r'\bdraft\b', re.I), 'scratch/draft'),
    (re.compile(r'^debug', re.I), 'debug output'),
    (re.compile(r'\.bak$', re.I), '*.bak'),
    (re.compile(r'\.log$', re.I), 'log file'),
]
JUNK_DIR_RULES = [
    (re.compile(r'^backup', re.I), 'backup dir'),
    (re.compile(r'стар', re.I), '"old" dir'),
    (re.compile(r'^temp', re.I), 'temp dir'),
]


# --- shared helpers -----------------------------------------------------------

def run_git(p, *args):
    # GIT_OPTIONAL_LOCKS=0 keeps git from refreshing the index: read-only
    env = dict(os.environ, GIT_OPTIONAL_LOCKS='0')
    r = subprocess.run(['git', '-C', str(p), *args], capture_output=True,
                       text=True, encoding='utf-8', errors='replace', env=env)
    return r.returncode, r.stdout


def file_junk_reason(name):
    for rx, why in JUNK_FILE_RULES:
        if rx.search(name):
            return why
    return None


def dir_junk_reason(name):
    for rx, why in JUNK_DIR_RULES:
        if rx.search(name):
            return why
    return None


def subtree(p):
    size = count = 0
    for dp, _dns, fns in os.walk(p):
        for fn in fns:
            f = Path(dp) / fn
            if f.is_symlink():
                continue
            try:
                size += f.stat().st_size
                count += 1
            except OSError:
                pass
    return size, count


def classify_remote(url):
    host = re.sub(r'^[^@]*@', '', url)
    m = re.search(r'(?:https?://)?([^/]+)', host)
    host = m.group(1) if m else url
    if re.search(r'github\.com|gitlab\.com|bitbucket\.org', host, re.I):
        return 'external hosting'
    return 'self-hosted'


# --- block D: repositories ------------------------------------------------------

def git_info(p):
    if not (p / '.git').exists():
        return None
    info = {'remote': None, 'last_commit': None, 'dirty': [], 'untracked': []}
    rc, out = run_git(p, 'remote', 'get-url', 'origin')
    if rc == 0 and out.strip():
        info['remote'] = out.strip()
    rc, out = run_git(p, 'log', '-1', '--format=%cI')
    if rc == 0 and out.strip():
        info['last_commit'] = out.strip()
    _rc, out = run_git(p, 'status', '--porcelain')
    for line in out.splitlines():
        if not line.strip():
            continue
        target = info['untracked'] if line[:2].strip() == '??' else info['dirty']
        target.append(line[3:].strip().strip('"'))
    return info


def nested_repos(p):
    found = []
    for dp, dns, _fns in os.walk(p):
        dns[:] = [d for d in dns if d != '.git' and d not in BUILD_DIRS]
        if dp != str(p) and (Path(dp) / '.git').exists():
            found.append(str(Path(dp).relative_to(p)))
            dns[:] = []
        if len(found) >= 10:
            break
    return found


# --- blocks E and F: sync and secrets in git ------------------------------------

def repo_extra(p, gi, deep=False):
    ex = {'branch': None, 'ahead_behind': None, 'remote_class': None,
          'credentials_in_remote': False, 'gitignore': (p / '.gitignore').exists(),
          'hooks': [], 'sync_commits_last30': 0, 'tracked_secrets': [],
          'nested_repos': nested_repos(p)}
    rc, out = run_git(p, 'branch', '--show-current')
    if rc == 0 and out.strip():
        ex['branch'] = out.strip()
    rc, out = run_git(p, 'rev-list', '--left-right', '--count', 'HEAD...@{u}')
    if rc == 0 and out.strip():
        a, b = out.split()
        ex['ahead_behind'] = {'ahead': int(a), 'behind': int(b)}
    url = gi.get('remote')
    if url:
        ex['remote_class'] = classify_remote(url)
        ex['credentials_in_remote'] = bool(re.search(r'://[^/@\s]+@', url))

    hooks_dir = p / '.git' / 'hooks'
    if hooks_dir.exists():
        for f in sorted(hooks_dir.iterdir()):
            if not f.is_file() or f.name.endswith('.sample'):
                continue
            try:
                content = f.read_text(encoding='utf-8', errors='replace')
            except OSError:
                continue
            ex['hooks'].append({
                'name': f.name,
                'flags': {
                    'add_all': bool(re.search(r'git add (-A|\.)', content)),
                    'push': 'push' in content,
                    'secret_scan': bool(re.search(r'secret|gitleaks|scan', content, re.I)),
                }})
    rc, out = run_git(p, 'log', '--oneline', '--since', '30 days ago', '--grep', 'sync')
    ex['sync_commits_last30'] = len([l for l in out.splitlines() if l.strip()])

    rc, out = run_git(p, 'grep', '--cached', '-i', '-nE', secscan.GIT_GREP_RE)
    if rc == 0:
        ex['tracked_secrets'] = secscan.scan_git_grep_output(out)[:10]

    if deep:
        rc, out = run_git(p, 'log', '-p', '--max-count=300')
        ex['history_secrets'] = secscan.scan_diff_output(out)
    return ex


# --- blocks A, B, C: harness, instructions, context tax -------------------------

def harness_report(home, root):
    tools = []
    now = time.time()
    for tool, cfg in HARNESS.items():
        d = home / cfg['dir']
        if not d.exists():
            tools.append({'tool': tool, 'path': str(d), 'exists': False, 'reads': cfg['reads']})
            continue
        mtimes = [d.stat().st_mtime]
        for mk in cfg['markers']:
            f = d / mk
            if f.exists():
                mtimes.append(f.stat().st_mtime)
        try:
            for ch in os.scandir(d):
                mtimes.append(ch.stat().st_mtime)
        except OSError:
            pass
        days = (now - max(mtimes)) / 86400
        state = 'active' if days <= HARNESS_FRESH_DAYS else (
            'abandoned' if days > HARNESS_STALE_DAYS else 'occasional')
        tools.append({'tool': tool, 'exists': True, 'last_activity_days_ago': round(days),
                      'state': state, 'reads': cfg['reads']})
    proj = [{'name': n, 'exists': (root / n).exists()}
            for n in ['.agents', '.claude', '.codex', '.zcode/config.json']]
    return {'tools': tools, 'project_dirs': proj, 'notes': []}


def context_checks(d, base):
    files = {}
    for name in ('AGENTS.md', 'CLAUDE.md'):
        f = d / name
        if f.exists():
            files[name] = f.read_text(encoding='utf-8', errors='replace')

    pkg_scripts = None
    pkg = d / 'package.json'
    if pkg.exists():
        try:
            pkg_scripts = json.loads(pkg.read_text(encoding='utf-8')).get('scripts', {})
        except (ValueError, OSError):
            pkg_scripts = {}
    has_makefile = (d / 'Makefile').exists() or (d / 'makefile').exists()

    entries = []
    for name, text in files.items():
        lines = [l for l in text.splitlines() if l.strip()]
        low = text.lower()
        markers = [m for m in GENERIC_MARKERS if m in low]
        is_pointer = (len(lines) <= 2 and bool(
            re.search(r'(see\b|см\.|→|full rules|полный порядок|актуальн)', text, re.I)))
        dead_links, dead_paths, dead_cmds = [], [], []
        for m in re.finditer(r'\[[^\]]*\]\(([^)\s]+)\)', text):
            ref = m.group(1).split('#')[0]
            if ref and not ref.startswith(('http', 'mailto:')) and not (d / ref).exists():
                dead_links.append(ref)
        for m in re.finditer(r'`([^`\s]+)`', text):
            raw = m.group(1).strip('`')
            if '/' not in raw or raw.startswith(('http', '~', '$', '-')):
                continue
            tok = raw.rstrip('/')
            if re.fullmatch(r'[\w.\\/-]+', tok) and not (d / tok).exists():
                dead_paths.append(tok)
        for m in re.finditer(r'\bnpm run ([\w:-]+)', text):
            if pkg_scripts is not None and m.group(1) not in pkg_scripts:
                dead_cmds.append('npm run ' + m.group(1))
        for m in re.finditer(r'\bmake ([\w-]+)', text):
            if not has_makefile:
                dead_cmds.append('make ' + m.group(1))
        entries.append({
            'path': str((d / name).relative_to(base)),
            'lines': len(lines),
            'size_bytes': len(text.encode('utf-8')),
            'is_pointer': is_pointer,
            'generic_markers': markers,
            'dead_links': dead_links,
            'dead_paths': dead_paths,
            'dead_commands': dead_cmds,
        })

    drift = None
    if len(files) == 2:
        # a pair linked by an @AGENTS.md import is one source: no drift
        linked = '@AGENTS.md' in files['AGENTS.md'] or '@AGENTS.md' in files['CLAUDE.md']
        if not linked:
            a = {l.strip() for l in files['AGENTS.md'].splitlines() if l.strip()}
            c = {l.strip() for l in files['CLAUDE.md'].splitlines() if l.strip()}
            if len(a) >= 4 and len(c) >= 4 and (a | c):
                j = len(a & c) / len(a | c)
                if j < 0.5:
                    drift = {'path': str(d.relative_to(base)) or '.', 'jaccard': round(j, 2)}
    return entries, drift


def context_tax(home, root):
    files = []
    for role, p in [('user-zcode', home / '.zcode' / 'AGENTS.md'),
                    ('user-claude', home / '.claude' / 'CLAUDE.md'),
                    ('project', root / 'AGENTS.md'), ('project', root / 'CLAUDE.md')]:
        if p.exists():
            files.append({'role': role, 'path': str(p), 'size_bytes': p.stat().st_size})
    mem_dir = home / '.zcode' / 'cli' / 'memories'
    over_lines = []
    if mem_dir.exists():
        for m in list(mem_dir.rglob('MEMORY.md'))[:20]:
            files.append({'role': 'memory-index', 'path': str(m),
                          'size_bytes': m.stat().st_size})
            with m.open('rb') as fh:
                if sum(1 for _ in fh) > MEMORY_LINE_LIMIT:
                    over_lines.append(str(m))
    proj_total = sum(f['size_bytes'] for f in files if f['role'] == 'project')
    return {'session_files': files,
            'project_total_bytes': proj_total,
            'benchmark_project_bytes': PROJECT_BENCH,
            'memory_over_limit': [f['path'] for f in files
                                  if f['role'] == 'memory-index'
                                  and f['size_bytes'] > MEMORY_LIMIT],
            'memory_over_lines': over_lines}


# --- block G: skills -----------------------------------------------------------

def parse_skill(f):
    try:
        text = f.read_text(encoding='utf-8', errors='replace')
    except OSError:
        text = ''
    m = re.match(r'^---\s*\n(.*?)\n---', text, re.S)
    fm = m.group(1) if m else ''
    nm = re.search(r'^name:\s*(.+?)\s*$', fm, re.M)
    dm = re.search(r'^description:\s*(.+?)\s*$', fm, re.M)
    desc = dm.group(1) if dm else ''
    return {'name': nm.group(1) if nm else f.parent.name,
            'desc_len': len(desc) if dm else None,
            'has_triggers': bool(re.search(r'use when|when asked|trigger|когда|использовать|если попрос|триггер', desc, re.I)),
            'md5': hashlib.md5(text.encode('utf-8', 'replace')).hexdigest(),
            'path': str(f)}


def skills_report(home, root):
    locs = [('user-zcode', home / '.zcode' / 'skills', 'one'),
            ('user-claude', home / '.claude' / 'skills', 'one'),
            ('project-agents', root / '.agents' / 'skills', 'one'),
            ('project-claude', root / '.claude' / 'skills', 'one'),
            ('plugins-cache', home / '.zcode' / 'cli' / 'plugins' / 'cache', 'deep')]
    found = []
    checked = []
    for loc, base, mode in locs:
        if not base.exists():
            continue
        checked.append(f'{loc}: {base}')
        if mode == 'one':
            for child in sorted(base.iterdir()):
                sk = child / 'SKILL.md'
                if sk.is_file():
                    found.append((loc, sk))
        else:
            for sk in list(base.rglob('SKILL.md'))[:200]:
                found.append((loc, sk))
    entries = []
    for loc, f in found:
        e = parse_skill(f)
        e['location'] = loc
        entries.append(e)
    # the plugin cache is managed by the CLI and keeps several versions of one
    # skill: diverging copies there are expected, not counted as a desync
    managed = [e for e in entries if e['location'] != 'plugins-cache']
    by_name = {}
    for e in managed:
        by_name.setdefault(e['name'], []).append(e)
    dups = []
    for name, es in sorted(by_name.items()):
        if len(es) > 1:
            same = len({e['md5'] for e in es}) == 1
            dups.append({'name': name, 'copies': len(es),
                         'sync': 'identical' if same else 'DIVERGED',
                         'paths': [e['path'] for e in es]})
    return {'entries': entries, 'duplicates': dups, 'locations_checked': checked}


# --- summary gates ---------------------------------------------------------------

def build_gates(rep):
    gates = []
    drift = rep.get('context_drift', [])
    gates.append({'n': 1, 'gate': 'One instruction file per level; duplicates are identical or a pointer',
                  'status': 'FAIL' if drift else 'PASS',
                  'evidence': [f"{d['path']}: similarity {d['jaccard']}" for d in drift]})
    generic = [(e['path'], e['generic_markers']) for e in rep['context_files']
               if e['generic_markers']]
    gates.append({'n': 2, 'gate': 'Auto-loaded context has no generic or overview blocks',
                  'status': 'WARN' if generic else 'PASS',
                  'evidence': [f"{p}: {', '.join(m)}" for p, m in generic]})
    dead = [(e['path'], e['dead_links'] + e['dead_paths'] + e['dead_commands'])
            for e in rep['context_files']
            if e['dead_links'] or e['dead_paths'] or e['dead_commands']]
    gates.append({'n': 3, 'gate': 'All cross-references in instruction files resolve',
                  'status': 'FAIL' if dead else 'PASS',
                  'evidence': [f"{p}: {len(d)} dead" for p, d in dead]})
    nongit = [t for t in rep['top_level'] if t['kind'] == 'dir']
    heavy = [t for t in nongit if t['size_bytes'] > 1024 * 1024]
    gates.append({'n': 4, 'gate': 'Every folder has a decided fate; valuable data is under version control',
                  'status': 'FAIL' if heavy else ('WARN' if nongit else 'PASS'),
                  'evidence': [f"{t['name']}: {t['size_bytes'] // 1024} KB outside git"
                               for t in nongit]})
    push_ev, sweep_fail = [], False
    for t in rep['top_level']:
        ex = t.get('extra')
        if not ex:
            continue
        for h in ex['hooks']:
            if h['flags']['push']:
                # a push hook on its own is fine (post-commit sync); the risk
                # is add -A sweeping unreviewed files into the commit
                push_ev.append(f"{t['name']}: hook {h['name']} pushes, remote {ex['remote_class'] or 'not set'}")
            if h['flags']['add_all'] and t['git']['untracked']:
                push_ev.append(f"{t['name']}: hook {h['name']} runs git add -A with "
                               f"{len(t['git']['untracked'])} untracked files, junk will land in the commit")
                sweep_fail = True
    gates.append({'n': 5, 'gate': 'Auto-push only for personal storage; publishing requires confirmation',
                  'status': 'FAIL' if sweep_fail else ('WARN' if push_ev else 'PASS'),
                  'evidence': push_ev})
    sec_ev = [f"{s['path']}:{s['line']} {s['kind']}" for s in rep['secrets']]
    for t in rep['top_level']:
        ex = t.get('extra')
        if not ex:
            continue
        if ex['credentials_in_remote']:
            sec_ev.append(f"{t['name']}: credentials in remote URL")
        sec_ev += [f"{t['name']} (staged): {e['file']}:{e['line']} {e['kind']}"
                   for e in ex['tracked_secrets']]
    gates.append({'n': 6, 'gate': 'No keys in tracked files or URLs; secret scan in the commit chain',
                  'status': 'FAIL' if sec_ev else 'PASS', 'evidence': sec_ev})
    skill_ev = []
    for d in rep['skills']['duplicates']:
        if d['sync'] != 'identical':
            skill_ev.append(f"{d['name']}: {d['copies']} copies, {d['sync']}")
    for e in rep['skills']['entries']:
        if e['desc_len'] is not None and e['desc_len'] > SKILL_DESC_LIMIT:
            skill_ev.append(f"{e['name']}: description {e['desc_len']} chars, limit 1024")
        elif not e['has_triggers']:
            skill_ev.append(f"{e['name']}: no triggers in description")
    hard = [e for e in skill_ev if 'DIVERGED' in e or 'limit 1024' in e]
    gates.append({'n': 7, 'gate': 'Skills: descriptions with triggers under 1024 chars, no drifted copies',
                  'status': 'FAIL' if hard else ('WARN' if skill_ev else 'PASS'),
                  'evidence': skill_ev})
    owner_ev = list(rep['harness'].get('notes', [])) + \
        [f"copy drift: {d['path']}" for d in drift]
    gates.append({'n': 8, 'gate': 'Every rule has one owner file; copy drift excluded by design',
                  'status': 'FAIL' if owner_ev else 'PASS',
                  'evidence': owner_ev or ['ok']})
    gates.append({'n': 9, 'gate': 'Instruction changes are verified by a run, not a feeling',
                  'status': 'MANUAL',
                  'evidence': ['scanner cannot check this: the skill offers to measure auto-load weight '
                               'before/after and run a typical task']})
    return gates


# --- findings with fingerprint (for baseline/diff) ------------------------------

def collect_findings(rep):
    """Stable finding identifiers: no dates or sizes, so a re-scan of an
    unchanged workspace yields the same set."""
    def fp(s):
        return hashlib.md5(s.encode('utf-8')).hexdigest()[:12]

    out = []
    for s in rep['secrets']:
        out.append({'fp': fp(f"secret|{s['path']}|{s['line']}|{s['kind']}"),
                    'section': 'secrets', 'path': s['path']})
    for e in rep['context_files']:
        for kind in ('dead_links', 'dead_paths', 'dead_commands'):
            for v in e[kind]:
                out.append({'fp': fp(f"{kind}|{e['path']}|{v}"),
                            'section': kind, 'path': f"{e['path']} | {v}"[:100]})
    for d in rep['context_drift']:
        out.append({'fp': fp(f"drift|{d['path']}"), 'section': 'context_drift',
                    'path': d['path']})
    for f in rep['junk']['files']:
        out.append({'fp': fp(f"junk-file|{f['path']}"), 'section': 'junk', 'path': f['path']})
    for f in rep['junk']['dirs']:
        out.append({'fp': fp(f"junk-dir|{f['path']}"), 'section': 'junk', 'path': f['path']})
    for e in rep['junk']['empty_dirs']:
        out.append({'fp': fp(f"empty-dir|{e}"), 'section': 'junk', 'path': e})
    for g in rep['duplicates']:
        key = '|'.join(sorted(g['files']))
        out.append({'fp': fp(f"dup|{key}"), 'section': 'duplicates', 'path': key[:100]})
    for g in rep['large_files']:
        out.append({'fp': fp(f"large|{g['path']}"), 'section': 'large_files', 'path': g['path']})
    for d in rep['skills']['duplicates']:
        if d['sync'] != 'identical':
            out.append({'fp': fp(f"skill-desync|{d['name']}"), 'section': 'skills',
                        'path': d['name']})
    for n in rep['harness']['notes']:
        out.append({'fp': fp(f"note|{n}"), 'section': 'harness', 'path': n[:100]})
    return out


# --- main walk -------------------------------------------------------------------

def chain_budget(root):
    """Codex budget: 32,768 bytes for the chain of root + nested AGENTS.md."""
    trees = [root] + [e for e in sorted(root.iterdir()) if e.is_dir()]
    out = []
    for tree in trees:
        main = tree / 'AGENTS.md'
        if not main.exists():
            continue
        total = main.stat().st_size
        for dp, dns, _fns in os.walk(tree):
            dns[:] = [d for d in dns if d != '.git' and d not in BUILD_DIRS]
            if dp == str(tree):
                continue
            nested = Path(dp) / 'AGENTS.md'
            if nested.exists():
                total += nested.stat().st_size
        out.append({'root': str(tree.relative_to(root)) or '.',
                    'total_bytes': total, 'over': total > CHAIN_BUDGET})
    return out


def scan(root, home, deep=False):
    t0 = time.monotonic()
    rep = {'schema_version': '1.0', 'root': str(root), 'home': str(home),
           'generated_at': datetime.now().astimezone().isoformat(timespec='seconds'),
           'top_level': [], 'dup_checkouts': {}, 'context_files': [], 'context_drift': [],
           'context_tax': {}, 'harness': {}, 'skills': {},
           'context_budget': [], 'chain_budget_over': False,
           'findings': [], 'rules_version': RULES_VERSION,
           'junk': {'files': [], 'dirs': [], 'empty_dirs': []},
           'duplicates': [], 'large_files': [], 'secrets': [], 'gates': [], 'stats': {}}
    per_top, total_files, hashes = {}, 0, {}
    seen_secret_lines = set()
    skipped_links = 0

    def inside_root(target):
        return target == root or root in target.parents

    for dirpath, dirnames, filenames in os.walk(root):
        keep = []
        for dn in dirnames:
            full = Path(dirpath) / dn
            if dn == '.git':
                continue
            if full.is_symlink():
                # never descend into or measure a symlinked directory:
                # it may point outside the workspace
                skipped_links += 1
                continue
            reason = f'build artifact ({dn})' if dn in BUILD_DIRS else dir_junk_reason(dn)
            if reason:
                size, count = subtree(full)
                rel = str(full.relative_to(root))
                top = rel.split(os.sep)[0]
                rep['junk']['dirs'].append({'path': rel, 'reason': reason,
                                            'size_bytes': size, 'files': count})
                per_top[top] = per_top.get(top, 0) + size
                total_files += count
                continue
            keep.append(dn)
        dirnames[:] = keep

        if Path(dirpath) != root and not dirnames and not filenames:
            rep['junk']['empty_dirs'].append(str(Path(dirpath).relative_to(root)))

        for fn in filenames:
            f = Path(dirpath) / fn
            if f.is_symlink():
                # boundary guard: a file symlink may point outside the root
                try:
                    if not inside_root(f.resolve()):
                        skipped_links += 1
                        continue
                except OSError:
                    skipped_links += 1
                    continue
            try:
                st = f.stat()
            except OSError:
                continue
            rel = str(f.relative_to(root))
            top = rel.split(os.sep)[0]
            per_top[top] = per_top.get(top, 0) + st.st_size
            total_files += 1

            why = file_junk_reason(fn)
            if why:
                rep['junk']['files'].append({'path': rel, 'reason': why,
                                             'size_bytes': st.st_size})
            if st.st_size >= BIG_FILE_BYTES:
                rep['large_files'].append({'path': rel, 'size_bytes': st.st_size})
            if DUP_MIN_BYTES <= st.st_size <= DUP_MAX_BYTES:
                h = hashlib.md5(f.read_bytes()).hexdigest()
                hashes.setdefault(h, []).append(rel)
            if (fn in SECRET_FILENAMES or NAME_SECRET_RX.search(fn)
                    or f.suffix.lower() in TEXT_EXTS) and st.st_size < 1024 * 1024:
                text = f.read_text(encoding='utf-8', errors='replace')
                for hit in secscan.scan_text(rel, text):
                    if (rel, hit['line']) in seen_secret_lines:
                        continue
                    seen_secret_lines.add((rel, hit['line']))
                    rep['secrets'].append({'path': rel, 'line': hit['line'],
                                           'kind': hit['kind'],
                                           'mask': hit['mask'],
                                           'fingerprint': hit['fingerprint'],
                                           'confidence': hit['confidence']})

    for h, paths in hashes.items():
        if len(paths) > 1:
            sz = (root / paths[0]).stat().st_size
            rep['duplicates'].append({'size_bytes': sz, 'files': paths})
    rep['duplicates'].sort(key=lambda g: -g['size_bytes'])

    remotes = {}
    for entry in sorted(root.iterdir(), key=lambda e: e.name):
        if entry.is_dir():
            gi = git_info(entry)
            item = {'name': entry.name,
                    'kind': 'repo' if gi else 'dir',
                    'git': gi,
                    'size_bytes': per_top.get(entry.name, 0)}
            if gi:
                item['extra'] = repo_extra(entry, gi, deep)
                if gi.get('remote'):
                    key = re.sub(r'^[^@]*@', '', gi['remote'])
                    remotes.setdefault(key, []).append(entry.name)
            rep['top_level'].append(item)
        else:
            rep['top_level'].append({'name': entry.name, 'kind': 'file',
                                     'size_bytes': entry.stat().st_size})
    rep['dup_checkouts'] = {u: names for u, names in remotes.items() if len(names) > 1}

    proj_ctx_dirs = [e for e in sorted(root.iterdir())
                     if e.is_dir() and ((e / 'AGENTS.md').exists() or (e / 'CLAUDE.md').exists())]
    for d, base in [(root, root), (home / '.zcode', home), (home / '.claude', home)] + \
                   [(e, root) for e in proj_ctx_dirs]:
        if d.exists():
            entries, drift = context_checks(d, base)
            rep['context_files'].extend(entries)
            if drift:
                rep['context_drift'].append(drift)

    rep['harness'] = harness_report(home, root)
    claude = next((t for t in rep['harness']['tools'] if t['tool'] == 'claude'), None)
    if claude and claude.get('state') == 'abandoned':
        for e in rep['context_files']:
            if e['path'].endswith('CLAUDE.md') and not e['is_pointer'] \
                    and not e['path'].startswith('.claude'):
                rep['harness']['notes'].append(
                    f"{e['path']}: maintained for a dead harness, claude inactive for "
                    f"{claude.get('last_activity_days_ago')} days")

    rep['context_tax'] = context_tax(home, root)
    rep['skills'] = skills_report(home, root)
    rep['context_budget'] = chain_budget(root)
    rep['chain_budget_over'] = any(c['over'] for c in rep['context_budget'])
    rep['findings'] = collect_findings(rep)
    rep['gates'] = build_gates(rep)
    rep['stats'] = {'total_files': total_files,
                    'total_size_bytes': sum(per_top.values()),
                    'skipped_symlinks_outside': skipped_links,
                    'duration_sec': round(time.monotonic() - t0, 2)}
    return rep


def main():
    ap = argparse.ArgumentParser(description='agent workspace audit')
    ap.add_argument('path', help='workspace root')
    ap.add_argument('--home', default=str(Path.home()), help='home directory (harnesses, memory, skills)')
    ap.add_argument('--deep', action='store_true', help='scan git history for secrets (slower)')
    ap.add_argument('--baseline', default=None, help='previous scan.json: adds a diff section (new findings only)')
    ap.add_argument('--out', default='scan.json', help='where to write the JSON report')
    a = ap.parse_args()
    root = Path(a.path).resolve()
    home = Path(a.home).resolve()
    if not root.is_dir():
        sys.exit('not a directory: ' + str(root))
    rep = scan(root, home, a.deep)
    if a.baseline and Path(a.baseline).exists():
        try:
            old = json.loads(Path(a.baseline).read_text(encoding='utf-8'))
        except (ValueError, OSError):
            old = None
        if old is not None:
            old_fps = {f['fp'] for f in old.get('findings', [])}
            new_fps = {f['fp'] for f in rep['findings']}
            rep['diff'] = {'new': [f for f in rep['findings'] if f['fp'] not in old_fps],
                           'resolved': [f for f in old.get('findings', [])
                                        if f['fp'] not in new_fps]}
    Path(a.out).write_text(json.dumps(rep, ensure_ascii=False, indent=2), encoding='utf-8')
    j = rep['junk']
    st = lambda s: sum(1 for g in rep['gates'] if g['status'] == s)
    print(f"scan: {rep['stats']['total_files']} files, "
          f"{rep['stats']['total_size_bytes'] // 1024} KB, {rep['stats']['duration_sec']} s")
    print(f"gates: FAIL {st('FAIL')}, WARN {st('WARN')}, PASS {st('PASS')}, MANUAL {st('MANUAL')}")
    print(f"findings: secrets {len(rep['secrets'])}, drift pairs {len(rep['context_drift'])}, "
          f"duplicate checkouts {len(rep['dup_checkouts'])}, "
          f"junk files {len(j['files'])}, junk dirs {len(j['dirs'])}, "
          f"empty dirs {len(j['empty_dirs'])}, duplicate groups {len(rep['duplicates'])}")
    print(f"fingerprinted findings: {len(rep['findings'])} (rules {rep['rules_version']})")
    if rep['stats'].get('skipped_symlinks_outside'):
        print(f"skipped symlinks pointing outside the root: "
              f"{rep['stats']['skipped_symlinks_outside']}")
    if 'diff' in rep:
        print(f"baseline: {len(rep['diff']['new'])} new, {len(rep['diff']['resolved'])} resolved")
    print('full report: ' + a.out)


if __name__ == '__main__':
    main()
