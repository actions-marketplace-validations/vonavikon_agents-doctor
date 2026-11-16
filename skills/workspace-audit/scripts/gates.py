"""Gate engine: turns scanner facts into the nine gates and typed findings.

Input is the rep dict from audit_scan.scan() plus the optional stage-2
fact sections: config_integrity, heavy_outside_git, junk_classified and
skills_extra (or the same fields merged into skills.entries). Every
section is optional: a section that is entirely absent yields unknown
rules, never a silent pass. A section that is present but empty is data:
it passes when nothing is wrong, except where the spec says absence
itself matters (configuration files, secret prevention) -- there it
warns, because absence of evidence must not read as a pass.

Thresholds live in GATE_POLICY so the scanner and the tests import one
source of truth. This module deliberately does not import audit_scan
(circular); audit_scan.py keeps its own PROJECT_BENCH / CHAIN_BUDGET /
SKILL_DESC_LIMIT copies for now and will switch to importing GATE_POLICY
when the stage-2 integration lands.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import report_model  # noqa: E402

# --- single source of truth for thresholds --------------------------------

GATE_POLICY = {
    # total size of junk files + junk/build dirs that fails G9
    'JUNK_FAIL_BYTES': 500 * 1024 * 1024,
    # more empty dirs than this turns the info-level observation into a warn
    'EMPTY_WARN_COUNT': 10,
    # a tracked file at or over this size fails G7
    'TRACKED_BIG_BYTES': 5 * 1024 * 1024,
    # skill description limit; above it the harness refuses to load the skill
    'DESC_LIMIT': 1024,
    # project instruction file benchmark (audit_scan.PROJECT_BENCH)
    'PROJECT_BENCH': 16 * 1024,
    # AGENTS.md chain budget, root + nested (audit_scan.CHAIN_BUDGET)
    'CHAIN_BUDGET': 32768,
    # what counts as a secret-prevention mechanism for G6
    'SECRET_PREVENTION_HINTS': {
        # only these hooks count as prevention when they run a secret scan
        'hook_names': ('pre-commit', 'pre-push'),
        # key inside hook flags set by the scanner
        'scan_flag': 'secret_scan',
        # patterns a .gitignore must cover; contents are not in the facts
        # yet, so a hook is the only verifiable proof today
        'gitignore_patterns': ('.env', '.mcp.json'),
    },
}

# --- declarative gate definitions -------------------------------------------

GATE_DEFS = [
    {
        'gid': 'G1', 'n': 1, 'name': 'Workspace structure',
        'description': 'Workspace layout sanity: one instruction source per level, '
                       'no unexpected nesting, no conflicting agent environments.',
        'pass_when': 'no drifted AGENTS.md/CLAUDE.md pairs, no nested repositories, '
                     'project directories match the harnesses in use',
        'fail_when': 'an AGENTS.md/CLAUDE.md pair at one level is neither identical '
                     'nor a pointer',
        'warn_when': 'a repository is nested inside another repository; project '
                     'directories exist for several harnesses while at most one is active',
        'recommendation': 'Fix the layout: one instruction source per level, no nested '
                          'repositories, project dirs only for harnesses in use.',
        'doc_ref': 'README.md#the-nine-gates',
    },
    {
        'gid': 'G2', 'n': 2, 'name': 'Configuration integrity',
        'description': 'Configuration files parse and have no duplicate keys.',
        'pass_when': 'every configuration file parses and each key occurs once',
        'fail_when': 'a configuration file has a syntax error or duplicate keys',
        'warn_when': 'no configuration files were found at all',
        'recommendation': 'Fix or remove broken config files; keep one key per setting.',
        'doc_ref': 'README.md#the-nine-gates',
    },
    {
        'gid': 'G3', 'n': 3, 'name': 'Rules consistency',
        'description': 'Instruction files resolve, agree and stay within budgets.',
        'pass_when': 'no dead references, no drifted pairs, no boilerplate, '
                     'files within the 16 KB benchmark and the 32768-byte chain budget',
        'fail_when': 'dead links, paths or commands; a drifted AGENTS.md/CLAUDE.md pair',
        'warn_when': 'generic boilerplate in auto-loaded context; an instruction file '
                     'over 16 KB; the AGENTS.md chain over 32768 bytes',
        'recommendation': 'Repair dead references, merge drifted pairs, replace '
                          'boilerplate with project-specific rules.',
        'doc_ref': 'README.md#the-nine-gates',
    },
    {
        'gid': 'G4', 'n': 4, 'name': 'Directory ownership and discoverability',
        'description': 'Every directory has a decided fate; valuable data sits under version control.',
        'pass_when': 'no heavy data directories outside git, no loose top-level folders',
        'fail_when': 'a heavy non-build directory sits outside every git repository',
        'warn_when': 'other top-level folders outside version control',
        'recommendation': 'Give every folder a fate: version control, archive or deletion.',
        'doc_ref': 'README.md#the-nine-gates',
    },
    {
        'gid': 'G5', 'n': 5, 'name': 'Skills and agent capabilities',
        'description': 'Skills have valid frontmatter, usable descriptions and synced copies.',
        'pass_when': 'frontmatter parses with the required fields, descriptions are under '
                     '1024 chars with triggers, copies are identical, references resolve',
        'fail_when': 'missing name or description, unparseable frontmatter, a description '
                     'over 1024 chars, diverged copies of one skill',
        'warn_when': 'no trigger phrase in a description; a skill references a missing file; '
                     'frontmatter parsed with the fallback parser (unknown)',
        'recommendation': 'Repair skill frontmatter, shorten descriptions, sync or remove '
                          'diverged copies.',
        'doc_ref': 'README.md#the-nine-gates',
    },
    {
        'gid': 'G6', 'n': 6, 'name': 'Secrets and Git security',
        'description': 'No secrets in files, index or remote URLs; a secret scan guards commits.',
        'pass_when': 'no secrets in worktree files, git index or remote URLs, and a '
                     'pre-commit/pre-push hook runs a secret scan',
        'fail_when': 'an exposed, staged or tracked secret; credentials in a remote URL',
        'warn_when': 'no secret-prevention mechanism exists (absence of prevention is never a pass)',
        'recommendation': 'Rotate exposed secrets, remove them from files and history, '
                          'add a pre-commit secret scan.',
        'doc_ref': 'README.md#security-model',
    },
    {
        'gid': 'G7', 'n': 7, 'name': 'Git hygiene',
        'description': 'Repositories are clean, ignored properly and free of oversized files.',
        'pass_when': 'clean worktrees, .gitignore present, no tracked file over 5 MB, '
                     'one checkout per remote',
        'fail_when': 'a tracked file over 5 MB',
        'warn_when': 'uncommitted or untracked work; a repo without .gitignore; '
                     'several checkouts of one remote',
        'recommendation': 'Commit or stash local work, add .gitignore, move big files '
                          'out of git, keep one checkout per remote.',
        'doc_ref': 'README.md#the-nine-gates',
    },
    {
        'gid': 'G8', 'n': 8, 'name': 'Agent environment governance',
        'description': 'One owner per rule; no instructions for dead harnesses; clean MCP config.',
        'pass_when': 'no dead-harness instructions, drifted pairs owned by G1/G3 '
                     '(cross-referenced here), no duplicate keys in MCP configs',
        'fail_when': 'instructions maintained for a dead harness; duplicate keys in an '
                     'MCP configuration',
        'warn_when': 'nothing (cross-references are informational)',
        'recommendation': 'Retire instructions for dead harnesses; keep one owner per rule '
                          'and one key per MCP server.',
        'doc_ref': 'README.md#the-nine-gates',
    },
    {
        'gid': 'G9', 'n': 9, 'name': 'Workspace health and maintainability',
        'description': 'Junk, build artifacts and oversized files stay within healthy limits.',
        'pass_when': 'no classified junk, total junk+build under 500 MB, few empty dirs, '
                     'no occasional harnesses, no large files outside git',
        'fail_when': 'junk and build artifacts together exceed 500 MB',
        'warn_when': 'confirmed or potentially unused junk; more than 10 empty dirs; an '
                     'occasional harness; a file over 5 MB outside git',
        'recommendation': 'Delete or archive junk, watch the total size, keep occasional '
                          'harnesses as a deliberate choice.',
        'doc_ref': 'README.md#limits-and-thresholds',
    },
]

# --- engine internals --------------------------------------------------------

_STATUS_RANK = {'not_applicable': 0, 'pass': 1, 'unknown': 2, 'warn': 3, 'fail': 4}

CATEGORY_BY_PREFIX = {
    'SEC': 'secrets', 'CFG': 'config', 'RUL': 'rules', 'DIR': 'dirs',
    'SKL': 'skills', 'GIT': 'git', 'GOV': 'governance', 'HLTH': 'health',
}

# project-dir marker -> harness tool it belongs to ('.agents' is the
# Z Code project skills dir, so it maps to the zcode harness)
_DIR_TO_TOOL = {'.claude': 'claude', '.codex': 'codex',
                '.zcode/config.json': 'zcode', '.agents': 'zcode'}

_REQUIRED_SKILL_FIELDS = ('name', 'description')


def worst_status(statuses):
    """Worst of the given statuses; fail > warn > unknown > pass > not_applicable."""
    if not statuses:
        return 'unknown'
    return max(statuses, key=lambda s: _STATUS_RANK.get(s, 0))


def _norm(path):
    return str(path).replace('\\', '/')


def _kb(n):
    return '%d KB' % ((n or 0) // 1024)


def _mb(n):
    return '%d MB' % ((n or 0) // (1024 * 1024))


class _Counter:
    """Per-prefix finding counters: SEC-001, CFG-001, ..."""

    def __init__(self):
        self._n = {p: 0 for p in CATEGORY_BY_PREFIX}

    def next_id(self, prefix):
        self._n[prefix] += 1
        return '%s-%03d' % (prefix, self._n[prefix])


class _GateRun:
    """Collects rule results, evidence lines and findings for one gate."""

    def __init__(self, gid, counter, findings, ctx):
        self.gid = gid
        self.counter = counter
        self.findings = findings
        self.ctx = ctx
        self.checks = []
        self.evidence = []

    def rule(self, name, status, evidence=()):
        self.checks.append({'rule': name, 'status': status})
        lines = list(evidence) or ['%s: %s' % (name, status)]
        self.evidence.extend(lines)

    def finding(self, prefix, severity, status, title, description, evidence,
                confidence, recommendation, autofix_available=False):
        f = report_model.make_finding(
            fid=self.counter.next_id(prefix), gate=self.gid,
            category=CATEGORY_BY_PREFIX[prefix], severity=severity,
            status=status, title=title, description=description,
            evidence=evidence, confidence=confidence,
            recommendation=recommendation,
            autofix_available=autofix_available)
        self.findings.append(f)
        return f


def _missing(run, prefix, title, section):
    run.finding(prefix, 'low', 'unknown', title,
                'Facts section %r is absent, so this check did not run; '
                'the gate cannot pass on missing data.' % section,
                [{'detail': 'facts section missing: %s' % section}], 0.5,
                'Re-run the scanner with the current version and pass the full facts dict.')


def _skill_meta(entry, skills_extra):
    """frontmatter facts from the merged entry keys, else from skills_extra."""
    meta = {}
    for key in ('frontmatter_ok', 'missing_fields', 'dead_refs', 'parser'):
        if key in entry:
            meta[key] = entry[key]
    for key, val in (skills_extra.get(entry.get('name')) or {}).items():
        meta.setdefault(key, val)
    return meta


# --- G1: workspace structure -------------------------------------------------

def _g1(facts, run):
    drift = facts.get('context_drift')
    if drift is None:
        _missing(run, 'DIR', 'Instruction pair drift not verified', 'context_drift')
        run.rule('drifted-config-pairs', 'unknown')
    else:
        for d in drift:
            f = run.finding(
                'DIR', 'high', 'fail',
                'Drifted AGENTS.md/CLAUDE.md pair in %s' % d.get('path', '?'),
                'AGENTS.md and CLAUDE.md at the same level are neither identical '
                'nor linked by a pointer; two rule sources diverge over time.',
                [{'location': d.get('path'), 'jaccard': d.get('jaccard')}],
                0.9, 'Keep one file as the source and turn the other into a pointer to it.')
            run.ctx.setdefault('drift_fids', []).append(f['fid'])
        run.rule('drifted-config-pairs', 'fail' if drift else 'pass',
                 ['drifted config pairs: %d' % len(drift)])

    top = facts.get('top_level')
    if top is None:
        _missing(run, 'DIR', 'Nested repositories not verified', 'top_level')
        run.rule('nested-repos', 'unknown')
    else:
        nested = [(t.get('name'), rel)
                  for t in top
                  for rel in ((t.get('extra') or {}).get('nested_repos') or [])]
        for repo, rel in nested:
            run.finding(
                'DIR', 'medium', 'warn',
                'Nested repository in %s: %s' % (repo, rel),
                'A git repository lives inside another repository; the outer one '
                'sees it as embedded untracked content and sync tools mis-handle it.',
                [{'repo': repo, 'nested': rel}], 0.85,
                'Register it as a submodule or move it out to the workspace top level.')
        run.rule('nested-repos', 'warn' if nested else 'pass',
                 ['nested repositories: %d' % len(nested)])

    h = facts.get('harness')
    if not isinstance(h, dict) or 'tools' not in h or 'project_dirs' not in h:
        _missing(run, 'DIR', 'Agent environment conflict not verified', 'harness')
        run.rule('harness-env-conflict', 'unknown')
    else:
        states = {t.get('tool'): t.get('state') for t in (h.get('tools') or [])}
        present = {}
        for pd in h.get('project_dirs') or []:
            tool = _DIR_TO_TOOL.get(_norm(pd.get('name', '')))
            if tool and pd.get('exists') and tool not in present:
                present[tool] = pd.get('name')
        active = sorted(t for t in present if states.get(t) == 'active')
        if len(present) > 1 and len(active) <= 1:
            detail = ', '.join('%s (%s, %s)' % (name, tool, states.get(tool, 'unknown'))
                               for tool, name in sorted(present.items()))
            run.finding(
                'DIR', 'low', 'warn',
                'Project dirs for several harnesses, at most one active',
                'Directories exist for %d harnesses but only %d active one(s); '
                'the idle ones still load their context and drift.' % (len(present), len(active)),
                [{'detail': detail}], 0.8,
                'Remove the directories of harnesses you no longer use, or accept '
                'the extra context deliberately.')
            run.rule('harness-env-conflict', 'warn',
                     ['harness dirs present: %d, active: %d' % (len(present), len(active))])
        else:
            run.rule('harness-env-conflict', 'pass',
                     ['harness dirs present: %d, active among them: %d'
                      % (len(present), len(active))])


# --- G2: configuration integrity ----------------------------------------------

def _g2(facts, run):
    cfg = facts.get('config_integrity')
    if cfg is None:
        _missing(run, 'CFG', 'Configuration integrity not verified', 'config_integrity')
        run.rule('config-parse', 'unknown')
        return
    if not cfg:
        run.finding(
            'CFG', 'info', 'warn', 'No configuration files found',
            'The scanner found no configuration files to parse. Absence of data is '
            'not a pass: nobody confirmed the workspace really has no configs.',
            [{'detail': 'no configuration files found'}], 0.9,
            'If the workspace should have configs (MCP, harness settings), find out '
            'why none were discovered.')
        run.rule('config-parse', 'warn', ['no configuration files found'])
        return
    broken = 0
    for e in cfg:
        if not e.get('ok', True):
            broken += 1
            run.finding(
                'CFG', 'high', 'fail',
                'Configuration file does not parse: %s' % e.get('path', '?'),
                'The %s file failed to parse (%s); tools reading it fall back to '
                'defaults or fail outright.' % (e.get('format', 'config'),
                                                e.get('error') or 'syntax error'),
                [{'file': e.get('path'), 'format': e.get('format'),
                  'error': e.get('error')}],
                0.95, 'Fix the syntax error, then re-run the audit.')
        for key in e.get('dup_keys') or []:
            broken += 1
            run.finding(
                'CFG', 'medium', 'fail',
                'Duplicate key %r in %s' % (key, e.get('path', '?')),
                'Duplicate keys in a %s file resolve silently to the last '
                'occurrence; what is written stops matching what runs.'
                % e.get('format', 'config'),
                [{'file': e.get('path'), 'key': key}], 0.9,
                'Remove the duplicate key and keep one deliberate value.')
    run.rule('config-parse', 'fail' if broken else 'pass',
             ['config files parsed: %d, broken: %d' % (len(cfg), broken)])


# --- G3: rules consistency ------------------------------------------------------

def _g3(facts, run):
    cf = facts.get('context_files')
    if cf is None:
        _missing(run, 'RUL', 'Instruction file checks not verified', 'context_files')
        run.rule('dead-references', 'unknown')
        run.rule('generic-markers', 'unknown')
        run.rule('instruction-size', 'unknown')
    else:
        dead = 0
        for e in cf:
            for kind, label in (('dead_links', 'link'), ('dead_paths', 'path'),
                                ('dead_commands', 'command')):
                for ref in e.get(kind) or []:
                    dead += 1
                    run.finding(
                        'RUL', 'medium', 'fail',
                        'Dead %s in %s: %s' % (label, e.get('path', '?'), ref),
                        'The instruction file points to %r which does not exist; '
                        'an agent following it fails or improvises.' % ref,
                        [{'file': e.get('path'), 'ref': ref, 'kind': label}],
                        0.9, 'Fix or remove the reference.')
        run.rule('dead-references', 'fail' if dead else 'pass',
                 ['instruction files checked: %d, dead references: %d' % (len(cf), dead)])

        markers = [(e.get('path'), m) for e in cf for m in (e.get('generic_markers') or [])]
        for p, m in markers:
            run.finding(
                'RUL', 'low', 'warn', 'Generic boilerplate in %s: %r' % (p, m),
                'Template or overview text inside auto-loaded context spends the '
                'context budget without giving the agent rules.',
                [{'file': p, 'marker': m}], 0.7,
                'Replace the boilerplate with project-specific rules or drop it.')
        run.rule('generic-markers', 'warn' if markers else 'pass',
                 ['generic markers: %d' % len(markers)])

        big = [e for e in cf if (e.get('size_bytes') or 0) > GATE_POLICY['PROJECT_BENCH']]
        for e in big:
            run.finding(
                'RUL', 'low', 'warn',
                'Instruction file over %s: %s' % (_kb(GATE_POLICY['PROJECT_BENCH']), e.get('path')),
                'The file is %s; the project-instruction benchmark is %s, everything '
                'above it taxes every session.'
                % (_kb(e.get('size_bytes') or 0), _kb(GATE_POLICY['PROJECT_BENCH'])),
                [{'file': e.get('path'), 'size': _kb(e.get('size_bytes') or 0)}],
                0.85, 'Split the file: keep rules auto-loaded, move the rest to linked docs.')
        run.rule('instruction-size', 'warn' if big else 'pass',
                 ['instruction files over benchmark: %d' % len(big)])

    drift = facts.get('context_drift')
    if drift is None:
        _missing(run, 'RUL', 'Rule pair drift not verified', 'context_drift')
        run.rule('pair-drift', 'unknown')
    else:
        for d in drift:
            f = run.finding(
                'RUL', 'high', 'fail', 'Two rule sources at %s' % d.get('path', '?'),
                'AGENTS.md and CLAUDE.md at the same level disagree (similarity %s); '
                'each edit widens the gap.' % d.get('jaccard'),
                [{'location': d.get('path'), 'jaccard': d.get('jaccard')}],
                0.9, 'Keep one file as the source and make the other a pointer '
                     '(structure view: G1).')
            run.ctx.setdefault('drift_fids', []).append(f['fid'])
        run.rule('pair-drift', 'fail' if drift else 'pass',
                 ['drifted pairs: %d' % len(drift)])

    if 'chain_budget_over' not in facts:
        _missing(run, 'RUL', 'AGENTS.md chain budget not verified', 'chain_budget_over')
        run.rule('chain-budget', 'unknown')
    elif facts.get('chain_budget_over'):
        over = [c for c in (facts.get('context_budget') or []) if c.get('over')]
        run.finding(
            'RUL', 'medium', 'warn',
            'AGENTS.md chain over %d bytes' % GATE_POLICY['CHAIN_BUDGET'],
            'The root plus nested AGENTS.md chain exceeds the Codex budget; '
            'the tail is truncated silently.',
            [{'chain': c.get('root'), 'bytes': c.get('total_bytes')} for c in over]
            or [{'detail': 'chain over budget'}],
            0.9, 'Trim the chain or split nested instructions into linked files.')
        run.rule('chain-budget', 'warn', ['chains over budget: %d' % max(len(over), 1)])
    else:
        run.rule('chain-budget', 'pass',
                 ['AGENTS.md chains within %d bytes' % GATE_POLICY['CHAIN_BUDGET']])


# --- G4: directory ownership -----------------------------------------------------

def _g4(facts, run):
    heavy = facts.get('heavy_outside_git')
    if heavy is None:
        _missing(run, 'DIR', 'Heavy directories outside git not verified',
                 'heavy_outside_git')
        run.rule('heavy-outside-git', 'unknown')
        heavy = None
    else:
        for h in heavy:
            run.finding(
                'DIR', 'medium', 'fail',
                'Heavy directory outside git: %s' % h.get('path', '?'),
                'The directory holds %s of data, is not a build artifact and sits '
                'outside every git repository; its fate is undecided.'
                % _kb(h.get('size_bytes')),
                [{'path': h.get('path'), 'size': _kb(h.get('size_bytes')),
                  'depth': h.get('depth')}],
                0.9, 'Move it under version control, archive it, or delete it.')
        run.rule('heavy-outside-git', 'fail' if heavy else 'pass',
                 ['heavy dirs outside git: %d' % len(heavy)])

    top = facts.get('top_level')
    if top is None:
        _missing(run, 'DIR', 'Top-level layout not verified', 'top_level')
        run.rule('unowned-top-dirs', 'unknown')
    else:
        heavy_paths = {_norm(h.get('path', '')) for h in (heavy or [])}
        loose = []
        for t in top:
            if t.get('kind') != 'dir':
                continue
            name = _norm(t.get('name', ''))
            if any(p == name or p.startswith(name + '/') for p in heavy_paths):
                continue
            loose.append(t)
        if loose:
            run.finding(
                'DIR', 'low', 'warn',
                '%d top-level folders outside version control' % len(loose),
                'These folders are not git repositories; their content has no '
                'history and no backup.',
                [{'path': t.get('name'), 'size': _kb(t.get('size_bytes'))} for t in loose],
                0.9, 'Decide for each folder: make it a repo, move it into one, or remove it.')
        run.rule('unowned-top-dirs', 'warn' if loose else 'pass',
                 ['top-level dirs outside git: %d' % len(loose)])


# --- G5: skills -----------------------------------------------------------------

def _g5(facts, run):
    skills = facts.get('skills')
    if not isinstance(skills, dict) or 'entries' not in skills:
        _missing(run, 'SKL', 'Skills not verified', 'skills')
        for name in ('frontmatter', 'description-length', 'triggers',
                     'skill-dead-refs', 'duplicate-copies'):
            run.rule(name, 'unknown')
        return
    entries = skills.get('entries') or []
    extra = facts.get('skills_extra') or {}

    fm_fail = fm_unknown = verified = over_desc = no_triggers = dead_refs = 0
    for e in entries:
        meta = _skill_meta(e, extra)
        name = e.get('name') or e.get('path') or '?'
        fm_ok = meta.get('frontmatter_ok')
        if fm_ok is None:
            fm_unknown += 1
            reason = ('fallback parser' if meta.get('parser') == 'fallback' or not meta
                      else 'no frontmatter facts')
            run.finding(
                'SKL', 'low', 'unknown',
                'Skill %r: frontmatter checks skipped (%s)' % (name, reason),
                'Frontmatter facts are missing or the file was parsed with the '
                'fallback parser, so the field checks for this skill did not run.',
                [{'file': e.get('path'), 'parser': meta.get('parser', 'unknown')}],
                0.6, 'Fix the frontmatter so it parses as YAML, then re-run the audit.')
            continue
        if fm_ok is False:
            fm_fail += 1
            run.finding(
                'SKL', 'high', 'fail',
                'Frontmatter of skill %r does not parse' % name,
                'The frontmatter could not be parsed (parser: %s); the skill may '
                'not load at all.' % meta.get('parser', 'yaml'),
                [{'file': e.get('path'), 'parser': meta.get('parser')}],
                0.9, 'Fix the frontmatter syntax in SKILL.md.')
            continue
        missing = [f for f in (meta.get('missing_fields') or [])
                   if f in _REQUIRED_SKILL_FIELDS]
        if e.get('desc_len') is None and 'description' not in missing:
            missing.append('description')
        if missing:
            fm_fail += 1
            run.finding(
                'SKL', 'high', 'fail',
                'Skill %r misses required fields: %s' % (name, ', '.join(missing)),
                'A SKILL.md without %s is not a valid skill; harnesses skip or '
                'mis-load it.' % ' and '.join(missing),
                [{'file': e.get('path'), 'missing': missing}], 0.95,
                'Add the missing field(s) to the frontmatter.')
            continue
        verified += 1
        if (e.get('desc_len') or 0) > GATE_POLICY['DESC_LIMIT']:
            over_desc += 1
            run.finding(
                'SKL', 'high', 'fail',
                'Description of skill %r is %d chars, limit %d'
                % (name, e['desc_len'], GATE_POLICY['DESC_LIMIT']),
                'The harness refuses to load a skill whose description exceeds the limit.',
                [{'file': e.get('path'), 'desc_len': e['desc_len']}], 0.95,
                'Shorten the description; move details into the skill body.')
        if not e.get('has_triggers'):
            no_triggers += 1
            run.finding(
                'SKL', 'low', 'warn',
                'No triggers in the description of skill %r' % name,
                'Without a "use when"-style phrase the harness rarely picks the skill.',
                [{'file': e.get('path')}], 0.8,
                'Add a trigger phrase ("use when ...") to the description.')
        for ref in meta.get('dead_refs') or []:
            dead_refs += 1
            run.finding(
                'SKL', 'medium', 'warn',
                'Skill %r references missing file: %s' % (name, ref),
                'The SKILL.md points to %r which does not exist next to it.' % ref,
                [{'file': e.get('path'), 'ref': ref}], 0.9,
                'Restore the file or drop the reference.')

    if fm_fail:
        fm_status = 'fail'
    elif fm_unknown:
        fm_status = 'unknown'
    elif not entries:
        fm_status = 'not_applicable'
    else:
        fm_status = 'pass'
    run.rule('frontmatter', fm_status,
             ['skills checked: %d, frontmatter failures: %d, unverified: %d'
              % (len(entries), fm_fail, fm_unknown)])

    if not entries:
        detail_status = 'not_applicable'
    elif verified == 0:
        detail_status = 'unknown'
    else:
        detail_status = None
    run.rule('description-length',
             detail_status or ('fail' if over_desc else 'pass'),
             ['descriptions over %d chars: %d' % (GATE_POLICY['DESC_LIMIT'], over_desc)])
    run.rule('triggers',
             detail_status or ('warn' if no_triggers else 'pass'),
             ['skills without triggers: %d' % no_triggers])
    run.rule('skill-dead-refs',
             detail_status or ('warn' if dead_refs else 'pass'),
             ['dead skill references: %d' % dead_refs])

    dups = skills.get('duplicates')
    if dups is None:
        _missing(run, 'SKL', 'Skill copy sync not verified', 'skills.duplicates')
        run.rule('duplicate-copies', 'unknown')
    else:
        diverged = [d for d in dups if d.get('sync') != 'identical']
        for d in diverged:
            run.finding(
                'SKL', 'high', 'fail', 'Diverged copies of skill %r' % d.get('name'),
                '%s copies of the skill exist and their content differs; edits land '
                'in one copy while the harness loads another.' % d.get('copies'),
                [{'name': d.get('name'), 'copies': d.get('copies'),
                  'paths': (d.get('paths') or [])[:10]}],
                0.95, 'Pick one canonical location and delete or sync the rest.')
        run.rule('duplicate-copies', 'fail' if diverged else 'pass',
                 ['skill name collisions: %d, diverged: %d' % (len(dups), len(diverged))])


# --- G6: secrets and git security --------------------------------------------------

def _g6(facts, run):
    sec = facts.get('secrets')
    if sec is None:
        _missing(run, 'SEC', 'Exposed secrets not verified', 'secrets')
        run.rule('exposed-secrets', 'unknown')
    else:
        for s in sec:
            run.finding(
                'SEC', 'critical', 'fail',
                'Exposed secret in %s:%s' % (s.get('path', '?'), s.get('line', '?')),
                'A %s was detected in a workspace file; the value is redacted, only '
                'the mask and fingerprint are recorded.' % s.get('kind', 'secret'),
                [{'file': s.get('path'), 'line': s.get('line'), 'kind': s.get('kind'),
                  'mask': s.get('mask'), 'fingerprint': s.get('fingerprint')}],
                s.get('confidence', 0.9),
                'Rotate the secret at its provider, remove it from the file and '
                'purge it from history.')
        run.rule('exposed-secrets', 'fail' if sec else 'pass',
                 ['secrets found in workspace files: %d' % len(sec)])

    top = facts.get('top_level')
    if top is None:
        _missing(run, 'SEC', 'Git-side secret checks not verified', 'top_level')
        run.rule('tracked-secrets', 'unknown')
        run.rule('secret-prevention', 'unknown')
        return
    git_hits = 0
    for t in top:
        ex = t.get('extra') or {}
        for ts in ex.get('tracked_secrets') or []:
            git_hits += 1
            run.finding(
                'SEC', 'critical', 'fail',
                'Secret tracked in git at %s: %s:%s'
                % (t.get('name'), ts.get('file'), ts.get('line')),
                'A %s sits in a tracked or staged file; it leaves the machine with '
                'the next push.' % ts.get('kind', 'secret'),
                [{'repo': t.get('name'), 'file': ts.get('file'), 'line': ts.get('line'),
                  'kind': ts.get('kind'), 'fingerprint': ts.get('fingerprint')}],
                ts.get('confidence', 0.9),
                'Rotate the secret, `git rm --cached` the file and purge the history.')
        if ex.get('credentials_in_remote'):
            git_hits += 1
            run.finding(
                'SEC', 'critical', 'fail',
                'Credentials in the remote URL of %s' % t.get('name'),
                'The origin URL embeds a login:password pair; it is in .git/config '
                'and shows up in every `git remote -v`.',
                [{'repo': t.get('name')}], 0.95,
                'Move auth to a credential helper, then change the password: '
                'the current one is already in a file.')
    run.rule('tracked-secrets', 'fail' if git_hits else 'pass',
             ['secret hits in git (index, remote URLs): %d' % git_hits])

    hints = GATE_POLICY['SECRET_PREVENTION_HINTS']
    repos_scanned = sum(1 for t in top if t.get('kind') == 'repo')
    hooks = []
    for t in top:
        for h in (t.get('extra') or {}).get('hooks') or []:
            if (h.get('name') in hints['hook_names']
                    and (h.get('flags') or {}).get(hints['scan_flag'])):
                hooks.append('%s: %s' % (t.get('name'), h.get('name')))
    if hooks:
        run.rule('secret-prevention', 'pass',
                 ['secret scan hooks: ' + '; '.join(hooks)])
    else:
        run.finding(
            'SEC', 'medium', 'warn', 'No secret-prevention mechanism found',
            'No %s hook runs a secret scan in any of the %d repositories. A '
            '.gitignore alone is not proof: coverage of %s is not derivable from '
            'the collected facts, so absence of a hook is treated as no prevention.'
            % ('/'.join(hints['hook_names']), repos_scanned,
               ', '.join(hints['gitignore_patterns'])),
            [{'detail': 'no %s hook with secret scan in any repository'
                        % '/'.join(hints['hook_names']),
              'repositories scanned': repos_scanned}],
            0.85,
            'Install a pre-commit secret scan (gitleaks or equivalent) in every '
            'active repository.')
        run.rule('secret-prevention', 'warn',
                 ['secret scan hooks found: 0 (repositories scanned: %d)'
                  % repos_scanned])


# --- G7: git hygiene ------------------------------------------------------------------

def _g7(facts, run):
    top = facts.get('top_level')
    if top is None:
        _missing(run, 'GIT', 'Git hygiene not verified', 'top_level')
        for name in ('worktree-clean', 'gitignore-present', 'tracked-big-files',
                     'single-checkout'):
            run.rule(name, 'unknown')
        return
    repos = [t for t in top if t.get('kind') == 'repo']
    if not repos:
        for name in ('worktree-clean', 'gitignore-present', 'tracked-big-files',
                     'single-checkout'):
            run.rule(name, 'not_applicable',
                     ['no git repositories at the top level'])
        return

    dirty = 0
    for t in repos:
        g = t.get('git') or {}
        nd = len(g.get('dirty') or [])
        nu = len(g.get('untracked') or [])
        if nd or nu:
            dirty += 1
            run.finding(
                'GIT', 'low', 'warn', 'Uncommitted work in %s' % t.get('name'),
                '%d modified and %d untracked paths; local-only work is one disk '
                'failure away from loss.' % (nd, nu),
                [{'repo': t.get('name'), 'dirty': nd, 'untracked': nu}], 0.9,
                'Commit or stash the changes; push if the repo has a remote.')
    run.rule('worktree-clean', 'warn' if dirty else 'pass',
             ['repos with uncommitted work: %d of %d' % (dirty, len(repos))])

    noign = [t for t in repos if not (t.get('extra') or {}).get('gitignore', False)]
    for t in noign:
        run.finding(
            'GIT', 'low', 'warn', 'No .gitignore in %s' % t.get('name'),
            'Without .gitignore, build artifacts and local config land in commits.',
            [{'repo': t.get('name')}], 0.9,
            'Add a .gitignore covering build dirs and local config files.')
    run.rule('gitignore-present', 'warn' if noign else 'pass',
             ['repos without .gitignore: %d' % len(noign)])

    lf = facts.get('large_files')
    if lf is None:
        _missing(run, 'GIT', 'Large tracked files not verified', 'large_files')
        run.rule('tracked-big-files', 'unknown')
    else:
        repo_names = {_norm(t.get('name', '')) for t in repos}
        big = 0
        for f in lf:
            size = f.get('size_bytes') or 0
            if size < GATE_POLICY['TRACKED_BIG_BYTES']:
                continue
            inside = _norm(f.get('path', '')).split('/')[0] in repo_names
            tracked = f.get('tracked', inside)
            if not tracked:
                continue
            big += 1
            run.finding(
                'GIT', 'medium', 'fail',
                'Tracked file over %s: %s' % (_mb(GATE_POLICY['TRACKED_BIG_BYTES']),
                                              f.get('path')),
                'A %s file lives in git; every clone pays for it and the history '
                'keeps it forever.' % _mb(size),
                [{'file': f.get('path'), 'size': _kb(size)}], 0.9,
                'Move the file out of git (or into git-lfs) and rewrite history '
                'if it already spread.')
        run.rule('tracked-big-files', 'fail' if big else 'pass',
                 ['tracked files over %s: %d' % (_mb(GATE_POLICY['TRACKED_BIG_BYTES']), big)])

    dup = facts.get('dup_checkouts')
    if dup is None:
        _missing(run, 'GIT', 'Duplicate checkouts not verified', 'dup_checkouts')
        run.rule('single-checkout', 'unknown')
    else:
        dups = [(url, names) for url, names in sorted(dup.items()) if len(names) > 1]
        for url, names in dups:
            run.finding(
                'GIT', 'low', 'warn',
                'Multiple checkouts of one remote: %s' % ', '.join(names),
                'The same repository is checked out %d times; edits in one copy do '
                'not reach the others.' % len(names),
                [{'remote': url, 'checkouts': names}], 0.9,
                'Keep one checkout or make the others deliberate worktrees.')
        run.rule('single-checkout', 'warn' if dups else 'pass',
                 ['remotes with several checkouts: %d' % len(dups)])


# --- G8: agent environment governance --------------------------------------------

def _g8(facts, run):
    h = facts.get('harness')
    notes = h.get('notes') if isinstance(h, dict) else None
    if notes is None:
        _missing(run, 'GOV', 'Agent environment governance not verified', 'harness')
        run.rule('dead-harness-instructions', 'unknown')
    else:
        for note in notes:
            run.finding(
                'GOV', 'medium', 'fail',
                'Instructions maintained for a dead harness',
                'An instruction file is kept for a harness that has been idle: %s'
                % note,
                [{'detail': note}], 0.85,
                'Remove the file or convert it to a pointer under the harness '
                'actually in use.')
        run.rule('dead-harness-instructions', 'fail' if notes else 'pass',
                 ['governance notes: %d' % len(notes)])

    drift = facts.get('context_drift')
    if drift is None:
        run.rule('drift-ownership', 'unknown')
    elif drift:
        refs = sorted(run.ctx.get('drift_fids', []))
        run.rule('drift-ownership', 'pass',
                 ['drifted pairs: %d, owned by G1/G3 findings (%s)'
                  % (len(drift), ', '.join(refs) or 'n/a')])
    else:
        run.rule('drift-ownership', 'pass', ['drifted pairs: 0'])

    cfg = facts.get('config_integrity')
    if cfg is None:
        _missing(run, 'GOV', 'MCP configuration not verified', 'config_integrity')
        run.rule('mcp-duplicate-keys', 'unknown')
    else:
        mcp_bad = 0
        for e in cfg:
            if 'mcp' not in _norm(e.get('path', '')).lower():
                continue
            for key in e.get('dup_keys') or []:
                mcp_bad += 1
                run.finding(
                    'GOV', 'medium', 'fail',
                    'Duplicate key %r in MCP config %s' % (key, e.get('path')),
                    'Two blocks in the MCP configuration share a key; one silently '
                    'wins and the running setup diverges from what is written.',
                    [{'file': e.get('path'), 'key': key}], 0.9,
                    'Rename or remove the duplicate block so each key maps to one server.')
        run.rule('mcp-duplicate-keys', 'fail' if mcp_bad else 'pass',
                 ['MCP configs with duplicate keys: %d' % mcp_bad])


# --- G9: workspace health ----------------------------------------------------------

def _g9(facts, run):
    jc = facts.get('junk_classified')
    if jc is None:
        _missing(run, 'HLTH', 'Junk classification not verified', 'junk_classified')
        run.rule('classified-junk', 'unknown')
    else:
        actionable = [j for j in jc
                      if j.get('cls') in ('confirmed_unused', 'potentially_unused')]
        for j in actionable:
            conf = j.get('confidence')
            if not isinstance(conf, (int, float)) or isinstance(conf, bool):
                conf = 0.7
            run.finding(
                'HLTH', 'low', 'warn',
                'Unused data (%s): %s' % (j.get('cls'), j.get('path', '?')),
                'Classified as %s (confidence %s): %s.'
                % (j.get('cls'), conf, j.get('reason')),
                [{'path': j.get('path'), 'reason': j.get('reason'),
                  'size': _kb(j.get('size_bytes')), 'class': j.get('cls')}],
                conf, 'Review, then archive or delete.',
                autofix_available=(j.get('cls') == 'confirmed_unused'))
        run.rule('classified-junk', 'warn' if actionable else 'pass',
                 ['classified junk items: %d' % len(actionable)])

    j = facts.get('junk')
    if j is None:
        _missing(run, 'HLTH', 'Junk volume not verified', 'junk')
        run.rule('junk-volume', 'unknown')
        run.rule('empty-dirs', 'unknown')
    else:
        files = j.get('files') or []
        dirs = j.get('dirs') or []
        total = (sum(f.get('size_bytes', 0) for f in files)
                 + sum(d.get('size_bytes', 0) for d in dirs))
        if total > GATE_POLICY['JUNK_FAIL_BYTES']:
            run.finding(
                'HLTH', 'medium', 'fail',
                'Junk and build artifacts over %s' % _mb(GATE_POLICY['JUNK_FAIL_BYTES']),
                'The workspace carries %s of junk files and build directories; '
                'scans, backups and disk suffer.' % _mb(total),
                [{'detail': 'total junk+build size: %d bytes' % total}], 0.95,
                'Delete build dirs (they regenerate) and archive or remove the rest.')
        run.rule('junk-volume',
                 'fail' if total > GATE_POLICY['JUNK_FAIL_BYTES'] else 'pass',
                 ['junk+build total: %s across %d files and %d dirs'
                  % (_mb(total), len(files), len(dirs))])
        empty = j.get('empty_dirs') or []
        if len(empty) > GATE_POLICY['EMPTY_WARN_COUNT']:
            run.finding(
                'HLTH', 'info', 'warn', '%d empty directories' % len(empty),
                'More than %d empty dirs: usually debris from moves and deletes.'
                % GATE_POLICY['EMPTY_WARN_COUNT'],
                [{'path': p} for p in empty[:50]], 0.9,
                'Remove the empty directories.')
            run.rule('empty-dirs', 'warn', ['empty dirs: %d' % len(empty)])
        elif empty:
            run.finding(
                'HLTH', 'info', 'pass', '%d empty directories' % len(empty),
                'A few empty dirs are harmless; recorded as an observation.',
                [{'path': p} for p in empty[:50]], 0.9,
                'Optional: remove the empty directories.')
            run.rule('empty-dirs', 'pass',
                     ['empty dirs: %d (at or below %d)'
                      % (len(empty), GATE_POLICY['EMPTY_WARN_COUNT'])])
        else:
            run.rule('empty-dirs', 'pass', ['empty dirs: 0'])

    h = facts.get('harness')
    tools = h.get('tools') if isinstance(h, dict) else None
    if tools is None:
        run.rule('occasional-harness', 'unknown')
    else:
        occ = [t for t in tools if t.get('state') == 'occasional']
        for t in occ:
            run.finding(
                'HLTH', 'info', 'warn',
                'Harness %s used occasionally' % t.get('tool'),
                'Last activity %s days ago: between fresh and abandoned; decide '
                'which way it goes.' % t.get('last_activity_days_ago'),
                [{'tool': t.get('tool'), 'days': t.get('last_activity_days_ago')}],
                0.8, 'Keep it maintained or retire its config files.')
        run.rule('occasional-harness', 'warn' if occ else 'pass',
                 ['occasional harnesses: %d' % len(occ)])

    lf = facts.get('large_files')
    top = facts.get('top_level')
    if lf is None or top is None:
        run.rule('large-untracked-files', 'unknown',
                 ['skipped: large_files or top_level facts missing'])
    else:
        repo_names = {_norm(t.get('name', '')) for t in top if t.get('kind') == 'repo'}
        outside = [f for f in lf
                   if _norm(f.get('path', '')).split('/')[0] not in repo_names]
        for f in outside:
            run.finding(
                'HLTH', 'low', 'warn',
                'File over %s outside git: %s'
                % (_mb(GATE_POLICY['TRACKED_BIG_BYTES']), f.get('path')),
                'Large files outside version control; check whether they are data '
                'worth keeping.',
                [{'path': f.get('path'), 'size': _kb(f.get('size_bytes'))}], 0.9,
                'Move under version control (git-lfs if needed) or delete.')
        run.rule('large-untracked-files', 'warn' if outside else 'pass',
                 ['large files outside git: %d' % len(outside)])


_BUILDERS = {'G1': _g1, 'G2': _g2, 'G3': _g3, 'G4': _g4, 'G5': _g5,
             'G6': _g6, 'G7': _g7, 'G8': _g8, 'G9': _g9}


def evaluate(facts):
    """Evaluate all nine gates over the facts dict.

    Returns (gates, findings): gates in GATE_DEFS order, findings in
    creation order with stable <PREFIX>-<counter> ids (SEC-001, CFG-001,
    ...). A gate's status is the worst status among its rules; a gate
    whose rules all lack data is unknown, never pass.
    """
    facts = facts or {}
    counter = _Counter()
    findings = []
    ctx = {}
    gates_out = []
    for gd in GATE_DEFS:
        run = _GateRun(gd['gid'], counter, findings, ctx)
        _BUILDERS[gd['gid']](facts, run)
        status = worst_status([c['status'] for c in run.checks])
        conf = min((f['confidence'] for f in findings if f['gate'] == gd['gid']),
                   default=0.95)
        gates_out.append(report_model.make_gate(
            gid=gd['gid'], n=gd['n'], name=gd['name'],
            description=gd['description'], checks=run.checks,
            pass_when=gd['pass_when'], fail_when=gd['fail_when'],
            warn_when=gd['warn_when'], status=status,
            evidence=run.evidence, confidence=round(conf, 2),
            recommendation=gd['recommendation'], doc_ref=gd['doc_ref']))
    return gates_out, findings
