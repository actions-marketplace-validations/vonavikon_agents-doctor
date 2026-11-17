#!/usr/bin/env python3
"""Agent Runtime Health (TZ section 12, Phase 6).

Opt-in runtime environment audit: verifies that this machine can run
the agent harnesses the static audit talks about. STRICTLY opt-in --
audit_scan.scan() must never call into this module on its own; it runs
only through an explicit check_environment() call or the CLI flag the
main session wires into agents_doctor.py.

Safety contract:
- offline: no network access of any kind (MCP endpoints are never
  contacted, config checks are structure-only);
- read-only: nothing is written to disk;
- the only subprocess ever spawned is `<bin> --version` with a 10s
  timeout, shell=False and a list argv.

Every check reports {id, name, status, detail, evidence} with status in
pass | fail | warn | unknown | not_applicable. The summary counts the
four real statuses; not_applicable (harnesses with no CLI to probe) is
excluded from the counts.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import iter_adapters        # noqa: E402
from harness.base import HarnessContext  # noqa: E402

try:
    import tomllib  # stdlib since Python 3.11
except ImportError:  # Python 3.10
    tomllib = None

# --- policy ----------------------------------------------------------------

# harness_id -> CLI binary name on PATH; None = nothing to probe
# (editor plugin or GUI application, not a command-line tool).
CLI_BINARIES = {
    'zcode': 'zcode',
    'claude_code': 'claude',
    'codex': 'codex',
    'gemini_cli': 'gemini',
    'opencode': 'opencode',
    'github_copilot': None,   # editor plugin
    'cursor': None,           # GUI application
    'windsurf': None,         # GUI application
}

# top-level keys under which harness configs keep their MCP server map
MCP_SECTION_KEYS = ('mcpServers', 'mcp_servers', 'mcp')
# files whose whole top-level object IS the server map (Claude Code)
MCP_MAP_FILENAMES = ('.mcp.json',)

VERSION_TIMEOUT_SECONDS = 10
STALE_LOCK_SECONDS = 3600
# keep in sync with trashops.TRASH_DIR_NAME; importing trashops here
# would drag the trash-run machinery in for one string constant
TRASH_DIR_NAME = '.agents-doctor-trash'

SUMMARY_STATUSES = ('pass', 'fail', 'warn', 'unknown')

# --- helpers ---------------------------------------------------------------


def _make_check(cid, name, status, detail, evidence=()):
    return {'id': cid, 'name': name, 'status': status,
            'detail': detail, 'evidence': list(evidence)}


def _exists(path: Path) -> bool:
    try:
        return path.exists()
    except OSError:
        return False


def _dir_exists(path: Path) -> bool:
    try:
        return path.is_dir()
    except OSError:
        return False


# --- RT-PY: interpreter version -------------------------------------------


def _check_python() -> dict:
    v = sys.version_info
    version = '%d.%d.%d' % (v[0], v[1], v[2])
    headline = sys.version.splitlines()[0] if sys.version else version
    if (v[0], v[1]) >= (3, 10):
        return _make_check(
            'RT-PY', 'Python runtime', 'pass',
            'Python %s meets the 3.10+ requirement' % version,
            [headline, sys.executable or 'interpreter path unknown'])
    return _make_check(
        'RT-PY', 'Python runtime', 'fail',
        'Python %s is below 3.10; the scanner itself requires 3.10+'
        % version,
        [headline])


# --- RT-GIT: git availability ----------------------------------------------


def _check_git() -> dict:
    git = shutil.which('git')
    if git:
        return _make_check('RT-GIT', 'git availability', 'pass',
                           'git found on PATH', [git])
    return _make_check(
        'RT-GIT', 'git availability', 'warn',
        'git not found on PATH; git-based gates degrade to unknown, '
        'not to fail', [])


# --- RT-CLI-<HARNESS>: CLI binary probes -----------------------------------


def _probe_version(binary):
    """Run `<binary> --version`. Returns (ok, detail). Never raises;
    the only command ever spawned by this module."""
    try:
        proc = subprocess.run(
            [binary, '--version'],
            capture_output=True, text=True, errors='replace',
            timeout=VERSION_TIMEOUT_SECONDS, shell=False)
    except subprocess.TimeoutExpired:
        return False, 'timed out after %ds' % VERSION_TIMEOUT_SECONDS
    except OSError as exc:
        return False, 'cannot execute (%s)' % exc
    if proc.returncode != 0:
        return False, 'exited with code %d' % proc.returncode
    lines = (proc.stdout or '').strip().splitlines()
    return True, lines[0].strip() if lines else 'exit 0 (no output)'


def _check_cli(adapter, home_hits, allow_subprocess) -> dict:
    """One RT-CLI check for a harness whose home markers were found."""
    hid = adapter.harness_id
    cid = 'RT-CLI-%s' % hid.upper()
    name = '%s CLI' % adapter.display_name
    evidence = ['home marker: %s' % h for h in home_hits[:3]]
    if hid not in CLI_BINARIES:
        return _make_check(
            cid, name, 'unknown',
            'no CLI binary mapping registered for this harness',
            evidence)
    binary = CLI_BINARIES[hid]
    if binary is None:
        kind = ('an editor plugin' if hid == 'github_copilot'
                else 'a GUI application')
        return _make_check(
            cid, name, 'not_applicable',
            '%s is %s, not a CLI tool; no binary to probe'
            % (adapter.display_name, kind), evidence)
    resolved = shutil.which(binary)
    if not resolved:
        return _make_check(
            cid, name, 'warn',
            'installed state dir present but CLI not on PATH',
            evidence + ['%s not found on PATH' % binary])
    evidence.append(resolved)
    if not allow_subprocess:
        return _make_check(
            cid, name, 'pass',
            'binary present (version check skipped)', evidence)
    ok, detail = _probe_version(resolved)
    if ok:
        return _make_check(cid, name, 'pass', detail, evidence)
    return _make_check(cid, name, 'warn',
                       '%s --version %s' % (binary, detail), evidence)


def _check_cli_harnesses(ctx, allow_subprocess) -> list:
    """RT-CLI checks for every harness with an existing home marker
    (an installation in the user home)."""
    checks = []
    for adapter in iter_adapters():
        try:
            markers = adapter.home_markers(ctx)
        except OSError:
            markers = []
        hits = [p for p in markers if _exists(p)]
        if hits:
            checks.append(_check_cli(adapter, hits, allow_subprocess))
    return checks


# --- RT-MCP-CONFIG: MCP config structure (offline) --------------------------


def _detected_adapters(ctx) -> list:
    """Adapters with at least one existing project marker (the same
    signal detection.py treats as 'detected')."""
    out = []
    for adapter in iter_adapters():
        markers = adapter.project_markers(ctx)
        if any(_exists(ctx.root_path(m)) for m in markers):
            out.append(adapter)
    return out


def _find_mcp_section(data, path):
    """Locate the MCP server map inside a parsed config. Returns
    (section_name, mapping) or None. Structure only -- endpoints are
    never contacted."""
    if path.name in MCP_MAP_FILENAMES:
        return 'top-level server map', data
    for key in MCP_SECTION_KEYS:
        value = data.get(key)
        if isinstance(value, dict):
            # Z Code nests one level deeper: {"mcp": {"servers": {..}}}
            if key == 'mcp' and isinstance(value.get('servers'), dict):
                return 'mcp.servers', value['servers']
            return key, value
    return None


def _parse_mcp_config(path):
    """Validate one MCP config file offline: extension-based parse,
    then the MCP section must be an object. Returns (verdict, detail)
    with verdict in ok | fail | unknown."""
    suffix = path.suffix.lower()
    try:
        raw = path.read_text(encoding='utf-8')
    except OSError as exc:
        return 'fail', 'unreadable: %s' % exc
    except UnicodeDecodeError:
        return 'fail', 'not valid UTF-8'
    if suffix == '.json':
        try:
            data = json.loads(raw)
        except ValueError as exc:
            return 'fail', 'invalid JSON: %s' % exc
    elif suffix == '.toml':
        if tomllib is None:
            return 'unknown', (
                'TOML support needs Python 3.11+ (tomllib); running '
                '%d.%d' % sys.version_info[:2])
        try:
            data = tomllib.loads(raw)
        except ValueError as exc:    # tomllib.TOMLDecodeError
            return 'fail', 'invalid TOML: %s' % exc
    else:
        return 'unknown', 'unsupported extension %r (expected .json ' \
                         'or .toml)' % suffix
    if not isinstance(data, dict):
        return 'fail', 'top-level is %s, expected an object' \
            % type(data).__name__
    section = _find_mcp_section(data, path)
    if section is None:
        return 'ok', 'parses; no MCP section (MCP likely not configured)'
    sec_name, servers = section
    return 'ok', "'%s' section present (%d entries)" % (sec_name,
                                                        len(servers))


def _check_mcp_config(ctx) -> dict:
    detected = _detected_adapters(ctx)
    if not detected:
        return _make_check(
            'RT-MCP-CONFIG', 'MCP config structure', 'not_applicable',
            'no harnesses detected at project level; nothing to check',
            [])
    evidence = []
    verdicts = []
    for adapter in detected:
        try:
            files = adapter.mcp_config_files(ctx)
        except OSError:
            files = []
        for cfg in files:
            verdict, detail = _parse_mcp_config(cfg)
            verdicts.append(verdict)
            evidence.append('%s: %s: %s'
                            % (adapter.harness_id, cfg, detail))
    if not verdicts:
        return _make_check(
            'RT-MCP-CONFIG', 'MCP config structure', 'pass',
            'no MCP config files for detected harnesses (%s)'
            % ', '.join(a.harness_id for a in detected), evidence)
    if 'fail' in verdicts:
        return _make_check(
            'RT-MCP-CONFIG', 'MCP config structure', 'fail',
            '%d of %d MCP config file(s) invalid'
            % (verdicts.count('fail'), len(verdicts)), evidence)
    if 'unknown' in verdicts:
        return _make_check(
            'RT-MCP-CONFIG', 'MCP config structure', 'unknown',
            '%d of %d MCP config file(s) could not be verified'
            % (verdicts.count('unknown'), len(verdicts)), evidence)
    return _make_check(
        'RT-MCP-CONFIG', 'MCP config structure', 'pass',
        '%d MCP config file(s) parse and carry a valid structure'
        % len(verdicts), evidence)


# --- RT-PATH: PATH sanity ---------------------------------------------------


def _check_path() -> dict:
    raw = os.environ.get('PATH', '')
    if not raw.strip():
        return _make_check(
            'RT-PATH', 'PATH environment', 'fail',
            'PATH environment variable is empty or unset', [])
    entries = [e for e in raw.split(os.pathsep) if e.strip()]
    evidence = ['%d non-empty PATH entries' % len(entries)]
    status, detail = 'pass', 'PATH ok (%d entries)' % len(entries)
    if os.pathsep not in raw:
        status = 'warn'
        detail = ("PATH has a single entry (no '%s' separators); "
                  'unusual but not fatal' % os.pathsep)
    git = shutil.which('git')
    if git:
        git_dir = Path(git).parent
        if _dir_exists(git_dir):
            evidence.append('git directory: %s' % git_dir)
        else:
            status = 'warn'
            detail = ('git resolves to %s but its directory does not '
                      'exist' % git)
            evidence.append('missing git directory: %s' % git_dir)
    else:
        evidence.append('git not on PATH (see RT-GIT)')
    return _make_check('RT-PATH', 'PATH environment', status, detail,
                       evidence)


# --- RT-LOCK-DIR: stale trash locks -----------------------------------------


def _check_lock_dir(ctx) -> dict:
    trash = ctx.root_path(TRASH_DIR_NAME)
    if not _exists(trash):
        return _make_check(
            'RT-LOCK-DIR', 'trash lock directory', 'pass',
            'no %s directory in the workspace' % TRASH_DIR_NAME, [])
    try:
        locks = sorted(trash.rglob('*.lock'))
    except OSError as exc:
        return _make_check(
            'RT-LOCK-DIR', 'trash lock directory', 'unknown',
            'cannot scan %s: %s' % (trash, exc), [str(trash)])
    if not locks:
        return _make_check(
            'RT-LOCK-DIR', 'trash lock directory', 'pass',
            '%s present, no .lock files' % TRASH_DIR_NAME, [str(trash)])
    now = time.time()
    stale = []
    for lock in locks:
        try:
            age = now - lock.stat().st_mtime
        except OSError as exc:
            return _make_check(
                'RT-LOCK-DIR', 'trash lock directory', 'unknown',
                'cannot stat %s: %s' % (lock, exc), [str(lock)])
        if age > STALE_LOCK_SECONDS:
            stale.append('%s (idle for %.0f minutes)'
                         % (lock.name, age / 60.0))
    if stale:
        return _make_check(
            'RT-LOCK-DIR', 'trash lock directory', 'warn',
            'stale lock file(s) older than %d minutes: %s'
            % (STALE_LOCK_SECONDS // 60, '; '.join(stale)),
            [str(l) for l in locks])
    return _make_check(
        'RT-LOCK-DIR', 'trash lock directory', 'pass',
        '%d lock file(s), all younger than %d minutes'
        % (len(locks), STALE_LOCK_SECONDS // 60),
        [str(l) for l in locks])


# --- public API --------------------------------------------------------------


def check_environment(root, home=None, *, allow_subprocess=True) -> dict:
    """Run every runtime health check.

    root: workspace root (str or Path).
    home: user home override (str or Path); defaults to Path.home().
    allow_subprocess: False forbids even the `<bin> --version` probes;
        binaries are then only checked for presence on PATH.

    Returns {'checks': [{id, name, status, detail, evidence}, ...],
             'summary': {pass, fail, warn, unknown}}.
    """
    root_path = Path(root).resolve()
    home_path = Path(home).resolve() if home is not None else Path.home()
    ctx = HarnessContext(root=root_path, home=home_path)
    checks = [_check_python(), _check_git()]
    checks.extend(_check_cli_harnesses(ctx, allow_subprocess))
    checks.append(_check_mcp_config(ctx))
    checks.append(_check_path())
    checks.append(_check_lock_dir(ctx))
    summary = {s: 0 for s in SUMMARY_STATUSES}
    for check in checks:
        if check['status'] in summary:
            summary[check['status']] += 1
    return {'checks': checks, 'summary': summary}


def _main(argv=None) -> int:
    import argparse
    parser = argparse.ArgumentParser(
        description='Agent runtime environment health check '
                    '(opt-in, offline, read-only)')
    parser.add_argument('root', nargs='?', default='.',
                        help='workspace root (default: current directory)')
    parser.add_argument('--home', default=None,
                        help='override the user home directory')
    parser.add_argument('--no-subprocess', action='store_true',
                        help='skip `<bin> --version` probes entirely')
    args = parser.parse_args(argv)
    report = check_environment(args.root, args.home,
                               allow_subprocess=not args.no_subprocess)
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 1 if report['summary']['fail'] else 0


if __name__ == '__main__':
    raise SystemExit(_main())
