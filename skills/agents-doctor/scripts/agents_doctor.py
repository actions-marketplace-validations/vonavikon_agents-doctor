#!/usr/bin/env python3
"""agents-doctor command line (production-readiness stage 4).

Single entry point on top of the scanner: focused audits, baseline
comparison, finding lookup and guarded fixes. The scanner runs
in-process (audit_scan.scan); nothing is re-shelled out to python, and
the only subprocesses are the read-only git calls the scanner itself
makes.

Subcommands:
  audit <root> [options]         scan a workspace, write scan.json
  compare <new.json> <old.json>  fingerprint diff: NEW/RESOLVED/PERSISTING/CHANGED
  explain <scan.json> <fid>      print one typed finding in full
  fix <scan.json> <fid>          plan a fix; with --apply run it after
                                 an interactive confirmation (delegates
                                 to remediate.py)

Exit codes: 0 ok (compare always exits 0), 1 usage/IO error,
2 explain: finding not found, 3 fix: no supported automatic fix.
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import audit_scan  # noqa: E402  (in-process scanner)
import remediate   # noqa: E402  (fix engine + fingerprint diff)

PROG = 'agents_doctor'

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

# focus name -> gate ids kept in the report (commands/agents-doctor.md
# is canonical); every other gate (rep['gates']) and finding
# (rep['findings_detailed']) is dropped before the JSON is written.
# Findings are filtered by their 'gate' field only: category lists used
# to ride along here and drifted from the gate mapping. Raw fact
# sections (secrets, junk, top_level, ...) stay complete either way.
FOCUS_SPECS = {
    'security': {'gates': ['G6', 'G7']},
    'structure': {'gates': ['G1', 'G4', 'G9']},
    'agents': {'gates': ['G2', 'G3', 'G5', 'G8']},
}


def _err(msg):
    print('%s: %s' % (PROG, msg), file=sys.stderr)
    return 1


def _load_json(path):
    try:
        return json.loads(Path(path).read_text(encoding='utf-8'))
    except (OSError, ValueError) as exc:
        print('%s: cannot read %s: %s' % (PROG, path, exc), file=sys.stderr)
        return None


def apply_focus(rep, focus):
    """Drop the gates and findings outside the focus, in place.

    Gates are kept by 'gid', findings by their 'gate' field; the gate
    list is the single source of truth, no category filtering.
    """
    spec = FOCUS_SPECS[focus]
    rep['gates'] = [g for g in rep.get('gates') or []
                    if g.get('gid') in spec['gates']]
    rep['findings_detailed'] = [f for f in rep.get('findings_detailed') or []
                                if f.get('gate') in spec['gates']]
    rep['focus'] = focus
    return rep


# --- subcommands ---------------------------------------------------------------

def cmd_audit(a):
    root = Path(a.root).resolve()
    home = Path(a.home).resolve()
    if not root.is_dir():
        return _err('not a directory: %s' % root)
    rep = audit_scan.scan(root, home, a.deep)
    if a.focus:
        apply_focus(rep, a.focus)
    if a.baseline:
        old = _load_baseline(a.baseline)
        if old is not None:
            old_fps = {f['fp'] for f in old.get('findings', [])}
            new_fps = {f['fp'] for f in rep.get('findings', [])}
            rep['diff'] = {
                'new': [f for f in rep['findings'] if f['fp'] not in old_fps],
                'resolved': [f for f in old.get('findings', [])
                             if f['fp'] not in new_fps]}
            print('baseline: %d new, %d resolved'
                  % (len(rep['diff']['new']), len(rep['diff']['resolved'])))
        else:
            print('warning: could not read baseline %s, diff skipped'
                  % a.baseline, file=sys.stderr)
    try:
        Path(a.out).write_text(
            json.dumps(rep, ensure_ascii=False, indent=2), encoding='utf-8')
    except OSError as exc:
        return _err('cannot write %s: %s' % (a.out, exc))
    if a.report:
        rc = _write_report(rep, a.report)
        if rc:
            return rc
    st = lambda s: sum(1 for g in rep['gates'] if g['status'] == s)
    print('gates: fail %d, warn %d, pass %d, unknown %d, n/a %d'
          % (st('fail'), st('warn'), st('pass'), st('unknown'),
             st('not_applicable')))
    if a.runtime:
        try:
            import runtime_health
            rh = runtime_health.check_environment(
                root, home, allow_subprocess=True)
        except Exception as exc:
            print('warning: runtime checks failed: %s' % exc,
                  file=sys.stderr)
            rh = None
        if rh is not None:
            # the runtime section must ride in the same JSON file
            try:
                on_disk = json.loads(Path(a.out).read_text(
                    encoding='utf-8'))
                on_disk['runtime'] = rh
                Path(a.out).write_text(
                    json.dumps(on_disk, ensure_ascii=False, indent=2),
                    encoding='utf-8')
            except (OSError, ValueError):
                pass
            summ = rh.get('summary', {})
            print('runtime: pass %d, warn %d, fail %d, unknown %d'
                  % (summ.get('pass', 0), summ.get('warn', 0),
                     summ.get('fail', 0), summ.get('unknown', 0)))
            for c in rh.get('checks', []):
                if c.get('status') in ('fail', 'warn'):
                    print('  [%s] %s: %s' % (c.get('status'),
                                             c.get('id'),
                                             c.get('detail', '')[:120]))
    line = ('audit: %d gates, %d findings -> %s'
            % (len(rep['gates']), len(rep['findings_detailed']), a.out))
    if a.focus:
        line += ' (focus: %s)' % a.focus
    print(line)
    return 0


def _load_baseline(path):
    try:
        return json.loads(Path(path).read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return None


def cmd_sarif(a):
    try:
        rep = json.loads(Path(a.scan).read_text(encoding='utf-8'))
    except (OSError, ValueError) as exc:
        return _err('cannot read %s: %s' % (a.scan, exc))
    try:
        import sarif as sarif_mod
    except ImportError:
        return _err('sarif.py not found next to agents_doctor.py')
    data = sarif_mod.to_sarif(rep)
    try:
        Path(a.out).write_text(
            json.dumps(data, indent=2), encoding='utf-8')
    except OSError as exc:
        return _err('cannot write %s: %s' % (a.out, exc))
    rules = len(data.get('runs', [{}])[0].get('tool', {})
                .get('driver', {}).get('rules', []))
    results = len(data.get('runs', [{}])[0].get('results', []))
    print('sarif: %d rules, %d results -> %s' % (rules, results, a.out))
    return 0


def _write_report(rep, report_path):
    """--report branch: report_generator.py is optional and may not be
    installed yet; a missing or incompatible one is a clean error, not
    a traceback."""
    try:
        import report_generator
    except ImportError:
        print('%s: report generator unavailable' % PROG, file=sys.stderr)
        return 1
    generate = getattr(report_generator, 'generate_report', None) \
        or getattr(report_generator, 'generate_markdown', None)
    if not callable(generate):
        print('%s: report generator unavailable' % PROG, file=sys.stderr)
        return 1
    try:
        markdown = generate(rep)
        Path(report_path).write_text(markdown, encoding='utf-8')
    except (OSError, TypeError, ValueError) as exc:
        return _err('report generation failed: %s' % exc)
    print('report: %s' % report_path)
    return 0


def cmd_compare(a):
    new_rep = _load_json(a.new)
    old_rep = _load_json(a.old)
    if new_rep is None or old_rep is None:
        return 1
    diff = remediate.fingerprint_diff(old_rep.get('findings'),
                                      new_rep.get('findings'))
    for name in ('new', 'resolved', 'persisting', 'changed'):
        items = diff[name]
        print('%s (%d)' % (name.upper(), len(items)))
        for f in items[:10]:  # caps double as the top-10 new paths
            print('  [%s] %s' % (f.get('section'), f.get('path')))
        if len(items) > 10:
            print('  ... and %d more' % (len(items) - 10))
    print('compare: %d new, %d resolved, %d persisting, %d changed'
          % tuple(len(diff[k]) for k in ('new', 'resolved', 'persisting', 'changed')))
    return 0


def _print_finding(f):
    print('%s  gate %s / %s  [%s/%s]  confidence %s'
          % (f.get('fid'), f.get('gate'), f.get('category'),
             f.get('severity'), f.get('status'), f.get('confidence')))
    print('title: %s' % f.get('title'))
    print('description: %s' % f.get('description'))
    print('evidence:')
    print(json.dumps(f.get('evidence'), ensure_ascii=False, indent=2))
    print('recommendation: %s' % f.get('recommendation'))
    print('autofix available: %s' % ('yes' if f.get('autofix_available') else 'no'))


def cmd_explain(a):
    rep = _load_json(a.scan)
    if rep is None:
        return 1
    for f in rep.get('findings_detailed') or []:
        if f.get('fid') == a.fid:
            _print_finding(f)
            print('explain: printed %s from %s' % (a.fid, a.scan))
            return 0
    print('%s: finding not found: %s' % (PROG, a.fid), file=sys.stderr)
    return 2


def cmd_fix(a):
    rep = _load_json(a.scan)
    if rep is None:
        return 1
    root = rep.get('root')
    if not root:
        return _err('scan has no root; re-run the audit')
    try:
        steps = remediate.plan(rep, a.fid)
    except remediate.UnsupportedError as exc:
        print('%s: %s' % (PROG, exc), file=sys.stderr)
        return 3
    except ValueError as exc:
        return _err(str(exc))
    if not a.apply:
        remediate.print_plan(a.fid, steps)
        print('fix %s: %d step(s) planned, nothing changed (dry run; re-run '
              'with --apply and confirm to execute)' % (a.fid, len(steps)))
        return 0
    try:
        report = remediate.apply_plan(steps, root)  # asks for confirmation
    except ValueError as exc:
        return _err(str(exc))
    if report['declined']:
        print('fix %s: declined, nothing executed' % a.fid)
        return 0
    print('fix %s: executed %d, skipped %d, failed %d'
          % (a.fid, len(report['executed']), len(report['skipped']),
             len(report['failed'])))
    for fail in report['failed']:
        print('  failed [%s] %s: %s'
              % (fail.get('action'), fail.get('target'), fail.get('error')),
              file=sys.stderr)
    return 1 if report['failed'] else 0


def cmd_simulate(a):
    root = Path(a.root).resolve()
    if not root.is_dir():
        return _err('not a directory: %s' % root)
    target = None
    if a.target:
        target = Path(a.target)
        if not target.is_absolute():
            target = root / target
        target = target.resolve()
        if root not in target.parents and target != root:
            return _err('target outside the workspace root: %s' % target)
    from harness import HarnessContext
    from instructions import simulate_loading
    from instructions.simulation import format_simulation_text
    ctx = HarnessContext(root=root, home=Path(a.home).resolve())
    ids = [a.harness] if a.harness else None
    rep = simulate_loading(ctx, target, ids)
    print(format_simulation_text(rep))
    return 0


def cmd_ui(a):
    try:
        import ui.server as ui_server
    except ImportError:
        return _err('ui/server.py not found next to agents_doctor.py')
    argv = ['--port', str(a.port)]
    if a.scan:
        argv += ['--scan', a.scan]
    if a.root:
        argv += ['--root', a.root]
    if a.home:
        argv += ['--home', a.home]
    if a.baseline:
        argv += ['--baseline', a.baseline]
    if a.no_open:
        argv += ['--no-open']
    return ui_server.main(argv)


# --- parser ----------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        prog='agents_doctor.py',
        description='agents-doctor: scan an agent workspace, compare audits, '
                    'explain findings and plan guarded fixes.',
        epilog='Fixes are a dry run by default: "fix" only prints a plan. '
               '--apply still asks for an interactive confirmation and every '
               'step stays inside the audited root (see remediate.py).')
    sub = p.add_subparsers(dest='command', metavar='<command>', required=True)

    pa = sub.add_parser(
        'audit', help='scan a workspace and write scan.json '
                      '(runs audit_scan.scan in-process)')
    pa.add_argument('root', help='workspace root directory')
    pa.add_argument('--home', default=str(Path.home()),
                    help='home directory with harnesses and skills '
                         '(default: this user home)')
    pa.add_argument('--deep', action='store_true',
                    help='also scan git history for secrets (slower)')
    pa.add_argument('--focus', choices=sorted(FOCUS_SPECS), default=None,
                    help='keep only part of the report: security=G6,G7; '
                         'structure=G1,G4,G9; agents=G2,G3,G5,G8')
    pa.add_argument('--baseline', default=None, metavar='PREV.json',
                    help='previous scan.json: adds a diff section '
                         '(new and resolved findings)')
    pa.add_argument('--out', default='scan.json',
                    help='where to write the JSON report (default: scan.json)')
    pa.add_argument('--report', default=None, metavar='AUDIT.md',
                    help='also write a markdown report '
                         '(needs report_generator.py)')
    pa.add_argument('--runtime', action='store_true',
                    help='opt-in runtime checks after the scan: CLI '
                         'binaries of detected harnesses (--version, '
                         'timeout-bounded), git/python presence, static '
                         'MCP config validation. No network requests.')
    pa.set_defaults(func=cmd_audit)

    ps = sub.add_parser(
        'sarif', help='convert scan.json to SARIF 2.1.0 for CI')
    ps.add_argument('scan', help='scan.json from an audit')
    ps.add_argument('--out', default='report.sarif',
                    help='output SARIF file (default: report.sarif)')
    ps.set_defaults(func=cmd_sarif)

    pc = sub.add_parser(
        'compare', help='diff two scan.json files by finding fingerprints')
    pc.add_argument('new', help='newer scan.json')
    pc.add_argument('old', help='older scan.json (baseline)')
    pc.set_defaults(func=cmd_compare)

    pe = sub.add_parser('explain', help='print one typed finding in full')
    pe.add_argument('scan', help='scan.json from an audit')
    pe.add_argument('fid', help='finding id, e.g. SEC-001')
    pe.set_defaults(func=cmd_explain)

    pf = sub.add_parser(
        'fix', help='plan a guarded fix for one finding '
                    '(dry run unless --apply is given)')
    pf.add_argument('scan', help='scan.json from an audit')
    pf.add_argument('fid', help='finding id to fix, e.g. GIT-002')
    pf.add_argument('--apply', action='store_true',
                    help='execute the plan after an interactive confirmation '
                         '(default: print the plan only)')
    pf.set_defaults(func=cmd_fix)

    psi = sub.add_parser(
        'simulate', help='show which instructions load for a directory '
                         '(model, not runtime-verified)')
    psi.add_argument('root', help='workspace root directory')
    psi.add_argument('--target', default=None, metavar='DIR',
                     help='target directory inside the root (default: root)')
    psi.add_argument('--harness', default=None, metavar='ID',
                     help='restrict to one adapter id '
                          '(e.g. claude_code; default: all detected)')
    psi.add_argument('--home', default=str(Path.home()),
                     help='home directory (default: this user home)')
    psi.set_defaults(func=cmd_simulate)

    pui = sub.add_parser(
        'ui', help='open the local web UI (localhost only)')
    pui.add_argument('root', nargs='?', default=None,
                     help='workspace root (fresh scan when no --scan)')
    pui.add_argument('--scan', default=None, metavar='scan.json',
                     help='serve an existing scan.json instead of scanning')
    pui.add_argument('--home', default=None)
    pui.add_argument('--baseline', default=None, metavar='OLD.json',
                     help='older scan.json: enables the Compare tab')
    pui.add_argument('--port', type=int, default=8765)
    pui.add_argument('--no-open', action='store_true',
                     help='do not open the browser automatically')
    pui.set_defaults(func=cmd_ui)
    return p


def main(argv=None):
    a = build_parser().parse_args(argv)
    return a.func(a)


if __name__ == '__main__':
    sys.exit(main())
