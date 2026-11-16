#!/usr/bin/env python3
"""workspace-audit command line (production-readiness stage 4).

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

PROG = 'workspace_audit'

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

# focus name -> gates and finding categories kept in the report; every
# other gate (rep['gates']) and finding (rep['findings_detailed']) is
# dropped before the JSON is written. Raw fact sections (secrets, junk,
# top_level, ...) stay complete either way.
FOCUS_SPECS = {
    'security': {'gates': ('G6', 'G7'),
                 'categories': ('secrets', 'git')},
    'structure': {'gates': ('G1', 'G2', 'G4'),
                  'categories': ('dirs', 'config')},
    'agents': {'gates': ('G3', 'G5', 'G8'),
               'categories': ('rules', 'skills', 'governance')},
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
    """Drop the gates and findings outside the focus, in place."""
    spec = FOCUS_SPECS[focus]
    rep['gates'] = [g for g in rep.get('gates') or []
                    if g.get('gid') in spec['gates']]
    rep['findings_detailed'] = [f for f in rep.get('findings_detailed') or []
                                if f.get('category') in spec['categories']]
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
    line = ('audit: %d gates, %d findings -> %s'
            % (len(rep['gates']), len(rep['findings_detailed']), a.out))
    if a.focus:
        line += ' (focus: %s)' % a.focus
    print(line)
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


# --- parser ----------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        prog='workspace_audit.py',
        description='workspace-audit: scan an agent workspace, compare audits, '
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
                    help='keep only part of the report: security=G6,G7 + '
                         'secrets,git; structure=G1,G2,G4 + dirs,config; '
                         'agents=G3,G5,G8 + rules,skills,governance')
    pa.add_argument('--out', default='scan.json',
                    help='where to write the JSON report (default: scan.json)')
    pa.add_argument('--report', default=None, metavar='AUDIT.md',
                    help='also write a markdown report '
                         '(needs report_generator.py)')
    pa.set_defaults(func=cmd_audit)

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
    return p


def main(argv=None):
    a = build_parser().parse_args(argv)
    return a.func(a)


if __name__ == '__main__':
    sys.exit(main())
