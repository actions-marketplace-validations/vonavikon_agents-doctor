#!/usr/bin/env python3
"""Render a scan.json report as the human-readable AUDIT markdown.

    python skills/workspace-audit/scripts/report_generator.py <scan.json> [--out AUDIT.md]

Without --out the markdown goes to stdout; with --out it is written to the
file. The generator is pure formatting: it reads the report dict, never the
filesystem, and never expands redacted secrets (masks stay masks).
Python 3.9+, stdlib only.
"""
import argparse
import json
import sys
from pathlib import Path

SEVERITY_RANK = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
OPEN_STATUSES = ('fail', 'warn', 'unknown')

EVIDENCE_TRUNC = 100
MAX_ACTIONS = 8
MAX_BASELINE_PATHS = 10
FOOTER = ('Read-only audit: nothing was modified. '
          'Rerun with --baseline to track drift.')


def overall_status(rep):
    """One word for the whole scan.

    FAIL beats everything; a warn or unknown gate downgrades to
    NEEDS ATTENTION; PASS requires every gate to pass or be not
    applicable. An open critical finding forces FAIL even if some
    future gate model let it slip past the gate statuses.
    """
    statuses = [g.get('status') for g in rep.get('gates', [])]
    if 'fail' in statuses:
        return 'FAIL'
    critical_open = any(f.get('severity') == 'critical'
                        and f.get('status') in OPEN_STATUSES
                        for f in rep.get('findings_detailed', []))
    if critical_open:
        return 'FAIL'
    if 'warn' in statuses or 'unknown' in statuses:
        return 'NEEDS ATTENTION'
    return 'PASS'


def _gate_tally(rep):
    counts = {}
    for g in rep.get('gates', []):
        s = g.get('status', 'unknown')
        counts[s] = counts.get(s, 0) + 1
    return counts


def _severity_counts(rep):
    counts = {}
    for f in rep.get('findings_detailed', []):
        sev = f.get('severity', 'info')
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _first_string(value):
    """First evidence entry as text: strings pass through, dicts yield
    their first string field (file, path, location, ... in dict order)."""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        for v in value.values():
            if isinstance(v, str):
                return v
    return ''


def _evidence_line(gate):
    ev = gate.get('evidence') or []
    return _first_string(ev[0]) if ev else ''


def _finding_location(finding):
    """file:line, else path, else the first string field of the first
    evidence entry; empty when there is no evidence."""
    ev = finding.get('evidence') or []
    if not ev:
        return ''
    first = ev[0]
    if isinstance(first, dict):
        if isinstance(first.get('file'), str):
            loc = first['file']
            if first.get('line') is not None:
                loc += ':' + str(first['line'])
            return loc
        if isinstance(first.get('path'), str):
            return first['path']
    return _first_string(first)


def _cell(text, limit=None):
    """Make a string safe for one markdown table cell: truncate the raw
    text first, then escape pipes and flatten newlines."""
    s = str(text)
    if limit is not None and len(s) > limit:
        s = s[:limit].rstrip() + '...'
    return s.replace('|', '\\|').replace('\n', ' ')


def _executive_summary(rep, status, sev_counts, tally):
    total = sum(sev_counts.values())
    sev_line = ', '.join(
        f"{sev_counts.get(s, 0)} {s}"
        for s in ('critical', 'high', 'medium', 'low', 'info'))
    findings = rep.get('findings_detailed', [])
    top = sorted((f for f in findings if f.get('severity') == 'critical'),
                 key=lambda f: f.get('fid', ''))
    if not top:
        top = sorted((f for f in findings if f.get('severity') == 'high'),
                     key=lambda f: f.get('fid', ''))
    lines = [
        f"Overall status: {status}.",
        f"The scan produced {total} findings ({sev_line}).",
    ]
    if top:
        f = top[0]
        lines.append(f"Most important finding: {f.get('fid')} - "
                     f"{f.get('title', '')}.")
    lines.append(
        "Gates: {fail} fail, {warn} warn, {pass_} pass, {unk} unknown.".format(
            fail=tally.get('fail', 0), warn=tally.get('warn', 0),
            pass_=tally.get('pass', 0), unk=tally.get('unknown', 0)))
    lines.append('Secret values are redacted in this report; '
                 'only masks and fingerprints are recorded.')
    return lines


def _health_section(rep, status):
    lines = [f"Status: {status}."]
    for g in rep.get('gates', []):
        if g.get('status') in ('fail', 'warn'):
            name = g.get('name') or g.get('gid', '?')
            lines.append(f"- {name} ({g['status']}): {_evidence_line(g)}")
    return lines


def _gate_table(rep):
    lines = ['| # | Gate | Status | Key evidence |',
             '| --- | --- | --- | --- |']
    for g in rep.get('gates', []):
        gid = g.get('gid', '?')
        name = g.get('name', '')
        lines.append('| {} | {} | {} | `{}` |'.format(
            _cell(gid), _cell(name), _cell(g.get('status', 'unknown')),
            _cell(_evidence_line(g), EVIDENCE_TRUNC)))
    return lines


def _critical_table(rep):
    rows = sorted(
        (f for f in rep.get('findings_detailed', [])
         if f.get('severity') in ('critical', 'high')),
        key=lambda f: f.get('fid', ''))
    lines = ['| fid | severity | title | location |',
             '| --- | --- | --- | --- |']
    for f in rows:
        lines.append('| {} | {} | {} | {} |'.format(
            _cell(f.get('fid', '')), _cell(f.get('severity', '')),
            _cell(f.get('title', '')), _cell(_finding_location(f))))
    return lines


def _all_findings_table(rep):
    rows = sorted(rep.get('findings_detailed', []),
                  key=lambda f: (SEVERITY_RANK.get(f.get('severity'), 99),
                                 f.get('fid', '')))
    lines = ['| fid | gate | severity | status | title |',
             '| --- | --- | --- | --- | --- |']
    for f in rows:
        lines.append('| {} | {} | {} | {} | {} |'.format(
            _cell(f.get('fid', '')), _cell(f.get('gate', '')),
            _cell(f.get('severity', '')), _cell(f.get('status', '')),
            _cell(f.get('title', ''))))
    return lines


def _baseline_section(rep):
    diff = rep.get('diff')
    if not diff:
        return None
    new = diff.get('new', [])
    resolved = diff.get('resolved', [])
    total_fps = len(rep.get('findings', []))
    persisting = max(0, total_fps - len(new) - len(resolved))
    changed = len(new) + len(resolved)
    lines = [
        f"NEW FINDINGS: {len(new)}",
        f"RESOLVED FINDINGS: {len(resolved)}",
        f"PERSISTING: {persisting}",
        f"CHANGED: {changed}",
        '',
    ]
    if new:
        lines.append(f"New since the baseline (first {MAX_BASELINE_PATHS}):")
        for fp in new[:MAX_BASELINE_PATHS]:
            path = fp.get('path', '') if isinstance(fp, dict) else str(fp)
            lines.append(f"- {path}")
    return lines


def _actions_section(rep):
    actions = []
    seen = set()

    def add(source, text):
        if not text or len(actions) >= MAX_ACTIONS:
            return
        if text in seen:
            return
        seen.add(text)
        actions.append(f"{source}: {text}")

    findings = sorted(
        (f for f in rep.get('findings_detailed', [])
         if f.get('severity') in ('critical', 'high')),
        key=lambda f: (SEVERITY_RANK.get(f.get('severity'), 99),
                       f.get('fid', '')))
    for f in findings:
        add(f"[{f.get('fid', '?')}]", f.get('recommendation', ''))
    for g in rep.get('gates', []):
        if g.get('status') == 'fail':
            add(f"[{g.get('gid', '?')}]", g.get('recommendation', ''))
    return [f"{i}. {a}" for i, a in enumerate(actions, 1)]


def generate_markdown(rep):
    """Render the report dict as the AUDIT markdown document."""
    status = overall_status(rep)
    tally = _gate_tally(rep)
    sev_counts = _severity_counts(rep)
    stats = rep.get('stats', {})

    out = ['# Workspace Audit', '']
    out.append('Generated {} | schema {} | rules {} | {} files scanned '
               '| {} s'.format(
                   rep.get('generated_at', 'unknown'),
                   rep.get('schema_version', '?'),
                   rep.get('rules_version', '?'),
                   stats.get('total_files', 0),
                   stats.get('duration_sec', 0)))
    out.append('')

    out.append('## Executive Summary')
    out.append('')
    out.extend(_executive_summary(rep, status, sev_counts, tally))
    out.append('')

    out.append('## Overall Workspace Health')
    out.append('')
    out.extend(_health_section(rep, status))
    out.append('')

    out.append('## Gate Results')
    out.append('')
    out.extend(_gate_table(rep))
    out.append('')

    out.append('## Critical Findings')
    out.append('')
    out.extend(_critical_table(rep))
    out.append('')

    out.append('## All Findings')
    out.append('')
    out.extend(_all_findings_table(rep))
    out.append('')

    baseline = _baseline_section(rep)
    if baseline is not None:
        out.append('## Baseline Comparison')
        out.append('')
        out.extend(baseline)
        out.append('')

    out.append('## Recommended Actions')
    out.append('')
    actions = _actions_section(rep)
    out.extend(actions if actions else ['None.'])
    out.append('')
    out.append(FOOTER)
    out.append('')
    return '\n'.join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description='render scan.json as the AUDIT markdown report')
    ap.add_argument('scan', help='scan.json produced by audit_scan.py')
    ap.add_argument('--out', default=None,
                    help='write the markdown here instead of stdout')
    a = ap.parse_args(argv)
    try:
        rep = json.loads(Path(a.scan).read_text(encoding='utf-8'))
    except (OSError, ValueError) as e:
        sys.exit(f'cannot read report: {e}')
    md = generate_markdown(rep)
    if a.out:
        Path(a.out).write_text(md, encoding='utf-8')
        print(f'wrote {a.out}')
    else:
        print(md, end='')
    return 0


if __name__ == '__main__':
    sys.exit(main())
