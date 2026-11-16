#!/usr/bin/env python3
"""QA evaluation for agents-doctor.

Method: programmatic fact checks. Expectations (scenarios/*/expected.json)
are locked before the run; the runner builds each fixture, runs the
deterministic scanner and compares the actual JSON to the expectations.
The LLM layer of the skill is not covered by this evaluation.
Asymmetry: FAIL proves a defect, PASS only means "not refuted in this run".
"""
import json
import os
import shutil
import stat
import subprocess
import sys
from datetime import date
from pathlib import Path

QA = Path(__file__).parent
SCANNER = QA.parent / 'skills' / 'agents-doctor' / 'scripts' / 'audit_scan.py'


def rm_force(p):
    def _onexc(func, path, _exc):
        os.chmod(path, stat.S_IWRITE)
        func(path)
    shutil.rmtree(p, onexc=_onexc)


def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True,
                       encoding='utf-8', errors='replace')
    if r.returncode != 0:
        print('!!! ' + ' '.join(str(c) for c in cmd))
        print(r.stdout)
        print(r.stderr)
    return r


def norm(p):
    return str(p).replace('\\', '/')


LABELS = {'secrets': 'secrets in files', 'junk_files': 'junk files',
          'junk_dirs': 'junk dirs', 'empty_dirs': 'empty folders',
          'duplicates': 'duplicate groups', 'large_files': 'large files',
          'context_drift': 'twin-drift pairs', 'dup_checkouts': 'duplicate checkouts'}


def eval_scenario(sc_dir):
    name = sc_dir.name
    run_dir = sc_dir / 'run'
    if run_dir.exists():
        rm_force(run_dir)
    r = run([sys.executable, str(sc_dir / 'setup.py')])
    if r.returncode != 0:
        return name, [], 'setup failed'
    out = run_dir / 'scan.json'
    r = run([sys.executable, str(SCANNER),
             str(run_dir / 'workspace'), '--home', str(run_dir / 'home'),
             '--out', str(out)])
    if r.returncode != 0:
        return name, [], 'scanner failed'
    rep = json.loads(out.read_text(encoding='utf-8'))
    exp = json.loads((sc_dir / 'expected.json').read_text(encoding='utf-8'))

    rows = []

    def ok(label, passed, detail=''):
        rows.append((label, 'PASS' if passed else 'FAIL', detail))

    gmap = {str(g['n']): g['status'] for g in rep['gates']}
    for n, want in sorted(exp.get('gates', {}).items()):
        ok(f'gate {n} = {want}', gmap.get(n) == want, f'actual {gmap.get(n)}')

    counts = {'secrets': len(rep['secrets']),
              'junk_files': len(rep['junk']['files']),
              'junk_dirs': len(rep['junk']['dirs']),
              'empty_dirs': len(rep['junk']['empty_dirs']),
              'duplicates': len(rep['duplicates']),
              'large_files': len(rep['large_files']),
              'context_drift': len(rep['context_drift']),
              'dup_checkouts': len(rep['dup_checkouts'])}
    for k, want in sorted(exp.get('counts', {}).items()):
        ok(f'{LABELS[k]} = {want}', counts.get(k) == want,
           f'actual {counts.get(k)}')

    if 'tracked_secrets_min' in exp:
        tracked = sum(len((t.get('extra') or {}).get('tracked_secrets', []))
                      for t in rep['top_level'])
        ok(f"tracked secrets >= {exp['tracked_secrets_min']}",
           tracked >= exp['tracked_secrets_min'], f'actual {tracked}')

    if 'critical_findings_min' in exp:
        crit = sum(1 for f in rep.get('findings_detailed', [])
                   if f.get('severity') == 'critical')
        ok(f"critical findings >= {exp['critical_findings_min']}",
           crit >= exp['critical_findings_min'], f'actual {crit}')

    if exp.get('findings_schema'):
        fnd = rep.get('findings_detailed', [])
        sev = {'critical', 'high', 'medium', 'low', 'info'}
        sts = {'pass', 'fail', 'warn', 'unknown', 'not_applicable'}
        problems = []
        fids = [f.get('fid') for f in fnd]
        if len(set(fids)) != len(fids):
            problems.append('duplicate fids')
        for f in fnd:
            if f.get('severity') not in sev:
                problems.append('bad severity: %s' % f.get('severity'))
            if f.get('status') not in sts:
                problems.append('bad status: %s' % f.get('status'))
            if f.get('status') in ('fail', 'warn') and not f.get('evidence'):
                problems.append('fail/warn without evidence: %s' % f.get('fid'))
            if not f.get('recommendation'):
                problems.append('no recommendation: %s' % f.get('fid'))
        ok('findings schema valid (unique fids, enums, evidence, recommendations)',
           not problems, '; '.join(problems[:3]) or 'clean')

    if 'memory_over_limit' in exp:
        fact = bool(rep['context_tax']['memory_over_limit'])
        ok(f'memory over limit = {exp["memory_over_limit"]}',
           fact == exp['memory_over_limit'], f'actual {fact}')

    if 'memory_over_lines' in exp:
        fact = bool(rep['context_tax'].get('memory_over_lines'))
        ok(f'memory over 200 lines = {exp["memory_over_lines"]}',
           fact == exp['memory_over_lines'], f'actual {fact}')

    if 'chain_budget_over' in exp:
        fact = bool(rep.get('chain_budget_over'))
        ok(f'AGENTS.md chain over 32 KB = {exp["chain_budget_over"]}',
           fact == exp['chain_budget_over'], f'actual {fact}')

    if 'diff_new_on_rerun' in exp:
        out2 = run_dir / 'scan2.json'
        r2 = run([sys.executable, str(SCANNER),
                  str(run_dir / 'workspace'), '--home', str(run_dir / 'home'),
                  '--baseline', str(out), '--out', str(out2)])
        if r2.returncode != 0:
            ok('rerun: new findings 0', False, 'scanner failed')
        else:
            rep2 = json.loads(out2.read_text(encoding='utf-8'))
            n_new = len(rep2.get('diff', {}).get('new', []))
            ok(f'rerun (--baseline): new findings {exp["diff_new_on_rerun"]}',
               n_new == exp['diff_new_on_rerun'], f'actual {n_new}')

    if 'nested_repos' in exp:
        nested = sorted(norm(n) for t in rep['top_level']
                        if t.get('extra') for n in t['extra']['nested_repos'])
        want = sorted(norm(n) for n in exp['nested_repos'])
        ok(f'nested repos = {want}', nested == want, f'actual {nested}')

    if 'skills_desync' in exp:
        desync = sorted(d['name'] for d in rep['skills']['duplicates']
                        if d['sync'] != 'identical')
        ok(f'skills desync = {sorted(exp["skills_desync"])}',
           desync == sorted(exp['skills_desync']), f'actual {desync}')

    notes = norm(' | '.join(rep['harness']['notes']))
    for s in exp.get('notes_contain', []):
        ok(f'dead-harness note ~ "{s}"', norm(s) in notes,
           notes[:120] or 'no notes')

    return name, rows, None


def main():
    scenarios = sorted(p for p in (QA / 'scenarios').iterdir() if p.is_dir())
    lines = ['# agents-doctor QA eval, ' + date.today().isoformat(), '']
    lines += ['## Method', '',
              'Programmatic fact checks: expectations in `scenarios/*/expected.json` '
              'are locked before the run; the runner builds each fixture, runs the '
              'deterministic scanner and compares the actual JSON to the expectations. '
              'The LLM layer of the skill is not covered by this evaluation. '
              'Asymmetry: FAIL proves a defect, PASS only means "not refuted in this run".',
              '']
    total_pass = total_fail = 0
    for sc in scenarios:
        name, rows, err = eval_scenario(sc)
        n_pass = sum(1 for _l, s, _d in rows if s == 'PASS')
        n_fail = sum(1 for _l, s, _d in rows if s == 'FAIL')
        total_pass += n_pass
        total_fail += n_fail
        print(f'{name}: PASS {n_pass}, FAIL {n_fail}' + (f', ERROR: {err}' if err else ''))
        lines += [f'## {name}', '']
        if err:
            lines += [f'Execution ERROR: {err}', '']
            continue
        lines += ['| Check | Status | Details |', '|---|---|---|']
        for label, status, detail in rows:
            lines.append(f'| {label} | {status} | {detail.replace("|", "/")} |')
        lines.append('')
    lines += ['## Summary', '',
              f'PASS {total_pass}, FAIL {total_fail}.',
              '',
              'Run artifacts: `scenarios/*/run/scan.json` (not tracked). '
              'Rerun: `cd qa && python eval.py`.',
              '']
    out = QA / f'QA-EVAL-{date.today().isoformat()}.md'
    out.write_text('\n'.join(lines), encoding='utf-8')
    print(f'PASS {total_pass}, FAIL {total_fail}; report: {out.name}')
    sys.exit(1 if total_fail else 0)


if __name__ == '__main__':
    main()
