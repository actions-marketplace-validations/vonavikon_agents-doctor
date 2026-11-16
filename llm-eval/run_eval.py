#!/usr/bin/env python3
"""End-to-end runner for the LLM layer of agents-doctor.

    python llm-eval/run_eval.py --model offline
    python llm-eval/run_eval.py --model my-model --api https://api.example.com/v1 \
        --key-env OPENAI_API_KEY --out runs/my-model/

Pipeline per fixture: build the prompt exactly as the skill would give it
(make_report_prompt), get a report - from the model (any OpenAI-compatible
/chat/completions endpoint via urllib), from a pre-baked/replayed report
(--pregenerated), or from the shipped samples (offline mode) - then grade it
deterministically with grade_report.py's checks (R1-R7 + RX) and write a
verdict.json per run plus a combined summary.md.

Modes:
  offline (default, --model offline): no network at all. Grades the shipped
      sample reports (llm-eval/samples: good-chaos, bad-chaos, good-clean),
      builds the adversarial fixtures locally and checks INPUT_VALIDATION on
      the malformed one. This is the CI contract: exit 0 iff every 'good'
      sample passes all critical checks (R1, R2, R3, R7) with >= 6 of 7
      rubric checks passing, every 'bad' sample is caught (a critical fails,
      <= 3 of 7 pass), and the malformed fixture is rejected.
  online (--api <base-url> --model <name>): calls <api>/chat/completions with
      a Bearer key from the env var named by --key-env (default
      OPENAI_API_KEY), 120 s timeout, one retry. Exit 0 iff all critical
      checks pass on the generated reports and INPUT_VALIDATION holds.
  replay (--pregenerated <dir>, no --api): grades existing reports instead of
      calling a model. File name convention per fixture stem S: good-S.md (or
      S.md) is expected to pass, bad-S.md is expected to fail - both are
      graded when both exist.

Artifacts land in --out (default llm-eval/runs/<timestamp>-<model>/): one
directory per graded report with verdict.json, report.md and prompt.txt, the
raw model response (response.json, online mode), the generated adversarial
fixtures under fixtures/, and summary.md. Python 3.9+, stdlib only.
"""
import argparse
import importlib.util
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SKILL_MD = REPO / 'skills' / 'agents-doctor' / 'SKILL.md'
DEFAULT_SAMPLES = HERE / 'samples'
DEFAULT_FIXTURES = [HERE / 'fixtures' / 'clean.json',
                    HERE / 'fixtures' / 'chaos.json']
CRITICAL_CHECKS = ('R1', 'R2', 'R3', 'R7')
RUBRIC_CHECKS = ('R1', 'R2', 'R3', 'R4', 'R5', 'R6', 'R7')
TIMEOUT_S = 120


def _load(name):
    spec = importlib.util.spec_from_file_location(f'llm_eval_{name}', HERE / f'{name}.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


grade_report = _load('grade_report')
make_report_prompt = _load('make_report_prompt')
adversarial = _load('adversarial')


# ---------------------------------------------------------------- model layer

def chat_completion(api_base, model, prompt, key_env='OPENAI_API_KEY',
                    timeout=TIMEOUT_S):
    """One chat completion against an OpenAI-compatible endpoint, one retry."""
    key = os.environ.get(key_env, '')
    url = api_base.rstrip('/') + '/chat/completions'
    body = json.dumps({
        'model': model,
        'temperature': 0,
        'messages': [{'role': 'user', 'content': prompt}],
    }).encode('utf-8')
    last = None
    for attempt in (1, 2):
        req = urllib.request.Request(
            url, data=body, method='POST',
            headers={'Content-Type': 'application/json',
                     'Authorization': f'Bearer {key}'})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                payload = json.loads(resp.read().decode('utf-8'))
            return payload['choices'][0]['message']['content'], payload
        except (urllib.error.URLError, OSError, KeyError, IndexError,
                ValueError) as e:
            last = e
            if attempt == 1:
                continue
    raise RuntimeError(f'model call failed after retry ({url}): {last}')


# ------------------------------------------------------------------- plumbing

def resolve_fixture(path_str):
    p = Path(path_str)
    candidates = [p] if p.is_absolute() else [
        Path.cwd() / p, HERE / p, REPO / p]
    for c in candidates:
        if c.exists():
            return c
    tried = ', '.join(str(c) for c in candidates)
    raise SystemExit(f'fixture not found: {path_str} (tried {tried})')


def _sample_candidates(sample_dir, stem):
    """(label, path) pairs for a fixture stem: good-S.md/S.md then bad-S.md."""
    found = []
    for tag, name in (('good', f'good-{stem}.md'), ('good', f'{stem}.md'),
                      ('bad', f'bad-{stem}.md')):
        p = Path(sample_dir) / name
        if p.exists() and p not in [f for _, f in found]:
            found.append((tag, p))
    return found


def _checks_dict(results):
    return {rid: {'status': status.lower(), 'evidence': detail}
            for rid, _label, status, detail in results}


def grade_report_into_verdict(fixture, scan, report_text, report_source,
                              model, expect, sample_based):
    results = grade_report.grade(report_text, scan)
    checks = _checks_dict(results)
    checks['INPUT_VALIDATION'] = {
        'status': 'na', 'evidence': 'scan passed input validation'}
    rubric_passes = sum(1 for r in RUBRIC_CHECKS
                        if checks[r]['status'] == 'pass')
    critical_ok = all(checks[c]['status'] in ('pass', 'na')
                      for c in CRITICAL_CHECKS)
    return {
        'fixture': str(fixture),
        'report': str(report_source),
        'model': model,
        'expect': expect,
        'sample_based': sample_based,
        'checks': checks,
        'totals': {
            'pass': sum(1 for v in checks.values() if v['status'] == 'pass'),
            'fail': sum(1 for v in checks.values() if v['status'] == 'fail'),
            'na': sum(1 for v in checks.values() if v['status'] == 'na'),
        },
        'rubric_passes': rubric_passes,
        'critical_ok': critical_ok,
    }


def write_verdict(out_root, tag, verdict, report_text, prompt, raw_payload=None):
    vdir = out_root / tag
    vdir.mkdir(parents=True, exist_ok=True)
    (vdir / 'report.md').write_text(report_text, encoding='utf-8')
    if prompt is not None:
        (vdir / 'prompt.txt').write_text(prompt, encoding='utf-8')
    if raw_payload is not None:
        (vdir / 'response.json').write_text(
            json.dumps(raw_payload, indent=2, ensure_ascii=False) + '\n',
            encoding='utf-8')
    (vdir / 'verdict.json').write_text(
        json.dumps(verdict, indent=2, ensure_ascii=False) + '\n',
        encoding='utf-8')
    return vdir


def check_input_validation(malformed_path, out_root, model):
    """The grader must reject the malformed fixture; returns (ok, verdict)."""
    scan = json.loads(malformed_path.read_text(encoding='utf-8'))
    problems = grade_report.validate_scan(scan)
    if problems:
        evidence = 'invalid report input: ' + '; '.join(problems[:3])
        status = 'pass'
    else:
        evidence = 'malformed fixture was not rejected by validate_scan'
        status = 'fail'
    checks = {
        rid: {'status': 'na',
              'evidence': 'not graded: input rejected before grading'}
        for rid in list(RUBRIC_CHECKS) + ['RX']
    }
    checks['INPUT_VALIDATION'] = {'status': status, 'evidence': evidence}
    verdict = {
        'fixture': str(malformed_path),
        'report': None,
        'model': model,
        'expect': 'input',
        'sample_based': True,
        'checks': checks,
        'totals': {
            'pass': sum(1 for v in checks.values() if v['status'] == 'pass'),
            'fail': sum(1 for v in checks.values() if v['status'] == 'fail'),
            'na': sum(1 for v in checks.values() if v['status'] == 'na'),
        },
        'rubric_passes': 0,
        'critical_ok': status == 'pass',
    }
    write_verdict(out_root, 'malformed-input', verdict,
                  report_text=malformed_path.read_text(encoding='utf-8'),
                  prompt=None)
    return status == 'pass', verdict


def write_summary(out_root, model, mode, verdicts):
    cols = list(RUBRIC_CHECKS) + ['RX', 'INPUT']
    lines = [
        f'# LLM eval summary',
        '',
        f'model: {model} | mode: {mode} | ran: {datetime.now().isoformat(timespec="seconds")}',
        '',
        '| fixture | report | ' + ' | '.join(cols) + ' | R-pass | expect | ok |',
        '|---|---|' + '---|' * (len(cols) + 3),
    ]
    for v in verdicts:
        cells = []
        for c in cols:
            key = 'INPUT_VALIDATION' if c == 'INPUT' else c
            cells.append(v['checks'].get(key, {}).get('status', '-'))
        report = Path(v['report']).name if v['report'] else '-'
        if v['expect'] == 'good':
            ok = v['critical_ok'] and (not v['sample_based']
                                       or v['rubric_passes'] >= 6)
        elif v['expect'] == 'bad':
            ok = (not v['critical_ok']) and (not v['sample_based']
                                             or v['rubric_passes'] <= 3)
        else:
            ok = v['checks']['INPUT_VALIDATION']['status'] == 'pass'
        lines.append(
            f"| {Path(v['fixture']).name} | {report} | "
            + ' | '.join(cells)
            + f" | {v['rubric_passes']}/7 | {v['expect']} | {'ok' if ok else 'BAD'} |")
    lines += ['', f'total verdicts: {len(verdicts)}', '']
    (out_root / 'summary.md').write_text('\n'.join(lines), encoding='utf-8')
    return lines


def verdict_ok(v):
    if v['expect'] == 'good':
        return v['critical_ok'] and (not v['sample_based']
                                     or v['rubric_passes'] >= 6)
    if v['expect'] == 'bad':
        return (not v['critical_ok']) and (not v['sample_based']
                                           or v['rubric_passes'] <= 3)
    return v['checks']['INPUT_VALIDATION']['status'] == 'pass'


def run(argv=None):
    ap = argparse.ArgumentParser(description='run the LLM-layer evaluation')
    ap.add_argument('--model', default='offline',
                    help='model name, or "offline" (default) to skip generation')
    ap.add_argument('--api', default=None,
                    help='OpenAI-compatible base URL, e.g. https://api.openai.com/v1 '
                         'or http://localhost:8000/v1; enables online mode')
    ap.add_argument('--key-env', default='OPENAI_API_KEY',
                    help='env var holding the Bearer key (default OPENAI_API_KEY)')
    ap.add_argument('--fixture', action='append', default=None,
                    help='scan JSON to evaluate; repeatable. Default: '
                         'llm-eval/fixtures/clean.json + chaos.json')
    ap.add_argument('--pregenerated', default=None,
                    help='directory with pre-written reports per fixture stem '
                         '(good-<stem>.md / <stem>.md / bad-<stem>.md); '
                         'replaces model generation for fixtures it covers')
    ap.add_argument('--out', default=None,
                    help='output directory (default: llm-eval/runs/<ts>-<model>/)')
    a = ap.parse_args(argv)

    offline = a.model == 'offline'
    if offline and a.api:
        ap.error('--model offline cannot be combined with --api')
    online = bool(a.api)
    if online and offline:
        ap.error('pass a real --model name together with --api')
    mode = 'online' if online else ('offline' if offline else 'replay')

    ts = datetime.now().strftime('%Y%m%d-%H%M%S')
    out_root = Path(a.out) if a.out else HERE / 'runs' / f'{ts}-{a.model}'
    out_root.mkdir(parents=True, exist_ok=True)

    # Always: adversarial set + INPUT_VALIDATION on the malformed fixture.
    adv_paths = adversarial.build_all(out_root / 'fixtures')
    malformed_path = out_root / 'fixtures' / 'malformed.json'
    input_ok, input_verdict = check_input_validation(malformed_path, out_root,
                                                     a.model)

    fixture_paths = ([resolve_fixture(f) for f in a.fixture]
                     if a.fixture else DEFAULT_FIXTURES)
    sample_dir = Path(a.pregenerated) if a.pregenerated else (
        DEFAULT_SAMPLES if (offline or not online) else None)

    verdicts = [input_verdict]
    for fixture in fixture_paths:
        stem = fixture.stem
        scan = json.loads(fixture.read_text(encoding='utf-8'))
        problems = grade_report.validate_scan(scan)
        if problems:
            # A chosen fixture that violates the schema is an input test, not
            # a model test: record rejection, do not call the model.
            checks = {rid: {'status': 'na',
                            'evidence': 'not graded: input rejected'}
                      for rid in list(RUBRIC_CHECKS) + ['RX']}
            checks['INPUT_VALIDATION'] = {
                'status': 'pass',
                'evidence': 'invalid report input: ' + '; '.join(problems[:3])}
            v = {
                'fixture': str(fixture),
                'report': None,
                'model': a.model,
                'expect': 'input',
                'sample_based': True,
                'checks': checks,
                'totals': {
                    'pass': sum(1 for c in checks.values()
                                if c['status'] == 'pass'),
                    'fail': sum(1 for c in checks.values()
                                if c['status'] == 'fail'),
                    'na': sum(1 for c in checks.values() if c['status'] == 'na'),
                },
                'rubric_passes': 0,
                'critical_ok': True,
            }
            write_verdict(out_root, f'{stem}-input', v,
                          report_text=fixture.read_text(encoding='utf-8'),
                          prompt=None)
            verdicts.append(v)
            print(f'{stem}: rejected as invalid input (INPUT_VALIDATION pass)')
            continue

        prompt = make_report_prompt.build_prompt(fixture, SKILL_MD)
        reports = []  # (tag, source, text, sample_based, raw_payload)

        if sample_dir is not None:
            for tag, path in _sample_candidates(sample_dir, stem):
                reports.append((tag, path, path.read_text(encoding='utf-8'),
                                True, None))
        if not reports and not online:
            where = sample_dir if sample_dir else DEFAULT_SAMPLES
            raise SystemExit(
                f'no report for fixture {fixture.name} in {where} and no --api; '
                f'pass --pregenerated or --api')
        if not reports and online:
            print(f'{stem}: calling model {a.model} ...')
            text, payload = chat_completion(a.api, a.model, prompt,
                                            key_env=a.key_env)
            reports.append(('good', f'{a.model} (api)', text, False, payload))

        for tag, source, text, sample_based, raw in reports:
            v = grade_report_into_verdict(fixture, scan, text, source,
                                          a.model, tag, sample_based)
            suffix = '' if len(reports) == 1 else f'-{tag}'
            write_verdict(out_root, f'{stem}{suffix}', v, text, prompt, raw)
            verdicts.append(v)
            crit = ', '.join(
                f"{c}={v['checks'][c]['status']}" for c in CRITICAL_CHECKS)
            print(f'{stem}{suffix}: expect {tag}, {v["rubric_passes"]}/7 '
                  f'rubric checks pass ({crit})')

    summary_lines = write_summary(out_root, a.model, mode, verdicts)
    ok = input_ok and all(verdict_ok(v) for v in verdicts
                          if v is not input_verdict)
    print('\n'.join(summary_lines))
    print(f'artifacts: {out_root}')
    if ok:
        print('result: PASS')
        return 0
    bad = [f"{Path(v['fixture']).name}({v['expect']})" for v in verdicts
           if v is not input_verdict and not verdict_ok(v)]
    if not input_ok:
        bad.append('malformed(input)')
    print(f'result: FAIL ({", ".join(bad) if bad else "unexpected"})')
    return 1


def main(argv=None):
    sys.exit(run(argv))


if __name__ == '__main__':
    main()
