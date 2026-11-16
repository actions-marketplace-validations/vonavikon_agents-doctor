#!/usr/bin/env python3
"""Validate a scan.json report against docs/schema/report-schema.json.

    python tools/validate_schema.py <scan.json>

If jsonschema is importable, the file is validated with Draft7Validator
(schema resolved relative to the repo root, independent of the CWD). If not,
a structural fallback checks the same required keys and enums by hand and
prints 'fallback (jsonschema not installed)'. Exit 0 = valid, 1 = problems.
Python 3.9+, stdlib only (jsonschema is an optional CI dependency).
"""
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCHEMA_PATH = REPO / 'docs' / 'schema' / 'report-schema.json'

REQUIRED_TOP = ['schema_version', 'root', 'home', 'generated_at', 'rules_version',
                'stats', 'gates', 'findings_detailed', 'secrets', 'top_level', 'junk']
REQUIRED_STATS = ['total_files', 'total_size_bytes', 'skipped_symlinks_outside', 'duration_sec']
REQUIRED_GATE = ['gid', 'n', 'status']
REQUIRED_FINDING = ['fid', 'gate', 'category', 'severity', 'status', 'title',
                    'evidence', 'recommendation']
STATUSES = {'pass', 'fail', 'warn', 'unknown', 'not_applicable'}
SEVERITIES = {'critical', 'high', 'medium', 'low', 'info'}


def check_fallback(rep):
    """Same contract as the schema, checked by hand."""
    problems = []
    for k in REQUIRED_TOP:
        if k not in rep:
            problems.append(f'missing top-level key: {k}')
    if rep.get('schema_version') != '1.0':
        problems.append(f'schema_version: expected "1.0", got {rep.get("schema_version")!r}')
    stats = rep.get('stats')
    if not isinstance(stats, dict):
        problems.append('stats: not an object')
    else:
        for k in REQUIRED_STATS:
            if k not in stats:
                problems.append(f'stats: missing key: {k}')
    gates = rep.get('gates')
    if not isinstance(gates, list):
        problems.append('gates: not an array')
    else:
        for i, g in enumerate(gates):
            for k in REQUIRED_GATE:
                if k not in g:
                    problems.append(f'gates[{i}]: missing key: {k}')
            if g.get('status') not in STATUSES:
                problems.append(f'gates[{i}].status: {g.get("status")!r} not in {sorted(STATUSES)}')
    findings = rep.get('findings_detailed')
    if not isinstance(findings, list):
        problems.append('findings_detailed: not an array')
    else:
        for i, f in enumerate(findings):
            for k in REQUIRED_FINDING:
                if k not in f:
                    problems.append(f'findings_detailed[{i}]: missing key: {k}')
            if f.get('status') not in STATUSES:
                problems.append(f'findings_detailed[{i}].status: '
                                f'{f.get("status")!r} not in {sorted(STATUSES)}')
            if f.get('severity') not in SEVERITIES:
                problems.append(f'findings_detailed[{i}].severity: '
                                f'{f.get("severity")!r} not in {sorted(SEVERITIES)}')
    secrets = rep.get('secrets')
    if not isinstance(secrets, list):
        problems.append('secrets: not an array')
    else:
        for i, s in enumerate(secrets):
            for k in ('path', 'kind', 'fingerprint'):
                if k not in s:
                    problems.append(f'secrets[{i}]: missing key: {k}')
            for k in ('value', 'preview'):
                if k in s:
                    problems.append(f'secrets[{i}]: forbidden key "{k}" '
                                    f'(reports carry masks, never secret material)')
    return problems


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    if not SCHEMA_PATH.is_file():
        print(f'[FAIL] schema file missing: {SCHEMA_PATH}')
        return 1
    target = Path(sys.argv[1])
    try:
        rep = json.loads(target.read_text(encoding='utf-8'))
    except OSError as e:
        print(f'[FAIL] cannot read {target}: {e}')
        return 1
    except ValueError as e:
        print(f'[FAIL] {target} does not parse as JSON: {e}')
        return 1

    try:
        import jsonschema
    except ImportError:
        jsonschema = None

    if jsonschema is not None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding='utf-8'))
        errors = sorted(jsonschema.Draft7Validator(schema).iter_errors(rep),
                        key=lambda e: list(e.absolute_path))
        problems = [f'{".".join(str(p) for p in e.absolute_path) or "<root>"}: {e.message}'
                    for e in errors]
        mode = 'jsonschema'
    else:
        problems = check_fallback(rep)
        mode = 'fallback (jsonschema not installed)'

    n_gates = len(rep.get('gates', [])) if isinstance(rep.get('gates'), list) else '-'
    n_fd = len(rep.get('findings_detailed', [])) if isinstance(rep.get('findings_detailed'), list) else '-'
    n_sec = len(rep.get('secrets', [])) if isinstance(rep.get('secrets'), list) else '-'

    if problems:
        for p in problems:
            print(f'[FAIL] {p}')
        print(f'schema validation failed ({mode}): {len(problems)} problem(s)')
        return 1
    print(f'[OK] schema ({mode}): {target.name} - '
          f'{n_gates} gates, {n_fd} findings, {n_sec} secrets')
    return 0


if __name__ == '__main__':
    sys.exit(main())
