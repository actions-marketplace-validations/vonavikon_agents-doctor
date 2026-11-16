#!/usr/bin/env python3
"""Export a scan.json report as SARIF 2.1.0 for code-scanning tools.

    python skills/workspace-audit/scripts/sarif.py <scan.json> --out report.sarif

One rule per gate (G1..G9), one result per finding whose status is fail
or warn. Locations are logical: the evidence file or path, falling back
to the scanned root. Secret values never enter the export; messages are
built from fid, title and recommendation only.
Python 3.9+, stdlib only.
"""
import argparse
import json
import sys
from pathlib import Path

SARIF_VERSION = '2.1.0'
SARIF_SCHEMA = 'https://json.schemastore.org/sarif-2.1.0.json'
TOOL_NAME = 'workspace-audit'
TOOL_URI = 'https://github.com/vonavikon/workspace-audit'
GATES_HELP_URI = TOOL_URI + '#the-nine-gates'
FINGERPRINT_KEY = 'workspaceAudit/v1'

ERROR_SEVERITIES = ('critical', 'high')


def _result_level(finding):
    """fail + critical/high -> error; fail medium/low or warn -> warning;
    info -> note."""
    severity = finding.get('severity', 'info')
    status = finding.get('status', '')
    if severity == 'info':
        return 'note'
    if status == 'fail' and severity in ERROR_SEVERITIES:
        return 'error'
    return 'warning'


def _result_location(finding, rep):
    """file or path from the first evidence entry; the scanned root when
    the evidence names neither."""
    ev = finding.get('evidence') or []
    if ev and isinstance(ev[0], dict):
        if isinstance(ev[0].get('file'), str):
            return ev[0]['file']
        if isinstance(ev[0].get('path'), str):
            return ev[0]['path']
    return rep.get('root', '.')


def to_sarif(rep):
    """Build the SARIF 2.1.0 dict for one scan report."""
    rules = []
    for g in rep.get('gates', []):
        name = g.get('name', '')
        rules.append({
            'id': g.get('gid', ''),
            'name': name,
            'shortDescription': {'text': name},
            'fullDescription': {'text': g.get('description', '')},
            'helpUri': GATES_HELP_URI,
        })

    results = []
    for f in rep.get('findings_detailed', []):
        if f.get('status') not in ('fail', 'warn'):
            continue
        results.append({
            'ruleId': f.get('gate', ''),
            'level': _result_level(f),
            'message': {'text': '{}: {} — {}'.format(
                f.get('fid', ''), f.get('title', ''),
                f.get('recommendation', ''))},
            'locations': [{
                'logicalLocations': [{
                    'fullyQualifiedName': _result_location(f, rep)}]}],
            'partialFingerprints': {FINGERPRINT_KEY: f.get('fid', '')},
            'properties': {
                'severity': f.get('severity', ''),
                'confidence': f.get('confidence'),
                'category': f.get('category', ''),
            },
        })

    return {
        '$schema': SARIF_SCHEMA,
        'version': SARIF_VERSION,
        'runs': [{
            'tool': {
                'driver': {
                    'name': TOOL_NAME,
                    'version': rep.get('rules_version', ''),
                    'informationUri': TOOL_URI,
                    'rules': rules,
                }
            },
            'results': results,
        }],
    }


def main(argv=None):
    ap = argparse.ArgumentParser(
        description='export scan.json as SARIF 2.1.0')
    ap.add_argument('scan', help='scan.json produced by audit_scan.py')
    ap.add_argument('--out', default='report.sarif',
                    help='where to write the SARIF file')
    a = ap.parse_args(argv)
    try:
        rep = json.loads(Path(a.scan).read_text(encoding='utf-8'))
    except (OSError, ValueError) as e:
        sys.exit(f'cannot read report: {e}')
    sarif = to_sarif(rep)
    text = json.dumps(sarif, ensure_ascii=False, indent=2)
    json.loads(text)  # round-trip check before touching the disk
    Path(a.out).write_text(text, encoding='utf-8')
    n_results = len(sarif['runs'][0]['results'])
    n_rules = len(sarif['runs'][0]['tool']['driver']['rules'])
    print(f'wrote {a.out}: {n_rules} rules, {n_results} results')
    return 0


if __name__ == '__main__':
    sys.exit(main())
