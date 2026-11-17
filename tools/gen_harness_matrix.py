#!/usr/bin/env python3
"""Regenerate docs/HARNESS-MATRIX.md from the live adapter registry.

The matrix is generated, never hand-edited: what you read in the doc
is what the code will do. Sources: adapter spec metadata (spec_source,
spec_verified, supported_versions, known_limitations), the small
capability table derived from the adapter methods each one overrides,
the adapter quality score and the per-capability conformance statuses
(harness/base.py CAPABILITY_STATUS via adapter_quality/spec_info).

    python tools/gen_harness_matrix.py [--check]

--check exits 1 when the committed doc is stale (CI guard).
"""
from __future__ import annotations

import argparse
import inspect
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRIPTS = REPO / 'skills' / 'agents-doctor' / 'scripts'
sys.path.insert(0, str(SCRIPTS))

import harness  # noqa: E402
from harness.base import CAPABILITY_KEYS  # noqa: E402

CAPABILITY_METHODS = [
    ('instruction_sources', 'instructions'),
    ('resolve_chain', 'resolution'),
    ('validate', 'validation'),
    ('detect_version', 'version'),
    ('skills_locations', 'skills'),
    ('context_budget_bytes', 'budget'),
]

# conformance status -> compact table cell (legend printed with the
# table; full statuses live in docs/capability-matrix.json)
STATUS_CODES = {
    'documented': 'dt',
    'runtime-tested': 'rt',
    'approximated': 'ap',
    'unsupported': 'us',
    'unknown': 'uk',
}

# method the base class defines; an adapter overrides it when it
# appears in the adapter's own __dict__ (or defines a non-default)


def _overridden(adapter, method):
    for cls in type(adapter).__mro__:
        if method in cls.__dict__:
            return cls is not harness.base.HarnessAdapter
    return False


def build_matrix() -> str:
    rows = []
    for adapter in harness.iter_adapters():
        caps = [label for method, label in CAPABILITY_METHODS
                if _overridden(adapter, method)]
        rows.append({
            'id': adapter.harness_id,
            'name': adapter.display_name,
            'adapter_version': getattr(adapter, 'adapter_version', '-'),
            'source': adapter.spec_source or '(unset)',
            'verified': adapter.spec_verified or '(unset)',
            'versions': adapter.supported_versions or '(unverified)',
            'caps': caps,
            'limits': adapter.known_limitations or [],
            'quality': adapter.adapter_quality(),
        })

    lines = ['# Harness Support Matrix', '']
    lines.append('Generated from the adapter registry by '
                 '`python tools/gen_harness_matrix.py` — do not edit '
                 'by hand.')
    lines.append('')
    lines.append('| harness | id | adapter ver | quality | capabilities | '
                 'spec verified | versions |')
    lines.append('|---|---|---|---|---|---|---|')
    for r in rows:
        caps = ', '.join(r['caps']) if r['caps'] else 'detection only'
        lines.append('| %s | `%s` | %s | %s | %s | %s | %s |'
                     % (r['name'], r['id'], r['adapter_version'],
                        r['quality']['score'], caps,
                        r['verified'], r['versions']))
    lines.append('')
    lines.append('Quality score: mean evidence weight over the 13 '
                 'conformance capabilities (runtime-tested 1.0, '
                 'documented 0.75, approximated 0.4, unsupported 0, '
                 'unknown 0) — see the table below and '
                 'docs/capability-matrix.json. It grades how well WE '
                 'know each harness, not how healthy a workspace is.')
    lines.append('')
    lines.append('## Capability statuses')
    lines.append('')
    lines.append('How each adapter knows what it claims, per '
                 'capability (harness/base.py CAPABILITY_STATUS):')
    lines.append('')
    header = ['harness'] + list(CAPABILITY_KEYS)
    lines.append('| %s |' % ' | '.join(header))
    lines.append('|%s' % ('---|' * len(header)))
    for r in rows:
        cells = [STATUS_CODES.get(s, 'uk')
                 for s in r['quality']['per_capability'].values()]
        lines.append('| %s | %s |' % (r['name'], ' | '.join(cells)))
    lines.append('')
    lines.append('Legend: **dt** documented (confirmed against official '
                 'docs) · **rt** runtime-tested (verified on a real '
                 'runtime) · **ap** approximated (approximate model, '
                 'documented deviations) · **us** unsupported '
                 '(deliberately not modelled) · **uk** unknown (not '
                 'enough data). Machine-readable copy: '
                 'docs/capability-matrix.json.')
    lines.append('')
    lines.append('## Specification provenance and limitations')
    lines.append('')
    for r in rows:
        lines.append('### %s (`%s`)' % (r['name'], r['id']))
        lines.append('')
        lines.append('Docs: %s' % r['source'])
        lines.append('')
        if r['limits']:
            lines.append('Known limitations:')
            for lim in r['limits']:
                lines.append('- %s' % lim)
        else:
            lines.append('No documented limitations.')
        lines.append('')
    return '\n'.join(lines) + '\n'


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('--check', action='store_true',
                    help='exit 1 when the committed matrix is stale')
    a = ap.parse_args(argv)
    matrix = build_matrix()
    out = REPO / 'docs' / 'HARNESS-MATRIX.md'
    if a.check:
        current = out.read_text(encoding='utf-8') \
            if out.exists() else ''
        if current != matrix:
            print('STALE: docs/HARNESS-MATRIX.md differs from the '
                  'registry; regenerate it', file=sys.stderr)
            return 1
        print('OK: harness matrix is current')
        return 0
    out.write_text(matrix, encoding='utf-8')
    print('written: %s' % out)
    return 0


if __name__ == '__main__':
    sys.exit(main())
