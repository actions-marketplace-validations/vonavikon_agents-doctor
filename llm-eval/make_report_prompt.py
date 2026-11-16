#!/usr/bin/env python3
"""Build the exact prompt a real agent gets for the report-writing step.

    python llm-eval/make_report_prompt.py --scan llm-eval/fixtures/chaos.json --out prompt.txt

The prompt is deterministic: the workflow and rules sections of
skills/workspace-audit/SKILL.md (report structure, gates table first, masked
secrets, false-positive filtering) followed by the full scan JSON in a fenced
block and the instruction 'Write the AUDIT report now.'. The same scan and
SKILL.md always produce byte-identical output, so prompt, model reply and
grade are reproducible together.

Secret safety: fixtures are redacted by construction (secrets carry masks and
fingerprints only). build_prompt refuses to emit a prompt that contains a
raw-looking token (sk-[A-Za-z0-9_-]{16,}) anyway; scanner masks such as
sk-*** do not match the pattern. Python 3.9+, stdlib only.
"""
import argparse
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
DEFAULT_SKILL = REPO / 'skills' / 'workspace-audit' / 'SKILL.md'

RAW_TOKEN_RX = re.compile(r'sk-[A-Za-z0-9_-]{16,}')


def _section(md, title):
    """Text of the '## <title>' section, up to the next '## ' heading or EOF."""
    lines = md.splitlines()
    start = None
    for i, ln in enumerate(lines):
        if ln.strip() == f'## {title}':
            start = i + 1
            break
    if start is None:
        raise ValueError(f'SKILL.md section not found: {title!r}')
    body = []
    for ln in lines[start:]:
        if ln.startswith('## '):
            break
        body.append(ln)
    text = '\n'.join(body).strip('\n')
    if not text.strip():
        raise ValueError(f'SKILL.md section is empty: {title!r}')
    return text


def build_prompt(scan_json_path, skill_md_path):
    """Deterministic prompt: SKILL.md instructions + full scan JSON + order to write."""
    scan_text = Path(scan_json_path).read_text(encoding='utf-8')
    json.loads(scan_text)  # a broken fixture must fail here, not inside the model
    skill_text = Path(skill_md_path).read_text(encoding='utf-8')
    workflow = _section(skill_text, 'Workflow')
    rules = _section(skill_text, 'Rules')

    prompt = (
        'You are the agent running the workspace-audit skill. The scanner already\n'
        'ran; the scan JSON below is its complete output.\n'
        '\n'
        '## Skill instructions (from skills/workspace-audit/SKILL.md)\n'
        '\n'
        '### Workflow\n'
        '\n'
        + workflow + '\n'
        '\n'
        '### Rules\n'
        '\n'
        + rules + '\n'
        '\n'
        '## Scan data (scan.json)\n'
        '\n'
        '```json\n'
        + scan_text.rstrip('\n') + '\n'
        '```\n'
        '\n'
        'Write the AUDIT report now.'
    )

    leaked = RAW_TOKEN_RX.findall(prompt)
    if leaked:
        raise ValueError(
            f'prompt would leak {len(leaked)} raw-looking secret token(s) '
            f'(e.g. {leaked[0][:5]}***); fix the fixture before evaluating')
    return prompt


def main(argv=None):
    ap = argparse.ArgumentParser(description='build the report-writing prompt')
    ap.add_argument('--scan', default=str(HERE / 'fixtures' / 'chaos.json'),
                    help='scan JSON to embed (default: llm-eval/fixtures/chaos.json)')
    ap.add_argument('--skill', default=str(DEFAULT_SKILL),
                    help='SKILL.md to take the instructions from')
    ap.add_argument('--out', default=None,
                    help='output file (default: print to stdout)')
    a = ap.parse_args(argv)

    prompt = build_prompt(a.scan, a.skill)
    if a.out:
        Path(a.out).write_text(prompt, encoding='utf-8')
        print(f'prompt written: {a.out} ({len(prompt)} chars)')
    else:
        sys.stdout.write(prompt + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
