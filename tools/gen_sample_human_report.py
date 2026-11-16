#!/usr/bin/env python3
"""Regenerate the plain-language sample reports from the chaos fixture.

    python tools/gen_sample_human_report.py

Takes llm-eval/fixtures/chaos.json, runs it through the human report
generator and writes docs/sample-human-report.md (EN) plus
docs/sample-human-report.ru.md (RU). Use after changing the generator
or the fixture so the committed samples stay in sync.
Python 3.9+, stdlib only.
"""
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'skills' / 'agents-doctor' / 'scripts'))

import report_human  # noqa: E402

FIXTURE = REPO / 'llm-eval' / 'fixtures' / 'chaos.json'
TARGETS = [
    ('en', REPO / 'docs' / 'sample-human-report.md'),
    ('ru', REPO / 'docs' / 'sample-human-report.ru.md'),
]


def main():
    rep = json.loads(FIXTURE.read_text(encoding='utf-8'))
    for lang, target in TARGETS:
        md = report_human.generate_human_markdown(rep, lang=lang)
        target.write_text(md, encoding='utf-8')
        print(f'wrote {target} ({lang})')
    return 0


if __name__ == '__main__':
    sys.exit(main())
