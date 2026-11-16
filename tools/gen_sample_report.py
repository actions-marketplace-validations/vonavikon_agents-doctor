#!/usr/bin/env python3
"""Regenerate docs/sample-report.md from the chaos fixture.

    python tools/gen_sample_report.py

Takes llm-eval/fixtures/chaos.json, runs it through the report generator
and writes docs/sample-report.md. Use after changing the generator or the
fixture so the committed sample stays in sync. Python 3.9+, stdlib only.
"""
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'skills' / 'agents-doctor' / 'scripts'))

import report_generator  # noqa: E402

FIXTURE = REPO / 'llm-eval' / 'fixtures' / 'chaos.json'
TARGET = REPO / 'docs' / 'sample-report.md'


def main():
    import json
    rep = json.loads(FIXTURE.read_text(encoding='utf-8'))
    TARGET.write_text(report_generator.generate_markdown(rep),
                      encoding='utf-8')
    print(f'wrote {TARGET} from {FIXTURE}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
