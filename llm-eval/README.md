# LLM-layer evaluation

Measures the model layer of the plugin (report writing), not the scanner: the
inputs are frozen scan snapshots and the grading is deterministic, so the same
report text always gets the same verdict. Model variance affects only the
writing step. Works with any model and any harness.

## Suite

| File | Role |
|---|---|
| `make_fixtures.py` | rebuilds QA scenarios 01-clean-newbie and 03-leaver-chaos and freezes their scan JSON as `fixtures/clean.json`, `fixtures/chaos.json` (+ `.gates.txt` sidecars) |
| `fixtures/` | frozen inputs, committed for reproducibility (regenerate with `make_fixtures.py`; scenario content is deterministic, timestamps vary) |
| `rubric.md` | grading rubric R1-R7 for a model-written audit report |
| `grade_report.py` | deterministic checks R1-R4 + word-count sanity; R5-R7 stay manual |

## Running with any model

1. Generate (or refresh) the fixtures:

   ```
   python llm-eval/make_fixtures.py --out llm-eval/fixtures/
   ```

2. In a fresh session, give the model `llm-eval/fixtures/chaos.json` (or
   `clean.json`) and the instructions from `skills/workspace-audit/SKILL.md`,
   and have it write `AUDIT-2026-11-16.md`. Nothing else: no live workspace
   access, no scanner run at this stage.

3. Grade the deterministic part:

   ```
   python llm-eval/grade_report.py AUDIT-2026-11-16.md llm-eval/fixtures/chaos.json
   ```

4. Grade R5-R7 manually with `rubric.md`, quoting one evidence line per
   criterion. The report passes the suite only when all criteria are PASS.

For a regression signal across model changes, keep the reports
(`AUDIT-<model>-<date>.md`) next to the fixtures and compare rows over time.
