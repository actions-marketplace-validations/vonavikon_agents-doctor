# CLI reference

All commands run from the repo root. `python` is Python 3.10+; the scanner
modules need nothing beyond the standard library.

## Scanner: audit_scan.py

```
python skills/workspace-audit/scripts/audit_scan.py <path> [--home <dir>]
    [--deep] [--baseline <old scan.json>] [--out <file>]
```

Example:

```
python skills/workspace-audit/scripts/audit_scan.py demo/employee-workspace \
    --home demo/fake-home --out demo-scan.json
```

Writes the JSON report to `--out` (default `scan.json`) and prints a
summary: file and size counts, gate statuses by level, typed finding
counts, skipped symlinks, baseline diff when given.

Exit codes: 0 after writing the report (findings do not change the exit
code), 1 when the root is not a directory or the report cannot be written,
2 on unknown flags. An unreadable `--baseline` file is skipped, not an
error.

## CLI entry: workspace_audit.py (stage 4)

One command over the scanner and the stage-4 modules.

```
python skills/workspace-audit/scripts/workspace_audit.py audit <path>
    [--focus security|structure|agents] [--report md|sarif|both]
    [--deep] [--home <dir>] [--baseline <scan.json>] [--out <file>]
```

Runs the scan, then writes the markdown report and/or the SARIF export.
`--focus` narrows the report to one gate group; the scan stays full. With
findings present the subcommand exits 1, so CI can gate on it.

```
python skills/workspace-audit/scripts/workspace_audit.py compare <scan.json>
    --baseline <old scan.json>
```

Prints the fingerprint diff: NEW, RESOLVED, PERSISTING, CHANGED.

```
python skills/workspace-audit/scripts/workspace_audit.py explain <scan.json> <fid>
```

Prints one typed finding: title, description, evidence, severity, status,
confidence, recommendation.

```
python skills/workspace-audit/scripts/workspace_audit.py fix <scan.json>
    --fid <fid> [--apply]
```

Prints the remediation plan. `--apply` executes it (moves to
`.workspace-audit-trash/`, never deletes); run an audit again afterwards.

Exit codes: 0 success, 1 findings present or a failed check, 2 requested
fid or file not found.

## Report writer: report_generator.py (stage 4)

```
python skills/workspace-audit/scripts/report_generator.py <scan.json>
    [--out AUDIT-<date>.md]
```

Turns a scan JSON into the markdown report: gates table first, then
findings grouped by block, commands for the user at the end. Exit 0
written, 1 bad input.

## SARIF export: sarif.py (stage 4)

```
python skills/workspace-audit/scripts/sarif.py <scan.json> [--out scan.sarif]
```

Exports findings as SARIF 2.1.0 for code viewers that accept it (GitHub
code scanning, VS Code). Exit 0 written, 1 bad input.

## Remediation: remediate.py (stage 4)

```
python skills/workspace-audit/scripts/remediate.py <scan.json>
    [--fid <fid>] [--apply]
```

Plans remediations for findings with `autofix_available: true` (one, with
`--fid`; all, without). Plan-only unless `--apply` is given; applied moves
go to `.workspace-audit-trash/`. Exit 0 plan ready (or applied), 1 a
planned step failed, 2 fid not found.

## Tools

```
python tools/validate_manifest.py
python tools/validate_schema.py <scan.json>
python tools/check_links.py [root]
```

`validate_manifest.py` cross-checks `.claude-plugin/plugin.json` and
`marketplace.json` (names, versions, skill layout). `validate_schema.py`
validates a scan JSON against `docs/schema/report-schema.json` (Draft7
when jsonschema is installed, structural fallback otherwise).
`check_links.py` verifies that local targets of markdown links exist.
Exit 0 pass, 1 problems printed, 2 usage error (check_links).

## Benchmarks

```
python bench/gen_workspace.py bench/work/ws-small --size small
python bench/run_benchmark.py bench/work/ws-small --home bench/work/home \
    --label "local (small)" --max-wall 60
```

The generator builds a deterministic synthetic workspace (small ~800,
medium ~12000, large ~60000 files). The runner appends one row to
`bench/BENCH-<date>.md`; `--max-wall` fails the run past a wall-time cap.
See [bench/README.md](../bench/README.md).

## LLM-layer eval

```
python llm-eval/make_fixtures.py --out llm-eval/fixtures/
python llm-eval/grade_report.py AUDIT-2026-11-16.md llm-eval/fixtures/chaos.json
```

Freezes scan fixtures and grades the deterministic part (R1-R4) of a
model-written report; R5-R7 are graded by hand with
[llm-eval/rubric.md](../llm-eval/rubric.md). See
[llm-eval/README.md](../llm-eval/README.md).

## QA eval

```
cd qa && python eval.py
```

Builds the three scenario fixtures, runs the scanner, compares actual JSON
against locked expectations and writes `qa/QA-EVAL-<date>.md`. Exit 0 when
every check passes, 1 otherwise.

## Human layer

- `python skills/workspace-audit/scripts/report_human.py <scan.json> [--lang en|ru] [--sessions 10] [--after <scan2.json>] [--out HUMAN-REPORT.md]` — plain-language value report; `--after` produces the before/after story.
- `python skills/workspace-audit/scripts/safe_clean.py <root> [--home H] [--yes] [--include-cautious] [--max-bytes N]` — guided safe cleanup; interactive typed-YES confirmation, trash-first, exit 0/1/2/3 (see `--help`).
- `python tools/gen_sample_human_report.py` — regenerates the EN/RU sample reports from the chaos fixture.

## Scanner flags added in v0.7.0

- `--profile` — per-stage timings to stderr (walk, git, context, enrich, gates).
- `--history-depth N` — cap the deep history scan per repo; coverage is reported and incomplete scans never read as pass.
- `--history-all-refs` — deep-scan across all refs, not only HEAD.
- `python skills/workspace-audit/scripts/safe_clean.py restore <run_dir> [--root R]` — restore a cleanup session from its manifest (typed YES).
- `python llm-eval/run_eval.py --model offline` — the LLM-layer grading pipeline without network or API keys; `--model <name> --api <base-url> --key-env VAR` runs a real model against the frozen fixtures.
