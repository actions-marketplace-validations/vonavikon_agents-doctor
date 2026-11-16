# Configuration

## No config file

There is no configuration file and no environment variable to set. All
runtime configuration is CLI flags, per invocation. The scanner sets the
one environment variable it needs itself (`GIT_OPTIONAL_LOCKS=0` for every
git call), so the audit cannot refresh or modify a git index.

Optional Python packages change behaviour when present: PyYAML enables
full frontmatter parsing (without it the flat fallback parser reports
unparseable frontmatter as `unknown`, never as ok); jsonschema enables
strict schema validation in `tools/validate_schema.py` (a structural
fallback runs otherwise).

## CLI flags

Scanner (`skills/agents-doctor/scripts/audit_scan.py`):

| Flag | Effect |
|---|---|
| `path` (positional) | Workspace root to audit. |
| `--home <dir>` | Home directory for harness, memory and user-skill checks. Default: the user profile. |
| `--deep` | Also scan git history for secrets. Slower on large repos. |
| `--baseline <scan.json>` | Previous report; adds a `diff` section with new and resolved fingerprinted findings. An unreadable baseline is skipped silently. |
| `--out <file>` | Report path. Default `scan.json`. This is the only file the scanner writes. |

Stage-4 CLI entry (`skills/agents-doctor/scripts/agents_doctor.py`):

| Subcommand | Flags | Effect |
|---|---|---|
| `audit` | `[path]`, `--focus security\|structure\|agents`, `--report md\|sarif\|both`, `--deep`, `--home <dir>`, `--baseline <scan.json>`, `--out <file>` | Run the scanner and produce the report. `--focus` narrows the report to that gate group (the scan itself stays full). `--report` selects markdown, SARIF or both. |
| `compare` | `<scan.json> --baseline <old scan.json>` | Print the NEW / RESOLVED / PERSISTING / CHANGED diff of fingerprinted findings. |
| `explain` | `<scan.json> <fid>` | Print one typed finding with evidence and recommendation. Exit 2 when the fid does not exist. |
| `fix` | `<scan.json> --fid <fid> [--apply]` | Plan a remediation for one finding. Plan-only by default; `--apply` executes it. Exit 2 when the fid does not exist. |

Exit codes for the stage-4 CLI: 0 success, 1 findings present or a failed
check (where the subcommand expresses one), 2 requested object not found.
See [cli.md](cli.md) for examples.

## Thresholds

All thresholds are constants in code, not options. The gates read them
from `GATE_POLICY` in `skills/agents-doctor/scripts/gates.py`:

| Constant | Value |
|---|---|
| `JUNK_FAIL_BYTES` | 500 MB of junk plus build artifacts (fails G9) |
| `EMPTY_WARN_COUNT` | more than 10 empty dirs warns |
| `TRACKED_BIG_BYTES` | 5 MB, tracked files at or over it fail G7 |
| `DESC_LIMIT` | 1024 chars for skill descriptions |
| `PROJECT_BENCH` | 16 KB project instruction file benchmark |
| `CHAIN_BUDGET` | 32 768 bytes for the root + nested AGENTS.md chain |

A few scanner-side thresholds (memory index 24.4 KB / 200 lines, harness
freshness 30/90 days, duplicate hash window 1-50 MB, heavy directory 1 MB)
live as constants next to their checks in `audit_scan.py` and `enrich.py`.
Changing any threshold is a code change with tests: see
[contributing.md](contributing.md). There is deliberately no per-workspace
override; two audits of the same tree must give the same verdict.

## Exclusions

Build directories (never treated as content, size counted toward the junk
total): `node_modules`, `__pycache__`, `.venv`, `venv`, `dist`, `build`,
`target`, `.cache`, `.idea`, `.pytest_cache`.

Junk-name heuristics are bilingual (English and Russian) and match on file
or directory names: temp, office lock files (`~$`), untitled, img_,
screenshot/скриншот, new folder/новая папка, final/финал,
version/версия, copy/копия, backup, old/стар, времен, scratch, draft,
debug, `.bak`, `.log`. A name match is a candidate, not a verdict: the
skill confirms with the user before proposing deletion. Hash-proven
duplicates are only counted inside the 1-50 MB window.

Symlinks pointing outside the workspace root are skipped and never
followed; the count lands in `stats.skipped_symlinks_outside` and the
report says so.

## Trash convention

Remediation (`remediate.py --apply`) never deletes. Files it removes from
the workspace are moved into `.agents-doctor-trash/` under the audited
root, one subdirectory per remediation run. Delete the trash yourself
after checking it; the scanner reports it as a normal directory on the
next run.
