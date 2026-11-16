# workspace-audit

Read-only workspace auditor for agent-driven setups (Claude Code, Z Code compatible). Finds stale instruction files, abandoned repos, folders outside git, junk, duplicates, secrets and drifted skills. The report stays local, there is no telemetry, and nothing is deleted.

## How it works

Two layers:

1. A deterministic scanner, `audit_scan.py`: pure Python stdlib, no dependencies, offline, about 0.5 s on a mid-size folder on a warm cache. It walks the workspace and writes JSON.
2. The skill orchestrator: reads the JSON, filters false positives, and writes `AUDIT-<date>.md` with a gates table and cleanup commands.

The scanner only reads. Deletions and edits always stay with the human.

## Security model

- Secret detection and redaction live in one module, `secret_scanner.py`: raw values never leave it. Every finding carries only the file, line, kind, confidence, a rule-derived mask and a salted one-way fingerprint.
- Worktree files, staged changes, tracked files and (with `--deep`) git history all go through the same redaction path. A regression suite plants canary secrets and asserts they appear in no artifact: report JSON, stdout or stderr.
- Filesystem boundary: file and directory symlinks pointing outside the workspace root are skipped and counted in `stats.skipped_symlinks_outside`.
- Git runs with `GIT_OPTIONAL_LOCKS=0`: the audit cannot refresh or modify the index.
- The scanner writes exactly one file: the report path passed via `--out`.

## What it checks

| Block | What it finds |
|---|---|
| Loading chain | which harness is actually used (zcode, claude, codex by freshness); instructions kept for a dead harness |
| Instruction files | dead links, paths and commands; drifted AGENTS.md + CLAUDE.md pairs; generic overview blocks in auto-loaded context |
| Context tax | weight of session files: project file against a 16 KB benchmark, memory index against 24.4 KB / 200 lines |
| Repos and folders | folder classification; remote is external hosting or self-hosted; credentials in URLs; second checkout of the same repo; nested repos |
| Sync mechanics | `.git/hooks` flags (`add -A`, push, secret scan), sync commits in the last 30 days, `.gitignore` |
| Secrets | tokens, passwords, AWS-style keys and private-key headers in files, in the git index, in remote URLs (values redacted to a mask and a salted fingerprint); git history with `--deep` |
| Skills | descriptions over 1024 chars (the skill will not load), descriptions without triggers, drifted copies |
| Hygiene | name-based junk (final/version/copy/old/temp, logs, drafts, `node_modules` and other build dirs, in English and Russian), hash-proven duplicates, files over 5 MB, empty folders |

Everything rolls up into nine gates with four statuses: pass, warn, fail and unknown. Unknown means the check could not run (missing data never reads as a pass). Gates and typed findings are separate: findings carry their own severity (critical/high/medium/low/info) and status. After instruction edits the skill still offers the old ninth-check practice: a before/after measurement of auto-load weight plus a typical task run.

## The nine gates

| # | Gate | What fails it |
|---|---|---|
| 1 | Workspace structure | A drifted AGENTS.md/CLAUDE.md pair at one level; nested repositories warn |
| 2 | Configuration integrity | A config file that does not parse or has duplicate keys; finding no configs at all is a warn |
| 3 | Rules consistency | Dead references and drifted pairs; boilerplate, files over 16 KB and chains over 32 768 bytes warn |
| 4 | Directory ownership and discoverability | A heavy non-build directory outside every git repo; loose top-level folders warn |
| 5 | Skills and agent capabilities | Missing or unparseable frontmatter, descriptions over 1024 chars, diverged copies; trigger-less descriptions warn |
| 6 | Secrets and Git security | Exposed, staged or tracked secrets, credentials in remote URLs; absence of a secret-prevention hook is never a pass |
| 7 | Git hygiene | A tracked file over 5 MB; dirty worktrees, missing .gitignore and duplicate checkouts warn |
| 8 | Agent environment governance | Instructions maintained for a dead harness; duplicate keys in MCP configs |
| 9 | Workspace health and maintainability | Junk plus build artifacts over 500 MB; classified junk, many empty dirs, occasional harnesses and large untracked files warn |

## Limits and thresholds

| Threshold | Value |
|---|---|
| Project instruction file benchmark | 16 KB |
| Memory index | 24.4 KB or 200 lines, whichever comes first |
| AGENTS.md chain budget (root + nested) | 32 768 bytes (Codex truncation) |
| Skill description | 1024 chars |
| Duplicate hash window | 1-50 MB |
| Large file threshold | 5 MB |
| Harness considered abandoned | after 90 days idle |

## Install

Claude Code / Z Code:

```
/plugin marketplace add vonavikon/workspace-audit
/plugin install workspace-audit@workspace-audit
```

Then tell the agent "run a workspace audit" and name a folder if needed.

The scanner also runs standalone, without an agent:

```
python skills/workspace-audit/scripts/audit_scan.py <path> --home <home> --out scan.json
```

Flags:

- `--home` — enables harness, memory and user-skill checks; defaults to the user profile.
- `--deep` — adds secret scanning of git history; slower on large repos.
- `--baseline <old scan.json>` — adds a diff section with new and resolved findings; fingerprints are stable across runs.

## Demo

Builds a synthetic workspace with all the typical problems and runs the scanner over it:

```
python demo/setup_demo.py
python skills/workspace-audit/scripts/audit_scan.py demo/employee-workspace --home demo/fake-home --out demo-scan.json
```

All tokens and hosts in the fixtures are synthetic.

## Report and exports

The skill writes `AUDIT-<date>.md`: executive summary, overall status (`FAIL` / `NEEDS ATTENTION` / `PASS`), gate results, findings by severity and recommended actions. A sample for a messy workspace: [docs/sample-report.md](docs/sample-report.md). The generators are deterministic and need no model:

```
python skills/workspace-audit/scripts/report_generator.py <scan.json> --out AUDIT.md
python skills/workspace-audit/scripts/sarif.py <scan.json> --out report.sarif
python skills/workspace-audit/scripts/workspace_audit.py --help
```

`sarif.py` writes SARIF 2.1.0 for CI integrations (one rule per gate, one result per fail/warn finding, stable fingerprints). `workspace_audit.py` is the single entry point: `audit --focus security|structure|agents`, `compare` (NEW/RESOLVED/PERSISTING/CHANGED against a baseline), `explain <fid>`, and `fix <fid>` — plan-only by default.

For non-technical readers there is a plain-language value report (English and Russian): what is wrong in human words, what it costs (extra tokens every session with the assumption printed, disk space, secrets in plain sight), and — with a second scan after cleanup — what got better. Samples: [EN](docs/sample-human-report.md), [RU](docs/sample-human-report.ru.md).

```
python skills/workspace-audit/scripts/report_human.py <scan.json> --lang ru [--after <scan2.json>]
```

And for people who do not want to read reports at all, the safe-cleanup wizard tidies up with near-zero risk: a plain-word preview, a typed YES, everything recoverable:

```
python skills/workspace-audit/scripts/safe_clean.py <root>
```

It only touches regenerable caches, empty folders and confirmed junk (aged, untracked, unreferenced, lockfile-backed `node_modules` only); build dirs modified within the last 7 days are skipped as active installs; tracked files, files with keys and anything uncertain are never touched; every movable item goes to `.workspace-audit-trash/` first. Design rationale and sources: [docs/research-human-layer.md](docs/research-human-layer.md).

Remediation is a separate, never-automatic mode (`remediate.py`): it plans a fix, requires an explicit `yes` before `--apply` touches anything, and re-audits afterwards. V1 supports three fix types: removing empty directories, creating a `.gitignore` from the template, and moving confirmed junk into `.workspace-audit-trash/`.

## Documentation

[Quick start](docs/quickstart.md) · [Architecture](docs/architecture.md) · [Gates methodology](docs/gates.md) · [Configuration and exclusions](docs/configuration.md) · [CLI reference](docs/cli.md) · [Troubleshooting](docs/troubleshooting.md) · [Contributing](docs/contributing.md) · [Changelog](CHANGELOG.md) · [Release process](RELEASE.md) · [Report JSON schema](docs/schema/report-schema.json)

## QA

```
cd qa && python eval.py
```

Three scenario fixtures with expected results locked in `expected.json` before the run; the runner compares the scanner's actual JSON against the expected one and writes a report. Current result: 71/71. Latest report: `qa/QA-EVAL-*.md`.

The deterministic core also has a unit and security-regression suite:

```
python -m unittest discover -s tests
```

23 tests, including canary-secrets redaction across worktree/staged/tracked/history artifacts and a read-only git-index check.

## Methodology

The split is deterministic scan first, LLM interpretation second: the scanner produces facts, and the language model only judges which facts are findings. This mirrors how industry audit tools place the LLM strictly above findings rather than in the collection path, and it follows context-file hygiene research showing that instruction weight and staleness directly affect agent behavior. Details: [docs/methodology.md](docs/methodology.md).

## Limitations

- Reports are in English.
- The LLM layer of the skill is not covered by the QA eval; the eval covers the deterministic core only.
- Remote classification knows only external hosting vs self-hosted; it does not know your organization.
- Skill versions in the CLI plugin cache are not treated as drift: the cache is managed by the CLI.
- Junk heuristics are name-based and bilingual (en/ru); tune expectations accordingly.
- The symlink boundary regression test skips on systems that forbid creating symlinks (Windows without Developer Mode); the boundary guard itself is always active.
- Remediation supports three fix types in v1 (empty dirs, .gitignore template, confirmed junk to trash); everything else reports `unsupported` instead of improvising.

## License

MIT.
