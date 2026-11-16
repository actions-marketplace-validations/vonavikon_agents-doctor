# workspace-audit

Read-only workspace auditor for agent-driven setups (Claude Code, Z Code compatible). Finds stale instruction files, abandoned repos, folders outside git, junk, duplicates, secrets and drifted skills. The report stays local, there is no telemetry, and nothing is deleted.

## How it works

Two layers:

1. A deterministic scanner, `audit_scan.py`: pure Python stdlib, no dependencies, offline, about 0.5 s on a mid-size folder on a warm cache. It walks the workspace and writes JSON.
2. The skill orchestrator: reads the JSON, filters false positives, and writes `AUDIT-<date>.md` with a gates table and cleanup commands.

The scanner only reads. Deletions and edits always stay with the human.

## What it checks

| Block | What it finds |
|---|---|
| Loading chain | which harness is actually used (zcode, claude, codex by freshness); instructions kept for a dead harness |
| Instruction files | dead links, paths and commands; drifted AGENTS.md + CLAUDE.md pairs; generic overview blocks in auto-loaded context |
| Context tax | weight of session files: project file against a 16 KB benchmark, memory index against 24.4 KB / 200 lines |
| Repos and folders | folder classification; remote is external hosting or self-hosted; credentials in URLs; second checkout of the same repo; nested repos |
| Sync mechanics | `.git/hooks` flags (`add -A`, push, secret scan), sync commits in the last 30 days, `.gitignore` |
| Secrets | tokens and passwords in files, in the git index, in remote URLs (values masked); git history with `--deep` |
| Skills | descriptions over 1024 chars (the skill will not load), descriptions without triggers, drifted copies |
| Hygiene | name-based junk (final/version/copy/old/temp, logs, drafts, `node_modules` and other build dirs, in English and Russian), hash-proven duplicates, files over 5 MB, empty folders |

Everything rolls up into nine pass/fail gates. The ninth, "instruction changes are verified by a run", is beyond the scanner by nature: after instruction edits the skill offers a before/after measurement of auto-load weight plus a typical task run.

## The nine gates

| # | Gate | What fails it |
|---|---|---|
| 1 | One instruction file per level; duplicates are identical or a pointer | An AGENTS.md/CLAUDE.md pair at the same level that differs in content |
| 2 | Auto-loaded context has no generic or overview blocks | Template phrases and overview sections in files the harness loads automatically |
| 3 | All cross-references in instruction files resolve | Dead links, paths and commands |
| 4 | Every folder has a decided fate; valuable data is under version control | Folders outside git, unclassified data, uncommitted work |
| 5 | Auto-push only for personal storage; publishing requires confirmation | Push hooks without a confirmation step |
| 6 | No keys in tracked files or URLs; secret scan in the commit chain | Token-like strings in the git index, credentials embedded in remote URLs, no secret scan before push |
| 7 | Skills: descriptions with triggers under 1024 chars, no drifted copies | Over-limit or trigger-less descriptions; same skill name with different content |
| 8 | Every rule has one owner file; copy drift excluded by design | The same rule maintained in several files |
| 9 | Instruction changes are verified by a run, not a feeling (always MANUAL, the skill offers the measurement) | Edits to instruction files without a before/after auto-load measurement and a typical task run |

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

## QA

```
cd qa && python eval.py
```

Three scenario fixtures with expected results locked in `expected.json` before the run; the runner compares the scanner's actual JSON against the expected one and writes a report. Current result: 71/71. Latest report: `qa/QA-EVAL-*.md`.

## Methodology

The split is deterministic scan first, LLM interpretation second: the scanner produces facts, and the language model only judges which facts are findings. This mirrors how industry audit tools place the LLM strictly above findings rather than in the collection path, and it follows context-file hygiene research showing that instruction weight and staleness directly affect agent behavior. Details: [docs/methodology.md](docs/methodology.md).

## Limitations

- Reports are in English.
- The LLM layer of the skill is not covered by the QA eval; the eval covers the deterministic core only.
- Remote classification knows only external hosting vs self-hosted; it does not know your organization.
- Skill versions in the CLI plugin cache are not treated as drift: the cache is managed by the CLI.
- Junk heuristics are name-based and bilingual (en/ru); tune expectations accordingly.

## License

MIT.
