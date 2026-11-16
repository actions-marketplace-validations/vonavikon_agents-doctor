# Quickstart

## Install

As a Claude Code / Z Code plugin:

```
/plugin marketplace add vonavikon/agents-doctor
/plugin install agents-doctor@agents-doctor
```

Installed as a plugin, the agent resolves the script locations itself
(`${CLAUDE_PLUGIN_ROOT}` in Claude Code, the skill directory in Z Code);
the standalone commands below assume a checkout of this repository.

Then tell the agent "run a workspace audit" and name a folder if the
current one is not the target.

Standalone, without an agent (Python 3.10+, no dependencies):

```
python skills/agents-doctor/scripts/audit_scan.py <path> --home <home> --out scan.json
```

## First run

Ask the agent to run a workspace audit. The plugin runs the deterministic
scanner over the folder, reads the JSON it produces, filters false
positives and writes the report. Without an agent, run the scanner
yourself and read `scan.json`; a stage-4 CLI entry
(`scripts/agents_doctor.py`) can also turn it into a markdown report.

## Reading the report

The report is a gates table first, then findings grouped by block. Two
scales are in play and they are independent:

- Gate and finding status: `pass`, `fail`, `warn`, `unknown`,
  `not_applicable`. Status is the outcome of a check.
  `unknown` means the check could not run: missing data never reads as a
  pass. `not_applicable` means the check had nothing to look at (for
  example git hygiene in a workspace with no repositories).
- Finding severity: `critical`, `high`, `medium`, `low`, `info`. Severity
  is the impact when a check does not pass.

A low-severity finding can fail a gate; a critical-severity finding is
always a fail. Start with failed gates, then sort findings by severity.

## The three flags

| Flag | Effect |
|---|---|
| `--home <dir>` | Home directory for harness, memory and user-skill checks. Defaults to the user profile. Point it at a fixture home when scanning synthetic workspaces. |
| `--deep` | Also scans git history for secrets. Slower on large repositories; run it when a secret may already be in history. |
| `--baseline <old scan.json>` | Adds a diff section: findings that are new since the old scan and findings that resolved. Fingerprints are stable across runs, so a diff is a real change. |

## Where files land

| File | What it is |
|---|---|
| `<root>/agents-doctor-scan.json` | Scanner output: facts, nine gates, typed findings. Keep it; it is the baseline for the next compare. |
| `<root>/AUDIT-<date>.md` | The readable report written by the skill (or by `report_generator.py`). |

Both files stay in the audited root. Nothing else is written anywhere.

## What the plugin never does

- Deletes, moves or edits anything. The scanner reads; the report ends
  with commands you run yourself.
- Sends data anywhere. No telemetry, no network access; the scanner works
  offline.
- Writes secret values. Detections carry a mask and a salted fingerprint
  only; the value never enters the JSON, the report or the chat.
- Follows symlinks out of the workspace. Links pointing outside the root
  are skipped and counted in `stats.skipped_symlinks_outside`.
