---
description: Run a workspace audit (full or focused: security, structure, agents; also human report, safe clean, compare, explain, fix)
---

# /agents-doctor

Parse `$ARGUMENTS` and route to one of the modes below. When several
folders could be the audit root, ask the user first. The scanner is
read-only; secrets stay masked in every output; nothing is ever deleted in
bulk.

## Locating the scripts (do this first)

The entry scripts live at `<PLUGIN_ROOT>/skills/agents-doctor/scripts/`.
Resolve `<PLUGIN_ROOT>` exactly one of these ways, in order:

1. Claude Code command context: the `${CLAUDE_PLUGIN_ROOT}` variable (use it
   directly in the commands below).
2. Otherwise: the plugin root is the parent directory of the folder that
   contains this command file (`commands/` lives at the plugin root).
3. If neither is knowable, ask the user for the installed plugin location;
   never search the current project for the scripts.

Replace `${CLAUDE_PLUGIN_ROOT}` below with the resolved value. All scripts
work from any current directory: they resolve their own dependencies.

## `human` (for non-technical readers)

Generate the plain-language value report from the last scan (or run a fresh
one first): `python "${CLAUDE_PLUGIN_ROOT}/skills/agents-doctor/scripts/report_human.py <scan.json> --lang en|ru [--after <scan2.json>]`.
It answers, in human words: what is wrong, what it costs (extra tokens every
session with the assumption printed, disk space, secrets left in plain
sight), and — after a cleanup, with `--after` — what got better. Post a
2-3 sentence chat summary from its "short version" section; offer `safe
clean` as the next step for users who want action without reading reports.

## `clean` (safe cleanup for non-technical users)

Run the guided cleanup wizard: `python "${CLAUDE_PLUGIN_ROOT}/skills/agents-doctor/scripts/safe_clean.py <root>`.
Walk the user through it. Rules the agent must keep: show the preview
categories and sizes in plain words; the fixed "will NOT touch" line is
non-negotiable (tracked files, files with keys, anything the audit is
unsure about); confirmation is the user typing YES themselves — never
confirm on their behalf, never pass --yes; everything movable goes to the
`.agents-doctor-trash` folder and can be restored; after cleanup offer
to re-run the audit and produce the human before/after report with
`--after`.

## no arguments or `full`

Run the full audit exactly per the workflow in
[SKILL.md](../skills/agents-doctor/SKILL.md): scan, filter false
positives, write `AUDIT-<date>.md`, post the chat summary (gate statuses,
the most important finding, path to the report).

## `security` / `structure` / `agents`

Run the same full scan, but the report and the chat summary cover only the
gates of the requested focus:

| Focus | Gates |
|---|---|
| security | G6 Secrets and Git security, G7 Git hygiene |
| structure | G1 Workspace structure, G4 Directory ownership, G9 Workspace health |
| agents | G2 Configuration integrity, G3 Rules consistency, G5 Skills, G8 Agent environment governance |

The scan itself is never narrowed: the same `agents-doctor-scan.json` is
produced, only the reporting filters.

If the stage-4 CLI entry is present, offer the deterministic focus first:

```
python "${CLAUDE_PLUGIN_ROOT}/skills/agents-doctor/scripts/agents_doctor.py audit <root> --focus security
```

If it is not available, filter the JSON yourself: keep the gates of the
focus, keep `findings_detailed` entries whose `gate` field belongs to them,
and drop the other report sections.

## `compare`

Run the audit with a baseline against the previous scan:

```
python "${CLAUDE_PLUGIN_ROOT}/skills/agents-doctor/scripts/audit_scan.py <root> --home <home> \
    --baseline <root>/agents-doctor-scan.json --out <root>/agents-doctor-scan-new.json
```

If no previous `agents-doctor-scan.json` exists in the root, say so and
offer a full audit instead. Then summarize four groups:

- NEW: fingerprints present only in the new scan
- RESOLVED: fingerprints present only in the old scan
- PERSISTING: same fingerprint in both, same severity and status
- CHANGED: same fingerprint in both, but severity or status differs

Finish with one line on whether the workspace got better or worse.

## `explain <fid>`

Find the finding with this `fid` in the scan JSON of the current root and
print it: title, description, evidence (file, line, mask, fingerprint),
severity, status, confidence, recommendation. Walk the user through what it
means and what the recommendation does. Never expand a mask or fingerprint
into a value. If the fid does not exist, list the fids that do.

## `fix <fid>`

Remediation is plan-only first, always:

1. Produce the plan without touching anything:
   `python "${CLAUDE_PLUGIN_ROOT}/skills/agents-doctor/scripts/remediate.py <scan.json> --fid <fid>`
2. Show the plan to the user: what will be moved where, what command would
   be run, what stays untouched.
3. Ask for an explicit confirmation ("apply"). A vague or missing answer
   means no.
4. Only after confirmation run the same command with `--apply`. Moved files
   go to `.agents-doctor-trash/`, never to a direct delete.
5. Re-run the audit and show the gate status before and after.

If the finding has `autofix_available: false`, say so and give the
recommendation as commands the user runs.

## anything else

Reply with this usage list and stop:

```
/agents-doctor                  full audit
/agents-doctor security         only secrets and git security gates
/agents-doctor structure        only layout and ownership gates
/agents-doctor agents           only instruction, skills and config gates
/agents-doctor compare          diff against the previous scan
/agents-doctor explain <fid>    walk through one finding
/agents-doctor fix <fid>        plan a fix (applies nothing without confirmation)
```

## Safety

- Read-only by default; the only write is the report file.
- Secrets stay masked: file, line, kind, mask, salted fingerprint. Never
  reproduce, complete or guess a value.
- No bulk delete. `fix` handles one finding at a time, moves to
  `.agents-doctor-trash/`, and only after an explicit confirmation.
