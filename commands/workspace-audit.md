---
description: Run a workspace audit (full, or focused: security, structure, agents; also compare, explain, fix)
---

# /workspace-audit

Parse `$ARGUMENTS` and route to one of the modes below. When several
folders could be the audit root, ask the user first. The scanner is
read-only; secrets stay masked in every output; nothing is ever deleted in
bulk.

## no arguments or `full`

Run the full audit exactly per the workflow in
[SKILL.md](../skills/workspace-audit/SKILL.md): scan, filter false
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

The scan itself is never narrowed: the same `workspace-audit-scan.json` is
produced, only the reporting filters.

If the stage-4 CLI entry is present, offer the deterministic focus first:

```
python skills/workspace-audit/scripts/workspace_audit.py audit <root> --focus security
```

If it is not available, filter the JSON yourself: keep the gates of the
focus, keep `findings_detailed` entries whose `gate` field belongs to them,
and drop the other report sections.

## `compare`

Run the audit with a baseline against the previous scan:

```
python skills/workspace-audit/scripts/audit_scan.py <root> --home <home> \
    --baseline <root>/workspace-audit-scan.json --out <root>/workspace-audit-scan-new.json
```

If no previous `workspace-audit-scan.json` exists in the root, say so and
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
   `python skills/workspace-audit/scripts/remediate.py <scan.json> --fid <fid>`
2. Show the plan to the user: what will be moved where, what command would
   be run, what stays untouched.
3. Ask for an explicit confirmation ("apply"). A vague or missing answer
   means no.
4. Only after confirmation run the same command with `--apply`. Moved files
   go to `.workspace-audit-trash/`, never to a direct delete.
5. Re-run the audit and show the gate status before and after.

If the finding has `autofix_available: false`, say so and give the
recommendation as commands the user runs.

## anything else

Reply with this usage list and stop:

```
/workspace-audit                  full audit
/workspace-audit security         only secrets and git security gates
/workspace-audit structure        only layout and ownership gates
/workspace-audit agents           only instruction, skills and config gates
/workspace-audit compare          diff against the previous scan
/workspace-audit explain <fid>    walk through one finding
/workspace-audit fix <fid>        plan a fix (applies nothing without confirmation)
```

## Safety

- Read-only by default; the only write is the report file.
- Secrets stay masked: file, line, kind, mask, salted fingerprint. Never
  reproduce, complete or guess a value.
- No bulk delete. `fix` handles one finding at a time, moves to
  `.workspace-audit-trash/`, and only after an explicit confirmation.
