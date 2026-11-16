# Workspace audit - AUDIT-2026-11-16

Scanned root: X:\Repos\workspace-audit\qa\scenarios\03-leaver-chaos\run\workspace
(frozen chaos fixture, DEMO content). Read-only audit: nothing was modified.

## Gates

| # | Gate | Status | Key evidence |
|---|------|--------|--------------|
| G1 | Workspace structure | fail | drifted config pairs: 1 |
| G2 | Configuration integrity | pass | config files parsed: 1, broken: 0 |
| G3 | Rules consistency | fail | instruction files checked: 5, dead references: 4 |
| G4 | Directory ownership and discoverability | fail | heavy dirs outside git: 1 |
| G5 | Skills and agent capabilities | fail | descriptions over 1024 chars: 1 |
| G6 | Secrets and Git security | fail | secrets found in workspace files: 1 |
| G7 | Git hygiene | warn | repos with uncommitted work: 1 of 3 |
| G8 | Agent environment governance | fail | governance notes: 1 |
| G9 | Workspace health and maintainability | warn | classified junk items: 5 |

6 of 9 gates fail, 2 warn, 1 pass. The workspace still works, but the mess is
big enough to slow every agent down.

## Top recommendation

Top recommendation: rotate the two exposed secrets now - SEC-001 (api-key in
.mcp.json line 6, mask sk-***) and SEC-002 (secret literal tracked in git at
legacy-crm config.py line 1) - at their providers, then remove them from the
files and purge them from history.

## Instruction files

AGENTS.md is 63 KB, far over the 16 KB benchmark (RUL-006), and carries four
dead references (RUL-001 to RUL-004): scripts/deploy.sh, docs/runbook.md,
docs/api.md, config/defaults.yaml. The tools pair AGENTS.md/CLAUDE.md drifted
apart (DIR-001, RUL-007): keep one file as the source and turn the other into
a pointer. tools\CLAUDE.md is still maintained for a harness idle for 200
days (GOV-001).

## Context tax

The AGENTS.md chain is 65447 bytes, over the 32768-byte budget (RUL-008), and
the memory index exceeds both its size and line limits, so its tail is cut
off silently.

## Repositories and folders

exports holds 8 MB of data outside every repository (DIR-003); five top-level
folders have no version control (DIR-004). legacy-crm contains a nested
repository vendor\engine (DIR-002), uncommitted work (GIT-001) and no
secret-scan hook; the same remote is checked out twice (GIT-004). Deletion
candidates for the user to confirm: documents\отчет-v1 (копия).pdf, three
screenshots, старые презентации, Новая папка (HLTH-001 to HLTH-006).

## Secrets

Two critical findings; the values are never reproduced here, only the scanner
masks. SEC-001: .mcp.json line 6, kind api-key, mask sk-***, fingerprint
sha256:424952bbfc6b2068. SEC-002: legacy-crm config.py line 1, fingerprint
sha256:d65e365cdae5b78b. No pre-commit/pre-push secret scan exists in any of
the 3 repositories (SEC-003).

## Skills

x-helper exists in two diverged copies (SKL-005) and one description is 1190
chars, over the 1024 limit (SKL-003); the harness will not load it. Both
x-helper copies and doc-helper lack trigger phrases (SKL-001, SKL-002,
SKL-004).

## Verification

This audit changed nothing. Re-run it yourself after cleanup and compare:

```
git -C legacy-crm stash list
git -C legacy-crm rm --cached config.py
python skills/workspace-audit/scripts/audit_scan.py . --out re-scan.json
```
