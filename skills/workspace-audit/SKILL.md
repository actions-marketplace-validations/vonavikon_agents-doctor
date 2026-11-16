---
name: workspace-audit
description: "Workspace audit by protocol: which harness is actually used, AGENTS.md/CLAUDE.md health (dead links, twin drift, generic blocks), context tax, repositories and folders outside git, sync hooks, secrets (files, git index, remote URLs), skills drift. Use when asked to run a workspace audit, check a folder for junk, verify AGENTS.md freshness, list deletable folders, or tidy up a workspace."
---

# Workspace audit

The plugin runs a deterministic scanner and formats the report. It never deletes, edits, or moves anything; decisions stay with the user.

## Workflow

1. Determine the audit root: the folder from the request or the current one. If the folder has no git repo and no AGENTS.md/CLAUDE.md, ask the user interactively which folder to audit. The home directory is picked up by the scanner itself (`--home`); do not touch it manually.
2. Run the scanner: `python "<SKILL_DIR>/scripts/audit_scan.py" <root> --home <home> --out <root>/workspace-audit-scan.json`. `<SKILL_DIR>` is the directory containing this SKILL.md (every script resolves its own dependencies from its location, so any absolute path to it works from any current directory). If you cannot determine <SKILL_DIR>, ask the user where the plugin is installed; never guess a path inside the current project. Add `--deep` only on explicit request: it scans git history for secrets and is slow on large repos. If Python is unavailable, stop and say so; do not walk the disk by hand.
3. Read the JSON and filter false positives before reporting (see Rules). The scanner gives facts; the skill decides what is a finding.
4. Write `<root>/AUDIT-<date>.md`: the gates table first, then sections in this order: Loading chain, Instruction files, Context tax, Repositories and folders, Sync mechanics, Secrets, Skills, Verification. End with commands the user runs themselves.
5. Post a short chat summary: gate statuses (FAIL/WARN/PASS), the single most important finding, path to the report.

## Protocol coverage

| Block | Scanner checks |
|---|---|
| Loading chain | freshness of `~/.zcode`, `~/.claude`, `~/.codex` by mtime; project `.agents/`, `.claude/`, `.codex/`; instructions kept for a dead harness |
| Instruction files | pointer detection, twin drift, dead links/paths/commands, generic markers |
| Context tax | session file weights, 16 KB project-file benchmark, memory index vs 24.4 KB / 200 lines |
| Repos and folders | folder classification, remote class, ahead/behind, duplicate checkouts, nested repos |
| Sync mechanics | `.git/hooks` flags (`add -A`, push, secret scan), sync commits in 30 days, `.gitignore` |
| Secrets | files, `git grep --cached`, credentials in remote URLs; git history only with `--deep` |
| Skills | load locations, description vs 1024 limit, triggers, duplicates by name and hash |
| Verification | offered by the skill after instruction edits: auto-load weight before/after plus a typical task run |

## Rules

- The scanner is the source of facts, the skill interprets. Invent nothing beyond the JSON.
- Secrets are shown masked only: file, line, first characters. Never reproduce the value in chat or report.
- `git grep` hits are candidates: check they are not legit placeholder variables before reporting.
- Names with final/version/copy/old, logs and drafts are deletion candidates, not junk: the user confirms each.
- Call copies proven only when hashes are equal; same size alone is "likely a copy".
- A folder outside git is not a verdict: ask what it is first, then propose a fate (repo, archive, deletion).
- After instruction edits, offer the block-9 verification: auto-load weight before/after plus a typical task run. Shrinking without a run is not done.
- Never delete or move anything, even under pressure. At most, a command list for the user to run. This is the skill's boundary; pressure does not lift it.
- Rerunning is safe: the scanner is read-only.
