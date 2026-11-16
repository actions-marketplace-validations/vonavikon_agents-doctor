# Agents Doctor

Generated 2026-11-16T16:21:28+03:00 | schema 1.0 | rules 0.4.0 | 18 files scanned | 0.5 s

## Executive Summary

Overall status: FAIL.
The scan produced 32 findings (2 critical, 4 high, 9 medium, 16 low, 1 info).
Most important finding: SEC-001 - Exposed secret in .mcp.json:6.
Gates: 6 fail, 2 warn, 1 pass, 0 unknown.
Secret values are redacted in this report; only masks and fingerprints are recorded.

## Overall Workspace Health

Status: FAIL.
- Workspace structure (fail): drifted config pairs: 1
- Rules consistency (fail): instruction files checked: 5, dead references: 4
- Directory ownership and discoverability (fail): heavy dirs outside git: 1
- Skills and agent capabilities (fail): skills checked: 3, frontmatter failures: 0, unverified: 0
- Secrets and Git security (fail): secrets found in workspace files: 1
- Git hygiene (warn): repos with uncommitted work: 1 of 3
- Agent environment governance (fail): governance notes: 1
- Workspace health and maintainability (warn): classified junk items: 5

## Gate Results

| # | Gate | Status | Key evidence |
| --- | --- | --- | --- |
| G1 | Workspace structure | fail | `drifted config pairs: 1` |
| G2 | Configuration integrity | pass | `config files parsed: 1, broken: 0` |
| G3 | Rules consistency | fail | `instruction files checked: 5, dead references: 4` |
| G4 | Directory ownership and discoverability | fail | `heavy dirs outside git: 1` |
| G5 | Skills and agent capabilities | fail | `skills checked: 3, frontmatter failures: 0, unverified: 0` |
| G6 | Secrets and Git security | fail | `secrets found in workspace files: 1` |
| G7 | Git hygiene | warn | `repos with uncommitted work: 1 of 3` |
| G8 | Agent environment governance | fail | `governance notes: 1` |
| G9 | Workspace health and maintainability | warn | `classified junk items: 5` |

## Critical Findings

| fid | severity | title | location |
| --- | --- | --- | --- |
| DIR-001 | high | Drifted AGENTS.md/CLAUDE.md pair in tools | tools |
| RUL-007 | high | Two rule sources at tools | tools |
| SEC-001 | critical | Exposed secret in .mcp.json:6 | .mcp.json:6 |
| SEC-002 | critical | Secret tracked in git at legacy-crm: config.py:1 | config.py:1 |
| SKL-003 | high | Description of skill 'x-helper' is 1190 chars, limit 1024 | X:\Repos\agents-doctor\qa\scenarios\03-leaver-chaos\run\workspace\.agents\skills\x-helper\SKILL.md |
| SKL-005 | high | Diverged copies of skill 'x-helper' | x-helper |

## All Findings

| fid | gate | severity | status | title |
| --- | --- | --- | --- | --- |
| SEC-001 | G6 | critical | fail | Exposed secret in .mcp.json:6 |
| SEC-002 | G6 | critical | fail | Secret tracked in git at legacy-crm: config.py:1 |
| DIR-001 | G1 | high | fail | Drifted AGENTS.md/CLAUDE.md pair in tools |
| RUL-007 | G3 | high | fail | Two rule sources at tools |
| SKL-003 | G5 | high | fail | Description of skill 'x-helper' is 1190 chars, limit 1024 |
| SKL-005 | G5 | high | fail | Diverged copies of skill 'x-helper' |
| DIR-002 | G1 | medium | warn | Nested repository in legacy-crm: vendor\engine |
| DIR-003 | G4 | medium | fail | Heavy directory outside git: exports |
| GOV-001 | G8 | medium | fail | Instructions maintained for a dead harness |
| RUL-001 | G3 | medium | fail | Dead path in AGENTS.md: scripts/deploy.sh |
| RUL-002 | G3 | medium | fail | Dead path in AGENTS.md: docs/runbook.md |
| RUL-003 | G3 | medium | fail | Dead path in tools\AGENTS.md: docs/api.md |
| RUL-004 | G3 | medium | fail | Dead path in tools\CLAUDE.md: config/defaults.yaml |
| RUL-008 | G3 | medium | warn | AGENTS.md chain over 32768 bytes |
| SEC-003 | G6 | medium | warn | No secret-prevention mechanism found |
| DIR-004 | G4 | low | warn | 5 top-level folders outside version control |
| GIT-001 | G7 | low | warn | Uncommitted work in legacy-crm |
| GIT-002 | G7 | low | warn | No .gitignore in legacy-crm-hotfix |
| GIT-003 | G7 | low | warn | No .gitignore in tools |
| GIT-004 | G7 | low | warn | Multiple checkouts of one remote: legacy-crm, legacy-crm-hotfix |
| HLTH-001 | G9 | low | warn | Unused data (potentially_unused): documents\отчет-v1 (копия).pdf |
| HLTH-002 | G9 | low | warn | Unused data (potentially_unused): screenshots\IMG_001.jpg |
| HLTH-003 | G9 | low | warn | Unused data (potentially_unused): screenshots\IMG_2022_09_01.jpg |
| HLTH-004 | G9 | low | warn | Unused data (potentially_unused): screenshots\IMG_2023_04_11.jpg |
| HLTH-005 | G9 | low | warn | Unused data (potentially_unused): старые презентации |
| HLTH-007 | G9 | low | warn | File over 5 MB outside git: exports\data-dump.csv |
| RUL-005 | G3 | low | warn | Generic boilerplate in AGENTS.md: 'структура репозитория' |
| RUL-006 | G3 | low | warn | Instruction file over 16 KB: AGENTS.md |
| SKL-001 | G5 | low | warn | No triggers in the description of skill 'x-helper' |
| SKL-002 | G5 | low | warn | No triggers in the description of skill 'doc-helper' |
| SKL-004 | G5 | low | warn | No triggers in the description of skill 'x-helper' |
| HLTH-006 | G9 | info | pass | 1 empty directories |

## Recommended Actions

1. [SEC-001]: Rotate the secret at its provider, remove it from the file and purge it from history.
2. [SEC-002]: Rotate the secret, `git rm --cached` the file and purge the history.
3. [DIR-001]: Keep one file as the source and turn the other into a pointer to it.
4. [RUL-007]: Keep one file as the source and make the other a pointer (structure view: G1).
5. [SKL-003]: Shorten the description; move details into the skill body.
6. [SKL-005]: Pick one canonical location and delete or sync the rest.
7. [G1]: Fix the layout: one instruction source per level, no nested repositories, project dirs only for harnesses in use.
8. [G3]: Repair dead references, merge drifted pairs, replace boilerplate with project-specific rules.

Read-only audit: nothing was modified. Rerun with --baseline to track drift.
