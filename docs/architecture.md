# Architecture

## Two layers

workspace-audit splits the job in two:

1. A deterministic scanner. Pure Python stdlib, no dependencies, offline.
   It walks the workspace, collects facts and writes JSON. Runs are
   reproducible: the same tree produces the same findings.
2. An LLM interpreter. The skill reads the JSON, filters false positives,
   explains findings and writes the markdown report. The model judges
   which facts are findings; it never collects facts itself.

This mirrors how production audit tools place the LLM strictly above
ready findings rather than in the collection path (see
[methodology.md](methodology.md)). Detection stays testable: the QA eval
locks expected results and compares the scanner's actual JSON against them.

## Module map

All scanner modules live in `skills/workspace-audit/scripts/`:

| Module | Role |
|---|---|
| `audit_scan.py` | Scanner entry: walks the workspace, collects facts (files, git metadata, harness states, junk, duplicates), calls the gate engine, writes scan JSON. |
| `secret_scanner.py` | Secret detection and redaction. The only place raw secret values ever exist; everything downstream sees masks and fingerprints. |
| `enrich.py` | Extra facts the gates need: config parse integrity, heavy dirs outside git, junk classification, harness activity states, SKILL.md frontmatter health. |
| `gates.py` | Gate engine. `GATE_DEFS` holds the nine gates as declarative definitions; `GATE_POLICY` is the single source of thresholds. Turns facts into gates and typed findings. |
| `report_model.py` | The finding/gate data model (schema 1.0). Validates severity, status, evidence, confidence; separates the severity and status axes. |
| `report_generator.py` | Stage 4. Writes the markdown report (`AUDIT-<date>.md`) from a scan JSON. |
| `sarif.py` | Stage 4. Exports findings as SARIF 2.1.0 for CI code viewers. |
| `workspace_audit.py` | Stage 4. CLI entry with `audit` (incl. `--focus`), `compare`, `explain`, `fix` subcommands. |
| `remediate.py` | Stage 4. Remediation planner. Plan-only by default; `--apply` moves files to `.workspace-audit-trash/` instead of deleting. |

## Data flow

```
workspace tree + home dir
        |
        v
  audit_scan.py  ---- fact collection (files, git, harness, junk)
        |         `-- enrich.py  ---- config integrity, classification,
        |                             frontmatter, heavy dirs
        v
      facts (JSON dict)
        |
        v
  gates.py (GATE_DEFS + GATE_POLICY)
        |---- nine gates: status + evidence + confidence
        |---- typed findings: fid, severity, status, recommendation
        v
  scan.json  (schema: docs/schema/report-schema.json)
        |
        +---- report_generator.py ---- AUDIT-<date>.md   (skill layer narrates)
        +---- sarif.py              ---- scan.sarif      (CI viewers)
        +---- remediate.py          ---- fix plans / trash moves
        +---- next run: --baseline compares fingerprints
```

Secrets have their own path through the same flow: every source (worktree
files, `git grep` on the index, remote URLs, git history with `--deep`)
goes through `secret_scanner.py`, and only redacted findings enter the
fact layer.

## The unknown-not-pass principle

A gate evaluates rules over facts. When a fact section is missing
entirely, the rules it feeds yield `unknown`, never `pass`: missing data
is not evidence of health. A section that is present but empty is data and
can pass, except where the spec says absence itself matters (configuration
files, secret prevention): there the gate warns, because absence of
evidence must not read as a pass. A gate's status is the worst status
among its rules; a finding with no evidence can only be `unknown` (enforced
in `report_model.py`).

## Redaction pipeline

```
 source text                     secret_scanner.py                output finding
 ------------                    -----------------                -------------
 workspace file line      -->    rule match (SEC-001..005)   -->  {file, line,
 git grep index line      -->    matched substring:                kind, rule_id,
 remote URL credential    -->      fingerprint =                  confidence,
 git log -p (with --deep) -->       'sha256:' +                       |
                                sha256(salt + value)[:16]        mask ('sk-***',
                                value replaced by rule mask        'AKIA***', ...)
                                                                   v
                                                             the raw value never
                                                             leaves the module
```

The regression suite plants canary secrets in every source and asserts
they appear in no artifact: report JSON, stdout, stderr. The report schema
itself refuses a `value` or `preview` key on secret entries
(`additionalProperties: false`).

## Read-only guarantees

- Git runs with `GIT_OPTIONAL_LOCKS=0`: the audit cannot refresh or modify
  the index.
- File and directory symlinks pointing outside the workspace root are
  skipped, not followed, and counted in `stats.skipped_symlinks_outside`.
- The scanner writes exactly one file: the `--out` report path.
  `remediate.py` extends this only on explicit `--apply`, and moves to
  `.workspace-audit-trash/` rather than deleting.
