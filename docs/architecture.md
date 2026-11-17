# Architecture

## Two layers

agents-doctor splits the job in two:

1. A deterministic scanner. Pure Python stdlib, no dependencies, offline.
   It walks the workspace, collects facts and writes JSON. Runs are
   reproducible: the same tree produces the same findings.
2. An LLM interpreter (optional). The skill reads the JSON, filters false
   positives, explains findings and writes the markdown report. The model
   judges which facts are findings; it never collects facts itself.

This mirrors how production audit tools place the LLM strictly above
ready findings rather than in the collection path (see
[methodology.md](methodology.md)). Detection stays testable: the QA eval
locks expected results and compares the scanner's actual JSON against them.

## Three planes

Since v2.0 the deterministic layer is organized in three planes:

1. **Core** (`audit_scan.py`, `enrich.py`, `gates.py`): the walk, the
   fact collection and the nine gates. Harness-agnostic by contract —
   it asks the registry, never a hardcoded environment.
2. **Harness intelligence** (`harness/`): the registry, one adapter per
   environment (Claude Code, Codex, Cursor, Gemini CLI, OpenCode,
   GitHub Copilot, Windsurf, Z Code), the detection engine and the
   external-plugin loader. Adapters FEED the nine gates via
   `harness/collect.py`; they do not replace them.
3. **Instruction intelligence** (`instructions/`): discovery, resolution
   simulation and deterministic conflict detection across all sources a
   target directory would actually load — including cross-harness
   divergence, reported as warn, never as error.

A fourth, optional plane is the **local web UI** (`ui/`): a localhost
server over one scan.json. Read-only; previews are secret-masked;
fixes are planned but never applied from the browser.

## Data flow and privacy

```
WORKSPACE (files, git, configs)
    │
    ▼  reads only
SCANNER (audit_scan.py)
    │        ├── harness/collect.py ── detection + adapter validation
    │        └── instructions/ ────── conflict simulation at root
    ▼  writes one file
scan.json (facts, redacted secrets, gates, findings, harnesses)
    │
    ├──▶ Markdown report (report_generator.py)     ── local
    ├──▶ Human report EN/RU (report_human.py)      ── local
    ├──▶ SARIF (sarif.py)                          ── local
    ├──▶ Baseline diff (--baseline)                ── local
    ├──▶ Web UI (ui/server.py, 127.0.0.1)          ── local
    │
    └──▶ LLM via AI harness (skill)                ── depends on harness
```

The scanner, all report generators, SARIF export, baseline comparison
and the web UI run entirely offline. Zero network requests, zero
telemetry. The only network socket agents-doctor ever opens is the
localhost listener of `ui` — and file previews there are masked by the
same secret rules before they reach the browser.

When used through an AI harness (Claude Code, Z Code), the model sees the
scan JSON as part of its context. Secret values are already redacted at
this point — the model sees only masks, fingerprints, and metadata. What
the harness does with this context is governed by the harness's own
privacy policy, not by agents-doctor.

## Module map

All scanner modules live in `skills/agents-doctor/scripts/`:

| Module | Role |
|---|---|
| `audit_scan.py` | Scanner entry: walks the workspace, collects facts (files, git metadata, harness states, junk, duplicates), calls the gate engine, writes scan JSON. |
| `harness/` | Registry + adapters + detection + collect bridge + external plugins. See [ADAPTER-GUIDE.md](ADAPTER-GUIDE.md) and [HARNESS-MATRIX.md](HARNESS-MATRIX.md). |
| `instructions/` | Instruction discovery, loading simulation, cross-source conflict detection (contradiction, duplication, divergence). |
| `secret_scanner.py` | Secret detection and redaction. The only place raw secret values ever exist; everything downstream sees masks and fingerprints. |
| `enrich.py` | Extra facts the gates need: config parse integrity, heavy dirs outside git, junk classification, harness activity states, SKILL.md frontmatter health. |
| `gates.py` | Gate engine. `GATE_DEFS` holds the nine gates as declarative definitions; `GATE_POLICY` is the single source of thresholds. Turns facts — including adapter findings — into gates and typed findings. |
| `report_model.py` | The finding/gate data model (schema 1.0). Validates severity, status, evidence, confidence; separates the severity and status axes. Adapter findings carry an extra stable `check_id` and `harness` field. |
| `report_generator.py` | Writes the markdown report (`AUDIT-<date>.md`) from a scan JSON. |
| `sarif.py` | Exports findings as SARIF 2.1.0 for CI code viewers. |
| `agents_doctor.py` | CLI entry: `audit`, `sarif`, `compare`, `explain`, `fix`, `simulate`, `ui`. |
| `remediate.py` | Remediation planner: fid-based and check_id-based fixes, crash recovery, concurrency lock. Plan-only by default; `--apply` moves files to `.agents-doctor-trash/`. |
| `ui/` | Local web UI (localhost server + static SPA). Read-only over one scan.json. |

## Data flow

```
workspace tree + home dir
        |
        v
  audit_scan.py  ---- fact collection (files, git, harness, junk)
        |         |-- enrich.py ---- config integrity, classification,
        |         |                 frontmatter, heavy dirs
        |         |-- harness/collect.py ---- detection per adapter,
        |         |                           adapter validate() findings,
        |         |                           external plugins (opt-in)
        |         `-- instructions/ ---- root-target simulation:
        |                               contradictions, duplications,
        |                               divergences
        v
      facts (JSON dict)
        |
        v
  gates.py (GATE_DEFS + GATE_POLICY)
        |---- nine gates: status + evidence + confidence
        |---- typed findings: fid (counter), check_id (stable),
        |     severity, status, recommendation
        v
  scan.json  (schema: docs/schema/report-schema.json)
        |
        +---- report_generator.py ---- AUDIT-<date>.md   (skill layer narrates)
        +---- sarif.py              ---- scan.sarif      (CI viewers)
        +---- ui/server.py          ---- local browser explorer
        +---- remediate.py          ---- fix plans / trash moves / recovery
        +---- next run: --baseline compares fingerprints
```

Secrets have their own path through the same flow: every source (worktree
files, `git grep` on the index, remote URLs, git history with `--deep`)
goes through `secret_scanner.py`, and only redacted findings enter
the fact layer.

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
 workspace file line      -->    rule match (SEC-001..107)   -->  {file, line,
 git grep index line      -->    matched substring:                kind, rule_id,
 remote URL credential    -->      fingerprint =                  confidence,
 git log -p (with --deep) -->       HMAC-SHA256(salt+value)          |
                                value replaced by rule mask        mask ('sk-***',
                                                                   'AKIA***', ...)
                                                                   v
                                                             the raw value never
                                                             leaves the module
```

The regression suite plants canary secrets in every source and asserts
they appear in no artifact: report JSON, stdout, stderr. The report schema
itself refuses a `value` or `preview` key on secret entries
(`additionalProperties: false`). The web UI masks file previews with the
same rules server-side.

## Read-only guarantees

- Git runs with `GIT_OPTIONAL_LOCKS=0`: the audit cannot refresh or modify
  the index.
- File and directory symlinks pointing outside the workspace root are
  skipped, not followed, and counted in `stats.skipped_symlinks_outside`.
- The scanner writes exactly one file: the `--out` report path.
  `remediate.py` extends this only on explicit `--apply`, and moves to
  `.agents-doctor-trash/` rather than deleting, under a concurrency lock,
  with crash recovery for interrupted runs.
- The web UI binds 127.0.0.1 only, contains every path under the audited
  root, executes nothing from the workspace, and exposes no mutating
  endpoint beyond an in-process rescan.
