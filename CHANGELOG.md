# Changelog

All notable changes to agents-doctor are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions
follow semantic versioning.

## [2.0.0] - 2026-11-17

Universal AI-agent workspace auditor: harness intelligence, instruction
intelligence, local web UI. Backward compatible: CLI subcommands, JSON
report shape, fid prefixes and all nine gates preserved; v1 scans still
compare via --baseline.

### Harness intelligence (TZ phases 1, 5, 7)

- Adapter registry + documented contract (harness/base.py): detection,
  instruction sources, loading resolution, config files, validation,
  spec provenance (source URL, verified date, known limitations).
- Eight adapters: Claude Code, OpenAI Codex, Cursor, Gemini CLI,
  OpenCode, GitHub Copilot, Windsurf, Z Code. Per-harness checks with
  stable check_ids (CLAUDE_SETTINGS_PERMISSIONS_WILDCARD,
  CODEX_SANDBOX_DANGER, CURSOR_GLOB_NOMATCH, ...).
- Honest detection: markers + activity; one stale file is 'possible',
  never proof of use. Spec matrix generated from the registry
  (tools/gen_harness_matrix.py, docs/HARNESS-MATRIX.md).
- The four hand-synced harness lists found by the Phase 0 audit are
  gone; audit_scan/enrich/gates query the registry.
- External adapters: explicit opt-in via .agents-doctor.toml
  [plugins] adapters = [...]; never auto-discovered, isolated on
  failure (harness/external.py).

### Instruction intelligence (TZ phase 2)

- Loading simulation per harness for any target directory:
  loaded/overridden/unloaded with reasons, precedence order, labelled
  as a model of the documented rules (approximated=true).
- Deterministic conflicts: contradictions across active sources,
  3-line duplications, cross-harness divergence (warn, never error).
  Same file pair reported once regardless of how many harnesses load
  it. CLI: agents_doctor.py simulate.
- Adapter findings and instruction conflicts join the nine gates with
  stable check_id + harness fields (additive to the report schema).

### Security (TZ phases 3, 11)

- Secret detection quality benchmark (bench/secret_quality.py):
  precision/recall/FPR/FNR over a labeled corpus + separately reported
  adversarial shapes; floors precision>=0.95, recall>=0.95 (CI-gateable).
- Rule improvements from the benchmark: case-insensitive Bearer,
  gh[pousr]_ GitHub token prefixes, secret_key keyword variant.
- MCP env-secret detection in Codex config (masked evidence).

### Remediation (TZ phase 4)

- Crash recovery: incomplete manifest entries detected and recovered
  (rollback or completion, idempotent).
- Concurrency lock (.agents-doctor-trash/.lock, O_EXCL, stale steal).
- Harness-aware fixes keyed by stable check_id (CLAUDE_LOCAL_DEPRECATED
  trash move; legacy-rules migrations as manual plans).
- Re-audit after apply: before/after finding counts.

### Local web UI (Visual TZ phases V1-V4)

- agents_doctor.py ui: localhost-only server over one scan.json.
  Overview, lazy file tree with aggregated problem counts, findings
  explorer with filters/grouping, masked file inspector (secret rules
  applied server-side), TreeMap (density/risk/size), instruction
  simulation, baseline comparison. Read-only; fix plans are dry-run.
  Path containment, 256 KB preview cap, no execution of workspace code.

### Runtime health (TZ phase 6)

- Opt-in runtime module (runtime_health.py): CLI/python/git presence,
  per-harness CLI binaries (--version, timeout-bounded), static MCP
  config validation. Never runs from the scan automatically; zero
  network requests.

## [1.0.0] - 2026-11-17

Production release: renamed to agents-doctor, all P0 hardening complete.

### Breaking changes

- Renamed from workspace-audit to agents-doctor (plugin, skill, command,
  CLI entry point, GitHub repo). Install command is now
  `/plugin marketplace add vonavikon/agents-doctor`.
- FOCUS_SPECS canonical mapping: security=G6,G7; structure=G1,G4,G9;
  agents=G2,G3,G5,G8. Findings filtered by gate ID, not category.

### Security (P0)

- TOCTOU hardening: _pre_operation_check() re-verifies canonical path,
  containment, symlink chain, type, size/mtime before every mutating
  operation (after user confirmation). 8 attack scenarios tested.
- Unified rollback: manifest v2 with rmdir restore (recreates empty dir),
  create_file undo (sha256 match required), create_directory undo.
  Idempotent, detects incomplete operations.
- Remote URL sanitization: git remote credentials never reach artifacts.
- HMAC-SHA256 fingerprints (128-bit) with per-installation key.
- Secret detection: unified rule table (py + POSIX ERE), 12 rule classes,
  ${} template placeholders excluded.
- Git history: bounded scan with --history-depth, --history-all-refs;
  incomplete scan = unknown, never pass.

### Product

- CLI: audit --baseline (diff section), sarif subcommand, focus modes,
  compare, explain, fix (dry-run + --apply)
- Content quality engine: signal-to-noise, generic phrases, contradictions,
  instruction density, redundancy, specificity — integrated into G3 and
  human report (EN/RU)
- Privacy model: fully local by default; LLM context documented honestly
- Safe cleanup: preview, typed YES, trash with manifest, restore command
- Human-readable reports EN/RU with token cost estimates
- SARIF 2.1.0 export for CI integrations
- Logo: pixel-art D + medical cross (Sega style)

### QA

- 485+ tests across unit, integration, security regression, QA eval,
  LLM offline grading, focus engine, TOCTOU attacks, rollback
- CI: Linux, Windows, macOS, Python 3.10 and 3.12
- Per-module coverage floors enforced in CI
- Release ZIP built from explicit allowlist, verified against it

## [0.7.0] - 2026-11-16

### Security

- Remote URLs are sanitized at the source (`sanitize_url.py`): userinfo
  and credential query parameters never reach scan.json, reports,
  stdout or baseline grouping keys; `credentials_in_remote` is computed
  on the raw value before it is dropped; a critical finding now
  recommends rotation. E2E canary: tests/test_remote_leak.py.
- Single source of secret rules (`secret_rules.py`): the file scanner,
  the git-grep filter and the history scanner share one rule table;
  parity corpus (39 lines incl. 14 false positives) pins python and
  ERE sides together. New classes: access tokens, db URLs with
  credentials, AWS secret keys, Google/GitHub/Slack tokens, JWTs.
- Fingerprints switched to HMAC-SHA256 with a per-installation key
  (`fingerprint.py`): 128 bits, key under the user config dir, no
  silent fallback to public hashing (corrupt key fails loudly with a
  remediation hint). Baselines from older versions will show one
  one-time all-new/all-resolved diff (fingerprint format changed).
- Git history scanning is bounded and honest (`history_scan.py`):
  streaming `git log -p`, `--history-depth N` cap, `--history-all-refs`,
  commits_scanned/commits_total reported per repo; an incomplete or
  unrequested history scan makes G6 `unknown`, never pass; history
  secrets now raise critical findings.

### Stage 4 — cleanup and remediation hardening

- `trashops.py`: TOCTOU re-stat before every operation (changed files abort
  with a reason), collision-safe trash destinations, per-run operation ids,
  write-ahead `manifest.json` per trash run, interrupted-run detection,
  and a `restore` command with reverse collision handling.
- `safe_clean.py` / `remediate.py` run all moves through trashops; the
  summary prints the run dir, manifest path and the exact restore command.
  Coverage: safe_clean 94%, remediate 95%, trashops 90%.

### Stage 5 — performance

- `--profile` stage timings; scandir-based traversal with DirEntry stats
  (zero per-file path stats); duplicates hashed only within size-collision
  groups, two-stage (4 KB head, then full); one shared, 8-thread read pass
  for duplicate sampling and secret scanning (one open per file).
- Local Windows, same workspaces: medium (11,964 files) 123.0 s -> 21.4 s,
  large (59,634 files) 581.9 s -> 82.2 s; results byte-identical before
  and after (files, junk, duplicates, secrets, gates).
- CI gains a windows benchmark job with wall targets (small <=10 s,
  medium <=60 s) alongside the linux one.

### Stage 6 — LLM evaluation

- `llm-eval/run_eval.py`: offline / online / replay runner over frozen
  fixtures; OpenAI-compatible adapter (stdlib urllib); adversarial fixture
  generator (conflicting instructions, injected markers, unknown-heavy,
  malformed input); automated R1-R7 grading plus input validation; runs
  offline in CI with zero network.

### Stage 7 — packaging, docs, QA

- Release zip built from an explicit allowlist and verified against it
  (no tests/bench/CI files inside); per-module coverage floors in CI
  (secret_scanner 95, core modules 90); link check and offline llm-eval
  as CI jobs; README/CLI/configuration docs synced with actual numbers.

## [0.6.0] - 2026-11-16

The human layer: value-first reporting and safe cleanup.

### Added

- `report_human.py`: plain-language report (EN/RU) — what is wrong in human
  words, what it costs (token ranges with printed assumptions, disk value,
  secrets in plain sight), and a before/after story with `--after`.
- `safe_clean.py`: guided cleanup for non-technical users — plain-word
  preview, typed YES, trash-first recovery, hard never-touch rules.
- Research note `docs/research-human-layer.md` with applied/declined
  findings and sources.
- Sample human reports (EN/RU), `/agents-doctor human` and `clean`
  command routing, CLI/docs updates.

### Changed

- Safe-cleanup guards from the research: node_modules without a sibling
  lockfile is cautious-tier; build dirs modified within 7 days are skipped
  as active installs.

## [0.5.0] - 2026-11-16

Stages 4 and 5 of the production-readiness spec: product experience and
guarded remediation. Full spec coverage complete.

### Added

- Stage-4 modules: `report_generator.py` (markdown report from scan JSON),
  `sarif.py` (SARIF 2.1.0 export), `agents_doctor.py` (CLI entry with
  `audit --focus/--report`, `compare`, `explain`, `fix`), `remediate.py`
  (plan-only remediation; `--apply` moves to `.agents-doctor-trash/`).
- Plugin command `/agents-doctor` with focused, compare, explain and fix
  modes.
- Documentation package: quickstart, architecture, gates methodology,
  configuration, CLI reference, troubleshooting, contributing.
- `tools/check_links.py` and `tests/test_check_links.py`: local markdown
  link targets verified in CI-green tests.
- Release tooling: `RELEASE.md`, this changelog.

## [0.4.0] - 2026-11-16

Audit engine and stage-3 QA.

### Added

- Typed findings and declarative gates (stage 2): `report_model.py` with
  schema 1.0, severity and status as separate axes, empty evidence forcing
  `unknown`; `gates.py` with the nine spec-named gates in `GATE_DEFS`,
  `GATE_POLICY` as the single threshold source, missing facts yielding
  `unknown` never `pass`, and G6 secret prevention held to a warn floor;
  `enrich.py` with config parse integrity and duplicate-key detection,
  heavy dirs outside git, junk classification (confirmed/potentially/unknown
  with git/reference/age signals), capped harness states, skills frontmatter
  via optional PyYAML with an honest fallback.
- Integration suite (stage 3): 12 fixtures per spec including
  prompt-injection twins; the suite surfaced 3 real bugs, fixed and pinned
  by `tests/test_stage3_fixes.py`.
- Benchmarks: deterministic workspace generator (small/medium/large) and a
  dual-measurement runner (subprocess wall time + tracemalloc peak alloc);
  recorded 817 / 11 964 / 59 634 files.
- Tools: `validate_manifest.py` (manifest cross-check) and
  `validate_schema.py` (draft-07 report schema with structural fallback).
- LLM-eval kit: frozen scan fixtures, rubric R1-R7, deterministic
  `grade_report.py` for the model layer.
- CI: ruff error lint, ubuntu/windows/macos test matrix plus a 3.10
  compatibility job, coverage with subprocess instrumentation, manifest and
  schema validation, benchmark wall caps, tagged release packaging.

### Fixed

- Platform crashes from the first CI run: `Path.exists()` raises
  `PermissionError` under mode-000 directories, so all existence probes on
  iterated paths go through a safe wrapper; the top-level file branch stats
  with an `OSError` guard (symlinked files on symlink-capable Windows).
- Test F10 asserted path absence where the locked directory legitimately
  appears as a structural observation; it now asserts content
  non-disclosure: no secret-category findings referencing the dir and the
  planted token absent from the whole report.
- `.coverage*` in `.gitignore` swallowed `.coveragerc`, so the coverage
  config never reached the runner; the ignore pattern now matches only the
  `.coverage` artifacts, and the pre-tomllib compatibility job moved from
  3.9 to 3.10.

Suite at release: 112 tests OK (4 OS-skip), scenario eval 77/77, coverage
100/90 against targets 90/85.

## [0.3.0] - 2026-11-16

Security foundation (stage 1).

### Added

- Unified `secret_scanner.py`: detection and redaction in one module, raw
  values never leave it; salted one-way fingerprints stable across runs.
- Filesystem boundary: symlinks pointing outside the workspace root are
  skipped and counted in `stats.skipped_symlinks_outside`.
- Read-only git: every git call runs with `GIT_OPTIONAL_LOCKS=0`, so the
  audit cannot refresh or modify the index.
- Security-regression suite: canary secrets planted in worktree, staged,
  tracked and history artifacts, asserted absent from report JSON, stdout
  and stderr.

Scenario eval at this stage: 71/71.

## [0.2.1] - 2026-11-16

English public release.

### Changed

- Reports and documentation switched from Russian to English; public
  marketplace listing; README rewritten for the public audience.

## [0.2.0] - 2026-11-02

### Added

- Baseline diff: `--baseline <old scan.json>` adds a diff section with new
  and resolved findings; fingerprinted findings are stable across runs, so
  a diff always means a real change.

## [0.1.0] - 2026-10-30

Initial release.

### Added

- Deterministic scanner (`audit_scan.py`, stdlib only) and the skill
  orchestrator: loading chain, instruction files, context tax, repos and
  folders, sync mechanics, secrets, skills, hygiene; the nine-gates report.

Note: 0.1.0 and 0.2.0 are the Russian-language era before the public
repository; this repository's history starts at the 0.2.1 import, so their
entries are reconstructed from release notes.
