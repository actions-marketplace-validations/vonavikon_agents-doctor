# Changelog

All notable changes to workspace-audit are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions
follow semantic versioning.

## [0.5.0] - 2026-11-16

Stages 4 and 5 of the production-readiness spec: product experience and
guarded remediation. Full spec coverage complete.

### Added

- Stage-4 modules: `report_generator.py` (markdown report from scan JSON),
  `sarif.py` (SARIF 2.1.0 export), `workspace_audit.py` (CLI entry with
  `audit --focus/--report`, `compare`, `explain`, `fix`), `remediate.py`
  (plan-only remediation; `--apply` moves to `.workspace-audit-trash/`).
- Plugin command `/workspace-audit` with focused, compare, explain and fix
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
