"""Windsurf conformance fixture (contract:
harness/conformance/runner.py docstring).

Root-only workspace: Windsurf keeps global state (memories, app
settings) inside app data — nothing to build in home, so user checks
must come back negative.

Workspace under test:
- root/.windsurf/rules/always.md   trigger: always -> loads for any
                                   target
- root/.windsurf/rules/glob.md     trigger: glob, glob: "src/**" ->
                                   active only under src/
- root/.windsurf/rules/broken.md   no trigger -> never activates,
                                   WINDSURF_RULE_NO_TRIGGER
- root/.windsurfrules              legacy file next to the rules dir ->
                                   WINDSURF_LEGACY_AND_RULES
- root/src/main.rs                 gives the glob rule a real scope
                                   (no NOMATCH finding)

Expected values below were checked against the real adapter behaviour
(resolve_chain, instruction_sources, validate) before this file was
committed."""
from __future__ import annotations

from pathlib import Path


def build(root: Path) -> None:
    rules = root / '.windsurf' / 'rules'
    rules.mkdir(parents=True, exist_ok=True)
    (rules / 'always.md').write_text(
        '---\n'
        'trigger: always\n'
        '---\n'
        '# House rules\n\n'
        'Keep the build green.\n',
        encoding='utf-8')
    (rules / 'glob.md').write_text(
        '---\n'
        'trigger: glob\n'
        'glob: "src/**"\n'
        '---\n'
        '# Rust rules\n\n'
        'Run clippy before committing.\n',
        encoding='utf-8')
    (rules / 'broken.md').write_text(
        '# Untitled rule\n\n'
        'Some prose without any trigger frontmatter.\n',
        encoding='utf-8')
    (root / '.windsurfrules').write_text(
        'Always answer in English.\n',
        encoding='utf-8')
    src = root / 'src'
    src.mkdir(parents=True, exist_ok=True)
    (src / 'main.rs').write_text(
        'fn main() {}\n',
        encoding='utf-8')


def expected() -> dict:
    return {
        # both documented project markers exist
        'detect_project': ['.windsurf', '.windsurfrules'],
        # Windsurf has no home markers by design (app-owned state)
        'detect_user': False,
        # three rules + legacy .windsurfrules
        'instruction_sources_count': 4,
        # root chain: always rule + legacy file load; the glob rule
        # does not match the root, broken.md never activates
        'resolve_root_loaded': ['.windsurf/rules/always.md',
                                '.windsurfrules'],
        # src chain: the glob rule joins (always > glob > legacy)
        'resolve_nested': {
            'dir': 'src',
            'loaded': ['.windsurf/rules/always.md',
                       '.windsurf/rules/glob.md',
                       '.windsurfrules'],
        },
        # rule without a trigger + legacy/rules coexistence
        'validate_findings': ['WINDSURF_RULE_NO_TRIGGER',
                              'WINDSURF_LEGACY_AND_RULES'],
    }
