"""Conformance fixture for the cursor adapter (contract:
harness/conformance/runner.py docstring).

Builds a Cursor workspace (Cursor has no home markers by design, the
runner home is irrelevant here):

    .cursor/rules/base.mdc    alwaysApply: true
    .cursor/rules/glob.mdc    globs: src/**  (auto-attached)
    .cursorrules              legacy root file
    src/main.py               gives the glob a real scope

The legacy file next to .cursor/rules/ is the planted problem
(CURSOR_LEGACY_AND_RULES).

Expected values were checked against the real adapter behaviour
(detection markers, instruction_sources, resolve_chain, validate)
before this file was committed.
"""

from pathlib import Path


def build(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)

    base = root / '.cursor' / 'rules' / 'base.mdc'
    base.parent.mkdir(parents=True, exist_ok=True)
    base.write_text(
        '---\n'
        'description: Base rules that always apply in the fixture\n'
        'alwaysApply: true\n'
        '---\n'
        'Use forward slashes in docs paths.\n',
        encoding='utf-8')

    (root / '.cursor' / 'rules' / 'glob.mdc').write_text(
        '---\n'
        'description: Rules for files under src\n'
        'globs: src/**\n'
        '---\n'
        'Source files stay under 300 lines.\n',
        encoding='utf-8')

    # planted problem: legacy file coexisting with .cursor/rules/
    (root / '.cursorrules').write_text(
        'Legacy root-level rules kept from an older setup.\n',
        encoding='utf-8')

    (root / 'src').mkdir(parents=True, exist_ok=True)
    (root / 'src' / 'main.py').write_text(
        'print("scope for the src glob")\n',
        encoding='utf-8')


def expected() -> dict:
    return {
        # exactly these project markers exist (set match)
        'detect_project': ['.cursor', '.cursorrules'],
        # cursor has no home markers by design (app-owned state dir)
        'detect_user': False,
        # base.mdc, glob.mdc, .cursorrules
        'instruction_sources_count': 3,
        # always rule + legacy file; the src/** glob misses the root
        # target, so glob.mdc is not loaded (it lands in
        # chain.unloaded, not as an inactive link — Cursor model)
        'resolve_root_loaded': ['.cursor/rules/base.mdc', '.cursorrules'],
        # src target: glob now matches, all three sources load
        'resolve_nested': {
            'dir': 'src',
            'loaded': ['.cursor/rules/base.mdc', '.cursor/rules/glob.mdc',
                       '.cursorrules'],
        },
        # .cursorrules coexists with .cursor/rules/
        'validate_findings': ['CURSOR_LEGACY_AND_RULES'],
    }
