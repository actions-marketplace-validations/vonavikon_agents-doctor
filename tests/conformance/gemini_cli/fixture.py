"""Conformance fixture for the gemini_cli adapter (contract:
harness/conformance/runner.py docstring).

Builds a Gemini CLI workspace (the runner home stays empty, so no
~/.gemini user layer exists):

    GEMINI.md                project root layer (no @imports)
    .gemini/settings.json    broken JSON -> the planted problem
    subdir/GEMINI.md         nested layer

Expected values were checked against the real adapter behaviour
(detection markers, instruction_sources, resolve_chain, validate)
before this file was committed.
"""

from pathlib import Path


def build(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)

    (root / 'GEMINI.md').write_text(
        '# Project instructions\n'
        'Conformance fixture workspace for the gemini_cli adapter.\n'
        'Answer step by step and cite file paths.\n',
        encoding='utf-8')

    # planted problem: unparseable settings.json -> fail/high
    settings = root / '.gemini' / 'settings.json'
    settings.parent.mkdir(parents=True, exist_ok=True)
    settings.write_text(
        '{\n'
        '  "coreTools": "run_shell_command"\n',
        encoding='utf-8')

    (root / 'subdir').mkdir(parents=True, exist_ok=True)
    (root / 'subdir' / 'GEMINI.md').write_text(
        '# Subdir instructions\n'
        'Nested layer for the subdir subtree.\n',
        encoding='utf-8')


def expected() -> dict:
    return {
        # exactly these project markers exist (set match)
        'detect_project': ['.gemini', 'GEMINI.md'],
        # empty home: no ~/.gemini marker, no user GEMINI.md
        'detect_user': False,
        # GEMINI.md, subdir/GEMINI.md
        'instruction_sources_count': 2,
        # project layer only: subdir/GEMINI.md is outside the root
        # target path, so the link stays inactive
        'resolve_root_loaded': ['GEMINI.md'],
        # subdir target: nested layer on the path joins the project one
        'resolve_nested': {
            'dir': 'subdir',
            'loaded': ['GEMINI.md', 'subdir/GEMINI.md'],
        },
        # .gemini/settings.json is not valid JSON (unclosed object)
        'validate_findings': ['GEMINI_SETTINGS_PARSE'],
    }
