"""Conformance fixture for the codex adapter (contract:
harness/conformance/runner.py docstring).

Builds a Codex workspace (the runner home stays empty, so no
~/.codex global layer exists):

    AGENTS.md               project root layer
    AGENTS.override.md      root override layer (wins over all)
    .codex/config.toml      sandbox_mode = danger-full-access -> the
                            planted problem
    subdir/AGENTS.md        nested layer

Expected values were checked against the real adapter behaviour
(detection markers, instruction_sources, resolve_chain, validate)
before this file was committed.
"""

from pathlib import Path


def build(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)

    (root / 'AGENTS.md').write_text(
        '# Project agents\n'
        'Conformance fixture workspace for the codex adapter.\n'
        'Answer with file references.\n',
        encoding='utf-8')

    (root / 'AGENTS.override.md').write_text(
        '# Overrides\n'
        'Prefer tables over prose in reports.\n',
        encoding='utf-8')

    # planted problem: sandbox fully disabled -> critical/fail
    cfg = root / '.codex' / 'config.toml'
    cfg.parent.mkdir(parents=True, exist_ok=True)
    cfg.write_text(
        'sandbox_mode = "danger-full-access"\n',
        encoding='utf-8')

    (root / 'subdir').mkdir(parents=True, exist_ok=True)
    (root / 'subdir' / 'AGENTS.md').write_text(
        '# Subdir agents\n'
        'Nested layer for the subdir subtree.\n',
        encoding='utf-8')


def expected() -> dict:
    return {
        # exactly these project markers exist (set match)
        'detect_project': ['.codex', 'AGENTS.md', 'AGENTS.override.md'],
        # empty home: no ~/.codex marker, no global AGENTS.md
        'detect_user': False,
        # AGENTS.md, AGENTS.override.md, subdir/AGENTS.md
        'instruction_sources_count': 3,
        # all three layers are active for the root target: the model
        # keeps first-level nested AGENTS.md active even at root —
        # this pins that model decision instead of letting it drift
        'resolve_root_loaded': ['AGENTS.md', 'AGENTS.override.md',
                                'subdir/AGENTS.md'],
        # subdir target: same three layers, nested now on the path
        'resolve_nested': {
            'dir': 'subdir',
            'loaded': ['AGENTS.md', 'AGENTS.override.md',
                       'subdir/AGENTS.md'],
        },
        # sandbox_mode = danger-full-access in .codex/config.toml
        'validate_findings': ['CODEX_SANDBOX_DANGER'],
    }
