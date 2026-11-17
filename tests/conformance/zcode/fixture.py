"""Z Code conformance fixture — the reference example for other
harnesses (contract: harness/conformance/runner.py docstring).

Workspace under test:
- root/AGENTS.md          project instructions
- root/src/AGENTS.md      nested instructions (NOT loaded by the
                          adapter — a documented limitation the
                          fixture pins explicitly)
- home/.zcode/AGENTS.md   user instructions
- home/.zcode/cli/memories/MEMORY.md   oversized on purpose, so
  validate() must report ZCODE_MEMORY_OVER_LIMIT

Expected values below were checked against the real adapter
behaviour (resolve_chain, instruction_sources, validate) before
this file was committed."""
from __future__ import annotations

from pathlib import Path

MEMORY_OVERSIZED = '# memory index\n' + 'note about everything. ' * 1800


def build(root: Path, home: Path) -> None:
    (root / 'AGENTS.md').write_text(
        '# Project instructions\n', encoding='utf-8')
    (root / 'src').mkdir()
    (root / 'src' / 'AGENTS.md').write_text(
        '# Nested instructions\n', encoding='utf-8')
    zcode = home / '.zcode'
    zcode.mkdir()
    (zcode / 'AGENTS.md').write_text(
        '# User instructions\n', encoding='utf-8')
    memories = zcode / 'cli' / 'memories'
    memories.mkdir(parents=True)
    (memories / 'MEMORY.md').write_text(MEMORY_OVERSIZED,
                                        encoding='utf-8')


def expected() -> dict:
    return {
        # root/AGENTS.md exists -> a project marker is found
        'detect_project': True,
        # home/.zcode exists -> the home marker is found
        'detect_user': True,
        # adapter models exactly two scopes: user + project root
        # (src/AGENTS.md is not an instruction source)
        'instruction_sources_count': 2,
        # both levels load together for the root target
        'resolve_root_loaded': ['AGENTS.md', '~/.zcode/AGENTS.md'],
        # for the nested target the model does NOT change: user +
        # project root again, never src/AGENTS.md — this pins the
        # known limitation instead of letting it drift silently
        'resolve_nested': {
            'dir': 'src',
            'loaded': ['AGENTS.md', '~/.zcode/AGENTS.md'],
        },
        # oversized MEMORY.md must be flagged
        'validate_findings': ['ZCODE_MEMORY_OVER_LIMIT'],
    }
