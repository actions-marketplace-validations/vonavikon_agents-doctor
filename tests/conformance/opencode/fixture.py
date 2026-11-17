"""OpenCode conformance fixture (contract:
harness/conformance/runner.py docstring).

Root-only workspace: the harness has user-level state
(~/.config/opencode), but this fixture keeps home empty, so no global
layer exists and user checks must come back negative.

Workspace under test:
- root/AGENTS.md            project instructions
- root/opencode.json        permissions.bash "*" -> the adapter must
                            report OPENCODE_PERMISSIONS_DANGEROUS
- root/.opencode/agent/x.md agent file without frontmatter ->
                            OPENCODE_AGENT_FRONTMATTER
- root/docs/AGENTS.md       nested instructions, active for the root
                            target and for docs/

Expected values below were checked against the real adapter behaviour
(resolve_chain, instruction_sources, validate) before this file was
committed."""
from __future__ import annotations

from pathlib import Path


def build(root: Path) -> None:
    (root / 'AGENTS.md').write_text(
        '# Project instructions\n\n'
        'Ship small commits; run the tests before pushing.\n',
        encoding='utf-8')
    (root / 'opencode.json').write_text(
        '{\n'
        '  "theme": "dark",\n'
        '  "permission": {\n'
        '    "bash": "*"\n'
        '  }\n'
        '}\n',
        encoding='utf-8')
    agent_dir = root / '.opencode' / 'agent'
    agent_dir.mkdir(parents=True, exist_ok=True)
    (agent_dir / 'x.md').write_text(
        '# Reviewer\n\nYou review pull requests.\n',
        encoding='utf-8')
    docs = root / 'docs'
    docs.mkdir(parents=True, exist_ok=True)
    (docs / 'AGENTS.md').write_text(
        '# Docs subtree instructions\n\n'
        'Documentation lives in Markdown only.\n',
        encoding='utf-8')


def expected() -> dict:
    return {
        # .opencode dir, opencode.json and AGENTS.md all exist
        'detect_project': ['.opencode', 'opencode.json', 'AGENTS.md'],
        # empty home: no ~/.config/opencode marker
        'detect_user': False,
        # project root + docs/AGENTS.md; no global layer (empty home),
        # no `instruction` override in the config
        'instruction_sources_count': 2,
        # root chain: project layer + nested first-level layer, both
        # active (nested loads for the root per the adapter model)
        'resolve_root_loaded': ['AGENTS.md', 'docs/AGENTS.md'],
        # docs chain: same two layers stay active
        'resolve_nested': {
            'dir': 'docs',
            'loaded': ['AGENTS.md', 'docs/AGENTS.md'],
        },
        # bash "*" wildcard + agent file without frontmatter
        'validate_findings': ['OPENCODE_PERMISSIONS_DANGEROUS',
                              'OPENCODE_AGENT_FRONTMATTER'],
    }
