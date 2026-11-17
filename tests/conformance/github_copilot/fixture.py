"""GitHub Copilot conformance fixture (contract:
harness/conformance/runner.py docstring).

Root-only workspace: Copilot keeps global ("personal") instructions
in the editor settings UI — there is no home file to build, so user
checks must come back negative.

Workspace under test:
- root/.github/copilot-instructions.md   main file, always loaded
- root/.github/instructions/cpp.md       applyTo: "src/**", active
                                         only under src/
- root/.github/prompts/p.md              no description ->
                                         COPILOT_PROMPT_FRONTMATTER
- root/src/main.cpp                      gives the applyTo glob a
                                         real scope (no NOMATCH)

Expected values below were checked against the real adapter behaviour
(resolve_chain, instruction_sources, validate) before this file was
committed."""
from __future__ import annotations

from pathlib import Path


def build(root: Path) -> None:
    gh = root / '.github'
    (gh / 'instructions').mkdir(parents=True, exist_ok=True)
    (gh / 'prompts').mkdir(parents=True, exist_ok=True)
    (gh / 'copilot-instructions.md').write_text(
        '# Copilot instructions\n\n'
        'Prefer the standard library; keep functions short.\n',
        encoding='utf-8')
    (gh / 'instructions' / 'cpp.md').write_text(
        '---\n'
        'applyTo: "src/**"\n'
        '---\n'
        '# C++ instructions\n\n'
        'Use C++20; no raw new/delete.\n',
        encoding='utf-8')
    (gh / 'prompts' / 'p.md').write_text(
        '# Review\n\n'
        'Review the current file for bugs.\n',
        encoding='utf-8')
    src = root / 'src'
    src.mkdir(parents=True, exist_ok=True)
    (src / 'main.cpp').write_text(
        'int main() { return 0; }\n',
        encoding='utf-8')


def expected() -> dict:
    return {
        # all three documented project markers exist
        'detect_project': ['.github/copilot-instructions.md',
                           '.github/instructions', '.github/prompts'],
        # Copilot has no home markers by design (editor-side settings)
        'detect_user': False,
        # main + applyTo-scoped instruction + prompt file
        'instruction_sources_count': 3,
        # root chain: only the main file loads; applyTo "src/**" does
        # not match the root, the prompt is on-demand only
        'resolve_root_loaded': ['.github/copilot-instructions.md'],
        # src chain: the scoped file joins, outranking the main file
        'resolve_nested': {
            'dir': 'src',
            'loaded': ['.github/instructions/cpp.md',
                       '.github/copilot-instructions.md'],
        },
        # prompt file without a frontmatter description
        'validate_findings': ['COPILOT_PROMPT_FRONTMATTER'],
    }
