"""Conformance fixture for the claude_code adapter (contract:
harness/conformance/runner.py docstring).

Builds a root-only Claude Code workspace (the runner home stays empty,
so no user-level ~/.claude sources exist):

    CLAUDE.md                    project memory
    .claude/settings.json        permissions.allow with Bash(*)  -> the
                                 planted problem
    .claude/rules/one.md         path-scoped rule, globs: docs/**
    docs/CLAUDE.md               nested memory
    docs/guide.md                gives the rule glob a real scope

Expected values were checked against the real adapter behaviour
(detection markers, instruction_sources, resolve_chain, validate)
before this file was committed."""

from pathlib import Path


def build(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)

    (root / 'CLAUDE.md').write_text(
        '# Project instructions\n'
        'Conformance fixture workspace for the claude_code adapter.\n'
        'Keep answers short and cite files.\n',
        encoding='utf-8')

    # planted problem: full-wildcard Bash permission -> fail/high
    settings = root / '.claude' / 'settings.json'
    settings.parent.mkdir(parents=True, exist_ok=True)
    settings.write_text(
        '{\n'
        '  "permissions": {\n'
        '    "allow": ["Bash(*)"]\n'
        '  }\n'
        '}\n',
        encoding='utf-8')

    rule = root / '.claude' / 'rules' / 'one.md'
    rule.parent.mkdir(parents=True, exist_ok=True)
    rule.write_text(
        '---\n'
        'description: Docs-scoped rule for the conformance fixture\n'
        'globs: docs/**\n'
        '---\n'
        'In docs use concise imperative sentences.\n',
        encoding='utf-8')

    (root / 'docs').mkdir(parents=True, exist_ok=True)
    (root / 'docs' / 'CLAUDE.md').write_text(
        '# Docs instructions\n'
        'Nested memory for the docs subtree.\n',
        encoding='utf-8')
    (root / 'docs' / 'guide.md').write_text(
        '# Guide\nWritten for the docs glob scope.\n',
        encoding='utf-8')


def expected() -> dict:
    return {
        # exactly these project markers exist (set match); with no
        # activity data the detection engine reads them as
        # Detection(detected, medium)
        'detect_project': ['.claude', 'CLAUDE.md',
                           '.claude/settings.json'],
        # empty home: no ~/.claude marker, no user memory source
        'detect_user': False,
        # CLAUDE.md, docs/CLAUDE.md, .claude/rules/one.md
        'instruction_sources_count': 3,
        # project CLAUDE.md only: the rule glob misses the root
        # target, docs/CLAUDE.md is outside the root target path
        'resolve_root_loaded': ['CLAUDE.md'],
        # docs target: rule glob matches, nested memory sits on the
        # path, project memory still loaded
        'resolve_nested': {
            'dir': 'docs',
            'loaded': ['.claude/rules/one.md', 'docs/CLAUDE.md',
                       'CLAUDE.md'],
        },
        # Bash(*) in permissions.allow
        'validate_findings': ['CLAUDE_SETTINGS_PERMISSIONS_WILDCARD'],
    }
