"""Z Code adapter. Mirrors the behaviour that audit_scan.py hardcoded
before Phase 1 (HARNESS dict entry), now as the single source:

- home state dir   ~/.zcode (activity markers: cli/history.jsonl,
                    projects, config)
- instructions     ~/.zcode/AGENTS.md (user), AGENTS.md (project root);
                    project wins over user
- memory           ~/.zcode/cli/memories/MEMORY.md, budget 24985 bytes
                    or 200 lines
- skills           ~/.zcode/skills, .agents/skills (project),
                    ~/.zcode/cli/plugins/cache (read-only installs)
- config           .zcode/config.json (project), ~/.zcode/config.json
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from ..base import (AdapterFinding, HarnessAdapter, HarnessContext,
                    InstructionChain, InstructionLink, InstructionSource)
from .. import register

MEMORY_LIMIT_BYTES = 24985
MEMORY_LIMIT_LINES = 200


@register
class ZcodeAdapter(HarnessAdapter):
    harness_id = 'zcode'
    display_name = 'Z Code'
    spec_source = ''
    spec_verified = '2026-11-17'
    supported_versions = 'current CLI (version not detectable offline)'
    known_limitations = [
        'nested AGENTS.md merging not modelled; only user + project root',
    ]

    def project_markers(self, ctx: HarnessContext) -> list:
        return ['.agents', '.zcode/config.json', 'AGENTS.md']

    def dir_conflict_map(self, ctx: HarnessContext) -> list:
        return ['.agents', '.zcode/config.json']

    def home_markers(self, ctx: HarnessContext) -> list:
        return [ctx.home_path('.zcode')]

    def instruction_sources(self, ctx: HarnessContext) -> list:
        srcs = []
        user_md = ctx.home_path('.zcode', 'AGENTS.md')
        if ctx.exists(user_md):
            srcs.append(InstructionSource(
                user_md, 'user', 'user-level AGENTS.md'))
        proj_md = ctx.root_path('AGENTS.md')
        if ctx.exists(proj_md):
            srcs.append(InstructionSource(
                proj_md, 'project', 'project AGENTS.md'))
        return srcs

    def resolve_chain(self, ctx: HarnessContext,
                      target_dir: Optional[Path] = None) -> InstructionChain:
        sources = self.instruction_sources(ctx)
        chain = InstructionChain(harness_id=self.harness_id,
                                 target_dir=target_dir or ctx.root)
        # model: both levels load together, project scope wins on collision
        for s in sources:
            prec = 2 if s.scope == 'project' else 1
            chain.links.append(InstructionLink(s, precedence=prec))
        return chain

    def skills_locations(self, ctx: HarnessContext) -> list:
        return [
            ctx.home_path('.zcode', 'skills'),
            ctx.root_path('.agents', 'skills'),
            ctx.home_path('.zcode', 'cli', 'plugins', 'cache'),
        ]

    def config_files(self, ctx: HarnessContext) -> list:
        files = [ctx.root_path('.zcode', 'config.json')]
        home_cfg = ctx.home_path('.zcode', 'config.json')
        if ctx.exists(home_cfg):
            files.append(home_cfg)
        return [f for f in files if ctx.exists(f)]

    def mcp_config_files(self, ctx: HarnessContext) -> list:
        # MCP servers live inside .zcode/config.json (mcp.servers)
        return [f for f in self.config_files(ctx)
                if f.name == 'config.json']

    def context_budget_bytes(self) -> Optional[int]:
        return None  # no documented instruction budget; memory has one

    def validate(self, ctx: HarnessContext) -> list:
        findings = []
        mem = ctx.home_path('.zcode', 'cli', 'memories', 'MEMORY.md')
        if ctx.exists(mem):
            try:
                text = mem.read_text(encoding='utf-8', errors='replace')
            except OSError:
                return findings
            over_bytes = len(text.encode('utf-8')) > MEMORY_LIMIT_BYTES
            over_lines = text.count('\n') + 1 > MEMORY_LIMIT_LINES
            if over_bytes or over_lines:
                why = []
                if over_bytes:
                    why.append('>%d bytes' % MEMORY_LIMIT_BYTES)
                if over_lines:
                    why.append('>%d lines' % MEMORY_LIMIT_LINES)
                findings.append(AdapterFinding(
                    check_id='ZCODE_MEMORY_OVER_LIMIT',
                    category='instructions', severity='medium',
                    status='warn',
                    title='Z Code agent memory over the load limit',
                    description=(
                        'MEMORY.md exceeds %s; the loaded index is '
                        'truncated and older notes become invisible to '
                        'the agent.' % ' and '.join(why)),
                    evidence=[{'file': str(mem),
                               'bytes': len(text.encode('utf-8')),
                               'lines': text.count('\n') + 1}],
                    recommendation=(
                        'compress or prune the memory index; move detail '
                        'into topic files and keep one-line pointers.'),
                    confidence=0.9))
        return findings
