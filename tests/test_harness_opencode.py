"""Tests for the OpenCode harness adapter
(skills/agents-doctor/scripts/harness/adapters/opencode.py).

Every test builds a throwaway workspace (root + home) so the adapter is
exercised against real files, matching how audit_scan.py calls it.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'skills' / 'agents-doctor' / 'scripts'))

from harness import HarnessContext, adapter_ids, get_adapter


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding='utf-8')


class OpencodeAdapterTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = Path(tmp.name)
        self.root = base / 'root'
        self.home = base / 'home'
        self.root.mkdir()
        self.home.mkdir()
        self.ctx = HarnessContext(root=self.root.resolve(),
                                  home=self.home.resolve())
        self.adapter = get_adapter('opencode')

    def _hits(self, check_id):
        return [f for f in self.adapter.validate(self.ctx)
                if f.check_id == check_id]

    # ------------------------------------------------ registration
    def test_registration(self):
        self.assertIn('opencode', adapter_ids())
        adapter = get_adapter('opencode')
        self.assertEqual(adapter.harness_id, 'opencode')
        self.assertEqual(adapter.display_name, 'OpenCode')

    def test_spec_info(self):
        info = self.adapter.spec_info()
        self.assertEqual(info['spec_source'],
                         'https://opencode.ai/docs/config/')
        self.assertEqual(info['spec_verified'], '2026-11-17')
        self.assertEqual(info['supported_versions'], 'current (unverified)')
        self.assertEqual(len(info['known_limitations']), 2)

    # ------------------------------------------------ detection
    def test_project_markers(self):
        self.assertEqual(self.adapter.project_markers(self.ctx),
                         ['.opencode', 'opencode.json', 'opencode.jsonc',
                          'AGENTS.md'])

    def test_home_markers(self):
        self.assertEqual(
            self.adapter.home_markers(self.ctx),
            [self.ctx.home_path('.config', 'opencode')])

    def test_detect_version_none(self):
        _write(self.home / '.config' / 'opencode' / 'opencode.json', '{}')
        self.assertIsNone(self.adapter.detect_version(self.ctx))

    # ------------------------------------------------ capabilities
    def test_skills_locations(self):
        self.assertEqual(self.adapter.skills_locations(self.ctx),
                         [self.ctx.root_path('.opencode', 'command'),
                          self.ctx.root_path('.opencode', 'agent'),
                          self.ctx.root_path('.opencode', 'plugin')])

    def test_config_files_and_mcp(self):
        self.assertEqual(self.adapter.config_files(self.ctx), [])
        _write(self.home / '.config' / 'opencode' / 'opencode.json', '{}')
        _write(self.root / 'opencode.json', '{}')
        _write(self.root / 'opencode.jsonc', '{}')
        files = self.adapter.config_files(self.ctx)
        self.assertEqual(len(files), 3)
        self.assertEqual(files[0],
                         self.ctx.home_path('.config', 'opencode',
                                            'opencode.json'))
        self.assertEqual(self.adapter.mcp_config_files(self.ctx), files)

    def test_context_budget_none(self):
        self.assertIsNone(self.adapter.context_budget_bytes())

    # ------------------------------------------------ instructions
    def test_instruction_sources_scopes(self):
        _write(self.home / '.config' / 'opencode' / 'AGENTS.md', 'global')
        _write(self.root / 'AGENTS.md', 'root')
        _write(self.root / 'opencode.json',
               '{"instruction": "custom.md"}')
        _write(self.root / 'custom.md', 'custom layer')
        _write(self.root / 'alpha' / 'AGENTS.md', 'a')
        _write(self.root / 'beta' / 'AGENTS.md', 'b')
        _write(self.root / '.opencode' / 'command' / 'x.md', 'cmd')
        srcs = self.adapter.instruction_sources(self.ctx)
        scopes = [s.scope for s in srcs]
        self.assertEqual(scopes.count('global'), 1)
        self.assertEqual(scopes.count('project'), 2)   # root + custom
        self.assertEqual(scopes.count('nested'), 2)    # alpha + beta
        # skills directories are not instruction sources
        for s in srcs:
            self.assertNotIn('.opencode', str(s.path))

    def test_resolve_chain_hierarchy(self):
        _write(self.home / '.config' / 'opencode' / 'AGENTS.md', 'global')
        _write(self.root / 'AGENTS.md', 'root')
        _write(self.root / 'opencode.json',
               '{"instruction": "custom.md"}')
        _write(self.root / 'custom.md', 'custom layer')
        _write(self.root / 'alpha' / 'AGENTS.md', 'a')
        chain = self.adapter.resolve_chain(self.ctx, self.root / 'alpha')
        self.assertTrue(chain.approximated)
        active = {(l.source.path.parent.name, l.source.path.name): l
                  for l in chain.links if l.active}
        g = active[('opencode', 'AGENTS.md')]   # home/.config/opencode
        self.assertEqual(g.precedence, 1)
        self.assertEqual(g.reason, 'global base layer')
        self.assertEqual(active[('root', 'AGENTS.md')].precedence, 10)
        self.assertEqual(active[('alpha', 'AGENTS.md')].precedence, 20)
        self.assertEqual(active[('root', 'custom.md')].precedence, 15)

    def test_resolve_chain_deep_nested_precedence(self):
        _write(self.root / 'a' / 'AGENTS.md', '1')
        _write(self.root / 'a' / 'b' / 'AGENTS.md', '2')
        chain = self.adapter.resolve_chain(self.ctx, self.root / 'a' / 'b')
        prec = {l.source.path.parent.name: l.precedence
                for l in chain.links if l.active}
        self.assertEqual(prec['a'], 20)
        self.assertEqual(prec['b'], 30)

    def test_resolve_chain_outside_path_inactive(self):
        _write(self.root / 'alpha' / 'AGENTS.md', 'a')
        _write(self.root / 'beta' / 'AGENTS.md', 'b')
        chain = self.adapter.resolve_chain(self.ctx, self.root / 'alpha')
        inactive = {l.source.path.parent.name: l
                    for l in chain.links if not l.active}
        self.assertIn('beta', inactive)
        self.assertEqual(inactive['beta'].reason, 'outside target path')
        active_parents = {l.source.path.parent.name
                          for l in chain.links if l.active}
        self.assertNotIn('beta', active_parents)
        self.assertIn('alpha', active_parents)

    # ------------------------------------------------ validation
    def test_validate_clean_workspace(self):
        self.assertEqual(self.adapter.validate(self.ctx), [])

    # OPENCODE_CONFIG_PARSE
    def test_config_parse_error_json(self):
        _write(self.root / 'opencode.json', '{"broken": ')
        hits = self._hits('OPENCODE_CONFIG_PARSE')
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].status, 'fail')
        self.assertEqual(hits[0].severity, 'high')
        self.assertEqual(hits[0].category, 'config')

    def test_config_parse_error_jsonc_after_stripping(self):
        _write(self.root / 'opencode.jsonc',
               '{\n  // comment\n  "a": ,\n}\n')
        hits = self._hits('OPENCODE_CONFIG_PARSE')
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].status, 'fail')
        self.assertIn('after stripping // comments',
                      hits[0].description)

    def test_jsonc_comments_and_urls_parse(self):
        # // comments stripped, https:// inside a string survives
        _write(self.root / 'opencode.jsonc',
               '{\n'
               '  // see https://opencode.ai/docs/config/\n'
               '  "url": "https://opencode.ai",\n'
               '  "mcp": {"fetch": {"command": "npx"}}\n'
               '}\n')
        self.assertEqual(self._hits('OPENCODE_CONFIG_PARSE'), [])
        self.assertEqual(self._hits('OPENCODE_MCP_PARSE'), [])

    def test_config_parse_global_config(self):
        _write(self.home / '.config' / 'opencode' / 'opencode.json', '[]')
        hits = self._hits('OPENCODE_CONFIG_PARSE')
        self.assertEqual(len(hits), 1)
        self.assertIn('not an object', hits[0].description)

    # OPENCODE_INSTRUCTION_MISSING
    def test_instruction_missing(self):
        _write(self.root / 'opencode.json',
               '{"instruction": "notes/custom.md"}')
        hits = self._hits('OPENCODE_INSTRUCTION_MISSING')
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].status, 'fail')
        self.assertEqual(hits[0].severity, 'medium')
        self.assertEqual(hits[0].category, 'config')
        # no parse finding alongside
        self.assertEqual(self._hits('OPENCODE_CONFIG_PARSE'), [])

    def test_instruction_present_no_finding(self):
        _write(self.root / 'opencode.json',
               '{"instruction": "notes/custom.md"}')
        _write(self.root / 'notes' / 'custom.md', 'rules')
        self.assertEqual(self._hits('OPENCODE_INSTRUCTION_MISSING'), [])

    # OPENCODE_PERMISSIONS_DANGEROUS
    def test_permissions_bash_wildcard_string_fail(self):
        _write(self.root / 'opencode.json',
               '{"permission": {"bash": "*"}}')
        hits = self._hits('OPENCODE_PERMISSIONS_DANGEROUS')
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].status, 'fail')
        self.assertEqual(hits[0].severity, 'high')
        self.assertEqual(hits[0].category, 'security')

    def test_permissions_bash_wildcard_rule_fail(self):
        _write(self.root / 'opencode.json',
               '{"permission": {"bash": {"*": "allow",\n'
               '                          "git status": "allow"}}}')
        hits = self._hits('OPENCODE_PERMISSIONS_DANGEROUS')
        wild = [h for h in hits if h.status == 'fail']
        self.assertEqual(len(wild), 1)
        self.assertEqual(wild[0].severity, 'high')

    def test_permissions_bash_alias_key(self):
        # `permissions` (plural) alias recognized too
        _write(self.root / 'opencode.json',
               '{"permissions": {"bash": "*"}}')
        hits = self._hits('OPENCODE_PERMISSIONS_DANGEROUS')
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].status, 'fail')

    def test_permissions_edit_allow_warn(self):
        _write(self.root / 'opencode.json',
               '{"permission": {"edit": "allow"}}')
        hits = self._hits('OPENCODE_PERMISSIONS_DANGEROUS')
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].status, 'warn')
        self.assertEqual(hits[0].severity, 'medium')

    def test_permissions_no_rm_deny_warn(self):
        _write(self.root / 'opencode.json',
               '{"permission": {"bash": {"git status": "allow"}}}')
        hits = self._hits('OPENCODE_PERMISSIONS_DANGEROUS')
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].status, 'warn')
        self.assertEqual(hits[0].severity, 'medium')

    def test_permissions_rm_deny_fences(self):
        _write(self.root / 'opencode.json',
               '{"permission": {"bash": {"git status": "allow",\n'
               '                          "rm -rf *": "deny"}}}')
        self.assertEqual(self._hits('OPENCODE_PERMISSIONS_DANGEROUS'), [])

    def test_permissions_clean(self):
        _write(self.root / 'opencode.json',
               '{"permission": {"edit": "ask",\n'
               '                 "bash": {"*": "deny",\n'
               '                          "git status": "allow"}}}')
        self.assertEqual(self._hits('OPENCODE_PERMISSIONS_DANGEROUS'), [])

    # OPENCODE_AGENT_FRONTMATTER
    def test_agent_frontmatter_missing(self):
        _write(self.root / '.opencode' / 'agent' / 'reviewer.md',
               '# Reviewer\n\nReads diffs.\n')
        hits = self._hits('OPENCODE_AGENT_FRONTMATTER')
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].status, 'warn')
        self.assertEqual(hits[0].severity, 'medium')
        self.assertEqual(hits[0].category, 'structure')

    def test_agent_frontmatter_without_description(self):
        _write(self.root / '.opencode' / 'agent' / 'reviewer.md',
               '---\nmode: primary\n---\nBody.\n')
        hits = self._hits('OPENCODE_AGENT_FRONTMATTER')
        self.assertEqual(len(hits), 1)
        self.assertIn('no description', hits[0].evidence[0]['detail'])

    def test_agent_frontmatter_ok(self):
        _write(self.root / '.opencode' / 'agent' / 'reviewer.md',
               '---\ndescription: reviews diffs\nmode: primary\n---\n'
               'Body.\n')
        self.assertEqual(self._hits('OPENCODE_AGENT_FRONTMATTER'), [])

    # OPENCODE_GLOBAL_LOCAL_DRIFT
    def test_global_local_drift_duplicate_block(self):
        shared = ('Always write tests first.\n'
                  'Commit in small steps.\n'
                  'Keep functions short.\n')
        _write(self.home / '.config' / 'opencode' / 'AGENTS.md',
               '# Global\n' + shared)
        _write(self.root / 'AGENTS.md', '# Project\n' + shared)
        hits = self._hits('OPENCODE_GLOBAL_LOCAL_DRIFT')
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].status, 'warn')
        self.assertEqual(hits[0].severity, 'low')
        self.assertEqual(hits[0].category, 'instructions')
        self.assertEqual(len(hits[0].evidence), 2)   # both files cited

    def test_global_local_drift_distinct_files_clean(self):
        _write(self.home / '.config' / 'opencode' / 'AGENTS.md',
               'Prefer short answers.\nUse the global style.\n'
               'Never guess versions.\n')
        _write(self.root / 'AGENTS.md',
               'Deploy from main only.\nRun ci/cards-lint.py first.\n'
               'Push after confirmation.\n')
        self.assertEqual(self._hits('OPENCODE_GLOBAL_LOCAL_DRIFT'), [])

    # OPENCODE_MCP_PARSE
    def test_mcp_section_not_object(self):
        _write(self.root / 'opencode.json', '{"mcp": []}')
        hits = self._hits('OPENCODE_MCP_PARSE')
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].status, 'warn')
        self.assertEqual(hits[0].severity, 'medium')

    def test_mcp_servers_alias_not_object(self):
        _write(self.root / 'opencode.json', '{"mcpServers": "nope"}')
        hits = self._hits('OPENCODE_MCP_PARSE')
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].evidence[0]['detail'],
                         'mcpServers = str')

    def test_mcp_section_object_clean(self):
        _write(self.root / 'opencode.json',
               '{"mcp": {"fetch": {"command": "npx"}}}')
        self.assertEqual(self._hits('OPENCODE_MCP_PARSE'), [])

    # ------------------------------------------------ serialization
    def test_to_dict_serializable(self):
        _write(self.home / '.config' / 'opencode' / 'AGENTS.md', 'global')
        _write(self.root / 'AGENTS.md', 'root')
        _write(self.root / 'opencode.json',
               '{"instruction": "custom.md",\n'
               ' "permission": {"edit": "allow"}}')
        _write(self.root / 'custom.md', 'custom layer')
        _write(self.root / 'sub' / 'AGENTS.md', 's')
        chain = self.adapter.resolve_chain(self.ctx, self.root / 'sub')
        self.assertIsInstance(json.dumps(chain.to_dict()), str)
        findings = self.adapter.validate(self.ctx)
        self.assertTrue(findings)
        self.assertIsInstance(
            json.dumps([f.to_dict() for f in findings]), str)


if __name__ == '__main__':
    unittest.main()
