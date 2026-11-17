"""Tests for the Codex harness adapter
(skills/agents-doctor/scripts/harness/adapters/codex.py).

Every test builds a throwaway workspace (root + home) so the adapter is
exercised against real files, matching how audit_scan.py calls it.
Secret-value tests plant canary literals and assert the raw value never
appears in the serialized findings.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'skills' / 'agents-doctor' / 'scripts'))

from harness import HarnessContext, adapter_ids, get_adapter
from harness.adapters import codex as codex_module

CANARY_SK = 'sk-abcdefghijklmnop1234'
CANARY_B64 = 'A' * 60


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding='utf-8')


class CodexAdapterTests(unittest.TestCase):
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
        self.adapter = get_adapter('codex')

    # ------------------------------------------------ registration
    def test_registration(self):
        self.assertIn('codex', adapter_ids())
        adapter = get_adapter('codex')
        self.assertEqual(adapter.harness_id, 'codex')
        self.assertEqual(adapter.display_name, 'OpenAI Codex')

    # ------------------------------------------------ detection
    def test_project_markers(self):
        self.assertEqual(self.adapter.project_markers(self.ctx),
                         ['.codex', 'AGENTS.md', 'AGENTS.override.md',
                          '.agents'])

    def test_home_markers(self):
        self.assertEqual(self.adapter.home_markers(self.ctx),
                         [self.ctx.home_path('.codex')])

    def test_detect_version_from_version_file(self):
        _write(self.home / '.codex' / 'version', '0.42.0\n')
        self.assertEqual(self.adapter.detect_version(self.ctx), '0.42.0')

    def test_detect_version_from_config_codex_version_key(self):
        _write(self.home / '.codex' / 'config.toml',
               'codex_version = "1.2.3"\n')
        self.assertEqual(self.adapter.detect_version(self.ctx), '1.2.3')

    def test_detect_version_from_config_version_key(self):
        _write(self.home / '.codex' / 'config.toml', 'version = "9.9.9"\n')
        self.assertEqual(self.adapter.detect_version(self.ctx), '9.9.9')

    def test_detect_version_none(self):
        self.assertIsNone(self.adapter.detect_version(self.ctx))

    # ------------------------------------------------ instructions
    def test_instruction_sources_scopes(self):
        _write(self.home / '.codex' / 'AGENTS.md', 'global')
        _write(self.root / 'AGENTS.md', 'root')
        _write(self.root / 'AGENTS.override.md', 'ovr')
        _write(self.root / 'alpha' / 'AGENTS.md', 'a')
        _write(self.root / 'beta' / 'AGENTS.md', 'b')
        _write(self.root / '.agents' / 'skills' / 'x' / 'SKILL.md', 's')
        srcs = self.adapter.instruction_sources(self.ctx)
        scopes = [s.scope for s in srcs]
        self.assertEqual(scopes.count('global'), 1)
        self.assertEqual(scopes.count('project'), 2)   # root + override
        self.assertEqual(scopes.count('nested'), 2)    # alpha + beta
        # skills directory is not an instruction source
        for s in srcs:
            self.assertNotIn('skills', str(s.path))

    def test_skills_locations(self):
        self.assertEqual(self.adapter.skills_locations(self.ctx),
                         [self.ctx.root_path('.agents', 'skills')])

    def test_config_files_and_mcp(self):
        self.assertEqual(self.adapter.config_files(self.ctx), [])
        _write(self.home / '.codex' / 'config.toml', '')
        _write(self.root / '.codex' / 'config.toml', '')
        files = self.adapter.config_files(self.ctx)
        self.assertEqual(len(files), 2)
        self.assertEqual(self.adapter.mcp_config_files(self.ctx), files)

    # ------------------------------------------------ chain model
    def test_resolve_chain_hierarchy(self):
        _write(self.home / '.codex' / 'AGENTS.md', 'global')
        _write(self.root / 'AGENTS.md', 'root')
        _write(self.root / 'AGENTS.override.md', 'ovr')
        _write(self.root / 'alpha' / 'AGENTS.md', 'a')
        chain = self.adapter.resolve_chain(self.ctx, self.root / 'alpha')
        self.assertTrue(chain.approximated)
        active = {(l.source.path.parent.name, l.source.path.name): l
                  for l in chain.links if l.active}
        self.assertEqual(active[('root', 'AGENTS.override.md')].precedence,
                         100)
        self.assertEqual(active[('alpha', 'AGENTS.md')].precedence, 20)
        self.assertEqual(active[('root', 'AGENTS.md')].precedence, 10)
        g = active[('.codex', 'AGENTS.md')]
        self.assertEqual(g.precedence, 1)
        self.assertEqual(g.reason, 'global base layer')

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

    def test_resolve_chain_deep_nested_precedence(self):
        _write(self.root / 'a' / 'AGENTS.md', '1')
        _write(self.root / 'a' / 'b' / 'AGENTS.md', '2')
        chain = self.adapter.resolve_chain(self.ctx, self.root / 'a' / 'b')
        prec = {l.source.path.parent.name: l.precedence
                for l in chain.links if l.active}
        self.assertEqual(prec['a'], 20)
        self.assertEqual(prec['b'], 30)

    def test_context_budget(self):
        self.assertEqual(self.adapter.context_budget_bytes(), 32768)

    # ------------------------------------------------ validation
    def test_validate_clean_workspace(self):
        self.assertEqual(self.adapter.validate(self.ctx), [])

    def test_sandbox_danger(self):
        _write(self.root / '.codex' / 'config.toml',
               'sandbox_mode = "danger-full-access"\n')
        hits = [f for f in self.adapter.validate(self.ctx)
                if f.check_id == 'CODEX_SANDBOX_DANGER']
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].status, 'fail')
        self.assertEqual(hits[0].severity, 'critical')
        self.assertEqual(hits[0].category, 'security')

    def test_sandbox_danger_with_approval_never(self):
        _write(self.root / '.codex' / 'config.toml',
               'sandbox_mode = "danger-full-access"\n'
               'approval_policy = "never"\n')
        findings = self.adapter.validate(self.ctx)
        hits = [f for f in findings
                if f.check_id == 'CODEX_SANDBOX_DANGER']
        self.assertEqual(len(hits), 1)
        # strengthened description mentions the approval policy
        self.assertIn("approval_policy = 'never'", hits[0].description)
        # no separate approval finding in the same file
        self.assertEqual([f for f in findings
                          if f.check_id == 'CODEX_APPROVAL_NEVER'], [])

    def test_approval_never(self):
        _write(self.root / '.codex' / 'config.toml',
               'approval_policy = "never"\n')
        findings = self.adapter.validate(self.ctx)
        hits = [f for f in findings
                if f.check_id == 'CODEX_APPROVAL_NEVER']
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].status, 'fail')
        self.assertEqual(hits[0].severity, 'high')
        self.assertEqual([f for f in findings
                          if f.check_id == 'CODEX_SANDBOX_DANGER'], [])

    def test_toml_parse_error(self):
        _write(self.root / '.codex' / 'config.toml',
               'this is [not valid toml')
        hits = [f for f in self.adapter.validate(self.ctx)
                if f.check_id == 'CODEX_TOML_PARSE']
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].status, 'fail')
        self.assertEqual(hits[0].severity, 'high')

    def test_toml_unknown_when_no_tomllib(self):
        _write(self.root / '.codex' / 'config.toml',
               'sandbox_mode = "danger-full-access"\n')
        with mock.patch.object(codex_module, 'tomllib', None):
            findings = self.adapter.validate(self.ctx)
        hits = [f for f in findings if f.check_id == 'CODEX_TOML_PARSE']
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].status, 'unknown')
        self.assertIn('tomllib unavailable on this python',
                      hits[0].description)
        # dependent config checks could not run either
        self.assertEqual([f for f in findings
                          if f.check_id == 'CODEX_SANDBOX_DANGER'], [])

    def test_override_without_base(self):
        _write(self.root / 'AGENTS.override.md', 'ovr')
        hits = [f for f in self.adapter.validate(self.ctx)
                if f.check_id == 'CODEX_OVERRIDE_IGNORED']
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].status, 'warn')
        self.assertEqual(hits[0].severity, 'medium')

    def test_override_with_base_no_finding(self):
        _write(self.root / 'AGENTS.override.md', 'ovr')
        _write(self.root / 'AGENTS.md', 'root')
        self.assertEqual([f for f in self.adapter.validate(self.ctx)
                          if f.check_id == 'CODEX_OVERRIDE_IGNORED'], [])

    def test_mcp_env_secrets(self):
        _write(self.home / '.codex' / 'config.toml',
               '[mcp_servers.search]\n'
               'command = "npx"\n'
               '\n'
               '[mcp_servers.search.env]\n'
               'API_KEY = "%s"\n'
               'TOKEN = "%s"\n'
               'SAFE = "${API_KEY}"\n' % (CANARY_SK, CANARY_B64))
        hits = [f for f in self.adapter.validate(self.ctx)
                if f.check_id == 'CODEX_MCP_ENV_SECRETS']
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].status, 'fail')
        self.assertEqual(hits[0].severity, 'high')
        # both literal values flagged, template not
        self.assertEqual(len(hits[0].evidence), 2)
        # raw secret values must not leak through the finding
        dumped = json.dumps(hits[0].to_dict())
        self.assertNotIn(CANARY_SK, dumped)
        self.assertNotIn(CANARY_B64, dumped)

    def test_mcp_env_templates_clean(self):
        _write(self.home / '.codex' / 'config.toml',
               '[mcp_servers.search]\n'
               'command = "npx"\n'
               '\n'
               '[mcp_servers.search.env]\n'
               'SAFE = "${API_KEY}"\n')
        self.assertEqual([f for f in self.adapter.validate(self.ctx)
                          if f.check_id == 'CODEX_MCP_ENV_SECRETS'], [])

    def test_chain_budget_over(self):
        _write(self.root / 'AGENTS.md', 'x' * 20000)
        _write(self.root / 'sub' / 'AGENTS.md', 'y' * 15000)
        hits = [f for f in self.adapter.validate(self.ctx)
                if f.check_id == 'CODEX_CHAIN_BUDGET']
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].status, 'warn')
        self.assertEqual(hits[0].severity, 'medium')

    def test_chain_budget_counts_global(self):
        _write(self.home / '.codex' / 'AGENTS.md', 'g' * 30000)
        _write(self.root / 'AGENTS.md', 'r' * 5000)
        hits = [f for f in self.adapter.validate(self.ctx)
                if f.check_id == 'CODEX_CHAIN_BUDGET']
        self.assertEqual(len(hits), 1)

    def test_chain_budget_ok(self):
        _write(self.root / 'AGENTS.md', 'small')
        _write(self.root / 'sub' / 'AGENTS.md', 'also small')
        self.assertEqual([f for f in self.adapter.validate(self.ctx)
                          if f.check_id == 'CODEX_CHAIN_BUDGET'], [])

    # ------------------------------------------------ serialization
    def test_to_dict_serializable(self):
        _write(self.home / '.codex' / 'AGENTS.md', 'global')
        _write(self.root / 'AGENTS.md', 'root')
        _write(self.root / 'AGENTS.override.md', 'ovr')
        _write(self.root / 'sub' / 'AGENTS.md', 's')
        _write(self.root / '.codex' / 'config.toml',
               'approval_policy = "never"\n')
        chain = self.adapter.resolve_chain(self.ctx, self.root / 'sub')
        self.assertIsInstance(json.dumps(chain.to_dict()), str)
        findings = self.adapter.validate(self.ctx)
        self.assertTrue(findings)
        self.assertIsInstance(
            json.dumps([f.to_dict() for f in findings]), str)

    def test_spec_info(self):
        info = self.adapter.spec_info()
        self.assertEqual(info['spec_source'],
                         'https://developers.openai.com/codex')
        self.assertEqual(info['spec_verified'], '2026-11-17')
        self.assertEqual(info['supported_versions'],
                         'current CLI (unverified)')
        self.assertEqual(len(info['known_limitations']), 2)


if __name__ == '__main__':
    unittest.main()
