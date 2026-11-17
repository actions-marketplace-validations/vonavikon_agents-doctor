"""Tests for the GitHub Copilot harness adapter
(skills/agents-doctor/scripts/harness/adapters/github_copilot.py).

Covers registration and detection surface, instruction sources,
resolve_chain precedence/activation, positive+negative cases for every
COPILOT_* check_id emitted by validate(), and serialization.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'skills' / 'agents-doctor' / 'scripts'))

from harness import adapter_ids, get_adapter
from harness.base import HarnessContext

CHECK_IDS = {
    'COPILOT_INSTRUCTIONS_MISSING_APPLYTO', 'COPILOT_APPLYTO_NOMATCH',
    'COPILOT_PROMPT_FRONTMATTER', 'COPILOT_MAIN_TOO_BIG',
    'COPILOT_MCP_JSON_PARSE', 'COPILOT_AGENT_FILES',
    'COPILOT_MCP_YAML_HEURISTIC',
}


class CopilotTestBase(unittest.TestCase):
    def setUp(self):
        self._root_tmp = tempfile.TemporaryDirectory()
        self._home_tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._root_tmp.cleanup)
        self.addCleanup(self._home_tmp.cleanup)
        self.root = Path(self._root_tmp.name)
        self.home = Path(self._home_tmp.name)
        self.ctx = HarnessContext(root=self.root, home=self.home)
        self.adapter = get_adapter('github_copilot')

    # ---- helpers -------------------------------------------------
    def write(self, rel, text):
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding='utf-8')
        return p

    def wjson(self, rel, data):
        return self.write(rel, json.dumps(data))

    def write_instruction(self, name, frontmatter=None, body='rule\n'):
        text = ''
        if frontmatter is not None:
            text = '---\n' + frontmatter.strip('\n') + '\n---\n'
        return self.write(Path('.github') / 'instructions' / name,
                          text + body)

    def write_prompt(self, name, frontmatter=None, body='prompt\n'):
        text = ''
        if frontmatter is not None:
            text = '---\n' + frontmatter.strip('\n') + '\n---\n'
        return self.write(Path('.github') / 'prompts' / name,
                          text + body)

    def findings(self):
        return {f.check_id: f for f in self.adapter.validate(self.ctx)}

    def chain(self, target=None):
        return self.adapter.resolve_chain(self.ctx, target)

    def link_map(self, target=None):
        chain = self.chain(target)
        return chain, {str(l.source.path): l for l in chain.links}


# ---- registry / identity ----------------------------------------
class TestRegistrationAndDetection(CopilotTestBase):
    def test_registered_with_spec_metadata(self):
        self.assertIn('github_copilot', adapter_ids())
        self.assertEqual(self.adapter.harness_id, 'github_copilot')
        self.assertEqual(self.adapter.display_name, 'GitHub Copilot')
        info = self.adapter.spec_info()
        self.assertEqual(info['spec_source'],
                         'https://docs.github.com/en/copilot')
        self.assertEqual(info['spec_verified'], '2026-11-17')
        self.assertEqual(info['supported_versions'], 'current (unverified)')
        self.assertTrue(info['known_limitations'])
        for limitation in info['known_limitations']:
            self.assertIsInstance(limitation, str)

    def test_detection_surface(self):
        self.assertEqual(
            set(self.adapter.project_markers(self.ctx)),
            {'.github/copilot-instructions.md', '.github/instructions',
             '.github/prompts'})
        self.assertEqual(self.adapter.home_markers(self.ctx), [])
        self.assertEqual(self.adapter.dir_conflict_map(self.ctx), [])
        self.assertIsNone(self.adapter.detect_version(self.ctx))

    def test_capabilities(self):
        self.assertIsNone(self.adapter.context_budget_bytes())
        # skills locations: only existing dirs
        self.assertEqual(self.adapter.skills_locations(self.ctx), [])
        prompts = self.root / '.github' / 'prompts'
        agents = self.root / '.github' / 'agents'
        prompts.mkdir(parents=True)
        agents.mkdir()
        self.assertEqual(set(self.adapter.skills_locations(self.ctx)),
                         {prompts, agents})
        # config / mcp files: only existing ones, both flavours
        self.assertEqual(self.adapter.config_files(self.ctx), [])
        self.assertEqual(self.adapter.mcp_config_files(self.ctx), [])
        yml = self.write('.github/copilot-mcp.yml', 'servers:\n')
        mcpjson = self.wjson('.github/mcp.json', {'servers': {}})
        self.assertEqual(set(self.adapter.config_files(self.ctx)),
                         {yml, mcpjson})
        self.assertEqual(set(self.adapter.mcp_config_files(self.ctx)),
                         {yml, mcpjson})


# ---- instruction sources ----------------------------------------
class TestInstructionSources(CopilotTestBase):
    def test_sources_kinds_and_scopes(self):
        main = self.write('.github/copilot-instructions.md', 'main')
        scoped = self.write_instruction(
            'python.md', 'applyTo: "**/*.py"\ndescription: py rules')
        bare = self.write_instruction('bare.md', 'description: no scope')
        prompt = self.write_prompt('review.md',
                                   'description: review the diff')
        srcs = {s.path.name: s for s in
                self.adapter.instruction_sources(self.ctx)}
        self.assertEqual(srcs['copilot-instructions.md'].scope, 'project')
        self.assertEqual(srcs['copilot-instructions.md'].path, main)
        self.assertEqual(srcs['python.md'].scope, 'path_scoped')
        self.assertEqual(srcs['python.md'].globs, ['**/*.py'])
        self.assertFalse(srcs['python.md'].always_apply)
        self.assertEqual(srcs['bare.md'].globs, [])
        self.assertEqual(srcs['review.md'].scope, 'project')
        self.assertEqual(srcs['review.md'].description, 'review the diff')
        self.assertEqual(srcs['review.md'].path, prompt)

    def test_applyto_frontmatter_forms(self):
        self.write_instruction('comma.md',
                               'applyTo: "*.py, *.ts"\ndescription: c')
        self.write_instruction('block.md',
                               'description: b\napplyTo:\n'
                               '  - "**/*.py"\n  - src/**')
        self.write_instruction('inline.md',
                               'applyTo: ["**/*.go"]\ndescription: i')
        srcs = {s.path.name: s for s in
                self.adapter.instruction_sources(self.ctx)}
        self.assertEqual(srcs['comma.md'].globs, ['*.py', '*.ts'])
        self.assertEqual(srcs['block.md'].globs, ['**/*.py', 'src/**'])
        self.assertEqual(srcs['inline.md'].globs, ['**/*.go'])


# ---- resolve_chain ----------------------------------------------
class TestResolveChain(CopilotTestBase):
    def test_main_precedence_and_approximation(self):
        self.write('.github/copilot-instructions.md', 'main')
        chain = self.chain(self.root)
        self.assertTrue(chain.approximated)
        self.assertEqual(len(chain.loaded), 1)
        link = chain.loaded[0]
        self.assertEqual(link.precedence, 20)
        self.assertTrue(link.active)
        self.assertIn('main instruction file', link.reason)

    def test_applyto_active_and_inactive(self):
        self.write_instruction('src.md',
                               'applyTo: "src/**"\ndescription: src')
        target = self.root / 'src' / 'lib'
        target.mkdir(parents=True)
        _chain, links = self.link_map(target)
        rule = links[str(self.root / '.github' / 'instructions' / 'src.md')]
        self.assertTrue(rule.active)
        self.assertEqual(rule.precedence, 30)
        self.assertEqual(rule.reason, 'applyTo matches target')
        # target outside the glob: inactive with the documented reason
        other = self.root / 'docs'
        other.mkdir()
        _chain, links = self.link_map(other)
        rule = links[str(self.root / '.github' / 'instructions' / 'src.md')]
        self.assertFalse(rule.active)
        self.assertEqual(rule.reason, 'glob does not match target')

    def test_no_applyto_never_applied(self):
        self.write_instruction('bare.md', 'description: no scope')
        _chain, links = self.link_map(self.root)
        link = links[str(self.root / '.github' / 'instructions' / 'bare.md')]
        self.assertFalse(link.active)
        self.assertIn('no applyTo', link.reason)

    def test_prompts_inactive(self):
        self.write('.github/copilot-instructions.md', 'main')
        self.write_prompt('review.md', 'description: review')
        _chain, links = self.link_map(self.root)
        prompt = links[str(self.root / '.github' / 'prompts' / 'review.md')]
        self.assertFalse(prompt.active)
        self.assertEqual(prompt.reason, 'prompt file: used on demand')
        # only the main file is loaded
        chain = self.chain(self.root)
        self.assertEqual([str(l.source.path) for l in chain.loaded],
                         [str(self.root / '.github' /
                              'copilot-instructions.md')])

    def test_links_sorted_strongest_first(self):
        self.write('.github/copilot-instructions.md', 'main')
        self.write_instruction('src.md', 'applyTo: "src/**"')
        self.write_prompt('p.md', 'description: p')
        (self.root / 'src').mkdir()
        precs = [l.precedence for l in self.chain(self.root).links]
        self.assertEqual(precs, sorted(precs, reverse=True))
        self.assertEqual(precs[0], 30)   # scoped above main above prompt
        self.assertEqual(precs[-1], 0)

    def test_chain_to_dict_shape(self):
        self.write('.github/copilot-instructions.md', 'main')
        self.write_instruction('bare.md', 'description: no scope')
        self.write_prompt('p.md', 'description: p')
        data = self.chain(self.root).to_dict()
        json.dumps(data)  # must not raise
        self.assertEqual(data['harness'], 'github_copilot')
        self.assertTrue(data['approximated'])
        self.assertEqual(len(data['loaded']), 1)          # main only
        self.assertEqual(len(data['overridden']), 2)      # bare + prompt
        self.assertEqual(data['unloaded'], [])
        self.assertEqual(data['conflicts'], [])


# ---- validate ----------------------------------------------------
class TestValidate(CopilotTestBase):
    def test_missing_applyto_positive_and_negative(self):
        self.write_instruction('bare.md', 'description: no scope')
        self.write_instruction('nofm.md')                 # no frontmatter
        found = self.findings()
        self.assertIn('COPILOT_INSTRUCTIONS_MISSING_APPLYTO', found)
        f = found['COPILOT_INSTRUCTIONS_MISSING_APPLYTO']
        self.assertEqual(f.status, 'warn')
        self.assertEqual(f.severity, 'medium')
        names = {e['file'].rsplit('\\', 1)[-1].rsplit('/', 1)[-1]
                 for e in f.evidence}
        self.assertEqual(names, {'bare.md', 'nofm.md'})
        # negative: an applyTo instruction is not flagged
        (self.root / '.github' / 'instructions' / 'bare.md').unlink()
        (self.root / '.github' / 'instructions' / 'nofm.md').unlink()
        self.write_instruction('ok.md',
                               'applyTo: "src/**"\ndescription: ok')
        self.assertNotIn('COPILOT_INSTRUCTIONS_MISSING_APPLYTO',
                         self.findings())

    def test_applyto_nomatch_positive_and_negative(self):
        self.write_instruction('dead.md',
                               'applyTo: "**/*.zzz"\ndescription: dead')
        src = self.root / 'src'
        src.mkdir()
        (src / 'app.py').write_text('x = 1', encoding='utf-8')
        found = self.findings()
        self.assertIn('COPILOT_APPLYTO_NOMATCH', found)
        f = found['COPILOT_APPLYTO_NOMATCH']
        self.assertEqual(f.status, 'warn')
        self.assertEqual(f.severity, 'low')
        self.assertIn('no applicable scope', f.description)
        # negative: a rule covering src/ stays unflagged
        self.write_instruction('alive.md',
                               'applyTo: "src/**"\ndescription: alive')
        found2 = self.findings()
        self.assertIn('COPILOT_APPLYTO_NOMATCH', found2)  # dead.md still
        alive_flagged = any('alive.md' in str(e)
                            for e in found2['COPILOT_APPLYTO_NOMATCH'].evidence)
        self.assertFalse(alive_flagged)

    def test_prompt_frontmatter_positive_and_negative(self):
        self.write_prompt('bare.md')                          # no fm
        self.write_prompt('nodesc.md', 'mode: chat')          # fm, no desc
        self.write_prompt('agent-mode.md', 'agent: true')     # no desc
        found = self.findings()
        self.assertIn('COPILOT_PROMPT_FRONTMATTER', found)
        f = found['COPILOT_PROMPT_FRONTMATTER']
        self.assertEqual(f.status, 'info')
        self.assertEqual(f.severity, 'low')
        details = {e['detail'] for e in f.evidence}
        self.assertIn('no YAML frontmatter block', details)
        self.assertIn('frontmatter has no description', details)
        # negative: prompt with a description passes
        (self.root / '.github' / 'prompts' / 'bare.md').unlink()
        (self.root / '.github' / 'prompts' / 'nodesc.md').unlink()
        (self.root / '.github' / 'prompts' / 'agent-mode.md').unlink()
        self.write_prompt('good.md', 'description: review code')
        self.assertNotIn('COPILOT_PROMPT_FRONTMATTER', self.findings())

    def test_main_too_big_positive_and_negative(self):
        main = self.root / '.github' / 'copilot-instructions.md'
        main.parent.mkdir(parents=True, exist_ok=True)
        main.write_text('x' * (25 * 1024 + 1), encoding='utf-8')
        found = self.findings()
        self.assertIn('COPILOT_MAIN_TOO_BIG', found)
        f = found['COPILOT_MAIN_TOO_BIG']
        self.assertEqual(f.status, 'warn')
        self.assertEqual(f.severity, 'medium')
        self.assertEqual(f.evidence[0]['size'], 25 * 1024 + 1)
        self.assertEqual(f.evidence[0]['limit'], 25 * 1024)
        # negative: exactly at the limit passes
        main.write_text('x' * (25 * 1024), encoding='utf-8')
        self.assertNotIn('COPILOT_MAIN_TOO_BIG', self.findings())

    def test_mcp_json_parse_positive_and_negative(self):
        mcp = self.root / '.github' / 'mcp.json'
        mcp.parent.mkdir(parents=True, exist_ok=True)
        mcp.write_text('{ not json', encoding='utf-8')
        found = self.findings()
        self.assertIn('COPILOT_MCP_JSON_PARSE', found)
        f = found['COPILOT_MCP_JSON_PARSE']
        self.assertEqual(f.status, 'fail')
        self.assertEqual(f.severity, 'high')
        self.assertEqual(f.evidence[0]['file'], str(mcp))
        # negative: valid JSON parses clean
        mcp.write_text('{"servers": {}}', encoding='utf-8')
        self.assertNotIn('COPILOT_MCP_JSON_PARSE', self.findings())

    def test_mcp_yaml_heuristic_positive_and_negative(self):
        yml = self.root / '.github' / 'copilot-mcp.yml'
        yml.parent.mkdir(parents=True, exist_ok=True)
        yml.write_text('this is not yaml at all', encoding='utf-8')
        found = self.findings()
        self.assertIn('COPILOT_MCP_YAML_HEURISTIC', found)
        f = found['COPILOT_MCP_YAML_HEURISTIC']
        self.assertEqual(f.status, 'warn')   # broken YAML: warn, not fail
        self.assertNotEqual(f.status, 'fail')
        self.assertEqual(f.evidence[0]['file'], str(yml))
        # negative: a plausible top-level key satisfies the heuristic
        yml.write_text('servers:\n  fetch:\n    command: npx\n',
                       encoding='utf-8')
        self.assertNotIn('COPILOT_MCP_YAML_HEURISTIC', self.findings())

    def test_agent_files_positive_and_negative(self):
        agents = self.root / '.github' / 'agents'
        agents.mkdir(parents=True)
        (agents / 'bad.md').write_text('no frontmatter', encoding='utf-8')
        (agents / 'good.md').write_text(
            '---\ndescription: does things\n---\nbody\n', encoding='utf-8')
        found = self.findings()
        self.assertIn('COPILOT_AGENT_FILES', found)
        f = found['COPILOT_AGENT_FILES']
        self.assertEqual(f.status, 'warn')
        self.assertEqual(f.severity, 'low')
        self.assertEqual(f.evidence[0]['file'], str(agents / 'bad.md'))
        # negative: every agent described
        (agents / 'bad.md').write_text(
            '---\ndescription: fixed\n---\n', encoding='utf-8')
        self.assertNotIn('COPILOT_AGENT_FILES', self.findings())

    def test_clean_workspace_zero_findings(self):
        self.write('.github/copilot-instructions.md', 'Be concise.')
        self.write_instruction('py.md',
                               'applyTo: "**/*.py"\ndescription: py')
        self.write_prompt('review.md', 'description: review the diff')
        agents = self.root / '.github' / 'agents'
        agents.mkdir(parents=True)
        (agents / 'helper.md').write_text(
            '---\ndescription: helps\n---\n', encoding='utf-8')
        self.wjson('.github/mcp.json', {'servers': {}})
        self.write('.github/copilot-mcp.yml', 'servers:\n  fetch:\n')
        src = self.root / 'src'
        src.mkdir()
        (src / 'main.py').write_text('x = 1', encoding='utf-8')
        self.assertEqual(self.adapter.validate(self.ctx), [])

    def test_findings_serializable_with_file_evidence(self):
        self.write_instruction('bare.md', 'description: no scope')
        self.write_prompt('p.md')
        mcp = self.root / '.github' / 'mcp.json'
        mcp.parent.mkdir(parents=True, exist_ok=True)
        mcp.write_text('broken', encoding='utf-8')
        findings = self.adapter.validate(self.ctx)
        self.assertTrue(findings)
        for f in findings:
            data = f.to_dict()
            json.dumps(data)  # must not raise
            self.assertTrue(f.evidence)
            for e in f.evidence:
                self.assertIsInstance(e, dict)
                self.assertIn('file', e)
        self.assertTrue(
            {'COPILOT_INSTRUCTIONS_MISSING_APPLYTO',
             'COPILOT_PROMPT_FRONTMATTER',
             'COPILOT_MCP_JSON_PARSE'}.issubset(
                {f.check_id for f in findings}))


if __name__ == '__main__':
    unittest.main()
