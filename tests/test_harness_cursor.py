"""Tests for the Cursor harness adapter
(skills/agents-doctor/scripts/harness/adapters/cursor.py).

Covers registration and detection surface, rule classification,
resolve_chain precedence/activation, and positive+negative cases for
every CURSOR_* check_id emitted by validate().
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'skills' / 'agents-doctor' / 'scripts'))

from harness import adapter_ids, get_adapter
from harness.base import HarnessContext

FM_ALWAYS = 'description: always on\nglobs: **\nalwaysApply: true'
FM_AUTO = 'description: python rule\nglobs: "*.py"'
FM_AGENT = 'description: ask me first'

CHECK_IDS = {
    'CURSOR_MDC_FRONTMATTER', 'CURSOR_GLOB_INVALID', 'CURSOR_GLOB_NOMATCH',
    'CURSOR_LEGACY_AND_RULES', 'CURSOR_RULES_DUPLICATE_DESC',
    'CURSOR_MCP_PARSE', 'CURSOR_RULE_NO_SCOPE',
}


class CursorTestBase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.ctx = HarnessContext(root=self.root, home=self.root / 'home')
        self.adapter = get_adapter('cursor')

    def write_rule(self, name, frontmatter=None, body='rule body\n'):
        rules = self.root / '.cursor' / 'rules'
        rules.mkdir(parents=True, exist_ok=True)
        text = ''
        if frontmatter is not None:
            text = '---\n' + frontmatter.strip('\n') + '\n---\n'
        path = rules / name
        path.write_text(text + body, encoding='utf-8')
        return path

    def write_legacy(self, text='legacy rule\n'):
        path = self.root / '.cursorrules'
        path.write_text(text, encoding='utf-8')
        return path

    def findings(self):
        return {f.check_id: f for f in self.adapter.validate(self.ctx)}

    def chain(self, target=None):
        return self.adapter.resolve_chain(self.ctx, target)


class TestRegistrationAndDetection(CursorTestBase):
    def test_registered_with_spec_metadata(self):
        self.assertIn('cursor', adapter_ids())
        info = self.adapter.spec_info()
        self.assertEqual(info['spec_source'],
                         'https://docs.cursor.com/context/rules')
        self.assertEqual(info['spec_verified'], '2026-11-17')
        self.assertEqual(info['supported_versions'], 'current (unverified)')
        self.assertTrue(info['known_limitations'])

    def test_detection_surface(self):
        self.assertEqual(self.adapter.project_markers(self.ctx),
                         ['.cursor', '.cursorrules'])
        self.assertEqual(self.adapter.home_markers(self.ctx), [])
        self.assertIsNone(self.adapter.detect_version(self.ctx))

    def test_config_files_follow_mcp_json(self):
        self.assertEqual(self.adapter.config_files(self.ctx), [])
        mcp = self.root / '.cursor' / 'mcp.json'
        mcp.parent.mkdir(parents=True, exist_ok=True)
        mcp.write_text('{"mcpServers": {}}', encoding='utf-8')
        self.assertEqual(self.adapter.config_files(self.ctx), [mcp])
        self.assertEqual(self.adapter.mcp_config_files(self.ctx), [mcp])


class TestInstructionSources(CursorTestBase):
    def test_classification_of_all_four_kinds_plus_legacy(self):
        always = self.write_rule('always.mdc', FM_ALWAYS)
        auto = self.write_rule('auto.mdc', FM_AUTO)
        agent = self.write_rule('agent.mdc', FM_AGENT)
        manual = self.write_rule('manual.mdc')
        legacy = self.write_legacy()
        srcs = {s.path.name: s for s in
                self.adapter.instruction_sources(self.ctx)}
        self.assertEqual(srcs['always.mdc'].scope, 'path_scoped')
        self.assertTrue(srcs['always.mdc'].always_apply)
        self.assertEqual(srcs['auto.mdc'].globs, ['*.py'])
        self.assertFalse(srcs['auto.mdc'].always_apply)
        self.assertEqual(srcs['agent.mdc'].description, 'ask me first')
        self.assertEqual(srcs['agent.mdc'].globs, [])
        self.assertEqual(srcs['manual.mdc'].description, '')
        self.assertEqual(srcs['.cursorrules'].scope, 'project')
        self.assertEqual(srcs[legacy.name].path, legacy)

    def test_globs_frontmatter_forms(self):
        self.write_rule('comma.mdc', 'description: c\nglobs: "*.py, *.ts"')
        self.write_rule('spaces.mdc', 'description: s\nglobs: *.py *.ts')
        self.write_rule('block.mdc',
                        'description: b\nglobs:\n  - "*.py"\n  - src/**')
        self.write_rule('inline.mdc', 'description: i\nglobs: ["*.py"]')
        srcs = {s.path.name: s for s in
                self.adapter.instruction_sources(self.ctx)}
        self.assertEqual(srcs['comma.mdc'].globs, ['*.py', '*.ts'])
        self.assertEqual(srcs['spaces.mdc'].globs, ['*.py', '*.ts'])
        self.assertEqual(srcs['block.mdc'].globs, ['*.py', 'src/**'])
        self.assertEqual(srcs['inline.mdc'].globs, ['*.py'])

    def test_rules_in_nested_dirs_are_collected(self):
        nested = self.root / '.cursor' / 'rules' / 'python'
        nested.mkdir(parents=True)
        (nested / 'nested.mdc').write_text(
            '---\ndescription: nested\nglobs: "*.py"\n---\n', encoding='utf-8')
        srcs = self.adapter.instruction_sources(self.ctx)
        self.assertEqual([s.path.name for s in srcs], ['nested.mdc'])


class TestResolveChain(CursorTestBase):
    def test_always_apply_active_for_any_target(self):
        self.write_rule('always.mdc', FM_ALWAYS)
        deep = self.root / 'packages' / 'app'
        deep.mkdir(parents=True)
        for target in (None, self.root, deep):
            chain = self.chain(target)
            loaded = chain.loaded
            self.assertEqual(len(loaded), 1)
            self.assertTrue(loaded[0].active)
            self.assertEqual(loaded[0].precedence, 30)
            self.assertTrue(chain.approximated)

    def test_auto_attached_active_on_glob_match_inactive_otherwise(self):
        self.write_rule('auto.mdc', 'description: docs\nglobs: docs/**')
        inside = self.root / 'docs' / 'guides'
        inside.mkdir(parents=True)
        chain = self.chain(inside)
        self.assertEqual(len(chain.loaded), 1)
        self.assertEqual(chain.loaded[0].precedence, 20)
        self.assertIn('glob match', chain.loaded[0].reason)
        self.assertEqual(chain.unloaded, [])
        # target outside the glob: rule moves to unloaded
        other = self.root / 'src'
        other.mkdir()
        chain2 = self.chain(other)
        self.assertEqual(chain2.loaded, [])
        self.assertEqual(len(chain2.unloaded), 1)
        source, reason = chain2.unloaded[0]
        self.assertEqual(source.path.name, 'auto.mdc')
        self.assertIn('do not match target', reason)

    def test_dir_prefix_glob_matches_dir_itself_and_children(self):
        self.write_rule('prefix.mdc', 'description: p\nglobs: src/**')
        src = self.root / 'src'
        src.mkdir()
        self.assertEqual(len(self.chain(src).loaded), 1)
        sub = src / 'deep' / 'pkg'
        sub.mkdir(parents=True)
        self.assertEqual(len(self.chain(sub).loaded), 1)
        elsewhere = self.root / 'other'
        elsewhere.mkdir()
        self.assertEqual(len(self.chain(elsewhere).loaded), 0)

    def test_agent_requested_rule_inactive_with_reason(self):
        self.write_rule('agent.mdc', FM_AGENT)
        chain = self.chain(self.root)
        self.assertEqual(chain.loaded, [])
        link = chain.links[0]
        self.assertFalse(link.active)
        self.assertEqual(link.reason, 'agent-requested: model decides')

    def test_manual_rule_inactive_with_reason(self):
        self.write_rule('manual.mdc')
        chain = self.chain(self.root)
        self.assertEqual(chain.loaded, [])
        self.assertEqual(chain.links[0].reason,
                         'manual rule: never auto-applied')

    def test_legacy_cursorrules_precedence_below_rules(self):
        self.write_legacy()
        self.write_rule('always.mdc', FM_ALWAYS)
        self.write_rule('auto.mdc', 'description: a\nglobs: **')
        chain = self.chain(self.root)
        by_prec = {link.precedence: link for link in chain.links}
        self.assertEqual(sorted(by_prec), [10, 20, 30])
        self.assertEqual(by_prec[10].source.scope, 'project')
        self.assertTrue(by_prec[10].active)
        self.assertIn('legacy', by_prec[10].reason)
        self.assertTrue(all(l.active for l in chain.links))

    def test_chain_to_dict_shape(self):
        self.write_rule('always.mdc', FM_ALWAYS)
        self.write_rule('agent.mdc', FM_AGENT)
        self.write_rule('auto.mdc', 'description: x\nglobs: nomatch/**')
        as_dict = self.chain(self.root).to_dict()
        self.assertEqual(as_dict['harness'], 'cursor')
        self.assertTrue(as_dict['approximated'])
        self.assertEqual(len(as_dict['loaded']), 1)          # always only
        self.assertEqual(len(as_dict['overridden']), 1)      # agent rule
        self.assertEqual(as_dict['overridden'][0]['reason'],
                         'agent-requested: model decides')
        self.assertEqual(len(as_dict['unloaded']), 1)        # auto, no match
        self.assertEqual(as_dict['conflicts'], [])


class TestValidate(CursorTestBase):
    def test_mdc_frontmatter_positive_and_negative(self):
        self.write_rule('bare.mdc')                       # no frontmatter
        self.write_rule('nodesc.mdc', 'globs: "*.py"')    # fm, no description
        found = self.findings()
        self.assertIn('CURSOR_MDC_FRONTMATTER', found)
        ev = found['CURSOR_MDC_FRONTMATTER'].evidence
        self.assertEqual({e['file'].rsplit('\\', 1)[-1].rsplit('/', 1)[-1]
                          for e in ev}, {'bare.mdc', 'nodesc.mdc'})
        self.assertEqual(found['CURSOR_MDC_FRONTMATTER'].status, 'warn')
        # negative: described .mdc and plain .md are not flagged
        (self.root / '.cursor' / 'rules' / 'bare.mdc').unlink()
        (self.root / '.cursor' / 'rules' / 'nodesc.mdc').unlink()
        self.write_rule('good.mdc', FM_AUTO)
        self.write_rule('notes.md')
        self.assertNotIn('CURSOR_MDC_FRONTMATTER', self.findings())

    def test_glob_invalid_positive_and_negative(self):
        self.write_rule('bad.mdc', 'description: b\nglobs: a**b')
        self.write_rule('empty.mdc', 'description: e\nglobs: ""')
        found = self.findings()
        self.assertIn('CURSOR_GLOB_INVALID', found)
        globs = {e['glob'] for e in found['CURSOR_GLOB_INVALID'].evidence}
        self.assertEqual(globs, {'a**b', ''})
        # negative: segment-safe ** and plain wildcards pass
        (self.root / '.cursor' / 'rules' / 'bad.mdc').unlink()
        (self.root / '.cursor' / 'rules' / 'empty.mdc').unlink()
        for i, g in enumerate(['**/*.py', 'src/**', '*.py', '**']):
            self.write_rule('ok%d.mdc' % i,
                            'description: ok%d\nglobs: %s' % (i, g))
        self.assertNotIn('CURSOR_GLOB_INVALID', self.findings())

    def test_glob_nomatch_positive_and_negative(self):
        self.write_rule('dead.mdc',
                        'description: dead\nglobs: nowhere/**')
        src = self.root / 'src'
        src.mkdir()
        (src / 'app.py').write_text('x = 1', encoding='utf-8')
        found = self.findings()
        self.assertIn('CURSOR_GLOB_NOMATCH', found)
        f = found['CURSOR_GLOB_NOMATCH']
        self.assertEqual(f.status, 'warn')
        self.assertIn('no applicable scope', f.description + str(f.evidence))
        # negative: a rule whose glob covers src/ stays unflagged
        self.write_rule('alive.mdc', 'description: alive\nglobs: src/**')
        found2 = self.findings()
        self.assertIn('CURSOR_GLOB_NOMATCH', found2)       # dead.mdc still
        alive_flagged = any('alive.mdc' in str(e)
                            for e in found2['CURSOR_GLOB_NOMATCH'].evidence)
        self.assertFalse(alive_flagged)

    def test_legacy_and_rules_positive_and_negative(self):
        legacy = self.write_legacy()
        # legacy alone: no conflict
        self.assertNotIn('CURSOR_LEGACY_AND_RULES', self.findings())
        self.write_rule('rule.mdc', FM_AGENT)
        found = self.findings()
        self.assertIn('CURSOR_LEGACY_AND_RULES', found)
        f = found['CURSOR_LEGACY_AND_RULES']
        self.assertEqual(f.status, 'warn')
        self.assertEqual(f.severity, 'medium')
        files = {e['file'] for e in f.evidence}
        self.assertIn(str(legacy), files)
        self.assertIn(str(self.root / '.cursor' / 'rules'), files)
        # negative: rules dir alone
        (self.root / '.cursorrules').unlink()
        self.assertNotIn('CURSOR_LEGACY_AND_RULES', self.findings())

    def test_duplicate_description_positive_and_negative(self):
        self.write_rule('one.mdc', FM_AGENT)
        self.write_rule('two.mdc', 'description: ask me first')
        found = self.findings()
        self.assertIn('CURSOR_RULES_DUPLICATE_DESC', found)
        f = found['CURSOR_RULES_DUPLICATE_DESC']
        self.assertEqual(f.status, 'info')
        self.assertEqual(f.severity, 'low')
        self.assertEqual(len(f.evidence), 1)
        self.assertEqual(len(f.evidence[0]['files']), 2)
        # negative: distinct descriptions
        (self.root / '.cursor' / 'rules' / 'two.mdc').write_text(
            '---\ndescription: something else\n---\n', encoding='utf-8')
        self.assertNotIn('CURSOR_RULES_DUPLICATE_DESC', self.findings())

    def test_mcp_parse_invalid_missing_and_valid(self):
        mcp = self.root / '.cursor' / 'mcp.json'
        mcp.parent.mkdir(parents=True, exist_ok=True)
        mcp.write_text('{ not json', encoding='utf-8')
        found = self.findings()
        self.assertIn('CURSOR_MCP_PARSE', found)
        f = found['CURSOR_MCP_PARSE']
        self.assertEqual(f.status, 'fail')
        self.assertEqual(f.severity, 'high')
        mcp.write_text('{"servers": {}}', encoding='utf-8')
        found = self.findings()
        self.assertEqual(found['CURSOR_MCP_PARSE'].status, 'warn')
        mcp.write_text(json.dumps({'mcpServers': {}}), encoding='utf-8')
        self.assertNotIn('CURSOR_MCP_PARSE', self.findings())

    def test_rule_no_scope_positive_and_negative(self):
        self.write_rule('manual.mdc')
        found = self.findings()
        self.assertIn('CURSOR_RULE_NO_SCOPE', found)
        f = found['CURSOR_RULE_NO_SCOPE']
        self.assertEqual(f.status, 'info')
        self.assertEqual(f.severity, 'low')
        # negative: description-only rule is agent-requested, not manual
        (self.root / '.cursor' / 'rules' / 'manual.mdc').write_text(
            '---\ndescription: now described\n---\n', encoding='utf-8')
        self.assertNotIn('CURSOR_RULE_NO_SCOPE', self.findings())


if __name__ == '__main__':
    unittest.main()
