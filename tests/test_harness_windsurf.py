"""Tests for the Windsurf harness adapter
(skills/agents-doctor/scripts/harness/adapters/windsurf.py).

Covers registration and detection surface, trigger classification,
resolve_chain precedence/activation for all four trigger kinds plus
the legacy file, and positive+negative cases for every WINDSURF_*
check_id emitted by validate().
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'skills' / 'agents-doctor' / 'scripts'))

from harness import adapter_ids, get_adapter
from harness.base import HarnessContext

FM_ALWAYS = 'trigger: always\ndescription: always on'
FM_GLOB = 'trigger: glob\nglob: **/*.py\ndescription: python rule'
FM_MANUAL = 'trigger: manual\ndescription: held in reserve'
FM_MODEL = 'trigger: model_decision\ndescription: ask me first'

CHECK_IDS = {
    'WINDSURF_RULE_NO_TRIGGER', 'WINDSURF_TRIGGER_UNKNOWN',
    'WINDSURF_GLOB_MISSING', 'WINDSURF_GLOB_NOMATCH',
    'WINDSURF_LEGACY_AND_RULES', 'WINDSURF_MCP_PARSE',
}


class WindsurfTestBase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.ctx = HarnessContext(root=self.root, home=self.root / 'home')
        self.adapter = get_adapter('windsurf')

    def write_rule(self, name, frontmatter=None, body='rule body\n'):
        rules = self.root / '.windsurf' / 'rules'
        rules.mkdir(parents=True, exist_ok=True)
        text = ''
        if frontmatter is not None:
            text = '---\n' + frontmatter.strip('\n') + '\n---\n'
        path = rules / name
        path.write_text(text + body, encoding='utf-8')
        return path

    def write_legacy(self, text='legacy rule\n'):
        path = self.root / '.windsurfrules'
        path.write_text(text, encoding='utf-8')
        return path

    def findings(self):
        return {f.check_id: f for f in self.adapter.validate(self.ctx)}

    def chain(self, target=None):
        return self.adapter.resolve_chain(self.ctx, target)


class TestRegistrationAndDetection(WindsurfTestBase):
    def test_registered_with_spec_metadata(self):
        self.assertIn('windsurf', adapter_ids())
        info = self.adapter.spec_info()
        self.assertEqual(info['spec_source'],
                         'https://docs.windsurf.com/windsurf/cascade/rules')
        self.assertEqual(info['spec_verified'], '2026-11-17')
        self.assertEqual(info['supported_versions'], 'current (unverified)')
        self.assertTrue(info['known_limitations'])

    def test_detection_surface(self):
        self.assertEqual(self.adapter.project_markers(self.ctx),
                         ['.windsurf', '.windsurfrules'])
        self.assertEqual(self.adapter.home_markers(self.ctx), [])
        self.assertIsNone(self.adapter.detect_version(self.ctx))
        self.assertIsNone(self.adapter.context_budget_bytes())
        self.assertEqual(self.adapter.instruction_sources(self.ctx), [])

    def test_config_files_follow_mcp_config_json(self):
        self.assertEqual(self.adapter.config_files(self.ctx), [])
        mcp = self.root / '.windsurf' / 'mcp_config.json'
        mcp.parent.mkdir(parents=True, exist_ok=True)
        mcp.write_text('{"mcpServers": {}}', encoding='utf-8')
        self.assertEqual(self.adapter.config_files(self.ctx), [mcp])
        self.assertEqual(self.adapter.mcp_config_files(self.ctx), [mcp])

    def test_skills_locations_points_at_workflows(self):
        self.assertEqual(self.adapter.skills_locations(self.ctx),
                         [self.root / '.windsurf' / 'workflows'])


class TestInstructionSources(WindsurfTestBase):
    def test_classification_of_all_trigger_kinds_plus_legacy(self):
        always = self.write_rule('always.md', FM_ALWAYS)
        glob = self.write_rule('glob.md', FM_GLOB)
        manual = self.write_rule('manual.md', FM_MANUAL)
        model = self.write_rule('model.md', FM_MODEL)
        legacy = self.write_legacy()
        srcs = {s.path.name: s for s in
                self.adapter.instruction_sources(self.ctx)}
        self.assertEqual(srcs['always.md'].scope, 'path_scoped')
        self.assertTrue(srcs['always.md'].always_apply)
        self.assertEqual(srcs['glob.md'].globs, ['**/*.py'])
        self.assertFalse(srcs['glob.md'].always_apply)
        self.assertEqual(srcs['manual.md'].description, 'held in reserve')
        self.assertEqual(srcs['model.md'].description, 'ask me first')
        self.assertEqual(srcs['.windsurfrules'].scope, 'project')
        self.assertEqual(srcs[legacy.name].path, legacy)

    def test_glob_field_forms(self):
        self.write_rule('comma.md', 'trigger: glob\nglob: "*.py, *.ts"')
        self.write_rule('block.md',
                        'trigger: glob\nglob:\n  - "*.py"\n  - src/**')
        self.write_rule('inline.md', 'trigger: glob\nglob: ["*.py"]')
        srcs = {s.path.name: s for s in
                self.adapter.instruction_sources(self.ctx)}
        self.assertEqual(srcs['comma.md'].globs, ['*.py', '*.ts'])
        self.assertEqual(srcs['block.md'].globs, ['*.py', 'src/**'])
        self.assertEqual(srcs['inline.md'].globs, ['*.py'])

    def test_rules_in_nested_dirs_are_collected(self):
        nested = self.root / '.windsurf' / 'rules' / 'python'
        nested.mkdir(parents=True)
        (nested / 'nested.md').write_text(
            '---\ntrigger: always\n---\n', encoding='utf-8')
        srcs = self.adapter.instruction_sources(self.ctx)
        self.assertEqual([s.path.name for s in srcs], ['nested.md'])


class TestResolveChain(WindsurfTestBase):
    def test_always_trigger_active_for_any_target(self):
        self.write_rule('always.md', FM_ALWAYS)
        deep = self.root / 'packages' / 'app'
        deep.mkdir(parents=True)
        for target in (None, self.root, deep):
            chain = self.chain(target)
            loaded = chain.loaded
            self.assertEqual(len(loaded), 1)
            self.assertTrue(loaded[0].active)
            self.assertEqual(loaded[0].precedence, 30)
            self.assertTrue(chain.approximated)

    def test_glob_rule_active_on_match_inactive_otherwise(self):
        self.write_rule('glob.md', 'trigger: glob\nglob: docs/**')
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
        self.assertEqual(source.path.name, 'glob.md')
        self.assertIn('does not match target', reason)

    def test_dir_prefix_glob_matches_dir_itself_and_children(self):
        self.write_rule('prefix.md', 'trigger: glob\nglob: src/**')
        src = self.root / 'src'
        src.mkdir()
        self.assertEqual(len(self.chain(src).loaded), 1)
        sub = src / 'deep' / 'pkg'
        sub.mkdir(parents=True)
        self.assertEqual(len(self.chain(sub).loaded), 1)
        elsewhere = self.root / 'other'
        elsewhere.mkdir()
        self.assertEqual(len(self.chain(elsewhere).loaded), 0)

    def test_model_decision_rule_inactive_with_reason(self):
        self.write_rule('model.md', FM_MODEL)
        chain = self.chain(self.root)
        self.assertEqual(chain.loaded, [])
        link = chain.links[0]
        self.assertFalse(link.active)
        self.assertIn('model decides', link.reason)

    def test_manual_rule_inactive_with_reason(self):
        self.write_rule('manual.md', FM_MANUAL)
        chain = self.chain(self.root)
        self.assertEqual(chain.loaded, [])
        self.assertEqual(chain.links[0].reason,
                         'manual rule: never auto-applied')

    def test_broken_triggers_inactive_with_reason(self):
        self.write_rule('notrigger.md', 'description: no trigger here')
        self.write_rule('weird.md', 'trigger: sometimes\ndescription: odd')
        self.write_rule('globskip.md', 'trigger: glob\ndescription: no glob')
        chain = self.chain(self.root)
        reasons = {l.source.path.name: l.reason for l in chain.links}
        self.assertEqual(chain.loaded, [])
        self.assertIn('no trigger', reasons['notrigger.md'])
        self.assertIn('unknown trigger', reasons['weird.md'])
        self.assertIn('no glob field', reasons['globskip.md'])

    def test_legacy_windsurfrules_precedence_below_rules(self):
        self.write_legacy()
        self.write_rule('always.md', FM_ALWAYS)
        self.write_rule('glob.md', 'trigger: glob\nglob: **')
        chain = self.chain(self.root)
        by_prec = {link.precedence: link for link in chain.links}
        self.assertEqual(sorted(by_prec), [10, 20, 30])
        self.assertEqual(by_prec[10].source.scope, 'project')
        self.assertTrue(by_prec[10].active)
        self.assertIn('legacy', by_prec[10].reason)
        self.assertTrue(all(l.active for l in chain.links))

    def test_chain_to_dict_shape(self):
        self.write_rule('always.md', FM_ALWAYS)
        self.write_rule('model.md', FM_MODEL)
        self.write_rule('glob.md', 'trigger: glob\nglob: nomatch/**')
        as_dict = self.chain(self.root).to_dict()
        self.assertEqual(as_dict['harness'], 'windsurf')
        self.assertTrue(as_dict['approximated'])
        self.assertEqual(len(as_dict['loaded']), 1)          # always only
        self.assertEqual(len(as_dict['overridden']), 1)      # model_decision
        self.assertIn('model decides', as_dict['overridden'][0]['reason'])
        self.assertEqual(len(as_dict['unloaded']), 1)        # glob, no match
        self.assertEqual(as_dict['conflicts'], [])


class TestValidate(WindsurfTestBase):
    def test_rule_no_trigger_positive_and_negative(self):
        self.write_rule('bare.md')                       # no frontmatter
        self.write_rule('nokey.md', 'description: no trigger key')
        found = self.findings()
        self.assertIn('WINDSURF_RULE_NO_TRIGGER', found)
        f = found['WINDSURF_RULE_NO_TRIGGER']
        self.assertEqual(f.status, 'warn')
        self.assertEqual(f.severity, 'medium')
        names = {e['file'].replace('\\', '/').rsplit('/', 1)[-1]
                 for e in f.evidence}
        self.assertEqual(names, {'bare.md', 'nokey.md'})
        # negative: any documented trigger keeps the rule unflagged
        (self.root / '.windsurf' / 'rules' / 'bare.md').unlink()
        (self.root / '.windsurf' / 'rules' / 'nokey.md').unlink()
        self.write_rule('good.md', FM_MANUAL)
        self.assertNotIn('WINDSURF_RULE_NO_TRIGGER', self.findings())

    def test_trigger_unknown_positive_and_negative(self):
        self.write_rule('weird.md', 'trigger: sometimes')
        found = self.findings()
        self.assertIn('WINDSURF_TRIGGER_UNKNOWN', found)
        f = found['WINDSURF_TRIGGER_UNKNOWN']
        self.assertEqual(f.status, 'warn')
        self.assertEqual(f.severity, 'medium')
        self.assertEqual(f.evidence[0]['trigger'], 'sometimes')
        # negative: all documented non-glob triggers pass
        (self.root / '.windsurf' / 'rules' / 'weird.md').unlink()
        for i, trig in enumerate(['always', 'manual', 'model_decision']):
            self.write_rule('ok%d.md' % i, 'trigger: %s' % trig)
        self.assertNotIn('WINDSURF_TRIGGER_UNKNOWN', self.findings())

    def test_glob_missing_positive_and_negative(self):
        self.write_rule('broken.md',
                        'trigger: glob\ndescription: forgot the pattern')
        found = self.findings()
        self.assertIn('WINDSURF_GLOB_MISSING', found)
        f = found['WINDSURF_GLOB_MISSING']
        self.assertEqual(f.status, 'fail')
        self.assertEqual(f.severity, 'medium')
        self.assertEqual(f.evidence[0]['file'],
                         str(self.root / '.windsurf' / 'rules'
                             / 'broken.md'))
        # negative: glob trigger with a glob field
        (self.root / '.windsurf' / 'rules' / 'broken.md').unlink()
        src = self.root / 'src'
        src.mkdir()
        (src / 'app.py').write_text('x = 1', encoding='utf-8')
        self.write_rule('ok.md', FM_GLOB)
        self.assertNotIn('WINDSURF_GLOB_MISSING', self.findings())

    def test_glob_nomatch_positive_and_negative(self):
        self.write_rule('dead.md', 'trigger: glob\nglob: nowhere/**')
        src = self.root / 'src'
        src.mkdir()
        (src / 'app.py').write_text('x = 1', encoding='utf-8')
        found = self.findings()
        self.assertIn('WINDSURF_GLOB_NOMATCH', found)
        f = found['WINDSURF_GLOB_NOMATCH']
        self.assertEqual(f.status, 'warn')
        self.assertEqual(f.severity, 'low')
        # negative: a rule whose glob covers src/ stays unflagged
        self.write_rule('alive.md', 'trigger: glob\nglob: src/**')
        found2 = self.findings()
        self.assertIn('WINDSURF_GLOB_NOMATCH', found2)      # dead.md still
        alive_flagged = any('alive.md' in str(e)
                            for e in found2['WINDSURF_GLOB_NOMATCH'].evidence)
        self.assertFalse(alive_flagged)

    def test_legacy_and_rules_positive_and_negative(self):
        legacy = self.write_legacy()
        # legacy alone: no conflict
        self.assertNotIn('WINDSURF_LEGACY_AND_RULES', self.findings())
        self.write_rule('rule.md', FM_MANUAL)
        found = self.findings()
        self.assertIn('WINDSURF_LEGACY_AND_RULES', found)
        f = found['WINDSURF_LEGACY_AND_RULES']
        self.assertEqual(f.status, 'warn')
        self.assertEqual(f.severity, 'medium')
        files = {e['file'] for e in f.evidence}
        self.assertIn(str(legacy), files)
        self.assertIn(str(self.root / '.windsurf' / 'rules'), files)
        # negative: rules dir alone
        (self.root / '.windsurfrules').unlink()
        self.assertNotIn('WINDSURF_LEGACY_AND_RULES', self.findings())

    def test_mcp_parse_positive_and_negative(self):
        mcp = self.root / '.windsurf' / 'mcp_config.json'
        mcp.parent.mkdir(parents=True, exist_ok=True)
        mcp.write_text('{ not json', encoding='utf-8')
        found = self.findings()
        self.assertIn('WINDSURF_MCP_PARSE', found)
        f = found['WINDSURF_MCP_PARSE']
        self.assertEqual(f.status, 'fail')
        self.assertEqual(f.severity, 'high')
        # negative: valid JSON parses clean
        mcp.write_text(json.dumps({'mcpServers': {}}), encoding='utf-8')
        self.assertNotIn('WINDSURF_MCP_PARSE', self.findings())


if __name__ == '__main__':
    unittest.main()
