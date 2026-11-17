"""Tests for the Gemini CLI harness adapter
(skills/agents-doctor/scripts/harness/adapters/gemini_cli.py).

Covers registration and detection surface, resolve_chain hierarchy
(user/project/nested/imported), and positive+negative cases for every
GEMINI_* check_id emitted by validate().
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'skills' / 'agents-doctor' / 'scripts'))

from harness import adapter_ids, get_adapter
from harness.base import HarnessContext

try:
    import tomllib
except ImportError:
    tomllib = None

CHECK_IDS = {
    'GEMINI_IMPORT_MISSING', 'GEMINI_IMPORT_DEPTH',
    'GEMINI_SETTINGS_PARSE', 'GEMINI_COMMANDS_FRONTMATTER',
    'GEMINI_NESTED_ORPHAN', 'GEMINI_EXTENSION_LAYOUT',
}


class GeminiTestBase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.home = self.root / 'home'
        self.ctx = HarnessContext(root=self.root, home=self.home)
        self.adapter = get_adapter('gemini_cli')

    def write(self, rel, text):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8')
        return path

    def write_user_gemini(self, text='user layer\n'):
        path = self.home / '.gemini' / 'GEMINI.md'
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8')
        return path

    def write_project_gemini(self, text='project rules\n'):
        return self.write('GEMINI.md', text)

    def findings(self):
        return {f.check_id: f for f in self.adapter.validate(self.ctx)}

    def chain(self, target=None):
        return self.adapter.resolve_chain(self.ctx, target)

    def active_by_scope(self, target=None):
        chain = self.chain(target)
        out = {}
        for link in chain.loaded:
            out.setdefault(link.source.scope, []).append(link)
        return out, chain


class TestRegistrationAndDetection(GeminiTestBase):
    def test_registered_with_spec_metadata(self):
        self.assertIn('gemini_cli', adapter_ids())
        info = self.adapter.spec_info()
        self.assertIn('docs.gemini-cli', info['spec_source'])
        self.assertIn('github.com/google-gemini/gemini-cli',
                      info['spec_source'])
        self.assertEqual(info['spec_verified'], '2026-11-17')
        self.assertEqual(info['supported_versions'], 'current (unverified)')
        self.assertTrue(info['known_limitations'])

    def test_detection_surface(self):
        self.assertEqual(self.adapter.project_markers(self.ctx),
                         ['.gemini', 'GEMINI.md'])
        self.assertEqual(self.adapter.home_markers(self.ctx),
                         [self.home / '.gemini'])
        self.assertIsNone(self.adapter.detect_version(self.ctx))
        self.assertIsNone(self.adapter.context_budget_bytes())

    def test_config_files_follow_settings_json(self):
        self.assertEqual(self.adapter.config_files(self.ctx), [])
        home_settings = self.home / '.gemini' / 'settings.json'
        home_settings.parent.mkdir(parents=True, exist_ok=True)
        home_settings.write_text('{}', encoding='utf-8')
        self.assertEqual(self.adapter.config_files(self.ctx),
                         [home_settings])
        project = self.write('.gemini/settings.json', '{}')
        self.assertEqual(self.adapter.config_files(self.ctx),
                         [home_settings, project])
        self.assertEqual(self.adapter.mcp_config_files(self.ctx),
                         [home_settings, project])

    def test_skills_locations(self):
        self.assertEqual(self.adapter.skills_locations(self.ctx),
                         [self.root / '.gemini' / 'extensions',
                          self.root / '.gemini' / 'commands'])


class TestInstructionSources(GeminiTestBase):
    def test_scopes_user_project_nested(self):
        user = self.write_user_gemini()
        project = self.write_project_gemini()
        nested = self.write('packages/app/GEMINI.md', 'nested\n')
        srcs = {s.path: s for s in
                self.adapter.instruction_sources(self.ctx)}
        self.assertEqual(srcs[user].scope, 'user')
        self.assertEqual(srcs[project].scope, 'project')
        self.assertEqual(srcs[nested].scope, 'nested')

    def test_nested_gemini_found_at_any_depth_hidden_skipped(self):
        deep = self.write('a/b/c/GEMINI.md', 'deep\n')
        self.write('.hidden/GEMINI.md', 'hidden\n')
        paths = [s.path for s in
                 self.adapter.instruction_sources(self.ctx)]
        self.assertIn(deep, paths)
        self.assertNotIn(self.root / '.hidden' / 'GEMINI.md', paths)


class TestResolveChain(GeminiTestBase):
    def test_hierarchy_user_project_nested(self):
        self.write_user_gemini()
        self.write_project_gemini()
        pkg = self.root / 'packages' / 'app'
        pkg.mkdir(parents=True)
        (pkg / 'GEMINI.md').write_text('nested layer\n', encoding='utf-8')
        active, chain = self.active_by_scope(pkg)
        self.assertEqual(active['user'][0].precedence, 10)
        self.assertEqual(active['project'][0].precedence, 20)
        self.assertEqual(active['nested'][0].precedence, 30)
        self.assertTrue(all(l.active for l in chain.links))
        self.assertTrue(chain.approximated)

    def test_nested_off_target_path_inactive(self):
        self.write_project_gemini()
        nested = self.write('packages/app/GEMINI.md', 'nested\n')
        chain = self.chain()                    # target = root
        nested_links = [l for l in chain.links
                        if l.source.path == nested]
        self.assertEqual(len(nested_links), 1)
        self.assertFalse(nested_links[0].active)
        self.assertEqual(nested_links[0].reason, 'outside target path')
        # working inside the subtree activates the same file
        active, _ = self.active_by_scope(self.root / 'packages' / 'app')
        self.assertEqual(active['nested'][0].source.path, nested)

    def test_nested_precedence_by_distance_to_target(self):
        self.write('packages/GEMINI.md', 'level one\n')
        self.write('packages/app/GEMINI.md', 'level two\n')
        target = self.root / 'packages' / 'app'
        active, _ = self.active_by_scope(target)
        by_path = {l.source.path: l for l in active['nested']}
        self.assertEqual(by_path[target / 'GEMINI.md'].precedence, 30)
        self.assertEqual(
            by_path[self.root / 'packages' / 'GEMINI.md'].precedence, 29)

    def test_imports_inherit_precedence(self):
        self.write_project_gemini('rules, see @notes.md\n')
        self.write('notes.md', 'more rules, see @deep.md\n')
        self.write('deep.md', 'deepest\n')
        active, chain = self.active_by_scope(self.root)
        imported = sorted(active['imported'], key=lambda l: l.precedence)
        self.assertEqual([l.source.path.name for l in imported],
                         ['notes.md', 'deep.md'])
        self.assertEqual(imported[0].precedence, 21)   # project 20 + 1
        self.assertEqual(imported[1].precedence, 22)   # notes 21 + 1
        self.assertIn('hop 1', imported[0].reason)
        self.assertIn('hop 2', imported[1].reason)
        self.assertEqual(chain.unloaded, [])

    def test_import_sixth_hop_unloaded(self):
        self.write_project_gemini('see @f1.md\n')
        for i in range(1, 6):                     # f1..f5 each import next
            self.write('f%d.md' % i, 'hop, see @f%d.md\n' % (i + 1))
        self.write('f6.md', 'too deep\n')
        active, chain = self.active_by_scope(self.root)
        imported = {l.source.path.name: l for l in active['imported']}
        self.assertEqual(sorted(imported),
                         ['f1.md', 'f2.md', 'f3.md', 'f4.md', 'f5.md'])
        self.assertEqual(imported['f5.md'].precedence, 25)  # 20 + 5
        deep = [(s, r) for s, r in chain.unloaded
                if s.path.name == 'f6.md']
        self.assertEqual(len(deep), 1)
        self.assertIn('5 hops', deep[0][1])

    def test_missing_import_lands_in_unloaded(self):
        self.write_project_gemini('see @nowhere.md\n')
        active, chain = self.active_by_scope(self.root)
        self.assertNotIn('imported', active)
        self.assertEqual(len(chain.unloaded), 1)
        source, reason = chain.unloaded[0]
        self.assertEqual(source.path.name, 'nowhere.md')
        self.assertIn('not found', reason)

    def test_mention_without_path_shape_is_not_an_import(self):
        self.write_project_gemini('ping @john in the thread\n')
        active, chain = self.active_by_scope(self.root)
        self.assertNotIn('imported', active)
        self.assertEqual(chain.unloaded, [])

    def test_chain_to_dict_shape(self):
        self.write_user_gemini()
        self.write_project_gemini('see @notes.md\n')
        self.write('notes.md', 'notes\n')
        self.write('other/GEMINI.md', 'nested elsewhere\n')
        as_dict = self.chain(self.root).to_dict()
        self.assertEqual(as_dict['harness'], 'gemini_cli')
        self.assertTrue(as_dict['approximated'])
        self.assertEqual([e['scope'] for e in as_dict['loaded']],
                         ['user', 'project', 'imported'])
        self.assertEqual(len(as_dict['overridden']), 1)   # nested off path
        self.assertEqual(as_dict['overridden'][0]['reason'],
                         'outside target path')
        self.assertEqual(as_dict['unloaded'], [])
        self.assertEqual(as_dict['conflicts'], [])


class TestValidate(GeminiTestBase):
    def test_import_missing_positive_and_negative(self):
        self.write_project_gemini('see @docs/rules.md and @gone.md\n')
        (self.root / 'docs').mkdir()
        (self.root / 'docs' / 'rules.md').write_text('r', encoding='utf-8')
        found = self.findings()
        self.assertIn('GEMINI_IMPORT_MISSING', found)
        f = found['GEMINI_IMPORT_MISSING']
        self.assertEqual(f.status, 'fail')
        self.assertEqual(f.severity, 'medium')
        self.assertEqual([e['import'] for e in f.evidence], ['gone.md'])
        # negative: every import target exists
        self.write_project_gemini('see @docs/rules.md\n')
        self.assertNotIn('GEMINI_IMPORT_MISSING', self.findings())

    def test_import_depth_positive_and_negative(self):
        self.write_project_gemini('see @f1.md\n')
        for i in range(1, 6):
            self.write('f%d.md' % i, 'see @f%d.md\n' % (i + 1))
        self.write('f6.md', 'bottom\n')
        found = self.findings()
        self.assertIn('GEMINI_IMPORT_DEPTH', found)
        f = found['GEMINI_IMPORT_DEPTH']
        self.assertEqual(f.status, 'warn')
        self.assertEqual(f.severity, 'medium')
        self.assertEqual([e['import'] for e in f.evidence], ['f6.md'])
        # negative: 5 hops exactly is within the limit
        self.write('f5.md', 'bottom now\n')   # chain stops at hop 5
        self.assertNotIn('GEMINI_IMPORT_DEPTH', self.findings())

    def test_settings_invalid_json_and_non_object_fail_high(self):
        path = self.write('.gemini/settings.json', '{ not json')
        found = self.findings()
        self.assertIn('GEMINI_SETTINGS_PARSE', found)
        f = found['GEMINI_SETTINGS_PARSE']
        self.assertEqual(f.status, 'fail')
        self.assertEqual(f.severity, 'high')
        path.write_text('["not", "an", "object"]', encoding='utf-8')
        found = self.findings()
        self.assertEqual(found['GEMINI_SETTINGS_PARSE'].status, 'fail')
        self.assertEqual(found['GEMINI_SETTINGS_PARSE'].severity, 'high')
        # negative: a plain valid object passes
        path.write_text('{"theme": "auto"}', encoding='utf-8')
        self.assertNotIn('GEMINI_SETTINGS_PARSE', self.findings())

    def test_settings_tool_filters_not_lists_warn(self):
        path = self.write('.gemini/settings.json',
                          '{"excludeTools": "run_shell_command"}')
        found = self.findings()
        self.assertIn('GEMINI_SETTINGS_PARSE', found)
        f = found['GEMINI_SETTINGS_PARSE']
        self.assertEqual(f.status, 'warn')
        self.assertEqual({e['key'] for e in f.evidence},
                         {'excludeTools'})
        # negative: both filters as lists pass
        path.write_text(json.dumps({'excludeTools': ['run_shell_command'],
                                    'coreTools': []}),
                        encoding='utf-8')
        self.assertNotIn('GEMINI_SETTINGS_PARSE', self.findings())

    def test_commands_missing_description(self):
        cmds = self.root / '.gemini' / 'commands'
        cmds.mkdir(parents=True)
        (cmds / 'deploy.toml').write_text('prompt = "deploy"\n',
                                          encoding='utf-8')
        found = self.findings()
        self.assertIn('GEMINI_COMMANDS_FRONTMATTER', found)
        f = found['GEMINI_COMMANDS_FRONTMATTER']
        if tomllib is None:
            self.assertEqual(f.status, 'unknown')
        else:
            self.assertEqual(f.status, 'warn')
            self.assertEqual(f.severity, 'low')
            self.assertEqual([Path(e['file']).name for e in f.evidence],
                             ['deploy.toml'])
            # negative: description present
            (cmds / 'deploy.toml').write_text(
                'description = "deploy the app"\nprompt = "deploy"\n',
                encoding='utf-8')
            self.assertNotIn('GEMINI_COMMANDS_FRONTMATTER',
                             self.findings())

    @unittest.skipIf(tomllib is None, 'tomllib unavailable')
    def test_commands_invalid_toml_fails(self):
        cmds = self.root / '.gemini' / 'commands'
        cmds.mkdir(parents=True)
        (cmds / 'broken.toml').write_text('description = unquoted\n',
                                          encoding='utf-8')
        found = self.findings()
        self.assertIn('GEMINI_COMMANDS_FRONTMATTER', found)
        self.assertEqual(found['GEMINI_COMMANDS_FRONTMATTER'].status,
                         'fail')

    def test_nested_orphan_positive_and_negative(self):
        orphan = self.write('packages/GEMINI.md', 'nested only\n')
        found = self.findings()
        self.assertIn('GEMINI_NESTED_ORPHAN', found)
        f = found['GEMINI_NESTED_ORPHAN']
        self.assertEqual(f.status, 'info')
        self.assertEqual(f.severity, 'low')
        self.assertEqual(f.evidence[0]['file'], str(orphan))
        # negative: root GEMINI.md present
        self.write_project_gemini()
        self.assertNotIn('GEMINI_NESTED_ORPHAN', self.findings())

    def test_extension_layout_positive_and_negative(self):
        ext = self.root / '.gemini' / 'extensions' / 'linter'
        ext.mkdir(parents=True)
        found = self.findings()
        self.assertIn('GEMINI_EXTENSION_LAYOUT', found)
        f = found['GEMINI_EXTENSION_LAYOUT']
        self.assertEqual(f.status, 'warn')
        self.assertEqual(f.severity, 'low')
        self.assertEqual(f.evidence[0]['file'], str(ext))
        # negative: extension with GEMINI.md inside
        (ext / 'GEMINI.md').write_text('lint rules\n', encoding='utf-8')
        self.assertNotIn('GEMINI_EXTENSION_LAYOUT', self.findings())

    def test_clean_workspace_yields_no_findings(self):
        self.assertEqual(self.adapter.validate(self.ctx), [])


if __name__ == '__main__':
    unittest.main()
