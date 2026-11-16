"""Margin tests for gates.py: the CI floor is exactly 90%, and a floor
sitting on the boundary is a flake factory. These pin a few small branches
(worst_status ordering, empty-dirs pass branch, G7 single-checkout warn
wording, G5 fallback-parser wording, drift-ownership cross-reference)."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]
                       / 'skills' / 'agents-doctor' / 'scripts'))
import gates  # noqa: E402


def _minimal(**over):
    rep = {
        'context_drift': [], 'context_files': [], 'context_tax': {},
        'harness': {'tools': [], 'project_dirs': [], 'notes': []},
        'skills': {'entries': [], 'duplicates': []}, 'skills_extra': {},
        'top_level': [], 'dup_checkouts': {}, 'junk': {},
        'duplicates': [], 'large_files': [], 'secrets': [],
        'chain_budget_over': False, 'context_budget': [],
        'junk_classified': [], 'config_integrity': [],
        'heavy_outside_git': [],
    }
    rep.update(over)
    return rep


class WorstStatusTests(unittest.TestCase):
    def test_order_and_empty(self):
        self.assertEqual(gates.worst_status([]), 'unknown')
        self.assertEqual(gates.worst_status(['pass', 'warn']), 'warn')
        self.assertEqual(gates.worst_status(['not_applicable', 'unknown']),
                         'unknown')
        self.assertEqual(gates.worst_status(['fail', 'warn', 'unknown']), 'fail')

    def test_unknown_rank_beats_pass(self):
        self.assertEqual(gates.worst_status(['pass', 'unknown']), 'unknown')


class GateBranches(unittest.TestCase):
    def eval_statuses(self, rep):
        g, _f = gates.evaluate(rep)
        return {x['gid']: x['status'] for x in g}

    def test_few_empty_dirs_pass_finding(self):
        rep = _minimal(junk={'files': [], 'dirs': [], 'empty_dirs': ['a']})
        g, findings = gates.evaluate(rep)
        empty = [f for f in findings if 'empty director' in f['title']]
        self.assertEqual(len(empty), 1)
        self.assertEqual(empty[0]['status'], 'pass')
        self.assertEqual(self.eval_statuses(rep)['G9'], 'pass')

    def test_dup_checkout_warn(self):
        repo = {'name': 'a', 'kind': 'repo',
                'git': {'remote': 'https://x/y', 'last_commit': 't',
                        'dirty': [], 'untracked': [],
                        'credentials_in_remote': False},
                'extra': {'hooks': [], 'gitignore': True,
                          'tracked_secrets': []}}
        rep = _minimal(top_level=[repo],
                       dup_checkouts={'https://x/y': ['a', 'b']})
        g, findings = gates.evaluate(rep)
        self.assertTrue(any('checkouts' in f['title'] for f in findings))

    def test_fallback_parser_unknown_wording(self):
        rep = _minimal(
            skills={'entries': [{'name': 's', 'path': 'p/SKILL.md',
                                 'desc_len': 10, 'has_triggers': True,
                                 'location': 'project-agents'}],
                    'duplicates': []},
            skills_extra={'p/SKILL.md': {'frontmatter_ok': None,
                                         'missing_fields': ['name'],
                                         'dead_refs': [], 'parser': 'fallback',
                                         'path': 'p/SKILL.md'}})
        g, findings = gates.evaluate(rep)
        self.assertTrue(any('fallback parser' in f['title'].lower()
                            or 'frontmatter checks skipped' in f['title']
                            for f in findings))
        self.assertEqual(self.eval_statuses(rep)['G5'], 'unknown')

    def test_drift_ownership_cross_reference(self):
        rep = _minimal(context_drift=[{'path': 'ws', 'jaccard': 0.0}])
        st = self.eval_statuses(rep)
        g, findings = gates.evaluate(rep)
        # drift fails G1 (structure) and G3 (rules); G8 only cross-references
        self.assertEqual(st['G1'], 'fail')
        self.assertEqual(st['G3'], 'fail')
        g8 = next(x for x in g if x['gid'] == 'G8')
        self.assertTrue(any('drifted pairs: 1' in e for e in g8['evidence']))


if __name__ == '__main__':
    unittest.main()
