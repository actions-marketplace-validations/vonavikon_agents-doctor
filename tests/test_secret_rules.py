"""Tests for skills/agents-doctor/scripts/secret_rules.py.

Parity: for every PARITY_CORPUS line find_rule(line) must match the
expected id, and for positives find_rule_ere(line) must pick the same
id. ERE strings are validated with an allowlist checker (no git
invocations): only POSIX ERE constructs may appear. The legacy
SEC-001..005 entries must stay identical to secret_scanner.RULES.
"""
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'skills' / 'agents-doctor' / 'scripts'))

import secret_rules
import secret_scanner


def assert_ere_safe(test, expr):
    """Allowlist checker: expr must only use POSIX ERE constructs that
    `git grep -E` accepts. Python-only constructs (\\b, (?...), \\s,
    \\d, \\w) and malformed interval expressions are rejected."""
    for bad in ('\\b', '(?', '\\s', '\\d', '\\w', '\\A', '\\z', '\\Z'):
        test.assertNotIn(bad, expr, '%r contains forbidden %r' % (expr, bad))
    i = 0
    while i < len(expr):
        if expr[i] == '{':
            end = expr.find('}', i)
            test.assertNotEqual(-1, end, 'unterminated { in %r' % expr)
            inner = expr[i + 1:end]
            test.assertRegex(inner, r'^[0-9]+(,[0-9]*)?$',
                             'bad interval {%s} in %r' % (inner, expr))
            i = end
        i += 1
    test.assertEqual(expr.count('('), expr.count(')'),
                     'unbalanced () in %r' % expr)


class RuleShapeTests(unittest.TestCase):
    REQUIRED_KEYS = {'id', 'kind', 'mask', 'confidence', 'py', 'ere'}

    def test_every_rule_has_required_keys_and_types(self):
        ids = []
        for rule in secret_rules.RULES:
            self.assertTrue(self.REQUIRED_KEYS <= set(rule), rule.get('id'))
            self.assertIsInstance(rule['id'], str)
            self.assertIsInstance(rule['kind'], str)
            self.assertIsInstance(rule['mask'], str)
            self.assertTrue(rule['mask'], rule['id'])
            self.assertIsInstance(rule['py'], re.Pattern)
            self.assertIsInstance(rule['ere'], str)
            self.assertTrue(rule['ere'], rule['id'])
            self.assertIsInstance(rule['confidence'], float)
            self.assertGreater(rule['confidence'], 0.0)
            self.assertLessEqual(rule['confidence'], 1.0)
            ids.append(rule['id'])
        self.assertEqual(len(ids), len(set(ids)), 'duplicate rule ids')

    def test_rule_order_specific_before_generic(self):
        self.assertEqual([r['id'] for r in secret_rules.RULES],
                         ['SEC-001', 'SEC-002', 'SEC-003', 'SEC-004',
                          'SEC-101', 'SEC-102', 'SEC-103', 'SEC-104',
                          'SEC-105', 'SEC-106', 'SEC-107', 'SEC-005'])


class LegacyRulesPreservedTests(unittest.TestCase):
    """SEC-001..005 keep ids, kinds, masks, confidences and python
    patterns identical to the current secret_scanner behavior."""

    def test_sec_001_to_005_match_secret_scanner(self):
        ours = {r['id']: r for r in secret_rules.RULES}
        for legacy in secret_scanner.RULES:
            rule = ours[legacy['id']]
            self.assertEqual(rule['kind'], legacy['kind'], legacy['id'])
            self.assertEqual(rule['mask'], legacy['mask'], legacy['id'])
            self.assertEqual(rule['confidence'], legacy['confidence'], legacy['id'])
            self.assertEqual(rule['py'].pattern, legacy['regex'].pattern,
                             legacy['id'])


class CorpusParityTests(unittest.TestCase):
    def test_python_and_ere_agree_on_corpus(self):
        positives = 0
        for line, expected in secret_rules.PARITY_CORPUS:
            with self.subTest(line=line):
                rule = secret_rules.find_rule(line)
                if expected is None:
                    self.assertIsNone(rule, line)
                else:
                    self.assertIsNotNone(rule, line)
                    self.assertEqual(rule['id'], expected, line)
                    self.assertEqual(secret_rules.find_rule_ere(line), expected, line)
                    positives += 1
        self.assertGreaterEqual(positives, 24)

    def test_every_rule_has_two_positive_lines(self):
        counts = {}
        for line, expected in secret_rules.PARITY_CORPUS:
            if expected is not None:
                counts[expected] = counts.get(expected, 0) + 1
        for rule in secret_rules.RULES:
            self.assertGreaterEqual(counts.get(rule['id'], 0), 2, rule['id'])

    def test_spec_false_positive_lines_are_non_findings(self):
        corpus = dict(secret_rules.PARITY_CORPUS)
        for line in [
            '${DB_PASSWORD}',
            'os.environ["API_KEY"]',
            'PASSWORDX = "y"',
            'password = ""',
            'password = "short"',
            'token = "12345678"',
            'see https://example.com/reset?token=abc',
            'API_KEY=${VAR}',
            'Bearer abcdefghij',
            'Authorization: Bearer <token>',
            'eyJ',
        ]:
            self.assertIn(line, corpus)
            self.assertIsNone(corpus[line], line)
            self.assertIsNone(secret_rules.find_rule(line), line)


class EreSyntaxTests(unittest.TestCase):
    def test_rule_eres_use_only_ere_constructs(self):
        for rule in secret_rules.RULES:
            assert_ere_safe(self, rule['ere'])

    def test_combined_res_are_ere_safe(self):
        assert_ere_safe(self, secret_rules.GIT_GREP_RE_COMBINED)
        assert_ere_safe(self, secret_rules.GIT_GREP_RE)


class CombinedReTests(unittest.TestCase):
    def test_combined_joined_in_stable_rule_order(self):
        self.assertEqual(secret_rules.GIT_GREP_RE_COMBINED,
                         '|'.join(r['ere'] for r in secret_rules.RULES))

    def test_git_grep_re_alias(self):
        self.assertEqual(secret_rules.GIT_GREP_RE,
                         secret_rules.GIT_GREP_RE_COMBINED)

    def test_combined_re_covers_every_alternative(self):
        for rule in secret_rules.RULES:
            self.assertIn(rule['ere'], secret_rules.GIT_GREP_RE_COMBINED,
                          rule['id'])


class WeakValueDecisionTests(unittest.TestCase):
    def test_digit_only_literal_is_not_a_finding(self):
        self.assertIsNone(secret_rules.find_rule('token = "12345678"'))

    def test_mixed_literal_still_a_finding(self):
        rule = secret_rules.find_rule('token = "abc12345"')
        self.assertIsNotNone(rule)
        self.assertEqual(rule['id'], 'SEC-005')


if __name__ == '__main__':
    unittest.main()
