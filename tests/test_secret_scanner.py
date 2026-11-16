"""Tests for skills/agents-doctor/scripts/secret_scanner.py.

Every test that produces findings plants canary literals in the scanned
input and asserts they never appear in json.dumps(results): raw secret
values must not leak through findings.
"""
import hashlib
import json
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'skills' / 'agents-doctor' / 'scripts'))

import secret_scanner

CANARY = 'CANARY-SK-abcdefghijklmnop'

# Lines that look like secrets but must NOT be flagged (placeholders,
# env indirection, too-short values, keyword glued into a longer word).
PLACEHOLDER_LINES = [
    '${DB_PASSWORD}',
    'sk-short',
    'API_KEY = os.environ["API_KEY"]',
    'PASSWORDX = "y"',
    'password = ""',
    'Bearer abcdefghij',  # token shorter than 20 chars
]

# (line, expected rule id) pairs that must be detected.
MUST_DETECT = [
    ('sk-abcdefghijklmnop1234', 'SEC-001'),
    ('Bearer abcdefghijklmnopqrstuv', 'SEC-002'),
    ('AKIAIOSFODNN7EXAMPLE', 'SEC-003'),
    ('-----BEGIN RSA PRIVATE KEY-----', 'SEC-004'),
    ('-----BEGIN OPENSSH PRIVATE KEY-----', 'SEC-004'),
    ('api_key = "supersecretvalue"', 'SEC-005'),
    ('DB_PASSWORD: "hunter2-secret"', 'SEC-005'),  # yaml colon form
    ('"Authorization": "Bearer abcdefghijklmnopqrstuv"', 'SEC-002'),
]

SCAN_TEXT_KEYS = {'file', 'line', 'kind', 'rule_id', 'confidence',
                  'value', 'mask', 'fingerprint'}
GREP_KEYS = {'file', 'line', 'kind', 'rule_id', 'confidence',
             'value', 'fingerprint'}
DIFF_KEYS = SCAN_TEXT_KEYS | {'commit'}


class NoLeakMixin:
    """Shared leak assertions for tests that produce findings."""

    def assert_no_raw_secrets(self, findings, raw_values):
        self.assertTrue(raw_values)
        blob = json.dumps(findings)
        for value in raw_values:
            self.assertNotIn(value, blob, 'raw secret leaked: %r' % value)
        for finding in findings:
            self.assertEqual(finding['value'], '[REDACTED]')


class FingerprintTests(unittest.TestCase):
    def test_salted_not_plain_sha256(self):
        plain16 = hashlib.sha256(b'x').hexdigest()[:16]
        self.assertNotEqual(secret_scanner.fingerprint('x'), 'sha256:' + plain16)
        self.assertNotEqual(secret_scanner.fingerprint('x'), plain16)

    def test_stable_across_calls(self):
        self.assertEqual(secret_scanner.fingerprint('x'),
                         secret_scanner.fingerprint('x'))

    def test_format(self):
        fp = secret_scanner.fingerprint('some-value')
        self.assertTrue(fp.startswith('hmac256:'))
        hex_part = fp[len('hmac256:'):]
        self.assertEqual(len(hex_part), 32)  # 128 bits
        int(hex_part, 16)  # raises unless hex digits only

    def test_different_inputs_differ(self):
        self.assertNotEqual(secret_scanner.fingerprint('a'),
                            secret_scanner.fingerprint('b'))


class FindInLineTests(unittest.TestCase):
    def test_placeholders_do_not_match(self):
        for line in PLACEHOLDER_LINES:
            self.assertIsNone(secret_scanner.find_in_line(line), line)
            self.assertEqual(secret_scanner.scan_text('f.py', line), [], line)

    def test_must_detect_lines(self):
        for line, rule_id in MUST_DETECT:
            rule = secret_scanner.find_in_line(line)
            self.assertIsNotNone(rule, line)
            self.assertEqual(rule['id'], rule_id, line)

    def test_returns_rule_dict_from_rules(self):
        self.assertIs(secret_scanner.find_in_line('sk-abcdefghijklmnop1234'),
                      secret_scanner.RULES[0])


class ScanTextTests(unittest.TestCase, NoLeakMixin):
    TEXT = '\n'.join([
        '# settings',
        'api_key = "supersecretvalue99"',
        'db_password: "hunter2-secret-value"',
        'token = "' + CANARY + '"',
        'sk-abcdefghijklmnop1234',
        'Bearer abcdefghijklmnopqrstuv',
        'AKIAIOSFODNN7EXAMPLE',
        '-----BEGIN OPENSSH PRIVATE KEY-----',
        'password = ""',  # placeholder: no finding
        'print("done")',
    ])
    RAW = [
        'supersecretvalue99',
        'hunter2-secret-value',
        CANARY,
        'sk-abcdefghijklmnop1234',
        'abcdefghijklmnopqrstuv',
        'AKIAIOSFODNN7EXAMPLE',
        'OPENSSH PRIVATE KEY',
    ]

    def test_redaction_lines_and_keys(self):
        findings = secret_scanner.scan_text('cfg/settings.py', self.TEXT)
        self.assertEqual([f['line'] for f in findings], [2, 3, 4, 5, 6, 7, 8])
        self.assertEqual([f['rule_id'] for f in findings],
                         ['SEC-005', 'SEC-005', 'SEC-005', 'SEC-001',
                          'SEC-002', 'SEC-003', 'SEC-004'])
        for finding in findings:
            self.assertEqual(set(finding), SCAN_TEXT_KEYS)
            self.assertEqual(finding['file'], 'cfg/settings.py')
            self.assertEqual(finding['value'], '[REDACTED]')
        self.assert_no_raw_secrets(findings, self.RAW)

    def test_fingerprint_comes_from_matched_substring(self):
        findings = secret_scanner.scan_text('f.txt', self.TEXT)
        by_line = {f['line']: f for f in findings}
        self.assertEqual(by_line[5]['fingerprint'],
                         secret_scanner.fingerprint('sk-abcdefghijklmnop1234'))
        # SEC-005 match spans keyword + separator + opening quote + value;
        # the closing quote is not part of the match ([^"']{8,}).
        self.assertEqual(by_line[4]['fingerprint'],
                         secret_scanner.fingerprint('token = "' + CANARY))

    def test_mask_comes_from_rule_not_value(self):
        text = ('a = "sk-CANARY-abcdefghijklmnop"\n'
                'b = "sk-CANARY-zyxwvutsrqponmlk"\n')
        findings = secret_scanner.scan_text('f.txt', text)
        self.assertEqual(len(findings), 2)
        self.assertEqual([f['mask'] for f in findings], ['sk-***', 'sk-***'])
        self.assertEqual(findings[0]['mask'], secret_scanner.RULES[0]['mask'])
        # same mask, different values -> different fingerprints
        self.assertNotEqual(findings[0]['fingerprint'], findings[1]['fingerprint'])
        self.assert_no_raw_secrets(findings,
                                   ['sk-CANARY-abcdefghijklmnop',
                                    'sk-CANARY-zyxwvutsrqponmlk'])

    def test_first_rule_wins_one_finding_per_line(self):
        # SEC-001 and SEC-005 both match; SEC-001 comes first in RULES.
        findings = secret_scanner.scan_text('f.py',
                                            'password = "sk-CANARY-abcdefghijklmnop"')
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['rule_id'], 'SEC-001')
        self.assertEqual(findings[0]['mask'], 'sk-***')
        # SEC-002 beats SEC-005 on an Authorization header.
        findings = secret_scanner.scan_text(
            'h.py', '"Authorization": "Bearer CANARYabcdefghijklmnopqr"')
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['rule_id'], 'SEC-002')
        self.assert_no_raw_secrets(findings,
                                   ['sk-CANARY-abcdefghijklmnop',
                                    'CANARYabcdefghijklmnopqr'])

    def test_empty_input(self):
        self.assertEqual(secret_scanner.scan_text('f.txt', ''), [])


class GitGrepTests(unittest.TestCase, NoLeakMixin):
    def test_paths_with_spaces_and_colons(self):
        out = '\n'.join([
            'dir with spaces/settings.py:12:token = "' + CANARY + '"',
            'we:ird/path.py:7:AKIAIOSFODNN7EXAMPLE',
            'clean.py:3:print("nothing here")',
        ])
        findings = secret_scanner.scan_git_grep_output(out)
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0]['file'], 'dir with spaces/settings.py')
        self.assertEqual(findings[0]['line'], 12)
        self.assertEqual(findings[0]['rule_id'], 'SEC-005')
        self.assertEqual(findings[1]['file'], 'we:ird/path.py')
        self.assertEqual(findings[1]['line'], 7)
        self.assertEqual(findings[1]['rule_id'], 'SEC-003')
        self.assertEqual(findings[1]['fingerprint'],
                         secret_scanner.fingerprint('AKIAIOSFODNN7EXAMPLE'))
        for finding in findings:
            self.assertEqual(set(finding), GREP_KEYS)
            self.assertEqual(finding['value'], '[REDACTED]')
            self.assertNotIn('mask', finding)
        self.assert_no_raw_secrets(findings, [CANARY, 'AKIAIOSFODNN7EXAMPLE'])

    def test_non_matching_and_empty_input(self):
        self.assertEqual(secret_scanner.scan_git_grep_output(''), [])
        self.assertEqual(secret_scanner.scan_git_grep_output('not a grep line'),
                         [])


class DiffTests(unittest.TestCase, NoLeakMixin):
    DIFF_TEXT = '''\
commit aaaabbbbccccdddd000011112222333344445555
Author: Dev <dev@example.com>
Date:   Mon Nov 16 10:00:00 2026 +0300

    add config

diff --git a/config.py b/config.py
index 1111111..2222222 100644
--- a/config.py
+++ b/config.py
@@ -1,4 +1,6 @@
 import os
-password = "old-value"
+password = "''' + CANARY + '''"
+key = "sk-abcdefghijklmnop1234"
 print("done")
 Bearer abcdefghijklmnopqrstuv

commit 9999eeee88887777666655554444333322221111
Author: Dev <dev@example.com>
Date:   Mon Nov 16 11:00:00 2026 +0300

    add creds, drop old

diff --git a/new dir/creds.txt b/new dir/creds.txt
new file mode 100644
index 0000000..3333333
--- /dev/null
+++ b/new dir/creds.txt
@@ -0,0 +1,3 @@
+AKIAIOSFODNN7EXAMPLE
+Bearer abcdefghijklmnopqrstuv
+clean tail line
\\ No newline at end of file

diff --git a/old.txt b/old.txt
deleted file mode 100644
index 4444444..0000000
--- a/old.txt
+++ /dev/null
@@ -1,1 +0,0 @@
-token = "''' + CANARY + '''"
'''

    def test_multi_commit_diff(self):
        findings = secret_scanner.scan_diff_output(self.DIFF_TEXT)
        expected = [
            ('config.py', 2, 'SEC-005', 'aaaabbb'),
            ('config.py', 3, 'SEC-001', 'aaaabbb'),
            ('config.py', 5, 'SEC-002', 'aaaabbb'),      # context line, new-side no.
            ('new dir/creds.txt', 1, 'SEC-003', '9999eee'),
            ('new dir/creds.txt', 2, 'SEC-002', '9999eee'),
        ]
        self.assertEqual([(f['file'], f['line'], f['rule_id'], f['commit'])
                          for f in findings], expected)
        for finding in findings:
            self.assertEqual(set(finding), DIFF_KEYS)
            self.assertEqual(finding['value'], '[REDACTED]')
        self.assert_no_raw_secrets(findings,
                                   [CANARY, 'sk-abcdefghijklmnop1234',
                                    'AKIAIOSFODNN7EXAMPLE',
                                    'abcdefghijklmnopqrstuv'])
        # the deleted old.txt (new side /dev/null) contributes nothing:
        # its '-token = "<canary>"' line is old-side and never scanned

    def test_max_hits_stops_early(self):
        findings = secret_scanner.scan_diff_output(self.DIFF_TEXT, max_hits=2)
        self.assertEqual(len(findings), 2)
        self.assertEqual([f['commit'] for f in findings],
                         ['aaaabbb', 'aaaabbb'])
        self.assert_no_raw_secrets(findings, [CANARY, 'sk-abcdefghijklmnop1234'])

    def test_empty_input(self):
        self.assertEqual(secret_scanner.scan_diff_output(''), [])


class GitGrepReTests(unittest.TestCase):
    def test_covers_rule_set_tokens(self):
        self.assertIsInstance(secret_scanner.GIT_GREP_RE, str)
        for token in ('sk-', 'Bearer', 'AKIA', 'PRIVATE KEY',
                      'api', 'password', 'token'):
            self.assertIn(token, secret_scanner.GIT_GREP_RE)

    def test_consistent_with_must_detect_and_placeholders(self):
        # Translate POSIX classes to Python re to check the ERE string picks
        # up the same lines the RULES regexes do.
        py_re = re.compile(
            secret_scanner.GIT_GREP_RE.replace('[[:space:]]', r'\s'),
            re.IGNORECASE)
        for line, _rule_id in MUST_DETECT:
            self.assertIsNotNone(py_re.search(line), line)
        for line in PLACEHOLDER_LINES:
            self.assertIsNone(py_re.search(line), line)


if __name__ == '__main__':
    unittest.main()
