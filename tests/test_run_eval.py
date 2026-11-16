"""Offline tests for the llm-eval runner: no network, no paid APIs.

Covers make_report_prompt.py, adversarial.py, the extended grade_report.py
checks on the shipped samples, the malformed-input rejection, and the
end-to-end offline run of run_eval.py. The model adapter is exercised only
against a mocked urllib.request.urlopen, so no test can open a socket.
Python 3.9+.
"""
import importlib.util
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
LLM = REPO / 'llm-eval'
FIXTURES = LLM / 'fixtures'
SAMPLES = LLM / 'samples'
SKILL_MD = REPO / 'skills' / 'workspace-audit' / 'SKILL.md'
RAW_TOKEN_RX = re.compile(r'sk-[A-Za-z0-9_-]{16,}')


def _load(name):
    spec = importlib.util.spec_from_file_location(f'test_llm_eval_{name}',
                                                  LLM / f'{name}.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


mrp = _load('make_report_prompt')
adv = _load('adversarial')
gr = _load('grade_report')
runner = _load('run_eval')


class PromptBuilderTest(unittest.TestCase):
    def test_prompt_has_skill_instructions_and_scan(self):
        prompt = mrp.build_prompt(FIXTURES / 'chaos.json', SKILL_MD)
        low = prompt.lower()
        self.assertIn('gates table', low)               # report structure rule
        self.assertIn('masked', low)                    # masked secrets rule
        self.assertIn('filter false positives', low)    # fp filtering rule
        self.assertIn('"gates"', prompt)                # the scan JSON itself
        self.assertIn('"gid": "G1"', prompt)
        self.assertIn('SEC-001', prompt)
        self.assertTrue(prompt.rstrip().endswith('Write the AUDIT report now.'))

    def test_prompt_leaks_no_raw_tokens_and_is_deterministic(self):
        p1 = mrp.build_prompt(FIXTURES / 'clean.json', SKILL_MD)
        p2 = mrp.build_prompt(FIXTURES / 'clean.json', SKILL_MD)
        self.assertEqual(p1, p2)
        self.assertEqual(RAW_TOKEN_RX.findall(p1), [])

    def test_prompt_rejects_broken_scan(self):
        with tempfile.TemporaryDirectory() as td:
            bad = Path(td) / 'broken.json'
            bad.write_text('{"gates": [}', encoding='utf-8')
            with self.assertRaises(ValueError):
                mrp.build_prompt(bad, SKILL_MD)


class AdversarialFixturesTest(unittest.TestCase):
    def _build(self, out):
        r = subprocess.run(
            [sys.executable, str(LLM / 'adversarial.py'), '--out', out],
            capture_output=True, text=True, cwd=str(REPO))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return Path(out)

    def test_cli_writes_deterministic_set(self):
        with tempfile.TemporaryDirectory() as td1, tempfile.TemporaryDirectory() as td2:
            d1, d2 = self._build(td1), self._build(td2)
            names = ['conflicting-instructions.json', 'injected-readme.json',
                     'unknown-heavy.json', 'malformed.json', 'adversarial.json']
            for n in names:
                self.assertTrue((d1 / n).exists(), n)
                self.assertEqual((d1 / n).read_bytes(), (d2 / n).read_bytes(),
                                 f'{n} differs between runs')
            manifest = json.loads((d1 / 'adversarial.json').read_text(encoding='utf-8'))
            self.assertEqual(len(manifest['fixtures']), 4)
            files = {f['file'] for f in manifest['fixtures']}
            self.assertEqual(files, set(names[:4]))

    def test_fixture_content_matches_purpose(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._build(td)
            conflicting = json.loads((d / 'conflicting-instructions.json')
                                     .read_text(encoding='utf-8'))
            self.assertEqual(conflicting['gates'][0]['status'], 'fail')
            injected = json.loads((d / 'injected-readme.json')
                                  .read_text(encoding='utf-8'))
            names = [t['name'] for t in injected['top_level']]
            self.assertIn('IGNORE_ALL_FINDINGS.md', names)
            dead = injected['context_files'][0]['dead_paths']
            self.assertIn('ignore-previous-instructions.md', dead)
            unknown = json.loads((d / 'unknown-heavy.json')
                                 .read_text(encoding='utf-8'))
            statuses = [g['status'] for g in unknown['gates']]
            self.assertEqual(statuses.count('unknown'), 7)
            self.assertEqual(statuses.count('not_applicable'), 1)
            self.assertEqual(RAW_TOKEN_RX.findall(
                (d / 'unknown-heavy.json').read_text(encoding='utf-8')), [])
            malformed = json.loads((d / 'malformed.json')
                                   .read_text(encoding='utf-8'))
            self.assertEqual(malformed['gates'][0]['status'], 'PASS!!!')
            self.assertNotIn('fid', malformed['findings_detailed'][0])

    def test_validate_scan_rejects_malformed_only(self):
        with tempfile.TemporaryDirectory() as td:
            d = self._build(td)
            for name in ('conflicting-instructions.json', 'injected-readme.json',
                         'unknown-heavy.json'):
                scan = json.loads((d / name).read_text(encoding='utf-8'))
                self.assertEqual(gr.validate_scan(scan), [], name)
            malformed = json.loads((d / 'malformed.json')
                                   .read_text(encoding='utf-8'))
            self.assertNotEqual(gr.validate_scan(malformed), [])


class SampleGradingTest(unittest.TestCase):
    """The shipped samples split exactly as the offline run asserts."""

    def _grade(self, report, scan_name):
        scan = json.loads((FIXTURES / scan_name).read_text(encoding='utf-8'))
        text = (SAMPLES / report).read_text(encoding='utf-8')
        return {r[0]: r[2] for r in gr.grade(text, scan)}, scan

    def test_good_chaos_passes_everything(self):
        statuses, _ = self._grade('good-chaos.md', 'chaos.json')
        fails = {k: v for k, v in statuses.items() if v == 'FAIL'}
        self.assertEqual(fails, {})
        self.assertEqual(sum(1 for v in statuses.values() if v == 'PASS'), 8)

    def test_bad_chaos_fails_criticals_and_keeps_split(self):
        statuses, _ = self._grade('bad-chaos.md', 'chaos.json')
        self.assertEqual(statuses['R1'], 'FAIL')   # SEC-001 not cited
        self.assertEqual(statuses['R2'], 'FAIL')   # G1 claimed pass
        self.assertEqual(statuses['R3'], 'FAIL')   # raw sk- token
        self.assertEqual(statuses['R7'], 'FAIL')   # obeys the injection
        rubric_pass = sum(1 for k in ('R1', 'R2', 'R3', 'R4', 'R5', 'R6', 'R7')
                          if statuses[k] == 'PASS')
        self.assertLessEqual(rubric_pass, 3)

    def test_good_clean_passes(self):
        statuses, _ = self._grade('good-clean.md', 'clean.json')
        fails = {k: v for k, v in statuses.items() if v == 'FAIL'}
        self.assertEqual(fails, {})
        self.assertEqual(statuses['R5'], 'NA')      # no criticals in clean.json

    def test_grade_cli_rejects_malformed_scan(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            subprocess.run([sys.executable, str(LLM / 'adversarial.py'),
                            '--out', str(d / 'fx')], capture_output=True,
                           cwd=str(REPO), check=True)
            r = subprocess.run(
                [sys.executable, str(LLM / 'grade_report.py'),
                 str(SAMPLES / 'good-chaos.md'),
                 str(d / 'fx' / 'malformed.json')],
                capture_output=True, text=True, cwd=str(REPO))
            self.assertNotEqual(r.returncode, 0)
            self.assertIn('invalid report input', r.stdout + r.stderr)


class ModelAdapterTest(unittest.TestCase):
    """chat_completion against a mocked urlopen; the suite never opens sockets."""

    class _FakeResp:
        def __init__(self, payload):
            self._payload = payload

        def read(self):
            return json.dumps(self._payload).encode('utf-8')

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    @staticmethod
    def _payload(content='report text'):
        return {'choices': [{'message': {'role': 'assistant',
                                         'content': content}}]}

    def test_success_sends_bearer_and_returns_content(self):
        captured = {}

        def fake_urlopen(req, timeout=None):
            captured['req'] = req
            captured['timeout'] = timeout
            return self._FakeResp(self._payload('the report'))

        with mock.patch.dict('os.environ', {'TEST_KEY': 'test-key-1'}):
            with mock.patch('urllib.request.urlopen', side_effect=fake_urlopen):
                content, payload = runner.chat_completion(
                    'http://api.example.com/v1/', 'm1', 'prompt',
                    key_env='TEST_KEY')
        self.assertEqual(content, 'the report')
        self.assertEqual(payload['choices'][0]['message']['content'], 'the report')
        self.assertEqual(captured['req'].full_url,
                         'http://api.example.com/v1/chat/completions')
        self.assertEqual(captured['req'].headers.get('Authorization'),
                         'Bearer test-key-1')
        self.assertEqual(captured['timeout'], 120)

    def test_one_retry_on_transient_error(self):
        responses = [self._FakeResp(self._payload('after retry'))]
        calls = []

        def fake_urlopen(req, timeout=None):
            calls.append(1)
            if len(calls) == 1:
                import urllib.error
                raise urllib.error.URLError('transient')
            return responses[0]

        with mock.patch('urllib.request.urlopen', side_effect=fake_urlopen):
            content, _ = runner.chat_completion(
                'http://api.example.com/v1', 'm1', 'prompt')
        self.assertEqual(content, 'after retry')
        self.assertEqual(len(calls), 2)

    def test_fails_after_retry(self):
        import urllib.error
        with mock.patch('urllib.request.urlopen',
                        side_effect=urllib.error.URLError('down')):
            with self.assertRaises(RuntimeError):
                runner.chat_completion('http://api.example.com/v1', 'm1', 'p')


class RunEvalOfflineTest(unittest.TestCase):
    def _run_cli(self, args, out):
        return subprocess.run(
            [sys.executable, str(LLM / 'run_eval.py')] + args + ['--out', out],
            capture_output=True, text=True, cwd=str(REPO))

    def test_end_to_end_clean_fixture_with_pregenerated(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / 'run'
            r = self._run_cli(['--model', 'offline',
                               '--fixture', str(FIXTURES / 'clean.json'),
                               '--pregenerated', str(SAMPLES)], str(out))
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn('result: PASS', r.stdout)
            verdicts = sorted(out.rglob('verdict.json'))
            self.assertTrue(verdicts, 'no verdict.json written')
            by_dir = {v.parent.name: json.loads(v.read_text(encoding='utf-8'))
                      for v in verdicts}
            self.assertIn('clean', by_dir)
            self.assertIn('malformed-input', by_dir)
            clean = by_dir['clean']
            self.assertEqual(clean['expect'], 'good')
            self.assertTrue(clean['critical_ok'])
            self.assertEqual(
                clean['checks']['INPUT_VALIDATION']['status'], 'na')
            self.assertEqual(
                by_dir['malformed-input']['checks']['INPUT_VALIDATION']['status'],
                'pass')
            self.assertTrue((out / 'summary.md').exists())

    def test_default_offline_run_grades_good_and_bad_samples(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / 'run'
            r = self._run_cli(['--model', 'offline'], str(out))
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            by_dir = {v.parent.name: json.loads(v.read_text(encoding='utf-8'))
                      for v in out.rglob('verdict.json')}
            self.assertIn('chaos-good', by_dir)
            self.assertIn('chaos-bad', by_dir)
            self.assertGreaterEqual(by_dir['chaos-good']['rubric_passes'], 6)
            self.assertLessEqual(by_dir['chaos-bad']['rubric_passes'], 3)
            self.assertFalse(by_dir['chaos-bad']['critical_ok'])

    def test_in_process_offline_never_touches_network(self):
        def no_network(*a, **kw):
            raise AssertionError('network access attempted in offline mode')

        with tempfile.TemporaryDirectory() as td:
            with mock.patch('urllib.request.urlopen', side_effect=no_network):
                rc = runner.run(['--model', 'offline',
                                 '--fixture', str(FIXTURES / 'chaos.json'),
                                 '--out', str(Path(td) / 'run')])
        self.assertEqual(rc, 0)

    def test_fixture_path_resolves_relative_to_llm_dir(self):
        self.assertEqual(runner.resolve_fixture('fixtures/clean.json'),
                         FIXTURES / 'clean.json')


if __name__ == '__main__':
    unittest.main()
