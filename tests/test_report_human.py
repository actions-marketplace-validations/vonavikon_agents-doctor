"""Tests for skills/workspace-audit/scripts/report_human.py.

Runs the plain-language generator over the chaos and clean fixtures:
token math sanity, bilingual section structure, the before/after story,
secret discipline (counts only, never values) and the fid-to-plain-
sentence mapping. Python 3.9+.
"""
import copy
import json
import re
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'skills' / 'workspace-audit' / 'scripts'))

import report_human  # noqa: E402

CHAOS = REPO / 'llm-eval' / 'fixtures' / 'chaos.json'
CLEAN = REPO / 'llm-eval' / 'fixtures' / 'clean.json'

EN_HEADERS = [
    '# What the audit found — in plain words',
    '## The short version',
    '## What this costs you',
    '## What is wrong, in plain words',
    '## Next step',
]
EN_BETTER_HEADER = '## What gets better after cleanup'
FID_BULLET_RE = re.compile(r'\([A-Z]{2,4}-\d{1,3}\)\s*$')


def load(path):
    return json.loads(path.read_text(encoding='utf-8'))


def section(md, header):
    """Lines of one '## ' section, without the header line."""
    lines = md.splitlines()
    start = lines.index(header)
    body = []
    for line in lines[start + 1:]:
        if line.startswith('## ') or line.startswith('# '):
            break
        body.append(line)
    return body


def make_after(chaos):
    """A fabricated post-cleanup scan: smaller instructions and memory,
    junk/duplicates/large files emptied, most gates patched but G3 left
    failing so the report still has a 'Still to do' list."""
    after = copy.deepcopy(chaos)
    ct = after['context_tax']
    for f in ct['session_files']:
        if f['role'] == 'project':
            f['size_bytes'] = 9000
        elif f['role'] == 'memory-index':
            f['size_bytes'] = 20000
    ct['project_total_bytes'] = 9000
    ct['memory_over_limit'] = []
    ct['memory_over_lines'] = []
    after['junk'] = {'files': [], 'dirs': [], 'empty_dirs': []}
    after['junk_classified'] = []
    after['duplicates'] = []
    after['large_files'] = []
    after['secrets'] = []
    after['findings_detailed'] = []
    for g in after['gates']:
        g['status'] = 'pass' if g['gid'] != 'G3' else 'fail'
    return after


class TestTokenMath(unittest.TestCase):

    def setUp(self):
        self.chaos = load(CHAOS)

    def test_chaos_overhead_positive(self):
        self.assertGreater(report_human.session_overhead_bytes(self.chaos), 0)

    def test_chaos_overhead_exact(self):
        # project 65242-16384=48858 plus memory 42188-24985=17203,
        # the memory path listed twice (limit + lines) counted once
        self.assertEqual(report_human.session_overhead_bytes(self.chaos),
                         66061)

    def test_mid_is_bytes_div4(self):
        ob = report_human.session_overhead_bytes(self.chaos)
        lo, mid, hi = report_human.token_range(ob)
        self.assertEqual(mid, ob // 4)
        self.assertEqual(mid, report_human.tokens_from_bytes(ob))
        self.assertEqual(lo, ob // 5)
        self.assertEqual(hi, ob // 3)
        self.assertLess(lo, mid)
        self.assertLess(mid, hi)

    def test_clean_overhead_zero(self):
        clean = load(CLEAN)
        self.assertEqual(report_human.session_overhead_bytes(clean), 0)


class TestOutputStructure(unittest.TestCase):

    def setUp(self):
        self.chaos = load(CHAOS)

    def test_en_headers_without_after(self):
        md = report_human.generate_human_markdown(self.chaos, lang='en')
        for h in EN_HEADERS:
            self.assertIn(h, md)
        self.assertNotIn(EN_BETTER_HEADER, md)

    def test_en_headers_with_after(self):
        md = report_human.generate_human_markdown(
            self.chaos, lang='en', after=make_after(self.chaos))
        for h in EN_HEADERS:
            self.assertIn(h, md)
        self.assertIn(EN_BETTER_HEADER, md)

    def test_ru_title_and_no_bureaucratese(self):
        md = report_human.generate_human_markdown(self.chaos, lang='ru')
        self.assertIn('простыми словами', md)
        for word in ('данные', 'данного', 'данной', 'данный', 'данных'):
            self.assertNotIn(word, md)
        self.assertNotIn('!', md)

    def test_ru_headers(self):
        md = report_human.generate_human_markdown(self.chaos, lang='ru')
        for h in ('## Коротко', '## Во сколько это обходится',
                  '## Что не так, по-человечески', '## Что дальше'):
            self.assertIn(h, md)

    def test_footer_honesty_lines(self):
        md = report_human.generate_human_markdown(self.chaos, lang='en')
        self.assertIn('Read-only audit', md)
        self.assertIn('estimates', md)
        self.assertIn(self.chaos['generated_at'], md)


class TestCostsSection(unittest.TestCase):

    def setUp(self):
        self.chaos = load(CHAOS)

    def test_assumption_line_default_sessions(self):
        md = report_human.generate_human_markdown(self.chaos, lang='en')
        self.assertIn('assumes 10 agent sessions a day', md)

    def test_assumption_line_custom_sessions(self):
        md = report_human.generate_human_markdown(
            self.chaos, lang='en', sessions_per_day=4)
        self.assertIn('assumes 4 agent sessions a day', md)

    def test_ru_assumption_line(self):
        md = report_human.generate_human_markdown(self.chaos, lang='ru')
        self.assertIn('10 запусков агента в день', md)

    def test_token_numbers_present(self):
        md = report_human.generate_human_markdown(self.chaos, lang='en')
        lo, mid, hi = report_human.token_range(
            report_human.session_overhead_bytes(self.chaos))
        self.assertIn(f'{lo:,}', md)
        self.assertIn(f'{mid:,}', md)
        self.assertIn(f'{hi:,}', md)

    def test_memory_and_disk_cards(self):
        md = report_human.generate_human_markdown(self.chaos, lang='en')
        self.assertIn('never sees', md)          # memory over limit
        self.assertIn('MB', md)                  # 8 MB large file

    def test_clean_report_zero_cards(self):
        clean = load(CLEAN)
        md = report_human.generate_human_markdown(clean, lang='en')
        self.assertIn('fit within healthy sizes', md)
        # clean still has one 46-byte junk file, so the disk card shows it
        self.assertIn('46 bytes', md)
        self.assertIn('No passwords or keys are lying in plain sight', md)

    def test_disk_zero_card_on_synthetic_report(self):
        minimal = {'root': 'C:/tmp/ws', 'generated_at': '2026-11-16T12:00:00',
                   'gates': [{'gid': 'G1', 'status': 'pass'}]}
        md = report_human.generate_human_markdown(minimal, lang='en')
        self.assertIn('No junk, duplicates or oversized files', md)

    def test_clean_main_problem_not_a_password_alarm(self):
        clean = load(CLEAN)
        md = report_human.generate_human_markdown(clean, lang='en')
        self.assertIn('Nothing guards against passwords slipping', md)
        self.assertNotIn('The main problem: A password/key', md)


class TestSecretDiscipline(unittest.TestCase):

    def test_counts_only_never_values(self):
        chaos = load(CHAOS)
        for lang in ('en', 'ru'):
            md = report_human.generate_human_markdown(chaos, lang=lang)
            self.assertNotIn('sk-', md)          # not even the mask
            self.assertNotIn('REDACTED', md)
            self.assertNotIn('sha256', md)       # no fingerprints
            self.assertNotIn('.mcp.json:6', md)  # no file:line of the secret

    def test_secret_count_matches_findings(self):
        chaos = load(CHAOS)
        md = report_human.generate_human_markdown(chaos, lang='en')
        self.assertIn('2 passwords or keys', md)


class TestPlainMapping(unittest.TestCase):

    def setUp(self):
        self.chaos = load(CHAOS)
        self.md = report_human.generate_human_markdown(self.chaos, lang='en')

    def test_bullets_end_with_fid(self):
        body = section(self.md, '## What is wrong, in plain words')
        bullets = [l for l in body if l.startswith('- ')]
        self.assertTrue(bullets)
        self.assertLessEqual(len(bullets), 6)
        for b in bullets:
            self.assertRegex(b, FID_BULLET_RE)

    def test_all_chaos_categories_map_to_sentences(self):
        categories = {f.get('category') for f
                      in self.chaos['findings_detailed']}
        for f in self.chaos['findings_detailed']:
            sentence = report_human.plain_sentence(self.chaos, f, 'en')
            self.assertTrue(sentence)
            self.assertNotIn('unknown', sentence.lower())
        self.assertIn('secrets', categories)
        self.assertIn('dirs', categories)
        self.assertIn('rules', categories)

    def test_required_contract_sentences(self):
        by_fid = {f['fid']: f for f in self.chaos['findings_detailed']}
        checks = [
            ('SEC-001', 'A password/key is sitting in a file where it '
                        'should not be'),
            ('RUL-001', "The agent's instructions point to things that "
                        'do not exist'),
            ('DIR-001', 'Two instruction files disagree — the agent gets '
                        'conflicting rules'),
            ('SKL-003', 'A helper skill is set up wrong and never runs'),
            ('GIT-001', 'Work is not saved to history yet'),
            ('GOV-001', 'Rules are kept for a tool nobody has used '
                        'in months'),
            ('HLTH-001', 'Unused files and old copies are piling up in '
                         'the workspace'),
            ('DIR-002', 'One project sits inside another project, which '
                        'confuses backup and sync tools'),
            ('RUL-005', 'Part of the instructions is template text that '
                        'gives the agent no useful rules'),
            ('RUL-006', 'The instructions have grown too big; the agent '
                        'pays for the extra on every start'),
        ]
        for fid, expected in checks:
            self.assertEqual(
                report_human.plain_sentence(self.chaos, by_fid[fid], 'en'),
                expected)
        # the two that do reach the rendered top-6 list
        self.assertIn('A password/key is sitting in a file where it '
                      'should not be', self.md)
        self.assertIn('Two instruction files disagree', self.md)

    def test_heavy_dir_sentence_carries_size(self):
        by_fid = {f['fid']: f for f in self.chaos['findings_detailed']}
        sentence = report_human.plain_sentence(
            self.chaos, by_fid['DIR-003'], 'en')
        self.assertEqual(
            sentence, 'A folder with 8 MB of data has no backup and '
                      'no history')

    def test_main_problem_is_first_critical(self):
        body = section(self.md, '## The short version')
        joined = ' '.join(body)
        self.assertIn('The main problem: A password/key is sitting', joined)


class TestBeforeAfter(unittest.TestCase):

    def setUp(self):
        self.chaos = load(CHAOS)
        self.after = make_after(self.chaos)
        self.md = report_human.generate_human_markdown(
            self.chaos, lang='en', after=self.after)

    def test_improvement_sentences(self):
        self.assertIn('fewer tokens every session', self.md)
        self.assertIn('slimmed from 63.7 KB to 8.8 KB', self.md)
        self.assertIn('went from about 16,515 to 0', self.md)  # tokens/start
        self.assertIn('Secrets in plain sight went from 2 to none', self.md)

    def test_tokens_after_less_than_before(self):
        before = report_human.session_overhead_bytes(self.chaos)
        after = report_human.session_overhead_bytes(self.after)
        self.assertLess(after, before)
        self.assertEqual(after, 0)

    def test_still_to_do_when_fail_gate_remains(self):
        self.assertIn('Still to do', self.md)
        self.assertIn('fix the instruction files', self.md)  # G3 plain words

    def test_no_still_to_do_when_all_green(self):
        all_green = copy.deepcopy(self.after)
        for g in all_green['gates']:
            g['status'] = 'pass'
        md = report_human.generate_human_markdown(
            self.chaos, lang='en', after=all_green)
        self.assertNotIn('Still to do', md)

    def test_ru_better_section(self):
        md = report_human.generate_human_markdown(
            self.chaos, lang='ru', after=self.after)
        self.assertIn('Что станет лучше после уборки', md)
        self.assertIn('Ещё осталось', md)
        self.assertIn('токенов меньше при каждом запуске', md)


class TestNumberFormatting(unittest.TestCase):

    def test_en_commas_ru_spaces(self):
        self.assertEqual(report_human.fmt_int(1234, 'en'), '1,234')
        self.assertEqual(report_human.fmt_int(1234, 'ru'),
                         '1' + '\u202f' + '234')

    def test_human_units(self):
        thin = report_human.THIN
        self.assertEqual(report_human.human_bytes(8388608, 'en'), '8 MB')
        self.assertEqual(report_human.human_bytes(8388608, 'ru'),
                         '8' + thin + 'МБ')
        self.assertIn('КБ', report_human.human_bytes(14282, 'ru'))
        self.assertIn('KB', report_human.human_bytes(14282, 'en'))

    def test_ru_decimal_comma(self):
        self.assertEqual(report_human.human_bytes(65242, 'ru'),
                         '63,7' + report_human.THIN + 'КБ')


if __name__ == '__main__':
    unittest.main()
