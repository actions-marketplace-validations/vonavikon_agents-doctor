"""Tests for skills/agents-doctor/scripts/content_quality.py.

Each quality dimension gets a focused test on crafted input, then a mixed
16-line AGENTS.md-like fixture exercises the whole report, and a synthetic
chaos document (the chaos.json fixture carries only metadata, no raw text)
stands in for a real bloated file. Everything is deterministic: thresholds
come from the module constants.
"""
import json
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'skills' / 'agents-doctor' / 'scripts'))
import content_quality as cq  # noqa: E402


class SignalRatioTests(unittest.TestCase):
    def test_mixed_file_ratio_near_07(self):
        text = '\n'.join([
            'Always run `make test` before committing.',
            'Never commit directly to `main`.',
            'Use `pnpm` instead of `npm`.',
            "Don't push without review.",
            'Check the logs in `build/out.log`.',
            'Avoid editing `vendor/` by hand.',
            '1. Verify the migration ran.',
            'The team meets weekly to discuss plans.',
            'This file exists to help newcomers orient.',
            'Architecture diagrams live on the wiki.',
        ])
        report = cq.analyze_content(text, 'AGENTS.md')
        self.assertEqual(report['non_blank_lines'], 10)
        self.assertEqual(report['signal_lines'], 7)
        self.assertAlmostEqual(report['signal_ratio'], 0.7, delta=0.001)
        self.assertEqual(report['filepath'], 'AGENTS.md')

    def test_pure_prose_below_03(self):
        text = '\n'.join([
            'This repository hosts the documentation platform for the service.',
            'The team meets every second Thursday to walk through the roadmap.',
            'Architecture decisions from past quarters are recorded below.',
            'The original prototype predates the current design by two years.',
            'Readers looking for context on naming conventions can ask in chat.',
            'A glossary of domain terms appears at the end of this document.',
        ])
        report = cq.analyze_content(text)
        self.assertLess(report['signal_ratio'], 0.3)
        self.assertEqual(report['signal_lines'], 0)

    def test_empty_file_ratio_zero(self):
        report = cq.analyze_content('')
        self.assertEqual(report['signal_ratio'], 0.0)
        self.assertEqual(report['non_blank_lines'], 0)
        self.assertEqual(report['signal_lines'], 0)

    def test_headings_and_code_are_noise(self):
        report = cq.analyze_content(
            '# Title\n```\npip install -r requirements.txt\n```\n')
        self.assertEqual(report['non_blank_lines'], 4)
        self.assertEqual(report['signal_lines'], 0)
        self.assertEqual(report['signal_ratio'], 0.0)


class GenericPhraseTests(unittest.TestCase):
    def test_generic_advice_flagged(self):
        text = 'Write clean code.\nFollow best practices.\nUse `pytest -x -q` for fast tests.'
        report = cq.analyze_content(text)
        phrases = [p['phrase'].lower() for p in report['generic_phrases']]
        self.assertIn('write clean code', phrases)
        self.assertIn('follow best practices', phrases)
        self.assertEqual(report['generic_count'], 2)
        for record in report['generic_phrases']:
            self.assertIsInstance(record['line'], int)
            self.assertIsInstance(record['position'], int)
            self.assertEqual(
                record['position'],
                text.splitlines()[record['line'] - 1].lower().find(record['phrase'].lower()))

    def test_specific_command_not_flagged(self):
        report = cq.analyze_content('Use `pytest -x -q` for fast tests.')
        self.assertEqual(report['generic_count'], 0)

    def test_all_pattern_families_detected(self):
        text = '\n'.join([
            'Be careful with every change.',
            'Maintain high quality in all modules.',
            'Test all changes before submitting.',
            'Keep it simple.',
            'Avoid unnecessary complexity.',
            'Document your code as you go.',
            'Commit regularly.',
            "Don't reinvent the wheel.",
        ])
        report = cq.analyze_content(text)
        self.assertGreaterEqual(report['generic_count'], 8)


class InstructionDensityTests(unittest.TestCase):
    def test_ten_unique_rules_in_one_kb(self):
        rules = ['%d. Run `make step%d` before commit' % (i, i)
                 for i in range(1, 11)]
        base = '\n'.join(rules)
        room = 1024 - len(base.encode('utf-8')) - 1
        self.assertGreater(room, 0)
        unit = 'Repository history and design context notes fill this narrative row. '
        filler = (unit * (room // len(unit) + 1))[:room]
        text = base + '\n' + filler

        report = cq.analyze_content(text)
        self.assertEqual(report['size_bytes'], 1024)
        self.assertEqual(report['unique_rules'], 10)
        self.assertAlmostEqual(report['instruction_density'], 10.0, delta=1e-9)

    def test_empty_file_density_zero(self):
        self.assertEqual(cq.analyze_content('')['instruction_density'], 0.0)


class RedundancyTests(unittest.TestCase):
    def test_near_duplicate_pair_detected(self):
        text = ('Always run tests before committing\n'
                'Always run the tests before you commit')
        report = cq.analyze_content(text)
        self.assertGreaterEqual(report['redundant_total'], 1)
        pair = report['redundant_pairs'][0]
        self.assertGreaterEqual(pair['similarity'], cq.REDUNDANT_SIMILARITY)
        texts = {pair['line_1'], pair['line_2']}
        self.assertIn('Always run tests before committing', texts)
        self.assertIn('Always run the tests before you commit', texts)

    def test_exact_repeat_is_similarity_one(self):
        text = 'Never edit `vendor/` by hand.\nNever edit `vendor/` by hand.'
        report = cq.analyze_content(text)
        self.assertGreaterEqual(report['redundant_total'], 1)
        self.assertEqual(report['redundant_pairs'][0]['similarity'], 1.0)

    def test_unrelated_rules_not_paired(self):
        text = ('Use `pnpm` instead of `npm`.\n'
                'Check the logs in `build/out.log`.')
        report = cq.analyze_content(text)
        self.assertEqual(report['redundant_total'], 0)


class ContradictionTests(unittest.TestCase):
    def test_push_to_main_contradiction(self):
        text = 'Always push directly to main.\nNever push directly to main.'
        report = cq.analyze_content(text)
        self.assertEqual(len(report['contradictions']), 1)
        contra = report['contradictions'][0]
        self.assertEqual(contra['topic'], 'push directly to main')
        self.assertIn('Always push directly to main', contra['line_a'])
        self.assertIn('Never push directly to main', contra['line_b'])

    def test_must_not_counts_as_negative(self):
        text = 'You must deploy on Fridays.\nYou must not deploy on Fridays.'
        report = cq.analyze_content(text)
        self.assertEqual(len(report['contradictions']), 1)
        self.assertEqual(report['contradictions'][0]['topic'], 'deploy on fridays')

    def test_unrelated_directives_not_contradictions(self):
        text = ('Always run `pytest -x -q` before pushing.\n'
                "Don't merge without a green pipeline.")
        self.assertEqual(cq.analyze_content(text)['contradictions'], [])


class SpecificityTests(unittest.TestCase):
    def test_specific_line_recognized(self):
        self.assertTrue(cq._is_specific('Run `npm run build` in `src/`'))
        self.assertTrue(cq._is_specific('Deploy via git push origin main'))

    def test_generic_line_recognized(self):
        self.assertFalse(cq._is_specific('Follow good coding practices'))

    def test_ratio_over_signal_lines(self):
        text = ('Run `npm run build` in `src/`\n'
                'Prefer explicit imports over wildcards.')
        report = cq.analyze_content(text)
        self.assertEqual(report['signal_lines'], 2)
        self.assertAlmostEqual(report['specificity'], 0.5, delta=0.001)

    def test_no_signal_lines_gives_zero(self):
        self.assertEqual(cq.analyze_content('Just prose here.')['specificity'], 0.0)


# A synthetic AGENTS.md-like file, 14 lines of mixed quality: headings,
# actionable rules with concrete references, generic filler, narrative.
# 7 of 13 non-blank lines are signal -> ratio 0.538 -> verdict 'good'.
FIXTURE = '\n'.join([
    '# Agent Instructions',
    '',
    '## Testing',
    'Always run `pytest -x -q` before committing.',
    'Test all changes locally as well.',
    'Never commit directly to `main`.',
    '## Style',
    'Write clean code and follow best practices.',
    'Use `ruff format` for imports.',
    'Prefer explicit imports over wildcards.',
    'The team meets on Tuesdays to review the backlog.',
    'Always run the tests before you commit.',
    'Never commit straight to the `main` branch.',
    'Avoid editing `vendor/` by hand.',
])


class MixedFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = cq.analyze_content(FIXTURE, 'AGENTS.md')

    def test_counts(self):
        self.assertEqual(self.report['total_lines'], 14)
        self.assertEqual(self.report['non_blank_lines'], 13)
        self.assertEqual(self.report['signal_lines'], 7)
        self.assertEqual(self.report['noise_lines'], 6)
        self.assertAlmostEqual(self.report['signal_ratio'], 7 / 13, delta=0.001)

    def test_generic_count(self):
        phrases = [p['phrase'].lower() for p in self.report['generic_phrases']]
        self.assertEqual(self.report['generic_count'], 3)
        self.assertIn('write clean code', phrases)
        self.assertIn('follow best practices', phrases)
        self.assertIn('test all changes', phrases)

    def test_density_positive(self):
        self.assertEqual(self.report['unique_rules'], 7)
        self.assertGreater(self.report['instruction_density'], 5.0)

    def test_redundant_branch_rules(self):
        pairs = self.report['redundant_pairs']
        self.assertEqual(self.report['redundant_total'], 1)
        self.assertGreaterEqual(pairs[0]['similarity'], 0.7)
        joined = pairs[0]['line_1'] + ' || ' + pairs[0]['line_2']
        self.assertIn('main', joined)

    def test_no_false_contradictions(self):
        # "commit directly to main" vs "run the tests before you commit" share
        # only 'commit'; stopword-filtered overlap stays under the threshold.
        self.assertEqual(self.report['contradictions'], [])

    def test_specificity(self):
        self.assertAlmostEqual(self.report['specificity'], 5 / 7, delta=0.001)

    def test_staleness_placeholder(self):
        self.assertEqual(self.report['staleness_hint'],
                         {'computable': False, 'reason': 'requires git history'})

    def test_summary_is_good(self):
        summary = cq.quality_summary(self.report)
        self.assertEqual(summary['overall'], 'good')


def _chaos_raw_text():
    """chaos.json stores metadata about context files, not their text; if a
    future fixture gains raw text, prefer it over the synthetic document."""
    path = REPO / 'llm-eval' / 'fixtures' / 'chaos.json'
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return None
    for item in data.get('context_files', []):
        if isinstance(item, dict):
            for key in ('text', 'content', 'raw'):
                value = item.get(key)
                if isinstance(value, str) and value.strip():
                    return value
    return None


def _synthetic_chaos_text():
    return '\n'.join([
        '# Agent Guidelines',
        '',
        '## Introduction',
        'This file gathers everything the agents might ever need to know about the repository.',
        'It was written over three years by many contributors with different opinions.',
        'Read it carefully before starting any task, it contains important context.',
        'The history of these guidelines reflects the history of the team itself.',
        '',
        '## General Advice',
        'Write clean code and follow best practices.',
        'Be careful with every change you make.',
        'Maintain high quality in everything you deliver.',
        'Test all changes before submitting them.',
        'Keep it simple and avoid unnecessary complexity.',
        'Document your code so future engineers understand it.',
        'Commit regularly to keep the history clean.',
        'Be consistent across all the modules you touch.',
        '',
        '## CI and Releases',
        'Always run the full test suite before every release.',
        'Always run the full test suite prior to each release.',
        'Run `make check` before tagging a release.',
        'Always review the checklist before every release.',
        'Always review the checklist before every release.',
        '',
        '## Branching',
        'Always push directly to main.',
        'Never push directly to main.',
        'Use short-lived branches when it makes sense.',
        '',
        '## Background',
        'The deployment pipeline was built in the spring and has evolved since then.',
        'Many of these notes predate the current tooling and no longer apply.',
        'Old sections were kept for historical interest rather than practical value.',
        'The team has debated tabs versus spaces several times over the years.',
        'Minutes from past retrospectives were merged into this document.',
        'Feel free to add new sections at the end of the file.',
    ])


class ChaosDocumentTests(unittest.TestCase):
    def test_synthetic_bloated_document(self):
        report = cq.analyze_content(_synthetic_chaos_text(), 'AGENTS.md')
        self.assertLess(report['signal_ratio'], 0.3)
        self.assertGreaterEqual(report['generic_count'], 5)
        self.assertGreaterEqual(report['redundant_total'], 2)
        topics = [c['topic'] for c in report['contradictions']]
        self.assertIn('push directly to main', topics)
        summary = cq.quality_summary(report)
        self.assertIn(summary['overall'], {'noisy', 'bloated', 'mostly-noise'})
        self.assertNotEqual(summary['overall'], 'excellent')

    def test_fixture_raw_text_path_does_not_crash(self):
        raw = _chaos_raw_text()
        if raw is None:
            self.skipTest('chaos.json carries no raw context file text')
        report = cq.analyze_content(raw, 'chaos:AGENTS.md')
        self.assertIn(cq.quality_summary(report)['overall'],
                      {'excellent', 'good', 'noisy', 'bloated', 'mostly-noise'})


class SummaryTests(unittest.TestCase):
    def test_noisy_file(self):
        text = '\n'.join([
            'Always run `make test` before committing.',
            "Don't push without review.",
            'Avoid editing `vendor/` by hand.',
            'Verify the migration ran.',
            'The team meets weekly to discuss plans.',
            'This file exists to help newcomers orient.',
            'Architecture diagrams live on the wiki.',
            'A glossary of domain terms appears at the end.',
            'Minutes from past retrospectives were merged here.',
            'The original prototype predates the current design.',
        ])
        summary = cq.quality_summary(cq.analyze_content(text))
        self.assertEqual(summary['overall'], 'noisy')

    def test_clean_actionable_file(self):
        text = '\n'.join([
            'Always run `pytest -x -q` before pushing.',
            'Use `pnpm install` to add dependencies.',
            'Never edit `src/generated/` by hand.',
            'Run `python -m build` from the repo root.',
            'Check `docs/runbook.md` when a deploy fails.',
            "Don't merge without a green pipeline.",
            'Verify the checksum before publishing.',
            'Avoid `sudo` in helper scripts.',
            'Prefer small pull requests with screenshots.',
            'The service ships weekly.',
        ])
        report = cq.analyze_content(text)
        self.assertEqual(report['generic_count'], 0)
        self.assertEqual(report['contradictions'], [])
        summary = cq.quality_summary(report)
        self.assertEqual(summary['overall'], 'excellent')

    def test_headline_and_details_shape(self):
        summary = cq.quality_summary(cq.analyze_content(FIXTURE))
        self.assertIsInstance(summary['headline'], str)
        self.assertTrue(summary['headline'].endswith('.'))
        self.assertIsInstance(summary['details'], list)
        for metric, value, interpretation in summary['details']:
            self.assertIsInstance(metric, str)
            self.assertIsNotNone(value)
            self.assertIsInstance(interpretation, str)

    def test_empty_file_verdict(self):
        # Threshold order sends an empty file to 'bloated' (density 0 < 0.3).
        summary = cq.quality_summary(cq.analyze_content(''))
        self.assertEqual(summary['overall'], 'bloated')


class EdgeCaseTests(unittest.TestCase):
    def test_empty_string(self):
        report = cq.analyze_content('')
        self.assertEqual(report['size_bytes'], 0)
        self.assertEqual(report['signal_ratio'], 0.0)
        self.assertEqual(report['instruction_density'], 0.0)
        self.assertEqual(report['generic_phrases'], [])
        self.assertEqual(report['redundant_pairs'], [])
        self.assertEqual(report['contradictions'], [])
        self.assertEqual(report['specificity'], 0.0)

    def test_only_headings(self):
        report = cq.analyze_content('# Alpha\n## Beta\n### Gamma Delta')
        self.assertEqual(report['non_blank_lines'], 3)
        self.assertEqual(report['signal_ratio'], 0.0)
        self.assertEqual(report['unique_rules'], 0)

    def test_only_code_blocks(self):
        text = '```\npip install -r requirements.txt\npytest -x -q\n```'
        report = cq.analyze_content(text)
        self.assertEqual(report['signal_ratio'], 0.0)
        # command samples inside fences are not scanned for generic advice
        self.assertEqual(report['generic_count'], 0)

    def test_unicode_text(self):
        text = ('# Руководство\n'
                '\n'
                'Всегда запускай `make test` перед коммитом.\n'
                'Просто описательный текст про архитектуру системы. 🚀\n'
                "Don't touch `src/ядро/` without tests.")
        report = cq.analyze_content(text)
        self.assertEqual(report['signal_lines'], 2)
        self.assertAlmostEqual(report['signal_ratio'], 0.5, delta=0.001)
        self.assertEqual(report['unique_rules'], 2)
        self.assertEqual(report['generic_count'], 0)

    def test_crlf_line_endings(self):
        report = cq.analyze_content('Always run `make test`.\r\nProse line here.\r\n')
        self.assertEqual(report['non_blank_lines'], 2)
        self.assertEqual(report['signal_lines'], 1)


if __name__ == '__main__':
    unittest.main()
