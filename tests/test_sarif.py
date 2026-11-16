"""Tests for skills/workspace-audit/scripts/sarif.py.

Exports the chaos fixture and synthetic findings to SARIF 2.1.0: rule
coverage, result filtering, level mapping, fingerprints, JSON
round-trip and the CLI. Python 3.9+.
"""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'skills' / 'workspace-audit' / 'scripts'))

import sarif

CHAOS = REPO / 'llm-eval' / 'fixtures' / 'chaos.json'
GIDS = {f'G{i}' for i in range(1, 10)}


def load_chaos():
    return json.loads(CHAOS.read_text(encoding='utf-8'))


def finding(fid, gate, severity, status):
    return {'fid': fid, 'gate': gate, 'category': 'test',
            'severity': severity, 'status': status, 'title': 'title ' + fid,
            'description': '', 'evidence': [{'file': 'a.txt', 'line': 3}],
            'confidence': 0.9, 'recommendation': 'do something',
            'autofix_available': False}


class ChaosSarifTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rep = load_chaos()
        cls.doc = sarif.to_sarif(cls.rep)
        cls.driver = cls.doc['runs'][0]['tool']['driver']
        cls.results = cls.doc['runs'][0]['results']

    def test_version(self):
        self.assertEqual(self.doc['version'], '2.1.0')

    def test_nine_rules(self):
        ids = [r['id'] for r in self.driver['rules']]
        self.assertEqual(sorted(ids), sorted(GIDS))
        for rule in self.driver['rules']:
            self.assertIn('shortDescription', rule)
            self.assertIn('fullDescription', rule)
            self.assertEqual(rule['helpUri'],
                             'https://github.com/vonavikon/workspace-audit'
                             '#the-nine-gates')

    def test_driver_identity(self):
        self.assertEqual(self.driver['name'], 'workspace-audit')
        self.assertEqual(self.driver['version'], self.rep['rules_version'])
        self.assertEqual(self.driver['informationUri'],
                         'https://github.com/vonavikon/workspace-audit')

    def test_results_match_fail_warn_findings(self):
        expected = [f for f in self.rep['findings_detailed']
                    if f['status'] in ('fail', 'warn')]
        self.assertEqual(len(self.results), len(expected))
        passed = [f['fid'] for f in self.rep['findings_detailed']
                  if f['status'] not in ('fail', 'warn')]
        messages = [r['message']['text'] for r in self.results]
        for fid in passed:
            self.assertNotIn(fid + ':', ' '.join(messages))

    def test_every_result_shape(self):
        for r in self.results:
            self.assertIn(r['ruleId'], GIDS)
            self.assertIn('workspaceAudit/v1', r['partialFingerprints'])
            self.assertTrue(r['locations'][0]['logicalLocations'][0]
                            ['fullyQualifiedName'])
            self.assertIn(r['level'], ('error', 'warning', 'note'))
            for key in ('severity', 'confidence', 'category'):
                self.assertIn(key, r['properties'])
        fids = {r['partialFingerprints']['workspaceAudit/v1']
                for r in self.results}
        self.assertEqual(len(fids), len(self.results))  # fids unique

    def test_levels_follow_chaos_severities(self):
        by_fid = {r['partialFingerprints']['workspaceAudit/v1']: r
                  for r in self.results}
        sec1 = by_fid['SEC-001']  # critical + fail
        self.assertEqual(sec1['level'], 'error')
        self.assertEqual(sec1['ruleId'], 'G6')
        self.assertIn('SEC-001', sec1['message']['text'])
        medium_fail = by_fid['RUL-001']  # medium + fail
        self.assertEqual(medium_fail['level'], 'warning')
        low_warn = by_fid['GIT-001']  # low + warn
        self.assertEqual(low_warn['level'], 'warning')

    def test_location_from_evidence_file(self):
        by_fid = {r['partialFingerprints']['workspaceAudit/v1']: r
                  for r in self.results}
        self.assertEqual(
            by_fid['SEC-001']['locations'][0]['logicalLocations'][0]
            ['fullyQualifiedName'], '.mcp.json')

    def test_json_round_trip(self):
        text = json.dumps(self.doc, ensure_ascii=False)
        parsed = json.loads(text)
        self.assertEqual(parsed['version'], '2.1.0')
        self.assertEqual(len(parsed['runs'][0]['results']),
                         len(self.results))


class LevelMappingTest(unittest.TestCase):
    def _level(self, severity, status):
        rep = {'gates': [], 'findings_detailed': [
            finding('TST-001', 'G1', severity, status)]}
        return sarif.to_sarif(rep)['runs'][0]['results'][0]['level']

    def test_fail_critical_is_error(self):
        self.assertEqual(self._level('critical', 'fail'), 'error')

    def test_fail_high_is_error(self):
        self.assertEqual(self._level('high', 'fail'), 'error')

    def test_fail_medium_is_warning(self):
        self.assertEqual(self._level('medium', 'fail'), 'warning')

    def test_fail_low_is_warning(self):
        self.assertEqual(self._level('low', 'fail'), 'warning')

    def test_warn_any_severity_is_warning(self):
        for severity in ('critical', 'high', 'medium', 'low'):
            self.assertEqual(self._level(severity, 'warn'), 'warning')

    def test_info_is_note_even_when_warn(self):
        self.assertEqual(self._level('info', 'warn'), 'note')

    def test_pass_and_unknown_excluded(self):
        rep = {'gates': [], 'findings_detailed': [
            finding('TST-001', 'G1', 'critical', 'pass'),
            finding('TST-002', 'G1', 'critical', 'unknown')]}
        results = sarif.to_sarif(rep)['runs'][0]['results']
        self.assertEqual(results, [])

    def test_location_falls_back_to_root(self):
        rep = {'root': 'C:/tmp/ws', 'gates': [], 'findings_detailed': [
            dict(finding('TST-001', 'G1', 'high', 'fail'), evidence=[{}])]}
        loc = sarif.to_sarif(rep)['runs'][0]['results'][0]['locations'][0]
        self.assertEqual(loc['logicalLocations'][0]['fullyQualifiedName'],
                         'C:/tmp/ws')


class CliTest(unittest.TestCase):
    def test_writes_sarif_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'report.sarif'
            r = subprocess.run(
                [sys.executable, str(REPO / 'skills' / 'workspace-audit' /
                                     'scripts' / 'sarif.py'),
                 str(CHAOS), '--out', str(out)],
                capture_output=True, text=True, cwd=str(REPO))
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertTrue(out.exists())
            doc = json.loads(out.read_text(encoding='utf-8'))
            self.assertEqual(doc['version'], '2.1.0')
            self.assertEqual(len(doc['runs'][0]['tool']['driver']['rules']), 9)


if __name__ == '__main__':
    unittest.main()
