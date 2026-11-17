"""Tests for the local web UI server (Visual TZ section 16):
API shape, path containment, secret masking in previews, read-only
guarantees."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs

SCRIPTS = Path(__file__).resolve().parents[1] / 'skills' / 'agents-doctor' / 'scripts'
sys.path.insert(0, str(SCRIPTS))

import audit_scan  # noqa: E402
from ui.server import UiState, _contain, _mask_line  # noqa: E402
from ui import server as srv  # noqa: E402


def _ws_with_secret():
    root = Path(tempfile.mkdtemp())
    home = Path(tempfile.mkdtemp())
    (root / 'AGENTS.md').write_text('# x\n', encoding='utf-8')
    (root / 'creds.txt').write_text(
        'token = "supersecret-value-12345"\nnormal line\n',
        encoding='utf-8')
    rep = audit_scan.scan(root, home, False)
    return rep, root, home


class ContainmentTest(unittest.TestCase):
    def test_contain_rejects_escape(self):
        rep, root, home = _ws_with_secret()
        state = UiState(rep, root)
        for bad in ('../etc', '..\\\\windows', 'a/../../x'):
            with self.assertRaises(PermissionError):
                _contain(state, bad)

    def test_contain_accepts_inside(self):
        rep, root, home = _ws_with_secret()
        state = UiState(rep, root)
        target = _contain(state, 'creds.txt')
        self.assertEqual(target.name, 'creds.txt')


class MaskingTest(unittest.TestCase):
    def test_mask_line_hides_values(self):
        line = 'api_key = "abcdefghijklmnop"'
        masked = _mask_line(line)
        self.assertNotIn('abcdefghijklmnop', masked)
        self.assertIn('***', masked)

    def test_mask_line_keeps_normal_lines(self):
        self.assertEqual(_mask_line('hello world'), 'hello world')

    def test_file_preview_masks_secrets(self):
        rep, root, home = _ws_with_secret()
        state = UiState(rep, root)
        out = srv.api_file(state, parse_qs('path=creds.txt'))
        blob = '\n'.join(out['lines'])
        self.assertNotIn('supersecret-value-12345', blob)
        self.assertIn('***', blob)
        self.assertTrue(out['flagged_lines'])

    def test_preview_is_capped(self):
        root = Path(tempfile.mkdtemp())
        home = Path(tempfile.mkdtemp())
        (root / 'big.txt').write_text('x' * (300 * 1024), encoding='utf-8')
        rep = {'root': str(root), 'home': str(home),
               'findings_detailed': [], 'gates': []}
        state = UiState(rep, root)
        out = srv.api_file(state, parse_qs('path=big.txt'))
        self.assertTrue(out['truncated'])

    def test_binary_preview(self):
        root = Path(tempfile.mkdtemp())
        (root / 'blob.bin').write_bytes(b'\x00\x01\x02binary')
        rep = {'root': str(root), 'findings_detailed': [], 'gates': []}
        state = UiState(rep, root)
        out = srv.api_file(state, parse_qs('path=blob.bin'))
        self.assertTrue(out['binary'])


class ApiTest(unittest.TestCase):
    def test_overview_shape(self):
        rep, root, home = _ws_with_secret()
        state = UiState(rep, root)
        out = srv.api_overview(state, {})
        for key in ('root', 'gates', 'severity_counts', 'status_counts',
                    'findings_total', 'rules_version'):
            self.assertIn(key, out)

    def test_findings_filter_by_gate(self):
        rep, root, home = _ws_with_secret()
        state = UiState(rep, root)
        out = srv.api_findings(state, parse_qs('gate=G6'))
        self.assertTrue(all(f['gate'] == 'G6' for f in out['findings']))
        out_all = srv.api_findings(state, {})
        self.assertGreaterEqual(out_all['count'], out['count'])

    def test_tree_children_with_counts(self):
        rep, root, home = _ws_with_secret()
        state = UiState(rep, root)
        out = srv.api_tree(state, parse_qs('path='))
        names = [c['name'] for c in out['children']]
        self.assertIn('creds.txt', names)
        creds = next(c for c in out['children'] if c['name'] == 'creds.txt')
        self.assertIn('counts', creds)
        self.assertEqual(creds['size'],
                         (root / 'creds.txt').stat().st_size)

    def test_tree_rejects_escape(self):
        rep, root, home = _ws_with_secret()
        state = UiState(rep, root)
        out = srv.api_tree(state, parse_qs('path=..'))
        self.assertIn('error', out)

    def test_finding_lookup(self):
        rep, root, home = _ws_with_secret()
        state = UiState(rep, root)
        some = rep['findings_detailed'][0]
        got = srv.api_finding(state, some['fid'])
        self.assertEqual(got['fid'], some['fid'])
        self.assertIsNone(srv.api_finding(state, 'NOPE-999'))

    def test_fixplan_is_dry_run(self):
        rep, root, home = _ws_with_secret()
        state = UiState(rep, root)
        out = srv.api_fixplan(state, parse_qs('fid=NOPE-999'))
        # unsupported finding: reported, never improvised
        self.assertFalse(out.get('supported', True)
                         and out.get('steps'))

    def test_compare_requires_baseline(self):
        rep, root, home = _ws_with_secret()
        state = UiState(rep, root)
        out = srv.api_compare(state, {})
        self.assertFalse(out['supported'])
        state.baseline = rep
        out2 = srv.api_compare(state, {})
        self.assertTrue(out2['supported'])
        self.assertEqual(out2['summary']['new'], 0)

    def test_simulate_endpoint(self):
        rep, root, home = _ws_with_secret()
        state = UiState(rep, root)
        out = srv.api_simulate(state, parse_qs(''))
        self.assertTrue(out.get('approximated'))
        self.assertIn('harnesses', out)


if __name__ == '__main__':
    unittest.main()
