"""Historical Analytics: audit_history.py storage, diff/regression/
trend/prune/export API, the history CLI subcommand, the audit
auto-recording and the privacy contract (no secret values in the db).

Windows notes: every temp path goes through Path(...).resolve(); the
default database lives under the workspace root, so tests never share
state.
"""
import contextlib
import io
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1] / 'skills' / 'agents-doctor' / 'scripts'
sys.path.insert(0, str(SCRIPTS))

import agents_doctor    # noqa: E402
import audit_history    # noqa: E402
import remediate        # noqa: E402

CANARY = 'sk-CANARY-0123456789abcdef'


def make_rep(root, fingerprints=(), detailed=(), gates=(),
             generated_at='2026-11-17T10:00:00+03:00'):
    """A minimal scan.json-shaped report."""
    return {
        'schema_version': '1.0', 'root': str(root), 'home': str(root),
        'generated_at': generated_at,
        'findings': [{'fp': fp, 'section': sec, 'path': path}
                     for fp, sec, path in fingerprints],
        'findings_detailed': [dict(d) for d in detailed],
        'gates': [dict(g) for g in gates],
    }


def typed(fid, gate, severity, status, **extra):
    d = {'fid': fid, 'gate': gate, 'severity': severity, 'status': status}
    d.update(extra)
    return d


class TempBase(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(lambda: __import__('shutil').rmtree(
            self.base, ignore_errors=True))
        self.ws = self.base / 'ws'
        self.ws.mkdir()
        self.db = self.base / 'history.db'


class InitDbTest(TempBase):
    def test_init_creates_full_schema(self):
        conn = audit_history.init_db(self.db)
        self.addCleanup(conn.close)
        names = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type IN ('table','index')")}
        self.assertIn('scans', names)
        self.assertIn('findings', names)
        self.assertIn('schema_migrations', names)
        self.assertIn('idx_findings_scan', names)
        self.assertIn('idx_findings_fp', names)
        version = conn.execute('SELECT MAX(version) FROM '
                               'schema_migrations').fetchone()[0]
        self.assertEqual(version, audit_history.LATEST_VERSION)

    def test_migrations_upgrade_old_version_without_data_loss(self):
        # simulate a database from when only migration 1 existed
        raw = sqlite3.connect(str(self.db))
        raw.execute('CREATE TABLE schema_migrations '
                    '(version INTEGER NOT NULL)')
        for stmt in audit_history.MIGRATIONS[0][1]:
            raw.execute(stmt)
        raw.execute('INSERT INTO schema_migrations (version) VALUES (1)')
        raw.execute("INSERT INTO scans (ts, root, findings_total,"
                    " severity_counts, gate_statuses, policy_summary,"
                    " scan_file)"
                    " VALUES ('2026-01-01T00:00:00', 'C:/old', 3, '{}',"
                    " '{}', NULL, NULL)")
        raw.commit()
        raw.close()
        conn = audit_history.init_db(self.db)
        self.addCleanup(conn.close)
        version = conn.execute('SELECT MAX(version) FROM '
                               'schema_migrations').fetchone()[0]
        self.assertEqual(version, audit_history.LATEST_VERSION)
        rows = conn.execute('SELECT root, findings_total FROM scans'
                            ).fetchall()
        self.assertEqual(rows, [('C:/old', 3)])  # the old row survived
        names = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertIn('findings', names)         # new tables applied

    def test_wal_mode_and_reopen(self):
        conn = audit_history.init_db(self.db)
        mode = conn.execute('PRAGMA journal_mode').fetchone()[0]
        conn.close()
        self.assertEqual(mode.lower(), 'wal')
        conn2 = audit_history.init_db(self.db)   # reopen: no error, no reset
        self.addCleanup(conn2.close)
        self.assertEqual(
            conn2.execute('SELECT COUNT(*) FROM scans').fetchone()[0], 0)

    def test_default_db_path_lives_under_root(self):
        p = audit_history.default_db_path(self.ws)
        self.assertEqual(p.parent, self.ws.resolve() / '.agents-doctor')
        self.assertEqual(p.name, 'history.db')


class RecordScanTest(TempBase):
    def test_record_and_list_roundtrip(self):
        conn = audit_history.init_db(self.db)
        self.addCleanup(conn.close)
        rep1 = make_rep(self.ws,
                        detailed=[typed('SEC-001', 'G6', 'critical', 'fail'),
                                  typed('HLTH-001', 'G5', 'medium', 'warn')],
                        gates=[{'gid': 'G6', 'status': 'fail'},
                               {'gid': 'G5', 'status': 'warn'}])
        rep2 = make_rep(self.ws, generated_at='2026-11-17T11:00:00+03:00')
        id1 = audit_history.record_scan(conn, rep1)
        id2 = audit_history.record_scan(conn, rep2, scan_file='scan.json')
        self.assertEqual((id1, id2), (1, 2))
        scans = audit_history.list_scans(conn)
        self.assertEqual([s['id'] for s in scans], [2, 1])  # newest first
        self.assertEqual(scans[1]['ts'], '2026-11-17T10:00:00+03:00')
        self.assertEqual(scans[1]['root'], str(self.ws))
        self.assertEqual(scans[1]['findings_total'], 0)
        self.assertEqual(scans[1]['severity_counts'],
                         {'critical': 1, 'medium': 1})
        self.assertEqual(scans[1]['gate_statuses'], {'G6': 'fail',
                                                     'G5': 'warn'})
        self.assertIsNone(scans[1]['policy_summary'])
        self.assertEqual(scans[0]['scan_file'], 'scan.json')
        self.assertIsNone(scans[1]['scan_file'])

    def test_fingerprint_rows_sorted_by_fp(self):
        conn = audit_history.init_db(self.db)
        self.addCleanup(conn.close)
        rep = make_rep(self.ws, fingerprints=[
            ('zzz', 'secrets', 'a'), ('aaa', 'junk', 'b'), ('mmm', 'junk', 'c')])
        audit_history.record_scan(conn, rep)
        fps = [r[0] for r in conn.execute(
            "SELECT fp FROM findings WHERE kind='fingerprint'"
            " ORDER BY rowid")]
        self.assertEqual(fps, ['aaa', 'mmm', 'zzz'])

    def test_typed_rows_stored_with_stable_fields(self):
        conn = audit_history.init_db(self.db)
        self.addCleanup(conn.close)
        rep = make_rep(self.ws, detailed=[
            typed('GOV-001', 'G8', 'high', 'warn',
                  check_id='CLAUDE_LOCAL_DEPRECATED', harness='claude_code'),
            typed('SEC-001', 'G6', 'critical', 'fail')])
        audit_history.record_scan(conn, rep)
        rows = conn.execute(
            "SELECT fid, gate, severity, status, check_id, harness"
            " FROM findings WHERE kind='typed' ORDER BY fid").fetchall()
        self.assertEqual(rows, [
            ('GOV-001', 'G8', 'high', 'warn',
             'CLAUDE_LOCAL_DEPRECATED', 'claude_code'),
            ('SEC-001', 'G6', 'critical', 'fail', None, None)])

    def test_findings_without_fp_are_skipped(self):
        conn = audit_history.init_db(self.db)
        self.addCleanup(conn.close)
        rep = make_rep(self.ws, fingerprints=[('fp1', 'junk', 'p')])
        rep['findings'].append({'section': 'junk', 'path': 'no-fp'})
        rep['findings'].append('not-a-dict')
        scan_id = audit_history.record_scan(conn, rep)
        n = conn.execute('SELECT COUNT(*) FROM findings WHERE scan_id = ?',
                         (scan_id,)).fetchone()[0]
        self.assertEqual(n, 1)
        row = audit_history.list_scans(conn)[0]
        self.assertEqual(row['findings_total'], 1)

    def test_get_scan(self):
        conn = audit_history.init_db(self.db)
        self.addCleanup(conn.close)
        audit_history.record_scan(conn, make_rep(self.ws))
        self.assertEqual(audit_history.get_scan(conn, 1)['id'], 1)
        self.assertIsNone(audit_history.get_scan(conn, 99))


class DiffTest(TempBase):
    def plant(self, conn, fingerprints, root=None):
        rep = make_rep(root or self.ws, fingerprints=fingerprints)
        return audit_history.record_scan(conn, rep)

    def test_diff_sections(self):
        conn = audit_history.init_db(self.db)
        self.addCleanup(conn.close)
        old_id = self.plant(conn, [
            ('aaa1', 'secrets', 'f1'),      # persists
            ('bbb2', 'junk', 'f2'),         # reshaped below
            ('ccc3', 'junk', 'f3')])        # resolved
        new_id = self.plant(conn, [
            ('aaa1', 'secrets', 'f1'),
            ('bbb9', 'junk', 'f2'),         # same section+path, new fp
            ('ddd4', 'large_files', 'f4')])  # brand new
        diff = audit_history.diff_scans(conn, old_id, new_id)
        self.assertEqual([f['fp'] for f in diff['persisting']], ['aaa1'])
        self.assertEqual([f['fp'] for f in diff['changed']], ['bbb9'])
        self.assertIn('ddd4', [f['fp'] for f in diff['new']])
        self.assertIn('bbb9', [f['fp'] for f in diff['new']])  # changed counts as new
        self.assertEqual(sorted(f['fp'] for f in diff['resolved']),
                         ['bbb2', 'ccc3'])

    def test_diff_is_reused_remediate_engine(self):
        conn = audit_history.init_db(self.db)
        self.addCleanup(conn.close)
        old_fps = [('aaa1', 'secrets', 'f1'), ('bbb2', 'junk', 'f2')]
        new_fps = [('aaa1', 'secrets', 'f1'), ('eee5', 'junk', 'f2')]
        old_id = self.plant(conn, old_fps)
        new_id = self.plant(conn, new_fps)
        got = audit_history.diff_scans(conn, old_id, new_id)
        direct = remediate.fingerprint_diff(
            [{'fp': fp, 'section': s, 'path': p} for fp, s, p in old_fps],
            [{'fp': fp, 'section': s, 'path': p} for fp, s, p in new_fps])
        self.assertEqual({k: [f['fp'] for f in v] for k, v in got.items()},
                         {k: [f['fp'] for f in v] for k, v in direct.items()})

    def test_diff_empty_scans(self):
        conn = audit_history.init_db(self.db)
        self.addCleanup(conn.close)
        a = self.plant(conn, [])
        b = self.plant(conn, [])
        diff = audit_history.diff_scans(conn, a, b)
        self.assertEqual({k: len(v) for k, v in diff.items()},
                         {'new': 0, 'resolved': 0, 'persisting': 0,
                          'changed': 0})


class RegressionsTest(TempBase):
    def record_pair(self, prev_detailed, last_detailed, root=None):
        conn = audit_history.init_db(self.db)
        self.addCleanup(conn.close)
        r = root or self.ws
        audit_history.record_scan(conn, make_rep(r, detailed=prev_detailed))
        last_id = audit_history.record_scan(
            conn, make_rep(r, detailed=last_detailed))
        return conn, last_id

    def test_severity_increase_is_regression(self):
        conn, last_id = self.record_pair(
            [typed('SEC-001', 'G6', 'medium', 'warn')],
            [typed('SEC-001', 'G6', 'high', 'warn')])
        regs = audit_history.regressions(conn, last_id)
        self.assertEqual(len(regs), 1)
        self.assertEqual(regs[0]['fid'], 'SEC-001')
        self.assertEqual(regs[0]['prev_severity'], 'medium')
        self.assertEqual(regs[0]['severity'], 'high')

    def test_status_drop_to_fail_is_regression(self):
        conn, last_id = self.record_pair(
            [typed('CFG-001', 'G4', 'low', 'pass')],
            [typed('CFG-001', 'G4', 'low', 'fail')])
        regs = audit_history.regressions(conn, last_id)
        self.assertEqual(len(regs), 1)
        self.assertIn('status pass -> fail', regs[0]['reasons'])

    def test_improvement_is_not_regression(self):
        conn, last_id = self.record_pair(
            [typed('HLTH-001', 'G5', 'high', 'fail')],
            [typed('HLTH-001', 'G5', 'medium', 'warn')])
        self.assertEqual(audit_history.regressions(conn, last_id), [])

    def test_unchanged_findings_are_not_regressions(self):
        conn, last_id = self.record_pair(
            [typed('SEC-001', 'G6', 'high', 'fail')],
            [typed('SEC-001', 'G6', 'high', 'fail')])
        self.assertEqual(audit_history.regressions(conn, last_id), [])

    def test_single_scan_has_no_regressions(self):
        conn = audit_history.init_db(self.db)
        self.addCleanup(conn.close)
        scan_id = audit_history.record_scan(
            conn, make_rep(self.ws, detailed=[typed('SEC-001', 'G6',
                                                    'critical', 'fail')]))
        self.assertEqual(audit_history.regressions(conn, scan_id), [])

    def test_check_id_match_survives_fid_change(self):
        conn, last_id = self.record_pair(
            [typed('GOV-001', 'G8', 'low', 'warn',
                   check_id='CLAUDE_LOCAL_DEPRECATED', harness='claude_code')],
            [typed('GOV-007', 'G8', 'high', 'warn',
                   check_id='CLAUDE_LOCAL_DEPRECATED', harness='claude_code')])
        regs = audit_history.regressions(conn, last_id)
        self.assertEqual(len(regs), 1)
        self.assertEqual(regs[0]['fid'], 'GOV-007')
        self.assertEqual(regs[0]['check_id'], 'CLAUDE_LOCAL_DEPRECATED')

    def test_previous_scan_of_same_root_only(self):
        other = self.base / 'other'
        other.mkdir()
        conn = audit_history.init_db(self.db)
        self.addCleanup(conn.close)
        audit_history.record_scan(conn, make_rep(other, detailed=[
            typed('SEC-001', 'G6', 'medium', 'warn')]))
        last_id = audit_history.record_scan(conn, make_rep(self.ws, detailed=[
            typed('SEC-001', 'G6', 'critical', 'fail')]))
        # no previous scan of THIS root: nothing to compare against
        self.assertEqual(audit_history.regressions(conn, last_id), [])

    def test_unknown_scan_id(self):
        conn = audit_history.init_db(self.db)
        self.addCleanup(conn.close)
        self.assertEqual(audit_history.regressions(conn, 42), [])


class TrendTest(TempBase):
    def test_trend_points_shape(self):
        conn = audit_history.init_db(self.db)
        self.addCleanup(conn.close)
        audit_history.record_scan(conn, make_rep(
            self.ws, detailed=[typed('A', 'G6', 'critical', 'fail'),
                               typed('B', 'G5', 'high', 'warn')],
            generated_at='2026-11-01T10:00:00+03:00'))
        audit_history.record_scan(conn, make_rep(
            self.ws, detailed=[typed('A', 'G6', 'high', 'warn')],
            generated_at='2026-11-02T10:00:00+03:00'))
        points = audit_history.trend(conn)
        self.assertEqual(len(points), 2)
        self.assertEqual(points[0]['ts'], '2026-11-01T10:00:00+03:00')
        self.assertEqual(points[0]['total'], 0)  # findings_total = fingerprint count
        self.assertEqual(points[0]['critical'], 1)
        self.assertEqual(points[0]['high'], 1)
        self.assertEqual(points[0]['medium'], 0)
        self.assertEqual(points[1]['critical'], 0)
        self.assertEqual(points[1]['high'], 1)

    def test_trend_root_filter(self):
        other = self.base / 'other'
        other.mkdir()
        conn = audit_history.init_db(self.db)
        self.addCleanup(conn.close)
        audit_history.record_scan(conn, make_rep(self.ws))
        audit_history.record_scan(conn, make_rep(other))
        self.assertEqual(len(audit_history.trend(conn)), 2)
        self.assertEqual(len(audit_history.trend(conn, root=str(self.ws))), 1)
        self.assertEqual(audit_history.trend(conn, root=str(other))[0]['total'], 0)


class PruneTest(TempBase):
    def make_five(self, conn):
        ids = []
        for i in range(5):
            rep = make_rep(self.ws, fingerprints=[
                ('fp%d' % i, 'junk', 'p%d' % i)])
            ids.append(audit_history.record_scan(conn, rep))
        return ids

    def test_prune_keeps_newest_and_deletes_findings(self):
        conn = audit_history.init_db(self.db)
        self.addCleanup(conn.close)
        ids = self.make_five(conn)
        deleted = audit_history.prune(conn, keep_scans=2)
        self.assertEqual(deleted, 3)
        left = [s['id'] for s in audit_history.list_scans(conn)]
        self.assertEqual(left, sorted(ids[-2:], reverse=True))  # newest first
        n = conn.execute('SELECT COUNT(*) FROM findings').fetchone()[0]
        self.assertEqual(n, 2)  # findings of deleted scans went too

    def test_prune_noop_under_limit(self):
        conn = audit_history.init_db(self.db)
        self.addCleanup(conn.close)
        self.make_five(conn)
        self.assertEqual(audit_history.prune(conn, keep_scans=100), 0)
        self.assertEqual(len(audit_history.list_scans(conn)), 5)

    def test_prune_zero_keeps_nothing(self):
        conn = audit_history.init_db(self.db)
        self.addCleanup(conn.close)
        self.make_five(conn)
        self.assertEqual(audit_history.prune(conn, keep_scans=0), 5)
        self.assertEqual(audit_history.list_scans(conn), [])


class ExportCsvTest(TempBase):
    def test_export_csv_roundtrip(self):
        import csv as csv_mod
        conn = audit_history.init_db(self.db)
        self.addCleanup(conn.close)
        audit_history.record_scan(conn, make_rep(
            self.ws, fingerprints=[('fp1', 'junk', 'p')],
            detailed=[typed('SEC-001', 'G6', 'critical', 'fail')]))
        audit_history.record_scan(conn, make_rep(self.ws),
                                  scan_file='scan.json')
        out = self.base / 'export.csv'
        count = audit_history.export_csv(conn, out)
        self.assertEqual(count, 2)
        with open(out, newline='', encoding='utf-8') as fh:
            rows = list(csv_mod.reader(fh))
        self.assertEqual(rows[0], ['id', 'ts', 'root', 'findings_total',
                                   'severity_counts', 'gate_statuses',
                                   'scan_file'])
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[2][3], '0')
        self.assertEqual(rows[2][6], 'scan.json')
        json.loads(rows[1][4])  # severity_counts column parses as json


class HistoryCliTest(TempBase):
    def run_cli(self, *args):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = agents_doctor.main(['history'] + list(args))
        return rc, buf.getvalue()

    def test_record_then_list(self):
        scan = self.base / 'scan.json'
        rep = make_rep(self.ws, fingerprints=[('fp1', 'junk', 'p')],
                       detailed=[typed('SEC-001', 'G6', 'critical', 'fail')])
        scan.write_text(json.dumps(rep), encoding='utf-8')
        rc, out = self.run_cli(str(self.ws), '--db', str(self.db),
                               '--record', str(scan))
        self.assertEqual(rc, 0)
        self.assertIn('recorded scan 1', out)
        rc, out = self.run_cli(str(self.ws), '--db', str(self.db))
        self.assertEqual(rc, 0)
        self.assertIn('1 scan(s)', out)
        self.assertIn('crit 1', out)

    def test_list_respects_last(self):
        conn = audit_history.init_db(self.db)
        conn.close()
        for i in range(3):
            rep = make_rep(self.ws, generated_at='2026-11-0%dT10:00:00+03:00'
                           % (i + 1))
            c = audit_history.init_db(self.db)
            audit_history.record_scan(c, rep)
            c.close()
        rc, out = self.run_cli(str(self.ws), '--db', str(self.db),
                               '--last', '2')
        self.assertEqual(rc, 0)
        self.assertIn('2 scan(s)', out)

    def test_diff_flag(self):
        conn = audit_history.init_db(self.db)
        audit_history.record_scan(conn, make_rep(self.ws, fingerprints=[
            ('aaa', 'junk', 'p'), ('bbb', 'junk', 'q')]))
        audit_history.record_scan(conn, make_rep(self.ws, fingerprints=[
            ('bbb', 'junk', 'q'), ('ccc', 'secrets', 'r')]))
        conn.close()
        rc, out = self.run_cli(str(self.ws), '--db', str(self.db),
                               '--diff', '1', '2')
        self.assertEqual(rc, 0)
        self.assertIn('NEW (1)', out)
        self.assertIn('RESOLVED (1)', out)
        self.assertIn('PERSISTING (1)', out)

    def test_diff_unknown_id_errors(self):
        conn = audit_history.init_db(self.db)
        audit_history.record_scan(conn, make_rep(self.ws))
        conn.close()
        rc, out = self.run_cli(str(self.ws), '--db', str(self.db),
                               '--diff', '1', '99')
        self.assertEqual(rc, 1)

    def test_regressions_flag(self):
        conn = audit_history.init_db(self.db)
        audit_history.record_scan(conn, make_rep(self.ws, detailed=[
            typed('SEC-001', 'G6', 'medium', 'warn')]))
        audit_history.record_scan(conn, make_rep(self.ws, detailed=[
            typed('SEC-001', 'G6', 'high', 'fail')]))
        conn.close()
        rc, out = self.run_cli(str(self.ws), '--db', str(self.db),
                               '--regressions')
        self.assertEqual(rc, 0)
        self.assertIn('regressions: 1', out)
        self.assertIn('SEC-001', out)

    def test_regressions_flag_no_history(self):
        conn = audit_history.init_db(self.db)
        conn.close()
        rc, out = self.run_cli(str(self.ws), '--db', str(self.db),
                               '--regressions')
        self.assertEqual(rc, 0)
        self.assertIn('no recorded scan', out)

    def test_trend_stdout_csv(self):
        conn = audit_history.init_db(self.db)
        audit_history.record_scan(conn, make_rep(self.ws, detailed=[
            typed('A', 'G6', 'critical', 'fail')]))
        audit_history.record_scan(conn, make_rep(self.ws))
        conn.close()
        rc, out = self.run_cli(str(self.ws), '--db', str(self.db), '--trend')
        self.assertEqual(rc, 0)
        lines = out.strip().splitlines()
        self.assertEqual(lines[0], 'ts,total,critical,high,medium,low,info')
        self.assertEqual(len(lines), 3)
        self.assertEqual(lines[1].split(',')[2], '1')
        self.assertEqual(lines[2].split(',')[2], '0')

    def test_trend_out_file(self):
        conn = audit_history.init_db(self.db)
        audit_history.record_scan(conn, make_rep(self.ws))
        conn.close()
        out_file = self.base / 'trend.csv'
        rc, out = self.run_cli(str(self.ws), '--db', str(self.db),
                               '--trend', '--out', str(out_file))
        self.assertEqual(rc, 0)
        self.assertIn('1 points', out)
        text = out_file.read_text(encoding='utf-8')
        self.assertTrue(text.startswith('ts,total,'))

    def test_prune_flag(self):
        conn = audit_history.init_db(self.db)
        for i in range(4):
            audit_history.record_scan(conn, make_rep(
                self.ws, generated_at='2026-11-0%dT10:00:00+03:00' % (i + 1)))
        conn.close()
        rc, out = self.run_cli(str(self.ws), '--db', str(self.db),
                               '--prune', '1')
        self.assertEqual(rc, 0)
        self.assertIn('deleted 3', out)
        conn = audit_history.init_db(self.db)
        self.assertEqual(len(audit_history.list_scans(conn)), 1)
        conn.close()

    def test_missing_db_errors(self):
        rc, out = self.run_cli(str(self.ws), '--db',
                               str(self.base / 'nope.db'))
        self.assertEqual(rc, 1)

    def test_not_a_directory_errors(self):
        rc, out = self.run_cli(str(self.base / 'missing-ws'))
        self.assertEqual(rc, 1)

    def test_record_bad_json_errors(self):
        bad = self.base / 'bad.json'
        bad.write_text('not json', encoding='utf-8')
        rc, out = self.run_cli(str(self.ws), '--db', str(self.db),
                               '--record', str(bad))
        self.assertEqual(rc, 1)
        rc, out = self.run_cli(str(self.ws), '--db', str(self.db),
                               '--record', str(self.base / 'missing.json'))
        self.assertEqual(rc, 1)

    def test_default_db_under_root(self):
        scan = self.base / 'scan.json'
        scan.write_text(json.dumps(make_rep(self.ws)), encoding='utf-8')
        rc, out = self.run_cli(str(self.ws), '--record', str(scan))
        self.assertEqual(rc, 0)
        self.assertTrue(
            (self.ws / '.agents-doctor' / 'history.db').exists())


class AuditAutoRecordTest(TempBase):
    def setUp(self):
        super().setUp()
        self.home = self.base / 'home'
        self.home.mkdir()
        (self.ws / 'AGENTS.md').write_text('# x\nrun tests\n', encoding='utf-8')
        self.db = audit_history.default_db_path(self.ws)

    def test_audit_records_into_history(self):
        out = self.base / 'scan.json'
        rc = agents_doctor.main(['audit', str(self.ws),
                                 '--home', str(self.home),
                                 '--out', str(out)])
        self.assertEqual(rc, 0)
        self.assertTrue(self.db.exists())
        conn = audit_history.init_db(self.db)
        self.addCleanup(conn.close)
        scans = audit_history.list_scans(conn)
        self.assertEqual(len(scans), 1)
        self.assertEqual(scans[0]['root'], str(self.ws))
        self.assertEqual(scans[0]['scan_file'], str(out))
        rc = agents_doctor.main(['audit', str(self.ws),
                                 '--home', str(self.home),
                                 '--out', str(out)])
        self.assertEqual(rc, 0)
        self.assertEqual(len(audit_history.list_scans(conn)), 2)

    def test_focused_audit_not_recorded(self):
        out = self.base / 'scan.json'
        rc = agents_doctor.main(['audit', str(self.ws),
                                 '--home', str(self.home),
                                 '--focus', 'security',
                                 '--out', str(out)])
        self.assertEqual(rc, 0)
        self.assertFalse(self.db.exists())

    def test_history_failure_never_fails_audit(self):
        out = self.base / 'scan.json'
        with mock.patch.object(agents_doctor.audit_history,
                               'record_scan',
                               side_effect=sqlite3.Error('boom')):
            rc = agents_doctor.main(['audit', str(self.ws),
                                     '--home', str(self.home),
                                     '--out', str(out)])
        self.assertEqual(rc, 0)
        self.assertTrue(out.exists())  # the audit itself finished


class PrivacyTest(TempBase):
    def test_canary_never_lands_in_database(self):
        conn = audit_history.init_db(self.db)
        detailed = [
            typed('SEC-001', 'G6', 'critical', 'fail',
                  title='Possible api_key ' + CANARY,
                  description='value ' + CANARY + ' in .env line 3',
                  evidence=[{'file': '.env', 'line': 3, 'detail': CANARY}]),
            typed('GOV-001', 'G8', 'high', 'warn',
                  check_id='CLAUDE_LOCAL_DEPRECATED',
                  harness='claude_code',
                  title='CLAUDE.local.md holds ' + CANARY),
        ]
        rep = make_rep(self.ws, fingerprints=[('fp1', 'secrets', '.env')],
                       detailed=detailed)
        rep['secrets'] = [{'path': '.env', 'line': 3, 'kind': 'api_key',
                           'mask': 'sk-CA***def',
                           'fingerprint': 'hmac256:' + CANARY,
                           'confidence': 0.9}]
        audit_history.record_scan(conn, rep)
        conn.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        conn.close()
        # canary must be absent from the database file and any wal remains
        for suffix in ('', '-wal', '-shm'):
            p = Path(str(self.db) + suffix)
            if p.exists():
                self.assertNotIn(CANARY.encode('utf-8'),
                                 p.read_bytes(),
                                 'canary leaked into %s' % p)
        # and the stored projection carries no free-text columns at all
        conn = audit_history.init_db(self.db)
        self.addCleanup(conn.close)
        cols = [r[1] for r in conn.execute('PRAGMA table_info(findings)')]
        self.assertEqual(cols, ['scan_id', 'kind', 'fp', 'section', 'path',
                                'fid', 'gate', 'severity', 'status',
                                'check_id', 'harness'])
        rows = conn.execute("SELECT fid, gate, severity, status, check_id,"
                            " harness FROM findings WHERE kind='typed'"
                            " ORDER BY fid").fetchall()
        self.assertEqual(len(rows), 2)  # the findings were recorded


if __name__ == '__main__':
    unittest.main()
