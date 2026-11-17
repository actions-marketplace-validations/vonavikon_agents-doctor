"""Browser E2E tests for the agents-doctor local web UI (Visual TZ
section 7, stage 1).

Playwright sync API on top of unittest (the repo runs unittest, not
pytest). Each test class builds a temp workspace, scans it in-process,
serves ui/server.py on an ephemeral 127.0.0.1 port and drives a real
headless Chromium against the SPA from ui/static.

Skip gate: without `playwright` installed every test here skips, so the
plain `unittest discover` suite stays green on machines (and CI jobs)
that never asked for browser tests. Install them with:

    pip install -r requirements-dev.txt
    python -m playwright install chromium

Every test ends by asserting that the page produced no console errors
and no unhandled page errors (the allowlist is empty by default; add an
entry only for browser artifacts, never to silence an app bug).
"""
import json
import re
import shutil
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[2] / 'skills' / \
    'agents-doctor' / 'scripts'
sys.path.insert(0, str(SCRIPTS))

import audit_scan  # noqa: E402
from ui import server as srv  # noqa: E402

try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT = True
except ImportError:
    PLAYWRIGHT = False

# Canary secret. Assembled from pieces so a scan of THIS repository
# never sees the whole token in the test source (same convention as
# secret_rules.py). The file under test does contain the full value.
CANARY = 'xox' + 'b-123456789012-1234567890123-abcdefghijklmnopqrstuv'

WAIT_MS = 15000  # explicit per-wait budget, well under unittest's wants


def build_workspace(root: Path) -> None:
    """Deterministic workspace: dead links, a wildcard Bash permission,
    a secrets file (canary + one more live-looking token) and a nested
    src/ folder so the tree has directories to expand."""
    (root / 'AGENTS.md').write_text(
        '# Fixture project\n\n'
        'See [Contributing](./CONTRIBUTING.md) and [Docs](./docs/guide.md) '
        'for details.\n', encoding='utf-8')
    (root / '.claude').mkdir()
    (root / '.claude' / 'settings.json').write_text(json.dumps({
        'permissions': {'allow': ['Bash(*)', 'WebFetch']},
    }), encoding='utf-8')
    (root / 'src').mkdir()
    (root / 'src' / 'creds.txt').write_text(
        '# service credentials\n'
        'slack_token = "%s"\n'
        'anthropic_key = "sk-ant-api03-abcdefghijklmnopqrstuv"\n'
        'normal = "hello world"\n' % CANARY, encoding='utf-8')
    (root / 'src' / 'notes.md').write_text(
        '# Notes\n\nExample header: Authorization: Bearer ya29.test-token\n',
        encoding='utf-8')


class UiHarness:
    """One scanned workspace + one UI server + one Chromium browser.

    Used as a per-class fixture: create in setUpClass, close() in
    tearDownClass. Pages are handed out per test via open_page(), each
    on a fresh context with console/pageerror collection wired up.
    """

    def __init__(self, workspace_builder):
        self.tmp = Path(tempfile.mkdtemp(prefix='ad-e2e-'))
        self.root = self.tmp / 'ws'
        self.home = self.tmp / 'home'
        self.root.mkdir()
        self.home.mkdir()
        workspace_builder(self.root)
        self.report = audit_scan.scan(self.root, self.home, False)
        state = srv.UiState(self.report, self.root)
        self.httpd = ThreadingHTTPServer(('127.0.0.1', 0),
                                         srv.make_handler(state, None))
        self.port = self.httpd.server_address[1]
        self.base = 'http://127.0.0.1:%d/' % self.port
        threading.Thread(target=self.httpd.serve_forever,
                         daemon=True).start()
        self._pw = sync_playwright().start()
        self.browser = self._pw.chromium.launch(headless=True)

    def open_page(self):
        """(page, console_errors) on a fresh context. console_errors
        collects console.error messages and uncaught page errors."""
        ctx = self.browser.new_context()
        page = ctx.new_page()
        errors = []
        page.on('console', lambda m: errors.append(m.text)
                if m.type == 'error' else None)
        page.on('pageerror', lambda e: errors.append('pageerror: %s' % e))
        return page, ctx, errors

    def close(self):
        self.browser.close()
        self._pw.stop()
        self.httpd.shutdown()
        self.httpd.server_close()
        shutil.rmtree(self.tmp, ignore_errors=True)


@unittest.skipUnless(PLAYWRIGHT, 'playwright not installed')
class MainWorkspaceE2ETest(unittest.TestCase):
    """Stage-1 scenarios over the fixture workspace: layout, overview,
    chips, findings + card, tree + inspector (masking!), simulate,
    compare, rescan, dead-file handling, request security."""

    @classmethod
    def setUpClass(cls):
        cls.harness = UiHarness(build_workspace)

    @classmethod
    def tearDownClass(cls):
        cls.harness.close()

    def setUp(self):
        self.page, self._ctx, self.console_errors = \
            self.harness.open_page()

    def tearDown(self):
        self._ctx.close()

    # ------------------------------------------------------- helpers

    def goto(self):
        self.page.goto(self.harness.base)
        return self.page

    def wait(self, selector):
        return self.page.wait_for_selector(selector, timeout=WAIT_MS)

    def open_tab(self, tab):
        self.page.click('#tab-' + tab)
        self.wait('#panel-%s:not([hidden])' % tab)

    def findings_counter(self):
        """'Showing X of Y fetched findings.' -> (X, Y)."""
        txt = self.page.inner_text('.findings-count')
        m = re.search(r'Showing (\d+) of (\d+) fetched', txt)
        self.assertIsNotNone(m, 'counter text unreadable: %r' % txt)
        return int(m.group(1)), int(m.group(2))

    def assert_no_console_errors(self):
        self.assertEqual(self.console_errors, [],
                         'browser console errors: %r' % self.console_errors)

    # ------------------------------------------------------- scenarios

    def test_01_page_loads(self):
        pg = self.goto()
        self.wait('#overview-body .stat-box')
        self.assertEqual(pg.title(),
                         'agents-doctor — Visual Workspace Explorer')
        # topbar meta shows the audited root path
        root_txt = pg.inner_text('#meta-root')
        self.assertIn(self.harness.root.name, root_txt)
        # seven tabs: overview tree treemap instructions findings
        # simulate compare
        self.assertEqual(pg.locator('.tabs .tab').count(), 7)
        self.assert_no_console_errors()

    def test_02_overview_chips_and_gates(self):
        pg = self.goto()
        self.wait('#overview-body .tbl tbody tr')
        # severity chips render with non-zero counts for the fixture
        crit = pg.locator(
            '#severity-chips .chip[title^="Hide Critical"]')
        self.assertGreater(int(crit.locator('.chip-count').inner_text()),
                           0)
        # nine gates, one table row each, every status has a glyph
        rows = pg.locator('#overview-body .tbl tbody tr')
        self.assertEqual(rows.count(), 9)
        glyphs = pg.locator('#overview-body .status-badge .st-glyph')
        self.assertEqual(glyphs.count(), 9)
        for i in range(glyphs.count()):
            self.assertNotEqual(glyphs.nth(i).inner_text().strip(), '')
        self.assert_no_console_errors()

    def test_03_chip_toggles_pressed_state(self):
        pg = self.goto()
        self.wait('#severity-chips .chip')
        hide = '#severity-chips .chip[title="Hide Critical findings"]'
        show = '#severity-chips .chip[title="Show Critical findings"]'
        chip = pg.locator(hide)
        self.assertEqual(chip.get_attribute('aria-pressed'), 'true')
        chip.click()
        # re-rendered DOM: the same chip now offers to show them again
        chip2 = pg.wait_for_selector(show, timeout=WAIT_MS)
        self.assertEqual(chip2.get_attribute('aria-pressed'), 'false')
        pg.locator(show).click()
        pg.wait_for_selector(hide, timeout=WAIT_MS)
        self.assert_no_console_errors()

    def test_04_findings_table_and_gate_filter(self):
        pg = self.goto()
        self.open_tab('findings')
        self.wait('#findings-body tbody tr.fnd-row')
        shown, total = self.findings_counter()
        self.assertGreater(shown, 0)
        self.assertGreaterEqual(total, shown)
        # gate filter: click the G6 row in the overview gates table
        self.open_tab('overview')
        self.wait('#overview-body .tbl tbody tr')
        pg.locator('#overview-body tbody tr', has_text='G6').first.click()
        self.wait('#panel-findings:not([hidden])')
        self.wait('#findings-body tbody tr.fnd-row')
        g_shown, g_total = self.findings_counter()
        self.assertLess(g_total, total)
        self.assertGreater(g_total, 0)
        # every visible row belongs to G6
        gates = pg.locator('#findings-body tbody tr.fnd-row td:nth-child(3)')
        for i in range(gates.count()):
            self.assertEqual(gates.nth(i).inner_text().strip(), 'G6')
        self.assert_no_console_errors()

    def test_05_findings_search_filter(self):
        pg = self.goto()
        self.open_tab('findings')
        self.wait('#findings-body tbody tr.fnd-row')
        _, total = self.findings_counter()
        pg.fill('#fnd-q', 'creds')
        # 300 ms debounce in app.js + fetch + render; the counter
        # element is replaced during reload, hence the null guard
        pg.wait_for_function(
            """() => {
                const el = document.querySelector('.findings-count');
                return el ? !el.textContent.includes('of %d fetched') : false;
            }""" % total,
            timeout=WAIT_MS)
        shown, filtered = self.findings_counter()
        self.assertGreaterEqual(filtered, 1)
        self.assertLess(filtered, total)
        self.assertEqual(shown, filtered)
        self.assert_no_console_errors()

    def test_06_finding_card_open_and_esc_close(self):
        pg = self.goto()
        self.open_tab('findings')
        row = self.wait('#findings-body tbody tr.fnd-row')
        fid = row.get_attribute('data-fid')
        row.click()
        self.wait('#card-overlay:not([hidden])')
        self.assertEqual(pg.inner_text('#card-fid').strip(), fid)
        # the card opens in a loading state; wait for the fetched body
        # before asserting badges and evidence
        self.wait('#card-badges .sev-badge')
        self.assertGreater(pg.locator('#card-badges .sev-badge').count(), 0)
        self.wait('#card-body .ev-item')
        self.assertGreater(pg.locator('#card-body .ev-item').count(), 0)
        pg.keyboard.press('Escape')
        # state='hidden': wait until the overlay is attached and hidden
        pg.wait_for_selector('#card-overlay', state='hidden',
                             timeout=WAIT_MS)
        self.assert_no_console_errors()

    def test_07_tree_expand_and_inspector(self):
        pg = self.goto()
        self.open_tab('tree')
        self.wait('#tree-body .tree-node-row')
        # expand src/ lazily, then open the secrets file
        pg.locator('.tree-node-row[data-path="src"]').click()
        pg.wait_for_selector('.tree-node-row[data-path="src/creds.txt"]',
                             timeout=WAIT_MS).click()
        self.wait('#inspector:not([hidden])')
        self.wait('#insp-code .code-line')
        self.assertEqual(pg.inner_text('#insp-path').strip(),
                         'src/creds.txt')
        body = pg.inner_text('#insp-code')
        self.assertIn('slack_token', body)
        # the masked value is shown, the raw canary never is
        self.assertIn('xox***', body)
        self.assertNotIn(CANARY, pg.content())
        self.assertNotIn(CANARY, body)
        self.assert_no_console_errors()

    def test_08_inspector_flagged_lines_and_rule_label(self):
        pg = self.goto()
        self.open_tab('tree')
        pg.locator('.tree-node-row[data-path="src"]').click()
        pg.wait_for_selector('.tree-node-row[data-path="src/creds.txt"]',
                             timeout=WAIT_MS).click()
        self.wait('#insp-code .code-line.flagged')
        flagged = pg.locator('#insp-code .code-line.flagged')
        self.assertGreaterEqual(flagged.count(), 2)  # slack + anthropic
        labels = pg.locator('#insp-code .code-flag-label')
        texts = {labels.nth(i).inner_text().strip()
                 for i in range(labels.count())}
        self.assertIn('SEC-106', texts)  # slack-token rule
        self.assert_no_console_errors()

    def test_09_secrets_never_in_dom(self):
        pg = self.goto()
        self.open_tab('tree')
        pg.locator('.tree-node-row[data-path="src"]').click()
        pg.wait_for_selector('.tree-node-row[data-path="src/creds.txt"]',
                             timeout=WAIT_MS).click()
        self.wait('#insp-code .code-line')
        # whole-DOM sweep: the canary token must not leak anywhere,
        # not even into attributes or shadow copies
        html = pg.content()
        self.assertNotIn(CANARY, html)
        self.assertNotIn('abcdefghijklmnopqrstuv', html)
        self.assert_no_console_errors()

    def test_10_simulate_zcode(self):
        pg = self.goto()
        self.open_tab('simulate')
        # <option> has no box of its own: wait for attached, not visible
        pg.wait_for_selector('#sim-harness option[value="zcode"]',
                             state='attached', timeout=WAIT_MS)
        pg.select_option('#sim-harness', 'zcode')
        pg.click('#sim-run')
        self.wait('#simulate-body .sim-harness-block')
        block = pg.locator('#simulate-body .sim-harness-block').first
        # the section title is CSS-uppercased ('ZCODE'), so compare
        # case-insensitively against the harness id
        self.assertIn('zcode', block.inner_text().lower())
        # loaded sources for the fixture: at least the root AGENTS.md
        self.assertIn('Loaded', block.inner_text())
        self.assertIn('AGENTS.md', block.inner_text())
        self.assert_no_console_errors()

    def test_11_compare_without_baseline(self):
        pg = self.goto()
        self.open_tab('compare')
        box = self.wait('#compare-body .empty-state')
        self.assertIn('Compare is not available', box.inner_text())
        # the hint is actionable, not a bare blank
        self.assertIn('--baseline', pg.inner_text('#compare-body'))
        self.assert_no_console_errors()

    def test_12_rescan_post_roundtrip(self):
        pg = self.goto()
        self.wait('#overview-body .stat-box')
        # 1) the page's own POST: the browser sends a same-origin
        #    Origin header and passes the CSRF guard
        pg.click('#btn-rescan')
        toast = self.wait('#toast:not([hidden])')
        self.assertIn('Rescan finished', toast.inner_text())
        # 2) the documented Origin-less path: explicit opt-in header
        resp = pg.request.post(
            self.harness.base + 'api/rescan',
            headers={'X-Agents-Doctor': 'local'})
        self.assertEqual(resp.status, 200)
        self.assertTrue(json.loads(resp.text())['rescanned'])
        self.assert_no_console_errors()

    def test_13_dead_file_preview_shows_error_no_crash(self):
        pg = self.goto()
        self.open_tab('tree')
        pg.locator('.tree-node-row[data-path="AGENTS.md"]').click()
        self.wait('#insp-code .code-line')
        target = self.harness.root / 'AGENTS.md'
        backup = target.read_text(encoding='utf-8')
        try:
            target.unlink()
            pg.locator('.tree-node-row[data-path="AGENTS.md"]').click()
            note = self.wait('#insp-code .binary-note')
            self.assertIn('Cannot open file', note.inner_text())
        finally:
            target.write_text(backup, encoding='utf-8')
        # the app handled the missing file: no uncaught JS anywhere
        self.assert_no_console_errors()

    def test_14_host_header_spoof_rejected(self):
        pg = self.goto()
        self.wait('#overview-body .stat-box')
        resp = pg.request.get(self.harness.base + 'api/overview',
                              headers={'Host': 'evil.com'})
        self.assertEqual(resp.status, 403)
        self.assertIn('error', json.loads(resp.text()))
        self.assert_no_console_errors()


@unittest.skipUnless(PLAYWRIGHT, 'playwright not installed')
class EmptyWorkspaceE2ETest(unittest.TestCase):
    """Scenario: nothing in the workspace. The page must still boot,
    show empty states and never touch a console error."""

    @classmethod
    def setUpClass(cls):
        cls.harness = UiHarness(lambda root: None)

    @classmethod
    def tearDownClass(cls):
        cls.harness.close()

    def setUp(self):
        self.page, self._ctx, self.console_errors = \
            self.harness.open_page()

    def tearDown(self):
        self._ctx.close()

    def test_01_empty_workspace_loads_with_empty_states(self):
        pg = self.page
        pg.goto(self.harness.base)
        # overview still renders the gates table (9 rows, no crash)
        pg.wait_for_selector('#overview-body .tbl tbody tr',
                             timeout=WAIT_MS)
        self.assertEqual(
            pg.locator('#overview-body .tbl tbody tr').count(), 9)
        # tree: explicit empty state, not a blank panel
        pg.click('#tab-tree')
        pg.wait_for_selector('#tree-body .empty-state', timeout=WAIT_MS)
        self.assertIn('Workspace root is empty',
                      pg.inner_text('#tree-body'))
        # findings table: the scan still yields advisory findings
        pg.click('#tab-findings')
        pg.wait_for_selector('.findings-count', timeout=WAIT_MS)
        self.assertEqual(self.console_errors, [],
                         'browser console errors: %r' % self.console_errors)


@unittest.skipUnless(PLAYWRIGHT, 'playwright not installed')
class TreeMapNavigationE2ETest(unittest.TestCase):
    """Stage-1 TreeMap fix (TZ 3.0 section 4): selection stays in the
    TreeMap, double click zooms, keyboard drives the same actions."""

    @classmethod
    def setUpClass(cls):
        cls.harness = UiHarness(build_workspace)

    @classmethod
    def tearDownClass(cls):
        cls.harness.close()

    def setUp(self):
        self.page, self._ctx, self.console_errors =             self.harness.open_page()
        self.page.goto(self.harness.base)
        self.page.wait_for_selector('#overview-body .stat-box',
                                    timeout=WAIT_MS)
        self.page.click('#tab-treemap')
        self.page.wait_for_selector('#treemap-body .tm-cell',
                                    timeout=WAIT_MS)

    def tearDown(self):
        self._ctx.close()

    def _cells(self):
        return self.page.query_selector_all('#treemap-body .tm-cell')

    def _dir_cell(self):
        for c in self._cells():
            if c.get_attribute('data-isdir') in ('true', '1'):
                return c
        self.fail('no directory cell rendered')

    # In a nested treemap the parent directory cell's CENTER is
    # covered by its child cells (which is correct squarify layout);
    # the parent's own hit area is its label strip at the top-left.
    CORNER = {'x': 10, 'y': 8}

    def _zoom_level(self):
        """Current treemap zoom level: the trailing crumb is rendered
        as span.crumb-current (buttons are only the ancestors)."""
        return self.page.inner_text('#treemap-crumbs .crumb-current'
                                    ).strip()

    def test_01_click_directory_selects_without_leaving_tab(self):
        cell = self._dir_cell()
        cell.click(position=self.CORNER)
        self.page.wait_for_selector('.tm-cell.selected', timeout=WAIT_MS)
        # still on the treemap panel: the tree panel stays hidden
        hidden = self.page.eval_on_selector(
            '#panel-tree', 'el => el.hidden')
        self.assertTrue(hidden,
                        'single click must not switch to the Tree tab')
        self.assertEqual(self.console_errors, [])

    def test_02_click_file_selects_and_opens_inspector(self):
        for c in self._cells():
            if c.get_attribute('data-isdir') not in ('true', '1'):
                c.click()
                break
        else:
            self.fail('no file cell rendered')
        self.page.wait_for_selector('#inspector:not([hidden])',
                                    timeout=WAIT_MS)
        self.assertEqual(self.console_errors, [])

    def test_03_doubleclick_directory_zooms_in(self):
        cell = self._dir_cell()
        path = cell.get_attribute('data-path')
        cell.dblclick(position=self.CORNER)
        # breadcrumb grows a level for the zoomed directory
        self.page.wait_for_selector(
            '#treemap-crumbs .crumb-current', timeout=WAIT_MS)
        self.assertEqual(self._zoom_level(), Path(path).name)
        self.assertEqual(self.console_errors, [])

    def test_04_enter_zooms_backspace_goes_up(self):
        cell = self._dir_cell()
        path = cell.get_attribute('data-path')
        self.page.eval_on_selector(
            '.tm-cell[data-path="%s"]' % path, 'el => el.focus()')
        self.page.keyboard.press('Enter')
        self.page.wait_for_selector(
            '#treemap-crumbs .crumb-current', timeout=WAIT_MS)
        self.assertEqual(self._zoom_level(), Path(path).name)
        self.page.keyboard.press('Backspace')
        self.assertEqual(self._zoom_level(), 'root')
        self.assertEqual(self.console_errors, [])

    def test_05_breadcrumb_returns_to_level(self):
        cell = self._dir_cell()
        path = cell.get_attribute('data-path')
        cell.dblclick(position=self.CORNER)
        self.page.wait_for_selector(
            '#treemap-crumbs .crumb-current', timeout=WAIT_MS)
        self.assertEqual(self._zoom_level(), Path(path).name)
        # click the root crumb button to come back
        self.page.click('.crumb-btn[data-path=""]')
        self.assertEqual(self._zoom_level(), 'root')
        self.assertEqual(self.console_errors, [])

    def test_06_selection_survives_tab_switch(self):
        cell = self._dir_cell()
        cell.click()
        self.page.wait_for_selector('.tm-cell.selected', timeout=WAIT_MS)
        self.page.click('#tab-findings')
        self.page.wait_for_selector('#panel-findings:not([hidden])',
                                    timeout=WAIT_MS)
        self.page.click('#tab-treemap')
        self.page.wait_for_selector('#treemap-body .tm-cell.selected',
                                    timeout=WAIT_MS)
        self.assertEqual(self.console_errors, [])


if __name__ == '__main__':
    unittest.main()
