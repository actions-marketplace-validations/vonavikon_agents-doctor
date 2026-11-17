/* agents-doctor — Visual Workspace Explorer, phases V1+V2.
   Vanilla JS, zero dependencies, fully offline. Served by ui/server.py;
   see the API contract in that file's docstring. */
(() => {
'use strict';

/* ---------------------------------------------------------------- helpers */

const $ = (id) => document.getElementById(id);
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const SEV_CAP = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };
const SEV_LETTER = { critical: 'C', high: 'H', medium: 'M', low: 'L', info: 'I' };
const SEV_WEIGHT = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
const SEV_VAR = {
  critical: '--sev-critical', high: '--sev-high', medium: '--sev-medium',
  low: '--sev-low', info: '--sev-info',
};
const STATUS_GLYPH = { pass: '\u2713', fail: '\u2715', warn: '\u26a0', unknown: '?', not_applicable: '\u2014' };
const STATUS_LABEL = { pass: 'pass', fail: 'fail', warn: 'warn', unknown: 'unknown', not_applicable: 'n/a' };
const STATUS_RANK = { fail: 0, warn: 1, unknown: 2, not_applicable: 3, pass: 4 };

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') node.className = v;
    else if (k === 'text') node.textContent = v;
    else if (k === 'html') node.innerHTML = v;           // trusted, built here only
    else if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2), v);
    else if (v === true) node.setAttribute(k, '');
    else node.setAttribute(k, String(v));
  }
  for (const c of children) {
    if (c === null || c === undefined) continue;
    node.append(c);
  }
  return node;
}

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

let toastTimer = null;
function toast(msg) {
  const t = $('toast');
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.hidden = true; }, 4500);
}

async function api(path, params = {}, method = 'GET') {
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== null && v !== undefined && v !== '') qs.set(k, v);
  }
  const url = path + (qs.toString() ? '?' + qs.toString() : '');
  let resp;
  try {
    resp = await fetch(url, method === 'POST' ? { method } : undefined);
  } catch (e) {
    throw new Error('network error: ' + e.message);
  }
  let body = null;
  try { body = await resp.json(); } catch { /* non-JSON below */ }
  if (!resp.ok) {
    const msg = body && body.error ? body.error : resp.status + ' ' + resp.statusText;
    throw new Error(msg);
  }
  if (body && body.error) throw new Error(body.error);
  return body;
}

const loadingHTML = (what) =>
  `<div class="loading"><span class="spinner" aria-hidden="true"></span> ${esc(what)}</div>`;
const emptyHTML = (msg) =>
  `<div class="empty-state"><span class="empty-glyph" aria-hidden="true">[ ]</span>${esc(msg)}</div>`;

function errorPanel(err, retryFn) {
  const box = el('div', { class: 'error-panel' });
  box.append(
    el('h3', { text: 'Failed to load' }),
    el('p', { text: String(err && err.message ? err.message : err) }),
    el('button', { class: 'btn-accent', onclick: retryFn, text: 'Retry' }),
  );
  return box;
}

function sevBadge(sev) {
  return el('span', { class: 'sev-badge sev-' + sev, title: 'severity: ' + sev, text: SEV_CAP[sev] || sev });
}

function statusBadge(st) {
  const known = st in STATUS_GLYPH;
  return el('span', {
    class: 'status-badge st-' + st,
    title: 'status: ' + st,
    html: `<span class="st-glyph" aria-hidden="true">${known ? STATUS_GLYPH[st] : '?'}</span>` +
          `<span>${known ? STATUS_LABEL[st] : esc(st)}</span>`,
  });
}

function countsFiltered(counts) {
  const out = {};
  for (const s of SEVERITIES) out[s] = state.sev.has(s) ? (counts[s] || 0) : 0;
  return out;
}
const countsTotal = (c) => SEVERITIES.reduce((sum, s) => sum + (c[s] || 0), 0);
const countsRisk = (c) => SEVERITIES.reduce((sum, s) => sum + SEV_WEIGHT[s] * (c[s] || 0), 0);

function badgeRowFromCounts(counts) {
  const row = el('span', { class: 'badge-row' });
  const c = countsFiltered(counts);
  for (const s of SEVERITIES) {
    if ((c[s] || 0) > 0) {
      row.append(el('span', {
        class: 'tree-badge tb-' + s,
        title: s + ': ' + c[s] + ' (filtered view)',
        text: SEV_LETTER[s] + ' ' + c[s],
      }));
    }
  }
  return row;
}

function dirname(p) {
  const i = p.lastIndexOf('/');
  return i <= 0 ? (i === 0 ? '/' : '') : p.slice(0, i);
}

/* ------------------------------------------------------------------ state */

const state = {
  tab: 'overview',
  overview: null,
  harnesses: null,
  sev: new Set(SEVERITIES),     // global severity filter
  showPassed: false,
  findings: {
    fetched: [], gate: '', harness: '', q: '',
    sortKey: 'severity', sortDir: 'desc', group: false,
    loadedOnce: false,
  },
  tree: {
    cache: new Map(),           // rel -> {children, truncated, loading, error}
    expanded: new Set(),
    filter: '', sort: 'name',
    loadedOnce: false, focusedPath: null, seq: 0, currentDir: '',
  },
  treemap: {
    metric: 'density', zoom: '', loadedOnce: false, nodes: new Map(), resizing: false,
    selected: null,   // path of the selected cell; survives zoom and tab switches
  },
  simulate: { result: null, harness: '' },
  instructions: null,
  compare: null,
  inspector: { path: null, line: null },
  history: { stack: [], idx: -1 },
};

/* ------------------------------------------------------------------ chips */

function renderChips() {
  const box = $('severity-chips');
  box.textContent = '';
  const ov = state.overview || {};
  const sevCounts = ov.severity_counts || {};
  const passCount = (ov.status_counts || {}).pass || 0;

  const make = (key, label, count, colorVar, pressed, onClick) => {
    const chip = el('button', {
      class: 'chip', role: 'button', 'aria-pressed': String(pressed),
      title: pressed ? 'Hide ' + label + ' findings' : 'Show ' + label + ' findings',
      onclick: onClick,
    });
    chip.append(
      el('span', { class: 'chip-dot', 'aria-hidden': 'true' }),
      el('span', { text: label }),
      el('span', { class: 'chip-count', text: String(count) }),
    );
    chip.style.setProperty('--chip-color', `var(${colorVar})`);
    return chip;
  };

  for (const s of SEVERITIES) {
    box.append(make(s, SEV_CAP[s], sevCounts[s] || 0, SEV_VAR[s], state.sev.has(s), () => {
      if (state.sev.has(s)) state.sev.delete(s); else state.sev.add(s);
      onGlobalFilterChange();
    }));
  }
  box.append(make('passed', 'Passed', passCount, '--pass', state.showPassed, () => {
    state.showPassed = !state.showPassed;
    onGlobalFilterChange();
  }));
}

function onGlobalFilterChange() {
  renderChips();
  if (state.findings.loadedOnce) renderFindings();
  if (state.tree.loadedOnce) renderTree();
  if (state.treemap.loadedOnce) renderTreemap();
}

/* ------------------------------------------------------------------- tabs */

const TABS = ['overview', 'tree', 'treemap', 'instructions', 'findings', 'simulate', 'compare'];
const initedTabs = new Set();

function switchTab(name) {
  if (!TABS.includes(name)) return;
  state.tab = name;
  for (const t of TABS) {
    $('tab-' + t).setAttribute('aria-selected', String(t === name));
    $('panel-' + t).hidden = t !== name;
  }
  if (!initedTabs.has(name)) {
    initedTabs.add(name);
    if (name === 'overview') loadOverview();
    if (name === 'tree') initTree();
    if (name === 'treemap') initTreemap();
    if (name === 'instructions') initInstructions();
    if (name === 'findings') initFindings();
    if (name === 'simulate') initSimulate();
    if (name === 'compare') initCompare();
  }
}

/* --------------------------------------------------------------- overview */

async function loadOverview() {
  const body = $('overview-body');
  body.innerHTML = loadingHTML('Loading overview…');
  try {
    state.overview = await api('/api/overview');
    renderMeta();
    renderChips();
    renderOverview();
  } catch (e) {
    body.textContent = '';
    body.append(errorPanel(e, loadOverview));
  }
}

function renderMeta() {
  const ov = state.overview || {};
  $('meta-root').querySelector('.meta-val').textContent = ov.root || '?';
  $('meta-date').querySelector('.meta-val').textContent = ov.generated_at || '?';
  $('meta-rules').querySelector('.meta-val').textContent = ov.rules_version || '?';
  $('meta-findings').querySelector('.meta-val').textContent =
    ov.findings_total != null ? ov.findings_total : '?';
}

function renderOverview() {
  const ov = state.overview;
  const body = $('overview-body');
  body.textContent = '';

  const sevCounts = ov.severity_counts || {};
  const statusCounts = ov.status_counts || {};
  const boxes = el('div', { class: 'ov-stats' });
  const addBox = (key, val) => boxes.append(
    el('div', { class: 'stat-box' }, el('div', { class: 'stat-key', text: key }),
      el('div', { class: 'stat-val', text: String(val) })));
  addBox('findings', ov.findings_total);
  addBox('critical', sevCounts.critical || 0);
  addBox('high', sevCounts.high || 0);
  const gates = ov.gates || [];
  addBox('gates pass', gates.filter((g) => g.status === 'pass').length);
  addBox('gates fail', gates.filter((g) => g.status === 'fail').length);
  addBox('gates warn', gates.filter((g) => g.status === 'warn').length);
  body.append(boxes);

  const stLine = el('p', { class: 'conf-note' });
  const parts = [];
  for (const st of ['pass', 'fail', 'warn', 'unknown', 'not_applicable']) {
    parts.push(`${STATUS_GLYPH[st]} ${STATUS_LABEL[st]} ${statusCounts[st] || 0}`);
  }
  stLine.textContent = 'Finding statuses: ' + parts.join('   ·   ');
  body.append(stLine);

  body.append(el('div', { class: 'ov-section-title', text: 'Gates' }));
  if (!gates.length) {
    body.append(el('div', { class: 'empty-state', text: 'No gates in this scan.' }));
    return;
  }
  const table = el('table', { class: 'tbl', ariaLabel: 'Gates' });
  const thead = el('thead', {}, el('tr', {},
    el('th', { text: 'gid' }), el('th', { text: 'Gate' }),
    el('th', { text: 'Status' }), el('th', { class: 'num', text: 'Confidence' })));
  const tbody = el('tbody');
  for (const g of gates) {
    const tr = el('tr', {
      class: 'row-click',
      title: 'Show findings of gate ' + g.gid,
      onclick: () => {
        state.findings.gate = g.gid || '';
        $('fnd-gate').value = state.findings.gate;
        switchTab('findings');
        if (state.findings.loadedOnce) loadFindings();
      },
    });
    tr.append(
      el('td', { class: 'mono', text: g.gid || '?' }),
      el('td', { text: g.name || '' }),
      el('td', {}, statusBadge(g.status)),
      el('td', { class: 'num', text: g.confidence != null ? Number(g.confidence).toFixed(2) : '—' }),
    );
    tbody.append(tr);
  }
  table.append(thead, tbody);
  body.append(table);
}

/* ------------------------------------------------------------- harnesses */

/* option lists are built by ensureHarnessOptions / fillHarnessSelect
   in the "path + api raw helpers" section below */

/* ------------------------------------------------------------------- tree */

async function loadDir(rel) {
  const entry = state.tree.cache.get(rel);
  if (entry && (entry.children || entry.error)) return entry;
  state.tree.cache.set(rel, { loading: true });
  try {
    const data = await api('/api/tree', { path: rel });
    const e = { children: data.children || [], truncated: !!data.truncated };
    state.tree.cache.set(rel, e);
    return e;
  } catch (err) {
    const e = { error: err.message };
    state.tree.cache.set(rel, e);
    return e;
  }
}

async function initTree() {
  await loadDir('');
  renderTree();
}

function nodeActiveTotal(child) {
  const c = countsFiltered(child.counts || {});
  return countsTotal(c);
}

function sortByName(a, b) {
  if (a.is_dir !== b.is_dir) return a.is_dir ? -1 : 1;
  return a.name.localeCompare(b.name);
}

function childMatchesFilter(child) {
  const f = state.tree.filter.toLowerCase();
  if (!f) return true;
  if (child.name.toLowerCase().includes(f)) return true;
  if (child.is_dir) {
    const e = state.tree.cache.get(child.path);
    if (e && e.children) return e.children.some((c) => childMatchesFilter(c));
  }
  return false;
}

function renderTree() {
  const body = $('tree-body');
  body.textContent = '';
  const rootEntry = state.tree.cache.get('');
  if (!rootEntry || !rootEntry.children) {
    body.innerHTML = loadingHTML('Loading tree…');
    return;
  }
  const frag = document.createDocumentFragment();
  buildChildren(frag, rootEntry.children, 0);
  if (!frag.childNodes.length) {
    body.innerHTML = emptyHTML(state.tree.filter
      ? 'No visible nodes match the name filter.'
      : 'Workspace root is empty.');
    return;
  }
  body.append(frag);
  if (rootEntry.truncated) {
    body.append(el('div', { class: 'tree-truncated', text: 'listing truncated: directory has more than 2000 entries' }));
  }
  restoreTreeFocus();
}

function buildChildren(container, children, depth) {
  const sorted = state.tree.sort === 'problems'
    ? children.slice().sort((a, b) => (nodeActiveTotal(b) - nodeActiveTotal(a)) || a.name.localeCompare(b.name))
    : children.slice().sort(sortByName);
  for (const child of sorted) {
    if (state.tree.filter && !childMatchesFilter(child)) continue;
    container.append(buildNode(child, depth));
  }
}

function buildNode(child, depth) {
  const expanded = state.tree.expanded.has(child.path);
  const active = countsFiltered(child.counts || {});
  const total = countsTotal(active);
  const wrap = el('div', { class: 'tree-branch', 'data-path': child.path });

  const twister = child.is_dir ? (expanded ? '\u25be' : '\u25b8') : '';
  const iconTxt = child.is_dir ? 'dir' : 'file';

  const row = el('div', {
    class: 'tree-node-row' + (total > 0 ? ' has-problems' : '') +
      (total > 0 && !child.is_dir ? ' is-flagged' : '') +
      (state.tree.filter && !child.name.toLowerCase().includes(state.tree.filter.toLowerCase()) ? ' is-dimmed' : ''),
    role: 'treeitem',
    'data-path': child.path,
    'data-isdir': String(!!child.is_dir),
    tabindex: '-1',
    id: 'tn-' + (state.tree.seq++),
    'aria-expanded': child.is_dir ? String(expanded) : null,
    'aria-selected': 'false',
  });
  row.append(
    el('span', { class: 'tree-twister', 'aria-hidden': 'true', text: twister || ' ' }),
    el('span', { class: 'tree-icon', 'aria-hidden': 'true', text: iconTxt }),
  );
  const nameSpan = el('span', { class: 'tree-name', text: child.name });
  row.append(nameSpan);
  if (child.symlink) {
    row.append(el('span', { class: 'tree-symlink', title: 'symbolic link', text: 'symlink \u21aa' }));
  }
  if (total > 0) row.append(badgeRowFromCounts(child.counts));
  wrap.append(row);

  row.addEventListener('click', () => {
    setTreeFocus(row);
    if (child.is_dir) {
      toggleDir(child.path);
    } else {
      openInspector(child.path, null, { push: true });
    }
  });

  if (child.is_dir && expanded) {
    const entry = state.tree.cache.get(child.path);
    const kids = el('div', { class: 'tree-children', role: 'group' });
    if (!entry || entry.loading) {
      kids.append(el('div', { class: 'tree-truncated', text: 'loading…' }));
    } else if (entry.error) {
      const errRow = el('div', { class: 'tree-truncated' });
      errRow.append(
        el('span', { text: 'error: ' + entry.error + ' ' }),
        el('button', {
          class: 'ev-link', text: 'retry',
          onclick: async (ev2) => {
            ev2.stopPropagation();
            state.tree.cache.delete(child.path);
            await loadDir(child.path);
            renderTree();
          },
        }),
      );
      kids.append(errRow);
    } else if (!entry.children.length) {
      kids.append(el('div', { class: 'tree-truncated', text: '(empty)' }));
    } else {
      buildChildren(kids, entry.children, depth + 1);
      if (entry.truncated) {
        kids.append(el('div', { class: 'tree-truncated', text: 'listing truncated (2000+)' }));
      }
    }
    wrap.append(kids);
  }
  return wrap;
}

async function toggleDir(path) {
  state.tree.currentDir = path;
  renderSimTargetChips();
  if (state.tree.expanded.has(path)) {
    state.tree.expanded.delete(path);
    renderTree();
    return;
  }
  state.tree.expanded.add(path);
  const entry = state.tree.cache.get(path);
  if (!entry || (!entry.children && !entry.loading && !entry.error)) {
    renderTree();                       // show the loading row
    await loadDir(path);
  }
  renderTree();
}

/* tree keyboard navigation */
function visibleTreeRows() {
  return Array.from($('tree-body').querySelectorAll('.tree-node-row'));
}
function setTreeFocus(row) {
  for (const r of visibleTreeRows()) {
    r.classList.remove('node-focused');
    r.setAttribute('aria-selected', 'false');
  }
  if (row) {
    row.classList.add('node-focused');
    row.setAttribute('aria-selected', 'true');
    row.scrollIntoView({ block: 'nearest' });
    state.tree.focusedPath = row.getAttribute('data-path');
  }
}
function restoreTreeFocus() {
  if (!state.tree.focusedPath) return;
  const row = visibleTreeRows().find((r) => r.getAttribute('data-path') === state.tree.focusedPath);
  if (row) setTreeFocus(row);
}

function treeKeydown(ev) {
  const rows = visibleTreeRows();
  if (!rows.length) return;
  const key = ev.key;
  if (!['ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight', 'Enter', 'Home', 'End'].includes(key)) return;
  ev.preventDefault();
  let i = rows.findIndex((r) => r.classList.contains('node-focused'));
  if (key === 'Home') { setTreeFocus(rows[0]); return; }
  if (key === 'End') { setTreeFocus(rows[rows.length - 1]); return; }
  if (key === 'ArrowDown') { setTreeFocus(rows[Math.min(i + 1, rows.length - 1)]); return; }
  if (key === 'ArrowUp') { setTreeFocus(rows[Math.max(i - 1, 0)]); return; }
  const row = rows[i >= 0 ? i : 0];
  if (!row) return;
  const path = row.getAttribute('data-path');
  const isDir = row.getAttribute('data-isdir') === 'true';
  const expanded = state.tree.expanded.has(path);
  if (key === 'ArrowRight' && isDir && !expanded) { toggleDir(path); return; }
  if (key === 'ArrowLeft' && isDir && expanded) { toggleDir(path); return; }
  if (key === 'ArrowLeft' && (!isDir || !expanded)) {
    // jump to parent row
    const parent = dirname(path);
    const prow = rows.find((r) => r.getAttribute('data-path') === parent);
    if (prow) setTreeFocus(prow);
    return;
  }
  if (key === 'Enter') {
    if (isDir) toggleDir(path);
    else openInspector(path, null, { push: true });
  }
}

/* --------------------------------------------------------------- findings */

async function initFindings() {
  await Promise.all([ensureHarnessOptions(), loadFindings()]);
}

async function loadFindings() {
  const body = $('findings-body');
  const f = state.findings;
  body.innerHTML = loadingHTML('Loading findings…');
  try {
    const data = await api('/api/findings', { gate: f.gate, harness: f.harness, q: f.q });
    f.fetched = data.findings || [];
    f.loadedOnce = true;
    renderFindings();
  } catch (e) {
    body.textContent = '';
    body.append(errorPanel(e, loadFindings));
  }
}

function visibleFindings() {
  const f = state.findings;
  return f.fetched.filter((x) => {
    if (!state.sev.has(x.severity)) return false;
    if (!state.showPassed && x.status === 'pass') return false;
    return true;
  });
}

const FIND_COLS = [
  { key: 'severity', label: 'Severity' },
  { key: 'fid', label: 'ID' },
  { key: 'gate', label: 'Gate' },
  { key: 'harness', label: 'Harness' },
  { key: 'title', label: 'Title' },
  { key: 'status', label: 'Status' },
  { key: 'fix', label: 'Fix' },
];

function findingSorter(key, dir) {
  const mul = dir === 'asc' ? 1 : -1;
  const val = (x) => {
    switch (key) {
      case 'severity': return SEV_WEIGHT[x.severity] || 0;
      case 'fid': return x.fid || '';
      case 'gate': return x.gate || '';
      case 'harness': return x.harness || '';
      case 'title': return (x.title || '').toLowerCase();
      case 'status': return STATUS_RANK[x.status] != null ? STATUS_RANK[x.status] : 9;
      case 'fix': return x.autofix_available ? 1 : 0;
      default: return 0;
    }
  };
  return (a, b) => {
    const va = val(a), vb = val(b);
    if (typeof va === 'string' || typeof vb === 'string') {
      return String(va).localeCompare(String(vb)) * mul;
    }
    return (va - vb) * mul;
  };
}

function renderFindings() {
  const body = $('findings-body');
  const f = state.findings;
  body.textContent = '';
  const rows = visibleFindings();
  const countLine = el('p', {
    class: 'findings-count',
    text: `Showing ${rows.length} of ${f.fetched.length} fetched findings.` +
      (f.q || f.gate || f.harness ? ' Server filters active (gate/harness/search).' : ''),
  });
  body.append(countLine);

  if (!rows.length) {
    body.append(el('div', {
      class: 'empty-state',
      text: !state.sev.size && !state.showPassed
        ? 'All severity chips are off — enable at least one filter chip above.'
        : 'No findings match the current filters.',
    }));
    return;
  }

  const table = el('table', { class: 'tbl', 'aria-label': 'Findings' });
  const thead = el('thead');
  const hr = el('tr');
  for (const col of FIND_COLS) {
    const th = el('th', { scope: 'col', text: col.label });
    if (col.key !== 'fix') th.classList.add('sortable');
    if (f.sortKey === col.key) th.setAttribute('aria-sort', f.sortDir === 'asc' ? 'ascending' : 'descending');
    if (col.key !== 'fix') {
      th.addEventListener('click', () => {
        if (f.sortKey === col.key) f.sortDir = f.sortDir === 'asc' ? 'desc' : 'asc';
        else { f.sortKey = col.key; f.sortDir = col.key === 'severity' ? 'desc' : 'asc'; }
        renderFindings();
      });
    }
    hr.append(th);
  }
  thead.append(hr);
  table.append(thead);
  const tbody = el('tbody');
  const sorted = rows.slice().sort(findingSorter(f.sortKey, f.sortDir));

  const rowEl = (x) => {
    const tr = el('tr', {
      class: 'fnd-row row-click', 'data-fid': x.fid, 'data-severity': x.severity,
      tabindex: '-1',
      title: 'Open finding details (Enter)',
    });
    tr.append(
      el('td', {}, sevBadge(x.severity)),
      el('td', { class: 'mono', text: x.fid }),
      el('td', { class: 'mono', text: x.gate || '—' }),
      el('td', { class: 'mono', text: x.harness || '—' }),
      el('td', { text: x.title || '' }),
      el('td', {}, statusBadge(x.status)),
      el('td', {},
        x.autofix_available
          ? el('span', { class: 'autofix-yes', title: 'automatic fix available', text: 'auto \u2713' })
          : el('span', { class: 'autofix-no', title: 'no automatic fix', text: '\u2014' })),
    );
    const open = () => openFindingCard(x.fid, { push: true });
    tr.addEventListener('click', open);
    tr.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') { ev.preventDefault(); open(); } });
    return tr;
  };

  if (f.group) {
    const groups = new Map();
    for (const x of sorted) {
      const evFile = (x.evidence && x.evidence[0] && x.evidence[0].file) || '';
      const key = evFile ? dirname(String(evFile).replace(/\\/g, '/')) || '/' : '(no file evidence)';
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(x);
    }
    for (const key of Array.from(groups.keys()).sort()) {
      const gh = el('tr', { class: 'group-header-row' });
      const td = el('td', { colspan: String(FIND_COLS.length) });
      td.append(el('div', { class: 'group-header' }, el('span', { text: key }), el('span', { class: 'group-count', text: '  — ' + groups.get(key).length + ' finding(s)' })));
      gh.append(td);
      tbody.append(gh);
      for (const x of groups.get(key)) tbody.append(rowEl(x));
    }
  } else {
    for (const x of sorted) tbody.append(rowEl(x));
  }
  table.append(tbody);
  body.append(table);

  bindTableArrowNav(table);
}

function bindTableArrowNav(table) {
  table.setAttribute('tabindex', '0');
  table.addEventListener('keydown', (ev) => {
    if (!['ArrowUp', 'ArrowDown'].includes(ev.key)) return;
    const rows = Array.from(table.querySelectorAll('tr.fnd-row'));
    if (!rows.length) return;
    ev.preventDefault();
    let i = rows.findIndex((r) => r === document.activeElement);
    if (i === -1) { rows[0].focus(); return; }
    const next = ev.key === 'ArrowDown' ? Math.min(i + 1, rows.length - 1) : Math.max(i - 1, 0);
    rows[next].focus();
  });
}

/* ----------------------------------------------------------- finding card */

async function openFindingCard(fid, opts = {}) {
  const push = opts.push !== false;
  const overlay = $('card-overlay');
  const bodyEl = $('card-body');
  overlay.hidden = false;
  $('card-fid').textContent = fid;
  $('card-badges').textContent = '';
  bodyEl.innerHTML = loadingHTML('Loading finding…');
  try {
    const x = await api('/api/finding/' + encodeURIComponent(fid));
    renderFindingCard(x);
    if (push) pushNav({ type: 'finding', fid });
  } catch (e) {
    bodyEl.textContent = '';
    bodyEl.append(errorPanel(e, () => openFindingCard(fid, { push: false })));
  }
}

function closeFindingCard() {
  $('card-overlay').hidden = true;
}

function renderFindingCard(x) {
  const badges = $('card-badges');
  badges.textContent = '';
  badges.append(sevBadge(x.severity), statusBadge(x.status));
  badges.append(el('span', { class: 'conf-note', text: 'conf ' + Number(x.confidence != null ? x.confidence : 0).toFixed(2) }));

  const body = $('card-body');
  body.textContent = '';

  body.append(el('h3', { text: 'What' }));
  body.append(el('p', { class: 'card-desc', text: x.title || '—' }));

  body.append(el('h3', { text: 'Why' }));
  body.append(el('p', { class: 'card-desc', text: x.description || '—' }));

  body.append(el('h3', { text: 'Where' }));
  if (x.evidence && x.evidence.length) {
    for (const ev of x.evidence) {
      const item = el('div', { class: 'ev-item' });
      if (ev.file) {
        const label = ev.line != null ? `${ev.file}:${ev.line}` : String(ev.file);
        item.append(el('button', {
          class: 'ev-link', text: label,
          title: 'Open in File Inspector',
          onclick: () => {
            closeFindingCard();
            openInspector(String(ev.file).replace(/\\/g, '/'), ev.line != null ? Number(ev.line) : null, { push: true });
          },
        }));
      } else {
        item.append(el('span', { class: 'mono', text: '(no file)' }));
      }
      if (ev.detail) item.append(el('div', { class: 'ev-detail', text: String(ev.detail) }));
      body.append(item);
    }
  } else {
    body.append(el('p', { class: 'card-desc', text: 'No evidence recorded.' }));
  }

  body.append(el('h3', { text: 'Recommendation' }));
  body.append(el('div', { class: 'recommendation', text: x.recommendation || 'No recommendation recorded.' }));

  body.append(el('h3', { text: 'Autofix' }));
  const fixArea = el('div', { class: 'fixplan' });
  fixArea.append(el('button', {
    class: 'btn-accent', text: 'Fix plan',
    onclick: () => loadFixPlan(x.fid),
  }));
  fixArea.append(el('span', {
    class: 'conf-note',
    text: x.autofix_available
      ? '  autofix available — the plan is a dry run, nothing is changed'
      : '  autofix flag is off; the plan may report "not supported"',
  }));
  body.append(fixArea);
  const planBox = el('div', { id: 'fix-plan-box' });
  body.append(planBox);

  body.append(el('h3', { text: 'Evidence JSON' }));
  const det = el('details', { class: 'ev-json' });
  det.append(el('summary', { text: 'show raw evidence' }));
  det.append(el('pre', { text: JSON.stringify(x.evidence, null, 2) }));
  body.append(det);
}

async function loadFixPlan(fid) {
  const box = $('fix-plan-box');
  if (!box) return;
  box.innerHTML = loadingHTML('Planning fix (dry run)…');
  let data;
  try {
    data = await api('/api/fixplan', { fid });
  } catch (e) {
    box.textContent = '';
    box.append(el('div', { class: 'recommendation', text: 'Fix plan failed: ' + e.message }));
    return;
  }
  box.textContent = '';
  if (!data.supported) {
    box.append(el('div', { class: 'recommendation', text: 'No supported automatic fix for ' + fid + '.' }));
    return;
  }
  const head = el('div', {});
  head.append(el('strong', { text: 'Planned steps' }));
  head.append(el('span', { class: 'dryrun-badge', text: 'DRY RUN' }));
  box.append(head);
  const ol = el('ol', { class: 'fix-steps' });
  for (const s of data.steps || []) {
    const li = el('li', {});
    li.append(el('span', { class: 'fix-step-action', text: '[' + (s.action || '?') + ']' }));
    li.append(document.createTextNode(' ' + (s.target || '') + (s.detail ? ' — ' + s.detail : '')));
    ol.append(li);
  }
  if (!ol.childNodes.length) ol.append(el('li', { text: '(empty plan)' }));
  box.append(ol);
  box.append(el('div', {
    class: 'conf-note',
    text: 'The UI never applies fixes. To execute after review, run in the CLI:',
  }));
  box.append(el('code', { class: 'fix-cmd', text: `python agents_doctor.py fix scan.json ${fid} --apply` }));
}

/* ---------------------------------------------------------- file inspector */

async function openInspector(path, line, opts = {}) {
  const push = opts.push !== false;
  state.inspector.path = path;
  state.inspector.line = line || null;
  const panel = $('inspector');
  panel.hidden = false;
  $('insp-path').textContent = path;
  $('insp-badges').textContent = '';
  $('insp-banner').textContent = '';
  const code = $('insp-code');
  code.textContent = '';
  code.append(el('div', { class: 'loading', html: loadingHTML('Loading file…') }));
  if (push) pushNav({ type: 'file', path, line: line || null });
  let data;
  try {
    data = await api('/api/file', { path });
  } catch (e) {
    code.textContent = '';
    code.append(el('div', { class: 'binary-note', text: 'Cannot open file: ' + e.message }));
    return;
  }
  if (state.inspector.path !== path) return;  // user moved on meanwhile
  renderInspector(data, path, line);
}

function renderInspector(data, path, line) {
  const banner = $('insp-banner');
  banner.textContent = '';
  if (data.truncated) {
    banner.append(el('div', { class: 'banner', html: '<b>truncated</b> — preview capped at 256 KB; open the file for full content' }));
  }
  const badges = $('insp-badges');
  badges.textContent = '';
  const br = badgeRowFromCounts(data.counts || {});
  if (br.childNodes.length) badges.append(br);
  else badges.append(el('span', { class: 'conf-note', text: 'no findings attached to this file' }));

  const code = $('insp-code');
  code.textContent = '';
  if (data.binary) {
    code.append(el('div', { class: 'binary-note', text: 'binary file — no text preview' }));
    return;
  }
  const flagged = new Map();
  for (const fl of data.flagged_lines || []) flagged.set(fl.line, fl);
  const frag = document.createDocumentFragment();
  const lines = data.lines && data.lines.length ? data.lines : [''];
  lines.forEach((text, i) => {
    const n = i + 1;
    const fl = flagged.get(n);
    const rowLine = el('div', {
      class: 'code-line' + (fl ? ' flagged' : '') + (line === n ? ' hl' : ''),
      id: 'L' + n,
    });
    rowLine.append(el('span', { class: 'code-ln', text: String(n) }));
    rowLine.append(el('span', { class: 'code-txt', text: text.length ? text : ' ' }));
    if (fl) {
      rowLine.append(el('span', {
        class: 'code-flag-label',
        title: 'secret rule ' + fl.rule + ' — value masked',
        text: fl.rule,
      }));
    }
    frag.append(rowLine);
  });
  code.append(frag);
  if (line != null) {
    const target = $('L' + line);
    if (target) target.scrollIntoView({ block: 'center' });
  } else {
    code.scrollTop = 0;
  }
}

function closeInspector() {
  $('inspector').hidden = true;
  state.inspector.path = null;
}

/* ---------------------------------------------------------------- history */

function pushNav(entry) {
  const h = state.history;
  h.stack = h.stack.slice(0, h.idx + 1);
  const top = h.stack[h.idx];
  if (top && top.type === entry.type &&
      top.type === 'file' && top.path === entry.path && top.line === entry.line) {
    updateHistoryButtons();
    return;  // same destination, no duplicate
  }
  if (top && top.type === entry.type && top.type === 'finding' && top.fid === entry.fid) {
    updateHistoryButtons();
    return;
  }
  h.stack.push(entry);
  if (h.stack.length > 100) h.stack.shift();
  h.idx = h.stack.length - 1;
  updateHistoryButtons();
}

function applyNav(entry) {
  if (entry.type === 'file') openInspector(entry.path, entry.line, { push: false });
  else if (entry.type === 'finding') openFindingCard(entry.fid, { push: false });
}

function historyGo(delta) {
  const h = state.history;
  const next = h.idx + delta;
  if (next < 0 || next >= h.stack.length) return;
  h.idx = next;
  applyNav(h.stack[h.idx]);
  updateHistoryButtons();
}

function updateHistoryButtons() {
  const h = state.history;
  $('btn-back').disabled = h.idx <= 0;
  $('btn-fwd').disabled = h.idx >= h.stack.length - 1;
}

/* ---------------------------------------------------------------- treemap */

async function initTreemap() {
  await loadTreemapLevels('');
  renderTreemap();
}

async function loadTreemapLevels(rootRel) {
  const entry = await loadDir(rootRel);
  if (entry.error) return { error: entry.error };
  const top = (entry.children || []).map((c) => ({ ...c }));
  const dirs = top.filter((c) => c.is_dir);
  await Promise.all(dirs.map(async (d) => {
    const sub = await loadDir(d.path);
    d.children = sub.error ? [] : (sub.children || []).map((c) => ({ ...c }));
  }));
  state.treemap.nodes.set(rootRel, top);
  return top;
}

async function treemapEnsure() {
  const zoom = state.treemap.zoom;
  if (!state.treemap.nodes.has(zoom)) {
    await loadTreemapLevels(zoom);
  }
  return state.treemap.nodes.get(zoom) || [];
}

function metricValue(node) {
  if (state.treemap.metric === 'disk') return diskValue(node);
  const c = countsFiltered(node.counts || {});
  return state.treemap.metric === 'risk' ? countsRisk(c) : countsTotal(c);
}

function diskValue(node) {
  if (!node.is_dir) return Number(node.size) || 0;
  return (node.children || []).reduce((sum, c) => sum + diskValue(c), 0);
}

function humanSize(bytes) {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let v = bytes, i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return (v >= 100 ? Math.round(v) : v.toFixed(1)) + ' ' + units[i];
}

function metricLabel(v) {
  return state.treemap.metric === 'disk' ? humanSize(v) : String(v);
}

function dominantSeverity(counts) {
  const c = countsFiltered(counts);
  let best = null, bestN = 0;
  for (const s of SEVERITIES) {
    if ((c[s] || 0) > bestN) { best = s; bestN = c[s]; }
  }
  return best;
}

/* squarified treemap (Bruls, Huizing & van Wijk) */
function squarifyLayout(items, x, y, w, h) {
  const rects = [];
  const sorted = items.filter((it) => it.value > 0).sort((a, b) => b.value - a.value);
  if (!sorted.length || w <= 0 || h <= 0) return rects;
  const total = sorted.reduce((s, it) => s + it.value, 0);
  const scale = (w * h) / total;
  let cx = x, cy = y, cw = w, ch = h;
  let queue = sorted.map((it) => ({ ...it, value: it.value * scale }));

  const worst = (row, side) => {
    const sum = row.reduce((s, it) => s + it.value, 0);
    const max = row[0].value, min = row[row.length - 1].value;
    const s2 = sum * sum, l2 = side * side;
    return Math.max((l2 * max) / s2, s2 / (l2 * min));
  };

  while (queue.length) {
    const side = Math.min(cw, ch);
    if (side <= 0) break;
    const row = [queue.shift()];
    while (queue.length && worst(row.concat(queue[0]), side) <= worst(row, side)) {
      row.push(queue.shift());
    }
    const sum = row.reduce((s, it) => s + it.value, 0);
    if (cw >= ch) {
      const colW = sum / ch;
      let off = 0;
      for (const it of row) {
        const hh = it.value / colW;
        rects.push({ ...it, x: cx, y: cy + off, w: colW, h: hh });
        off += hh;
      }
      cx += colW; cw -= colW;
    } else {
      const rowH = sum / cw;
      let off = 0;
      for (const it of row) {
        const ww = it.value / rowH;
        rects.push({ ...it, x: cx + off, y: cy, w: ww, h: rowH });
        off += ww;
      }
      cy += rowH; ch -= rowH;
    }
  }
  return rects;
}

const TM_TOP = [34, 38, 47];    // low value bg
const TM_HOT = [122, 96, 66];   // high value bg (warm tint, readable with dark text? keep light text)
function cellBackground(v, max) {
  const t = max > 0 ? Math.min(1, v / max) : 0;
  const c = TM_TOP.map((a, i) => Math.round(a + (TM_HOT[i] - a) * t));
  return `rgb(${c[0]},${c[1]},${c[2]})`;
}

function renderTreemap() {
  const body = $('treemap-body');
  const zoom = state.treemap.zoom;
  renderTreemapCrumbs();
  const nodes = state.treemap.nodes.get(zoom);
  if (!nodes) {
    body.innerHTML = loadingHTML('Loading tree for treemap…');
    return;
  }

  const W = body.clientWidth || 800;
  const H = body.clientHeight || 500;
  const items = nodes
    .map((n) => ({ node: n, value: metricValue(n) }))
    .filter((it) => it.value > 0);
  const total = items.reduce((s, it) => s + it.value, 0);

  body.textContent = '';
  if (!total) {
    body.innerHTML = emptyHTML(state.treemap.metric === 'disk'
      ? 'Nothing to draw: no file sizes available for the fetched tree levels.'
      : 'Nothing to draw: no problems match the current severity filter (metric ' +
        state.treemap.metric + ').');
    return;
  }
  const max = Math.max(...items.map((it) => it.value));
  const root = el('div', { class: 'treemap-root', role: 'group', 'aria-label': 'Treemap of ' + (zoom || 'workspace root') });
  root.style.height = H + 'px';
  const rects = squarifyLayout(items, 0, 0, W, H);
  for (const r of rects) root.append(renderTreemapCell(r, max, 0));
  body.append(root);
  applyTreemapSelection(root);
}

/* Re-apply the persisted selection after a re-render (zoom, metric or
   filter change). The selected node may be off-screen (e.g. it is the
   directory we just zoomed into) — then nothing lights up, which is fine. */
function applyTreemapSelection(root) {
  if (!state.treemap.selected) return;
  const cell = root.querySelector('.tm-cell[data-path="' + CSS.escape(state.treemap.selected) + '"]');
  if (cell) cell.classList.add('selected');
}

function renderTreemapCell(r, max, depth) {
  const n = r.node;
  const isDir = !!n.is_dir;
  const cell = el('div', {
    class: 'tm-cell' + (isDir ? ' tm-zoomable' : ''),
    tabindex: '0',
    role: 'button',
    'data-path': n.path,
    'data-isdir': String(isDir),
    'aria-label': tmTooltipText(n, r.value),
  });
  cell.style.left = r.x + 'px';
  cell.style.top = r.y + 'px';
  cell.style.width = r.w + 'px';
  cell.style.height = r.h + 'px';
  cell.style.background = cellBackground(r.value, max);

  const dom = dominantSeverity(n.counts || {});
  if (r.w > 34 && r.h > 16) {
    cell.append(el('span', { class: 'tm-label', text: n.name + (depth === 0 && isDir ? '/' : '') }));
  }
  if (dom && r.w > 26 && r.h > 14) {
    cell.append(el('span', {
      class: 'tm-sev-corner tb-' + dom,
      text: SEV_LETTER[dom],
      title: 'dominant severity: ' + dom,
      'aria-hidden': 'true',
    }));
  }

  // nested second level inside large directory cells
  if (isDir && n.children && r.w >= 70 && r.h >= 48) {
    const labelH = 15;
    const subItems = n.children
      .map((c) => ({ node: c, value: metricValue(c) }))
      .filter((it) => it.value > 0);
    if (subItems.length) {
      const subMax = Math.max(...subItems.map((it) => it.value));
      const sub = el('div', { class: 'tm-sub' });
      sub.style.top = labelH + 'px';
      const subRects = squarifyLayout(subItems, 0, 0, r.w - 2, r.h - labelH - 2);
      for (const sr of subRects) sub.append(renderTreemapCell(sr, subMax, depth + 1));
      cell.append(sub);
    }
  }

  attachTreemapTooltip(cell, n);
  return cell;
}

/* Tooltip only (hover + keyboard focus). Activation handlers live on
   #treemap-body as delegated listeners — see onTreemapClick & co. */
function attachTreemapTooltip(cell, n) {
  const tip = $('treemap-tooltip');
  const show = (evx) => {
    tip.textContent = tmTooltipText(n, metricValue(n));
    tip.hidden = false;
    const pad = 14;
    let tx = evx.clientX + pad, ty = evx.clientY + pad;
    const r = tip.getBoundingClientRect();
    if (tx + r.width > window.innerWidth - 8) tx = evx.clientX - r.width - pad;
    if (ty + r.height > window.innerHeight - 8) ty = evx.clientY - r.height - pad;
    tip.style.left = tx + 'px';
    tip.style.top = ty + 'px';
  };
  cell.addEventListener('mousemove', show);
  cell.addEventListener('mouseenter', show);
  cell.addEventListener('mouseleave', () => { tip.hidden = true; });
  cell.addEventListener('focus', () => {
    const r = cell.getBoundingClientRect();
    tip.textContent = tmTooltipText(n, metricValue(n));
    tip.hidden = false;
    tip.style.left = Math.min(r.right + 8, window.innerWidth - 320) + 'px';
    tip.style.top = (r.top + 8) + 'px';
  });
  cell.addEventListener('blur', () => { tip.hidden = true; });
}

/* Pure decision tables for cell activation. DOM-free on purpose: the node
   smoke test requires app.js and exercises these directly (see bottom of
   file). Delegated handlers below must go through them so there is exactly
   one place that decides what an interaction means.
   detail is MouseEvent.detail: 1 = single click, 2+ = double click,
   0 = keyboard-synthesized click (treated as single). */
function resolveTreemapClick(detail, isDir) {
  if (detail >= 2) return isDir ? 'zoom' : 'none';
  return isDir ? 'select' : 'select-inspect';
}

function resolveTreemapKey(key, isDir) {
  if (key === 'Enter' || key === ' ') return isDir ? 'zoom' : 'inspect';
  if (key === 'Backspace') return 'up';
  return null;
}

function treemapCellFromEvent(ev) {
  // innermost .tm-cell: nested sub-cells must win over their parent cell
  return ev.target && ev.target.closest ? ev.target.closest('.tm-cell') : null;
}

function selectTreemapCell(cell) {
  state.treemap.selected = cell.getAttribute('data-path');
  for (const c of $('treemap-body').querySelectorAll('.tm-cell.selected')) {
    c.classList.remove('selected');
  }
  cell.classList.add('selected');
}

/* Single vs double click is told apart via MouseEvent.detail, not a
   setTimeout(250) dance: the first click of a double click simply selects
   the cell (same as OS file managers, harmless), and detail >= 2 makes the
   click handler stand back so the dblclick handler can zoom. A timeout
   would delay every selection by 250 ms and need cancel bookkeeping on
   every re-render, which rebuilds all cells. */
function onTreemapClick(ev) {
  const cell = treemapCellFromEvent(ev);
  if (!cell) return;
  const isDir = cell.getAttribute('data-isdir') === 'true';
  const act = resolveTreemapClick(ev.detail || 1, isDir);
  if (act === 'select' || act === 'select-inspect') selectTreemapCell(cell);
  if (act === 'select-inspect') {
    openInspector(cell.getAttribute('data-path'), null, { push: true });
  }
}

function onTreemapDblclick(ev) {
  const cell = treemapCellFromEvent(ev);
  if (!cell) return;
  ev.preventDefault();   // no double-click text selection on labels
  const isDir = cell.getAttribute('data-isdir') === 'true';
  if (resolveTreemapClick(2, isDir) !== 'zoom') return;
  selectTreemapCell(cell);
  zoomTreemap(cell.getAttribute('data-path'));
}

/* Container-level keyboard: Enter/Space activate the focused cell,
   Backspace zooms out one level (no-op at root). Escape for the tooltip
   is handled in globalKeydown together with card/inspector closing. */
function onTreemapKeydown(ev) {
  // zooming re-renders every cell, which drops focus to the panel:
  // Backspace-up must still work from anywhere inside the treemap,
  // not only while a cell happens to hold focus
  const inTreemap = ev.target && ev.target.closest
    && ev.target.closest('#treemap-body') !== null;
  if (!inTreemap) return;
  if (ev.key === 'Backspace') {
    ev.preventDefault();
    treemapZoomOut();
    return;
  }
  const cell = treemapCellFromEvent(ev);
  if (!cell) return;
  const isDir = cell.getAttribute('data-isdir') === 'true';
  const act = resolveTreemapKey(ev.key, isDir);
  if (!act) return;
  ev.preventDefault();
  if (act === 'up') { treemapZoomOut(); return; }
  selectTreemapCell(cell);
  if (act === 'zoom') zoomTreemap(cell.getAttribute('data-path'));
  else openInspector(cell.getAttribute('data-path'), null, { push: true });
}

function tmTooltipText(n, value) {
  const c = countsFiltered(n.counts || {});
  const lines = [n.path + (n.is_dir ? '/' : '')];
  for (const s of SEVERITIES) {
    if (state.sev.has(s)) lines.push(`${s}: ${c[s] || 0}`);
  }
  if (state.treemap.metric === 'disk') {
    lines.push(`disk: ${humanSize(value)}` + (n.is_dir ? ' (partial: fetched levels only)' : ''));
    if (n.size != null) lines.push(`file size: ${humanSize(n.size)}`);
  } else {
    lines.push(`${state.treemap.metric}: ${value}`);
  }
  if (!n.is_dir && n.symlink) lines.push('symlink');
  return lines.join('\n');
}

async function zoomTreemap(rel) {
  state.treemap.zoom = rel;
  await treemapEnsure();
  renderTreemap();
  treemapRefocus();
}

function treemapZoomOut() {
  if (!state.treemap.zoom) return false;
  const segs = state.treemap.zoom.split('/').filter(Boolean);
  segs.pop();
  state.treemap.zoom = segs.join('/');
  treemapEnsure().then(renderTreemap);
  return true;
}

/* Re-rendering replaces every cell, so the focused cell node dies and
   focus falls back to <body> — after that, keyboard navigation is dead.
   Park focus on the container (tabindex=-1) after each zoom re-render;
   Backspace-up works from anywhere inside the treemap anyway. */
function treemapRefocus() {
  const active = document.activeElement;
  if (active && active.closest && active.closest('#treemap-body')) return;
  const body = $('treemap-body');
  if (body) body.focus({ preventScroll: true });
}

function renderTreemapCrumbs() {
  const nav = $('treemap-crumbs');
  nav.textContent = '';
  const zoom = state.treemap.zoom;
  const mk = (label, target, current) => {
    if (current) nav.append(el('span', { class: 'crumb-current', text: label }));
    else nav.append(el('button', {
      class: 'crumb-btn', text: label, 'data-path': target,
      'aria-label': 'Zoom to ' + (label || 'root'),
      onclick: () => zoomTreemap(target),
    }));
  };
  mk('root', '', !zoom);
  if (zoom) {
    const segs = zoom.split('/').filter(Boolean);
    segs.forEach((seg, i) => {
      nav.append(el('span', { class: 'crumb-sep', text: '/' , 'aria-hidden': 'true' }));
      mk(seg, segs.slice(0, i + 1).join('/'), i === segs.length - 1);
    });
  }
}

/* ------------------------------------------------- path + api raw helpers */

async function apiRaw(path, params = {}) {
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== null && v !== undefined && v !== '') qs.set(k, v);
  }
  const url = path + (qs.toString() ? '?' + qs.toString() : '');
  const resp = await fetch(url);
  if (!resp.ok) throw new Error(resp.status + ' ' + resp.statusText);
  return resp.json();
}

function rootPrefix() {
  const r = state.overview && state.overview.root ? String(state.overview.root) : null;
  return r ? r.replace(/\\/g, '/').replace(/\/+$/, '') : null;
}

/** Relative workspace path for p (abs or rel); null when outside root. */
function toRelPath(p) {
  let s = String(p).replace(/\\/g, '/').replace(/\/+$/, '');
  const root = rootPrefix();
  if (root) {
    if (s === root) return '';
    if (s.startsWith(root + '/')) return s.slice(root.length + 1);
  }
  if (/^[a-zA-Z]:\//.test(s) || s.startsWith('/')) return null;  // abs, outside root
  return s.replace(/^\/+/, '');                                   // already relative
}

function fileNameOf(p) {
  const parts = String(p).replace(/\\/g, '/').split('/');
  return parts[parts.length - 1] || p;
}

/** Clickable path: button → File Inspector when inside root, plain span otherwise. */
function pathLink(p, line, labelText) {
  const rel = toRelPath(p);
  const text = labelText != null ? labelText : String(p);
  if (rel === null) {
    return el('span', {
      class: 'mono outside-root',
      title: 'outside workspace root — no preview available',
      text: text,
    });
  }
  return el('button', {
    class: 'ev-link',
    text: text,
    title: rel + (line != null ? ':' + line : '') + ' — open in File Inspector',
    onclick: () => openInspector(rel, line != null ? Number(line) : null, { push: true }),
  });
}

/* --------------------------------------------------------------- simulate */

async function ensureHarnessOptions() {
  if (state.harnesses) return;
  try {
    state.harnesses = await api('/api/harnesses');
  } catch {
    state.harnesses = { detected: [], spec_matrix: [] };
  }
  const sel = $('fnd-harness');
  sel.textContent = '';
  sel.append(el('option', { value: '', text: 'all harnesses' }));
  for (const h of state.harnesses.spec_matrix || []) {
    sel.append(el('option', {
      value: h.harness_id,
      text: h.display_name ? `${h.display_name} (${h.harness_id})` : h.harness_id,
    }));
  }
}

function fillHarnessSelect(selectEl, allLabel) {
  selectEl.textContent = '';
  selectEl.append(el('option', { value: '', text: allLabel }));
  for (const h of (state.harnesses && state.harnesses.spec_matrix) || []) {
    selectEl.append(el('option', {
      value: h.harness_id,
      text: h.display_name ? `${h.display_name} (${h.harness_id})` : h.harness_id,
    }));
  }
}

async function initSimulate() {
  await ensureHarnessOptions();
  fillHarnessSelect($('sim-harness'), 'all harnesses');
  renderSimTargetChips();
}

function renderSimTargetChips() {
  const box = $('sim-target-chips');
  box.textContent = '';
  const mk = (label, value) => box.append(el('button', {
    class: 'chip', 'aria-pressed': 'false',
    title: 'Use ' + (value === '' ? 'workspace root' : value) + ' as target',
    text: label,
    onclick: () => { $('sim-target').value = value; },
  }));
  mk('root', '');
  if (state.tree.currentDir) {
    mk('tree: ' + state.tree.currentDir, state.tree.currentDir);
  }
}

async function runSimulate() {
  const body = $('simulate-body');
  const harness = $('sim-harness').value;
  const target = $('sim-target').value.trim().replace(/\\/g, '/').replace(/^\/+/, '');
  state.simulate.harness = harness;
  body.innerHTML = loadingHTML('Simulating instruction loading…');
  try {
    const data = await api('/api/simulate', { target, harness });
    state.simulate.result = data;
    renderSimulate(data);
  } catch (e) {
    body.textContent = '';
    body.append(errorPanel(e, runSimulate));
  }
}

const KIND_CLASS = { contradiction: 'tb-critical', divergence: 'tb-high', duplication: 'tb-low' };

function renderSimulate(data) {
  const body = $('simulate-body');
  body.textContent = '';

  if (data.approximated) {
    body.append(el('div', {
      class: 'banner sim-banner',
      html: '<b>model, not runtime-verified</b> — ' + esc(data.note || 'chains follow documented loading models'),
    }));
  }

  const summ = data.conflict_summary || {};
  body.append(el('p', {
    class: 'conf-note',
    text: `Target: ${data.target_dir || '?'}   ·   loaded sources: ${data.loaded_sources_total != null ? data.loaded_sources_total : '?'}   ·   ` +
      `conflicts: contradiction ${summ.contradiction || 0}, divergence ${summ.divergence || 0}, duplication ${summ.duplication || 0}`,
  }));

  const chains = data.harnesses || {};
  for (const hid of Object.keys(chains)) {
    const chain = chains[hid];
    const block = el('div', { class: 'sim-harness-block' });
    block.append(el('div', { class: 'ov-section-title', text: hid }));
    if (!chain.supported) {
      block.append(el('p', { class: 'conf-note', text: 'not modelled: ' + (chain.reason || 'adapter does not model instruction loading') }));
      body.append(block);
      continue;
    }
    const list = (title, items, renderRow) => {
      if (!items || !items.length) return;
      block.append(el('h4', { class: 'sim-sub-title', text: `${title} (${items.length})` }));
      const ul = el('ul', { class: 'sim-list' });
      for (const item of items) ul.append(el('li', {}, renderRow(item)));
      block.append(ul);
    };
    list('Loaded', chain.loaded, (l) => {
      const row = el('span', { class: 'pathline' });
      row.append(pathLink(l.path));
      row.append(el('span', {
        class: 'mono subtle',
        text: `  [${l.scope}] prec ${l.precedence != null ? l.precedence : '?'}` + (l.reason ? ' — ' + l.reason : ''),
      }));
      return row;
    });
    list('Overridden / unused', chain.overridden, (l) => {
      const row = el('span', { class: 'pathline' });
      row.append(pathLink(l.path));
      row.append(el('span', { class: 'mono subtle', text: '  ' + (l.reason || '') }));
      return row;
    });
    list('Unloaded', chain.unloaded, (l) => {
      const row = el('span', { class: 'pathline' });
      row.append(pathLink(l.path));
      row.append(el('span', { class: 'mono subtle', text: '  ' + (l.reason || '') }));
      return row;
    });
    body.append(block);
  }

  const conflicts = data.conflicts || [];
  if (conflicts.length) {
    body.append(el('div', { class: 'ov-section-title', text: `Conflicts (${conflicts.length})` }));
    for (const c of conflicts) {
      const item = el('div', { class: 'conflict-item' });
      item.append(el('span', {
        class: 'tree-badge ' + (KIND_CLASS[c.kind] || 'tb-info'),
        text: c.kind,
        title: 'conflict kind: ' + c.kind,
      }));
      item.append(document.createTextNode(' '));
      item.append(pathLink(c.file_a, c.line_a, `${c.file_a}:${c.line_a}`));
      item.append(el('span', { class: 'mono subtle', text: '  ' + (c.text_a || '').slice(0, 120) }));
      item.append(el('span', { class: 'mono subtle', text: '  \u2194  ' }));
      item.append(pathLink(c.file_b, c.line_b, `${c.file_b}:${c.line_b}`));
      item.append(el('span', { class: 'mono subtle', text: '  ' + (c.text_b || c.preview || '').slice(0, 120) }));
      if (c.topic) item.append(el('div', { class: 'ev-detail', text: 'topic: ' + c.topic }));
      body.append(item);
    }
  }
}

/* ----------------------------------------------------------- instructions */

const SCOPE_ORDER = ['global', 'user', 'project', 'nested', 'path_scoped', 'imported'];

async function initInstructions() {
  await ensureHarnessOptions();
  const body = $('instructions-body');
  body.innerHTML = loadingHTML('Simulating instruction loading at workspace root…');
  try {
    const data = await api('/api/simulate', {});
    state.instructions = data;
    renderInstructionsTable(data);
    const sel = $('ins-harness');
    sel.textContent = '';
    const chains = data.harnesses || {};
    const supported = Object.keys(chains).filter((k) => chains[k].supported);
    if (!supported.length) sel.append(el('option', { value: '', text: '(no modelled harness)' }));
    for (const hid of supported) sel.append(el('option', { value: hid, text: hid }));
    renderInstructionsDiagram();
  } catch (e) {
    body.textContent = '';
    body.append(errorPanel(e, initInstructions));
  }
}

function renderInstructionsTable(data) {
  const body = $('instructions-body');
  body.textContent = '';

  if (data.approximated) {
    body.append(el('div', {
      class: 'banner sim-banner',
      html: '<b>model, not runtime-verified</b> — sources resolved from documented loading models, not a live runtime',
    }));
  }

  const rows = [];
  for (const [hid, chain] of Object.entries(data.harnesses || {})) {
    if (!chain.supported) continue;
    for (const l of chain.loaded || []) {
      rows.push({ harness: hid, scope: l.scope || '?', prec: l.precedence, path: l.path, status: 'loaded', reason: l.reason || '' });
    }
    for (const l of chain.overridden || []) {
      rows.push({ harness: hid, scope: '', prec: l.precedence, path: l.path, status: 'overridden', reason: l.reason || '' });
    }
    for (const l of chain.unloaded || []) {
      rows.push({ harness: hid, scope: '', prec: null, path: l.path, status: 'unloaded', reason: l.reason || '' });
    }
  }

  if (!rows.length) {
    body.append(el('div', { class: 'empty-state', text: 'No instruction sources discovered for this workspace.' }));
    return;
  }
  body.append(el('p', { class: 'findings-count', text: `${rows.length} source entries across harnesses. Click a path to open it in the File Inspector.` }));

  const byScope = new Map();
  for (const r of rows) {
    const key = r.scope || '(unknown scope)';
    if (!byScope.has(key)) byScope.set(key, []);
    byScope.get(key).push(r);
  }
  const scopes = Array.from(byScope.keys()).sort((a, b) => {
    const ia = SCOPE_ORDER.indexOf(a), ib = SCOPE_ORDER.indexOf(b);
    if (ia !== -1 && ib !== -1) return ia - ib;
    if (ia !== -1) return -1;
    if (ib !== -1) return 1;
    return a.localeCompare(b);
  });

  const table = el('table', { class: 'tbl', 'aria-label': 'Instruction sources' });
  table.append(el('thead', {}, el('tr', {},
    el('th', { text: 'Harness' }), el('th', { text: 'Scope' }),
    el('th', { class: 'num', text: 'Prec' }), el('th', { text: 'Path' }),
    el('th', { text: 'Status' }), el('th', { text: 'Reason' }))));
  const tbody = el('tbody');
  for (const scope of scopes) {
    const gh = el('tr', {});
    const td = el('td', { colspan: '6' });
    td.append(el('div', { class: 'group-header' },
      el('span', { text: scope }),
      el('span', { class: 'group-count', text: '  — ' + byScope.get(scope).length + ' source(s)' })));
    gh.append(td);
    tbody.append(gh);
    for (const r of byScope.get(scope).sort((a, b) => (b.prec != null ? b.prec : -1) - (a.prec != null ? a.prec : -1) || a.harness.localeCompare(b.harness))) {
      const tr = el('tr', {});
      tr.append(
        el('td', { class: 'mono', text: r.harness }),
        el('td', { class: 'mono', text: r.scope || '—' }),
        el('td', { class: 'num', text: r.prec != null ? String(r.prec) : '—' }),
        el('td', {}, pathLink(r.path, null, fileNameOf(r.path))),
        el('td', {}, el('span', {
          class: 'status-badge st-' + (r.status === 'loaded' ? 'pass' : r.status === 'overridden' ? 'warn' : 'not_applicable'),
          html: `<span class="st-glyph" aria-hidden="true">${r.status === 'loaded' ? '\u2713' : r.status === 'overridden' ? '\u26a0' : '\u2014'}</span><span>${r.status}</span>`,
        })),
        el('td', { class: 'mono subtle', text: r.reason || '' }),
      );
      tbody.append(tr);
    }
  }
  table.append(tbody);
  body.append(table);

  const diagramTitle = el('div', { class: 'ov-section-title', text: 'Load chain diagram' });
  body.append(diagramTitle);
  body.append(el('div', { id: 'ins-diagram', class: 'ins-diagram' }));
}

function renderInstructionsDiagram() {
  const box = $('ins-diagram');
  if (!box || !state.instructions) return;
  const hid = $('ins-harness').value;
  const chain = hid && (state.instructions.harnesses || {})[hid];
  if (!chain || !chain.supported) {
    box.textContent = '';
    box.append(el('div', { class: 'empty-state', text: 'Select a harness above to draw its load chain.' }));
    return;
  }
  const links = (chain.loaded || []).slice()
    .sort((a, b) => (a.precedence != null ? a.precedence : 0) - (b.precedence != null ? b.precedence : 0));
  if (!links.length) {
    box.textContent = '';
    box.append(el('div', { class: 'empty-state', text: 'No loaded sources for this harness.' }));
    return;
  }
  box.textContent = '';
  box.innerHTML = chainSvg(hid, links);
  const note = el('p', {
    class: 'conf-note',
    text: `Top \u2192 bottom = increasing precedence (higher wins). ${links.length} loaded, ` +
      `${(chain.overridden || []).length} overridden, ${(chain.unloaded || []).length} unloaded.`,
  });
  box.append(note);
}

/** SVG chain diagram built as a string: one rectangle per source, arrows downward. */
function chainSvg(hid, links) {
  const INK = '#d6d9e0', BOX = '#22262f', EDGE = '#5289c7', ARROW = '#8b919d';
  const labels = links.map((l) => `${l.scope} \u2014 ${fileNameOf(l.path)} (prec ${l.precedence != null ? l.precedence : '?'})`);
  const boxW = Math.max(260, Math.min(720, ...labels.map((t) => t.length * 7.4 + 36)));
  const boxH = 34, gap = 22, pad = 12;
  const w = boxW + pad * 2;
  const h = links.length * (boxH + gap) + pad * 2;
  const cx = w / 2;
  let s = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="${w}" height="${h}" role="img" aria-label="Load chain for ${esc(hid)}: ${esc(labels.join(', '))}" class="chain-svg">`;
  s += `<title>Load chain for ${esc(hid)}</title>`;
  links.forEach((l, i) => {
    const y = pad + i * (boxH + gap);
    s += `<rect x="${cx - boxW / 2}" y="${y}" width="${boxW}" height="${boxH}" rx="5" fill="${BOX}" stroke="${EDGE}" stroke-width="1"/>`;
    s += `<text x="${cx}" y="${y + boxH / 2 + 4}" text-anchor="middle" font-family="ui-monospace,Consolas,monospace" font-size="12" fill="${INK}">${esc(labels[i])}</text>`;
    s += `<title>${esc(l.path)}</title>`;
    if (i < links.length - 1) {
      const y1 = y + boxH, y2 = y + boxH + gap;
      s += `<line x1="${cx}" y1="${y1}" x2="${cx}" y2="${y2 - 6}" stroke="${ARROW}" stroke-width="1.4"/>`;
      s += `<polygon points="${cx - 4},${y2 - 7} ${cx + 4},${y2 - 7} ${cx},${y2}" fill="${ARROW}"/>`;
    }
  });
  s += '</svg>';
  return s;
}

/* ---------------------------------------------------------------- compare */

async function initCompare() {
  const body = $('compare-body');
  body.innerHTML = loadingHTML('Loading fingerprint diff…');
  let cmp;
  try {
    cmp = await apiRaw('/api/compare');
  } catch (e) {
    body.textContent = '';
    body.append(errorPanel(e, initCompare));
    return;
  }
  if (!cmp || cmp.supported === false) {
    state.compare = null;
    renderCompareUnsupported(cmp && cmp.error);
    return;
  }
  let findings = [];
  try {
    findings = (await api('/api/findings')).findings || [];
  } catch { /* severity/fid matching simply stays empty */ }
  state.compare = cmp;
  renderCompare(cmp, findings);
}

function renderCompareUnsupported(err) {
  const body = $('compare-body');
  body.textContent = '';
  const box = el('div', { class: 'empty-state' });
  box.append(el('p', { text: 'Compare is not available: ' + (err || 'no baseline scan was given at server start.') }));
  box.append(el('p', { text: 'Restart the UI with a baseline scan to enable the diff:' }));
  box.append(el('code', { class: 'fix-cmd', text: 'python agents_doctor.py ui --scan scan.json --baseline old-scan.json' }));
  body.append(box);
}

const CMP_SECTIONS = [
  { key: 'new', label: 'NEW', hint: 'fingerprints that appeared since the baseline' },
  { key: 'resolved', label: 'RESOLVED', hint: 'baseline fingerprints no longer present' },
  { key: 'persisting', label: 'PERSISTING', hint: 'same fingerprints in both scans' },
  { key: 'changed', label: 'CHANGED', hint: 'same section+path, reshaped fingerprint (also counted as new)' },
];

function buildFindingIndex(findings) {
  const idx = new Map();
  for (const f of findings) {
    if (f.status === 'pass' || f.status === 'not_applicable') continue;
    for (const ev of f.evidence || []) {
      if (!ev.file) continue;
      const p = String(ev.file).replace(/\\/g, '/');
      const cur = idx.get(p);
      if (!cur || (SEV_WEIGHT[f.severity] || 0) > (SEV_WEIGHT[cur.severity] || 0)) idx.set(p, f);
    }
  }
  return idx;
}

function matchFinding(idx, entryPath) {
  const p = String(entryPath || '').replace(/\\/g, '/');
  if (idx.has(p)) return idx.get(p);
  const base = p.split(' | ')[0].trim();
  return base ? idx.get(base) || null : null;
}

function renderCompare(cmp, currentFindings) {
  const body = $('compare-body');
  body.textContent = '';
  const idx = buildFindingIndex(currentFindings);

  const head = el('p', { class: 'conf-note' });
  head.textContent = `baseline: ${cmp.baseline_generated_at || '?'}   ·   current: ${cmp.current_generated_at || '?'}`;
  body.append(head);

  const chips = el('div', { class: 'ov-stats' });
  for (const sec of CMP_SECTIONS) {
    const n = (cmp.summary || {})[sec.key] || 0;
    const box = el('div', { class: 'stat-box', title: sec.hint });
    box.append(el('div', { class: 'stat-key', text: sec.label }));
    box.append(el('div', { class: 'stat-val', text: String(n) }));
    chips.append(box);
  }
  body.append(chips);

  const diff = cmp.diff || {};
  for (const sec of CMP_SECTIONS) {
    const entries = diff[sec.key] || [];
    body.append(el('div', { class: 'ov-section-title', text: `${sec.label} (${entries.length}) — ${sec.hint}` }));
    if (!entries.length) {
      body.append(el('div', { class: 'empty-state', text: 'None.' }));
      continue;
    }
    const table = el('table', { class: 'tbl', 'aria-label': sec.label + ' findings' });
    table.append(el('thead', {}, el('tr', {},
      el('th', { text: 'Severity' }), el('th', { text: 'Section' }),
      el('th', { text: 'Path' }), el('th', { text: 'Current finding' }))));
    const tbody = el('tbody');
    for (const entry of entries) {
      const match = matchFinding(idx, entry.path);
      const clickable = !!(match && match.fid);
      const tr = el('tr', {
        class: clickable ? 'row-click fnd-row' : 'fnd-row',
        'data-severity': match ? match.severity : 'info',
        title: clickable ? 'Open finding ' + match.fid : 'no matching finding in the current scan',
      });
      if (clickable) tr.addEventListener('click', () => openFindingCard(match.fid, { push: true }));
      tr.append(
        el('td', {}, match ? sevBadge(match.severity) : el('span', { class: 'mono subtle', text: '—' })),
        el('td', { class: 'mono', text: entry.section || '?' }),
        el('td', { class: 'mono', text: String(entry.path || '?').replace(/\\/g, '/') }),
        el('td', { class: 'mono', text: match ? match.fid : '—' }),
      );
      tbody.append(tr);
    }
    table.append(tbody);
    body.append(table);
  }
}

/* ----------------------------------------------------------------- rescan */

async function rescan() {
  const btn = $('btn-rescan');
  btn.disabled = true;
  btn.textContent = 'Rescanning…';
  try {
    const res = await api('/api/rescan', {}, 'POST');
    // drop all caches, keep filters and UI state
    state.tree.cache.clear();
    state.tree.expanded.clear();
    state.treemap.nodes.clear();
    state.treemap.zoom = '';
    state.treemap.selected = null;
    state.simulate.result = null;
    state.instructions = null;
    state.compare = null;
    initedTabs.delete('instructions');
    initedTabs.delete('simulate');
    initedTabs.delete('compare');
    await loadOverview();
    state.harnesses = null;
    await ensureHarnessOptions();
    if (initedTabs.has('simulate') || $('sim-harness').options.length) {
      fillHarnessSelect($('sim-harness'), 'all harnesses');
    }
    toast(`Rescan finished: ${res.findings} findings. Current view reloaded.`);
    // refresh whatever the user is looking at
    if (state.tab === 'tree') initTree();
    else if (state.tab === 'treemap') initTreemap();
    else if (state.tab === 'instructions') initInstructions();
    else if (state.tab === 'findings' && state.findings.loadedOnce) loadFindings();
    else if (state.tab === 'compare') initCompare();
    else if (state.tab === 'simulate') {
      $('simulate-body').innerHTML = emptyHTML('Scan changed after rescan — press Run to simulate again.');
    }
    if (state.inspector.path) openInspector(state.inspector.path, state.inspector.line, { push: false });
  } catch (e) {
    toast('Rescan failed: ' + e.message);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Rescan';
  }
}

/* ------------------------------------------------------------- global keys */

function globalKeydown(ev) {
  if (ev.altKey && ev.key === 'ArrowLeft') { ev.preventDefault(); historyGo(-1); return; }
  if (ev.altKey && ev.key === 'ArrowRight') { ev.preventDefault(); historyGo(1); return; }
  if (ev.key === 'Escape') {
    if (!$('card-overlay').hidden) { closeFindingCard(); return; }
    if (state.tab === 'treemap' && !$('treemap-tooltip').hidden) {
      $('treemap-tooltip').hidden = true;
      return;
    }
    if (!$('inspector').hidden) { closeInspector(); return; }
    if (state.tab === 'treemap') treemapZoomOut();
  }
}

/* -------------------------------------------------------------------- boot */

function bindUI() {
  document.querySelectorAll('.tab').forEach((btn) => {
    btn.addEventListener('click', () => switchTab(btn.dataset.tab));
  });
  $('btn-rescan').addEventListener('click', rescan);
  $('btn-back').addEventListener('click', () => historyGo(-1));
  $('btn-fwd').addEventListener('click', () => historyGo(1));

  $('tree-search').addEventListener('input', (ev) => {
    state.tree.filter = ev.target.value.trim();
    renderTree();
  });
  $('tree-sort').addEventListener('change', (ev) => {
    state.tree.sort = ev.target.value;
    renderTree();
  });
  $('tree-expand-all').addEventListener('click', () => {
    for (const [rel, e] of state.tree.cache) {
      if (e.children) {
        for (const c of e.children) if (c.is_dir) state.tree.expanded.add(c.path);
      }
    }
    renderTree();
  });
  $('tree-collapse-all').addEventListener('click', () => {
    state.tree.expanded.clear();
    renderTree();
  });
  $('tree-body').addEventListener('keydown', treeKeydown);

  $('fnd-gate').addEventListener('change', (ev) => {
    state.findings.gate = ev.target.value;
    loadFindings();
  });
  $('fnd-harness').addEventListener('change', (ev) => {
    state.findings.harness = ev.target.value;
    loadFindings();
  });
  let qTimer = null;
  $('fnd-q').addEventListener('input', (ev) => {
    clearTimeout(qTimer);
    const v = ev.target.value;
    qTimer = setTimeout(() => { state.findings.q = v; loadFindings(); }, 300);
  });
  $('fnd-group').addEventListener('change', (ev) => {
    state.findings.group = ev.target.checked;
    renderFindings();
  });

  $('insp-close').addEventListener('click', closeInspector);
  $('card-close').addEventListener('click', closeFindingCard);
  $('card-overlay').addEventListener('click', (ev) => {
    if (ev.target === $('card-overlay')) closeFindingCard();
  });

  $('metric-density').addEventListener('click', () => setTreemapMetric('density'));
  $('metric-risk').addEventListener('click', () => setTreemapMetric('risk'));
  $('metric-disk').addEventListener('click', () => setTreemapMetric('disk'));

  $('treemap-body').addEventListener('click', onTreemapClick);
  $('treemap-body').addEventListener('dblclick', onTreemapDblclick);
  $('treemap-body').addEventListener('keydown', onTreemapKeydown);

  $('sim-run').addEventListener('click', runSimulate);
  $('sim-target').addEventListener('keydown', (evx) => {
    if (evx.key === 'Enter') runSimulate();
  });
  $('ins-harness').addEventListener('change', () => renderInstructionsDiagram());

  let resizeTimer = null;
  window.addEventListener('resize', () => {
    if (state.tab !== 'treemap' || !state.treemap.nodes.size) return;
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(renderTreemap, 150);
  });

  document.addEventListener('keydown', globalKeydown);
}

function setTreemapMetric(m) {
  state.treemap.metric = m;
  $('metric-density').setAttribute('aria-pressed', String(m === 'density'));
  $('metric-risk').setAttribute('aria-pressed', String(m === 'risk'));
  $('metric-disk').setAttribute('aria-pressed', String(m === 'disk'));
  $('metric-formula').textContent =
    m === 'risk' ? 'Risk = 5\u00b7crit + 4\u00b7high + 3\u00b7med + 2\u00b7low + 1\u00b7info (sum over subtree)'
    : m === 'disk' ? 'Disk = file sizes from /api/tree; dir sizes are partial sums over fetched levels (severity filter does not apply)'
    : 'Density = count of findings in subtree';
  if (state.treemap.nodes.size) renderTreemap();
}

function boot() {
  bindUI();
  updateHistoryButtons();
  switchTab('overview');
}

/* Browser: boot on DOM ready. Node (smoke test of the pure decision
   tables): skip the DOM entirely and export them via CommonJS. */
if (typeof document !== 'undefined') {
  document.addEventListener('DOMContentLoaded', boot);
}
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { resolveTreemapClick, resolveTreemapKey };
}
})();
