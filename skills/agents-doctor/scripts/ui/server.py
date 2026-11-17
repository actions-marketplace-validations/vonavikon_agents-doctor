"""Local web UI server (Visual TZ section 2, Phase V1+).

    python skills/agents-doctor/scripts/ui/server.py --scan scan.json
    python .../ui/server.py --root <workspace>   # runs a fresh scan

Serves a single-page app from ui/static plus a JSON API over one
scan.json. Binds 127.0.0.1 only; no requests leave the machine.

Safety rules (Visual TZ section 16):
- every file path is resolved and contained under the audited root
  before anything is opened (symlinks resolved first);
- file previews are size-capped and secret-masked: lines matching a
  secret rule show the mask, never the value;
- static assets come only from the packaged ui/static directory;
- read-only: no endpoint writes, moves or executes anything. The
  remediation preview endpoint plans fixes but never applies them.

API (all GET unless noted, JSON):
  /api/overview                      stats, gates, severity/status counts
  /api/harnesses                     detection + spec matrix
  /api/findings                      ?severity= &gate= &status= &harness= &q=
  /api/finding/<fid>                 one finding in full
  /api/tree                          ?path=<rel>  lazy children + counts
  /api/file                          ?path=<rel>  masked text preview
  /api/simulate                      ?target=<rel> &harness=<id>
  /api/fixplan                       ?fid=<id> remediation plan (dry)
  /api/rescan              (POST)    rerun the scan in-process
"""
from __future__ import annotations

import argparse
import json
import mimetypes
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

UI_DIR = Path(__file__).resolve().parent
SCRIPTS = UI_DIR.parent
sys.path.insert(0, str(SCRIPTS))

import audit_scan          # noqa: E402  (in-process rescan)
import secret_rules        # noqa: E402  (preview masking)
import remediate           # noqa: E402  (dry-run plans only)

MAX_PREVIEW_BYTES = 256 * 1024
MAX_TREE_CHILDREN = 2000
SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info']


class UiState:
    """Shared, lock-guarded state: the loaded report + its root."""

    def __init__(self, report: dict, root: Path, baseline: dict | None = None):
        self.lock = threading.Lock()
        self.report = report
        self.root = root.resolve()
        self.baseline = baseline
        self._counts = _per_file_counts(report)

    def reload(self, report: dict, baseline: dict | None = None):
        with self.lock:
            self.report = report
            if baseline is not None:
                self.baseline = baseline
            self._counts = _per_file_counts(report)

    @property
    def counts(self) -> dict:
        with self.lock:
            return self._counts


def _per_file_counts(report: dict) -> dict:
    """rel-path -> {'critical': n, ...} from findings evidence."""
    counts = {}
    for f in report.get('findings_detailed') or []:
        sev = f.get('severity', 'info')
        if f.get('status') in ('pass', 'not_applicable'):
            continue
        for ev in f.get('evidence') or []:
            p = ev.get('file')
            if not p:
                continue
            p = str(p).replace('\\', '/').strip('/')
            entry = counts.setdefault(p, {s: 0 for s in SEVERITY_ORDER})
            entry[sev] = entry.get(sev, 0) + 1
    return counts


def _contain(state: UiState, rel: str) -> Path:
    """Resolve rel under root; raise PermissionError on escape."""
    rel = unquote(rel or '').replace('\\', '/').lstrip('/')
    target = (state.root / rel).resolve()
    root = state.root.resolve()
    if root not in target.parents and target != root:
        raise PermissionError('outside workspace root')
    return target


def _safe_read(target: Path) -> tuple:
    """Read up to the cap. Returns (text, truncated, is_binary)."""
    try:
        size = target.stat().st_size
    except OSError as exc:
        raise FileNotFoundError(str(exc))
    try:
        blob = target.read_bytes()[:MAX_PREVIEW_BYTES + 1]
    except OSError as exc:
        raise FileNotFoundError(str(exc))
    truncated = size > MAX_PREVIEW_BYTES or len(blob) > MAX_PREVIEW_BYTES
    blob = blob[:MAX_PREVIEW_BYTES]
    if b'\x00' in blob[:4096]:
        return ('', truncated, True)
    return (blob.decode('utf-8', errors='replace'), truncated, False)


def _mask_line(line: str) -> str:
    """Replace every secret-rule match on the line with its mask."""
    out = line
    for rule in secret_rules.RULES:
        matches = list(rule['py'].finditer(out))
        if not matches:
            continue
        for m in reversed(matches):
            if '${' in m.group(0):
                continue
            out = out[:m.start()] + rule['mask'] + out[m.end():]
    return out


def _dir_counts(state: UiState, rel_dir: str) -> dict:
    """Aggregated counts for everything under rel_dir ('' = root)."""
    agg = {s: 0 for s in SEVERITY_ORDER}
    prefix = '' if rel_dir in ('', '.') else rel_dir.strip('/') + '/'
    for path, per in state.counts.items():
        if path == rel_dir or path.startswith(prefix):
            for sev, n in per.items():
                agg[sev] += n
    return agg


# ---------------------------------------------------------------- handlers

def api_overview(state: UiState, _qs):
    rep = state.report
    gates = rep.get('gates') or []
    sev = {s: 0 for s in SEVERITY_ORDER}
    st = {}
    for f in rep.get('findings_detailed') or []:
        sev[f.get('severity', 'info')] = sev.get(f.get('severity', 'info'),
                                                 0) + 1
        s = f.get('status', 'unknown')
        st[s] = st.get(s, 0) + 1
    return {
        'root': str(state.root),
        'generated_at': rep.get('generated_at'),
        'schema_version': rep.get('schema_version'),
        'rules_version': rep.get('rules_version'),
        'stats': rep.get('stats') or {},
        'gates': [{'gid': g.get('gid'), 'name': g.get('name'),
                   'status': g.get('status'), 'confidence': g.get('confidence')}
                  for g in gates],
        'severity_counts': sev,
        'status_counts': st,
        'findings_total': len(rep.get('findings_detailed') or []),
    }


def api_harnesses(state: UiState, _qs):
    rep = state.report
    detected = rep.get('harnesses') or []
    try:
        import harness as harness_pkg
        matrix = harness_pkg.spec_matrix()
    except Exception:
        matrix = []
    return {'detected': detected, 'spec_matrix': matrix}


def api_findings(state: UiState, qs):
    sev = qs.get('severity', [None])[0]
    gate = qs.get('gate', [None])[0]
    status = qs.get('status', [None])[0]
    hid = qs.get('harness', [None])[0]
    q = (qs.get('q', [''])[0] or '').lower()
    out = []
    for f in state.report.get('findings_detailed') or []:
        if sev and f.get('severity') != sev:
            continue
        if gate and f.get('gate') != gate:
            continue
        if status and f.get('status') != status:
            continue
        if hid and f.get('harness', '') != hid:
            continue
        if q:
            blob = ' '.join([str(f.get('title', '')),
                             str(f.get('description', '')),
                             str(f.get('fid', '')),
                             json.dumps(f.get('evidence') or [])]).lower()
            if q not in blob:
                continue
        out.append(f)
    return {'count': len(out), 'findings': out}


def api_finding(state: UiState, fid: str):
    for f in state.report.get('findings_detailed') or []:
        if f.get('fid') == fid:
            return f
    return None


def api_tree(state: UiState, qs):
    rel = qs.get('path', [''])[0]
    try:
        target = _contain(state, rel)
    except (PermissionError, FileNotFoundError) as exc:
        return {'error': str(exc)}
    if not target.is_dir():
        return {'error': 'not a directory'}
    children = []
    try:
        entries = sorted(target.iterdir(), key=lambda p: (
            not p.is_dir(), p.name.lower()))
    except OSError as exc:
        return {'error': str(exc)}
    for entry in entries[:MAX_TREE_CHILDREN]:
        relpath = entry.relative_to(state.root).as_posix()
        child = {
            'name': entry.name,
            'path': relpath,
            'is_dir': entry.is_dir(),
            'symlink': entry.is_symlink(),
        }
        try:
            st = entry.stat()
            if not child['is_dir']:
                child['size'] = st.st_size
                child['mtime'] = st.st_mtime
        except OSError:
            child['size'] = None
        if child['is_dir']:
            child['counts'] = _dir_counts(state, relpath)
        else:
            child['counts'] = state.counts.get(relpath,
                                               {s: 0 for s in SEVERITY_ORDER})
        children.append(child)
    return {
        'path': rel,
        'children': children,
        'truncated': len(entries) > MAX_TREE_CHILDREN,
        'counts': _dir_counts(state, rel),
    }


def api_file(state: UiState, qs):
    rel = qs.get('path', [''])[0]
    try:
        target = _contain(state, rel)
        if target.is_dir():
            return {'error': 'is a directory'}
        text, truncated, binary = _safe_read(target)
    except (PermissionError, FileNotFoundError) as exc:
        return {'error': str(exc)}
    if binary:
        return {'path': rel, 'binary': True, 'truncated': truncated,
                'lines': []}
    lines = []
    flagged = []
    for i, raw in enumerate(text.splitlines(), 1):
        rule = secret_rules.find_rule(raw) if raw else None
        if rule:
            flagged.append({'line': i, 'rule': rule['id'],
                            'mask': rule['mask']})
        lines.append(_mask_line(raw))
    return {
        'path': rel,
        'binary': False,
        'truncated': truncated,
        'lines': lines,
        'flagged_lines': flagged,
        'counts': state.counts.get(
            rel.replace('\\', '/').strip('/'),
            {s: 0 for s in SEVERITY_ORDER}),
    }


def api_simulate(state: UiState, qs):
    target = qs.get('target', [''])[0]
    harness_ids = qs.get('harness', [None])[0]
    try:
        from harness import HarnessContext
        from instructions import simulate_loading
        ctx = HarnessContext(root=state.root, home=Path(state.report.get(
            'home') or Path.home()))
        tgt = _contain(state, target) if target else None
        ids = [harness_ids] if harness_ids else None
        return simulate_loading(ctx, tgt, ids)
    except (PermissionError, FileNotFoundError) as exc:
        return {'error': str(exc)}
    except Exception as exc:  # simulation must never kill the server
        return {'error': 'simulation failed: %s' % exc}


def api_fixplan(state: UiState, qs):
    fid = qs.get('fid', [''])[0]
    if not fid:
        return {'error': 'fid required'}
    try:
        steps = remediate.plan(state.report, fid)
    except Exception as exc:
        return {'error': str(exc), 'supported': False}
    return {
        'supported': True,
        'dry_run': True,
        'steps': [{'action': s.get('action'), 'target': s.get('target'),
                   'detail': s.get('detail', '')} for s in steps],
        'note': 'UI never applies fixes; run agents_doctor.py fix --apply',
    }


def api_compare(state: UiState, qs):
    """Fingerprint diff against the baseline scan given at server start
    (never an arbitrary path from the wire)."""
    if not state.baseline:
        return {'error': 'no baseline scan given at server start '
                         '(--baseline old-scan.json)', 'supported': False}
    try:
        diff = remediate.fingerprint_diff(
            state.baseline.get('findings') or [],
            state.report.get('findings') or [])
    except Exception as exc:
        return {'error': str(exc), 'supported': False}
    for name in ('new', 'resolved', 'persisting', 'changed'):
        for f in diff.get(name) or []:
            f.pop('fp', None)   # fingerprints are internal
    return {
        'supported': True,
        'baseline_generated_at': state.baseline.get('generated_at'),
        'current_generated_at': state.report.get('generated_at'),
        'summary': {k: len(v) for k, v in diff.items()},
        'diff': diff,
    }


def make_handler(state: UiState):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass  # quiet: the UI is a local tool

        def _json(self, obj, code=200):
            body = json.dumps(obj, ensure_ascii=False).encode('utf-8')
            self.send_response(code)
            self.send_header('Content-Type', 'application/json; '
                                             'charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _static(self, name: str):
            base = (UI_DIR / 'static').resolve()
            target = (base / name).resolve()
            if base not in target.parents and target != base / 'index.html':
                self._json({'error': 'forbidden'}, 403)
                return
            try:
                blob = target.read_bytes()
            except OSError:
                self._json({'error': 'not found'}, 404)
                return
            ctype = mimetypes.guess_type(str(target))[0] or 'text/plain'
            self.send_response(200)
            self.send_header('Content-Type',
                             ctype + ('; charset=utf-8'
                                      if ctype.startswith('text/') else ''))
            self.send_header('Content-Length', str(len(blob)))
            self.end_headers()
            self.wfile.write(blob)

        def do_GET(self):
            parsed = urlparse(self.path)
            qs = parse_qs(parsed.query)
            route = parsed.path
            try:
                if route in ('/', '/index.html'):
                    self._static('index.html')
                elif route.startswith('/static/'):
                    self._static(unquote(route[len('/static/'):]))
                elif route == '/api/overview':
                    self._json(api_overview(state, qs))
                elif route == '/api/harnesses':
                    self._json(api_harnesses(state, qs))
                elif route == '/api/findings':
                    self._json(api_findings(state, qs))
                elif route.startswith('/api/finding/'):
                    fid = unquote(route.split('/', 3)[3])
                    obj = api_finding(state, fid)
                    self._json(obj if obj is not None
                               else {'error': 'finding not found'}, 200
                               if obj else 404)
                elif route == '/api/tree':
                    self._json(api_tree(state, qs))
                elif route == '/api/file':
                    self._json(api_file(state, qs))
                elif route == '/api/simulate':
                    self._json(api_simulate(state, qs))
                elif route == '/api/fixplan':
                    self._json(api_fixplan(state, qs))
                elif route == '/api/compare':
                    self._json(api_compare(state, qs))
                else:
                    self._json({'error': 'no such route'}, 404)
            except BrokenPipeError:
                pass
            except Exception as exc:  # never leak a traceback to the wire
                self._json({'error': 'internal: %s' % exc}, 500)

        def do_POST(self):
            if urlparse(self.path).path == '/api/rescan':
                try:
                    rep = audit_scan.scan(state.root,
                                          Path(state.report.get('home')
                                               or Path.home()),
                                          False)
                    state.reload(rep)
                    self._json({'rescanned': True,
                                'findings': len(rep.get('findings_detailed')
                                                or [])})
                except Exception as exc:
                    self._json({'error': str(exc)}, 500)
            else:
                self._json({'error': 'no such route'}, 404)

    return Handler


def load_or_scan(scan_path, root, home):
    """Report dict from a scan.json, or a fresh in-process scan."""
    if scan_path:
        rep = json.loads(Path(scan_path).read_text(encoding='utf-8'))
        root = Path(rep.get('root') or root or Path(scan_path).parent)
        return rep, root
    root = Path(root or '.').resolve()
    if not root.is_dir():
        raise SystemExit('not a directory: %s' % root)
    return audit_scan.scan(root, Path(home or Path.home()), False), root


def main(argv=None):
    ap = argparse.ArgumentParser(description='agents-doctor local web UI')
    ap.add_argument('--scan', default=None, help='existing scan.json')
    ap.add_argument('--root', default=None, help='workspace root '
                                                 '(fresh scan when no --scan)')
    ap.add_argument('--home', default=None)
    ap.add_argument('--baseline', default=None, metavar='OLD.json',
                    help='older scan.json: enables the Compare tab')
    ap.add_argument('--port', type=int, default=8765)
    ap.add_argument('--no-open', action='store_true')
    a = ap.parse_args(argv)
    report, root = load_or_scan(a.scan, a.root, a.home)
    baseline = None
    if a.baseline:
        try:
            baseline = json.loads(Path(a.baseline).read_text(
                encoding='utf-8'))
        except (OSError, ValueError) as exc:
            print('warning: baseline unreadable (%s); compare disabled'
                  % exc, file=sys.stderr)
    state = UiState(report, root, baseline)
    httpd = ThreadingHTTPServer(('127.0.0.1', a.port), make_handler(state))
    url = 'http://127.0.0.1:%d/' % a.port
    print('agents-doctor UI: %s  (root: %s)  Ctrl+C to stop'
          % (url, state.root))
    if not a.no_open:
        try:
            import webbrowser
            threading.Timer(0.5, lambda: webbrowser.open(url)).start()
        except Exception:
            pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print('\nstopped')
    return 0


if __name__ == '__main__':
    sys.exit(main())
