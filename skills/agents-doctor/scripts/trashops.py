#!/usr/bin/env python3
"""Shared trash-run machinery for the two file-mutating tools,
safe_clean.py and remediate.py (production-readiness stage 4).

Both tools move junk into timestamped run directories under
<root>/<TRASH_DIR_NAME>/ and record everything they do in a manifest.json
inside the run directory. The rules implemented here:

- Operation id: every execute() run gets a short random opid (8 hex
  chars); the run directory is <YYYYmmdd-HHMMSS>-<opid>, so two runs in
  the same second can never share a directory.
- Write-ahead manifest: the entry for an item is written with status
  'moving' BEFORE the move starts and updated to 'moved' or 'failed'
  after. A crash mid-run leaves the in-flight entry visible in the
  manifest, which is exactly what crash recovery looks for.
- Manifest header: {opid, root, started_at, tool, interrupted_run,
  totals}; entries add {action, original_path, trash_path, size,
  mtime_ns, moved_at, status, error?, restorable}.
- Crash recovery: before a new run starts, earlier run directories are
  scanned; a manifest holding any in-flight entry ('moving'/'removing')
  marks that run as interrupted. Nothing in it is deleted or resumed
  blindly -- its opid is recorded in the new manifest header as
  'interrupted_run' and the new run continues.
- Destination collisions never overwrite: an existing trash destination
  gets '.__N__' (N=1..999) appended to the basename until a free name is
  found. The manifest records the suffixed path.
- TOCTOU snapshots: planning code records {size, mtime_ns, type} per
  item via snapshot(); the executor re-stats immediately before each
  operation and aborts the item when unchanged() says the file changed.
- Restore: restore(run_dir, root) moves 'moved' entries back, with a
  '.restored-N' suffix when the original location is occupied, and
  updates the manifest. Removed empty folders are recorded with
  restorable: false and are skipped by restore.

Every mutating helper re-checks containment (resolved paths must stay
under root / the run directory) right before it acts. Python 3.9+,
stdlib only.
"""
import json
import os
import shutil
import stat as stat_mod
import uuid
from datetime import datetime
from pathlib import Path

# shared trash root name; safe_clean and remediate re-export this
TRASH_DIR_NAME = '.agents-doctor-trash'
MANIFEST_NAME = 'manifest.json'

# entry statuses that mean "an operation was in flight when the process
# died" -- the signal crash recovery looks for
IN_FLIGHT = ('moving', 'removing')

# statuses restore() will pick up again (a restore that failed once can
# be retried while the trash copy still exists)
RESTORABLE = ('moved', 'restore_failed')


def new_opid():
    """Short operation id: first 8 hex chars of a uuid4."""
    return uuid.uuid4().hex[:8]


def run_stamp():
    """Run-directory timestamp part: YYYYmmdd-HHMMSS."""
    return datetime.now().strftime('%Y%m%d-%H%M%S')


def _iso_now():
    return datetime.now().isoformat(timespec='seconds')


def snapshot(path):
    """{size, mtime_ns, type} from os.stat, or None when stat fails
    (missing path, lost permissions). 'type' is 'dir', 'file' or
    'other'. Symlinks are never snapshotted here: the callers refuse
    them before this runs."""
    try:
        st = os.stat(str(path))
    except OSError:
        return None
    if stat_mod.S_ISDIR(st.st_mode):
        kind = 'dir'
    elif stat_mod.S_ISREG(st.st_mode):
        kind = 'file'
    else:
        kind = 'other'
    return {'size': st.st_size, 'mtime_ns': st.st_mtime_ns, 'type': kind}


def unchanged(snap, cur):
    """True when the plan-time snapshot and the execute-time re-stat
    describe the same file: same size, mtime_ns and type. A missing
    plan-time snapshot (a hand-built plan) means 'nothing to compare'
    and passes; a plan-time snapshot with a failed re-stat means the
    item changed (or vanished) and does not pass."""
    if snap is None:
        return True
    if cur is None:
        return False
    return (snap.get('size') == cur.get('size')
            and snap.get('mtime_ns') == cur.get('mtime_ns')
            and snap.get('type') == cur.get('type'))


def _exists(p):
    """exists() that treats permission errors as absent (pathlib raises)."""
    try:
        return p.exists()
    except OSError:
        return False


def _rel_shape_ok(rel):
    """A relative path is usable inside root/run_dir: not absolute, no
    '..' after normalization, not empty."""
    p = os.path.normpath(str(rel))
    return bool(p) and p != '.' and not os.path.isabs(p) \
        and p != '..' and not p.startswith('..' + os.sep)


def _is_under(path, base):
    """True when resolved path is strictly below resolved base."""
    try:
        path = Path(path).resolve()
        base = Path(base).resolve()
    except OSError:
        return False
    return base in path.parents


def collision_free_dst(dst):
    """Never overwrite: when dst exists, append '.__N__' (N=1..999) to
    the basename until a free name is found. Raises OSError when all
    999 are taken (a pathological directory nobody should have)."""
    if not _exists(dst):
        return dst
    for n in range(1, 1000):
        cand = dst.parent / ('%s.__%d__' % (dst.name, n))
        if not _exists(cand):
            return cand
    raise OSError('no free trash destination under %s' % dst)


def load_manifest(run_dir):
    """Read manifest.json from a run dir; ValueError when missing or
    not valid JSON. Returns the parsed dict."""
    mp = Path(run_dir) / MANIFEST_NAME
    try:
        data = json.loads(mp.read_text(encoding='utf-8'))
    except OSError as exc:
        raise ValueError('no %s in %s: %s' % (MANIFEST_NAME, run_dir, exc))
    except ValueError as exc:
        raise ValueError('cannot parse %s: %s' % (mp, exc))
    if not isinstance(data, dict):
        raise ValueError('%s is not a manifest object: %s' % (mp, type(data).__name__))
    return data


def save_manifest(run_dir, data):
    """Write a manifest atomically (temp file + os.replace), so a crash
    mid-write never leaves a half-written manifest behind."""
    mp = Path(run_dir) / MANIFEST_NAME
    tmp = mp.with_name(MANIFEST_NAME + '.tmp')
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2),
                   encoding='utf-8')
    os.replace(str(tmp), str(mp))
    return mp


class TrashRun:
    """One execute() run: a unique run directory plus its write-ahead
    manifest. Created only after the user confirmed; the header is on
    disk before the first item runs."""

    def __init__(self, root, tool, opid=None, stamp=None, interrupted=None):
        self.root = Path(root).resolve()
        self.opid = opid or new_opid()
        self.run_dir = self.root / TRASH_DIR_NAME / ('%s-%s' % (stamp or run_stamp(), self.opid))
        self.manifest_path = self.run_dir / MANIFEST_NAME
        self.header = {
            'opid': self.opid,
            'root': str(self.root),
            'started_at': _iso_now(),
            'tool': str(tool),
            'interrupted_run': interrupted,
            'totals': {'planned': 0, 'moved': 0, 'failed': 0, 'skipped': 0,
                       'removed_dirs': 0, 'freed_bytes': 0},
        }
        self.entries = []
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.save()

    def save(self):
        """Flush header + entries to manifest.json (atomic replace)."""
        save_manifest(self.run_dir,
                      dict(self.header, totals=dict(self.header['totals']),
                           entries=self.entries))

    def add_entry(self, entry):
        """Append an entry and flush; returns its index."""
        self.entries.append(entry)
        self.save()
        return len(self.entries) - 1

    def update_entry(self, idx, **fields):
        """Patch one entry (by index) and flush."""
        self.entries[idx].update(fields)
        self.save()

    def finish(self, **totals):
        """Record the final totals (keys must match the zeroed set)."""
        self.header['totals'].update(totals)
        self.save()


def move_to_trash(run, src, rel, size, mtime_ns, kind=None):
    """Move one confirmed path into the run directory, write-ahead
    style: the manifest entry goes to disk with status 'moving' before
    shutil.move runs, then becomes 'moved' or 'failed'. The destination
    is collision-suffixed, never overwritten. Returns (dst, entry_idx).
    Raises whatever the move raised after marking the entry 'failed'."""
    rel = os.path.normpath(str(rel))
    dst = collision_free_dst(run.run_dir / rel)
    dst.parent.mkdir(parents=True, exist_ok=True)
    idx = run.add_entry({
        'opid': run.opid,
        'action': 'trash',
        'original_path': rel,
        'trash_path': dst.relative_to(run.run_dir).as_posix(),
        'size': size or 0,
        'mtime_ns': mtime_ns,
        'type': kind,
        'moved_at': _iso_now(),
        'status': 'moving',
        'restorable': True,
    })
    try:
        shutil.move(str(src), str(dst))
    except Exception as exc:
        run.update_entry(idx, status='failed',
                         error='%s: %s' % (type(exc).__name__, exc))
        raise
    run.update_entry(idx, status='moved')
    return dst, idx


def record_rmdir(run, target, rel, snap):
    """rmdir one confirmed-empty directory, write-ahead style: entry
    status 'removing' before os.rmdir, 'removed' after. Empty folders
    are not restorable; the manifest says so."""
    idx = run.add_entry({
        'opid': run.opid,
        'action': 'rmdir',
        'original_path': os.path.normpath(str(rel)),
        'trash_path': None,
        'size': (snap or {}).get('size') or 0,
        'mtime_ns': (snap or {}).get('mtime_ns'),
        'type': (snap or {}).get('type'),
        'moved_at': _iso_now(),
        'status': 'removing',
        'restorable': False,
    })
    try:
        os.rmdir(str(target))
    except Exception as exc:
        run.update_entry(idx, status='failed',
                         error='%s: %s' % (type(exc).__name__, exc))
        raise
    run.update_entry(idx, status='removed')
    return idx


def find_interrupted(root):
    """Scan <root>/<TRASH_DIR_NAME>/*/manifest.json for in-flight
    entries ('moving'/'removing'). Returns the opid of the most recent
    interrupted run (by manifest mtime), or None. Interrupted runs are
    never modified or resumed by this call -- the caller only records
    the opid."""
    trash = Path(root) / TRASH_DIR_NAME
    best_mtime, best_opid = None, None
    try:
        run_dirs = sorted(trash.iterdir())
    except OSError:
        return None
    for rd in run_dirs:
        mp = rd / MANIFEST_NAME
        if not _exists(mp):
            continue
        try:
            data = json.loads(mp.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            continue
        entries = data.get('entries') or []
        if isinstance(entries, list) and any(
                isinstance(e, dict) and e.get('status') in IN_FLIGHT
                for e in entries):
            try:
                mtime = mp.stat().st_mtime
            except OSError:
                mtime = 0
            if best_mtime is None or mtime >= best_mtime:
                best_mtime, best_opid = mtime, data.get('opid') or rd.name
    return best_opid


# --- restore ------------------------------------------------------------------------

def restore(run_dir, root=None, opid=None, assume_yes=False, confirm=None):
    """Put the 'moved' entries of one trash run back.

    Reads <run_dir>/manifest.json, asks for the word YES (assume_yes
    exists for tests and automation only), then moves every trash entry
    whose status is 'moved' (or 'restore_failed' from an earlier
    attempt) back to root/<original_path>. When that spot is occupied
    the file lands next to it as <name>.restored-N, never overwriting.
    Entries with action 'rmdir' are counted as not restorable and
    skipped. Both sides are containment-checked: the trash copy must
    stay under the run dir, the target under root. Each restore is
    itself write-ahead ('restoring' before the move), and the entry
    ends as 'restored' (with restored_to) or 'restore_failed' (with
    error). Returns a summary dict; raises ValueError when the run
    directory has no readable manifest or the opid does not match."""
    run_dir = Path(run_dir)
    data = load_manifest(run_dir)
    mopid = data.get('opid')
    if opid is not None and opid != mopid:
        raise ValueError('manifest opid %r does not match the requested %r'
                         % (mopid, opid))
    if root is None:
        root = data.get('root')
        if not root:
            raise ValueError('manifest has no root; pass root= explicitly')
    root = Path(root).resolve()

    entries = data.get('entries') or []
    summary = {'declined': False, 'run_dir': str(run_dir.resolve()),
               'manifest_path': str(run_dir / MANIFEST_NAME), 'opid': mopid,
               'root': str(root), 'restored': [], 'failed': [],
               'not_restorable': 0, 'already_done': 0}
    todo = [i for i, e in enumerate(entries)
            if isinstance(e, dict)
            and e.get('action', 'trash') == 'trash'
            and e.get('status') in RESTORABLE]
    summary['already_done'] = sum(
        1 for e in entries
        if isinstance(e, dict) and e.get('status') == 'restored')
    summary['not_restorable'] = sum(
        1 for e in entries
        if isinstance(e, dict) and e.get('action') == 'rmdir'
        and e.get('status') == 'removed')
    if not todo:
        return summary            # nothing restorable: no prompt, no changes

    if not assume_yes:
        ask = confirm if confirm is not None else input
        try:
            answer = ask('Type YES to restore %d item(s): ' % len(todo))
        except EOFError:
            answer = ''
        if answer != 'YES':
            summary['declined'] = True
            return summary

    for i in todo:
        e = entries[i]
        orig = str(e.get('original_path') or '')
        trash_rel = str(e.get('trash_path') or '')
        try:
            if not _rel_shape_ok(orig) or not _rel_shape_ok(trash_rel):
                raise ValueError('path has an unsafe shape')
            src = run_dir / trash_rel
            if not _is_under(src, run_dir) or not _exists(src):
                raise ValueError('trash copy missing or outside the run dir: %s'
                                 % trash_rel)
            dst = root / os.path.normpath(orig)
            resolved = dst.resolve()
            if root not in resolved.parents \
                    or resolved.parts[len(root.resolve().parts)] == TRASH_DIR_NAME:
                raise ValueError('original path escapes root or sits in the '
                                 'trash folder')
            if _exists(dst):
                for n in range(1, 1000):
                    cand = dst.parent / ('%s.restored-%d' % (dst.name, n))
                    if not _exists(cand):
                        dst = cand
                        break
                else:
                    raise OSError('no free restore destination for %s' % dst)
            dst.parent.mkdir(parents=True, exist_ok=True)
            e['status'] = 'restoring'
            save_manifest(run_dir, data)
            shutil.move(str(src), str(dst))
        except Exception as exc:
            e['status'] = 'restore_failed'
            e['error'] = '%s: %s' % (type(exc).__name__, exc)
            save_manifest(run_dir, data)
            summary['failed'].append({'original_path': orig,
                                      'error': e['error']})
            continue
        e['status'] = 'restored'
        e['restored_to'] = dst.relative_to(root).as_posix()
        e['restored_at'] = _iso_now()
        e.pop('error', None)
        save_manifest(run_dir, data)
        summary['restored'].append({'original_path': orig,
                                    'restored_to': e['restored_to']})
    return summary
