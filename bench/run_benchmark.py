#!/usr/bin/env python3
"""Benchmark runner for skills/agents-doctor/scripts/audit_scan.py.

    python bench/run_benchmark.py <workspace_dir> --home <home_dir> \
        --out bench/BENCH-2026-11-16.md [--label "local windows"] [--max-wall 60]

Dual measurement, because the two numbers answer different questions:

  wall (subprocess)  one full CLI run (python audit_scan.py ... --out tmp) via
                     subprocess; includes interpreter startup and writing the
                     JSON report. This is what a user of the skill feels.
  scan() peak alloc  the same scan executed in-process by importing audit_scan
                     and calling scan() under tracemalloc; reports the peak of
                     *Python-allocated* memory during the call. Not RSS: C
                     buffers, the interpreter itself and freed-then-reused
                     arena pages are not visible to tracemalloc.

Appends one markdown row per run to --out (default bench/BENCH-<date>.md
under the repo). Exits non-zero if --max-wall is given and the subprocess
wall time exceeds it. Python 3.9+, stdlib only.
"""
import argparse
import os
import subprocess
import sys
import tempfile
import time
import tracemalloc
from datetime import datetime
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCANNER = REPO / 'skills' / 'agents-doctor' / 'scripts' / 'audit_scan.py'
HEADER = ('| date | label | files | size MB | wall (subprocess), s | '
          'scan() peak alloc, MB | findings | gates f/w/p/u/na | skipped links |')
SEP = '|---|---|---|---|---|---|---|---|---|'


def run_subprocess(ws, home):
    """One CLI run; returns (wall_seconds, stdout)."""
    fd, tmp = tempfile.mkstemp(suffix='.json', prefix='bench-scan-')
    os.close(fd)
    out = Path(tmp)
    try:
        cmd = [sys.executable, str(SCANNER), str(ws),
               '--home', str(home), '--out', str(out)]
        t0 = time.perf_counter()
        r = subprocess.run(cmd, capture_output=True, text=True)
        wall = time.perf_counter() - t0
        if r.returncode != 0:
            sys.exit(f'scanner failed ({r.returncode}):\n{r.stdout}{r.stderr}')
        return wall, r.stdout
    finally:
        out.unlink(missing_ok=True)


def run_inprocess(ws, home):
    """Import audit_scan and run scan() under tracemalloc; returns (report, peak_mb)."""
    sys.path.insert(0, str(SCANNER.parent))
    import audit_scan  # noqa: E402 (import after sys.path bootstrap is the point)
    tracemalloc.start()
    rep = audit_scan.scan(Path(ws).resolve(), Path(home).resolve())
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return rep, peak / 1048576


def main():
    ap = argparse.ArgumentParser(description='audit_scan benchmark runner')
    ap.add_argument('workspace', help='workspace dir to scan (e.g. bench/work/ws-small)')
    ap.add_argument('--home', required=True,
                    help='home dir for the scanner (use a small fixture home for comparable rows)')
    ap.add_argument('--out', default=None,
                    help='markdown file to append the row to '
                         '(default: bench/BENCH-<date>.md under the repo)')
    ap.add_argument('--label', default='', help='size/machine label for the row')
    ap.add_argument('--max-wall', type=float, default=None, metavar='SECONDS',
                    help='exit non-zero if the subprocess wall time exceeds this')
    a = ap.parse_args()

    out = Path(a.out) if a.out else REPO / 'bench' / f'BENCH-{datetime.now():%Y-%m-%d}.md'

    wall, stdout = run_subprocess(a.workspace, a.home)
    print(stdout.rstrip())
    rep, peak_mb = run_inprocess(a.workspace, a.home)

    st = rep['stats']
    g = rep['gates']
    gsum = '/'.join(str(sum(1 for x in g if x['status'] == s))
                    for s in ('fail', 'warn', 'pass', 'unknown', 'not_applicable'))
    row = (f'| {datetime.now():%Y-%m-%d %H:%M} | {a.label} | {st["total_files"]} | '
           f'{st["total_size_bytes"] / 1048576:.1f} | {wall:.2f} | {peak_mb:.1f} | '
           f'{len(rep["findings_detailed"])} | {gsum} | {st["skipped_symlinks_outside"]} |')
    out.parent.mkdir(parents=True, exist_ok=True)
    if not out.exists():
        out.write_text(f'# audit_scan benchmarks\n\n{HEADER}\n{SEP}\n', encoding='utf-8')
    with out.open('a', encoding='utf-8') as f:
        f.write(row + '\n')
    print(f'row appended: {out}')
    print(f'wall (subprocess): {wall:.2f} s, scan() peak alloc: {peak_mb:.1f} MB')

    if a.max_wall is not None and wall > a.max_wall:
        print(f'FAIL: wall {wall:.2f} s exceeds --max-wall {a.max_wall} s')
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
