#!/usr/bin/env python3
"""Deterministic synthetic workspace generator for benchmarking audit_scan.

    python bench/gen_workspace.py <target_dir> --size small|medium|large [--seed 42]

Same size + seed produces an identical tree (content, layout and git commits):
  - N real git repos: git init + ONE fast-import commit (fixed author and
    committer dates), so repo-NN is indistinguishable from a normal checkout
    for the scanner (remote, log, status, git grep --cached all work);
    repo-00 and repo-01 share a remote URL on purpose (duplicate-checkout
    detection), roughly half of the rest get their own remote
  - each repo: AGENTS.md, README.md, .gitignore, src/ files (~40 lines,
    1-12 KB, mix of .py/.json/.md)
  - junk files (temp-*.log, backup-*.txt) at the workspace root and in repos
  - one 8 KB duplicate pair (same content written twice)
  - a .env with a DEMO token (clearly fake, fixture-only) in every third repo
  - node_modules build dirs inside each repo
  - datasets/ dirs with 1-2 MB binary files (medium and large only)

Files stay small so even a large (~60000 files) tree builds fast: writes go
through a small thread pool, and the git commit is a single fast-import run
instead of one object per file. Prints a summary: files, dirs, bytes, seconds.
Python 3.9+, stdlib only (plus the git binary for the repo fixtures).
"""
import argparse
import os
import random
import shutil
import stat
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

SIZES = {
    # ~800 / ~12000 / ~60000 files including junk, dups, node_modules
    'small':  dict(repos=3,  files_per_repo=250,  junk=30,  data_dirs=0, data_files=0, node_files=5),
    'medium': dict(repos=8,  files_per_repo=1465, junk=120, data_dirs=3, data_files=2, node_files=8),
    'large':  dict(repos=15, files_per_repo=3930, junk=420, data_dirs=8, data_files=2, node_files=10),
}
COMMIT_DATE = ('bench bot <bench@example.com> 1768474800 +0300')  # 2026-01-15T12:00:00+03:00
WORDS = ['alpha', 'beta', 'gamma', 'delta', 'epsilon', 'zeta', 'eta', 'theta',
         'iota', 'kappa', 'lambda', 'mu', 'nu', 'xi', 'omicron', 'pi', 'rho',
         'sigma', 'tau', 'psi', 'chi', 'omega']
PACKAGES = ['core', 'api', 'util', 'models', 'store', 'net', 'ui', 'tasks']
ENV_DEMO = ('# benchmark fixture: DEMO token, never a real secret\n'
            'API_TOKEN=sk-demo-0123456789abcdef\n'
            'LOG_LEVEL=info\n')


def rm_force(p):
    """rmtree that clears the read-only bit git puts on object files."""
    def _retry(func, path, _exc):
        os.chmod(path, stat.S_IWRITE)
        func(path)
    try:
        shutil.rmtree(p, onexc=_retry)      # Python 3.12+
    except TypeError:
        shutil.rmtree(p, onerror=_retry)    # Python 3.9-3.11


def write_file(path, content):
    """The single writer helper: every file in the tree goes through here."""
    if isinstance(content, str):
        content = content.encode('utf-8')
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return len(content)


def source_content(rng):
    """A ~40-line Python-ish file, padded to a random 1-12 KB."""
    target = rng.randint(1, 12) * 1024
    lines = ['"""Benchmark fixture: generated content, not real code."""', '']
    i = 0
    while len(lines) < 40 or len('\n'.join(lines)) < target:
        lines.append(f'def step_{i}(x):')
        lines.append(f'    return x * {rng.randint(2, 99)} + {rng.randint(0, 9)}  # {rng.choice(WORDS)}')
        lines.append('')
        i += 1
    lines.append(f'# fixture marker {rng.choice(WORDS)}-{i}')
    return '\n'.join(lines) + '\n'


def plan_repo(ws, idx, cfg, rng):
    """Plans one repo: returns (repo_dir, committed, ignored, total_bytes).

    committed/ignored are lists of (posix_relpath, bytes); ignored files are
    written to the worktree but excluded from the commit (node_modules, *.log).
    """
    committed, ignored, nbytes = [], [], 0
    name = f'repo-{idx:02d}'

    def add(rel, content, gitignored=False):
        nonlocal nbytes
        if isinstance(content, str):
            content = content.encode('utf-8')
        (ignored if gitignored else committed).append((rel, content))
        nbytes += len(content)

    add('AGENTS.md',
        f'# {name}\n\nBenchmark fixture repo.\n- keep files small\n'
        f'- regenerate with bench/gen_workspace.py\n')
    add('README.md', f'# {name}\n\nSynthetic benchmark repository. '
                     f'All content is generated.\n')
    add('.gitignore', 'node_modules/\n__pycache__/\n*.log\n')
    add('src/__init__.py', '')
    for n in range(cfg['files_per_repo']):
        pkg = PACKAGES[(idx + n) % len(PACKAGES)]
        r = n % 10
        if r < 8:
            ext, content = '.py', source_content(rng)
        elif r == 8:
            ext = '.json'
            content = (f'{{"module": "{pkg}", "n": {n},'
                       f' "tuned": {str(rng.choice([True, False])).lower()}}}\n')
        else:
            ext = '.md'
            content = f'# notes {n}\n\n' + 'generated note line\n' * 20
        add(f'src/{pkg}/mod_{n:05d}{ext}', content)
    if idx % 3 == 1:
        add('.env', ENV_DEMO)
    for j in range(cfg['node_files']):
        add(f'node_modules/lib/pkg-{j % 3}/file-{j}.js',
            f'// fixture {j}\nmodule.exports = {rng.randint(1, 999)};\n',
            gitignored=True)
    add(f'temp-{idx}.log', 'temp log line\n' * 30, gitignored=True)
    add(f'backup-{idx}.txt', 'backup of something\n' * 30)
    return ws / name, committed, ignored, nbytes


def fast_import_stream(committed):
    parts = [f'commit refs/heads/master\nauthor {COMMIT_DATE}\n'
             f'committer {COMMIT_DATE}\ndata 17\nbenchmark fixture\n'.encode()]
    for rel, data in committed:
        parts.append(f'M 100644 inline {rel}\n'.encode())
        parts.append(f'data {len(data)}\n'.encode())
        parts.append(data)
        parts.append(b'\n')
    parts.append(b'\n')
    return b''.join(parts)


def git(repo, *args, stdin=None):
    # fsync off: build speed only, the resulting repo is a normal packfile repo
    r = subprocess.run(['git', '-C', str(repo), '-c', 'core.fsync=none',
                        '-c', 'core.fsyncMethod=batch', *args],
                       check=True, capture_output=True, input=stdin)
    return r


def init_git(repo, idx, committed):
    git(repo, 'init', '-q')
    git(repo, 'symbolic-ref', 'HEAD', 'refs/heads/master')
    git(repo, 'fast-import', '--quiet', stdin=fast_import_stream(committed))
    git(repo, 'read-tree', 'HEAD')  # populate the index, worktree is already there
    if idx in (0, 1):
        git(repo, 'remote', 'add', 'origin', 'https://example.invalid/bench/shared.git')
    elif idx % 2 == 0:
        git(repo, 'remote', 'add', 'origin', f'https://example.invalid/bench/repo-{idx:02d}.git')


def main():
    ap = argparse.ArgumentParser(description='deterministic benchmark workspace generator')
    ap.add_argument('target', help='directory to create (must not exist, or pass --force)')
    ap.add_argument('--size', required=True, choices=sorted(SIZES))
    ap.add_argument('--seed', type=int, default=42)
    ap.add_argument('--force', action='store_true', help='replace an existing target dir')
    ap.add_argument('--workers', type=int, default=8, help='writer thread pool size')
    a = ap.parse_args()

    target = Path(a.target)
    if target.exists():
        if not a.force:
            sys.exit(f'target exists (use --force to replace): {target}')
        rm_force(target)

    cfg = SIZES[a.size]
    rng = random.Random(a.seed)
    t0 = time.perf_counter()
    target.mkdir(parents=True)
    stats = {'files': 0, 'bytes': 0}
    pool = ThreadPoolExecutor(max_workers=a.workers)
    jobs = []

    def dispatch(path, content):
        stats['files'] += 1
        stats['bytes'] += len(content) if isinstance(content, bytes) else len(content.encode())
        jobs.append(pool.submit(write_file, path, content))

    dispatch(target / 'AGENTS.md',
             '# Benchmark workspace\n\nGenerated by bench/gen_workspace.py. '
             'All content is synthetic.\n')
    for idx in range(cfg['repos']):
        repo, committed, ignored, _ = plan_repo(target, idx, cfg, rng)
        repo.mkdir(parents=True, exist_ok=True)
        init_git(repo, idx, committed)
        for rel, content in committed + ignored:
            dispatch(repo / Path(rel), content)
    for j in range(cfg['junk']):
        name = f'temp-{j:03d}.log' if j % 2 == 0 else f'backup-{j:03d}.txt'
        dispatch(target / 'junk' / name, 'x' * rng.randint(200, 2000) + '\n')
    base = '\n'.join(f'duplicate fixture line {i} {rng.choice(WORDS)}' for i in range(600))
    dup = (base + '\n')[:8192].encode('ascii')
    dispatch(target / 'dup' / 'first.dat', dup)
    dispatch(target / 'dup' / 'second.dat', dup)
    for d in range(cfg['data_dirs']):
        block = rng.randbytes(65536)
        for f in range(cfg['data_files']):
            size = rng.choice([1, 2]) * 1024 * 1024
            dispatch(target / 'datasets' / f'ds-{d:02d}' / f'part-{f}.bin',
                     block * (size // len(block)))

    for j in jobs:
        j.result()
    pool.shutdown()
    secs = time.perf_counter() - t0

    files = dirs = 0
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames if d != '.git']
        dirs += 1
        files += len(filenames)
    print(f'workspace: {target} (size={a.size} seed={a.seed})')
    print(f'files: {files} (excl. .git), dirs: {dirs}, '
          f'bytes: {stats["bytes"] / 1048576:.1f} MiB (excl. .git)')
    print(f'built in {secs:.1f} s')


if __name__ == '__main__':
    main()
