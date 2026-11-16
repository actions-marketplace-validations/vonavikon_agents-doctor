#!/usr/bin/env python3
"""Check local targets of markdown links in every .md file of a tree.

Rules:
  - Inline links [text](target) and images ![alt](target) with a local
    relative target must resolve to an existing file next to the linking
    document (fragment after '#' is ignored, %XX escapes are decoded).
  - External targets (any URI scheme: http, https, mailto, ...) and
    anchor-only targets (#section) are skipped.
  - A target containing a backslash is a problem: markdown links must use
    forward slashes so they resolve on every platform.
  - Fenced code blocks are skipped, so CLI examples never count as links.

Function API: check_tree(root) -> (problems, files_checked), where problems
is a list of strings. CLI: python tools/check_links.py [root]. Exit 0 with
'[OK] links (N files checked)', or exit 1 with one line per problem.

Excluded from the walk: .git, node_modules, __pycache__, bench/work (bench
fixtures), qa/scenarios/*/run (eval output), demo/employee-workspace and
demo/fake-home (generated demo trees). Python 3.10+, stdlib only.
"""
import os
import re
import sys
import urllib.parse
from pathlib import Path

EXCLUDE_DIR_NAMES = {'.git', 'node_modules', '__pycache__'}
EXCLUDE_PREFIXES = ('bench/work/', 'demo/employee-workspace/', 'demo/fake-home/')
EXCLUDE_RES = (re.compile(r'^qa/scenarios/[^/]+/run(/|$)'),)

LINK_RX = re.compile(
    r'!?\[[^\]]*\]\(\s*(?:<([^>]+)>|([^)\s]+))(?:\s+"[^"]*")?\s*\)')
SCHEME_RX = re.compile(r'^[a-zA-Z][a-zA-Z0-9+.-]*:')
FENCE_RX = re.compile(r'^\s*(```|~~~)')


def iter_markdown_files(root):
    """Yield .md paths under root, pruning excluded directories."""
    root = Path(root)
    for dirpath, dirnames, filenames in os.walk(root):
        rel = Path(dirpath).relative_to(root).as_posix()
        kept = []
        for d in dirnames:
            if d in EXCLUDE_DIR_NAMES:
                continue
            child = d if rel == '.' else rel + '/' + d
            if any(child.startswith(p) for p in EXCLUDE_PREFIXES):
                continue
            if any(rx.search(child) for rx in EXCLUDE_RES):
                continue
            kept.append(d)
        dirnames[:] = kept
        for fn in filenames:
            if fn.endswith('.md'):
                yield Path(dirpath) / fn


def strip_fences(text):
    """Blank out fenced code blocks so examples are not parsed as links."""
    out = []
    in_fence = False
    for line in text.splitlines():
        if FENCE_RX.match(line):
            in_fence = not in_fence
            out.append('')
            continue
        out.append('' if in_fence else line)
    return '\n'.join(out)


def check_file(md_path, root):
    """Return problem strings for one markdown file."""
    problems = []
    rel = Path(md_path).relative_to(root).as_posix()
    try:
        text = Path(md_path).read_text(encoding='utf-8', errors='replace')
    except OSError as e:
        return ['%s: cannot read: %s' % (rel, e)]
    for m in LINK_RX.finditer(strip_fences(text)):
        target = m.group(1) or m.group(2) or ''
        if not target or target.startswith('#'):
            continue
        if SCHEME_RX.match(target):
            continue  # http(s), mailto, data, ...: not a local file
        if '\\' in target:
            problems.append('%s: backslash in link target: %s' % (rel, target))
            continue
        path_part = target.split('#', 1)[0]
        if not path_part:
            continue
        resolved = Path(md_path).parent / urllib.parse.unquote(path_part)
        if not resolved.exists():
            problems.append('%s: link target does not exist: %s' % (rel, target))
    return problems


def check_tree(root):
    """Check every .md file under root. Returns (problems, files_checked)."""
    root = Path(root).resolve()
    problems = []
    files = 0
    for md in iter_markdown_files(root):
        files += 1
        problems.extend(check_file(md, root))
    return problems, files


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) > 1:
        print(__doc__)
        return 2
    root = Path(argv[0]).resolve() if argv else Path(__file__).resolve().parents[1]
    problems, files = check_tree(root)
    if problems:
        for p in problems:
            print('[FAIL] ' + p)
        print('link check failed: %d problem(s) (%d files checked)'
              % (len(problems), files))
        return 1
    print('[OK] links (%d files checked)' % files)
    return 0


if __name__ == '__main__':
    sys.exit(main())
