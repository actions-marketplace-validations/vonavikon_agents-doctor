#!/usr/bin/env python3
"""Validate the plugin manifests and top-level packaging of workspace-audit.

Checks (exit 0 = all pass, exit 1 = any problem, problems printed):
  - .claude-plugin/plugin.json and marketplace.json exist and parse as JSON
  - plugin.json has non-empty name, version, description and author.name
  - marketplace.json plugins[0] name and version match plugin.json
  - skills/<plugin name>/ exists and contains SKILL.md
  - SKILL.md frontmatter `name` matches the skill directory name
    (flat `key: value` parser, no YAML dependency)
  - LICENSE and README.md exist at the repo root

Intentionally skipped: the "no .pyc tracked" git check (needs git history).
Python 3.9+, stdlib only.
"""
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def parse_frontmatter(text):
    """Flat frontmatter parser: `key: value` lines between the first --- pair."""
    lines = text.splitlines()
    if not lines or lines[0].strip() != '---':
        return {}
    fm = {}
    for ln in lines[1:]:
        s = ln.strip()
        if s == '---':
            break
        if s.startswith('#') or ':' not in s:
            continue
        k, v = s.split(':', 1)
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in '"\'':
            v = v[1:-1]
        fm[k.strip()] = v
    return fm


def main():
    problems = []
    pj_path = REPO / '.claude-plugin' / 'plugin.json'
    mk_path = REPO / 'marketplace.json'
    pj = mk = None

    for label, path in [('plugin.json', pj_path), ('marketplace.json', mk_path)]:
        if not path.is_file():
            problems.append(f'{label}: missing at {path.relative_to(REPO)}')
            continue
        try:
            parsed = json.loads(path.read_text(encoding='utf-8'))
        except ValueError as e:
            problems.append(f'{label}: does not parse as JSON: {e}')
            continue
        if not isinstance(parsed, dict):
            problems.append(f'{label}: top level is not an object')
            continue
        if label == 'plugin.json':
            pj = parsed
        else:
            mk = parsed

    if pj is not None:
        for key in ('name', 'version', 'description'):
            if not str(pj.get(key, '')).strip():
                problems.append(f'plugin.json: empty or missing "{key}"')
        author = pj.get('author')
        if not (isinstance(author, dict) and str(author.get('name', '')).strip()):
            problems.append('plugin.json: empty or missing "author.name"')

        skill_dir = REPO / 'skills' / str(pj.get('name', ''))
        if not str(pj.get('name', '')).strip():
            pass  # already reported above
        elif not skill_dir.is_dir():
            problems.append(f'skills/{pj.get("name")}/: directory does not exist')
        elif not (skill_dir / 'SKILL.md').is_file():
            problems.append(f'skills/{pj.get("name")}/SKILL.md: missing')
        else:
            fm = parse_frontmatter((skill_dir / 'SKILL.md').read_text(encoding='utf-8'))
            fm_name = str(fm.get('name', '')).strip()
            if not fm_name:
                problems.append('SKILL.md: frontmatter has no "name" key')
            elif fm_name != str(pj.get('name')):
                problems.append(f'SKILL.md: frontmatter name "{fm_name}" does not match '
                                f'directory "{pj.get("name")}"')

    if mk is not None:
        plugins = mk.get('plugins')
        if not isinstance(plugins, list) or not plugins:
            problems.append('marketplace.json: "plugins" is missing or empty')
        elif pj is not None:
            p0 = plugins[0]
            if not isinstance(p0, dict) or p0.get('name') != pj.get('name'):
                problems.append(f'marketplace.json: plugins[0].name {p0.get("name")!r} '
                                f'does not match plugin.json name {pj.get("name")!r}')
            if not isinstance(p0, dict) or p0.get('version') != pj.get('version'):
                problems.append(f'marketplace.json: plugins[0].version {p0.get("version")!r} '
                                f'does not match plugin.json version {pj.get("version")!r}')

    for extra in ('LICENSE', 'README.md'):
        if not (REPO / extra).is_file():
            problems.append(f'{extra}: missing at repo root')

    if problems:
        for p in problems:
            print(f'[FAIL] {p}')
        print(f'manifest validation failed: {len(problems)} problem(s)')
        return 1
    print('[OK] manifest')
    return 0


if __name__ == '__main__':
    sys.exit(main())
