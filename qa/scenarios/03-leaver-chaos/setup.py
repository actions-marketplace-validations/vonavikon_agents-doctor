#!/usr/bin/env python3
"""Scenario 3: departing-employee chaos. Blind checks for heavy cases: a secret
removed from the working copy but alive in the git index; a nested repo; a second
checkout; twin-drift; instructions for a dead harness; overloaded memory."""
import json
import os
import shutil
import stat
import subprocess
import time
from pathlib import Path

RUN = Path(__file__).parent / 'run'
WS = RUN / 'workspace'
HOME = RUN / 'home'


def rm_force(p):
    def _onexc(func, path, _exc):
        os.chmod(path, stat.S_IWRITE)
        func(path)
    shutil.rmtree(p, onexc=_onexc)


def w(base, rel, content=''):
    p = base / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding='utf-8') if isinstance(content, str) \
        else p.write_bytes(content)
    return p


def touch_old(p, days):
    t = time.time() - days * 86400
    os.utime(p, (t, t))


def git(p, *args, date=None):
    env = dict(os.environ)
    if date:
        env['GIT_AUTHOR_DATE'] = date
        env['GIT_COMMITTER_DATE'] = date
    subprocess.run(['git', '-C', str(p), '-c', 'user.name=Oleg Uhozhy',
                    '-c', 'user.email=o.uhozhy@example.com', *args],
                   check=True, capture_output=True, env=env)


if RUN.exists():
    rm_force(RUN)

# --- bloated root AGENTS.md with a generic block and dead links --------------
rules = [
    '# Правила', '',
    '- Деплой: `scripts/deploy.sh`',
    '- Регламент дежурств: `docs/runbook.md`',
    '', '## Структура репозитория', '',
    'Обзор для агента, чтобы он ориентировался в папках.', '',
]
rules += [f'Раздел {i:03d}: описание содержимого раздела, какие файлы здесь '
          f'встречаются и как с ними работать.' for i in range(380)]
w(WS, 'AGENTS.md', '\n'.join(rules) + '\n')
w(WS, '.mcp.json', json.dumps({
    'mcpServers': {
        'tasks': {
            'url': 'https://mcp.example.com/mcp',
            'headers': {'Authorization': 'sk-DEMO-9876543210fedcbaXYZ'}
        }
    }}, indent=2) + '\n')

# --- legacy-crm: secret in the index, nested repo, pre-push without untracked 
legacy = WS / 'legacy-crm'
w(WS, 'legacy-crm/.gitignore', 'vendor/\n')
w(WS, 'legacy-crm/README.md', '# legacy-crm\n')
w(WS, 'legacy-crm/config.py', 'api_key = "legacy-prod-key-777"\n')
git(legacy, 'init')
git(legacy, 'add', '-A')
git(legacy, 'commit', '-m', 'legacy', date='2026-09-15T12:00:00')
git(legacy, 'remote', 'add', 'origin', 'https://gitlab.example.com/legacy/crm.git')
w(WS, 'legacy-crm/.git/hooks/pre-push', '#!/bin/sh\ngit push origin main\n')
eng = WS / 'legacy-crm/vendor/engine'
w(WS, 'legacy-crm/vendor/engine/lib.js', 'module.exports = 1;\n')
git(eng, 'init')
git(eng, 'add', '-A')
git(eng, 'commit', '-m', 'vendored')
# secret removed from the working copy but still in the git index: blind test of block E
(WS / 'legacy-crm/config.py').unlink()

# --- second checkout of the same repo on a forgotten branch ------------------
hotfix = WS / 'legacy-crm-hotfix'
w(WS, 'legacy-crm-hotfix/README.md', '# hotfix\n')
git(hotfix, 'init')
git(hotfix, 'add', '-A')
git(hotfix, 'commit', '-m', 'hotfix base', date='2026-07-01T10:00:00')
git(hotfix, 'checkout', '-b', 'hotfix/payments')
git(hotfix, 'remote', 'add', 'origin', 'https://gitlab.example.com/legacy/crm.git')

# --- tools: twin-drift and instructions for a dead harness --------------------
tools = WS / 'tools'
w(WS, 'tools/AGENTS.md',
  '# tools\n\n'
  '- Утилиты сборки.\n'
  '- Справочник API: `docs/api.md`\n'
  '- Выкладка только через CI.\n'
  '- Обновлять зависимости раз в квартал.\n')
w(WS, 'tools/CLAUDE.md',
  '# CLAUDE.md\n\n'
  '- Сборка локально запрещена.\n'
  '- Тесты: `node --test`\n'
  '- Дефолты: `config/defaults.yaml`\n'
  '- Отчёты складывать в docs.\n')
git(tools, 'init')
git(tools, 'add', '-A')
git(tools, 'commit', '-m', 'tools', date='2026-08-10T16:00:00')

# --- valuables and junk outside git -------------------------------------------
w(WS, 'exports/data-dump.csv', b'0' * (8 * 1024 * 1024))
pdf = 'итоговый отчёт, версия для печати\n' * 120
w(WS, 'documents/отчет-v1.pdf', pdf)
w(WS, 'documents/отчет-v1 (копия).pdf', pdf)
for n, sz in {'IMG_001.jpg': 2048, 'IMG_2022_09_01.jpg': 3072,
              'IMG_2023_04_11.jpg': 1536}.items():
    w(WS, f'screenshots/{n}', b'\xff\xd8\xff\xe0' + b'\x00' * sz)
w(WS, 'старые презентации/слайды-2024.txt', 'текст слайдов\n')
w(WS, 'старые презентации/слайды-2025.txt', 'текст слайдов\n')
(WS / 'Новая папка').mkdir()

# --- skills: desync and oversized description ----------------------------------
w(WS, '.agents/skills/x-helper/SKILL.md',
  '---\n'
  'name: x-helper\n'
  'description: "' + 'аудит отчётов, протоколы, заметки, сводки, дайджесты. ' * 22 + '"\n'
  '---\n\n'
  '# x-helper\n\nПроектная версия с правками.\n')
w(WS, '.agents/skills/doc-helper/SKILL.md',
  '---\n'
  'name: doc-helper\n'
  'description: "Помогает с документами."\n'
  '---\n\n'
  '# doc-helper\n\nШаблонизатор документов.\n')

# --- home: live zcode, dead claude, overloaded memory --------------------------
w(HOME, '.zcode/AGENTS.md', '# Правила\n\n- Кратко.\n')
w(HOME, '.zcode/cli/history.jsonl', '{"t":"2026-10-30"}\n')
mem = ['# Memory index', '']
mem += [f'- [Заметка {i}](з{i}.md) — вывод по теме {i}, старые наблюдения, не проверял'
        for i in range(340)]
w(HOME, '.zcode/cli/memories/projects/demo/memory/MEMORY.md', '\n'.join(mem) + '\n')
w(HOME, '.zcode/skills/x-helper/SKILL.md',
  '---\n'
  'name: x-helper\n'
  'description: "' + 'сводки, протоколы, отчёты, дайджесты. ' * 10 + '"\n'
  '---\n\n'
  '# x-helper\n\nПользовательская версия.\n')
w(HOME, '.claude/CLAUDE.md', '# старые правила\n\n- кратко\n')
(HOME / '.claude/projects').mkdir()
for p in (HOME / '.claude', HOME / '.claude/CLAUDE.md', HOME / '.claude/projects'):
    touch_old(p, 200)

print('Scenario 3 created:', RUN)
