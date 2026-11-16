#!/usr/bin/env python3
"""Builds a fictional workspace + fake home for the workspace-audit plugin demo.

All tokens, keys and hosts in the fixtures are synthetic.
"""
import json
import os
import shutil
import stat
import subprocess
import time
from pathlib import Path

BASE = Path(__file__).parent
ROOT = BASE / 'employee-workspace'
HOME = BASE / 'fake-home'


def rm_force(p):
    def _onexc(func, path, _exc):
        os.chmod(path, stat.S_IWRITE)
        func(path)
    shutil.rmtree(p, onexc=_onexc)


def w(base, rel, content=''):
    p = base / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        p.write_bytes(content)
    else:
        p.write_text(content, encoding='utf-8')
    return p


def touch_old(p, days):
    t = time.time() - days * 86400
    os.utime(p, (t, t))


def git(p, *args, date=None):
    env = dict(os.environ)
    if date:
        env['GIT_AUTHOR_DATE'] = date
        env['GIT_COMMITTER_DATE'] = date
    subprocess.run(
        ['git', '-C', str(p), '-c', 'user.name=Ivan Petrov',
         '-c', 'user.email=i.petrov@example.com', *args],
        check=True, capture_output=True, env=env)


for d in (ROOT, HOME):
    if d.exists():
        rm_force(d)

# --- 1. reports-service: live repo with an autosync hook --------------------
svc = ROOT / 'reports-service'
w(ROOT, 'reports-service/src/main.js',
  'const http = require("http");\n'
  'http.createServer((q, s) => s.end("ok")).listen(3000);\n')
w(ROOT, 'reports-service/package.json', json.dumps({
    'name': 'reports-service', 'version': '1.0.0',
    'scripts': {'start': 'node src/main.js'}}, indent=2) + '\n')
w(ROOT, 'reports-service/README.md',
  '# reports-service\n\nСервис отчётности.\n\nДокументация API: [docs/api.md](docs/api.md)\n')
w(ROOT, 'reports-service/AGENTS.md',
  '# reports-service\n\n'
  'Сервис отчётности на Node.js.\n\n'
  '- Деплой: `scripts/deploy.sh`\n'
  '- Справочник API: `docs/api.md`\n'
  '- Тесты: `npm run test`\n'
  '- Линт: `make lint`\n'
  '- Формат отчёта описан в `src/formatters/report.js`\n')
w(ROOT, 'reports-service/CLAUDE.md',
  '# CLAUDE.md\n\n'
  '- Node 20, запуск `npm run start`\n'
  '- Тесты: `node --test`\n'
  '- Дефолтный конфиг: `config/defaults.json`\n')
git(svc, 'init')
git(svc, 'add', '-A')
git(svc, 'commit', '-m', 'init', date='2026-10-28T18:20:00')
git(svc, 'remote', 'add', 'origin', 'https://gitlab.example.com/reports/reports-service.git')
w(ROOT, 'reports-service/src/main.js',
  'const http = require("http");\n'
  '// TODO: вынести порт в конфиг\n'
  'http.createServer((q, s) => s.end("ok")).listen(3000);\n')
git(svc, 'add', '-A')
git(svc, 'commit', '-m', 'sync: автокоммит сессии 2026-10-29', date='2026-10-29T09:00:00')
w(ROOT, 'reports-service/.git/hooks/pre-commit',
  '#!/bin/sh\ngit add -A\ngit push origin main\n')
w(ROOT, 'reports-service/src/main.js',
  'const http = require("http");\n'
  '// TODO: вынести порт в конфиг\n'
  '// TODO: добавить health-check\n'
  'http.createServer((q, s) => s.end("ok")).listen(3000);\n')
w(ROOT, 'reports-service/scratch-notes.md', 'черновик: перевести деплой на docker\n')

# --- 2. reports-service-copy: second checkout of the same repo --------------
cp = ROOT / 'reports-service-copy'
w(ROOT, 'reports-service-copy/README.md', '# копия для экспериментов\n')
git(cp, 'init')
git(cp, 'add', '-A')
git(cp, 'commit', '-m', 'experiment base', date='2026-06-01T12:00:00')
git(cp, 'checkout', '-b', 'experiment/v2')
git(cp, 'remote', 'add', 'origin', 'https://gitlab.example.com/reports/reports-service.git')

# --- 3. old-prototype: abandoned, creds in the remote URL, secret in a commit -
old = ROOT / 'old-prototype'
w(ROOT, 'old-prototype/server.js',
  'const app = require("./app");\n'
  'const API_KEY = "demo-secret-do-not-use";\n'
  'app.listen(8080);\n')
w(ROOT, 'old-prototype/TODO.txt', '- прикрутить авторизацию\n- переписать на новый API\n')
git(old, 'init')
git(old, 'add', '-A')
git(old, 'commit', '-m', 'prototype', date='2026-02-14T11:30:00')
git(old, 'remote', 'add', 'origin',
    'https://oauth2:glpat-DEMO000000000000@gitlab.example.com/old/prototype.git')
w(ROOT, 'old-prototype/TODO.txt',
  '- прикрутить авторизацию\n- переписать на новый API\n- спросить у Антона про вебхуки\n')
w(ROOT, 'old-prototype/debug.log',
  '2026-02-14 11:31:02 GET /health 200\n2026-02-14 11:31:05 GET /report 500\n')

# --- 4. partner-upload: valuables outside git -------------------------------
payload = ('расчёт, выручка, план;\n' * 450)
w(ROOT, 'partner-upload/Отчёт_финал_версия2.xlsx', payload)
w(ROOT, 'partner-upload/отчет-финал-ФИНАЛ.xlsx', payload)
w(ROOT, 'partner-upload/backup_2026-03/Отчёт_март.xlsx', payload)
w(ROOT, 'partner-upload/IMG_20260115_1243.jpg', b'\xff\xd8\xff\xe0' + b'\x00' * 4096)
w(ROOT, 'partner-upload/временный анализ.py', 'import pandas as pd\n# быстро прикинуть\n')
w(ROOT, 'partner-upload/видео-презентация.mp4', b'\x00' * (6 * 1024 * 1024))

# --- 5. node-sandbox: outside git, node_modules ------------------------------
w(ROOT, 'node-sandbox/index.js', 'const _ = require("lodash");\nconsole.log(_.chunk([1, 2, 3], 2));\n')
for i in range(12):
    w(ROOT, f'node-sandbox/node_modules/pkg{i}/index.js', 'module.exports = 1;\n' + 'x' * 8192)

# --- 6. root: bloated AGENTS.md + skill duplicate + misc ---------------------
rules = [
    '# Правила рабочего пространства',
    '',
    '- Деплой сервисов: только через `scripts/deploy.sh`',
    '- Термины и сокращения: `docs/glossary.md`',
    '- Спринт-отчёты складывать в `reports/`',
    '- Стиль кода: `rules/coding-style.md`',
    '',
    '## Как устроен этот workspace',
    '',
    'Шаблон правил: Drop this file into your project as CLAUDE.md.',
    '',
]
rules += [f'Раздел {i:02d}: в этой части пространства лежат рабочие материалы; '
          f'ниже перечислено, что в нём встречается, как это принято называть и где искать похожее.'
          for i in range(140)]
w(ROOT, 'AGENTS.md', '\n'.join(rules) + '\n')
w(ROOT, '.mcp.json', json.dumps({
    'mcpServers': {
        'task-portal': {
            'url': 'https://mcp.example.com/mcp',
            'headers': {'Authorization': 'sk-DEMO-1234567890abcdefXYZ'}
        }
    }}, indent=2) + '\n')
w(ROOT, 'temp-add.html', '<html><body>черновик карточки</body></html>\n')
(ROOT / 'Новая папка (2)').mkdir()
w(ROOT, '.agents/skills/demo-helper/SKILL.md',
  '---\n'
  'name: demo-helper\n'
  'description: "Использовать, когда просят собрать еженедельный отчёт или протокол встречи."\n'
  '---\n\n'
  '# demo-helper\n\nПравленая копия от октября.\n')

# --- 7. fake home: live zcode, dead claude and codex -------------------------
w(HOME, '.zcode/AGENTS.md',
  '# Глобальные правила\n\n'
  '- Отвечать по-деловому, без воды.\n'
  '- Длинные отчёты сначала показывать черновиком.\n')
w(HOME, '.zcode/cli/history.jsonl', '{"t":"2026-10-30"}\n')
mem = ['# Memory index', '']
mem += [f'- [Заметка {i}](заметка-{i}.md) — выводы по теме {i}, старые наблюдения, давно не проверял'
        for i in range(320)]
w(HOME, '.zcode/cli/memories/projects/demo/memory/MEMORY.md', '\n'.join(mem) + '\n')
w(HOME, '.zcode/skills/demo-helper/SKILL.md',
  '---\n'
  'name: demo-helper\n'
  f'description: "{"аудит отчётов, протоколы встреч, заметки, сводки, дайджесты. " * 26}"\n'
  '---\n\n'
  '# demo-helper\n\nПомогает с отчётами.\n')
w(HOME, '.claude/CLAUDE.md', '# старые правила для Claude Code\n\n- отвечать кратко\n')
(HOME / '.claude/projects').mkdir()
w(HOME, '.codex/config.toml', 'model = "gpt-5"\n')
touch_old(HOME / '.claude', 120)
touch_old(HOME / '.claude/CLAUDE.md', 120)
touch_old(HOME / '.claude/projects', 120)
touch_old(HOME / '.codex', 240)
touch_old(HOME / '.codex/config.toml', 240)

print('Demo created:', ROOT)
print('Fake home:', HOME)
