#!/usr/bin/env python3
"""Scenario 2: developer, moderate mess. Dead links, a secret in .env,
node_modules, identical skill copies (no desync), CLAUDE.md pointer."""
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
    subprocess.run(['git', '-C', str(p), '-c', 'user.name=Pavel Dev',
                    '-c', 'user.email=p.dev@example.com', *args],
                   check=True, capture_output=True, env=env)


if RUN.exists():
    rm_force(RUN)

# --- workspace ---------------------------------------------------------------
w(WS, 'AGENTS.md',
  '# Правила\n\n'
  '- Сборка: `scripts/build.sh`\n'
  '- Архитектура: `docs/arch.md`\n'
  '- Код-ревью в течение суток.\n'
  '- Коммит-месседжи по конвенции.\n'
  '- Секреты только в переменных окружения.\n')

api = WS / 'payments-api'
w(WS, 'payments-api/.gitignore', 'node_modules/\n')
w(WS, 'payments-api/src/index.js', 'const app = require("../lib");\napp.start();\n')
w(WS, 'payments-api/package.json', json.dumps({
    'name': 'payments-api', 'version': '2.1.0',
    'scripts': {'start': 'node src/index.js', 'test': 'node --test'}},
    indent=2) + '\n')
w(WS, 'payments-api/Makefile', 'lint:\n\tnpx eslint .\n\ntest:\n\tnpm run test\n')
w(WS, 'payments-api/AGENTS.md',
  '# payments-api\n\n'
  '- Запуск: `npm run start`\n'
  '- Тесты: `npm run test`\n'
  '- Линт: `make lint`\n'
  '- Точка входа: `src/index.js`\n')
w(WS, 'payments-api/CLAUDE.md',
  '# CLAUDE.md\n\n'
  '- Основные правила: @AGENTS.md\n'
  '- Дополнения только через ревью.\n'
  '- Перед пушем тесты обязательны.\n')
git(api, 'init')
git(api, 'add', '-A')
git(api, 'commit', '-m', 'api', date='2026-10-30T09:00:00')
git(api, 'remote', 'add', 'origin', 'https://gitlab.example.com/payments/api.git')

notes = WS / 'notes'
w(WS, 'notes/plan.md', '- распродажа осенью\n- обновить лендинг\n')
git(notes, 'init')
git(notes, 'add', '-A')
git(notes, 'commit', '-m', 'plan', date='2026-05-20T14:00:00')
w(WS, 'notes/plan.md', '- распродажа осенью\n- обновить лендинг\n- придумать акцию к НГ\n')
w(WS, 'notes/скриншот-бейдж.png', b'\x89PNG' + b'\x00' * 2048)

w(WS, 'sandbox/index.js', 'try { require("lib1") } catch (e) {}\n')
w(WS, 'sandbox/node_modules/lib1/index.js', 'module.exports = 1;\n' + 'y' * 4096)

w(WS, '.env', 'DB_PASSWORD="DEMO-hunter2-password"\n')

lint_helper = (
    '---\n'
    'name: lint-helper\n'
    'description: "Использовать, когда просят проверить стиль кода или прогнать линт."\n'
    '---\n\n'
    '# lint-helper\n\nПодсказки по линтеру команды.\n')
w(WS, '.agents/skills/lint-helper/SKILL.md', lint_helper)
w(HOME, '.zcode/skills/lint-helper/SKILL.md', lint_helper)

# --- home --------------------------------------------------------------------
w(HOME, '.zcode/AGENTS.md', '# Правила\n\n- Писать кратко.\n')
w(HOME, '.zcode/cli/history.jsonl', '{"t":"2026-10-30"}\n')
mem = ['# Memory index', '']
mem += [f'- [Заметка {i}](з{i}.md) — вывод по теме {i}, проверен' for i in range(100)]
w(HOME, '.zcode/cli/memories/projects/demo/memory/MEMORY.md', '\n'.join(mem) + '\n')
w(HOME, '.codex/config.toml', 'model = "gpt-5"\n')
touch_old(HOME / '.codex', 45)
touch_old(HOME / '.codex/config.toml', 45)

print('Scenario 2 created:', RUN)
