#!/usr/bin/env python3
"""Scenario 1: clean newbie workspace. False-positive checks: valid links, env vars
instead of secrets, a healthy skill must not be flagged."""
import os
import shutil
import stat
import subprocess
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


def git(p, *args, date=None):
    env = dict(os.environ)
    if date:
        env['GIT_AUTHOR_DATE'] = date
        env['GIT_COMMITTER_DATE'] = date
    subprocess.run(['git', '-C', str(p), '-c', 'user.name=Anna Novichok',
                    '-c', 'user.email=a.novichok@example.com', *args],
                   check=True, capture_output=True, env=env)


if RUN.exists():
    rm_force(RUN)

# --- workspace ---------------------------------------------------------------
w(WS, 'AGENTS.md',
  '# Правила пространства\n\n'
  '- Онбординг: `docs/onboarding.md`\n'
  '- Спринт-отчёты: `reports/`\n'
  '- Перед коммитом прогонять тесты.\n'
  '- Согласование длинных текстов: сначала черновик.\n')
w(WS, 'docs/onboarding.md', '# Онбординг\n\nПервые шаги на проекте.\n')
w(WS, 'reports/2026-10.md', '# Спринт, октябрь\n\nИтоги спринта.\n')

repo = WS / 'docs-vault'
w(WS, 'docs-vault/.gitignore', 'temp/\n')
w(WS, 'docs-vault/README.md', '# docs-vault\n\nБаза знаний команды.\n')
w(WS, 'docs-vault/src/config.py',
  'import os\n\nAPI_KEY = os.environ["API_KEY"]\nDB = os.environ.get("DB_URL")\n')
git(repo, 'init')
git(repo, 'add', '-A')
git(repo, 'commit', '-m', 'docs base', date='2026-10-29T10:00:00')
git(repo, 'remote', 'add', 'origin', 'https://gitlab.example.com/infra/docs-vault.git')

w(WS, 'incoming/temp-notes.md', 'быстрые заметки созвона\n')
w(WS, 'incoming/памятка.docx', 'памятка по процессу, текстовая заглушка\n')

w(WS, '.agents/skills/report-helper/SKILL.md',
  '---\n'
  'name: report-helper\n'
  'description: "Использовать, когда просят собрать спринт-отчёт или еженедельную сводку."\n'
  '---\n\n'
  '# report-helper\n\nСобирает сводки по шаблону.\n')

# --- home --------------------------------------------------------------------
w(HOME, '.zcode/AGENTS.md',
  '# Глобальные правила\n\n- Отвечать по делу.\n- Не выдумывать факты.\n')
w(HOME, '.zcode/cli/history.jsonl', '{"t":"2026-10-30"}\n')
mem = ['# Memory index', '']
mem += [f'- [Тема {i}](т{i}.md) — короткий вывод' for i in range(60)]
w(HOME, '.zcode/cli/memories/projects/demo/memory/MEMORY.md', '\n'.join(mem) + '\n')

print('Scenario 1 created:', RUN)
