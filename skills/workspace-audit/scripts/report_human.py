#!/usr/bin/env python3
"""Render a scan.json report as plain-language markdown for non-technical readers.

    python report_human.py <scan.json> [--lang en|ru] [--sessions 10]
                            [--after <scan2.json>] [--out HUMAN-REPORT.md]

English or Russian. With --after (a second scan made after cleanup) the
report gains a "What gets better after cleanup" section that compares the
two scans. The generator is pure formatting: it reads the report dict,
never the filesystem, and never touches secret values (counts only).

All token and cost figures are estimates; every assumption is printed
next to the numbers it feeds. Python 3.9+, stdlib only.
"""
import argparse
import json
import re
import sys
from pathlib import Path

SEVERITY_RANK = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
OPEN_STATUSES = ('fail', 'warn')

PROJECT_BENCHMARK_DEFAULT = 16384
MEMORY_LIMIT_BYTES = 24985
DAYS_PER_MONTH = 30
DEFAULT_SESSIONS_PER_DAY = 10

KB = 1024
MB = 1024 ** 2
GB = 1024 ** 3
THIN = '\u202f'  # narrow no-break space: RU thousands separator, unit gap

MAX_WRONG_BULLETS = 6
MAX_TODO = 3

# Plain-language task for a still-failing gate, by gate id.
GID_PLAIN = {
    'G1': {'en': 'put the folder layout in order',
           'ru': 'навести порядок в структуре папок'},
    'G2': {'en': 'repair the settings files',
           'ru': 'починить файлы настроек'},
    'G3': {'en': 'fix the instruction files',
           'ru': 'исправить файлы инструкций'},
    'G4': {'en': 'decide the fate of the loose folders',
           'ru': 'решить судьбу свободных папок'},
    'G5': {'en': 'repair the helper skills',
           'ru': 'починить вспомогательные навыки'},
    'G6': {'en': 'rotate and hide the passwords',
           'ru': 'сменить и спрятать пароли'},
    'G7': {'en': 'save the unfinished work to history',
           'ru': 'сохранить незавершённую работу в историю изменений'},
    'G8': {'en': 'remove rules for tools nobody uses',
           'ru': 'убрать правила для неиспользуемых инструментов'},
    'G9': {'en': 'clear out the remaining junk',
           'ru': 'разобрать оставшийся мусор'},
}

STRINGS = {
    'en': {
        'title': 'What the audit found — in plain words',
        'subtitle': 'Folder checked: {root}',
        'h_short': 'The short version',
        'state_fail': 'Of {total} checks, {fail} are red and {warn} are yellow: '
                      'the workspace still works, but the mess is big enough '
                      'to slow every agent down.',
        'state_warn': 'Of {total} checks, none is red and {warn} are yellow: '
                      'the workspace is in decent shape, with a few things '
                      'to tidy up.',
        'state_ok': 'All {total} checks pass: the workspace is clean, and '
                    'the agents carry no dead weight.',
        'main_problem': 'The main problem: {sentence}',
        'promise': 'Cleanup can make every agent start faster and waste less.',
        'h_costs': 'What this costs you',
        'cost_tokens': 'Every session starts with about {lo}–{hi} extra tokens '
                       'of instructions and memory the agent does not need '
                       '(best estimate: {mid}).',
        'cost_monthly': 'Over a month that makes roughly {mlo}–{mhi} extra '
                        'tokens (best estimate: {mmid}).',
        'cost_assumption': 'The monthly figure assumes {sessions} agent '
                           'sessions a day and {days} days a month.',
        'cost_tokens_zero': 'Instructions and memory fit within healthy sizes: '
                            'no extra tokens are loaded at every start.',
        'cost_memory': 'The agent memory file is {kb} over the limit, and '
                       'everything past the limit is cut off — that part of '
                       'your notes the agent never sees.',
        'cost_junk': 'Junk files and folders take up {size}.',
        'cost_dup': 'Verified duplicate copies add another {size}.',
        'cost_large': 'Large files without a backup hold {size}.',
        'cost_disk_zero': 'No junk, duplicates or oversized files '
                          'were found.',
        'cost_secrets': '{n} passwords or keys are left in plain sight, in '
                        'files or in saved history; the values themselves '
                        'are not shown here.',
        'cost_secrets_one': '{n} password or key is left in plain sight, in '
                            'files or in saved history; the value itself '
                            'is not shown here.',
        'cost_secrets_zero': 'No passwords or keys are lying in plain sight.',
        'foot_quality': 'Why it matters: with a long context, background '
                        'noise measurably lowers the quality of the answers.',
        'foot_tokens': 'How tokens are counted: an estimate of 4 bytes per '
                       'token; depending on the language of the text the '
                       'real ratio sits between 3 and 5 bytes per token.',
        'h_wrong': 'What is wrong, in plain words',
        'wrong_none': 'Nothing serious: no checks failed.',
        'plain_secrets': 'A password/key is sitting in a file where it '
                         'should not be',
        'plain_no_prevention': 'Nothing guards against passwords '
                               'slipping into saved work',
        'plain_heavy': 'A folder with {size} of data has no backup and '
                       'no history',
        'plain_heavy_nosize': 'A folder with a lot of data has no backup '
                              'and no history',
        'plain_unowned': 'Some folders are outside any backup: their content '
                         'has no history',
        'plain_nested': 'One project sits inside another project, which '
                        'confuses backup and sync tools',
        'plain_drift': 'Two instruction files disagree — the agent gets '
                       'conflicting rules',
        'plain_dead': "The agent's instructions point to things that do "
                      'not exist',
        'plain_boiler': 'Part of the instructions is template text that '
                        'gives the agent no useful rules',
        'plain_fat': 'The instructions have grown too big; the agent pays '
                     'for the extra on every start',
        'plain_skills': 'A helper skill is set up wrong and never runs',
        'plain_git': 'Work is not saved to history yet',
        'plain_config': 'A settings file is broken',
        'plain_noconfig': 'No settings files were found — worth checking why',
        'plain_gov': 'Rules are kept for a tool nobody has used in months',
        'plain_health': 'Unused files and old copies are piling up in '
                        'the workspace',
        'h_better': 'What gets better after cleanup',
        'better_gates': 'Red checks went from {f1} to {f2}, yellow from '
                        '{w1} to {w2}.',
        'better_slim': 'Agent instructions slimmed from {x} to {y} — about '
                       '{z} fewer tokens every session.',
        'better_tokens': 'Extra tokens per start went from about {a} to {b}.',
        'better_junk': 'Junk went from {a} to {b}.',
        'better_secrets': 'Secrets in plain sight went from {a} to {b}.',
        'better_secrets_zero': 'Secrets in plain sight went from {a} to none.',
        'still_todo': '**Still to do:**',
        'h_next': 'Next step',
        'next_1': 'Run the safe cleanup (`safe_clean.py`): it works through '
                  'the findings one at a time and asks before every change.',
        'next_2': 'Then run the audit again: the second report shows the '
                  '"after" picture and what improved.',
        'next_3': 'This audit changed nothing: it only read files and '
                  'counted.',
        'footer': 'Read-only audit: nothing was modified. Generated {ts}. '
                  'The numbers are estimates, not bills: they show the '
                  'order of magnitude.',
    },
    'ru': {
        'title': 'Что нашла проверка — простыми словами',
        'subtitle': 'Проверенная папка: {root}',
        'h_short': 'Коротко',
        'state_fail': 'Из {total} проверок {fail} {failw} и {warn} {warnw}: '
                      'работать ещё можно, но беспорядка уже хватает, '
                      'чтобы тормозить агента.',
        'state_warn': 'Из {total} проверок ни одна не красная, {warn} {warnw}: '
                      'с рабочей папкой всё в порядке, хотя есть '
                      'что прибрать.',
        'state_ok': 'Все {total} проверок зелёные: рабочая папка чистая, '
                    'и агент не тащит за собой ничего лишнего.',
        'main_problem': 'Главная проблема: {sentence}',
        'promise': 'После уборки агент будет стартовать быстрее '
                   'и тратить меньше.',
        'h_costs': 'Во сколько это обходится',
        'cost_tokens': 'При каждом запуске агент получает примерно {lo}–{hi} '
                       'лишних токенов инструкций и памяти, которые ему '
                       'не нужны (лучшая оценка: {mid}).',
        'cost_monthly': 'За месяц набегает порядка {mlo}–{mhi} лишних '
                        'токенов (лучшая оценка: {mmid}).',
        'cost_assumption': 'Месячная оценка исходит из {sessions} запусков '
                           'агента в день и {days} дней в месяце.',
        'cost_tokens_zero': 'Инструкции и память укладываются в здоровые '
                            'размеры: при запуске ничего лишнего '
                            'не загружается.',
        'cost_memory': 'Файл памяти агента превышает лимит на {kb}, и всё '
                       'сверх лимита обрезается — эту часть ваших заметок '
                       'агент никогда не видит.',
        'cost_junk': 'Мусорные файлы и папки занимают {size}.',
        'cost_dup': 'Подтверждённые дубликаты добавляют ещё {size}.',
        'cost_large': 'Большие файлы без резервной копии занимают {size}.',
        'cost_disk_zero': 'Мусора, дубликатов и слишком больших файлов '
                          'не нашлось.',
        'cost_secrets': 'На виду — в файлах или в сохранённой истории — '
                        'осталось {n} {parols} и {keys}; сами значения '
                        'здесь не показываем.',
        'cost_secrets_one': 'На виду — в файле или в сохранённой истории — '
                            'остался пароль или ключ; само значение '
                            'здесь не показываем.',
        'cost_secrets_zero': 'Паролей и ключей на виду нет.',
        'foot_quality': 'Почему это важно: в длинном контексте фоновый шум '
                        'заметно снижает качество ответов.',
        'foot_tokens': 'Как считаются токены: оценка — 4 байта на токен; '
                       'в зависимости от языка текста реальное отношение — '
                       'от 3 до 5 байт на токен.',
        'h_wrong': 'Что не так, по-человечески',
        'wrong_none': 'Серьёзного ничего нет: проваленных проверок нет.',
        'plain_secrets': 'В файле лежит пароль/ключ, где его быть не должно',
        'plain_no_prevention': 'Ничто не мешает паролям попасть '
                               'в сохранённую работу',
        'plain_heavy': 'Папка объёмом {size} без резервной копии и истории '
                       'изменений',
        'plain_heavy_nosize': 'Большая папка без резервной копии и истории '
                              'изменений',
        'plain_unowned': 'Некоторые папки вне любых резервных копий: '
                         'у их содержимого нет истории',
        'plain_nested': 'Один проект лежит внутри другого проекта, и это '
                        'путает инструменты синхронизации и резервного '
                        'копирования',
        'plain_drift': 'Два файла инструкций противоречат друг другу — '
                       'агент получает конфликтные правила',
        'plain_dead': 'Инструкции агента ссылаются на то, чего не существует',
        'plain_boiler': 'Часть инструкций — шаблонный текст, который не даёт '
                        'агенту полезных правил',
        'plain_fat': 'Инструкции разрослись, и агент переплачивает за '
                     'лишнее при каждом запуске',
        'plain_skills': 'Вспомогательный навык настроен неправильно и '
                        'никогда не запускается',
        'plain_git': 'Работа ещё не сохранена в историю',
        'plain_config': 'Файл настроек повреждён',
        'plain_noconfig': 'Файлы настроек не нашлись — стоит проверить почему',
        'plain_gov': 'Правила поддерживаются для инструмента, которым '
                     'давно не пользуются',
        'plain_health': 'В рабочей папке копятся неиспользуемые файлы '
                        'и старые копии',
        'h_better': 'Что станет лучше после уборки',
        'better_gates': 'Красных проверок стало {f2} вместо {f1}, жёлтых — '
                        '{w2} вместо {w1}.',
        'better_slim': 'Инструкции агента похудели с {x} до {y} — примерно '
                       'на {z} токенов меньше при каждом запуске.',
        'better_tokens': 'Лишних токенов при запуске было около {a}, '
                         'стало около {b}.',
        'better_junk': 'Мусора было {a}, стало {b}.',
        'better_secrets': 'Паролей на виду было {a}, стало {b}.',
        'better_secrets_zero': 'Паролей на виду было {a}, стало ноль.',
        'still_todo': '**Ещё осталось:**',
        'h_next': 'Что дальше',
        'next_1': 'Запустите безопасную уборку (`safe_clean.py`): она '
                  'проходит находки по одной и спрашивает перед каждым '
                  'изменением.',
        'next_2': 'Потом запустите проверку ещё раз: второй отчёт покажет '
                  'картину «после» и то, что изменилось.',
        'next_3': 'Эта проверка ничего не меняла: она только читала файлы '
                  'и считала.',
        'footer': 'Проверка только читает: ничего не менялось. Отчёт собран '
                  '{ts}. Числа — оценки, а не счета: они показывают порядок '
                  'величины.',
    },
}


# --------------------------------------------------------------------------
# value math
# --------------------------------------------------------------------------

def tokens_from_bytes(b):
    """Mixed English text heuristic: about 4 bytes per token."""
    return b // 4


def token_range(b):
    """(low, mid, high) token estimates for b bytes.

    mid is the working estimate (b // 4); low and high come from the
    5-bytes-per-token and 3-bytes-per-token bounds documented in the
    report footnote.
    """
    return b // 5, b // 4, b // 3


def session_overhead_bytes(rep):
    """Bytes the agent re-reads beyond healthy sizes on every start.

    Two parts, both printed as assumptions in the report:
    - project instructions above the 16 KB benchmark (other roles are
      small by design and cost nothing here);
    - memory-index files over the memory limit; the same path listed in
      both memory_over_limit and memory_over_lines is counted once
      (over-limit bytes approximated as size - 24985).
    """
    ct = rep.get('context_tax') or {}
    bench = ct.get('benchmark_project_bytes', PROJECT_BENCHMARK_DEFAULT)
    total = 0
    sizes = {}
    for f in ct.get('session_files', []):
        sizes[f.get('path')] = f.get('size_bytes', 0)
        if f.get('role') == 'project':
            total += max(0, f.get('size_bytes', 0) - bench)
    over_paths = []
    for key in ('memory_over_limit', 'memory_over_lines'):
        for p in ct.get(key) or []:
            if p not in over_paths:
                over_paths.append(p)
    for p in over_paths:
        total += max(0, sizes.get(p, 0) - MEMORY_LIMIT_BYTES)
    return total


def memory_over_bytes(rep):
    """Bytes of memory-index content above the limit (paths deduped)."""
    ct = rep.get('context_tax') or {}
    sizes = {f.get('path'): f.get('size_bytes', 0)
             for f in ct.get('session_files', [])}
    over_paths = []
    for key in ('memory_over_limit', 'memory_over_lines'):
        for p in ct.get(key) or []:
            if p not in over_paths:
                over_paths.append(p)
    return sum(max(0, sizes.get(p, 0) - MEMORY_LIMIT_BYTES)
               for p in over_paths)


def junk_bytes(rep):
    junk = rep.get('junk') or {}
    files = sum(f.get('size_bytes', 0) for f in junk.get('files') or [])
    dirs = sum(d.get('size_bytes', 0) for d in junk.get('dirs') or [])
    return files + dirs


def duplicates_bytes(rep):
    """Space reclaimable from hash-proven duplicates: every redundant
    copy (all but one per group) is waste."""
    return sum(g.get('size_bytes', 0) * max(0, len(g.get('files') or []) - 1)
               for g in rep.get('duplicates') or [])


def large_files_bytes(rep):
    return sum(f.get('size_bytes', 0) for f in rep.get('large_files') or [])


def project_instruction_bytes(rep):
    ct = rep.get('context_tax') or {}
    total = sum(f.get('size_bytes', 0) for f in ct.get('session_files', [])
                if f.get('role') == 'project')
    return total if total else ct.get('project_total_bytes', 0)


def open_secret_count(rep):
    """Open secret findings (exposed or tracked in git). Falls back to
    the raw secrets[] count when findings are not detailed."""
    n = sum(1 for f in rep.get('findings_detailed') or []
            if f.get('category') == 'secrets' and f.get('status') == 'fail')
    if n == 0 and rep.get('secrets'):
        n = len(rep['secrets'])
    return n


def gate_counts(rep):
    fails = sum(1 for g in rep.get('gates') or []
                if g.get('status') == 'fail')
    warns = sum(1 for g in rep.get('gates') or []
                if g.get('status') == 'warn')
    return fails, warns


# --------------------------------------------------------------------------
# number formatting
# --------------------------------------------------------------------------

def fmt_int(n, lang):
    """Grouped integer: EN commas, RU narrow spaces."""
    s = f'{n:,}'
    return s.replace(',', THIN) if lang == 'ru' else s


def _fmt_value(v, lang):
    """One decimal at most; RU uses a comma as the decimal separator."""
    if v >= 100 or abs(v - round(v)) < 0.05:
        s = str(int(round(v)))
    else:
        s = f'{v:.1f}'
    return s.replace('.', ',') if lang == 'ru' else s


def _ru_plural(n, one, few, many):
    n100, n10 = n % 100, n % 10
    if 11 <= n100 <= 14:
        return many
    if n10 == 1:
        return one
    if 2 <= n10 <= 4:
        return few
    return many


def _ru_count_adj(n, one, many):
    """Agreement for a counted adjective used as a substantive
    («1 красная», «2/6 красных»)."""
    return one if n % 10 == 1 and n % 100 != 11 else many


def human_bytes(n, lang):
    """Human-friendly size: KB/MB/GB, rounded, locale-style separators."""
    if lang == 'ru':
        units = {'kb': 'КБ', 'mb': 'МБ', 'gb': 'ГБ'}
    else:
        units = {'kb': 'KB', 'mb': 'MB', 'gb': 'GB'}
    if n >= GB:
        v, key = n / GB, 'gb'
    elif n >= MB:
        v, key = n / MB, 'mb'
    elif n >= KB:
        v, key = n / KB, 'kb'
    else:
        if lang == 'ru':
            word = _ru_plural(n, 'байт', 'байта', 'байт')
            return fmt_int(n, lang) + THIN + word
        return f'{n} byte' if n == 1 else f'{n} bytes'
    sep = THIN if lang == 'ru' else ' '
    return _fmt_value(v, lang) + sep + units[key]


# --------------------------------------------------------------------------
# plain-language sentence mapping
# --------------------------------------------------------------------------

_SIZE_RE = re.compile(r'\s*([\d.]+)\s*(B|KB|MB|GB)?', re.I)
_UNIT_MULT = {'B': 1, 'KB': KB, 'MB': MB, 'GB': GB, None: 1}


def _heavy_size(rep, finding):
    """Best-effort size of a 'heavy directory' finding: first the
    heavy_outside_git list, then the evidence size string."""
    ev = (finding.get('evidence') or [{}])[0]
    path = ev.get('path') or ev.get('location') or ''
    for h in rep.get('heavy_outside_git') or []:
        if h.get('path') == path and h.get('size_bytes'):
            return h['size_bytes']
    m = _SIZE_RE.match(str(ev.get('size') or ''))
    if m and m.group(1):
        try:
            return int(float(m.group(1)) * _UNIT_MULT.get(
                m.group(2).upper() if m.group(2) else None, 1))
        except ValueError:
            return None
    return None


def plain_sentence(rep, finding, lang):
    """One plain sentence for a finding, chosen by category and keywords
    in the title. Falls back to the lowercased title in quotes."""
    s = STRINGS[lang]
    cat = finding.get('category') or ''
    title = finding.get('title') or ''
    t = title.lower()
    if cat == 'secrets':
        if 'no secret' in t or 'prevention' in t:
            return s['plain_no_prevention']
        return s['plain_secrets']
    if cat == 'dirs':
        if 'drifted' in t:
            return s['plain_drift']
        if 'nested' in t:
            return s['plain_nested']
        if ('heavy' in t or 'outside version control' in t
                or 'outside git' in t):
            size = _heavy_size(rep, finding)
            if size:
                return s['plain_heavy'].format(size=human_bytes(size, lang))
            if 'heavy' in t:
                return s['plain_heavy_nosize']
            return s['plain_unowned']
        return _fallback(title, lang)
    if cat == 'rules':
        if 'dead' in t:
            return s['plain_dead']
        if 'drift' in t or 'disagree' in t or 'two rule sources' in t:
            return s['plain_drift']
        if 'chain' in t or 'over 16' in t:
            return s['plain_fat']
        if 'generic' in t or 'boilerplate' in t:
            return s['plain_boiler']
        return _fallback(title, lang)
    if cat == 'skills':
        return s['plain_skills']
    if cat == 'git':
        return s['plain_git']
    if cat == 'config':
        if 'no configuration' in t or 'no settings' in t:
            return s['plain_noconfig']
        return s['plain_config']
    if cat == 'governance':
        return s['plain_gov']
    if cat == 'health':
        return s['plain_health']
    return _fallback(title, lang)


def _fallback(title, lang):
    if lang == 'ru':
        return '«' + title.lower() + '»'
    return '"' + title.lower() + '"'


def _sorted_open_findings(rep):
    open_f = [f for f in rep.get('findings_detailed') or []
              if f.get('status') in OPEN_STATUSES]
    open_f.sort(key=lambda f: SEVERITY_RANK.get(f.get('severity', 'info'), 9))
    return open_f


# --------------------------------------------------------------------------
# sections
# --------------------------------------------------------------------------

def _short_version(rep, lang):
    s = STRINGS[lang]
    fails, warns = gate_counts(rep)
    total = len(rep.get('gates') or [])
    lines = ['## ' + s['h_short'], '']
    if fails:
        if lang == 'ru':
            lines.append(s['state_fail'].format(
                total=total, fail=fails,
                failw=_ru_count_adj(fails, 'красная', 'красных'),
                warn=warns,
                warnw=_ru_count_adj(warns, 'жёлтая', 'жёлтых')))
        else:
            lines.append(s['state_fail'].format(
                total=total, fail=fails, warn=warns))
    elif warns:
        if lang == 'ru':
            lines.append(s['state_warn'].format(
                total=total, warn=warns,
                warnw=_ru_count_adj(warns, 'жёлтая', 'жёлтых')))
        else:
            lines.append(s['state_warn'].format(total=total, warn=warns))
    else:
        lines.append(s['state_ok'].format(total=total))
    open_f = _sorted_open_findings(rep)
    if open_f:
        lines.append(s['main_problem'].format(
            sentence=plain_sentence(rep, open_f[0], lang)))
    lines.append(s['promise'])
    return lines


def _costs_section(rep, lang, sessions_per_day):
    s = STRINGS[lang]
    lines = ['## ' + s['h_costs'], '']
    overhead = session_overhead_bytes(rep)
    if overhead > 0:
        lo, mid, hi = token_range(overhead)
        per_month = DAYS_PER_MONTH * max(0, sessions_per_day)
        mlo, mmid, mhi = lo * per_month, mid * per_month, hi * per_month
        lines.append('- ' + s['cost_tokens'].format(
            lo=fmt_int(lo, lang), hi=fmt_int(hi, lang),
            mid=fmt_int(mid, lang)))
        lines.append('  - ' + s['cost_monthly'].format(
            mlo=fmt_int(mlo, lang), mhi=fmt_int(mhi, lang),
            mmid=fmt_int(mmid, lang)))
        lines.append('  - ' + s['cost_assumption'].format(
            sessions=fmt_int(max(0, sessions_per_day), lang),
            days=DAYS_PER_MONTH))
    else:
        lines.append('- ' + s['cost_tokens_zero'])
    mo = memory_over_bytes(rep)
    if mo > 0:
        lines.append('- ' + s['cost_memory'].format(
            kb=human_bytes(mo, lang)))
    parts = []
    jb = junk_bytes(rep)
    db = duplicates_bytes(rep)
    lb = large_files_bytes(rep)
    if jb:
        parts.append(s['cost_junk'].format(size=human_bytes(jb, lang)))
    if db:
        parts.append(s['cost_dup'].format(size=human_bytes(db, lang)))
    if lb:
        parts.append(s['cost_large'].format(size=human_bytes(lb, lang)))
    if parts:
        lines.append('- ' + ' '.join(parts))
    else:
        lines.append('- ' + s['cost_disk_zero'])
    secrets = open_secret_count(rep)
    if secrets:
        if secrets == 1:
            lines.append('- ' + s['cost_secrets_one'].format(n=secrets))
        else:
            extra = {}
            if lang == 'ru':
                extra = {
                    'parols': _ru_plural(secrets, 'пароль', 'пароля',
                                         'паролей'),
                    'keys': _ru_plural(secrets, 'ключ', 'ключа', 'ключей'),
                }
            lines.append('- ' + s['cost_secrets'].format(n=secrets, **extra))
    else:
        lines.append('- ' + s['cost_secrets_zero'])
    lines.append('')
    lines.append('*' + s['foot_quality'] + '*')
    lines.append('*' + s['foot_tokens'] + '*')
    return lines


def _wrong_section(rep, lang):
    s = STRINGS[lang]
    lines = ['## ' + s['h_wrong'], '']
    open_f = _sorted_open_findings(rep)
    if not open_f:
        lines.append(s['wrong_none'])
        return lines
    for f in open_f[:MAX_WRONG_BULLETS]:
        lines.append('- ' + plain_sentence(rep, f, lang)
                     + ' (' + str(f.get('fid', '?')) + ')')
    return lines


def _better_section(rep, after, lang):
    s = STRINGS[lang]
    lines = ['## ' + s['h_better'], '']
    f1, w1 = gate_counts(rep)
    f2, w2 = gate_counts(after)
    lines.append('- ' + s['better_gates'].format(
        f1=f1, f2=f2, w1=w1, w2=w2))
    pb = project_instruction_bytes(rep)
    pa = project_instruction_bytes(after)
    if pb != pa:
        saved = max(0, tokens_from_bytes(pb - pa))
        lines.append('- ' + s['better_slim'].format(
            x=human_bytes(pb, lang), y=human_bytes(pa, lang),
            z=fmt_int(saved, lang)))
    tb = tokens_from_bytes(session_overhead_bytes(rep))
    ta = tokens_from_bytes(session_overhead_bytes(after))
    lines.append('- ' + s['better_tokens'].format(
        a=fmt_int(tb, lang), b=fmt_int(ta, lang)))
    jb = junk_bytes(rep)
    ja = junk_bytes(after)
    if jb or ja:
        lines.append('- ' + s['better_junk'].format(
            a=human_bytes(jb, lang), b=human_bytes(ja, lang)))
    sb = open_secret_count(rep)
    sa = open_secret_count(after)
    if sb or sa:
        if sa == 0:
            lines.append('- ' + s['better_secrets_zero'].format(a=sb))
        else:
            lines.append('- ' + s['better_secrets'].format(a=sb, b=sa))
    todo = [GID_PLAIN[g.get('gid')][lang]
            for g in after.get('gates') or []
            if g.get('status') == 'fail' and g.get('gid') in GID_PLAIN]
    if todo:
        lines.append('')
        lines.append(s['still_todo'])
        for item in todo[:MAX_TODO]:
            lines.append('- ' + item)
    return lines


def _next_section(lang):
    s = STRINGS[lang]
    return ['## ' + s['h_next'], '',
            '- ' + s['next_1'],
            '- ' + s['next_2'],
            '- ' + s['next_3']]


# --------------------------------------------------------------------------
# assembly
# --------------------------------------------------------------------------

def generate_human_markdown(rep, lang='en', sessions_per_day=10, after=None):
    """Render one scan report (dict) as plain-language markdown.

    lang: 'en' or 'ru'. sessions_per_day feeds the monthly estimate and
    is always printed next to it. after: an optional second scan dict
    (made after cleanup) that adds the before/after section.
    """
    if lang not in STRINGS:
        raise ValueError(f'unsupported lang: {lang!r}')
    s = STRINGS[lang]
    out = ['# ' + s['title'], '',
           s['subtitle'].format(root=rep.get('root', '?')), '']
    out.extend(_short_version(rep, lang))
    out.append('')
    out.extend(_costs_section(rep, lang, sessions_per_day))
    out.append('')
    out.extend(_wrong_section(rep, lang))
    out.append('')
    if after is not None:
        out.extend(_better_section(rep, after, lang))
        out.append('')
    out.extend(_next_section(lang))
    out.append('')
    out.append('---')
    out.append('')
    out.append(s['footer'].format(ts=rep.get('generated_at', '?')))
    out.append('')
    return '\n'.join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description='render scan.json as a plain-language report (EN/RU)')
    ap.add_argument('scan', help='scan.json produced by audit_scan.py')
    ap.add_argument('--lang', choices=['en', 'ru'], default='en',
                    help='output language (default: en)')
    ap.add_argument('--sessions', type=int,
                    default=DEFAULT_SESSIONS_PER_DAY,
                    help='agent sessions per day for the monthly estimate '
                         f'(default: {DEFAULT_SESSIONS_PER_DAY})')
    ap.add_argument('--after', default=None,
                    help='second scan.json made after cleanup; adds the '
                         'before/after section')
    ap.add_argument('--out', default=None,
                    help='write the markdown here instead of stdout')
    a = ap.parse_args(argv)
    try:
        if hasattr(sys.stdout, 'reconfigure'):
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        rep = json.loads(Path(a.scan).read_text(encoding='utf-8'))
        after = None
        if a.after:
            after = json.loads(Path(a.after).read_text(encoding='utf-8'))
    except (OSError, ValueError) as e:
        sys.exit(f'cannot read report: {e}')
    md = generate_human_markdown(rep, lang=a.lang,
                                 sessions_per_day=a.sessions, after=after)
    if a.out:
        Path(a.out).write_text(md, encoding='utf-8')
        print(f'wrote {a.out}')
    else:
        print(md, end='')
    return 0


if __name__ == '__main__':
    sys.exit(main())
