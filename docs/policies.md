# Policies

Модуль Policy Engine (ТЗ v2.1.0): корпоративные политики поверх готового
аудита. Политика — YAML-файл с правилами; движок проверяет по нему scan.json
и файлы workspace и пишет отчёт соответствия. Скан не пересчитывается:
политики читают уже собранные факты.

Код: `skills/agents-doctor/scripts/policies.py`. Тесты:
`tests/test_policies.py`.

## Быстрый старт

```
python skills/agents-doctor/scripts/agents_doctor.py audit . --out scan.json
python skills/agents-doctor/scripts/agents_doctor.py policy scan.json \
    --policy corporate.yml --policy team.yml --out report.json
```

`--policy` можно повторять: файлы наслаиваются (см. «Наследование»).
`--format md` пишет markdown-таблицу вместо JSON. Exit-код всегда 0 после
записи отчёта — блокировка CI это отдельный флаг политики
(`block_on_failure`), а не код возврата. Битый YAML — exit 1 с именем
файла и строкой.

## Формат политики

```yaml
version: 1

policy:
  name: corporate-baseline        # метаданные, в отчёт
  description: Обязательные правила для всех workspace

  secrets:
    severity: critical            # info | warning | error | critical
    block_on_failure: true        # информационно, для CI

  mcp:
    allowlist:                    # имена разрешённых MCP-серверов
      - approved-server

  instructions:
    require_agents_md: true

  git:
    prevent_secret_commits: true

  permissions:
    forbid_wildcard: true         # Bash(*), danger-full-access и т.п.

  content:
    ban_patterns:                 # regex (re.search) по текстовым файлам
      - 'INTERNAL-PROJECT-CODE'
      - 'ACME-CONFIDENTIAL'

custom_rules:                     # расширяемость: произвольные правила
  - id: POL-CUSTOM-001
    check: content.regex
    patterns: ['internal-codename']
    severity: error
    message: Запрещено упоминание внутреннего проекта
```

Каждый домен опционален. Отсутствует — правило не активно (статус
`not_applicable` в отчёте). `severity` разрешена в любом домене; без неё
домен использует значение по умолчанию из таблицы ниже.

## Домены и проверки

Проверки идут по scan.json (rep) и по файловой системе root. «Пустой
факт» — раздел скана отсутствует или не даёт данных — даёт статус
`unknown`, не `pass`: непроверенное не считается безопасным.

| Домен | Rule ID | Что проверяет | Факты | Severity по умолчанию |
|---|---|---|---|---|
| secrets | POL-SECRETS-EXPOSED | в `rep["secrets"]` нет записей со статусом fail | rep | critical |
| mcp | POL-MCP-ALLOWLIST | каждый настроенный MCP-сервер входит в allowlist | файлы root | error |
| instructions | POL-INSTRUCTIONS-AGENTS-MD | в root есть AGENTS.md или CLAUDE.md | файлы root | warning |
| git | POL-GIT-SECRET-COMMITS | нет tracked_secrets и есть pre-commit/pre-push хук с secret-scan | rep + `top_level[].extra` | critical |
| permissions | POL-PERMISSIONS-WILDCARD | в findings_detailed нет находок с check_id `CLAUDE_SETTINGS_PERMISSIONS_WILDCARD`, `CODEX_SANDBOX_DANGER`, `CODEX_APPROVAL_NEVER`, `OPENCODE_PERMISSIONS_DANGEROUS` | rep | error |
| content | POL-CONTENT-BAN-PATTERNS | запрещённые паттерны не встречаются в текстовых файлах | файлы root | error |

MCP-серверы движок читает сам из `.mcp.json` (`mcpServers`),
`.claude/settings*.json` (`mcpServers`), `.codex/config.toml`
(`[mcp_servers.*]`, tomllib при наличии), `.cursor/mcp.json`. Evidence —
только имя сервера и файл: command и env в отчёт не попадают.

content.ban_patterns (и custom-правила) сканируют только AGENTS.md,
CLAUDE.md, `.mcp.json` и `.claude/settings*.json` в корне, кап 256 КБ на
файл. Evidence — файл, строка и сам матч: матч это запрещённый текст, не
секрет.

## Severity-маппинг

| Политика | Finding severity | Статус правила/violation |
|---|---|---|
| critical | critical | fail |
| error | high | fail |
| warning | medium | warn |
| info | low | info |

Каждое нарушение несёт: стабильный id (POL-\<DOMAIN\>-\<CHECK\> или id
custom-правила), текст правила, evidence (файл/строка/деталь), severity,
message. Поле `version` каждого файла попадает в `policy_versions`
отчёта. Одинаковый вход и версия — одинаковый отчёт (детерминизм, без
времени и порядка обхода).

## Исключения

Раздел `[policy]` в `.agents-doctor.toml`:

```toml
[policy]
exceptions = { POL-MCP-ALLOWLIST = "локальный стенд разработки" }
files = ["team.yml"]
```

`exceptions` — map rule_id → причина. Причина обязательна: исключение без
причины применяется, но добавляет warning. Исключение гасит правило
целиком: его нарушения уходят в `exceptions[]` отчёта, правило получает
статус `suppressed`. Exception с неизвестным rule_id — warning (ловит
опечатки). `files` — пути к дополнительным YAML-политикам workspace-уровня,
наслаиваются поверх переданных в `--policy`.

## Наследование

Несколько файлов политик применяются по порядку: позже в списке —
приоритетнее (team поверх corporate). Для одного домена действует
последний файл, который его определил — целиком, а не по полям. Домен,
определённый только в раннем файле, продолжает работать.

Конфликт разных severity одного домена в иерархии — warning в отчёт,
применяется более строгий (critical > error > warning > info). Custom-правила
накапливаются по всем файлам; одинаковый id — warning, побеждает поздний.

## Неизвестное не безопасно

Неизвестный домен, неизвестное поле домена, неизвестный верхнеуровневый
ключ — warning в отчёт, значение игнорируется. `name` и `description`
внутри `policy:` — метаданные, не домены. Невалидный severity, не-список
в allowlist/ban_patterns, не-булев флаг — warning. Битый YAML —
PolicyError с именем файла и строкой, политика не применяется частично
никогда.

## YAML без зависимостей

PyYAML опционален (как frontmatter скиллов). Без него работает
собственный fallback-парсер уровня TOML-парсера config.py: вложенные
отображения по отступам, списки `- item` (в том числе элементы-словари
для custom_rules) и inline `[a, b]`, скаляры (bool/int/float/null,
кавычки одинарные и двойные), комментарии `#` (с начала строки и
хвостовые). Табуляция в отступе, незакрытая кавычка или скобка,
дубль ключа, `- item` без списка, `a: b: c` — ошибка со строкой.

## Отчёт

`evaluate_policies(rep, root, policy_files) -> dict`:

```
policy_versions   [{file, version}] по порядку файлов
policy_name       name последнего файла, где задан
block_on_failure  флаг домена secrets (информационно, для CI)
rules_evaluated   [{id, domain, rule, status, severity, violations,
                    suppressed, source}]
violations        [{id, severity, status, message, rule, evidence}]
exceptions        [{id, reason, suppressed}]
warnings          [строки]
summary           {rules, pass, fail, warn, info, unknown, suppressed,
                    not_applicable, violations, by_severity}
```

Статусы правила: `pass`, `fail`, `warn`, `info` (по маппингу severity),
`unknown` (фактов нет), `suppressed` (исключение), `not_applicable`
(домен не задан или выключен). Markdown-формат (`render_markdown`,
`--format md`) — таблица rule / status / violations / severity плюс
warnings, exceptions и список нарушений.

Секреты в политику не попадают и в отчёт не попадают: проверка secrets
копирует из скана только путь, вид, маску и fingerprint; MCP-evidence —
имя сервера и файл. Канареечные тесты на это есть в tests/test_policies.py.

## Policy-pack дистрибуция

Политика распространяется в пакете маркета: YAML-файл кладётся в пакет
рядом с `plugin.json`, agents-doctor ищет политики глобом
`policies/*.yml` в установленных плагинах и подключает их как
corporate-уровень (поверх — `--policy` и `[policy] files`). Формат тот
же, что описан выше; имя файла — слагом (`corporate-baseline.yml`).
Поиск по глобу — деталь реализации главной сессии; здесь зафиксирован
контракт: файлы `policies/*.yml` рядом с `plugin.json`, формат из этого
документа.
