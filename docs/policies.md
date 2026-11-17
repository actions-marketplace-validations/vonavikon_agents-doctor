# Policies

Модуль Policy Engine (ТЗ v2.1.0, enforcement — ТЗ 3.0): корпоративные
политики поверх готового аудита. Политика — YAML-файл с правилами;
движок проверяет по нему scan.json и файлы workspace и пишет отчёт
соответствия. Скан не пересчитывается: политики читают уже собранные
факты.

Код: `skills/agents-doctor/scripts/policies.py`. Тесты:
`tests/test_policies.py`, `tests/test_policy_enforcement.py`.

## Быстрый старт

```
python skills/agents-doctor/scripts/agents_doctor.py audit . --out scan.json
python skills/agents-doctor/scripts/agents_doctor.py policy scan.json \
    --policy corporate.yml --policy team.yml --out report.json
```

`--policy` можно повторять: файлы наслаиваются (см. «Наследование»).
`--format md` пишет markdown-таблицу вместо JSON. Exit-коды — контракт
для CI, см. «Enforcement v2»: 0 проверка пройдена (или enforcement
выключен), 1 сработало блокирующее правило, 2 битый или отсутствующий
policy-файл, 3 нечитаемый scan.json или нет root, 4 строгий enforcement
при неизвестных правилах. Отчёт записывается до любого из этих
выходов.

## Формат политики

```yaml
version: 2

policy:
  name: corporate-baseline        # метаданные, в отчёт
  description: Обязательные правила для всех workspace

  enforcement:                    # v2: см. «Enforcement v2»
    enabled: true
    default_action: warn
    unknown_action: warn

  secrets:
    severity: critical            # info | warning | error | critical
    block_on_failure: true        # v2: блокирует CI, см. enforcement
    block_above: high             # v2: порог severity для блокировки

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

  harness_versions:
    required:                     # harness id -> диапазон версий
      claude_code: '>=2.1'
      codex: '<2'

  required_skills:                # имена обязательных скиллов
    - gramax

custom_rules:                     # расширяемость: произвольные правила
  - id: POL-CUSTOM-001
    check: content.regex
    patterns: ['internal-codename']
    severity: error
    message: Запрещено упоминание внутреннего проекта
```

Каждый домен опционален. Отсутствует — правило не активно (статус
`not_applicable` в отчёте). `severity` разрешена в любом домене; без неё
домен использует значение по умолчанию из таблицы ниже. Поля
`block_on_failure` и `block_above` работают только в файлах
`version: 2`; в `version: 1` `block_on_failure` на secrets остаётся
информационным, как раньше.

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
| harness_versions | POL-HARNESS-VERSIONS | версия каждого обязательного harness внутри диапазона | rep + `harnesses[].version` | error |
| required_skills | POL-REQUIRED-SKILLS | каждый обязательный скилл установлен | rep + `skills.entries[].name` | error |

MCP-серверы движок читает сам из `.mcp.json` (`mcpServers`),
`.claude/settings*.json` (`mcpServers`), `.codex/config.toml`
(`[mcp_servers.*]`, tomllib при наличии), `.cursor/mcp.json`. Evidence —
только имя сервера и файл: command и env в отчёт не попадают.

content.ban_patterns (и custom-правила) сканируют только AGENTS.md,
CLAUDE.md, `.mcp.json` и `.claude/settings*.json` в корне, кап 256 КБ на
файл. Evidence — файл, строка и сам матч: матч это запрещённый текст, не
секрет.

harness_versions: диапазон — один оператор (`>=`, `<=`, `>`, `<`, `==`) и
semver-подобная строка, сравнение покомпонентно численно (`2.1` равно
`2.1.0`, меньше `2.1.1`; нечисловые суффиксы вроде `-beta` игнорируются).
Harness в скане с `version: null` или отсутствующий в скане — статус
`unknown`, не pass и не violation. Версия вне диапазона — violation с
evidence `{harness, version, required}`.

required_skills: список имён; отсутствие скилла в
`rep["skills"]["entries"]` — violation. Пустой список скиллов или
отсутствие раздела — `unknown`: скан не собрал факты, непроверенное не
считается безопасным.

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

Enforcement-настройки из v2-файлов объединяются поверх всех файлов:
`enabled` — OR (любой файл с `enabled: true` включает enforcement),
`default_action` и `unknown_action` — при конфликте значений строже
(block > warn) с warning. Enforcement-блок в файле version: 1
игнорируется с warning.

## Enforcement v2

Схема `version: 2` превращает нарушения политик в exit-коды для CI.
Достаточно добавить `enforcement`-блок в `policy:` — v1-файлы работают
как раньше (все выходы 0 после записи отчёта, `block_on_failure`
информационный).

```yaml
version: 2

policy:
  name: enterprise-baseline
  enforcement:
    enabled: true            # выключатель; false или отсутствие = поведение v1
    default_action: block    # block | warn — для доменов без явного block_on_failure
    unknown_action: warn     # block | warn — для правил в статусе unknown
  secrets:
    severity: critical
    block_on_failure: true   # теперь блокирует
    block_above: high        # блокировать при нарушениях уровня high и выше (опционально)
```

Правило блокирует, когда:

- домен задал `block_on_failure: true`, а нарушения домена достигают
  порога `block_above` (если задан; уровень «этот и выше» по шкале
  finding severity: low < medium < high < critical); или
- домен без явного `block_on_failure` нарушил при
  `default_action: block`. Явный `block_on_failure: false` отключает
  блокировку домена даже при `default_action: block`.

Custom-правила следуют `default_action`: у них нет своих
`block_on_failure`/`block_above`. Погашенное исключением правило
(`suppressed`) не блокирует — исключение сильнее enforcement.

### Exit-коды подкоманды policy

| Код | Смысл |
|---|---|
| 0 | нарушений нет или enforcement выключен |
| 1 | сработало блокирующее правило (список — в `summary.enforcement.blocking_rules`) |
| 2 | ошибка конфигурации: битый или отсутствующий policy-файл |
| 3 | проверка невозможна: scan.json не читается или в нём нет root |
| 4 | строгий enforcement: `unknown_action: block` и есть правила в статусе unknown |

Отчёт печатается или записывается всегда до выхода, в том числе при
exit 1. В `summary` отчёта добавляется блок:

```
enforcement  {enabled, action_taken, exit_code, blocking_rules}
```

`action_taken` — `block`, `warn` (нарушения есть, но не блокирующие)
или `none`.

`audit --policy` повторяет ту же логику: compliance-отчёт вшивается в
scan.json, при блокировке печатается `policy: BLOCKED by N rule(s): …`
и команда возвращает 1 (exit 4 — при блокировке из-за unknown) строго
после записи scan.json.

### CI: GitHub Actions

```yaml
- uses: actions/checkout@v4
- uses: vonavikon/agents-doctor@v2.1.1
  with:
    path: '.'
    policy: policies/enterprise.yml
    policy-enforcement: 'true'
```

Вход `policy-enforcement` (по умолчанию `'false'`): при `'true'`
exit-код шага policy пробрасывается в джобу. Без него исходы
enforcement (1 и 4) остаются консультативными — шаг пишет отчёт и
завершается нулём. Ошибки конфигурации и скана (2, 3) валят джобу в
обоих режимах: проверка не выполнилась.

### Миграция v1 → v2

Просто добавь `enforcement`-блок и поменяй `version: 2` — v1-файлы
продолжают работать без изменений. Пока `enabled: false` (или блока
нет), поведение неотличимо от v1: все exit-коды 0 после записи отчёта.

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
                    not_applicable, violations, by_severity,
                    enforcement}
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
