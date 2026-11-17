# Phase 0 — Architecture Gap Analysis

Дата: 2026-11-17. Аудит v1.0.0 (commit 000ece7). Основа плана миграции по ТЗ
«Agents Doctor — развитие до полноценной системы аудита AI-agent environments».

## 1. Текущее состояние

9 gate'ов (G1–G9) детерминированы и покрыты 516+ тестами. Движок: факты
(audit_scan + enrich) → gates.py (GATE_DEFS + GATE_POLICY) → findings +
scan.json. Инвариант unknown-not-pass сохранён. Remediation: trash-first,
manifest v2, TOCTOU-проверки, rollback — уже реализовано.

## 2. Главная проблема: harness-логика размазана и захардкожена

Среды zcode/claude/codex описаны в **четырёх параллельных списках**,
синхронизируемых вручную:

| Список | Где | Что держит |
|---|---|---|
| `HARNESS` dict | audit_scan.py:53-60 | home-каталог, markers, `reads` (декларативно, не используется) |
| `project_dirs` | audit_scan.py:273-274 | 4 пути existence-пробоя на root |
| `HARNESS_DIRS` | enrich.py:58 | каталоги для mtime-активности |
| `_DIR_TO_TOOL` | gates.py:171-172 | маппинг для harness-env-conflict |

Cursor, Gemini CLI, OpenCode, GitHub Copilot, Windsurf — не упоминаются нигде.

## 3. Пересечения с целевой архитектурой (что мигрирует в адаптеры)

1. `HARNESS` dict → `harness/adapters/*` + registry.
2. `context_checks` (audit_scan.py:278-342) — знает только пару
   AGENTS.md/CLAUDE.md, `@AGENTS.md`-импорт — claude/codex-специфика в общем
   коде → instruction layer + адаптеры.
3. `context_tax` (audit_scan.py:345-368) — user-инструкции захардкожены
   (`~/.zcode/AGENTS.md`, `~/.claude/CLAUDE.md`) → адаптеры.
4. `skills_report` locs (audit_scan.py:390-395) — 5 локаций → адаптеры.
5. `chain_budget` (audit_scan.py:500-518) — Codex-бюджет 32768 в общем коде →
   codex-адаптер.
6. `CONFIG_NAMES` (enrich.py:55) → адаптеры (config_files()).
7. Dead-harness note (audit_scan.py:793-800) — только claude → обобщить через
   адаптеры (G8).

## 4. Контракты, которые обязаны сохраниться (back-compat)

- **CLI**: `audit_scan.py <path> --home --deep --history-depth
  --history-all-refs --profile --baseline --out`; `agents_doctor.py
  audit|sarif|compare|explain|fix` с текущими флагами и exit-кодами;
  `safe_clean.py` + `restore`.
- **JSON**: топ-ключи scan.json (schema_version '1.0' в report_model.py:13 и
  audit_scan.py:530), поля findings_detailed/gates по report_model.py.
  Новые поля (harness, check_id, environment) — только аддитивно.
- **fid-префиксы**: SEC/CFG/RUL/DIR/SKL/GIT/GOV/HLTH. Адаптерные проверки
  добавляют стабильный `check_id` (например `CLAUDE_INSTRUCTION_CONFLICT`),
  fid остаётся счётчиком.
- **9 gate'ов и GATE_POLICY** — пороги не меняются без явного решения.

## 5. Чего нет (разрывы по фазам ТЗ)

| Фаза ТЗ | Статус | Что делаем |
|---|---|---|
| Harness Registry + Adapter interface | нет | `harness/` пакет: base, registry, detection |
| Instruction resolution / simulation | частично (только валидация пары файлов) | `instructions/` пакет: discovery → resolution → simulation |
| Cross-harness conflicts | нет | поверх цепочек адаптеров |
| Version compatibility | нет | spec-метаданные адаптера + version detect |
| Config security (permissions/hooks/MCP) | частично (parse + dup_keys + 'mcp' подстрока) | адаптерные валидаторы |
| Secret benchmark precision/recall | нет (только PARITY_CORPUS) | bench/secret-quality |
| Runtime health | частично (mtime-активность) | opt-in runtime-модуль |
| UI | нет (только human-reports) | `ui/` local web |

## 6. План миграции (без второй параллельной системы)

Ничего не переписываем с нуля: адаптеры **питают** существующие gates, а не
заменяют их. audit_scan/enrich/gates переходят с четырёх захардкоженных
списков на запросы к реестру — поведение для zcode/claude/codex остаётся
байт-в-байт (это фиксируют существующие тесты).

Порядок: Phase 1 (реестр+детект+3 адаптера) → Phase 2 (инструкции) →
Phase 3 (конфиг-безопасность+версии) → Phase 4 (remediation) → Phase 5-7
(остальные среды) → UI V1-V4. Каждый этап оставляет репо зелёным.
