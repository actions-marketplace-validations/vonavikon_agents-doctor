# Harness Support Matrix

Generated from the adapter registry by `python tools/gen_harness_matrix.py` — do not edit by hand.

| harness | id | adapter ver | capabilities | spec verified | versions |
|---|---|---|---|---|---|
| Z Code | `zcode` | 1.0.0 | instructions, resolution, validation, skills, budget | 2026-11-17 | current CLI (version not detectable offline) |
| Claude Code | `claude_code` | 1.0.0 | instructions, resolution, validation, version, skills, budget | 2026-11-17 | 2.x (loading model, unverified against runtime) |
| OpenAI Codex | `codex` | 1.0.0 | instructions, resolution, validation, version, skills, budget | 2026-11-17 | current CLI (unverified) |
| Cursor | `cursor` | 1.0.0 | instructions, resolution, validation, version | 2026-11-17 | current (unverified) |
| Gemini CLI | `gemini_cli` | 1.0.0 | instructions, resolution, validation, version, skills, budget | 2026-11-17 | current (unverified) |
| OpenCode | `opencode` | 1.0.0 | instructions, resolution, validation, version, skills, budget | 2026-11-17 | current (unverified) |
| GitHub Copilot | `github_copilot` | 1.0.0 | instructions, resolution, validation, version, skills, budget | 2026-11-17 | current (unverified) |
| Windsurf | `windsurf` | 1.0.0 | instructions, resolution, validation, version, skills, budget | 2026-11-17 | current (unverified) |

## Specification provenance and limitations

### Z Code (`zcode`)

Docs: (unset)

Known limitations:
- nested AGENTS.md merging not modelled; only user + project root

### Claude Code (`claude_code`)

Docs: https://docs.anthropic.com/en/docs/claude-code

Known limitations:
- subdirectory CLAUDE.md lazy loading modelled as path-based inclusion: a nested file is active only when the target directory lies inside its subtree
- enterprise managed policies not modelled (no offline source)
- AGENTS.md support depends on version >= 2.1.296; when both CLAUDE.md and AGENTS.md exist, both are reported as project sources
- no documented instruction context budget

### OpenAI Codex (`codex`)

Docs: https://developers.openai.com/codex

Known limitations:
- AGENTS.md merge order modelled as documented, not runtime-verified
- project .codex/config.toml support varies by version

### Cursor (`cursor`)

Docs: https://docs.cursor.com/context/rules

Known limitations:
- glob semantics approximated with fnmatch + dir-prefix; nested .mdc referencing not modelled

### Gemini CLI (`gemini_cli`)

Docs: https://docs.gemini-cli / https://github.com/google-gemini/gemini-cli

Known limitations:
- hierarchical GEMINI.md loading modelled as documented, not runtime-verified
- AI memories under ~/.gemini/tmp/<hash>/memories/ are not modelled
- import depth limit of 5 hops taken from documentation
- @import token extraction approximated with a regex; fenced code blocks are not excluded

### OpenCode (`opencode`)

Docs: https://opencode.ai/docs/config/

Known limitations:
- jsonc comment stripping is heuristic (string-aware // line comments only; /* */ block comments are not handled)
- AGENTS.md merge order and the `instruction` file precedence are modelled from the docs, not runtime-verified

### GitHub Copilot (`github_copilot`)

Docs: https://docs.github.com/en/copilot

Known limitations:
- global instructions live in editor settings, not the repo; they cannot be detected or validated offline
- YAML mcp config validated heuristically (no top-level key check only, no full YAML parse)

### Windsurf (`windsurf`)

Docs: https://docs.windsurf.com/windsurf/cascade/rules

Known limitations:
- memories and workflows internals not modelled
- glob semantics approximated with fnmatch + dir-prefix

