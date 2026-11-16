# Research: the human layer (report + safe cleanup), 2026-11-16

Three parallel research agents (plain-language value reports, safe-cleanup UX,
token-cost estimation) reviewed public sources. This note records what was
applied, what was deliberately not applied, and the sources.

## Applied to the code

| Finding (source) | Where it landed |
|---|---|
| Preview before delete is the primary action, deletion the second explicit step (BleachBit, `git clean -n`, docker prune) | `safe_clean.py` flow: plan → plain-word preview → typed `YES` |
| Prefer undo over confirmation; trash-first everywhere (NN/g User Control & Freedom; Send2Trash practice) | everything movable goes to `.agents-doctor-trash/<timestamp>/`, nothing is deleted in place; only truly-empty dirs are `rmdir`'d |
| Categorize by risk; auto-clean only the top tier (CleanMyMac Safety Database model) | default-safe tier (caches, empty dirs, confirmed junk) vs cautious tier behind `--include-cautious` |
| Whitelist-only deletion; ecosystem-documented regenerables only (gitignore templates, `cargo clean`) | `BUILD_DIR_SAFE` + cautious remainder of the scanner's build dirs |
| A lockfile is what makes `node_modules` reliably regenerable; patched/vendored content is lost otherwise (patch-package exists for this) | node_modules without a sibling lockfile drops to the cautious tier |
| Age-filter everything: recency correlates with in-use (docker `until=`, Storage Sense retention) | build dirs modified within 7 days are skipped as `recent` |
| Hard path containment; never follow symlinks out of the root; re-verify at execute time (GitLab 2017 postmortem class; safe-rm) | containment re-checked immediately before each move; symlinked and escaping paths refused |
| Cap per-action size (Recycle-Bin eviction is silent and oldest-first, per community sources — unverified against a primary doc) | hard 500 MB ceiling per item (`HARD_MAX_BYTES`), `--max-bytes` can lower it |
| Round numbers, ranges instead of point estimates, assumptions printed inline (consumer-number research; Royal Society / EFSA uncertainty guidance) | `report_human.py`: token ranges (low/high), monthly estimate always carries the sessions/day assumption |
| Gain-framed before/after deltas computed against the user's own baseline (Opower RCTs; O'Keefe & Jensen meta-analysis) | the "What gets better after cleanup" section exists only with a real second scan |
| Never show a finding you cannot reproduce or a severity you cannot justify (FTC v. Restoro/Reimage, $26M) | human report derives 100% from scan JSON; plain sentences map to fids; no counts without items |
| Familiar units and chunked numbers (W3C COGA-Usable) | KB/GB with rounded values, thousands separators (EN commas, RU narrow spaces) |

## Deliberately not applied (yet)

- OS Recycle Bin via send2trash: the tool-managed trash folder already gives
  cross-platform recovery with a known retention story; switching is a small
  change if field use asks for it.
- "X MB ≈ N photos" analogies: widespread in practice, but no controlled study
  shows they improve comprehension or action — flagged for a future A/B test.
- Per-category interactive toggles in the CLI wizard: current preview + typed
  YES covers the non-technical flow; a TUI would be the next step.
- Caches (pip/npm) as a separate later step after dependencies: our cautious
  tier already sequences nothing destructive together with them.

## Token math (the honest version)

- English/markdown: ≈ 4 bytes/token (OpenAI help center), ≈ 3.5 chars/token
  (Anthropic, secondhand). The report uses a //5–//3 band around //4.
- Russian/Cyrillic: sources conflict by tokenizer generation (letter-per-token
  on cl100k-class vs 3–4 chars/token on newer); any ru-specific divisor needs
  a ±40% band — the current wide band covers both without claiming precision.
- Quality footnote: context growth degrades even trivial tasks — Context Rot
  (18 models, trychroma.com/research/context-rot) and NoLiMa (GPT-4o 99.3% at
  <1K → 69.7% at 32K, arxiv.org/abs/2502.05167).
- Vendor numbers themselves are estimates ("the count is an estimate" —
  Anthropic Count Tokens API docs), which licenses ranges in our output.

## Sources (selection)

npm doctor docs; flutter doctor (Codecademy); Windows Storage / Cleanup
Recommendations (support.microsoft.com); macOS Storage (support.apple.com);
digital.gov plain-language guidelines; W3C COGA-Usable; RPI round-numbers
release; O'Keefe & Jensen 2008; Opower/JPAL and Allcott 2011; FTC v.
Restoro/Reimage (ftc.gov); NN/g articles on confirmation dialogs, error
prevention, user control; BleachBit; docker system prune docs; git-clean
docs; Atlassian git clean tutorial; Send2Trash (PyPI); patch-package;
Cargo Book (cargo clean); github/gitignore templates; GitLab 2017 outage
coverage; safe-rm; Windows 10 1809 data-loss postmortem coverage; OpenAI
token help center; Anthropic token-counting docs; LiteLLM/Helicone cost
calc docs; Digital Applied instruction-file audit (4 bytes/token field
check); Liu et al. TACL 2024 (Lost in the Middle); Modarressi et al. ICML
2025 (NoLiMa); Chroma Context Rot.
