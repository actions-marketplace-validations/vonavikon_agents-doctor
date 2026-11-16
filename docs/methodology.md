# Methodology

## Deterministic core, LLM interpreter

Mature tools keep detection deterministic and put the LLM only above ready
findings. MegaLinter's LLM advisor adds advice to finished reports; Semgrep
uses LLM triage to sort false positives out of results; driftlint keeps LLM
verdicts second-class, marked "needs review". This scanner follows the same
split: detection emits a JSON fact layer, which keeps runs reproducible, and
the LLM only narrates the findings.

## Verified agent limits

Primary sources, checked at implementation time:

- Codex truncates AGENTS.md chains at 32 768 bytes total
  (`codex-rs/config/defaults.toml`, `project_doc_max_bytes`).
- Claude Code loads MEMORY.md up to 200 lines or 25 KB, whichever comes
  first; files over 4 MiB are skipped; on-demand files are capped at
  40 000 characters (code.claude.com/docs/en/memory).
- Skill descriptions are capped at 1 024 characters, and the listing trims
  description plus `when_to_use` at 1 536 characters
  (platform.claude.com agent-skills best practices).

The 16 KB project-file benchmark is ours, deliberately stricter than vendor
limits: it flags bloat before a vendor cutoff silently truncates the file.

## Why hygiene matters

An ETH study (arXiv:2602.11988) measured the cost of instruction noise:
LLM-generated AGENTS.md raise inference cost by 20-23% (p<0.001) with no
significant change in task success; human-written files beat generated ones
by +7% success (p=0.038); cutting generic overview blocks gives a stable
+2.7% success. Context noise degrades even trivial tasks: the Chroma
"Context Rot" study and GSM-IC both show accuracy dropping as irrelevant
context grows.

## Trust engineering

False positives decide whether a static-analysis tool survives. Bessey et
al. (CACM 2010) report that false-positive rates above ~30% kill adoption,
and the first ~3 reports decide the tool's fate. Google's Tricorder keeps
the effective false-positive rate under ~10% and shows analysis at the
point of decision. From these numbers the scanner takes its rules:

- secrets are masked in every output;
- name-based junk detection reports "candidates", not verdicts;
- legacy workspaces get a baseline diff, so only new drift is reported;
- fingerprints are stable across runs, so a diff always means a real change.

## Sources

- https://agents.md/
- https://github.com/openai/codex
- https://code.claude.com/docs/en/memory
- https://code.claude.com/docs/en/skills
- https://platform.claude.com/docs/en/agents-and-tools/agent-skills/best-practices
- https://arxiv.org/abs/2602.11988
- https://www.trychroma.com/research/context-rot
- https://arxiv.org/abs/2302.00093
- https://cacm.acm.org/research/a-few-billion-lines-of-code-later/
- https://abseil.io/resources/swe-book/html/ch20.html
- https://github.com/oxsecurity/megalinter
- https://github.com/alifurkangokce/driftlint
- https://docs.semgrep.dev/semgrep-assistant/overview/
