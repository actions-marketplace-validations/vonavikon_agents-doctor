"""Instruction Intelligence (Phase 2, TZ section 6).

Orchestrates the per-harness adapters into workspace-wide answers:
- discovery: every instruction source every detected harness may read;
- simulation: the effective instruction set for a target directory,
  per harness, with the honest 'approximated' label;
- conflicts: deterministic contradictions and duplication across
  sources, including cross-harness divergence (reported as divergence,
  never automatically as an error — TZ section 8).

The package never invents harness semantics: everything comes from the
adapters' resolve_chain models.
"""
from __future__ import annotations

from .discovery import discover_all, load_source_text
from .simulation import simulate_loading
from .conflicts import find_conflicts

__all__ = ['discover_all', 'load_source_text', 'simulate_loading',
           'find_conflicts']
