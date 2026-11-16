#!/usr/bin/env python3
"""Undo one agents-doctor trash run (restore what was moved).

    python tools/restore.py <run_dir> [--root R] [--yes]

Thin wrapper around the restore logic in
skills/agents-doctor/scripts (trashops.restore via safe_clean's
restore subcommand): reads the run's manifest.json, asks for the word
YES, moves every recorded item back to its original place -- or next to
it as <name>.restored-N when that place is taken -- and never
overwrites anything. Removed empty folders are not restorable. Exit
codes: 0 ok or declined, 1 some items failed, 2 bad arguments or
unreadable manifest. Python 3.9+, stdlib only.
"""
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / 'skills' / 'agents-doctor' / 'scripts'
sys.path.insert(0, str(SCRIPTS))

import safe_clean  # noqa: E402  (restore subcommand, itself backed by trashops)

if __name__ == '__main__':
    sys.exit(safe_clean.main(['restore'] + sys.argv[1:]))
