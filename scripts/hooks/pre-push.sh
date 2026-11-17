#!/usr/bin/env bash
# agents-doctor pre-push hook (standalone; no pre-commit framework).
#
# Runs a fast workspace audit (no --deep, so it stays quick) before the
# push and blocks it when at least one finding has status fail and
# severity at or above the threshold (critical by default). The report
# lands under .git, outside the tree being pushed. Ref information that
# git pipes to pre-push on stdin is not needed and left unread.
#
# Install, from a clone of agents-doctor:
#   cp scripts/hooks/pre-push.sh <your-repo>/.git/hooks/pre-push
#   chmod +x <your-repo>/.git/hooks/pre-push
# or keep the hooks in the clone (updates then ride git pull):
#   git -C <your-repo> config core.hooksPath /abs/path/to/agents-doctor/scripts/hooks
#
# Overrides (env vars):
#   AGENTS_DOCTOR_PY      path to agents_doctor.py
#   AGENTS_DOCTOR_FAIL_ON severity gate: none|critical|high|medium|low|info
#
# A doctor that is not installed must not block work: when
# agents_doctor.py or python cannot be found, the hook warns and lets
# the push through. Once the audit runs, a nonzero exit blocks.

set -u

FAIL_ON="${AGENTS_DOCTOR_FAIL_ON:-critical}"

ROOT="$(git rev-parse --show-toplevel 2>/dev/null)"
if [ -z "$ROOT" ]; then
  echo "agents-doctor: not a git repository, hook skipped" >&2
  exit 0
fi

# locate agents_doctor.py: env override, next to this hook
# (core.hooksPath into a clone), vendored inside the audited repo
HOOK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd)"
DOCTOR="${AGENTS_DOCTOR_PY:-}"
if [ -z "$DOCTOR" ]; then
  for candidate in \
    "$HOOK_DIR/../../skills/agents-doctor/scripts/agents_doctor.py" \
    "$ROOT/skills/agents-doctor/scripts/agents_doctor.py"
  do
    if [ -f "$candidate" ]; then
      DOCTOR="$candidate"
      break
    fi
  done
fi

if [ -z "$DOCTOR" ]; then
  echo "agents-doctor: agents_doctor.py not found (set AGENTS_DOCTOR_PY); push allowed without audit" >&2
  exit 0
fi

if ! command -v python >/dev/null 2>&1; then
  echo "agents-doctor: python not found; push allowed without audit" >&2
  exit 0
fi

# park the report inside the git dir: works for worktrees too, and the
# hook never adds an untracked file to the tree it is guarding
GIT_DIR="$(git rev-parse --absolute-git-dir 2>/dev/null \
  || git rev-parse --git-dir)"
REPORT="$GIT_DIR/agents-doctor-scan.json"

python "$DOCTOR" audit "$ROOT" --fail-on "$FAIL_ON" --out "$REPORT"
rc=$?
if [ "$rc" -eq 0 ]; then
  echo "agents-doctor: audit clean (report: $REPORT)"
  exit 0
fi

echo "agents-doctor: audit exit $rc, push blocked (fail-on: $FAIL_ON)" >&2
echo "agents-doctor: report: $REPORT" >&2
echo "agents-doctor: fix the findings, or bypass once with: git push --no-verify" >&2
exit 1
