# What the audit found — in plain words

Folder checked: C:\workspaces\chaos-demo\workspace

## The short version

Of 9 checks, 6 are red and 2 are yellow: the workspace still works, but the mess is big enough to slow every agent down.
The main problem: A password/key is sitting in a file where it should not be
Cleanup can make every agent start faster and waste less.

## What this costs you

- Every session starts with about 13,212–22,020 extra tokens of instructions and memory the agent does not need (best estimate: 16,515).
  - Over a month that makes roughly 3,963,600–6,606,000 extra tokens (best estimate: 4,954,500).
  - The monthly figure assumes 10 agent sessions a day and 30 days a month.
- The agent memory file is 16.8 KB over the limit, and everything past the limit is cut off — that part of your notes the agent never sees.
- Junk files and folders take up 13.9 KB. Verified duplicate copies add another 7.4 KB. Large files without a backup hold 8 MB.
- 2 passwords or keys are left in plain sight, in files or in saved history; the values themselves are not shown here.

*Why it matters: with a long context, background noise measurably lowers the quality of the answers.*
*How tokens are counted: an estimate of 4 bytes per token; depending on the language of the text the real ratio sits between 3 and 5 bytes per token.*

## What is wrong, in plain words

- A password/key is sitting in a file where it should not be (SEC-001)
- A password/key is sitting in a file where it should not be (SEC-002)
- Two instruction files disagree — the agent gets conflicting rules (DIR-001)
- Two instruction files disagree — the agent gets conflicting rules (RUL-007)
- A helper skill is set up wrong and never runs (SKL-003)
- A helper skill is set up wrong and never runs (SKL-005)

## Next step

- Run the safe cleanup (`safe_clean.py`): it works through the findings one at a time and asks before every change.
- Then run the audit again: the second report shows the "after" picture and what improved.
- This audit changed nothing: it only read files and counted.

---

Read-only audit: nothing was modified. Generated 2026-11-16T16:21:28+03:00. The numbers are estimates, not bills: they show the order of magnitude.
