# Troubleshooting

## The agent says Python is unavailable

The skill stops there on purpose: it does not walk the disk by hand. The
scanner needs Python 3.10 or newer and nothing else (stdlib only, no pip
install). Install Python, confirm with `python --version`, and rerun the
audit. On Windows, make sure `python` is on PATH for the shell the agent
uses, not only in your own terminal.

## A gate says unknown

`unknown` means the check could not run, not that it passed. Two usual
causes:

- Missing facts. The scan JSON was produced by an older scanner version or
  was trimmed. Re-run with the current version and pass the full JSON to
  the report step.
- Fallback parser. SKILL.md frontmatter is parsed with PyYAML when it is
  installed; without it a flat fallback parser runs and whatever it cannot
  parse is reported as `unknown`, never as ok. `pip install pyyaml` and
  re-run to get full frontmatter checks.

The finding attached to an unknown rule names the missing facts section.

## The symlink boundary test is skipped

On Windows without Developer Mode, creating symlinks in a test requires
administrator privileges, so the regression test skips. The boundary guard
itself is always active: symlinks pointing outside the workspace root are
never followed, and the scanner counts them in
`stats.skipped_symlinks_outside`. To run the test on Windows, enable
Developer Mode or run the suite as administrator.

## The scanner is slow on a huge tree

The scan is I/O bound: it stats every file and reads text candidates. On
one Windows machine, full CLI runs took about 1 s for 817 files, 100 s for
11 964 files and 514 s for 59 634 files (see
[bench/README.md](../bench/README.md); a cold cache is slower). `--deep`
adds a git history walk per repository and costs more on large histories.
Run it without `--deep` first; keep `--deep` for when a secret may already
be in history.

## The report says NEEDS ATTENTION but nothing failed

Attention covers `warn` and `unknown` too, not only `fail`. Open the gates
table: a gate with status warn (uncommitted work, no secret-scan hook,
loose folders) or unknown (a check that could not run) marks the workspace
as needing decisions. If everything is genuinely pass, rerun with the
current plugin version and report a bug with the scan JSON attached
(after checking it contains no secrets, which it should not by design).

## Can secrets end up in the report?

No detection carries a value. Findings hold the file, line, kind, a rule
mask (`sk-***`, `AKIA***`, `Bearer ***`, `PRIVATE KEY***`, `***`) and a
salted one-way fingerprint (`sha256:` + 16 hex chars). The report schema
rejects a `value` or `preview` key on secret entries outright. To verify
on your own tree, plant a canary: put a fake token like
`sk-THISISNOTREAL1234567890` in a scratch file, run the audit, then grep
every artifact:

```
grep -R "THISISNOTREAL" . --include="*.json" --include="*.md"
```

The token must appear nowhere: not in the JSON, not in the report, not in
the command output. The security-regression suite runs exactly this check
with canaries on every commit; your run reproduces it locally.

## Windows notes

- Long paths. Trees deeper than 260 characters fail with `FileNotFoundError`
  unless long paths are enabled (registry `LongPathsEnabled`, or a Python
  newer than 3.6 which handles it when the OS allows).
- Symlink privileges. Creating symlinks needs Developer Mode or an elevated
  shell; the scanner itself only reads symlinks and needs no privilege.
- Deleting a cloned repo. `git` marks objects read-only, so a plain
  `rmtree` of a `.git` directory can fail. The QA runner chmods files
  before removing; when you clean up manually, use an erase that clears
  the read-only bit (for example `rm -rf` in Git Bash, or the `.agents-doctor-trash/`
  convention of `remediate.py`, which handles this).
