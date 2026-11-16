# Bench

Synthetic workspaces and a benchmark runner for `skills/agents-doctor/scripts/audit_scan.py`.

## Generate a workspace

```
python bench/gen_workspace.py bench/work/ws-small  --size small
python bench/gen_workspace.py bench/work/ws-medium --size medium
python bench/gen_workspace.py bench/work-large --size large --seed 42 --force
```

Deterministic: the same `--size` + `--seed` builds a byte-identical tree (real
git repos with fixed commit dates, junk files, an 8 KB duplicate pair, a demo
`.env` token every third repo, `node_modules` dirs, 1-2 MB dataset files on
medium/large). Small is ~800 files, medium ~12000, large ~60000; files are
1-20 KB so even large builds in under ~90 s. The generator prints files, dirs,
bytes and build time.

Use a small fixture home directory (not your real home) so rows are comparable
across machines:

```
mkdir -p bench/work/home/.zcode/cli
echo "# fixture home" > bench/work/home/.zcode/AGENTS.md
echo '{}' > bench/work/home/.zcode/cli/history.jsonl
```

## Run

```
python bench/run_benchmark.py bench/work/ws-small --home bench/work/home \
    --out bench/BENCH-2026-11-16.md --label "local windows (small)"
```

Each invocation appends one row; run it several times to see variance. Use
`--max-wall <seconds>` to fail (exit non-zero) when the run gets too slow, for
example in CI.

## Reading the numbers

| Column | Meaning |
|---|---|
| wall (subprocess), s | one full CLI run via subprocess: interpreter startup, scan, writing scan.json. What a user of the skill waits. |
| scan() peak alloc, MB | peak of Python allocations during the in-process `scan()` call, measured with `tracemalloc`. |
| gates f/w/p/u/na | gate counts by status: fail / warn / pass / unknown / not_applicable. |
| skipped links | symlinks pointing outside the workspace root, skipped by the scanner. |

Peak alloc is **not** RSS: `tracemalloc` sees only memory Python allocated
during the `scan()` call. C-level buffers, the interpreter itself and memory
the allocator keeps in freed arenas do not show up, so RSS is always higher.
The two measurements also differ in scope: wall includes startup and JSON
writing, peak alloc does not.

## Committed vs generated

- `bench/BENCH-*.md` are committed: the running results log.
- Generated workspaces and the fixture home live under `bench/work/` and are
  **not** committed; add `bench/work/` to `.gitignore`.
