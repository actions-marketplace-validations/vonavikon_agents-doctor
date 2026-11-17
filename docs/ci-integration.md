# CI integration

Running agents-doctor in CI and local hooks: GitHub Actions, GitLab CI,
Jenkins, the pre-commit framework and plain git hooks. All examples
assume Python 3.10+ (standard library only, nothing to install).

## The exit gate: `audit --fail-on`

By default `audit` exits 0 whatever the findings — the report is
advisory. CI callers opt into a gate with `--fail-on`:

```
python skills/agents-doctor/scripts/agents_doctor.py audit . --fail-on high
```

The report is written first; only after a successful write does the
command exit 1, and only when at least one finding has **status fail**
and severity at or above the requested level:
`critical > high > medium > low > info`. Findings with status warn or
unknown never trip the gate. `--fail-on none` (the default) keeps the
historical behavior and exits 0.

## GitHub Actions

The repository ships a composite action at its root. It runs the audit,
exports SARIF and (optionally) evaluates a policy file; check out your
code first — the action does not check out anything itself.

```yaml
jobs:
  agents-doctor:
    runs-on: ubuntu-latest
    permissions:
      security-events: write   # for the SARIF upload
    steps:
      - uses: actions/checkout@v4
      - uses: vonavikon/agents-doctor@v2.1.0
        with:
          path: '.'
          fail-on: critical     # none|critical|high|medium|low|info
          deep: 'false'         # true: also scan git history (slower)
          sarif: 'true'         # writes agents-doctor.sarif
          # policy: policies/team.yml
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: agents-doctor.sarif
```

Inputs: `path` (workspace path, default `.`), `fail-on` (default
`critical`), `deep` (default `false`), `sarif` (default `true`),
`policy` (optional path to a policy YAML). The action produces
`agents-doctor-scan.json`, `agents-doctor.sarif` and — with `policy` —
`agents-doctor-policy.json` in the workspace. SARIF export and policy
evaluation also run when the audit itself failed the job, so the
artifacts are there to look at.

## Direct invocation (any CI)

No action needed — one `run` step:

```yaml
      - run: python skills/agents-doctor/scripts/agents_doctor.py audit .
              --fail-on high --out agents-doctor-scan.json
      - run: python skills/agents-doctor/scripts/agents_doctor.py sarif
              agents-doctor-scan.json --out agents-doctor.sarif
```

For a foreign repository, check out agents-doctor next to your code and
point the run at the script, or vendor the `skills/agents-doctor/`
folder.

## GitLab CI

The same command in `.gitlab-ci.yml`:

```yaml
agents-doctor:
  stage: test
  image: python:3.12
  script:
    - python skills/agents-doctor/scripts/agents_doctor.py audit .
      --fail-on critical --out agents-doctor-scan.json
  artifacts:
    when: always
    paths:
      - agents-doctor-scan.json
```

## Jenkins

A `sh` step; the exit code fails the build as usual:

```groovy
stage('agents-doctor') {
    steps {
        sh 'python skills/agents-doctor/scripts/agents_doctor.py audit . --fail-on critical'
    }
}
```

## pre-commit framework

The repository ships `.pre-commit-hooks.yaml`. The hook runs a fast
audit (no `--deep`) on every commit and blocks on critical findings:

```yaml
repos:
  - repo: https://github.com/vonavikon/agents-doctor
    rev: v2.1.0
    hooks:
      - id: agents-doctor-audit
```

The entry resolves `agents_doctor.py` through the repository being
committed (pre-commit runs system hooks from your repo root), so either
vendor `skills/agents-doctor/` in that repo or pin the path explicitly
with a local hook:

```yaml
repos:
  - repo: local
    hooks:
      - id: agents-doctor-audit
        name: agents-doctor workspace audit
        entry: python /abs/path/to/agents-doctor/skills/agents-doctor/scripts/agents_doctor.py
               audit . --fail-on critical
        language: system
        pass_filenames: false
        always_run: true
```

## Standalone git hooks (no framework)

`scripts/hooks/pre-commit.sh` and `scripts/hooks/pre-push.sh` are plain
bash; each blocks its git action on the same gate (`--fail-on critical`
by default, override with `AGENTS_DOCTOR_FAIL_ON`). Install from a
clone of agents-doctor:

```
cp scripts/hooks/pre-commit.sh <your-repo>/.git/hooks/pre-commit
cp scripts/hooks/pre-push.sh   <your-repo>/.git/hooks/pre-push
chmod +x <your-repo>/.git/hooks/pre-commit <your-repo>/.git/hooks/pre-push
```

or point `core.hooksPath` at the clone so updates ride `git pull`:

```
git -C <your-repo> config core.hooksPath /abs/path/to/agents-doctor/scripts/hooks
```

The hooks park the scan report under `.git/` so they never dirty the
worktree. If `agents_doctor.py` or python cannot be found, the hook
warns and lets the action through; once the audit runs, its exit code
decides.

## Exit codes

| Code | Meaning |
| ---- | ------- |
| 0 | Success: report written, no gate tripped (`compare` always exits 0) |
| 1 | `--fail-on` threshold reached, or a usage/IO error (bad root, unwritable report, failed fix step) |
| 2 | `explain`: finding id not found; invalid flag values (argparse usage error) |
| 3 | `fix`: no supported automatic fix for the finding |

## audit vs policy

`audit --fail-on` gates on finding severity inside the scanner's own
rules. Corporate rules ("no `.env` files at all", "AGENTS.md must name
an owner") are a separate concern: policy YAML files are evaluated
against a scan by the policy engine — either embedded into the audit
(`audit --policy FILE.yml`, the compliance report lands inside the scan
JSON) or as a standalone `policy` subcommand writing its own report.
Whether a violation blocks a pipeline is defined by the policy file
itself, not by an exit code. See [policies.md](policies.md).
