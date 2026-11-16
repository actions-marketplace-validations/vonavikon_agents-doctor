# Release checklist

One release = one tag `vX.Y.Z`. CI does the packaging; the steps below are
the human part.

## Before tagging

1. All CI jobs green on `main`: lint, the ubuntu/windows/macos test matrix
   (plus the 3.10 compatibility job), coverage (secret module 90, core 85),
   validate (manifests, schema fixtures), benchmark (wall caps).
2. Bump the version in BOTH manifests: `.claude-plugin/plugin.json` and
   `marketplace.json`. The versions must match; `python
   tools/validate_manifest.py` fails when they do not.
3. Update `CHANGELOG.md`: move the Unreleased entries under the new
   version with today's date, start a fresh Unreleased section.
4. Regenerate `docs/sample-report.md` so it shows the current report
   format: rebuild the demo workspace, scan it, run the report generator
   over the demo scan JSON, and commit the result.
5. Run the local full suite and the evals:

   ```
   python -m unittest discover -s tests -v
   cd qa && python eval.py
   python llm-eval/grade_report.py <report> llm-eval/fixtures/chaos.json
   python tools/check_links.py
   python tools/validate_manifest.py
   ```

## Tag and release

6. Commit the version bump, then tag: `git tag vX.Y.Z && git push origin
   main vX.Y.Z`. The `release` job (needs lint, tests, coverage, validate,
   benchmark) reruns the suite, packages `workspace-audit-<ver>.zip`
   (plugin files only) and creates the GitHub release with generated
   notes. Watch it finish on the Actions page.

## After release

7. Verify the marketplace install exactly as a user would:

   ```
   /plugin marketplace add vonavikon/workspace-audit
   /plugin install workspace-audit@workspace-audit
   ```

   Then run an audit in a scratch folder and check the report renders.

8. If the release is bad, roll back: delete the tag
   (`git tag -d vX.Y.Z && git push origin :refs/tags/vX.Y.Z`) and delete
   the GitHub release. Users who already installed keep the broken
   version, so fix forward: patch, bump to X.Y.Z+1, release again. Do not
   retag a moved commit under the same version.
