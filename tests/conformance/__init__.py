"""Conformance fixtures: tests/conformance/<harness_id>/fixture.py.
The fixture contract is documented in
skills/agents-doctor/scripts/harness/conformance/runner.py. This
package intentionally imports nothing: unittest discovery loads it
before any test file has set up sys.path. Subdirectories hold only
fixture.py files (no __init__.py), so discovery never imports them —
the runner loads them by path."""
