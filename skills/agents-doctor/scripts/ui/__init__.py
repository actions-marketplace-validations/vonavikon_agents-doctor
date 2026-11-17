"""Local web UI for agents-doctor (Visual TZ, Phase V1+).

Serves the diagnostics of an existing scan.json (or a fresh in-process
scan) on 127.0.0.1. Local-first: no external requests, no telemetry;
the browser talks only to this process. See ui/server.py for the API
contract and safety rules.
"""
