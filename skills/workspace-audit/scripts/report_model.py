"""Unified finding and gate model for workspace-audit reports.

Findings and gates share one schema so the JSON report, the baseline diff
and the skill layer all speak the same language. The module has no
dependencies beyond the standard library and knows nothing about how
facts are collected.

Status and severity are separate axes: status is the check outcome,
severity is the impact when the check does not pass. A finding with no
evidence cannot claim any outcome except unknown.
"""

SCHEMA_VERSION = '1.0'

SEVERITIES = ('critical', 'high', 'medium', 'low', 'info')
STATUSES = ('pass', 'fail', 'warn', 'unknown', 'not_applicable')

FINDING_KEYS = ('fid', 'gate', 'category', 'severity', 'status', 'title',
                'description', 'evidence', 'confidence', 'recommendation',
                'autofix_available')
GATE_KEYS = ('gid', 'n', 'name', 'description', 'checks', 'pass_when',
             'fail_when', 'warn_when', 'status', 'evidence', 'confidence',
             'recommendation', 'doc_ref')


def valid_severity(s):
    return s in SEVERITIES


def valid_status(s):
    return s in STATUSES


def _valid_confidence(c):
    return (isinstance(c, (int, float)) and not isinstance(c, bool)
            and 0.0 <= c <= 1.0)


def make_finding(fid, gate, category, severity, status, title, description,
                 evidence, confidence, recommendation,
                 autofix_available=False):
    """Build one finding dict.

    evidence is a list of free-form dicts (file, line, detail, ...) and
    must never carry raw secret values: pass only paths, line numbers,
    kinds, masks and fingerprints. A finding with empty evidence can only
    have status 'unknown': no proof, no verdict.
    """
    if not valid_severity(severity):
        raise ValueError('unknown severity: %r' % (severity,))
    if not valid_status(status):
        raise ValueError('unknown status: %r' % (status,))
    if not isinstance(evidence, list):
        raise ValueError('evidence must be a list of dicts')
    if any(not isinstance(e, dict) for e in evidence):
        raise ValueError('evidence entries must be dicts')
    if not evidence and status != 'unknown':
        raise ValueError('a finding with empty evidence must have status unknown')
    if not _valid_confidence(confidence):
        raise ValueError('confidence must be a number between 0 and 1')
    return {
        'schema_version': SCHEMA_VERSION,
        'fid': fid,
        'gate': gate,
        'category': category,
        'severity': severity,
        'status': status,
        'title': title,
        'description': description,
        'evidence': evidence,
        'confidence': confidence,
        'recommendation': recommendation,
        'autofix_available': autofix_available,
    }


def make_gate(gid, n, name, description, checks, pass_when, fail_when,
              warn_when, status, evidence, confidence, recommendation,
              doc_ref):
    """Build one gate dict. n keeps the historical 1..9 gate number from
    the pre-model report format."""
    if not isinstance(n, int) or isinstance(n, bool) or not 1 <= n <= 9:
        raise ValueError('gate number must be an int in 1..9, got %r' % (n,))
    if not valid_status(status):
        raise ValueError('unknown status: %r' % (status,))
    if not isinstance(checks, list):
        raise ValueError('checks must be a list')
    if not isinstance(evidence, list):
        raise ValueError('evidence must be a list of strings')
    if any(not isinstance(e, str) for e in evidence):
        raise ValueError('evidence entries must be strings')
    if not _valid_confidence(confidence):
        raise ValueError('confidence must be a number between 0 and 1')
    return {
        'schema_version': SCHEMA_VERSION,
        'gid': gid,
        'n': n,
        'name': name,
        'description': description,
        'checks': checks,
        'pass_when': pass_when,
        'fail_when': fail_when,
        'warn_when': warn_when,
        'status': status,
        'evidence': evidence,
        'confidence': confidence,
        'recommendation': recommendation,
        'doc_ref': doc_ref,
    }
