"""Centralized git remote URL sanitizer for workspace-audit.

Contract:
- Credential material embedded in a remote URL (user:pass segments,
  token-like usernames, credential query-parameter values) never appears
  in any value this module returns. Userinfo is dropped entirely from
  scheme URLs, credential query values become ***REDACTED***, and
  token-like usernames in scp-style remotes become ***REDACTED***.
- On any parse failure (including internally raised ValueError)
  sanitize_remote_url() returns the constant UNPARSED
  ('unparsed-remote'). It never raises, never logs, and never echoes
  the input back. has_credentials() returns a bool and never raises.
- sanitize_remote_url() is idempotent:
  sanitize_remote_url(sanitize_remote_url(x)) == sanitize_remote_url(x).
- Host classification (external hosting vs self-hosted) lives in
  audit_scan.classify_remote; it is deliberately not duplicated here.

A username segment is "token-like" when it is at least 20 characters
long or contains 'token' or 'key' (case-insensitive), tested on both
the raw and the percent-decoded form. Scheme URLs drop every userinfo
segment (a bare username can itself be an embedded credential and is
never needed for reporting); has_credentials() still distinguishes a
plain username (john@, git@) from a credential-looking one.
"""

import re
from urllib.parse import unquote, urlsplit

UNPARSED = 'unparsed-remote'
REDACTED = '***REDACTED***'

# Query parameter keys whose values are credentials. Case-insensitive
# exact key match (raw or percent-decoded); repeated params are masked
# one by one, so 'token=a&token=b' masks both values.
CREDENTIAL_QUERY_KEYS = frozenset((
    'token', 'access_token', 'password', 'pass', 'auth', 'api_key',
    'apikey', 'key', 'secret', 'signature', 'sig', 'client_secret',
    'refresh_token',
))

_SCHEME_RE = re.compile(r'^[A-Za-z][A-Za-z0-9+.-]*://')


def sanitize_remote_url(url: str) -> str:
    """Return the url with all credential material removed or masked.

    Scheme URLs (https, http, ssh, git, ...) lose their userinfo
    entirely; scheme, host, port, path and fragment are kept. Credential
    query values become ***REDACTED*** while other parameters survive
    verbatim. scp-style 'user@host:path' keeps its user unless the user
    contains a colon or looks like a token, in which case the user
    segment becomes ***REDACTED***. Plain 'host:path' remotes and local
    paths are returned unchanged. Anything unparseable returns UNPARSED
    instead of echoing the input.
    """
    try:
        return _sanitize(url)
    except Exception:
        return UNPARSED


def has_credentials(url: str) -> bool:
    """True when the url carries detectable credentials.

    True for: user:pass userinfo, a token-like username, credential
    query parameters, a colon or token-like user in an scp-style
    remote, and ssh:// (any scheme) URLs with a password. False for a
    plain username (john@, git@), clean URLs, local paths, and
    unparseable input.
    """
    try:
        return _has_credentials(url)
    except Exception:
        return False


# --- internal helpers (never raise outward) --------------------------------

def _has_control_chars(text):
    return any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in text)


def _is_token_like(user):
    lowered = user.lower()
    return len(user) >= 20 or 'token' in lowered or 'key' in lowered


def _is_credential_query_key(raw_key):
    return (raw_key.lower() in CREDENTIAL_QUERY_KEYS
            or unquote(raw_key).lower() in CREDENTIAL_QUERY_KEYS)


def _mask_query(query):
    """Mask values of credential keys; keep every other part verbatim."""
    if not query:
        return ''
    parts = []
    for part in query.split('&'):
        if '=' in part:
            key, _value = part.split('=', 1)
            if _is_credential_query_key(key):
                parts.append(key + '=' + REDACTED)
            else:
                parts.append(part)
        else:
            parts.append(part)  # bare key with no value: nothing to mask
    return '&'.join(parts)


def _sanitize(url):
    if not isinstance(url, str):
        return UNPARSED
    url = url.strip()
    if not url or _has_control_chars(url):
        return UNPARSED
    if _SCHEME_RE.match(url):
        return _sanitize_scheme_url(url)
    if '@' in url:
        return _sanitize_scp_with_user(url)
    if ':' in url:
        return _sanitize_scp_no_user(url)
    return url  # local path or bare hostname: no credential carriers


def _sanitize_scheme_url(url):
    parsed = urlsplit(url)
    netloc = parsed.netloc
    if not netloc or any(ch.isspace() for ch in netloc):
        return UNPARSED
    if parsed.hostname is None:
        return UNPARSED
    try:
        parsed.port  # property access validates the port range
    except ValueError:
        return UNPARSED
    hostport = netloc.rsplit('@', 1)[-1]
    if not hostport:
        return UNPARSED
    scheme = url.split('://', 1)[0].lower()
    result = scheme + '://' + hostport + parsed.path
    query = _mask_query(parsed.query)
    if query:
        result += '?' + query
    if parsed.fragment:
        result += '#' + parsed.fragment
    return result


def _sanitize_scp_with_user(url):
    user, _, rest = url.rpartition('@')
    if not rest or ':' not in rest or '://' in rest:
        return UNPARSED
    if any(ch.isspace() for ch in rest):
        return UNPARSED
    host = rest.split(':', 1)[0]
    if not host or '/' in host or any(ch.isspace() for ch in host):
        return UNPARSED
    if not user:
        return rest
    decoded = unquote(user)
    if (':' in user or ':' in decoded
            or _is_token_like(user) or _is_token_like(decoded)):
        user = REDACTED
    return user + '@' + rest


def _sanitize_scp_no_user(url):
    host, _, rest = url.partition(':')
    if not host or not rest:
        return UNPARSED
    if '/' in host or '@' in host or any(ch.isspace() for ch in host):
        return UNPARSED
    return url


def _has_credentials(url):
    if not isinstance(url, str):
        return False
    url = url.strip()
    if not url or _has_control_chars(url):
        return False
    if _SCHEME_RE.match(url):
        parsed = urlsplit(url)
        netloc = parsed.netloc
        userinfo = netloc.rsplit('@', 1)[0] if '@' in netloc else ''
        if userinfo:
            decoded = unquote(userinfo)
            if ':' in userinfo or ':' in decoded:
                return True
            if _is_token_like(userinfo) or _is_token_like(decoded):
                return True
        for part in parsed.query.split('&'):
            if '=' in part and _is_credential_query_key(part.split('=', 1)[0]):
                return True
        return False
    if '@' in url:
        user, _, _rest = url.rpartition('@')
        if not user:
            return False
        decoded = unquote(user)
        if ':' in user or ':' in decoded:
            return True
        return _is_token_like(user) or _is_token_like(decoded)
    return False
