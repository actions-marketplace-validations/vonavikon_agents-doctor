"""fingerprint: keyed one-way fingerprints for workspace-audit evidence.

Findings carry fingerprints instead of raw secrets. This module replaces
the old public-salt SHA-256 with HMAC-SHA256 keyed by a per-installation
secret: fingerprints stay stable on one machine (baselines, dedup) but
cannot be computed, compared or rainbow-tabled anywhere else.

Key location (override with the WORKSPACE_AUDIT_KEY_PATH environment
variable; an empty value is ignored - the variable exists for tests and
power users who want the key on another volume):
- Windows: %LOCALAPPDATA%\\workspace-audit\\secret_key, falling back to
  ~\\AppData\\Local when LOCALAPPDATA is unset. The key file inherits the
  NTFS ACLs of the user profile; the stdlib has no ACL API, so no Windows
  permission enforcement is claimed - the guarantee is only that the key
  stays inside the user's local profile directory.
- POSIX: $XDG_CONFIG_HOME/workspace-audit/secret_key, default
  ~/.config/workspace-audit/secret_key. The directory is created 0o700
  and the key file is written 0o600 (umask permitting).

Key material: 32 random bytes (secrets.token_bytes). A key file that
cannot be read or holds fewer than 16 bytes raises FingerprintKeyError;
the error message carries the path and the reason, never the key bytes.

No silent fallback: with create=False and no key, or with a broken key,
callers get FingerprintKeyError and decide themselves. This module never
falls back to a public salt.

Migration note: the format changed from the old public-salt SHA-256
('sha256:' prefix, 16 hex chars) to 'hmac256:' + 32 hex chars (128 bits).
Baselines written by older versions will show a one-time all-new /
all-resolved diff on the first run after the upgrade; the rules_version
bump in the scan report documents the change.

CLI self-test: python fingerprint.py --check
"""

import hashlib
import hmac
import os
import secrets
import sys
from pathlib import Path

KEY_BYTES = 32
MIN_KEY_BYTES = 16
ENV_KEY_PATH = 'WORKSPACE_AUDIT_KEY_PATH'


class FingerprintKeyError(Exception):
    """The per-installation key is missing, unreadable or malformed."""


def key_path():
    """Location of the key file. WORKSPACE_AUDIT_KEY_PATH wins when set."""
    override = os.environ.get(ENV_KEY_PATH)
    if override:
        return Path(override)
    if os.name == 'nt':
        base = os.environ.get('LOCALAPPDATA') or Path.home() / 'AppData' / 'Local'
        return Path(base) / 'workspace-audit' / 'secret_key'
    base = os.environ.get('XDG_CONFIG_HOME') or Path.home() / '.config'
    return Path(base) / 'workspace-audit' / 'secret_key'


def get_key(create=True):
    """Load the key, creating it (32 random bytes) when missing.

    create=False with no key file raises FingerprintKeyError. An existing
    file that cannot be read or holds fewer than MIN_KEY_BYTES raises
    FingerprintKeyError; the message never contains key material.
    """
    path = key_path()
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        if not create:
            raise FingerprintKeyError(
                'no fingerprint key at %s and create is disabled' % path) from None
        return _create_key(path)
    except OSError as exc:
        raise FingerprintKeyError(
            'cannot read the fingerprint key file %s: %s' % (path, exc)) from None
    if len(data) < MIN_KEY_BYTES:
        raise FingerprintKeyError(
            'fingerprint key at %s is invalid: %d bytes, at least %d required'
            % (path, len(data), MIN_KEY_BYTES))
    return data


def _create_key(path):
    data = secrets.token_bytes(KEY_BYTES)
    try:
        path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return get_key()  # another process created it first: load theirs
    except OSError as exc:
        raise FingerprintKeyError(
            'cannot create the fingerprint key file %s: %s' % (path, exc)) from None
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    return data


def fingerprint(value):
    """'hmac256:' + first 32 hex chars of HMAC-SHA256(key, value).

    Stable across calls and runs on one installation; installations with
    different keys disagree on the same value.
    """
    key = get_key()
    return 'hmac256:' + hmac.new(key, value.encode('utf-8'),
                                 hashlib.sha256).hexdigest()[:32]


def main(argv=None):
    argv = list(sys.argv[1:]) if argv is None else list(argv)
    if argv in (['--help'], ['-h'], []):
        print('usage: python fingerprint.py --check\n'
              '  --check  verify the local key and print a sample fingerprint')
        return 0
    if argv != ['--check']:
        print('usage: python fingerprint.py --check', file=sys.stderr)
        return 1
    try:
        sample = fingerprint('workspace-audit self-test')
    except FingerprintKeyError as exc:
        print('key check failed: %s' % exc, file=sys.stderr)
        return 1
    print('key: ok, fingerprint sample: %s' % sample)
    return 0


if __name__ == '__main__':
    sys.exit(main())
