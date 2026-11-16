"""Tests for skills/workspace-audit/scripts/fingerprint.py.

Every test pins WORKSPACE_AUDIT_KEY_PATH into a temp directory: the
suite must never read or create the real per-installation key.
"""

import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / 'skills' / 'workspace-audit' / 'scripts'
sys.path.insert(0, str(SCRIPTS))

import fingerprint as fp  # noqa: E402

SAMPLE = 'workspace-audit test value'


class FingerprintKeyTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix='wsa-fp-test-')
        self.addCleanup(self._tmp.cleanup)
        self.base = Path(self._tmp.name)
        self.key_file = self.base / 'secret_key'
        self.set_key_path(self.key_file)

    def set_key_path(self, path):
        os.environ[fp.ENV_KEY_PATH] = str(path)
        self.addCleanup(os.environ.pop, fp.ENV_KEY_PATH, None)

    # --- key lifecycle ---------------------------------------------------

    def test_key_created_and_reloaded_stable(self):
        first = fp.get_key()
        self.assertEqual(len(first), fp.KEY_BYTES)
        self.assertTrue(self.key_file.exists())
        # a manually written valid key must be returned verbatim, proving
        # the second call loads the file instead of regenerating it
        self.key_file.write_bytes(b'K' * fp.KEY_BYTES)
        self.assertEqual(fp.get_key(), b'K' * fp.KEY_BYTES)

    def test_second_call_same_fingerprint(self):
        one = fp.fingerprint(SAMPLE)
        self.assertEqual(fp.fingerprint(SAMPLE), one)
        self.assertNotEqual(fp.fingerprint(SAMPLE + '!'), one)

    def test_different_key_different_fingerprint(self):
        one = fp.fingerprint(SAMPLE)
        self.set_key_path(self.base / 'other' / 'secret_key')
        two = fp.fingerprint(SAMPLE)
        self.assertNotEqual(one, two)
        self.assertTrue(two.startswith('hmac256:'))

    def test_output_length_and_prefix(self):
        out = fp.fingerprint(SAMPLE)
        self.assertTrue(out.startswith('hmac256:'))
        self.assertEqual(len(out), len('hmac256:') + 32)

    def test_key_path_override_env_honored(self):
        target = self.base / 'nested' / 'dir' / 'secret_key'
        self.set_key_path(target)
        fp.get_key()
        self.assertTrue(target.is_file())

    def test_corrupted_short_key_rejected(self):
        self.key_file.write_bytes(b'short')
        with self.assertRaises(fp.FingerprintKeyError):
            fp.get_key()
        with self.assertRaises(fp.FingerprintKeyError):
            fp.fingerprint(SAMPLE)

    def test_create_false_without_key_raises(self):
        missing = self.base / 'missing' / 'secret_key'
        self.set_key_path(missing)
        with self.assertRaises(fp.FingerprintKeyError):
            fp.get_key(create=False)
        self.assertFalse(missing.exists())

    @unittest.skipIf(os.name == 'nt', 'POSIX permission bits')
    def test_posix_permission_bits(self):
        nested = self.base / 'cfg' / 'workspace-audit' / 'secret_key'
        self.set_key_path(nested)
        fp.get_key()
        self.assertEqual(stat.S_IMODE(os.stat(nested).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(nested.parent).st_mode), 0o700)

    def test_error_messages_never_contain_key_material(self):
        self.key_file.write_bytes(b'TOPSECRET-raw')  # 13 bytes: malformed
        with self.assertRaises(fp.FingerprintKeyError) as ctx:
            fp.get_key()
        message = str(ctx.exception)
        self.assertNotIn('TOPSECRET-raw', message)
        self.assertNotIn(b'TOPSECRET-raw'.hex(), message)

    # --- CLI self-test -----------------------------------------------------

    def run_check(self, env_path):
        env = dict(os.environ, **{fp.ENV_KEY_PATH: str(env_path)})
        return subprocess.run(
            [sys.executable, str(SCRIPTS / 'fingerprint.py'), '--check'],
            capture_output=True, text=True, encoding='utf-8',
            errors='replace', env=env, timeout=60)

    def test_cli_check_ok_and_stable_across_runs(self):
        key = self.base / 'cli' / 'secret_key'
        first = self.run_check(key)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertTrue(
            first.stdout.startswith('key: ok, fingerprint sample: hmac256:'),
            first.stdout)
        second = self.run_check(key)
        self.assertEqual(second.returncode, 0)
        self.assertEqual(first.stdout, second.stdout)

    def test_cli_check_missing_key_fails(self):
        # the key path sits below a regular file, so the key is missing
        # and cannot be created: the self-test must exit 1
        blocker = self.base / 'blocker'
        blocker.write_text('not a directory', encoding='utf-8')
        result = self.run_check(blocker / 'secret_key')
        self.assertEqual(result.returncode, 1)
        self.assertNotIn('key: ok', result.stdout)
        self.assertTrue(result.stderr.strip())


if __name__ == '__main__':
    unittest.main()
