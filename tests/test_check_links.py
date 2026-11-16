"""Tests for tools/check_links.py.

Two synthetic trees exercise the function API (clean and dirty), then the
real repo root must come back clean: every markdown link in the repository
resolves. If you add a doc with a broken link, this test fails first.
"""
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'tools'))
import check_links  # noqa: E402


def write(root, rel, content):
    p = Path(root) / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        p.write_bytes(content)
    else:
        p.write_text(content, encoding='utf-8')
    return p


class CleanTreeTest(unittest.TestCase):
    def test_no_problems(self):
        with tempfile.TemporaryDirectory() as tmp:
            write(tmp, 'index.md', '\n'.join([
                '[b](b.md)',
                '![pic](pic.png)',
                '[nested](sub/c.md)',
                '[fragment](sub/c.md#part)',
                '[external](https://example.com/a)',
                '[mail](mailto:x@example.com)',
                '[anchor](#section)',
                '[spaced](<a file.md>)',
                '```',
                '[not a link](because-fence.md)',
                '```',
            ]))
            write(tmp, 'b.md', 'ok')
            write(tmp, 'pic.png', b'\x89PNG')
            write(tmp, 'sub/c.md', 'ok')
            write(tmp, 'a file.md', 'ok')
            problems, files = check_links.check_tree(tmp)
        self.assertEqual(problems, [])
        self.assertEqual(files, 4)


class DirtyTreeTest(unittest.TestCase):
    def test_missing_and_backslash_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            write(tmp, 'a.md', '[missing](nope.md) and [back](sub\\c.md)')
            write(tmp, 'sub/c.md', 'exists, but the link uses a backslash')
            problems, files = check_links.check_tree(tmp)
        self.assertEqual(files, 2)
        joined = '\n'.join(problems)
        self.assertIn('nope.md', joined)
        self.assertIn('backslash', joined)
        self.assertEqual(len(problems), 2)


class RepoGreenTest(unittest.TestCase):
    def test_repo_markdown_links_resolve(self):
        problems, files = check_links.check_tree(REPO)
        self.assertEqual(problems, [], '\n'.join(problems))
        self.assertGreater(files, 0)


if __name__ == '__main__':
    unittest.main()
