"""Integration tests against temporary git repositories."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from cleanrepo import git_ops
from cleanrepo.errors import CleanrepoError


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(repo), *args],
                          capture_output=True, text=True, check=False)


def _init_repo(root: Path) -> None:
    _git(root, "init", "-q", "-b", "main")
    _git(root, "config", "user.email", "tester@example.com")
    _git(root, "config", "user.name", "Tester")


class GitOpsTest(unittest.TestCase):
    DUMMY = Path(__file__).parent / "dummy"
    AWS = (DUMMY / "aws.txt").read_text(encoding="utf-8").splitlines()[0].split(" = ", 1)[1].strip()

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        _init_repo(self.root)

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, name: str, content: str) -> Path:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def test_git_root_detection(self):
        self.assertEqual(git_ops.git_root(self.root), self.root.resolve())

    def test_git_root_error_outside_repo(self):
        with tempfile.TemporaryDirectory() as outside:
            with self.assertRaises(CleanrepoError):
                git_ops.git_root(Path(outside))

    def test_staged_payloads(self):
        self.write("app.py", "print('hi')\n")
        _git(self.root, "add", "app.py")
        payloads = git_ops.staged_payloads(self.root)
        self.assertEqual([name for name, _ in payloads], ["app.py"])
        self.assertIn(b"print('hi')", payloads[0][1])

    def test_history_payloads_find_deleted_secret(self):
        self.write("conf.py", f"token = {self.AWS}\n")
        _git(self.root, "add", "conf.py")
        _git(self.root, "commit", "-q", "-m", "add secret")
        # secret removed from the worktree on the next commit
        self.write("conf.py", "token = ''\n")
        _git(self.root, "add", "conf.py")
        _git(self.root, "commit", "-q", "-m", "remove secret")
        payloads = git_ops.history_payloads(self.root)
        labels = [label for label, _ in payloads]
        joined = "\n".join(text for _, text in payloads)
        self.assertTrue(any(":" in label for label in labels))
        self.assertIn(self.AWS, joined)

    def test_hook_install_remove(self):
        hook = git_ops.install_hook(self.root)
        self.assertTrue(hook.exists())
        self.assertTrue(os.access(hook, os.X_OK))
        self.assertTrue(git_ops.is_cleanrepo_hook(hook))
        self.assertTrue(git_ops.uninstall_hook(self.root))
        self.assertFalse(hook.exists())


if __name__ == "__main__":
    unittest.main()
