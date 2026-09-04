"""End-to-end CLI tests: exit-code contract and stream purity."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CLI = [sys.executable, "-m", "cleanrepo.cli"]
DUMMY = REPO_ROOT / "tests" / "dummy"
AWS = (DUMMY / "aws.txt").read_text(encoding="utf-8").splitlines()[0].split(" = ", 1)[1].strip()


def _run(*args: str, cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run([*CLI, *args], capture_output=True, text=True,
                          cwd=str(cwd), check=False)


class CleanScanTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, name: str, content: str) -> Path:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def test_clean_file_exit_zero(self):
        self.write("note.txt", "hello world\n")
        result = _run("scan", str(self.root), cwd=self.root)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("No findings", result.stdout)

    def test_leak_file_exit_one(self):
        self.write("secret.txt", f"api_key = {AWS}\n")
        result = _run("scan", str(self.root), cwd=self.root)
        self.assertEqual(result.returncode, 1, result.stdout)

    def test_json_purity_on_findings(self):
        self.write("secret.txt", f"{AWS}\n")
        result = _run("scan", str(self.root), "--json", cwd=self.root)
        self.assertEqual(result.returncode, 1)
        payload = json.loads(result.stdout)
        self.assertGreaterEqual(payload["findings_count"], 1)
        self.assertEqual(payload["findings"][0]["rule"], "aws-access-key")

    def test_sarif_payload(self):
        self.write("secret.txt", f"{AWS}\n")
        result = _run("scan", str(self.root), "--sarif", cwd=self.root)
        self.assertEqual(result.returncode, 1)
        sarif = json.loads(result.stdout)
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertGreaterEqual(len(sarif["runs"][0]["results"]), 1)
        self.assertEqual(sarif["runs"][0]["results"][0]["ruleId"],
                         "aws-access-key")

    def test_missing_path_exit_two(self):
        result = _run("scan", str(self.root / "absent"), cwd=self.root)
        self.assertEqual(result.returncode, 2)
        self.assertIn("error:", result.stderr)

    def test_rot13_wordlist_flag(self):
        term = "project-omega"
        rot13 = term.translate(str.maketrans(
            "abcdefghijklmnopqrstuvwxyz", "nopqrstuvwxyzabcdefghijklm"))
        self.write("blocked_rot13.txt", f"# comment\n{rot13}\n")
        self.write("doc.txt", "deploying project-omega tonight\n")
        result = _run("scan", str(self.root),
                      "--rot13-list", str(self.root / "blocked_rot13.txt"),
                      cwd=self.root)
        self.assertEqual(result.returncode, 1)
        self.assertIn("project-omega", result.stdout)

    def test_ignore_paths_flag(self):
        self.write("sub/secret.txt", f"{AWS}\n")
        result = _run("scan", str(self.root), "--json",
                      "--ignore-paths", "sub/**", cwd=self.root)
        self.assertEqual(result.returncode, 0)


class StagedScanTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        subprocess.run(["git", "init", "-q", "-b", "main"], cwd=self.root,
                       check=True)
        subprocess.run(["git", "config", "user.email", "t@example.com"],
                       cwd=self.root, check=True)
        subprocess.run(["git", "config", "user.name", "T"],
                       cwd=self.root, check=True)

    def tearDown(self):
        self._tmp.cleanup()

    def test_staged_leak_exit_one(self):
        (self.root / "app.py").write_text(f"KEY = '{AWS}'\n")
        subprocess.run(["git", "add", "app.py"], cwd=self.root, check=True)
        result = _run("scan", "--staged", cwd=self.root)
        self.assertEqual(result.returncode, 1, result.stdout)

    def test_staged_clean_exit_zero(self):
        (self.root / "app.py").write_text("print('ok')\n")
        subprocess.run(["git", "add", "app.py"], cwd=self.root, check=True)
        result = _run("scan", "--staged", cwd=self.root)
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_staged_outside_repo_exit_two(self):
        with tempfile.TemporaryDirectory() as outside:
            result = _run("scan", "--staged", cwd=Path(outside))
        self.assertEqual(result.returncode, 2)


class HookCliTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        subprocess.run(["git", "init", "-q", "-b", "main"], cwd=self.root,
                       check=True)

    def tearDown(self):
        self._tmp.cleanup()

    def test_install_then_uninstall(self):
        result = _run("hook", "install", str(self.root), cwd=self.root)
        self.assertEqual(result.returncode, 0)
        hook = self.root / ".git" / "hooks" / "pre-commit"
        self.assertTrue(hook.exists())
        result = _run("hook", "uninstall", str(self.root), cwd=self.root)
        self.assertEqual(result.returncode, 0)
        self.assertFalse(hook.exists())


class IgnoreFileTest(unittest.TestCase):
    """.cleanrepoignore auto-discovery and --ignore-file behaviour."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, name: str, content: str) -> Path:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def test_auto_ignore_file_excludes_patterns(self):
        self.write(".cleanrepoignore", "# comment\naws_dummy_*.txt\n")
        self.write("aws_dummy_1.txt", f"{AWS}\n")
        self.write("keep.txt", f"{AWS}\n")
        result = _run("scan", str(self.root), "--json", cwd=self.root)
        self.assertEqual(result.returncode, 1)
        payload = json.loads(result.stdout)
        paths = [f["path"] for f in payload["findings"]]
        self.assertEqual(paths, ["keep.txt"])

    def test_dir_glob_excludes_nested(self):
        self.write(".cleanrepoignore", "fixtures/\n")
        self.write("fixtures/secret.txt", f"{AWS}\n")
        self.write("src/app.py", "print('ok')\n")
        result = _run("scan", str(self.root), "--json", cwd=self.root)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)["findings_count"], 0)

    def test_explicit_ignore_file_flag(self):
        alt = self.root / "rules.ignore"
        alt.write_text("token_*.txt\n", encoding="utf-8")
        self.write("token_a.txt", f"{AWS}\n")
        result = _run("scan", str(self.root), "--json",
                      "--ignore-file", str(alt), cwd=self.root)
        self.assertEqual(result.returncode, 0)

    def test_missing_ignore_file_exits_two(self):
        result = _run("scan", str(self.root),
                      "--ignore-file", str(self.root / "absent.ignore"),
                      cwd=self.root)
        self.assertEqual(result.returncode, 2)
        self.assertIn("ignore file not found", result.stderr)

    def test_staged_respects_auto_ignore(self):
        subprocess.run(["git", "init", "-q", "-b", "main"], cwd=self.root,
                       check=True)
        subprocess.run(["git", "config", "user.email", "t@example.com"],
                       cwd=self.root, check=True)
        subprocess.run(["git", "config", "user.name", "T"],
                       cwd=self.root, check=True)
        self.write(".cleanrepoignore", "gen_*.py\n")
        self.write("gen_key.py", f"KEY = '{AWS}'\n")
        subprocess.run(["git", "add", "-A"], cwd=self.root, check=True)
        result = _run("scan", "--staged", "--json", cwd=self.root)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)["findings_count"], 0)


if __name__ == "__main__":
    unittest.main()
