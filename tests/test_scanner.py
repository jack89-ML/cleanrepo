"""Unit tests for filesystem scanning behaviour."""

import tempfile
import unittest
from pathlib import Path

from cleanrepo import scanner

DUMMY = Path(__file__).parent / "dummy"
AWS = (DUMMY / "aws.txt").read_text(encoding="utf-8").splitlines()[0].split(" = ", 1)[1].strip()
HEX1 = (DUMMY / "high_entropy.txt").read_text(encoding="utf-8").splitlines()[0]


class BinaryDetectionTest(unittest.TestCase):
    def test_null_byte_marked_binary(self):
        self.assertTrue(scanner.is_binary(b"abc\x00def"))
        self.assertTrue(scanner.is_binary(b"\x00" * 100 + b"text"))

    def test_plain_text_not_binary(self):
        self.assertFalse(scanner.is_binary(b"just plain text\nline 2\n"))


class FileIterationTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        (self.root / "ok.txt").write_text("hello world\n", encoding="utf-8")
        (self.root / "secret.txt").write_text(f"{AWS}\n")
        (self.root / "image.png").write_bytes(b"\x89PNG\r\n\x00binary")
        skip = self.root / ".venv"
        skip.mkdir()
        (skip / "lib.py").write_text(f"{AWS}\n")
        dummy = self.root / "dummy"
        dummy.mkdir()
        (dummy / "fake.txt").write_text(f"{AWS}\n")

    def tearDown(self):
        self._tmp.cleanup()

    def test_default_ignores_and_binary_skip(self):
        files = [p.name for p in scanner.text_files(self.root)]
        self.assertIn("secret.txt", files)     # real target kept
        self.assertIn("ok.txt", files)
        self.assertNotIn("image.png", files)   # binary
        self.assertNotIn("lib.py", files)      # .venv
        self.assertNotIn("fake.txt", files)    # dummy fixtures

    def test_extra_ignore_pattern(self):
        files = [p.name for p in
                 scanner.text_files(self.root, ignore_paths=["*.txt"])]
        self.assertEqual(files, [])

    def test_scan_finding_shape(self):
        findings = scanner.scan_text(f"creds: {AWS}\n",
                                     path="demo.txt")
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.path, "demo.txt")
        self.assertEqual(finding.line, 1)
        self.assertEqual(finding.rule, "aws-access-key")
        self.assertIn("AKIA", finding.match)
        self.assertTrue(finding.context.strip())

    def test_entropy_can_be_disabled(self):
        text = f"payload {HEX1}\n"
        with_enabled = scanner.scan_text(text, entropy_enabled=True)
        with_disabled = scanner.scan_text(text, entropy_enabled=False)
        self.assertTrue(any(f.rule == "high-entropy" for f in with_enabled))
        self.assertFalse(any(f.rule == "high-entropy"
                             for f in with_disabled))


if __name__ == "__main__":
    unittest.main()
