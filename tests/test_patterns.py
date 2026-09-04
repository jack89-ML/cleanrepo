"""Unit tests for rules, entropy and ROT13 helpers (dummy fixtures only)."""

import math
import pathlib
import unittest

from cleanrepo import patterns
from cleanrepo.scanner import scan_text

DUMMY = pathlib.Path(__file__).parent / "dummy"


def _dummy(name: str) -> str:
    return (DUMMY / name).read_text(encoding="utf-8")


class SecretPatternsTest(unittest.TestCase):
    def test_aws_key_detected(self):
        findings = scan_text(_dummy("aws.txt"))
        rules = {f.rule for f in findings}
        self.assertIn("aws-access-key", rules)

    def test_private_key_detected(self):
        findings = scan_text(_dummy("private_key.txt"))
        self.assertIn("private-key", {f.rule for f in findings})

    def test_local_paths_detected(self):
        findings = scan_text(_dummy("local_paths.txt"))
        rules = {f.rule for f in findings}
        self.assertIn("local-home-path", rules)
        matches = [f.match for f in findings if f.rule == "local-home-path"]
        self.assertTrue(any("C:\\Users\\alice" in m for m in matches))

    def test_local_home_path_inline_delimiters(self):
        home = "/home/"
        user = "alice"
        cases = [
            home + user + "/project",
            "'C:\\" + "Users\\bob\\secret'",
            "export DIR=/" + "Users/charlie/docs",
        ]
        for case in cases:
            findings = scan_text(case + "\n")
            self.assertTrue(
                any(f.rule == "local-home-path" for f in findings),
                f"not detected: {case}")

    def test_wordlist_word_boundaries(self):
        # substring inside a longer alnum word must not trigger
        findings = scan_text("omegaprod ready; projectomega shipped\n",
                             wordlist=["omega"])
        self.assertEqual(findings, [])
        hit = scan_text("project omega shipped\n", wordlist=["omega"])
        self.assertEqual(len(hit), 1)
        self.assertEqual(hit[0].rule, "wordlist")

    def test_private_ips_detected(self):
        findings = scan_text(_dummy("private_ips.txt"))
        rules = {f.rule for f in findings}
        self.assertIn("private-ip", rules)
        self.assertEqual(
            sum(1 for f in findings if f.rule == "private-ip"), 4)

    def test_db_urls_detected(self):
        findings = scan_text(_dummy("db_urls.txt"))
        self.assertEqual(sum(1 for f in findings if f.rule == "database-url"),
                         2)

    def test_tokens_detected(self):
        findings = scan_text(_dummy("tokens.txt"))
        rules = {f.rule for f in findings}
        self.assertIn("github-pat", rules)
        self.assertIn("gitlab-pat", rules)
        self.assertIn("jwt", rules)


class EntropyTest(unittest.TestCase):
    def test_shannon_range(self):
        self.assertAlmostEqual(patterns.shannon_entropy("aaaa"), 0.0)
        uniform = "".join(chr(65 + i) for i in range(26))
        self.assertGreaterEqual(patterns.shannon_entropy(uniform),
                                math.log2(26) - 0.01)

    def test_hex_token_flagged_natural_text_not(self):
        natural = ("the quick brown fox jumps over the lazy dog "
                   "and keeps running")
        tokens_natural = patterns.high_entropy_tokens(natural)
        self.assertEqual(tokens_natural, [])
        hex_line = _dummy("high_entropy.txt")
        tokens_hex = patterns.high_entropy_tokens(hex_line)
        self.assertEqual(len(tokens_hex), 2)
        self.assertTrue(all(len(t) == 64 for t in tokens_hex))


class Rot13Test(unittest.TestCase):
    def test_roundtrip(self):
        self.assertEqual(patterns.rot13(patterns.rot13("segreto")), "segreto")
        self.assertEqual(patterns.rot13("project-omega"), "cebwrpg-bzrtn")

    def test_wordlist_decoding(self):
        words = patterns.load_rot13_wordlist(DUMMY / "blocked_rot13.txt")
        self.assertEqual(words, ["project-omega", "client-atlas",
                                 "blackbox-alpha"])

    def test_encoded_word_found_in_text(self):
        # term present in clear text would be protected: wordlist carries
        # only the ROT13 form, decoded at runtime for the scan
        words = patterns.load_rot13_wordlist(DUMMY / "blocked_rot13.txt")
        findings = scan_text("deploying project-omega tonight",
                             wordlist=["unused"], rot13_words=words)
        self.assertTrue(any(f.rule == "wordlist"
                            and "project-omega" in f.match
                            for f in findings))


if __name__ == "__main__":
    unittest.main()
