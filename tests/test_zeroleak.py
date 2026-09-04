"""Zero-leak guard: the source tree must never reference real case data."""

import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class ZeroLeakTest(unittest.TestCase):
    # ROT13-encoded sensitive tokens so the guard itself carries nothing
    # literal that could leak into the repository.
    FORBIDDEN = {
        "Fniryyv",
        "Pebgbar",
        "Pngnamneb",
        "Fpnyvfr",
        "Cbagvrev",
        "Trezvanen",
        "Snovnab",
        "hfhpncvbar",
        "wcrenppuvb",
        "crenppuvb",
    }

    def _decoded(self):
        table = str.maketrans(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "nopqrstuvwxyzabcdefghijklmNOPQRSTUVWXYZABCDEFGHIJKLM")
        return {token.translate(table) for token in self.FORBIDDEN}

    def test_no_leak_tokens_in_tree(self):
        offenders = []
        forbidden = self._decoded()
        for path in ROOT.rglob("*"):
            if not path.is_file():
                continue
            rel = path.relative_to(ROOT).as_posix()
            if any(part in {".git", ".venv", "__pycache__", "dummy"}
                   for part in rel.split("/")):
                continue
            if path.suffix.lower() in {".pyc", ".png", ".svg", ".ico"}:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for token in forbidden:
                if re.search(rf"\b{token}\b", text, re.IGNORECASE):
                    offenders.append(f"{rel}: {token}")
        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main()
