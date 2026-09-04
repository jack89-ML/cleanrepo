"""Filesystem scanning: binary detection, default ignores, line-oriented
hit extraction with sanitized context."""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path

from .patterns import Rule, builtin_rules, high_entropy_tokens

DEFAULT_SKIP_DIRS = {
    ".git", ".hg", ".svn", ".venv", "venv", "env", "__pycache__",
    "node_modules", "dist", "build", ".pytest_cache", ".mypy_cache",
    ".ruff_cache", ".tox", ".idea", ".vscode", "*.egg-info", "dummy",
}
DEFAULT_SKIP_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp",
    ".tif", ".tiff", ".pdf", ".zip", ".gz", ".tar", ".bz2", ".xz", ".7z",
    ".pyc", ".woff", ".woff2", ".ttf", ".eot", ".mp3", ".mp4", ".avi",
    ".mov", ".exe", ".dll", ".so", ".dylib", ".a", ".o", ".class",
}
_NULL_CHUNK = b"\x00"


@dataclass
class Finding:
    path: str
    line: int
    rule: str
    description: str
    severity: str
    category: str
    match: str
    context: str

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "line": self.line,
            "rule": self.rule,
            "description": self.description,
            "severity": self.severity,
            "category": self.category,
            "match": self.match,
            "context": self.context,
        }


def is_binary(data: bytes) -> bool:
    """Binary sniff on the leading chunk (NUL byte heuristic)."""
    return _NULL_CHUNK in data[:8192]


def should_skip_path(rel_path: str) -> bool:
    """Shared skip predicate for directory/ext defaults (path scans, staged
    payloads and history alike)."""
    parts = rel_path.replace("\\", "/").split("/")
    if any(part in DEFAULT_SKIP_DIRS or
           fnmatch.fnmatch(part, "*.egg-info") for part in parts):
        return True
    suffix = "." + parts[-1].rsplit(".", 1)[-1].lower() if "." in parts[-1] \
        else ""
    return suffix in DEFAULT_SKIP_EXT


def text_files(root: Path, ignore_paths: list[str] | None = None) -> list[Path]:
    """Text files under ``root`` honouring default + extra ignores."""
    ignore_paths = ignore_paths or []
    results: list[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        if should_skip_path(rel):
            continue
        if any(fnmatch.fnmatch(rel, pattern) for pattern in ignore_paths):
            continue
        try:
            probe = path.read_bytes()
        except OSError:
            continue
        if is_binary(probe):
            continue
        results.append(path)
    return results


def scan_text(content: str, path: str = "",
              rules: list[Rule] | None = None,
              rot13_words: list[str] | None = None,
              wordlist: list[str] | None = None,
              entropy_enabled: bool = True,
              entropy_threshold: float = 3.5) -> list[Finding]:
    """Run every rule and optional wordlists over a text buffer."""
    rules = rules if rules is not None else builtin_rules()
    rot13_words = rot13_words or []
    wordlist = wordlist or []
    findings: list[Finding] = []
    seen: set[tuple] = set()

    def push(line_no: int, rule_id: str, description: str, severity: str,
             category: str, match: str, context: str) -> None:
        key = (rule_id, line_no, match)
        if key in seen:
            return
        seen.add(key)
        findings.append(Finding(path=path, line=line_no, rule=rule_id,
                                description=description, severity=severity,
                                category=category, match=match[:80],
                                context=context))

    lines = content.splitlines()

    for line_no, line in enumerate(lines, start=1):
        covered: list[tuple[int, int]] = []
        for rule in rules:
            for match in rule.pattern.finditer(line):
                covered.append((match.start(), match.end()))
                push(line_no, rule.rule_id, rule.description, rule.severity,
                     rule.category, match.group(0),
                     _context(line, match.start(), match.end()))
        if entropy_enabled:
            for token in high_entropy_tokens(line,
                                             threshold=entropy_threshold):
                start = line.find(token)
                end = start + len(token)
                # a specific rule already owns this span: avoid double hits
                if any(start < c_end and end > c_start
                       for c_start, c_end in covered):
                    continue
                push(line_no, "high-entropy",
                     "high-entropy token (possible generated secret)",
                     "medium", "entropy", token, _context(line, start, end))
    for word in wordlist + rot13_words:
        if not word:
            continue
        matcher = None
        if len(word) >= 3 and re.fullmatch(r"[A-Za-z0-9]+", word):
            matcher = re.compile(rf"\b{re.escape(word)}\b", re.IGNORECASE)
        else:
            needle = word.lower()
        for line_no, line in enumerate(lines, start=1):
            if matcher is not None:
                position = matcher.search(line)
                if position is None:
                    continue
                start = position.start()
            else:
                start = line.lower().find(needle)
                if start < 0:
                    continue
            push(line_no, "wordlist", f"blocked word '{word}'", "medium",
                 "wordlist", word, _context(line, start, start + len(word)))
    return findings


def _context(line: str, start: int, end: int, width: int = 120) -> str:
    if len(line) <= width:
        return line.strip()
    window_start = max(0, start - (width // 3))
    window_end = min(len(line), window_start + width)
    prefix = "…" if window_start > 0 else ""
    suffix = "…" if window_end < len(line) else ""
    return (prefix + line[window_start:window_end] + suffix).strip()
