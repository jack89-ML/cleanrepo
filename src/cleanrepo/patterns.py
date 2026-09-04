"""Detection rules, ROT13 helpers and Shannon-entropy primitives.

The built-in rule set covers cloud/API credentials, private key headers,
local absolute paths, RFC 1918 private networks and database connection
strings. Wordlists may be supplied in clear text or ROT13-encoded so the
rules file itself never stores the sensitive terms it protects.
"""

from __future__ import annotations

import codecs
import math
import re
from dataclasses import dataclass


def rot13(text: str) -> str:
    """Bidirectional ROT13 transform (apply twice to decode)."""
    return codecs.encode(text, "rot13")


def load_rot13_wordlist(path) -> list[str]:
    """Read a ROT13-encoded wordlist and return decoded terms."""
    words = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            words.append(rot13(line).lower())
    return words


def load_plain_wordlist(path) -> list[str]:
    words = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            words.append(line.lower())
    return words


@dataclass(frozen=True)
class Rule:
    rule_id: str
    description: str
    severity: str          # critical | high | medium | low
    category: str
    pattern: re.Pattern


def _compile(id_, description, severity, category, regex):
    return Rule(rule_id=id_, description=description, severity=severity,
                category=category,
                pattern=re.compile(regex, re.IGNORECASE if id_ not in (
                    "aws-access-key",) else 0))


def builtin_rules() -> list[Rule]:
    return [
        _compile("aws-access-key", "AWS access key id", "critical", "cloud",
                 r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        _compile("github-pat", "GitHub personal access token", "critical",
                 "cloud", r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b"),
        _compile("gitlab-pat", "GitLab personal access token", "critical",
                 "cloud", r"\bglpat-[A-Za-z0-9_-]{20,}\b"),
        _compile("jwt", "JSON web token", "high", "cloud",
                 r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\."
                 r"[A-Za-z0-9_-]{5,}\b"),
        _compile("generic-api-key", "generic API key assignment", "high",
                 "cloud",
                 r"\b(?:api[_-]?key|secret|token|password)\b\s*[:=]\s*"
                 r"[\"']?[A-Za-z0-9_\-]{12,}[\"']?"),
        _compile("private-key", "private key header", "critical",
                 "crypto",
                 r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE "
                 r"KEY(?: BLOCK)?-----"),
        _compile("local-home-path", "local absolute home path", "medium",
                 "path",
                 r"(?i)(?:(?<=[\s\"'=(])|^|(?<=\b))"
                 r"(?:/(?:home|Users)/|[a-zA-Z]:[/\\]Users[/\\])"
                 r"[A-Za-z0-9._-]+[/\\]"),
        _compile("private-ip", "RFC 1918 private IPv4 address", "low",
                 "network",
                 r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
                 r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"
                 r"192\.168\.\d{1,3}\.\d{1,3})\b"),
        _compile("database-url", "database connection string with "
                 "credentials", "high", "cloud",
                 r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?)://"
                 r"[^:\s/]+:[^@\s/]+@"),
    ]


ENTROPY_TOKEN = re.compile(r"[A-Za-z0-9-]{20,}")


def shannon_entropy(value: str) -> float:
    """Shannon entropy in bits per character."""
    if not value:
        return 0.0
    length = len(value)
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    entropy = -sum((count / length) * math.log2(count / length)
                   for count in counts.values())
    return entropy


def high_entropy_tokens(line: str, threshold: float = 3.5,
                        distinct_min: int = 4) -> list[str]:
    """Long alnum runs whose entropy suggests a generated secret.

    Natural prose and snake_case identifiers rarely produce 20+ char runs
    containing a digit, so candidates must include at least one ASCII digit
    (hex/base64/uuid-like tokens) — pure-letter words and method names are
    never flagged.
    """
    found: list[str] = []
    for match in ENTROPY_TOKEN.finditer(line):
        token = match.group(0)
        if len(token) < 20:
            continue
        if not any(char.isdigit() for char in token):
            continue
        if len(set(token)) < distinct_min:
            continue
        if shannon_entropy(token) >= threshold:
            found.append(token)
    return found
