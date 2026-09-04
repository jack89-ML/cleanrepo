"""Output rendering: terminal table, pure JSON and minimal SARIF 2.1.0."""

from __future__ import annotations

import json

from . import __version__

_SEVERITY_LEVEL = {"critical": "error", "high": "error",
                   "medium": "warning", "low": "note"}


def render_table(findings: list) -> str:
    if not findings:
        return "No findings (clean)."
    headers = ["path", "line", "rule", "severity", "match"]
    rows = [[f.path, str(f.line), f.rule, f.severity, f.match]
            for f in findings]
    widths = [max(len(headers[i]),
                  *(len(str(row[i])) for row in rows))
              for i in range(len(headers))]
    lines = ["  ".join(headers[i].ljust(widths[i])
                       for i in range(len(headers)))]
    lines.append("-" * (sum(widths) + 2 * (len(headers) - 1)))
    for row in rows:
        lines.append("  ".join(str(row[i]).ljust(widths[i])
                               for i in range(len(headers))))
    return "\n".join(lines)


def render_json(findings: list, scanned_files: int) -> str:
    payload = {
        "cleanrepo_version": __version__,
        "scanned_files": scanned_files,
        "findings_count": len(findings),
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def render_sarif(findings: list) -> str:
    results = []
    rules = {}
    for finding in findings:
        rule_key = finding.rule
        rules.setdefault(rule_key, {
            "id": rule_key,
            "shortDescription": {"text": finding.description},
            "properties": {"category": finding.category,
                           "severity": finding.severity},
        })
        results.append({
            "ruleId": rule_key,
            "level": _SEVERITY_LEVEL.get(finding.severity, "note"),
            "message": {"text": f"{finding.description}: {finding.match}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.path},
                    "region": {"startLine": finding.line},
                }
            }],
        })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "cleanrepo",
                    "version": __version__,
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }
    return json.dumps(sarif, ensure_ascii=False, indent=2)
