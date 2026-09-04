# cleanrepo

Deterministic pre-publish OPSEC scanner for source trees and git history. Detects leaked secrets, private keys, local absolute paths, internal IPs and high-entropy tokens before a repository goes public — as a standalone CLI or as a git pre-commit hook. Pure Python 3.10+ standard library.

[![CI](https://github.com/jack89-ML/cleanrepo/actions/workflows/test.yml/badge.svg)](https://github.com/jack89-ML/cleanrepo/actions)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## What it detects

| Category | Examples | Rule ids |
| :--- | :--- | :--- |
| Cloud & API credentials | AWS access keys (`AKIA…`), GitHub PAT (`ghp_…`), GitLab PAT (`glpat-…`), JWTs, `api_key = …` assignments | `aws-access-key`, `github-pat`, `gitlab-pat`, `jwt`, `generic-api-key` |
| Cryptographic material | OpenSSH / RSA / EC / DSA / PGP private key headers | `private-key` |
| Local paths | `/home/<user>/`, `/Users/<user>/`, `C:\Users\<user>\` | `local-home-path` |
| Internal networks | RFC 1918 IPv4 (10/8, 172.16/12, 192.168/16) | `private-ip` |
| Database URLs | connection strings embedding credentials (`postgres`, `mysql`, `mongodb`) | `database-url` |
| Generated secrets | long alphanumeric runs with Shannon entropy ≥ 3.5 bits/char | `high-entropy` |
| Blocked terms | your own watchlist, clear or ROT13-encoded | `wordlist` |

## Design principles

- **Zero dependencies** — scanning, entropy math, git plumbing and hook management use only the standard library.
- **Deterministic** — same tree, same findings, stable ordering, no network.
- **Silent on binaries** — NUL-byte sniffing skips binary payloads before any rule runs.
- **Sane defaults** — VCS/tooling directories (`.git`, `.venv`, `__pycache__`, `node_modules`, `dist`, …) and binary/image formats are ignored out of the box, together with any directory named `dummy` (conventional home for intentionally fake fixtures).
- **ROT13-native watchlists** — the rules file itself never needs to contain the sensitive terms it protects.
- **Pipeline purity** — with `--json` / `--sarif`, `stdout` carries only the payload; diagnostics go to `stderr`.

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Usage

### Scan a directory

```bash
cleanrepo scan .                 # whole tree, default ignores
cleanrepo scan ./src --json      # machine-readable findings
cleanrepo scan . --ignore-paths 'docs/**' --ignore-paths '*.md'
cleanrepo scan . --no-entropy    # skip entropy analysis
```

### Scan git state

```bash
cleanrepo scan --staged          # index only — fast pre-commit check
cleanrepo scan --history         # added lines of every commit in git log
```

### Blocked words

```bash
# plain list (one term per line, `#` comments allowed)
cleanrepo scan . --wordlist ./rules.txt

# ROT13-encoded list, so the rules file never stores plaintext terms
cleanrepo scan . --rot13-list ./rules.rot13
# build it with: python3 -c "import codecs;print(codecs.encode('term','rot13'))"
```

### Pre-commit hook

```bash
cleanrepo hook install           # writes executable .git/hooks/pre-commit
cleanrepo hook uninstall
```

The hook runs `cleanrepo scan --staged` and blocks the commit on findings.

## Exit codes

| Code | Meaning |
| :--- | :--- |
| `0` | clean — no findings |
| `1` | findings — violations detected |
| `2` | operational error — missing path, invalid flags, not a git tree |
| `130` | interrupted by user (SIGINT) |

## SARIF output

`cleanrepo scan . --sarif` emits minimal SARIF 2.1.0, importable into GitHub's Security tab (Code Scanning) or any SARIF-capable CI:

```bash
cleanrepo scan . --sarif > results.sarif
```

## Testing

The suite runs fully offline over synthetic fixtures (RFC 2606 domains, official dummy AWS key, fake private keys):

```bash
python3 -m unittest discover -s tests -v
```

Includes a zero-leak guard (`tests/test_zeroleak.py`) that scans the tree for forbidden real-world tokens.

## License

MIT
