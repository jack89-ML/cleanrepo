# cleanrepo — Operations Cheatsheet

Deterministic pre-publish OPSEC scanner. Exit codes: `0` clean · `1` findings · `2` error · `130` interrupted.

## Quick commands

```bash
cleanrepo scan .                     # scan current tree (default ignores)
cleanrepo scan ./src --json          # machine-readable findings
cleanrepo scan --staged              # only files in the git index
cleanrepo scan --history             # added lines of every commit
cleanrepo hook install               # write .git/hooks/pre-commit
cleanrepo hook uninstall             # remove (only hooks cleanrepo installed)
```

## Options

```bash
--rot13-list file.txt     # blocked terms, ROT13-encoded (one per line, # comments)
--wordlist file.txt       # blocked terms in plain text
--entropy | --no-entropy  # toggle high-entropy token analysis (default on)
--ignore-paths 'glob'     # extra skip pattern (repeatable)
--json                    # pure JSON payload on stdout
--sarif                   # minimal SARIF 2.1.0 for GitHub Security tab
```

Build a ROT13 wordlist without storing plaintext terms:

```bash
python3 -c "import codecs; print(codecs.encode('term','rot13'))" >> rules.rot13
```

## jq pipelines

```bash
# rule summary
cleanrepo scan . --json | jq -r '.findings | group_by(.rule)[] | "\(.[0].rule): \(length)"'

# severity histogram
cleanrepo scan . --json | jq -r '.findings[].severity' | sort | uniq -c

# first hit per file
cleanrepo scan . --json | jq -r '.findings | group_by(.path)[] | "\(.[0].path): \(.[0].line) \(.[0].rule)"'

# only critical findings, TSV for spreadsheets
cleanrepo scan . --json | jq -r '.findings[] | select(.severity=="critical") | [.path,.line,.rule,.match] | @tsv'
```

## Git hook workflow

```bash
cleanrepo hook install              # one-time setup per repo
git add file.py && git commit -m x  # staged scan runs automatically, blocks on findings

# bypass once in an emergency (NOT recommended)
git commit --no-verify -m "urgent"
```

## CI gate (GitHub Actions snippet)

```yaml
- name: Cleanrepo scan
  run: |
    pip install cleanrepo
    cleanrepo scan . || exit 1
```

## Default ignores (silent, no false positives)

- Directories: `.git .venv venv env __pycache__ node_modules dist build .pytest_cache .mypy_cache .ruff_cache .tox .idea .vscode *.egg-info dummy`
- Extensions: images (`png jpg svg …`), archives, binaries, fonts, media
- Binary detection: leading NUL-byte chunk is skipped before any rule runs

`dummy/` is the conventional home for intentionally fake fixture secrets — excluded by design so unit-test fixtures never trip the scanner.

## SARIF into GitHub Security

```bash
cleanrepo scan . --sarif > results.sarif
```

Import via Code Scanning ("upload SARIF") or any SARIF-capable CI; rules map to
error/warning/note by severity.
