"""Command-line interface for cleanrepo.

Exit codes: 0 clean, 1 findings, 2 operational error, 130 interrupted.
With --json/--sarif the payload is the only thing on stdout; diagnostics
go to stderr.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .errors import (EXIT_CLEAN, EXIT_ERROR, EXIT_FINDINGS,
                     EXIT_INTERRUPTED, CleanrepoError)
from .git_ops import (git_root, history_payloads, install_hook, staged_payloads,
                      uninstall_hook)
from .output import render_json, render_sarif, render_table
from .patterns import load_plain_wordlist, load_rot13_wordlist
from .scanner import (CLEANREPO_IGNORE, load_ignore_patterns, matches_ignore,
                      scan_text, text_files)


def _decode(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def _collect_ignores(args) -> list[str]:
    """Auto .cleanrepoignore in the scan root, merged with --ignore-file."""
    patterns: list[str] = []
    root = Path(args.path)
    if args.staged or args.history:
        base = git_root(root if root.is_dir() else None)
    elif root.is_dir():
        base = root
    else:
        base = root.parent
    auto = base / CLEANREPO_IGNORE
    if auto.is_file():
        patterns.extend(load_ignore_patterns(auto))
    if args.ignore_file:
        explicit = Path(args.ignore_file)
        if not explicit.is_file():
            raise CleanrepoError(f"ignore file not found: {explicit}")
        patterns.extend(load_ignore_patterns(explicit))
    return patterns


def _collect_findings(args):
    root_arg = Path(args.path)
    rot13_words = (load_rot13_wordlist(Path(args.rot13_list))
                   if args.rot13_list else [])
    wordlist = (load_plain_wordlist(Path(args.wordlist))
                if args.wordlist else [])
    ignore_patterns = _collect_ignores(args)

    if args.staged:
        if args.history:
            raise CleanrepoError("choose either --staged or --history, not both")
        repo = git_root(root_arg if root_arg.is_dir() else None)
        payloads = [(name, content) for name, content in staged_payloads(repo)
                    if not matches_ignore(name, ignore_patterns)]
        sources = [(name, _decode(content)) for name, content in payloads]
    elif args.history:
        repo = git_root(root_arg if root_arg.is_dir() else None)
        sources = [(label, text)
                   for label, text in history_payloads(repo)
                   if not matches_ignore(label.split(":", 1)[-1],
                                         ignore_patterns)]
    else:
        if not root_arg.exists():
            raise CleanrepoError(f"path not found: {args.path}")
        if root_arg.is_file():
            name = root_arg.name
            if matches_ignore(name, ignore_patterns):
                sources = []
            else:
                sources = [(name, _decode(root_arg.read_bytes()))]
        else:
            files = text_files(root_arg, ignore_paths=args.ignore_paths +
                               ignore_patterns)
            sources = [(str(path.relative_to(root_arg)),
                        _decode(path.read_bytes()))
                       for path in files]

    findings = []
    scanned = len(sources)
    for name, content in sources:
        findings.extend(scan_text(
            content, path=name,
            rot13_words=rot13_words,
            wordlist=wordlist,
            entropy_enabled=args.entropy,
        ))
    findings.sort(key=lambda f: (f.path, f.line))
    return findings, scanned


def _cmd_scan(args) -> int:
    findings, scanned = _collect_findings(args)
    if args.json:
        print(render_json(findings, scanned))
    elif args.sarif:
        print(render_sarif(findings))
    else:
        if findings:
            print(render_table(findings))
            print(f"\n{len(findings)} finding(s) in {scanned} file(s).",
                  file=sys.stderr)
        else:
            print("No findings (clean).")
            print(f"Scanned {scanned} file(s); no findings.", file=sys.stderr)
    return EXIT_FINDINGS if findings else EXIT_CLEAN


def _cmd_hook(args) -> int:
    target = Path(args.path) if args.path else Path(".")
    if not target.is_dir():
        raise CleanrepoError(f"path not found: {target}")
    repo = git_root(target)
    if args.action == "install":
        hook = install_hook(repo)
        print(f"pre-commit hook installed: {hook}")
        return EXIT_CLEAN
    removed = uninstall_hook(repo)
    print("pre-commit hook removed." if removed
          else "no pre-commit hook found.")
    return EXIT_CLEAN


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cleanrepo",
        description="Deterministic pre-publish OPSEC and anti-leak scanner.",
    )
    parser.add_argument("--version", action="version",
                        version=f"cleanrepo {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan files or git payloads")
    scan.add_argument("path", nargs="?", default=".",
                      help="file or directory to scan (default: current dir)")
    scan.add_argument("--staged", action="store_true",
                      help="scan only staged changes (git index)")
    scan.add_argument("--history", action="store_true",
                      help="scan added lines of the whole git history")
    scan.add_argument("--rot13-list", default=None,
                      help="ROT13-encoded blocked words (one per line)")
    scan.add_argument("--wordlist", default=None,
                      help="plain blocked words (one per line)")
    scan.add_argument("--entropy", dest="entropy", action="store_true",
                      default=True,
                      help="enable high-entropy token analysis (default)")
    scan.add_argument("--no-entropy", dest="entropy", action="store_false",
                      help="disable high-entropy token analysis")
    scan.add_argument("--ignore-paths", action="append", default=[],
                      metavar="GLOB",
                      help="additional glob patterns to skip (repeatable)")
    scan.add_argument("--ignore-file", default=None,
                      metavar="PATH",
                      help="explicit gitignore-style file (merged with an "
                           "auto .cleanrepoignore in the scan root)")
    fmt = scan.add_mutually_exclusive_group()
    fmt.add_argument("--json", action="store_true",
                     help="pure JSON on stdout")
    fmt.add_argument("--sarif", action="store_true",
                     help="minimal SARIF 2.1.0 on stdout")

    hook = sub.add_parser("hook", help="manage the git pre-commit hook")
    hook.add_argument("action", choices=["install", "uninstall"])
    hook.add_argument("path", nargs="?", default=None,
                      help="repository path (default: current directory)")
    return parser


def run(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
    except SystemExit:
        return EXIT_ERROR
    try:
        if args.command == "scan":
            return _cmd_scan(args)
        if args.command == "hook":
            return _cmd_hook(args)
    except KeyboardInterrupt:
        print("interrupted by user", file=sys.stderr)
        return EXIT_INTERRUPTED
    except CleanrepoError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except Exception as exc:  # unexpected failure -> exit 2, no traceback
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    return EXIT_ERROR  # pragma: no cover


def main() -> None:
    try:
        sys.exit(run())
    except KeyboardInterrupt:  # pragma: no cover
        print("interrupted by user", file=sys.stderr)
        sys.exit(EXIT_INTERRUPTED)


if __name__ == "__main__":
    main()
