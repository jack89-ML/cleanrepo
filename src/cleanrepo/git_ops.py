"""Git integration: staged-payload extraction, history inspection and
pre-commit hook management. All git access goes through subprocess so the
package stays dependency-free."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from .errors import CleanrepoError

HOOK_SKELETON = """#!/bin/sh
# cleanrepo pre-commit hook (installed by `cleanrepo hook install`).
# Blocks the commit when the staged scan reports findings.
if command -v cleanrepo >/dev/null 2>&1; then
    cleanrepo scan --staged --no-entropy || exit 1
else
    python3 -m cleanrepo.cli scan --staged --no-entropy || exit 1
fi
"""


def _run(args: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(args, capture_output=True, cwd=str(cwd)
                              if cwd else None, timeout=300)
    except FileNotFoundError as exc:
        raise CleanrepoError("git binary not found on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise CleanrepoError(f"git timed out: {exc}") from exc


def git_root(start: Path | None = None) -> Path:
    cwd = start or Path.cwd()
    completed = _run(["git", "rev-parse", "--show-toplevel"], cwd=cwd)
    if completed.returncode != 0:
        raise CleanrepoError(
            f"not inside a git work tree: {cwd} "
            f"({completed.stderr.decode(errors='replace').strip()})")
    return Path(completed.stdout.decode(errors="replace").strip())


def staged_payloads(root: Path) -> list[tuple[str, bytes]]:
    """(path, content) pairs for files in the index (staged)."""
    completed = _run(["git", "-C", str(root), "diff", "--cached",
                      "--name-only", "-z"])
    if completed.returncode != 0:
        raise CleanrepoError("git diff --cached failed")
    names = [name for name in
             completed.stdout.decode(errors="replace").split("\x00") if name]
    payloads: list[tuple[str, bytes]] = []
    for name in names:
        blob = _run(["git", "-C", str(root), "show", f":{name}"])
        if blob.returncode != 0:
            continue
        payloads.append((name, blob.stdout))
    return payloads


def history_payloads(root: Path, limit_commits: int = 0) -> list[tuple[str, str]]:
    """Added lines of every commit, bucketed per commit:file.

    Returns ``(label, added_text)`` with label ``<sha8>:<path>`` so findings
    point at the exact commit that introduced a secret.
    """
    rev_list = _run(["git", "-C", str(root), "rev-list", "--all"])
    if rev_list.returncode != 0:
        raise CleanrepoError("git rev-list --all failed")
    shas = rev_list.stdout.decode(errors="replace").split()
    if limit_commits:
        shas = shas[:limit_commits]
    payloads: list[tuple[str, str]] = []
    for sha in shas:
        patch = _run(["git", "-C", str(root), "show", "--format=",
                      "--no-ext-diff", "--no-renames", sha])
        if patch.returncode != 0:
            continue
        current_file = "?"
        added: list[str] = []
        for raw in patch.stdout.decode(errors="replace").splitlines():
            if raw.startswith("diff --git "):
                if added:
                    payloads.append((f"{sha[:8]}:{current_file}",
                                     "\n".join(added)))
                added = []
                parts = raw.split(" b/", 1)
                current_file = parts[1] if len(parts) > 1 else "?"
            elif raw.startswith("+++"):
                continue
            elif raw.startswith("+"):
                added.append(raw[1:])
        if added:
            payloads.append((f"{sha[:8]}:{current_file}", "\n".join(added)))
    return payloads


def install_hook(root: Path) -> Path:
    git_dir = root / ".git"
    hooks_dir = git_dir / "hooks" if git_dir.is_dir() else \
        Path((_run(["git", "-C", str(root), "rev-parse", "--git-dir"])
               .stdout.decode(errors="replace").strip())) / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook = hooks_dir / "pre-commit"
    hook.write_text(HOOK_SKELETON, encoding="utf-8")
    hook.chmod(hook.stat().st_mode | 0o111)
    return hook


def uninstall_hook(root: Path) -> bool:
    git_dir = root / ".git"
    hook = git_dir / "hooks" / "pre-commit"
    if hook.exists():
        hook.unlink()
        return True
    return False


def is_cleanrepo_hook(hook: Path) -> bool:
    """True when the hook file was written by this tool."""
    try:
        return "cleanrepo pre-commit hook" in hook.read_text(encoding="utf-8",
                                                            errors="ignore")
    except OSError:
        return False
