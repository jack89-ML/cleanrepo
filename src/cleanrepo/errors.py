"""Error taxonomy and POSIX exit-code contract.

  0  clean (no findings)
  1  findings (violations detected)
  2  operational error
  130 interrupted by user
"""

from __future__ import annotations

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2
EXIT_INTERRUPTED = 130


class CleanrepoError(Exception):
    """Operational failure (missing path, bad arguments, git errors)."""
