"""What every part of the scanner shares: the result type each pipeline stage
returns, the base of the scanner's own errors, and stderr logging for the
command-line entry points.
"""

from __future__ import annotations

import logging
import sys
from dataclasses import dataclass, field
from typing import Optional


class VulnmapperError(Exception):
    """Base of the errors the scanner raises and handles itself (an NVD or
    nmap call that could not be completed, a lookup with no answer)."""


@dataclass
class StageResult:
    """What one optional stage of a scan produced.

    ``block`` becomes ``metadata.<stage>`` in graph.json and ``warnings`` join
    ``metadata.warnings``. The CVE stages also return, per node, the
    vulnerabilities.json entry (``entries``) and the CVE rows behind it
    (``rows``). ``note`` and ``ran`` are the stage's line in
    ``metadata.stages``.
    """

    block: dict = field(default_factory=dict)
    warnings: list = field(default_factory=list)
    entries: dict = field(default_factory=dict)
    rows: dict = field(default_factory=dict)
    note: Optional[str] = None
    ran: bool = True


def plural(n: int, word: str) -> str:
    """``plural(1, "host")`` -> "1 host"; ``plural(3, "host")`` -> "3 hosts"."""
    return f"{n} {word}{'' if n == 1 else 's'}"


def setup_logging() -> None:
    """Log lines go to stderr; stdout is kept for the JSON a command prints."""
    logging.basicConfig(
        stream=sys.stderr,
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
