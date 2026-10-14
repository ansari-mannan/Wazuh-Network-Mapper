"""What every part of the scanner shares: the result type each pipeline stage
returns, the base of the scanner's own errors, and stderr logging for the
command-line entry points.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import tempfile
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


def write_bytes_atomic(path: str, data: bytes) -> None:
    """Write ``data`` to ``path`` through a temp file in the same folder (named
    after the target), then rename it over ``path``: a reader sees the old file
    or the new one, never half of one. The file gets a plain open()'s mode."""
    folder = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=f".{os.path.basename(path)}.", suffix=".tmp", dir=folder)
    try:
        umask = os.umask(0)                 # mkstemp creates 0600
        os.umask(umask)
        os.chmod(tmp, 0o666 & ~umask)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def write_json_atomic(path: str, document, indent: Optional[int] = None) -> None:
    """``document`` as JSON (compact unless ``indent``) and a newline, atomically."""
    text = json.dumps(document, indent=indent, separators=None if indent else (",", ":"))
    write_bytes_atomic(path, (text + "\n").encode("utf-8"))
