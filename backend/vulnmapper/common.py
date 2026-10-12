"""Small pieces every part of the scanner shares: stderr logging for the
command-line entry points.
"""

from __future__ import annotations

import logging
import sys


def setup_logging() -> None:
    """Log lines go to stderr; stdout is kept for the JSON a command prints."""
    logging.basicConfig(
        stream=sys.stderr,
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
