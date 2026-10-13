"""``python -m vulnmapper``: runs a scan (pipeline.py).
"""

import sys

from .pipeline import run

if __name__ == "__main__":
    sys.exit(run())
