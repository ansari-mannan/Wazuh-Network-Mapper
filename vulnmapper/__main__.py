"""Package entry point: ``python -m vulnmapper`` runs the unified pipeline."""

import sys

from .pipeline import run

if __name__ == "__main__":
    sys.exit(run())
