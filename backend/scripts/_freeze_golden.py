#!/usr/bin/env python3
"""Refreeze the golden outputs that tests/test_golden.py compares against.

Only run this after a change that is meant to alter the scanner's output;
the scenarios and the normalisation live in the test, so both stay in step.

Run from backend/:  python3 scripts/_freeze_golden.py
"""

from __future__ import annotations

import os
import sys

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO)
sys.path.insert(0, os.path.join(_REPO, "tests"))


def main() -> int:
    import test_golden

    os.makedirs(test_golden._GOLDEN, exist_ok=True)
    for name in test_golden.SCENARIOS:
        for fname, doc in test_golden.produce(name).items():
            with open(os.path.join(test_golden._GOLDEN, fname), "w", encoding="utf-8") as fh:
                fh.write(test_golden.dump(doc))
            print(f"froze {name} -> tests/golden/{fname}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
