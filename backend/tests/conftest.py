"""pytest loads this first; the guard itself is tests/offline.py, which the
unittest runner gets through the test modules' own imports."""

import offline  # noqa: F401  (no test reaches the internet)
