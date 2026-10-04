#!/usr/bin/env python3
"""Freeze the behaviour baseline for the consolidation refactor (Phase 0).

``assemble()`` is the most complex pure stage (inputs -> dict), so it is the
strongest offline behaviour pin. We drive it with the exact input pairs the
existing test suite already builds (real lab-shaped data), and freeze each
resulting document to ``tests/golden/*.expected.json``.

The ONLY non-deterministic field assemble() emits is ``metadata.scan_time``
(``datetime.now``); it is normalised to a sentinel so the frozen document is
stable. Everything else must stay byte-for-byte identical across the refactor —
that is what ``tests/test_golden.py`` enforces after every step.

Run from the repo root:  python3 tools/_freeze_golden.py
"""

from __future__ import annotations

import json
import os
import shutil
import sys

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_GOLDEN = os.path.join(_REPO, "tests", "golden")
sys.path.insert(0, _REPO)
sys.path.insert(0, os.path.join(_REPO, "tests"))

# Sentinel that test_golden.py also substitutes before comparing.
FROZEN_SCAN_TIME = "FROZEN_SCAN_TIME"


def normalise(doc: dict) -> dict:
    """Replace the only non-deterministic field so the document is stable."""
    meta = doc.get("metadata")
    if isinstance(meta, dict) and "scan_time" in meta:
        meta["scan_time"] = FROZEN_SCAN_TIME
    return doc


def scenarios():
    """Yield ``(name, endpoints, network_doc)`` input pairs from the test suite.

    Imported lazily so this file only depends on the package + tests being on the
    path. These are the same inputs the existing tests assert against, so the
    golden is grounded in the suite's real lab-shaped data.
    """
    import test_assemble  # tests/test_assemble.py (module-level builders)

    yield ("parenting_ladder", test_assemble.endpoints(), test_assemble.network_doc())


def main() -> int:
    from vulnmapper.assemble import assemble

    os.makedirs(_GOLDEN, exist_ok=True)
    for name, endpoints, network_doc in scenarios():
        doc = normalise(assemble(endpoints, network_doc))
        out = os.path.join(_GOLDEN, f"{name}.expected.json")
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(doc, indent=2, sort_keys=False))
            fh.write("\n")
        print(f"froze {name} -> {out} ({len(doc['nodes'])} nodes, {len(doc['edges'])} edges)")

    # A second reference: a frozen copy of the committed graph.json.
    src = os.path.join(_REPO, "graph.json")
    if os.path.exists(src):
        shutil.copyfile(src, os.path.join(_GOLDEN, "graph.committed.json"))
        print("froze graph.json -> tests/golden/graph.committed.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
