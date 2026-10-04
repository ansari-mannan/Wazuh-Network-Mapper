#!/usr/bin/env python3
"""Standalone entry point — the APA score stage.

    python -m vulnmapper.endpoints.score   ->   scored_agents.json

Thin shim over :class:`vulnmapper.endpoints.WazuhSource`; the output filename and
env var names (``INDEXER_*``, ``AGENTS_IN``, ``SCORED_OUT``) are preserved.
Progress goes to stderr.
"""

from __future__ import annotations

import json
import os
import sys

from . import WazuhSource


def main() -> int:
    agents_in = os.environ.get("AGENTS_IN", "agents.json")
    out_path = os.environ.get("SCORED_OUT", "scored_agents.json")

    with open(agents_in) as f:
        agents = json.load(f)

    out = WazuhSource().score(agents)

    with open(out_path, "w") as f:
        json.dump(out, f, indent=2)

    print(f"Wrote {len(out)} scored agents to {out_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
