#!/usr/bin/env python3
"""Standalone entry point — the NTM collect stage.

    python -m vulnmapper.endpoints.collect   ->   agents.json

Thin shim over :class:`vulnmapper.endpoints.WazuhSource`; the output filename and
env var names (``WAZUH_*``, ``AGENTS_OUT``) are preserved. Progress goes to stderr.
"""

from __future__ import annotations

import json
import os
import sys

from . import WazuhSource


def main() -> int:
    out_path = os.environ.get("AGENTS_OUT", "agents.json")

    nodes = WazuhSource().collect()

    with open(out_path, "w") as f:
        json.dump(nodes, f, indent=2)

    print(f"Wrote {len(nodes)} agents to {out_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
