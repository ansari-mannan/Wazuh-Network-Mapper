#!/usr/bin/env python3
"""``python -m vulnmapper.endpoints.score``: the score step alone, reading
agents.json ($AGENTS_IN) and writing ``{endpoints, cves, warnings}`` to
scored_agents.json ($SCORED_OUT), which ``python -m vulnmapper --scored`` reads.
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

    source = WazuhSource()
    out = source.score(agents)

    with open(out_path, "w") as f:
        json.dump({"endpoints": out, "cves": source.cves, "warnings": source.warnings},
                  f, indent=2)

    print(f"Wrote {len(out)} scored agents to {out_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
