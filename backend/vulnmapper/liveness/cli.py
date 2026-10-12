"""``python -m vulnmapper.liveness``: read the graph and the last state, run
one pass, print the new state on stdout. The dashboard server runs it on a
timer and saves the output as liveness.json.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from collections import defaultdict
from typing import Optional

from ..common import setup_logging
from .monitor import DEFAULT_THRESHOLD, LivenessMonitor
from .records import AGENT_MAX_AGE_S

log = logging.getLogger("vulnmapper.liveness")


def load_state(path: Optional[str]) -> dict:
    """The previous state document, or {} when missing or invalid."""
    if not path:
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, ValueError):
        return {}
    if not isinstance(doc, dict) or not isinstance(doc.get("nodes"), dict):
        return {}
    return doc


def _threshold(text: str) -> int:
    value = int(text)
    if value < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return value


_agent_max_age = _threshold     # whole seconds, at least 1


def main(argv: Optional[list] = None) -> int:
    setup_logging()
    parser = argparse.ArgumentParser(
        prog="vulnmapper.liveness",
        description="Re-check whether the nodes in graph.json answer; print the "
                    "liveness state document on stdout.")
    parser.add_argument("--graph", required=True, metavar="PATH", help="graph.json to read")
    parser.add_argument("--state", metavar="PATH",
                        help="previous liveness.json (missing or invalid = empty)")
    parser.add_argument("--threshold", type=_threshold, default=DEFAULT_THRESHOLD,
                        help="misses on a proven method before a node is inactive")
    parser.add_argument("--agent-max-age", type=_agent_max_age, default=AGENT_MAX_AGE_S,
                        metavar="SECONDS",
                        help="oldest Wazuh agent check-in that still counts as a reply")
    args = parser.parse_args(argv)

    try:
        with open(args.graph, encoding="utf-8") as f:
            graph = json.load(f)
        if not isinstance(graph, dict):
            raise ValueError("not a graph document")
    except (OSError, ValueError) as e:
        print(f"vulnmapper.liveness: cannot read graph {args.graph}: {e}", file=sys.stderr)
        return 1

    monitor = LivenessMonitor(threshold=args.threshold, previous=load_state(args.state),
                              agent_max_age=args.agent_max_age)
    doc = asyncio.run(monitor.check(graph))
    sys.stdout.write(json.dumps(doc, indent=2) + "\n")
    sys.stdout.flush()
    counts = defaultdict(int)
    for rec in doc["nodes"].values():
        counts[rec["state"]] += 1
    log.info("liveness pass: %d node(s): %s", len(doc["nodes"]),
             ", ".join(f"{k} {v}" for k, v in sorted(counts.items())) or "none")
    if doc["rescan_suggested"]:
        log.info("rescan suggested: %s", "; ".join(doc["rescan_reasons"]))
    return 0
