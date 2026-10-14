"""``python -m vulnmapper.scoring.rescore --graph PATH``: score the saved scan
again after the protected assets (targets.json) changed, without a rescan.

An asset's importance is one of OVSS's inputs (its dependency), so marking an
asset changes its findings' scores and tiers, its node's roll-up and the
order of the attack routes. This reads graph.json, vulnerabilities.json and
targets.json beside the graph, scores them with the threat feeds and CVE
records already cached there, recomputes the attack paths and rewrites all
three outputs, each atomically. Files only: nothing is downloaded (a cache
older than a day is used as it is), and metadata.scan_time is not changed.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from typing import Optional

from .. import attackpaths, vulnfile
from ..common import setup_logging, write_json_atomic
from .feeds import FeedUnavailable
from .stage import WARNING, score

log = logging.getLogger("vulnmapper.scoring")


def no_network(url, timeout, progress=None):
    raise FeedUnavailable("a rescore never downloads")


def _read(path: str) -> Optional[dict]:
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def rescore(graph_path: str, liveness_path: Optional[str] = None, clock=None) -> dict:
    """Rescore the files beside ``graph_path`` in place; returns the attack
    paths document."""
    from ..devicecves.nvd import SystemClock

    folder = os.path.dirname(os.path.abspath(graph_path))
    graph = _read(graph_path)
    if graph is None:
        raise FileNotFoundError(graph_path)
    vulns_path = vulnfile.default_path(graph_path)
    vulns = _read(vulns_path)
    target_warnings: list = []
    targets = attackpaths.load_targets(attackpaths.targets_path(graph_path), target_warnings)
    liveness = None
    if liveness_path:
        try:
            liveness = _read(liveness_path)
        except (OSError, ValueError) as exc:
            log.warning("ignoring liveness state %s: %s", liveness_path, exc)

    _, result = score(graph, vulns or {}, targets, folder, clock or SystemClock(), no_network)
    metadata = graph.setdefault("metadata", {})
    metadata["ovss"] = result.block
    # the feed and targets warnings now say what this scoring used, not the scan's
    metadata["warnings"] = [w for w in metadata.get("warnings") or []
                            if w.get("type") not in (WARNING, attackpaths.TARGETS_INVALID)
                            ] + result.warnings + target_warnings
    # built after scoring, so routes are ranked by the new node scores
    paths = attackpaths.compute(graph, targets, vulns, liveness=liveness)

    if vulns is not None:
        write_json_atomic(vulns_path, vulns)
    write_json_atomic(attackpaths.default_path(graph_path), paths)
    write_json_atomic(graph_path, graph, indent=2)
    log.info("rescored: %s", result.note)
    return paths


def main(argv: Optional[list] = None, clock=None) -> int:
    setup_logging()
    parser = argparse.ArgumentParser(
        prog="vulnmapper.scoring.rescore",
        description="Rescore graph.json and vulnerabilities.json and recompute "
                    "attack_paths.json beside them after targets.json changed. "
                    "Files only, no network.")
    parser.add_argument("--graph", required=True, metavar="PATH",
                        help="the graph JSON (the other files are read and written beside it)")
    parser.add_argument("--liveness", metavar="PATH",
                        help="liveness.json; hosts it marks inactive are not used as route "
                             "starts when it was made for this graph (default: not used)")
    args = parser.parse_args(argv)
    try:
        rescore(args.graph, args.liveness, clock)
    except (OSError, ValueError) as exc:
        log.error("could not rescore %s: %s", args.graph, exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
