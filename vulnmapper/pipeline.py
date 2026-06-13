"""Top-level run: collect -> score -> link -> assemble -> one graph on stdout.

    python -m vulnmapper --community cyfor123 > graph.json

stdout is the unified ``{nodes, edges, metadata}`` JSON document and nothing
else; every log line goes to stderr (the Node layer reads stdout to get the
result). Each stage tolerates per-item failures and the run always emits a valid
document.

Stages can be fed from cached files instead of run live, which is how the
frontend's pre-rendered graph is rebuilt without touching the lab:

  --scored PATH    use an existing scored endpoints JSON (skip collect + score)
  --network PATH   use an existing network topology JSON (skip the crawl)
  --no-endpoints / --no-network   build a one-sided graph

Live stages read credentials from the environment (``WAZUH_*`` for collect,
``INDEXER_*`` for score, ``--community`` / ``SNMP_COMMUNITIES`` for the crawl).
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from datetime import datetime, timezone
from typing import Optional

from .assemble import assemble

log = logging.getLogger("vulnmapper.pipeline")


def _setup_logging() -> None:
    logging.basicConfig(
        stream=sys.stderr,
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulnmapper",
        description="Unify Wazuh endpoints + SNMP/LLDP network discovery into one "
                    "{nodes, edges, metadata} graph document on stdout.",
    )
    parser.add_argument("--scored", metavar="PATH",
                        help="use an existing scored endpoints JSON instead of "
                             "running the live collect + score stages.")
    parser.add_argument("--network", metavar="PATH",
                        help="use an existing network topology JSON instead of "
                             "running the live crawl.")
    parser.add_argument("--no-endpoints", action="store_true",
                        help="build a network-only graph (no Wazuh endpoints).")
    parser.add_argument("--no-network", action="store_true",
                        help="build an endpoints-only graph (no network crawl).")
    # Live-crawl credentials (mirrors the network CLI; ignored with --network).
    parser.add_argument("--community", action="append", metavar="STRING",
                        help="SNMPv2c community to try for the live crawl (repeatable).")
    parser.add_argument("--seed", action="append", metavar="IP",
                        help="explicit seed device IP for the live crawl (repeatable).")
    parser.add_argument("-o", "--output", metavar="PATH",
                        help="write the graph JSON to PATH (UTF-8) instead of stdout.")
    return parser


def _load_endpoints(args, timing: dict) -> list[dict]:
    """Collect + score endpoints, recording per-phase elapsed time in ``timing``.

    A phase that is skipped (``--no-endpoints``, or a cached ``--scored`` file)
    leaves its duration as ``None`` rather than 0 — null means "did not run", not
    "ran instantly".
    """
    if args.no_endpoints:
        return []
    if args.scored:
        with open(args.scored) as f:
            return json.load(f)
    # Live: collect from the Manager API, then score against the Indexer.
    from .endpoints import WazuhSource

    source = WazuhSource()

    log.info("collecting endpoints from the Wazuh Manager API ...")
    t0 = time.monotonic()
    agents = source.collect()
    timing["endpoint_collect_s"] = time.monotonic() - t0

    log.info("scoring %d endpoint(s) against the Wazuh Indexer ...", len(agents))
    t0 = time.monotonic()
    scored = source.score(agents)
    timing["endpoint_score_s"] = time.monotonic() - t0
    return scored


def _load_network(args, timing: dict) -> dict:
    """Run (or load) the network topology, recording crawl elapsed time."""
    if args.no_network:
        return {"nodes": [], "edges": []}
    if args.network:
        with open(args.network) as f:
            return json.load(f)
    # Live: run the seed-based LLDP crawl.
    from .network.crawl import Config, load_credentials
    from .network.crawl import crawl_document

    cfg = Config(
        credentials=load_credentials(args.community),
        seeds=list(args.seed or []),
    )
    log.info("running the live SNMP/LLDP crawl ...")
    t0 = time.monotonic()
    doc = crawl_document(cfg)
    timing["network_crawl_s"] = time.monotonic() - t0
    return doc


class Pipeline:
    """The top-level orchestrator: collect -> score -> crawl -> assemble -> emit.

    A thin object wrapper so the sequence diagram has a single clean lifeline; the
    behaviour is exactly the former module-level ``run()`` — each stage delegates
    to the same functions, in the same order, with the same timing and output.
    """

    def load_endpoints(self, args, timing: dict) -> list[dict]:
        return _load_endpoints(args, timing)

    def load_network(self, args, timing: dict) -> dict:
        return _load_network(args, timing)

    def assemble(self, endpoints: list[dict], network_doc: dict) -> dict:
        return assemble(endpoints, network_doc)

    def emit(self, document: dict, output_path: Optional[str]) -> None:
        text = json.dumps(document, indent=2)
        if output_path:
            with open(output_path, "w", encoding="utf-8", newline="\n") as f:
                f.write(text + "\n")
            log.info("wrote graph to %s", output_path)
        else:
            sys.stdout.write(text + "\n")
            sys.stdout.flush()

    def run(self, argv: Optional[list[str]] = None) -> int:
        _setup_logging()
        args = build_parser().parse_args(argv)

        # Real per-phase timing: monotonic clock for the durations (immune to wall-
        # clock jumps), wall clock only for the ISO start/finish stamps. A skipped
        # phase stays null. ``total_s`` covers the whole run end-to-end.
        timing: dict = {
            "endpoint_collect_s": None,
            "endpoint_score_s": None,
            "network_crawl_s": None,
            "assemble_s": None,
            "total_s": None,
            "started_at": None,
            "finished_at": None,
        }
        started_at = datetime.now(timezone.utc)
        run_t0 = time.monotonic()
        timing["started_at"] = started_at.isoformat()

        endpoints = self.load_endpoints(args, timing)
        network_doc = self.load_network(args, timing)

        assemble_t0 = time.monotonic()
        document = self.assemble(endpoints, network_doc)
        timing["assemble_s"] = time.monotonic() - assemble_t0

        finished_at = datetime.now(timezone.utc)
        timing["finished_at"] = finished_at.isoformat()
        timing["total_s"] = time.monotonic() - run_t0

        # scan_time now means "finished_at" (kept for backward compat); the per-phase
        # breakdown lives in metadata.timing.
        document["metadata"]["timing"] = timing
        document["metadata"]["scan_time"] = finished_at.isoformat()

        counts = document["metadata"]["counts"]
        log.info(
            "SUMMARY: %d node(s) (%d endpoints, %d devices), %d edge(s) "
            "(%d lldp, %d endpoint), %d unparented endpoint(s).",
            counts["nodes"], counts["endpoints"], counts["devices"],
            counts["lldp_edges"] + counts["endpoint_edges"],
            counts["lldp_edges"], counts["endpoint_edges"], counts["unparented_endpoints"],
        )

        self.emit(document, args.output)
        return 0


def run(argv: Optional[list[str]] = None) -> int:
    """Entry point used by ``python -m vulnmapper`` (delegates to :class:`Pipeline`)."""
    return Pipeline().run(argv)


if __name__ == "__main__":
    sys.exit(run())
