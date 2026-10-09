"""Top-level run: collect -> score -> crawl -> assemble -> device CVEs ->
configuration checks -> one graph.

    python -m vulnmapper --community <community> > graph.json

stdout is the unified ``{nodes, edges, metadata}`` JSON document and nothing
else; every log line goes to stderr (the Node layer reads stdout to get the
result). Each stage tolerates per-item failures and the run always emits a valid
document.

Stages can be fed from cached files instead of run live, which is how the
frontend's pre-rendered graph is rebuilt without touching the lab:

  --scored PATH    use an existing scored endpoints JSON (skip collect + score)
  --network PATH   use an existing network topology JSON (skip the crawl)
  --no-endpoints / --no-network   build a one-sided graph
  --vulns-out PATH every CVE finding (vulnerabilities.json); defaults to the
                   folder of -o, skipped when the graph goes to stdout
  --no-device-cves skip the device vulnerability stage (NVD lookups)
  --nvd-cache PATH where NVD answers are kept; default nvd-cache.json beside
                   the vulnerabilities file (or beside -o)
  --no-checklist   skip the configuration checks (no extra SNMP reads)
  --check-default-communities
                   also try the factory SNMP names public and private (two
                   read-only requests per device; off by default)
  --check-management-ports
                   on devices that do not list their TCP listeners, open one
                   connection to TCP 23 and 80 and close it (off by default)
  --no-name-lookup skip the reverse DNS lookup of hosts that have no name

Live stages read credentials from the environment (``WAZUH_*`` for collect,
``INDEXER_*`` for score, ``--community`` / ``SNMP_COMMUNITIES`` for the crawl,
``NVD_API_KEY``, optional, for the device CVE stage). The device CVE stage runs
on the assembled graph's devices whether they were crawled live or loaded with
``--network``; NVD failing never fails the scan.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from datetime import datetime, timezone
from typing import Optional

from . import vulnfile
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
    parser.add_argument("--vulns-out", metavar="PATH",
                        help="write every CVE finding to PATH (default: "
                             "vulnerabilities.json next to -o; skipped when the "
                             "graph goes to stdout).")
    parser.add_argument("--no-device-cves", action="store_true",
                        help="skip the device vulnerability stage (no NVD lookups); "
                             "device nodes are emitted as before.")
    parser.add_argument("--nvd-cache", metavar="PATH",
                        help="NVD answer cache (default: nvd-cache.json beside the "
                             "vulnerabilities file, or beside -o).")
    parser.add_argument("--nvd-budget", type=float, default=None, metavar="SECONDS",
                        help="time budget for the NVD lookups of one scan (default 180).")
    parser.add_argument("--no-checklist", action="store_true",
                        help="skip the device configuration checks (no extra SNMP reads); "
                             "device nodes are emitted as before.")
    parser.add_argument("--check-default-communities", action="store_true",
                        help="also test whether devices answer the factory SNMP names "
                             "public and private (two read-only requests per device; the "
                             "network may log them as failed logins). Off by default.")
    parser.add_argument("--check-management-ports", action="store_true",
                        help="on devices that do not list their TCP listeners over SNMP, "
                             "open one connection to TCP 23 (telnet) and 80 (HTTP) and close "
                             "it at once; no data is sent. Off by default.")
    parser.add_argument("--no-name-lookup", action="store_true",
                        help="do not ask the system resolver for the reverse DNS name of "
                             "hosts that have an address and no name.")
    return parser


def _load_endpoints(args, timing: dict, vulns: dict) -> list[dict]:
    """Collect + score endpoints, recording per-phase elapsed time in ``timing``.

    A phase that is skipped (``--no-endpoints``, or a cached ``--scored`` file)
    leaves its duration as ``None`` rather than 0 — null means "did not run", not
    "ran instantly". The shared CVE catalogue and the score-stage warnings go in
    ``vulns`` (``cves`` / ``warnings``).

    A ``--scored`` file is either the old shape (a list of endpoints, with no
    full findings) or ``{"endpoints": [...], "cves": {...}, "warnings": [...]}``.
    """
    if args.no_endpoints:
        return []
    if args.scored:
        with open(args.scored) as f:
            doc = json.load(f)
        if isinstance(doc, list):
            return doc
        vulns["cves"] = doc.get("cves")
        vulns["warnings"] = doc.get("warnings") or []
        return doc.get("endpoints") or []
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
    vulns["cves"] = source.cves
    vulns["warnings"] = source.collect_warnings + source.warnings
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
        checklist=not args.no_checklist,
        check_default_communities=args.check_default_communities and not args.no_checklist,
        check_management_ports=args.check_management_ports and not args.no_checklist,
    )
    log.info("running the live SNMP/LLDP crawl ...")
    t0 = time.monotonic()
    doc = crawl_document(cfg)
    timing["network_crawl_s"] = time.monotonic() - t0
    return doc


class Pipeline:
    """The top-level orchestrator: collect -> score -> crawl -> assemble ->
    device CVEs -> emit.

    A thin object wrapper so the sequence diagram has a single clean lifeline.
    ``nvd_transport`` and ``clock`` replace the NVD HTTP layer and the clock
    (tests serve saved replies); ``resolver`` replaces the reverse DNS lookup.
    """

    def __init__(self, nvd_transport=None, clock=None, resolver=None) -> None:
        self._nvd_transport = nvd_transport
        self._clock = clock
        self._resolver = resolver

    def load_endpoints(self, args, timing: dict, vulns: dict) -> list[dict]:
        return _load_endpoints(args, timing, vulns)

    def load_network(self, args, timing: dict) -> dict:
        return _load_network(args, timing)

    def assemble(self, endpoints: list[dict], network_doc: dict) -> dict:
        return assemble(endpoints, network_doc)

    def lookup_names(self, document: dict) -> dict:
        from .hosts import lookup_names

        return lookup_names(document, **({"resolver": self._resolver} if self._resolver else {}))

    def device_cves(self, document: dict, cache_path: Optional[str], budget_s: float):
        from .devicecves.cache import Cache
        from .devicecves.nvd import NvdClient, SystemClock
        from .devicecves.stage import run_stage

        clock = self._clock or SystemClock()
        client = NvdClient(transport=self._nvd_transport, clock=clock, budget_s=budget_s)
        return run_stage(document, client, Cache(cache_path, clock))

    def checklist(self, document: dict, network_doc: dict, probe_enabled: bool,
                  port_test: bool = False):
        from .checklist.stage import run_stage

        return run_stage(document, network_doc, probe_enabled, port_test=port_test)

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
            "device_cves_s": None,
            "total_s": None,
            "started_at": None,
            "finished_at": None,
        }
        started_at = datetime.now(timezone.utc)
        run_t0 = time.monotonic()
        timing["started_at"] = started_at.isoformat()

        vulns: dict = {"cves": None, "warnings": []}
        endpoints = self.load_endpoints(args, timing, vulns)
        network_doc = self.load_network(args, timing)

        assemble_t0 = time.monotonic()
        document = self.assemble(endpoints, network_doc)
        timing["assemble_s"] = time.monotonic() - assemble_t0

        if not args.no_name_lookup:
            t0 = time.monotonic()
            document["metadata"]["name_lookup"] = self.lookup_names(document)
            timing["name_lookup_s"] = time.monotonic() - t0

        vulns_path = args.vulns_out or (vulnfile.default_path(args.output)
                                        if args.output else None)
        device_entries: dict = {}
        if not args.no_device_cves:
            from .devicecves.cache import default_path as cache_beside
            from .devicecves.stage import DEFAULT_BUDGET_S, merge_catalogue

            cache_path = args.nvd_cache or (cache_beside(vulns_path) if vulns_path else None)
            log.info("looking up device CVEs in NVD ...")
            t0 = time.monotonic()
            stage = self.device_cves(document, cache_path, args.nvd_budget or DEFAULT_BUDGET_S)
            timing["device_cves_s"] = time.monotonic() - t0
            document["metadata"]["device_cves"] = stage.block
            document["metadata"]["warnings"].extend(stage.warnings)
            vulns["cves"] = dict(vulns["cves"] or {})
            for rows in stage.rows.values():
                merge_catalogue(vulns["cves"], rows)
            device_entries = stage.entries

        if not args.no_checklist:
            log.info("evaluating device configuration checks ...")
            t0 = time.monotonic()
            checks = self.checklist(document, network_doc, args.check_default_communities,
                                    args.check_management_ports)
            timing["checklist_s"] = time.monotonic() - t0
            document["metadata"]["checklist"] = checks.block
            document["metadata"]["warnings"].extend(checks.warnings)

        finished_at = datetime.now(timezone.utc)
        timing["finished_at"] = finished_at.isoformat()
        timing["total_s"] = time.monotonic() - run_t0

        # scan_time now means "finished_at" (kept for backward compat); the per-phase
        # breakdown lives in metadata.timing.
        document["metadata"]["timing"] = timing
        document["metadata"]["scan_time"] = finished_at.isoformat()
        document["metadata"]["warnings"].extend(vulns["warnings"])

        counts = document["metadata"]["counts"]
        log.info(
            "SUMMARY: %d node(s) (%d endpoints, %d devices), %d edge(s) "
            "(%d lldp, %d endpoint), %d unparented endpoint(s).",
            counts["nodes"], counts["endpoints"], counts["devices"],
            counts["lldp_edges"] + counts["endpoint_edges"],
            counts["lldp_edges"], counts["endpoint_edges"], counts["unparented_endpoints"],
        )

        self.emit(document, args.output)

        if vulns_path:
            vulnfile.write_atomic(vulns_path, vulnfile.build_document(
                endpoints, vulns["cves"], document["metadata"]["scan_time"],
                devices=device_entries))
            log.info("wrote vulnerabilities to %s", vulns_path)
        else:
            log.info("graph went to stdout and --vulns-out was not given; "
                     "not writing %s", vulnfile.FILENAME)
        return 0


def run(argv: Optional[list[str]] = None) -> int:
    """Entry point used by ``python -m vulnmapper`` (delegates to :class:`Pipeline`)."""
    return Pipeline().run(argv)


if __name__ == "__main__":
    sys.exit(run())
