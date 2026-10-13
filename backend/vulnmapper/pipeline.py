"""The scan from start to finish: Wazuh endpoints and the network crawl, then
assembly and each optional stage in turn, writing graph.json (stdout or -o),
vulnerabilities.json and attack_paths.json. Log lines go to stderr only, and
a stage that fails for one host or device never fails the scan.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from datetime import datetime, timezone
from typing import Callable, Optional

from . import attackpaths, hosts, vulnfile
from .assemble import assemble
from .checklist.stage import run_checklist
from .common import StageResult, plural, setup_logging
from .devicecves.stage import run_device_cves
from .devicecves.vectors import run_cve_vectors
from .servicescan.stage import run_service_scan

log = logging.getLogger("vulnmapper.pipeline")


class ScanContext:
    """One run of the pipeline, as every stage sees it: the options, the graph
    as it is built, the CVE catalogue and vulnerabilities.json entries the
    stages add to, and the services they share (one NVD client and cache for
    the whole scan, and the stand-ins tests pass for the network)."""

    def __init__(self, args: argparse.Namespace, *, nvd_transport=None, clock=None,
                 resolver=None, snmp_client=None, nmap_runner=None) -> None:
        self.args = args
        self.resolver = resolver
        self.snmp_client = snmp_client
        self.nmap_runner = nmap_runner
        self._nvd_transport = nvd_transport
        self._clock = clock
        self._nvd: Optional[tuple] = None

        self.endpoints: list[dict] = []
        self.network_doc: dict = {"nodes": [], "edges": []}
        self.document: dict = {}
        # vulnerabilities.json's shared CVE text (None until something adds to
        # it) and the per-node entries of everything that is not an agent
        self.cves: Optional[dict] = None
        self.device_entries: dict = {}
        self.score_warnings: list = []
        self.stages: list = []

        # Durations come from the monotonic clock (immune to wall-clock jumps);
        # a stage that did not run keeps null, which is not "ran instantly".
        self.timing: dict = {
            "endpoint_collect_s": None,
            "endpoint_score_s": None,
            "network_crawl_s": None,
            "assemble_s": None,
            "device_cves_s": None,
            "total_s": None,
            "started_at": None,
            "finished_at": None,
        }

        beside_graph = args.output
        self.vulns_path = args.vulns_out or (vulnfile.default_path(beside_graph)
                                             if beside_graph else None)
        self.paths_out = args.paths_out or (attackpaths.default_path(beside_graph)
                                            if beside_graph else None)
        self.targets_path = args.targets or (attackpaths.targets_path(beside_graph)
                                             if beside_graph else None)

    def nvd(self) -> tuple:
        """The scan's ``(NvdClient, Cache)``, made on first use: both NVD stages
        and the service scan share one request spacing and one time budget."""
        if self._nvd is None:
            from .devicecves.cache import Cache, default_path
            from .devicecves.nvd import NvdClient, SystemClock
            from .devicecves.stage import DEFAULT_BUDGET_S

            cache_path = self.args.nvd_cache or (default_path(self.vulns_path)
                                                 if self.vulns_path else None)
            clock = self._clock or SystemClock()
            self._nvd = (NvdClient(transport=self._nvd_transport, clock=clock,
                                   budget_s=self.args.nvd_budget or DEFAULT_BUDGET_S),
                         Cache(cache_path, clock))
        return self._nvd

    def nvd_tally(self, stage: str, before: tuple) -> tuple:
        """Log and return the cache's ``(hits, misses, expired)`` since ``before``."""
        hits, misses, expired = (a - b for a, b in zip(self.nvd()[1].tally(), before))
        log.info("NVD cache, %s: %d hit(s), %d miss(es) (%d not cached, %d expired)",
                 stage, hits, misses + expired, misses, expired)
        return hits, misses, expired

    def add_findings(self, result: StageResult) -> None:
        """A CVE stage's rows join the catalogue, its entries vulnerabilities.json."""
        from .endpoints import merge_catalogue

        self.cves = dict(self.cves or {})
        for rows in result.rows.values():
            merge_catalogue(self.cves, rows)
        self.device_entries.update(result.entries)

    def record(self, name: str, seconds: Optional[float], note: Optional[str],
               ran: bool = True) -> None:
        """One line of ``metadata.stages``."""
        self.stages.append({"name": name, "status": "ran" if ran else "skipped",
                            "seconds": None if seconds is None else round(seconds, 1),
                            "note": note})

    def vulnerabilities(self, scan_time: Optional[str]) -> dict:
        """vulnerabilities.json as it stands."""
        return vulnfile.build_document(self.endpoints, self.cves, scan_time,
                                       devices=self.device_entries)


def _begin(label: str) -> float:
    """Announce a stage and start its clock. The dashboard follows a running
    scan by the last ``stage: <label>`` line on stderr, so keep the form."""
    log.info("stage: %s", label)
    return time.monotonic()


def build_parser() -> argparse.ArgumentParser:
    """The scan's options. Credentials never come from here except the SNMP
    community: live stages read ``WAZUH_*``, ``INDEXER_*``, ``SNMP_*`` and the
    optional ``NVD_API_KEY`` from the environment (backend/.env.example)."""
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
    parser.add_argument("--no-cve-vectors", action="store_true",
                        help="skip the CVE vector stage (NVD lookups by CVE id); nodes, "
                             "top_cves and the CVE catalogue are emitted as before.")
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
    parser.add_argument("--nmap-unmanaged", action="store_true",
                        help="service-scan (nmap -sV) the unmanaged hosts the scan discovered: "
                             "detect their open ports and service versions, then look those up in "
                             "NVD for potential CVEs. This actively connects to and probes those "
                             "hosts; never managed hosts or network devices. Off by default.")
    parser.add_argument("--nmap-hosts-cap", type=int, default=None, metavar="N",
                        help="most unmanaged hosts to service-scan per run (default 256); the rest "
                             "are left for the next scan.")
    parser.add_argument("--nmap-budget", type=float, default=None, metavar="SECONDS",
                        help="time budget for the whole service scan (default 300).")
    parser.add_argument("--no-attack-paths", action="store_true",
                        help="skip the exposure-path stage (no attack_paths.json); reads no "
                             "network and leaves the graph as before.")
    parser.add_argument("--targets", metavar="PATH",
                        help="important assets for the exposure-path stage (default: "
                             "targets.json beside -o; absent means no targets).")
    parser.add_argument("--paths-out", metavar="PATH",
                        help="write the exposure paths to PATH (default: attack_paths.json "
                             "beside -o; skipped when the graph goes to stdout).")
    parser.add_argument("--no-name-lookup", action="store_true",
                        help="do not ask the system resolver for the reverse DNS name of "
                             "hosts that have an address and no name.")
    parser.add_argument("--probe-unmanaged-snmp", action="store_true",
                        help="ask each host without a Wazuh agent (at most 256) for its SNMP "
                             "system group with the scan's own credentials, never the factory "
                             "names. This sends the credentials to machines nobody has "
                             "verified. Off by default.")
    return parser


def _read_endpoints(scan: ScanContext) -> None:
    """The Wazuh endpoints: collected and scored live, or read from ``--scored``.

    A ``--scored`` file is either the old shape (a plain list of endpoints,
    with no full findings) or ``{"endpoints": [...], "cves": {...},
    "warnings": [...]}``.
    """
    args = scan.args
    if args.no_endpoints:
        pass
    elif args.scored:
        with open(args.scored) as f:
            doc = json.load(f)
        if isinstance(doc, list):
            scan.endpoints = doc
        else:
            scan.cves = doc.get("cves")
            scan.score_warnings = doc.get("warnings") or []
            scan.endpoints = doc.get("endpoints") or []
    else:
        from .endpoints import WazuhSource

        source = WazuhSource()
        t0 = _begin("Collecting endpoints from the Wazuh Manager API")
        agents = source.collect()
        scan.timing["endpoint_collect_s"] = time.monotonic() - t0

        log.info("scoring %d endpoint(s) against the Wazuh Indexer ...", len(agents))
        t0 = _begin("Scoring endpoints against the Wazuh Indexer")
        scan.endpoints = source.score(agents)
        scan.timing["endpoint_score_s"] = time.monotonic() - t0
        scan.cves = source.cves
        scan.score_warnings = source.collect_warnings + source.warnings

    collect_s = scan.timing["endpoint_collect_s"]
    scan.record("Wazuh endpoints", collect_s and collect_s + scan.timing["endpoint_score_s"],
                "off" if args.no_endpoints else
                plural(len(scan.endpoints), "endpoint") + (" (from a file)" if args.scored else ""),
                ran=not args.no_endpoints)


def _read_network(scan: ScanContext) -> None:
    """The network: the SNMP/LLDP crawl run live, or read from ``--network``."""
    args = scan.args
    if args.no_network:
        pass
    elif args.network:
        with open(args.network) as f:
            scan.network_doc = json.load(f)
    else:
        from .network.config import Config, load_credentials
        from .network.crawl import crawl_document

        checklist = not args.no_checklist
        cfg = Config(
            credentials=load_credentials(args.community),
            seeds=list(args.seed or []),
            checklist=checklist,
            check_default_communities=args.check_default_communities and checklist,
            check_management_ports=args.check_management_ports and checklist,
        )
        t0 = _begin("Crawling the network over SNMP/LLDP")
        scan.network_doc = crawl_document(cfg)
        scan.timing["network_crawl_s"] = time.monotonic() - t0

    devices = sum(1 for n in scan.network_doc.get("nodes") or [] if n.get("pollable"))
    scan.record("Network crawl", scan.timing["network_crawl_s"],
                "off" if args.no_network else
                plural(devices, "device") + " polled" + (" (from a file)" if args.network else ""),
                ran=not args.no_network)


def _run_stage(scan: ScanContext, name: str, run: Callable[[ScanContext], StageResult], *,
               skip: Optional[str], label: str, timing: str,
               metadata: Optional[str] = None) -> None:
    """Run one optional stage, or record why it did not run.

    ``skip`` is that reason ("off" for a stage the options turned off), None to
    run it. Its block goes in ``metadata.<metadata>`` and its warnings join the
    graph's; its time and note make its line in ``metadata.stages``.
    """
    if skip is not None:
        scan.record(name, None, skip, ran=False)
        return
    t0 = _begin(label)
    result = run(scan)
    scan.timing[timing] = time.monotonic() - t0
    if metadata is not None:
        scan.document["metadata"][metadata] = result.block
    scan.document["metadata"]["warnings"].extend(result.warnings)
    scan.record(name, scan.timing[timing], result.note, ran=result.ran)


def _off_unless(enabled: bool) -> Optional[str]:
    return None if enabled else "off"


class Pipeline:
    """The whole scan, from the Wazuh endpoints and the network crawl to
    graph.json, vulnerabilities.json and attack_paths.json.

    ``nvd_transport`` and ``clock`` replace the NVD HTTP layer and the clock
    (tests serve saved replies); ``resolver`` replaces the reverse DNS lookup,
    ``snmp_client`` the SNMP client of the question to unmanaged hosts and
    ``nmap_runner`` nmap.
    """

    def __init__(self, nvd_transport=None, clock=None, resolver=None,
                 snmp_client=None, nmap_runner=None) -> None:
        self._services = dict(nvd_transport=nvd_transport, clock=clock, resolver=resolver,
                              snmp_client=snmp_client, nmap_runner=nmap_runner)

    def run(self, argv: Optional[list[str]] = None) -> int:
        setup_logging()
        args = build_parser().parse_args(argv)
        scan = ScanContext(args, **self._services)
        started = time.monotonic()
        scan.timing["started_at"] = datetime.now(timezone.utc).isoformat()

        _read_endpoints(scan)
        _read_network(scan)
        t0 = time.monotonic()
        scan.document = assemble(scan.endpoints, scan.network_doc)
        scan.timing["assemble_s"] = time.monotonic() - t0

        _run_stage(scan, "SNMP question to unmanaged hosts", hosts.run_snmp_question,
                   skip=_off_unless(args.probe_unmanaged_snmp),
                   label="Asking unmanaged hosts over SNMP",
                   timing="snmp_question_s", metadata="snmp_question")
        _run_stage(scan, "Reverse DNS names", hosts.run_name_lookup,
                   skip=_off_unless(not args.no_name_lookup),
                   label="Looking up host names",
                   timing="name_lookup_s", metadata="name_lookup")
        _run_stage(scan, "Device CVEs (NVD)", run_device_cves,
                   skip=_off_unless(not args.no_device_cves),
                   label="Looking up device CVEs in NVD",
                   timing="device_cves_s", metadata="device_cves")
        # The service scan runs before the vector stage, so its CVEs flow
        # through it (vector fields, reachable_cve) and on to the attack paths.
        _run_stage(scan, "nmap service scan", run_service_scan,
                   skip=_off_unless(args.nmap_unmanaged),
                   label="Service-scanning unmanaged hosts with nmap",
                   timing="nmap_s", metadata="nmap")
        _run_stage(scan, "CVE vectors (NVD)", run_cve_vectors,
                   skip=_off_unless(not args.no_cve_vectors),
                   label="Looking up CVE vectors in NVD",
                   timing="cve_vectors_s", metadata="cve_vectors")
        _run_stage(scan, "Configuration checks", run_checklist,
                   skip=_off_unless(not args.no_checklist),
                   label="Evaluating device configuration checks",
                   timing="checklist_s", metadata="checklist")

        finished_at = datetime.now(timezone.utc)
        scan.timing["finished_at"] = finished_at.isoformat()
        scan.timing["total_s"] = time.monotonic() - started
        metadata = scan.document["metadata"]
        metadata["timing"] = scan.timing
        # scan_time means "finished at"; the per-stage breakdown is in timing
        metadata["scan_time"] = finished_at.isoformat()
        metadata["warnings"].extend(scan.score_warnings)

        # last, so attack_paths.json's source_scan names this graph's scan_time
        _run_stage(scan, "Attack paths", attackpaths.run_attack_paths,
                   skip=self._attack_paths_skip(scan), label="Computing attack paths",
                   timing="attack_paths_s")
        metadata["stages"] = scan.stages

        self._log_summary(scan.document)
        self.emit(scan.document, args.output)
        self._write_vulnerabilities(scan)
        return 0

    @staticmethod
    def _attack_paths_skip(scan: ScanContext) -> Optional[str]:
        if scan.args.no_attack_paths:
            return "off"
        if scan.paths_out is None:
            log.info("graph went to stdout and --paths-out was not given; "
                     "not writing %s", attackpaths.FILENAME)
            return "no output file given"
        return None

    @staticmethod
    def _log_summary(document: dict) -> None:
        counts = document["metadata"]["counts"]
        log.info(
            "SUMMARY: %d node(s) (%d endpoints, %d devices), %d edge(s) "
            "(%d lldp, %d endpoint), %d unparented endpoint(s).",
            counts["nodes"], counts["endpoints"], counts["devices"],
            counts["lldp_edges"] + counts["endpoint_edges"],
            counts["lldp_edges"], counts["endpoint_edges"], counts["unparented_endpoints"],
        )

    def emit(self, document: dict, output_path: Optional[str]) -> None:
        text = json.dumps(document, indent=2)
        if output_path:
            with open(output_path, "w", encoding="utf-8", newline="\n") as f:
                f.write(text + "\n")
            log.info("wrote graph to %s", output_path)
        else:
            sys.stdout.write(text + "\n")
            sys.stdout.flush()

    @staticmethod
    def _write_vulnerabilities(scan: ScanContext) -> None:
        if scan.vulns_path:
            vulnfile.write_atomic(scan.vulns_path,
                                  scan.vulnerabilities(scan.document["metadata"]["scan_time"]))
            log.info("wrote vulnerabilities to %s", scan.vulns_path)
        else:
            log.info("graph went to stdout and --vulns-out was not given; "
                     "not writing %s", vulnfile.FILENAME)


def run(argv: Optional[list[str]] = None) -> int:
    """``python -m vulnmapper``."""
    return Pipeline().run(argv)


if __name__ == "__main__":
    sys.exit(run())
