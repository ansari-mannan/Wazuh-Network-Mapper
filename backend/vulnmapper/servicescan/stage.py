"""The service-scan stage: nmap the unmanaged hosts, then look the service
versions found up in NVD through the device-CVE path. Runs after the device CVE
stage and before the vectors, so its CVEs flow on to the attack paths.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from typing import TYPE_CHECKING, Optional

from ..common import StageResult, plural
from ..hosts import question_targets
from ..devicecves import families
from ..devicecves.cache import Cache
from ..devicecves.lookup import STATUS_OK, Lookup, lookup
from ..devicecves.nvd import NvdClient
from ..devicecves.stage import apply_result, device_entry
from .nmap import PER_HOST_TIMEOUT_S, SPEED_ARGS, NmapBudgetExceeded, NmapRunner, parse_nmap_xml

if TYPE_CHECKING:
    from ..pipeline import ScanContext

log = logging.getLogger("vulnmapper.servicescan")

# Eligibility is exactly the unmanaged hosts with a known IP that the scan has
# already discovered (``hosts.question_targets``): never a managed host, never a
# network device, never an address the scan did not see. The stage is bounded by
# a host cap and a time budget; over either, the rest are left for the next run.
#
# Each host that answered keeps its ``open_ports`` (the honest evidence, recorded
# even without a CVE). A detected product+version with an nmap CPE is turned into
# a CPE lookup and run through :func:`devicecves.lookup.lookup`, so the host gains
# the same ``cve_summary``, ``top_cves``, ``max_cvss`` and ``cve_lookup``
# a device gets. The lookup record is marked ``source "nmap"`` and
# ``potential``: a detected version is not proof the vulnerable build is running.
# The host stays ``unmanaged``; this gives it data, not an agent.

DEFAULT_HOSTS_CAP = 256
DEFAULT_BUDGET_S = 300.0
# Hosts per nmap run: a run cut off by the budget loses only its own batch.
BATCH_SIZE = 16
# nmap runs at once
PARALLEL_BATCHES = 2
# What nmap found on a host is reused for a day (nmap-cache.json beside the
# graph), unless the scan asks for a fresh service scan. Only hosts that
# answered are kept: a silent host is asked again next scan.
CACHE_FILENAME = "nmap-cache.json"
CACHE_FRESH = timedelta(hours=24)
SOURCE = "nmap"
_PORT_KEYS = ("port", "protocol", "service", "product", "version")


def idents_from_ports(open_ports: list) -> list:
    """A CPE lookup identity for each distinct application CPE that carries a
    version, in port order (an old OpenSSH and an old Apache on one host are
    both looked up). nmap emits CPE 2.2 (``cpe:/a:vendor:product:ver``)."""
    idents: dict = {}
    for p in open_ports:
        for cpe in p.get("cpes") or []:
            parts = cpe.split(":")        # cpe:/a:vendor:product:version[:...]
            if len(parts) < 5 or parts[1] != "/a" or not parts[4]:
                continue
            vendor, product, cpe_version = parts[2], parts[3], parts[4]
            version = p.get("version") or cpe_version
            label = " ".join(x for x in (p.get("product") or product, version) if x)
            key = f"cpe:2.3:a:{vendor}:{product}:{families.cpe_value(cpe_version)}:*:*:*:*:*:*:*"
            idents.setdefault(key, {"match": "cpe", "version": version, "product": label, "cpe": key})
    return list(idents.values())


def merge_lookups(results: list) -> Lookup:
    """One host's lookups as one: its products and CPEs joined, the CVE rows of
    every answered lookup with each CVE once. ok when any lookup answered;
    otherwise the first lookup's status."""
    ok = [r for r in results if r.status == STATUS_OK]
    first = (ok or results)[0]
    rows, seen = [], set()
    for r in ok:
        for row in r.rows or []:
            if row.get("cve") not in seen:
                seen.add(row.get("cve"))
                rows.append(row)
    return Lookup(status=first.status, match=first.match, reason=first.reason,
                  product="; ".join(r.product for r in results if r.product) or None,
                  cpe=", ".join(r.cpe for r in results if r.cpe) or None,
                  rows=rows if ok else None,
                  fetched_at=min((r.fetched_at for r in ok if r.fetched_at), default=first.fetched_at),
                  stale=any(r.stale for r in ok))


def _apply_host(node: dict, scan: dict, client: NvdClient, cache: Cache,
                out: StageResult) -> None:
    """Record one answering host's ports, name, hint and (where found) CVEs."""
    node["open_ports"] = [{k: p.get(k) for k in _PORT_KEYS} for p in scan["open_ports"]]
    if scan.get("netbios") and not node.get("hostname"):
        node["hostname"], node["name_source"] = scan["netbios"], "netbios"
    if scan.get("device_hint") and not node.get("role"):
        node["device_hint"] = scan["device_hint"]

    idents = idents_from_ports(scan["open_ports"])
    if not idents:
        return
    # every lookup shares the scan's NVD client, so its request budget
    result = merge_lookups([lookup(ident, client, cache) for ident in idents])
    rows = apply_result(node, result)
    node["cve_lookup"]["source"] = SOURCE
    node["cve_lookup"]["potential"] = True
    nid = node["node_id"]
    if rows is not None:
        out.rows[nid] = rows
    out.entries[nid] = device_entry(node, rows)


def run_stage(graph: dict, client: NvdClient, cache: Cache, *,
              cap: int = DEFAULT_HOSTS_CAP, budget_s: float = DEFAULT_BUDGET_S,
              runner: Optional[NmapRunner] = None) -> StageResult:
    """Service-scan the eligible unmanaged hosts and update them in place."""
    return apply_scans(scan_hosts(graph, cap=cap, budget_s=budget_s, runner=runner), client, cache)


def nmap_cache(path: Optional[str], clock) -> Cache:
    return Cache(path, clock, fresh_found=CACHE_FRESH, fresh_empty=CACHE_FRESH, label="nmap cache")


def scan_hosts(graph: dict, *, cap: int = DEFAULT_HOSTS_CAP, budget_s: float = DEFAULT_BUDGET_S,
               runner: Optional[NmapRunner] = None, cache: Optional[Cache] = None,
               fresh: bool = False) -> tuple:
    """The nmap half of the stage: ``(targets, {ip: scan}, result so far)``.
    Reads the graph and changes nothing, so it can run beside other stages.
    ``cache`` (nmap-cache.json) serves hosts nmap answered for in the last
    day, unless ``fresh``; it is updated with what nmap answers now."""
    out = StageResult()
    targets, capped = question_targets(graph, cap)
    runner = runner if runner is not None else NmapRunner()
    block = {"eligible": len(targets), "scanned": 0, "cached": 0, "answered": 0, "named": 0,
             "with_cves": 0, "nmap_requests": 0, "cap_reached": capped, "budget_exceeded": False}
    if capped:
        log.warning("more than %d unmanaged hosts; only the first %d are service-scanned", cap, cap)
        out.warnings.append({"type": "nmap_cap_reached", "cap": cap})
    out.block = block
    if not targets:
        return targets, {}, out
    if not runner.available:
        log.warning("nmap is not installed; the service scan was skipped")
        out.warnings.append({"type": "nmap_not_installed"})
        return [], {}, out

    scans: dict = {}
    todo = []
    for n in targets:
        entry = None if fresh or cache is None else cache.get(n["ip"])
        if entry and entry["fresh"] and entry["found"]:
            scans[n["ip"]] = entry["data"]
            block["cached"] += 1
        else:
            todo.append(n["ip"])

    # In batches, PARALLEL_BATCHES at a time, each with the budget that is left
    # when it starts, so the hosts of every batch that finished are kept when
    # another runs out of time.
    started = time.monotonic()
    lock = threading.Lock()

    def one(batch: list) -> dict:
        left = budget_s - (time.monotonic() - started)
        if left <= 0:
            raise NmapBudgetExceeded()
        with lock:
            block["nmap_requests"] += 1
        return parse_nmap_xml(runner.scan(batch, left))

    batches = [todo[i:i + BATCH_SIZE] for i in range(0, len(todo), BATCH_SIZE)]
    with ThreadPoolExecutor(max_workers=PARALLEL_BATCHES, thread_name_prefix="nmap") as pool:
        futures = [pool.submit(one, batch) for batch in batches]
    left_over = 0
    for batch, future in zip(batches, futures):
        try:
            found = future.result()
        except NmapBudgetExceeded:
            left_over += len(batch)
            continue
        block["scanned"] += len(batch)
        for ip in batch:            # in host order, whatever order nmap answered in
            if ip in found:
                scans[ip] = found[ip]
                if cache is not None:
                    cache.put(ip, found=True, data=found[ip])
    if left_over:
        log.warning("nmap time budget (%.0f s) ran out; %d host(s) are left for the next scan",
                    budget_s, left_over)
        out.warnings.append({"type": "nmap_budget_exceeded", "budget_s": budget_s})
        block["budget_exceeded"] = True
    if cache is not None:
        cache.save()
    return targets, scans, out


def apply_scans(scanned: tuple, client: NvdClient, cache: Cache) -> StageResult:
    """The other half: record what :func:`scan_hosts` found on the hosts, and
    look their service versions up in NVD."""
    targets, scans, out = scanned
    block = out.block
    for node in targets:
        scan = scans.get(node["ip"])
        if scan is None:
            continue
        block["answered"] += 1
        had_name = bool(node.get("hostname"))
        _apply_host(node, scan, client, cache, out)
        if node.get("name_source") == "netbios" and not had_name:
            block["named"] += 1
        if node.get("cve_lookup", {}).get("status") == STATUS_OK and node.get("cve_summary"):
            block["with_cves"] += 1
    cache.save()
    log.info("service scan: %d eligible, %d scanned, %d answered, %d with CVEs, %d NVD request(s)",
             block["eligible"], block["scanned"], block["answered"], block["with_cves"], client.requests)
    return out


def nmap_hosts(scan: "ScanContext") -> tuple:
    """:func:`scan_hosts` with the run's host cap, nmap budget, runner and cache."""
    args = scan.args
    folder = scan.cache_folder()
    return scan_hosts(scan.document, cap=args.nmap_hosts_cap or DEFAULT_HOSTS_CAP,
                      budget_s=args.nmap_budget or DEFAULT_BUDGET_S, runner=scan.nmap_runner,
                      cache=nmap_cache(os.path.join(folder, CACHE_FILENAME) if folder else None,
                                       scan.clock),
                      fresh=args.fresh_service_scan)


def run_service_scan(scan: "ScanContext", scanned: Optional[tuple] = None) -> StageResult:
    """The pipeline's service scan, within the run's host cap and nmap budget;
    ``scanned`` is :func:`nmap_hosts`' answer when nmap already ran.
    It counts as skipped when nmap is not installed."""
    client, cache = scan.nvd()
    before = cache.tally()
    result = apply_scans(scanned or nmap_hosts(scan), client, cache)
    scan.nvd_tally("service scan", before)
    block = result.block
    not_installed = any(w["type"] == "nmap_not_installed" for w in result.warnings)
    result.ran = not not_installed
    result.note = ("nmap not installed" if not_installed else
                   f"{plural(block['scanned'], 'host')} scanned, {block['cached']} from the "
                   f"cache, {block['answered']} answered, {block['with_cves']} with CVEs; "
                   f"nmap {' '.join(SPEED_ARGS)} --host-timeout {int(PER_HOST_TIMEOUT_S)}s")
    scan.add_findings(result)
    return result
