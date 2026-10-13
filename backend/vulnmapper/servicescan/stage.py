"""The service-scan stage: nmap the unmanaged hosts, then look the service
versions found up in NVD through the device-CVE path. Runs after the device CVE
stage and before the vectors, so its CVEs flow on to the attack paths.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Optional

from ..common import StageResult, plural
from ..hosts import question_targets
from ..devicecves import families
from ..devicecves.cache import Cache
from ..devicecves.lookup import STATUS_OK, lookup
from ..devicecves.nvd import NvdClient
from ..devicecves.stage import apply_result, device_entry
from .nmap import NmapBudgetExceeded, NmapRunner, parse_nmap_xml

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
SOURCE = "nmap"
_PORT_KEYS = ("port", "protocol", "service", "product", "version")


def ident_from_ports(open_ports: list) -> Optional[dict]:
    """A CPE lookup identity from the first service with an application CPE that
    carries a version, or None. nmap emits CPE 2.2 (``cpe:/a:vendor:product:ver``)."""
    for p in open_ports:
        for cpe in p.get("cpes") or []:
            parts = cpe.split(":")        # cpe:/a:vendor:product:version[:...]
            if len(parts) < 5 or parts[1] != "/a" or not parts[4]:
                continue
            vendor, product, cpe_version = parts[2], parts[3], parts[4]
            version = p.get("version") or cpe_version
            label = " ".join(x for x in (p.get("product") or product, version) if x)
            return {"match": "cpe", "version": version, "product": label,
                    "cpe": f"cpe:2.3:a:{vendor}:{product}:{families.cpe_value(cpe_version)}"
                           ":*:*:*:*:*:*:*"}
    return None


def _apply_host(node: dict, scan: dict, client: NvdClient, cache: Cache,
                out: StageResult) -> None:
    """Record one answering host's ports, name, hint and (where found) CVEs."""
    node["open_ports"] = [{k: p.get(k) for k in _PORT_KEYS} for p in scan["open_ports"]]
    if scan.get("netbios") and not node.get("hostname"):
        node["hostname"], node["name_source"] = scan["netbios"], "netbios"
    if scan.get("device_hint") and not node.get("role"):
        node["device_hint"] = scan["device_hint"]

    ident = ident_from_ports(scan["open_ports"])
    if ident is None:
        return
    result = lookup(ident, client, cache)
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
    out = StageResult()
    targets, capped = question_targets(graph, cap)
    runner = runner if runner is not None else NmapRunner()
    block = {"eligible": len(targets), "scanned": 0, "answered": 0, "named": 0,
             "with_cves": 0, "nmap_requests": 0, "cap_reached": capped, "budget_exceeded": False}
    if capped:
        log.warning("more than %d unmanaged hosts; only the first %d are service-scanned", cap, cap)
        out.warnings.append({"type": "nmap_cap_reached", "cap": cap})
    if not targets:
        out.block = block
        return out
    if not runner.available:
        log.warning("nmap is not installed; the service scan was skipped")
        out.warnings.append({"type": "nmap_not_installed"})
        out.block = block
        return out

    block["scanned"] = len(targets)
    block["nmap_requests"] = 1
    try:
        xml_text = runner.scan([n["ip"] for n in targets], budget_s)
    except NmapBudgetExceeded:
        log.warning("nmap time budget (%.0f s) ran out; the hosts are left for the next scan", budget_s)
        out.warnings.append({"type": "nmap_budget_exceeded", "budget_s": budget_s})
        block["budget_exceeded"] = True
        out.block = block
        return out
    scans = parse_nmap_xml(xml_text)

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
    out.block = block
    log.info("service scan: %d eligible, %d scanned, %d answered, %d with CVEs, %d NVD request(s)",
             block["eligible"], block["scanned"], block["answered"], block["with_cves"], client.requests)
    return out


def run_service_scan(scan: "ScanContext") -> StageResult:
    """The pipeline's service scan, within the run's host cap and nmap budget.
    It counts as skipped when nmap is not installed."""
    args = scan.args
    client, cache = scan.nvd()
    before = cache.tally()
    result = run_stage(scan.document, client, cache,
                       cap=args.nmap_hosts_cap or DEFAULT_HOSTS_CAP,
                       budget_s=args.nmap_budget or DEFAULT_BUDGET_S, runner=scan.nmap_runner)
    scan.nvd_tally("service scan", before)
    block = result.block
    not_installed = any(w["type"] == "nmap_not_installed" for w in result.warnings)
    result.ran = not not_installed
    result.note = ("nmap not installed" if not_installed else
                   f"{plural(block['scanned'], 'host')} scanned, {block['answered']} answered, "
                   f"{block['with_cves']} with CVEs")
    scan.add_findings(result)
    return result
