"""Liveness heartbeat: re-check whether the nodes already in graph.json answer.

    python -m vulnmapper.liveness --graph PATH [--state PATH] [--threshold 3]

Reads the graph (never writes it) and the previous state, runs one pass and
prints the new state document on stdout; logs go to stderr only, the same
contract as ``pipeline.py``. Exits 0 with a valid document unless the graph
itself cannot be read.

Only IPs already in the graph are probed: no sweeps, no discovery.

Probe method per node
  * pollable device with an IP, SNMP credentials available -> ``snmp``
    (a credential that resolves is a reply; a failure is "snmp, no reply")
  * any other node with an IP (endpoints, devices without credentials or not
    pollable) -> ``icmp``: ``ping -c 1 -W 1 <ip>``, exit 0 is a reply
  * no IP, an invalid IP, or an IP shared by more than one non-stale node -> no
    probe (state ``unknown``, method null)

State rules per node: a reply makes it ``active`` (misses 0, ``last_seen`` now,
method proven). Silence on a proven method adds a miss and, at ``threshold``
misses, makes it ``inactive``; below that the state is unchanged. Silence on a
never-proven method proves nothing (Windows blocks ping), so nothing changes.

Port layer: each pollable device that answered SNMP in this pass has its port
status read with the crawler's ``collect_port_status``. An endpoint whose link
to that device uses a port that is now ``down`` becomes ``inactive`` at once
with method ``port`` (unless it answered in this same pass). An ``up`` port
changes nothing.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import logging
import sys
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

log = logging.getLogger("vulnmapper.liveness")

DEFAULT_THRESHOLD = 3
MAX_IN_FLIGHT = 32
EDGE_ENDPOINT_LINK = "endpoint_link"


def _setup_logging() -> None:
    logging.basicConfig(
        stream=sys.stderr,
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


# ---------------------------------------------------------------------------
# The real prober (system ping + the crawler's SNMP client)
# ---------------------------------------------------------------------------

class SystemProber:
    """Probes through the system ``ping`` binary and the existing SnmpClient.

    The SNMP community comes only from the environment (``load_credentials``)
    and is never logged or placed in argv.
    """

    def __init__(self, credentials: list) -> None:
        self.has_snmp = bool(credentials)
        self._snmp = None
        if credentials:
            from .network.snmp import SnmpClient
            self._snmp = SnmpClient(credentials, timeout=1.0, retries=1)

    async def icmp(self, ip: str) -> bool:
        ipaddress.ip_address(ip)          # validated again right before argv
        proc = await asyncio.create_subprocess_exec(
            "ping", "-c", "1", "-W", "1", ip,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        return await proc.wait() == 0

    async def snmp(self, ip: str) -> bool:
        return await self._snmp.resolve_credential(ip) is not None

    async def port_status(self, ip: str) -> dict:
        from .network.parse import collect_port_status
        return await collect_port_status(self._snmp, ip)


# ---------------------------------------------------------------------------
# One pass (pure apart from the injected prober)
# ---------------------------------------------------------------------------

def _valid_ip(ip) -> bool:
    try:
        ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return False
    return True


def _method_for(node: dict, has_snmp: bool) -> str:
    if node.get("kind") == "device" and node.get("pollable") and has_snmp:
        return "snmp"
    return "icmp"


def _carry(old: dict, now: str) -> dict:
    """A fresh record carrying the fields that survive across passes."""
    return {
        "state": old.get("state") or "unknown",
        "method": old.get("method"),
        "misses": old.get("misses") if isinstance(old.get("misses"), int) else 0,
        "last_seen": old.get("last_seen"),
        "last_checked": now,
        "proven_methods": list(old.get("proven_methods") or []),   # a copy, never shared
    }


def _apply_probe(rec: dict, method: str, replied: bool, threshold: int, now: str) -> None:
    rec["method"] = method
    if replied:
        rec.update(state="active", misses=0, last_seen=now)
        if method not in rec["proven_methods"]:
            rec["proven_methods"].append(method)
    elif method in rec["proven_methods"]:
        rec["misses"] += 1
        if rec["misses"] >= threshold:
            rec["state"] = "inactive"
    # silence on a never-proven method: nothing changes


async def liveness_pass(graph: dict, previous: dict, prober, threshold: int,
                        now: Optional[str] = None) -> dict:
    """Run one pass and return the new state document.

    ``graph`` is the parsed graph.json, ``previous`` the last state document
    ({} when there is none), ``prober`` has ``has_snmp`` and async ``icmp(ip)``,
    ``snmp(ip)`` and ``port_status(ip)``. The inputs are not modified.
    """
    now = now or datetime.now(timezone.utc).isoformat()
    old_nodes = previous.get("nodes") if isinstance(previous, dict) else None
    old_nodes = old_nodes if isinstance(old_nodes, dict) else {}
    nodes = [n for n in graph.get("nodes") or [] if isinstance(n, dict) and n.get("node_id")]

    # Shared addresses: stale nodes step aside; a still-shared IP is not probed.
    by_ip: dict = defaultdict(list)
    for node in nodes:
        if _valid_ip(node.get("ip")):
            by_ip[node["ip"]].append(node)
    shared: set = set()
    for group in by_ip.values():
        if len(group) < 2:
            continue
        live = [n for n in group if not n.get("stale")]
        shared.update(n["node_id"] for n in group if n.get("stale") or len(live) > 1)

    records: dict = {}
    to_probe: list = []
    for node in nodes:
        nid = node["node_id"]
        old = old_nodes.get(nid)
        rec = _carry(old if isinstance(old, dict) else {}, now)
        records[nid] = rec
        if nid in shared:
            rec.update(state="unknown", method=None, reason="shared_ip")
        elif not node.get("ip"):
            rec.update(state="unknown", method=None)
        elif not _valid_ip(node["ip"]):
            log.warning("%s: invalid IP in graph; not probed", nid)
            rec.update(state="unknown", method=None, reason="invalid_ip")
        else:
            to_probe.append((node, _method_for(node, prober.has_snmp)))

    semaphore = asyncio.Semaphore(MAX_IN_FLIGHT)

    async def probe(node, method):
        async with semaphore:
            try:
                fn = prober.snmp if method == "snmp" else prober.icmp
                return node, method, await fn(node["ip"]), None
            except Exception as e:          # one node must not abort the pass
                return node, method, None, e

    replied_now: set = set()
    snmp_up: list = []
    for node, method, replied, error in await asyncio.gather(
            *(probe(n, m) for n, m in to_probe)):
        rec = records[node["node_id"]]
        if error is not None:
            log.warning("%s: %s probe failed: %s", node["node_id"], method, error)
            rec.update(method=method, reason="probe_error")
            continue
        _apply_probe(rec, method, bool(replied), threshold, now)
        if replied:
            replied_now.add(node["node_id"])
            if method == "snmp":
                snmp_up.append(node)

    # Port layer: a link on a port that is now down means the host is gone.
    links = defaultdict(list)
    for edge in graph.get("edges") or []:
        if isinstance(edge, dict) and edge.get("type") == EDGE_ENDPOINT_LINK \
                and edge.get("local_port"):
            links[edge.get("target")].append((edge.get("source"), edge["local_port"]))

    async def ports(device):
        try:
            return device, await prober.port_status(device["ip"])
        except Exception as e:
            log.warning("%s: port status failed: %s", device["node_id"], e)
            return device, {}

    for device, status in await asyncio.gather(
            *(ports(d) for d in snmp_up if links.get(d["node_id"]))):
        for source, port in links[device["node_id"]]:
            rec = records.get(source)
            if rec is None or source in replied_now or status.get(port) != "down":
                continue
            rec.update(state="inactive", method="port")

    return {"checked_at": now, "threshold": threshold, "nodes": records}


# ---------------------------------------------------------------------------
# CLI: read files, run the pass, print
# ---------------------------------------------------------------------------

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


def main(argv: Optional[list] = None) -> int:
    _setup_logging()
    parser = argparse.ArgumentParser(
        prog="vulnmapper.liveness",
        description="Re-check whether the nodes in graph.json answer; print the "
                    "liveness state document on stdout.")
    parser.add_argument("--graph", required=True, metavar="PATH", help="graph.json to read")
    parser.add_argument("--state", metavar="PATH",
                        help="previous liveness.json (missing or invalid = empty)")
    parser.add_argument("--threshold", type=_threshold, default=DEFAULT_THRESHOLD,
                        help="misses on a proven method before a node is inactive")
    args = parser.parse_args(argv)

    try:
        with open(args.graph, encoding="utf-8") as f:
            graph = json.load(f)
        if not isinstance(graph, dict):
            raise ValueError("not a graph document")
    except (OSError, ValueError) as e:
        print(f"vulnmapper.liveness: cannot read graph {args.graph}: {e}", file=sys.stderr)
        return 1

    from .network.crawl import load_credentials
    prober = SystemProber(load_credentials(None))
    doc = asyncio.run(liveness_pass(graph, load_state(args.state), prober, args.threshold))
    sys.stdout.write(json.dumps(doc, indent=2) + "\n")
    sys.stdout.flush()
    counts = defaultdict(int)
    for rec in doc["nodes"].values():
        counts[rec["state"]] += 1
    log.info("liveness pass: %d node(s): %s", len(doc["nodes"]),
             ", ".join(f"{k} {v}" for k, v in sorted(counts.items())) or "none")
    return 0


if __name__ == "__main__":
    sys.exit(main())
