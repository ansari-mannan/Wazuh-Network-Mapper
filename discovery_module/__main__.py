"""Network discovery + topology pipeline for the Wazuh vulnerability mapper.

One command runs the whole flow and prints ONE JSON document to stdout:

    python -m discovery_module --subnet 172.20.99.0/24 \\
        --subnet 172.20.100.0/30 --community cyfor123

Pipeline:
  1. DISCOVER & IDENTIFY  - sweep the subnet(s); for each live SNMP device read
     vendor/model/firmware/serial/hostname and its LLDP chassis MAC.
  2. TOPOLOGY EDGES       - walk each device's LLDP remote table.
  3. CORRELATE            - match neighbors to discovered nodes -> directed edges.
  4. DEDUPLICATE          - collapse both-direction reports into single edges.

Contract: stdout carries ONLY the final JSON document (so a parent process,
e.g. Node.js, can parse it); all progress/status goes to stderr.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import os
import sys
from datetime import datetime, timezone
from typing import Optional

# Make the sibling clients/ and vendors/ packages importable whether this is
# launched as `python __main__.py`, `python -m discovery_module`, or from the
# parent directory.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from clients.snmp_client import (
    OID_LLDP_LOC_CHASSIS_ID,
    OID_SYS_DESCR,
    OID_SYS_NAME,
    OID_SYS_OBJECT_ID,
    SnmpClient,
)
from topology import build_edges, dedupe_edges, walk_lldp_neighbors
from utils import collapse_whitespace, normalize_mac
from vendors import VENDOR_BY_ENTERPRISE

# Cap on simultaneous in-flight probes. Kept conservative because SNMP is UDP:
# firing hundreds of probes at once overruns the OS receive buffer (observed on
# Windows) and live devices get silently missed. 32 reliably found all devices
# in lab testing; raise via --concurrency only if your stack keeps up.
DEFAULT_CONCURRENCY = 32

_ENTERPRISE_PREFIX = "1.3.6.1.4.1."


def _enterprise_number(sys_object_id: Optional[str]) -> Optional[str]:
    """Pull the enterprise (vendor) number out of a sysObjectID.

    "1.3.6.1.4.1.9.1.516" -> "9";  "1.3.6.1.4.1.12356.101.1.2005" -> "12356".
    """
    if not sys_object_id or not sys_object_id.startswith(_ENTERPRISE_PREFIX):
        return None
    remainder = sys_object_id[len(_ENTERPRISE_PREFIX):]
    return remainder.split(".")[0] or None


# ---- Phase 1: discover & identify -----------------------------------------

async def probe_host(
    client: SnmpClient, ip: str, semaphore: asyncio.Semaphore
) -> Optional[dict]:
    """Probe one host. Returns a node dict if it answers SNMP, else None."""
    async with semaphore:
        # One PDU for the system group + the device's own LLDP chassis MAC.
        base = await client.get_many(
            ip,
            [
                OID_SYS_DESCR,
                OID_SYS_OBJECT_ID,
                OID_SYS_NAME,
                OID_LLDP_LOC_CHASSIS_ID,
            ],
        )

    if base is None:
        return None  # No response -> not a live SNMP device.

    sys_descr = collapse_whitespace(base.get(OID_SYS_DESCR))
    sys_object_id = base.get(OID_SYS_OBJECT_ID)
    hostname = base.get(OID_SYS_NAME)
    mac = normalize_mac(base.get(OID_LLDP_LOC_CHASSIS_ID))

    print(f"  live SNMP device: {ip} ({hostname or 'no sysName'})", file=sys.stderr)

    enterprise = _enterprise_number(sys_object_id)
    vendor_entry = VENDOR_BY_ENTERPRISE.get(enterprise)

    if vendor_entry is not None:
        vendor_name, vendor_module = vendor_entry
        specifics = await vendor_module.identify(sys_descr, sys_object_id, client, ip)
    else:
        vendor_name = "unknown vendor"
        specifics = {"model": None, "firmware": None, "serial": None}

    return {
        "ip": ip,
        "hostname": hostname,
        "vendor": vendor_name,
        "model": specifics.get("model"),
        "firmware": specifics.get("firmware"),
        "serial": specifics.get("serial"),
        "mac": mac,
        "discovery_method": "snmp",
    }


def _expand_hosts(subnets: list[str]) -> list[str]:
    """Flatten subnets to a de-duplicated, ordered list of host IPs."""
    seen: dict[str, None] = {}
    for subnet in subnets:
        for host in ipaddress.ip_network(subnet, strict=False).hosts():
            seen.setdefault(str(host), None)
    return list(seen)


def dedupe_nodes(nodes: list[dict]) -> list[dict]:
    """Collapse one physical device that answers on multiple IPs into one node.

    A dual-homed device (e.g. an L3 switch with an interface in two subnets)
    is discovered once per IP. Identity is keyed by MAC when known, else
    hostname, else IP. The first occurrence wins (so the lower/management IP is
    kept); extra IPs are logged to stderr rather than emitted, to keep the node
    schema stable.
    """
    by_key: dict[str, dict] = {}
    order: list[str] = []
    for node in nodes:
        if node["mac"]:
            key = f"mac:{node['mac']}"
        elif node["hostname"]:
            key = f"host:{node['hostname']}"
        else:
            key = f"ip:{node['ip']}"

        if key in by_key:
            kept = by_key[key]
            print(
                f"  merged {node['ip']} into {kept['ip']} "
                f"(same device: {kept['hostname'] or kept['mac'] or kept['ip']})",
                file=sys.stderr,
            )
        else:
            by_key[key] = node
            order.append(key)
    return [by_key[k] for k in order]


# ---- Full pipeline ---------------------------------------------------------

async def run_pipeline(
    subnets: list[str],
    community: str,
    *,
    timeout: float,
    concurrency: int,
    port: int = 161,
    retries: int = 2,
) -> dict:
    client = SnmpClient(community, port=port, timeout=timeout, retries=retries)
    semaphore = asyncio.Semaphore(concurrency)

    hosts = _expand_hosts(subnets)
    print(
        f"Phase 1: sweeping {len(subnets)} subnet(s) = {len(hosts)} host(s), "
        f"timeout={timeout}s, concurrency={concurrency}",
        file=sys.stderr,
    )

    probed = await asyncio.gather(
        *(probe_host(client, ip, semaphore) for ip in hosts)
    )
    discovered = [n for n in probed if n is not None]
    nodes = dedupe_nodes(discovered)
    print(
        f"Phase 1: {len(discovered)} live SNMP response(s) -> "
        f"{len(nodes)} unique device(s).",
        file=sys.stderr,
    )

    # Phase 2: walk each device's LLDP remote table.
    print("Phase 2: walking LLDP neighbor tables ...", file=sys.stderr)

    async def _walk(node):
        async with semaphore:
            neighbors = await walk_lldp_neighbors(client, node["ip"])
        if neighbors:
            print(
                f"  {node['hostname'] or node['ip']}: {len(neighbors)} LLDP neighbor(s)",
                file=sys.stderr,
            )
        return node["ip"], neighbors

    walked = await asyncio.gather(*(_walk(n) for n in nodes))
    neighbors_by_ip = dict(walked)

    # Phases 3 & 4: correlate to nodes, then dedupe.
    directed = build_edges(nodes, neighbors_by_ip)
    edges = dedupe_edges(directed)
    print(
        f"Phase 3/4: {len(directed)} directed neighbor link(s) -> "
        f"{len(edges)} deduplicated edge(s).",
        file=sys.stderr,
    )

    return {
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "nodes": nodes,
        "edges": edges,
    }


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="discovery_module", description=__doc__)
    parser.add_argument(
        "--subnet",
        action="append",
        required=True,
        metavar="CIDR",
        help="subnet to sweep, e.g. 172.20.99.0/24 (repeatable)",
    )
    parser.add_argument("--community", required=True, help="SNMPv2c community string")
    parser.add_argument(
        "--timeout", type=float, default=1.0, help="per-request timeout (s)"
    )
    parser.add_argument(
        "--port", type=int, default=161, help="SNMP UDP port (default 161)"
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=2,
        help="SNMP retries per request (default 2). SNMP is UDP; >0 is needed "
        "so a single dropped packet doesn't miss a device or abort an LLDP walk.",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=DEFAULT_CONCURRENCY,
        help=f"max simultaneous probes (default {DEFAULT_CONCURRENCY})",
    )
    args = parser.parse_args(argv)

    for subnet in args.subnet:
        try:
            ipaddress.ip_network(subnet, strict=False)
        except ValueError as exc:
            print(f"Invalid --subnet {subnet!r}: {exc}", file=sys.stderr)
            return 2

    document = asyncio.run(
        run_pipeline(
            args.subnet,
            args.community,
            timeout=args.timeout,
            concurrency=args.concurrency,
            port=args.port,
            retries=args.retries,
        )
    )

    # Short summary to stderr so correctness is easy to eyeball.
    print(
        f"SUMMARY: {len(document['nodes'])} node(s), {len(document['edges'])} edge(s).",
        file=sys.stderr,
    )

    # The ONLY thing on stdout: the final JSON document.
    json.dump(document, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
