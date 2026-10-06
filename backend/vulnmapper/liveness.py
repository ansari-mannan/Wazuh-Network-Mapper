"""Liveness heartbeat: check reachability for nodes in graph.json.

  python -m vulnmapper.liveness --graph PATH [--state PATH] [--threshold 3]

Emits liveness JSON to stdout.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import logging
import sys
from datetime import datetime, timezone
from typing import Optional, Callable, Awaitable

from .network.crawl import load_credentials
from .network.snmp import SnmpClient

log = logging.getLogger("vulnmapper.liveness")

def _setup_logging() -> None:
    logging.basicConfig(
        stream=sys.stderr,
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

async def _ping_impl(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return False
    proc = await asyncio.create_subprocess_exec(
        "ping", "-n", "1", "-w", "1000", ip,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    return await proc.wait() == 0

class Prober:
    def __init__(self, ping_fn: Callable[[str], Awaitable[bool]] = _ping_impl):
        self.ping = ping_fn
        self.snmp = SnmpClient(load_credentials(None))

    async def check(self, node: dict) -> tuple[Optional[str], bool]:
        ip = node.get("ip")
        if not ip: return None, False

        # SNMP
        if node.get("kind") == "device" and node.get("pollable"):
            if await self.snmp.resolve_credential(ip):
                if await self.snmp.get(ip, "1.3.6.1.2.1.1.3.0"):
                    return "snmp", True

        # ICMP
        return "icmp", await self.ping(ip)

async def main():
    _setup_logging()
    parser = argparse.ArgumentParser()
    parser.add_argument("--graph", required=True)
    parser.add_argument("--state")
    parser.add_argument("--threshold", type=int, default=3)
    args = parser.parse_args()

    with open(args.graph) as f:
        graph = json.load(f)

    # Load previous state
    prev_state = {}
    if args.state:
        try:
            with open(args.state) as f:
                prev_state = json.load(f).get("nodes", {})
        except (FileNotFoundError, json.JSONDecodeError):
            pass

    prober = Prober()
    nodes = graph.get("nodes", {})

    semaphore = asyncio.Semaphore(32)
    async def _wrapped_probe(nid, node):
        async with semaphore:
            method, replied = await prober.check(node)
            return nid, method, replied

    tasks = [_wrapped_probe(nid, node) for nid, node in nodes.items()]
    probes = await asyncio.gather(*tasks)

    new_state_nodes = {}
    now = datetime.now(timezone.utc).isoformat()

    for nid, method, replied in probes:
        old = prev_state.get(nid, {})
        proven = old.get("proven_methods", [])
        misses = old.get("misses", 0)

        if method is None:
            new_state_nodes[nid] = {"state": "unknown", "last_checked": now}
            continue

        new_node = old.copy()
        new_node["last_checked"] = now

        if replied:
            new_node["state"] = "active"
            new_node["misses"] = 0
            new_node["last_seen"] = now
            new_node["method"] = method
            if method not in proven:
                proven.append(method)
                new_node["proven_methods"] = proven
        elif method in proven:
            misses += 1
            new_node["misses"] = misses
            if misses >= args.threshold:
                new_node["state"] = "inactive"
            else:
                new_node["state"] = "active"
        else:
            # Silence proves nothing
            new_node.setdefault("state", "unknown")
            new_node["method"] = method

        new_state_nodes[nid] = new_node

    print(json.dumps({
        "checked_at": now,
        "threshold": args.threshold,
        "nodes": new_state_nodes
    }, indent=2))

if __name__ == "__main__":
    asyncio.run(main())
