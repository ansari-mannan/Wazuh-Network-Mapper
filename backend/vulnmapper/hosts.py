"""Hosts without a Wazuh agent: label them, and learn what they probably are.

A host is an endpoint-kind node. One with an ``agent_id`` is managed (active
or disconnected alike; the Wazuh server is agent 000); one without came from
a switch's forwarding table, an LLDP or CDP announcement, or an access
point's client list, and is unmanaged: nothing reports its software, so its
vulnerabilities are not known. Network devices are not hosts.

Passive clues, from data already in the graph (:func:`label`):

  mac_type    "global" (the first three bytes name a manufacturer in IEEE's
              registry) or "local" (locally administered: randomised or
              virtual, with no manufacturer)
  mac_vendor  the registry's organisation for a global MAC (None if absent)

Clues that ask someone else, run by the pipeline:

  :func:`lookup_names`  reverse DNS through the system resolver (on by
                        default; it asks the site's DNS server, not the host)
  :func:`ask_hosts`     one SNMP read of each unmanaged host's system group
                        with the owner's credentials (off by default: it sends
                        the credential to machines nobody has vouched for)

risk_score is not touched by any of these.
"""

from __future__ import annotations

import asyncio
import gzip
import logging
import os
import socket
import threading
import time
from functools import lru_cache
from typing import Callable, Optional

from .schema import KIND_DEVICE, KIND_ENDPOINT, canonical_mac

log = logging.getLogger("vulnmapper.hosts")

REGISTRY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "oui.tsv.gz")
# IEEE blocks are 24 (MA-L), 28 (MA-M) or 36 (MA-S) bits: longest first.
PREFIX_LENGTHS = (9, 7, 6)
# The holder of a 24-bit block IEEE splits into MA-M / MA-S blocks: not a maker.
REGISTRY_AUTHORITY = "IEEE Registration Authority"


# --- passive: managed or not, MAC type and manufacturer ----------------------

@lru_cache(maxsize=1)
def _registry() -> dict:
    out = {}
    with gzip.open(REGISTRY, "rt", encoding="utf-8") as fh:
        for line in fh:
            if not line.startswith("#"):
                prefix, _, name = line.rstrip("\n").partition("\t")
                out[prefix] = name
    return out


def mac_type(mac) -> Optional[str]:
    """"local" when the locally administered bit is set, else "global"."""
    cmac = canonical_mac(mac)
    if cmac is None:
        return None
    return "local" if int(cmac[:2], 16) & 0x02 else "global"


def manufacturer(mac) -> Optional[str]:
    """The IEEE registry's organisation for a global MAC, else None."""
    cmac = canonical_mac(mac)
    if cmac is None or mac_type(cmac) != "global":
        return None
    registry = _registry()
    name = next((registry[cmac[:n]] for n in PREFIX_LENGTHS if cmac[:n] in registry), None)
    return None if name == REGISTRY_AUTHORITY else name


def label(graph: dict) -> dict:
    """Mark every host managed or unmanaged, add its MAC clues and
    ``metadata.coverage``. In place; returns ``graph``."""
    hosts = [n for n in graph.get("nodes") or [] if n.get("kind") == KIND_ENDPOINT]
    for node in hosts:
        node["unmanaged"] = node.get("agent_id") is None
        kind = mac_type(node.get("mac"))
        if kind is not None:
            node["mac_type"] = kind
            node["mac_vendor"] = manufacturer(node["mac"])
    managed = sum(not n["unmanaged"] for n in hosts)
    graph.setdefault("metadata", {})["coverage"] = {
        "hosts": len(hosts),
        "managed": managed,
        "unmanaged": len(hosts) - managed,
        "managed_share": round(managed / len(hosts), 3) if hosts else None,
    }
    return graph


# --- reverse DNS ---------------------------------------------------------------

LOOKUP_TIMEOUT_S = 1.0
LOOKUP_BUDGET_S = 5.0
LOOKUP_PARALLEL = 32


def _reverse(ip: str) -> Optional[str]:
    return socket.gethostbyaddr(ip)[0]


def lookup_names(graph: dict, resolver: Callable = _reverse,
                 timeout_s: float = LOOKUP_TIMEOUT_S, budget_s: float = LOOKUP_BUDGET_S,
                 parallel: int = LOOKUP_PARALLEL) -> dict:
    """Fill ``hostname`` (and ``name_source: "dns"``) on hosts that have an
    address and no name. Returns ``{asked, named, budget_reached}``.

    The system resolver cannot be interrupted, so each lookup runs in a daemon
    thread and an answer later than ``timeout_s`` is not waited for. Lookups
    run ``parallel`` at a time until ``budget_s`` is spent.
    """
    todo = [n for n in graph.get("nodes") or []
            if n.get("kind") == KIND_ENDPOINT and n.get("ip") and not n.get("hostname")]
    names: dict = {}
    deadline = time.monotonic() + budget_s
    asked = 0

    def ask(ip):
        try:
            names[ip] = resolver(ip)
        except Exception:      # no PTR record, resolver error: no name
            pass

    for start in range(0, len(todo), parallel):
        left = deadline - time.monotonic()
        if left <= 0:
            break
        batch = todo[start:start + parallel]
        threads = [threading.Thread(target=ask, args=(n["ip"],), daemon=True) for n in batch]
        for thread in threads:
            thread.start()
        asked += len(batch)
        stop = time.monotonic() + min(timeout_s, left)
        for thread in threads:
            thread.join(max(0.0, stop - time.monotonic()))
    named = 0
    snapshot = dict(names)       # threads still running cannot change what is used
    for node in todo:
        name = snapshot.get(node["ip"])
        if name and name != node["ip"]:
            node["hostname"], node["name_source"] = name, "dns"
            named += 1
    _rename_edges(graph, {n["node_id"]: n["hostname"] for n in todo if n.get("name_source")})
    return {"asked": asked, "named": named, "budget_reached": asked < len(todo)}


def _rename_edges(graph: dict, names: dict) -> None:
    for edge in graph.get("edges") or []:
        for end in ("source", "target"):
            if edge.get(end) in names:
                edge[f"{end}_name"] = names[edge[end]]


# --- the optional SNMP question ---------------------------------------------------

QUESTION_CAP = 256
QUESTION_PARALLEL = 32


def question_targets(graph: dict, cap: int = QUESTION_CAP) -> tuple:
    """``(hosts to ask, cap reached)``: unmanaged hosts with an address."""
    hosts = [n for n in graph.get("nodes") or []
             if n.get("kind") == KIND_ENDPOINT and n.get("unmanaged") and n.get("ip")]
    return hosts[:cap], len(hosts) > cap


async def _ask_one(client, ip: str) -> Optional[dict]:
    """The host's identity, and whether it forwards traffic; None when silent."""
    from .network import parse
    from .network.crawl import fetch

    if await client.resolve_credential(ip) is None:
        return None
    info = await fetch(client, ip)
    if info is None:
        return None
    # One row of any neighbour or forwarding table makes it a device.
    for base in (parse.LLDP_REM_BASE, parse.CDP_CACHE_BASE,
                 parse.DOT1Q_FDB_PORT_BASE, parse.DOT1D_FDB_PORT_BASE):
        if await client.walk(ip, base, max_rows=1):
            info["forwards"] = True
            break
    else:
        info["forwards"] = False
    return info


async def ask_hosts(client, ips: list, parallel: int = QUESTION_PARALLEL) -> dict:
    """``{ip: identity or None}``: each host asked once, ``parallel`` at a time."""
    gate = asyncio.Semaphore(parallel)

    async def one(ip):
        async with gate:
            try:
                return ip, await _ask_one(client, ip)
            except Exception:          # a host that misbehaves simply did not answer
                log.exception("SNMP question to %s failed", ip)
                return ip, None
    return dict(await asyncio.gather(*(one(ip) for ip in ips)))


def apply_answer(node: dict, info: dict) -> None:
    """What an answering host said about itself, on its graph node."""
    node["snmp"] = True
    if not node.get("hostname") and info.get("hostname"):
        node["hostname"], node["name_source"] = info["hostname"], "snmp"
    node["sys_descr"] = info.get("sys_descr")
    if node.get("kind") != KIND_DEVICE and info.get("vendor") not in (None, "unknown vendor"):
        node["vendor"] = info["vendor"]
        node["model"] = info.get("model")
        node["firmware"] = info.get("firmware")
    if info.get("software_family"):
        node["software_family"] = info["software_family"]
