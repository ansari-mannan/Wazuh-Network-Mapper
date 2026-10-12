"""One liveness pass over graph.json: probe every node by its best method,
read the switch ports and access point client lists, and work out each
node's new state. Pure apart from the prober it is handed.
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

from ..schema import CONF_WIFI, EDGE_ENDPOINT_LINK, ROLE_ACCESS_POINT, canonical_mac
from .records import (AGENT_MAX_AGE_S, MANAGER_AGENT_ID, _agent_verdict, _apply_probe, _carry,
                      _parse_time, _valid_ip)

log = logging.getLogger("vulnmapper.liveness")

DEFAULT_THRESHOLD = 2
MAX_IN_FLIGHT = 32
AGENT_TIMEOUT_S = 5.0           # login + agent list, or the method is skipped

# MAC-table confirmation (method "mac-table"): a wired host that no faster
# method has ever proven is looked up in its switch's forwarding table. A
# switch keeps a MAC for minutes after its host goes quiet, so this confirms
# presence and is slow to show absence; the port layer stays the fast signal.
FAST_METHODS = {"icmp", "snmp", "agent", "wifi"}
MAC_TABLE_BUDGET_S = 2.0        # per switch per pass, or it is skipped this pass

# A Wi-Fi client's "port" in a port_down mark.
WIFI_LINK = "wifi"
MAX_RESCAN_REASONS = 10


async def _fetch_agents(prober, timeout: float) -> tuple:
    """``({agent_id: row}, None)``, or ``(None, reason)`` when the check failed."""
    try:
        rows = await asyncio.wait_for(prober.agents(), timeout)
    except asyncio.TimeoutError:
        return None, f"agent check timed out after {timeout:g} s"
    except Exception as e:
        return None, f"agent check failed: {type(e).__name__}: {e}"[:300]
    return {str(r["id"]): r for r in rows or []
            if isinstance(r, dict) and r.get("id") is not None}, None


def _scan_time(graph: dict):
    meta = graph.get("metadata")
    return meta.get("scan_time") if isinstance(meta, dict) else None


def _colon(mac: str) -> str:
    return ":".join(mac[i:i + 2] for i in range(0, 12, 2))


def _linked_ports(graph: dict) -> dict:
    """device node_id -> the set of its ports that some graph edge uses."""
    linked = defaultdict(set)
    for edge in graph.get("edges") or []:
        if not isinstance(edge, dict):
            continue
        if edge.get("type") == EDGE_ENDPOINT_LINK:
            linked[edge.get("target")].add(edge.get("local_port"))
        else:
            linked[edge.get("source")].add(edge.get("local_port"))
            linked[edge.get("target")].add(edge.get("remote_port"))
    return linked


def _method_for(node: dict, has_snmp: bool) -> str:
    if node.get("kind") == "device" and node.get("pollable") and has_snmp:
        return "snmp"
    return "icmp"


async def liveness_pass(graph: dict, previous: dict, prober, threshold: int,
                        now: Optional[str] = None, agent_max_age: float = AGENT_MAX_AGE_S,
                        agent_timeout: float = AGENT_TIMEOUT_S) -> dict:
    """Run one pass and return the new state document.

    ``graph`` is the parsed graph.json, ``previous`` the last state document
    ({} when there is none), ``prober`` has ``has_snmp`` and async ``icmp(ip)``,
    ``snmp(ip)`` and ``port_status(ip)``, and optionally ``has_agents`` and
    async ``agents()``. The inputs are not modified.
    """
    now = now or datetime.now(timezone.utc).isoformat()
    previous = previous if isinstance(previous, dict) else {}
    use_agents = bool(getattr(prober, "has_agents", False))
    # One Manager API request for the whole pass, alongside the probes.
    agent_task = asyncio.ensure_future(_fetch_agents(prober, agent_timeout)) \
        if use_agents else None
    old_nodes = previous.get("nodes")
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

    # Each endpoint's link: (device, port) for a wired one, (access point,
    # WIFI_LINK) for a Wi-Fi client.
    wired_links = defaultdict(list)   # device node_id -> [(endpoint node_id, port)]
    link_of: dict = {}
    for edge in graph.get("edges") or []:
        if not isinstance(edge, dict) or edge.get("type") != EDGE_ENDPOINT_LINK:
            continue
        if edge.get("confidence") == CONF_WIFI:
            link_of.setdefault(edge.get("source"), (edge.get("target"), WIFI_LINK))
        elif edge.get("local_port"):
            wired_links[edge.get("target")].append((edge.get("source"), edge["local_port"]))
            link_of.setdefault(edge.get("source"), (edge.get("target"), edge["local_port"]))
    mac_of = {n["node_id"]: canonical_mac(n.get("mac")) for n in nodes}
    # Access points whose client list can be read this pass (SNMP, an address).
    access_points = {n["node_id"]: n for n in nodes
                     if n.get("role") == ROLE_ACCESS_POINT and n.get("pollable")
                     and _valid_ip(n.get("ip")) and prober.has_snmp}

    def on_wifi(nid: str) -> Optional[str]:
        """The access point a node is a Wi-Fi client of, if its list is readable."""
        here = link_of.get(nid)
        if here and here[1] == WIFI_LINK and here[0] in access_points and mac_of.get(nid):
            return here[0]
        return None

    records: dict = {}
    had_state: set = set()       # nodes that had a state before this pass
    to_probe: list = []
    by_agent: list = []          # endpoints checked by agent check-in
    by_wifi: list = []           # other Wi-Fi clients: checked by the AP's list
    for node in nodes:
        nid = node["node_id"]
        old = old_nodes.get(nid)
        old = old if isinstance(old, dict) else {}
        rec = _carry(old, now)
        records[nid] = rec
        if old.get("state"):
            had_state.add(nid)
        if use_agents and node.get("kind") == "endpoint" and node.get("agent_id"):
            by_agent.append(node)        # identified by agent id, not by address
            continue
        if on_wifi(nid):
            by_wifi.append(node)         # identified by MAC, in place of ping
            continue
        # A node made inactive by a down port stays so until the port layer
        # below restores it, even when it cannot be probed.
        unprobed = {} if "port_down" in rec else {"state": "unknown", "method": None}
        if nid in shared:
            rec.update(unprobed, reason="shared_ip")
        elif not node.get("ip"):
            rec.update(unprobed)
        elif not _valid_ip(node["ip"]):
            log.warning("%s: invalid IP in graph; not probed", nid)
            rec.update(unprobed, reason="invalid_ip")
        else:
            to_probe.append((node, _method_for(node, prober.has_snmp)))
    probed_by = {node["node_id"]: method for node, method in to_probe}
    probed_by.update((node["node_id"], "agent") for node in by_agent)
    probed_by.update((node["node_id"], "wifi") for node in by_wifi)

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

    def settle(node, method, replied, down=False, live=True):
        """Apply one method's verdict. A ``live`` reply (the host itself
        answered) also overrides a down port this pass; a MAC-table entry is
        not live, so a down port still wins over it."""
        rec = records[node["node_id"]]
        if replied and live:
            rec.pop("port_down", None)
        elif "port_down" in rec:
            return          # the down port explains the silence
        _apply_probe(rec, method, bool(replied), threshold, now, down)
        if replied and live:
            replied_now.add(node["node_id"])
            if method == "snmp":
                snmp_up.append(node)

    for node, method, replied, error in await asyncio.gather(
            *(probe(n, m) for n, m in to_probe)):
        if error is not None:
            log.warning("%s: %s probe failed: %s", node["node_id"], method, error)
            records[node["node_id"]].update(method=method, reason="probe_error")
            continue
        settle(node, method, replied)

    agent_rows, agent_error = (await agent_task) if agent_task else ({}, None)
    if agent_error:
        log.warning("%s; agent endpoints left unchanged this pass", agent_error)

    # Port layer: a link on a port that is now down means the host is gone.
    async def ports(device):
        try:
            return device["node_id"], await prober.port_status(device["ip"])
        except Exception as e:
            log.warning("%s: port status failed: %s", device["node_id"], e)
            return device["node_id"], None

    async def client_list(ap):
        try:
            return ap["node_id"], await prober.wifi_clients(ap["ip"])
        except Exception as e:
            log.warning("%s: Wi-Fi client list failed: %s", ap["node_id"], e)
            return ap["node_id"], None

    # Every polled device, linked or not: a new host can turn up on any port.
    # Every access point that answered SNMP: its client list, once per pass.
    statuses_and_lists = await asyncio.gather(
        asyncio.gather(*(ports(d) for d in snmp_up)),
        asyncio.gather(*(client_list(d) for d in snmp_up if d["node_id"] in access_points)))
    statuses = {dev: st for dev, st in statuses_and_lists[0] if isinstance(st, dict)}
    present = {ap: {canonical_mac(m) for m in macs} - {None}
               for ap, macs in statuses_and_lists[1] if macs is not None}

    def link_state(nid: str):
        """``(link, "up" | "down" | None)``: None when it was not read this pass."""
        here = link_of.get(nid)
        if here is None:
            return None, None
        device, port = here
        if port == WIFI_LINK:
            if device not in present:
                return here, None
            return here, "up" if mac_of.get(nid) in present[device] else "down"
        return here, statuses[device].get(port) if device in statuses else None

    def down_since(nid: str, rec: dict) -> Optional[str]:
        """When the node's link went down (port down, or gone from its AP's
        client list); None if it is not down.

        Read down now: since its first observation (this pass if new). Not read
        (the switch or AP did not answer) but already marked down: still down.
        """
        here, state = link_state(nid)
        if here is None:
            return None
        mark = rec.get("port_down")
        marked_here = isinstance(mark, dict) and (mark.get("device"), mark.get("port")) == here
        if state == "down" or (state is None and marked_here):
            # a mark from before "since" existed: first observed now (strict)
            return (mark.get("since") if marked_here else None) or now
        return None

    # Agent check-in. If the Manager API could not be read, these nodes keep
    # the state they had (no fallback to ping: Windows hosts would not answer).
    now_dt = _parse_time(now) or datetime.now(timezone.utc)
    for node in by_agent:
        rec = records[node["node_id"]]
        row = agent_rows.get(str(node["agent_id"])) if agent_rows is not None else None
        if row is None:
            rec["reason"] = "agent_unavailable" if agent_rows is None else "agent_not_listed"
            continue
        rec["agent"] = {"status": row.get("status"), "last_keepalive": row.get("lastKeepAlive")}
        replied, down = _agent_verdict(row, now_dt, agent_max_age)
        since = down_since(node["node_id"], rec) if replied else None
        if since is not None:
            seen, went_down = _parse_time(row.get("lastKeepAlive")), _parse_time(since)
            if seen is None or went_down is None or seen <= went_down:
                continue    # checked in before the port went down: the port decides
        settle(node, "agent", replied, down)

    # Wi-Fi: a node in its access point's client list replied (agent or not);
    # one missing from it is handled below like a down port.
    for nid, rec in records.items():
        here, state = link_state(nid)
        if here is None or here[1] != WIFI_LINK:
            continue
        if state == "up":
            settle(next(n for n in nodes if n["node_id"] == nid), "wifi", True)
        elif state is None and any(n["node_id"] == nid for n in by_wifi):
            rec["reason"] = "wifi_unavailable"

    # MAC table: a wired host no faster method has proven, on a switch that
    # answered SNMP this pass, is looked up in that switch's forwarding table.
    switches = {d["node_id"]: d for d in snmp_up}
    agent_ids = {n["node_id"] for n in by_agent}
    by_switch: dict = defaultdict(list)
    for node in nodes:
        nid = node["node_id"]
        rec = records[nid]
        here = link_of.get(nid)
        if node.get("kind") != "endpoint" or nid in agent_ids or nid in replied_now \
                or "port_down" in rec or not mac_of.get(nid) or here is None \
                or here[1] == WIFI_LINK or here[0] not in switches \
                or set(rec["proven_methods"]) & FAST_METHODS:
            continue
        vlan = node.get("vlan") if isinstance(node.get("vlan"), int) else None
        by_switch[here[0]].append((node, (vlan, mac_of[nid]), here[1]))

    async def mac_lookup(device_id, items):
        device = switches[device_id]
        per_vlan = str(device.get("vendor") or "").lower().startswith("cisco")
        try:
            found = await asyncio.wait_for(prober.mac_lookup(
                device["ip"], [entry for _n, entry, _p in items], per_vlan_context=per_vlan),
                MAC_TABLE_BUDGET_S)
        except Exception as e:      # slow (over the budget) or failing: skipped
            log.warning("%s: MAC-table lookup skipped this pass: %s", device_id,
                        e or type(e).__name__)
            return items, None
        return items, found

    for items, found in await asyncio.gather(
            *(mac_lookup(d, items) for d, items in by_switch.items())):
        for node, entry, port in items:
            if found is None:
                records[node["node_id"]]["reason"] = "mac_table_unavailable"
            else:
                settle(node, "mac-table", found.get(entry) == port, live=False)

    # Recovery: the port that went down is up again, or a new scan placed the
    # node elsewhere. Its earlier state comes back (an up port never makes a
    # node active by itself); misses restart from 0.
    for nid, rec in records.items():
        down = rec.get("port_down")
        if not down:
            continue
        where = (down.get("device"), down.get("port"))
        here, state = link_state(nid)
        if here != where or state == "up":
            del rec["port_down"]
            rec.update(state=down.get("previous_state") or "unknown", misses=0,
                       method=probed_by.get(nid))

    # A link that is down now (port down, or gone from the AP's client list):
    # inactive at once, remembering the state before.
    for nid, rec in records.items():
        here, state = link_state(nid)
        if state != "down" or nid in replied_now:
            continue
        mark = rec.get("port_down")
        if not mark or (mark.get("device"), mark.get("port")) != here:
            rec["port_down"] = {"device": here[0], "port": here[1],
                                "previous_state": rec["state"] if nid in had_state
                                or rec["state"] != "unknown" else None,
                                "since": now}
        elif not mark.get("since"):
            mark["since"] = now       # a mark written before "since" existed
        rec.update(state="inactive", method=CONF_WIFI if here[1] == WIFI_LINK else "port")

    ports_now, reasons = _port_memory_and_rescan(graph, nodes, previous, statuses, agent_rows,
                                                 present)
    doc = {"checked_at": now, "threshold": threshold, "nodes": records, "ports": ports_now,
           "graph_scan_time": _scan_time(graph),
           "rescan_suggested": bool(reasons), "rescan_reasons": reasons}
    if agent_error:
        doc["agent_error"] = agent_error
    return doc


def _port_memory_and_rescan(graph: dict, nodes: list, previous: dict, statuses: dict,
                            agent_rows: Optional[dict], wifi_lists: Optional[dict] = None) -> tuple:
    """``(ports to remember, rescan reasons)`` for the end of a pass."""
    names = {n["node_id"]: n.get("hostname") or n["node_id"]
             for n in nodes if n.get("kind") == "device"}
    old_ports = previous.get("ports") if isinstance(previous.get("ports"), dict) else {}
    remembered: dict = {}
    for dev in names:       # a device that did not answer keeps what it had
        if dev in statuses:
            remembered[dev] = dict(statuses[dev])
        elif isinstance(old_ports.get(dev), dict):
            remembered[dev] = dict(old_ports[dev])

    reasons: list = []
    linked = _linked_ports(graph)
    for dev, now_ports in statuses.items():
        before = old_ports.get(dev) if isinstance(old_ports.get(dev), dict) else {}
        for port, state in now_ports.items():
            if state == "up" and before.get(port) == "down" and port not in linked[dev]:
                reasons.append(f"port {port} on {names.get(dev, dev)} came up with "
                               "nothing linked to it")
    known_macs = {canonical_mac(n.get("mac")) for n in nodes} - {None}
    for ap, macs in (wifi_lists or {}).items():
        for mac in sorted(macs - known_macs):
            reasons.append(f"Wi-Fi client {_colon(mac)} on {names.get(ap, ap)} "
                           "is not in the graph")
    if agent_rows:
        in_graph = {str(n["agent_id"]) for n in nodes if n.get("agent_id")}
        for agent_id, row in agent_rows.items():
            if agent_id != MANAGER_AGENT_ID and agent_id not in in_graph \
                    and str(row.get("status") or "").lower() == "active":
                reasons.append(f"active Wazuh agent {agent_id} is not in the graph")

    # A suggestion stands until a new scan replaces the graph.
    if previous.get("graph_scan_time") == _scan_time(graph) \
            and isinstance(previous.get("rescan_reasons"), list):
        reasons = [r for r in previous["rescan_reasons"] if isinstance(r, str)] + reasons
    return remembered, list(dict.fromkeys(reasons))[:MAX_RESCAN_REASONS]
