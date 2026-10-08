"""Liveness heartbeat: re-check whether the nodes already in graph.json answer.

    python -m vulnmapper.liveness --graph PATH [--state PATH] [--threshold 2]
                                  [--agent-max-age 30]

Reads the graph (never writes it) and the previous state, runs one pass and
prints the new state document on stdout; logs go to stderr only, the same
contract as ``pipeline.py``. Exits 0 with a valid document unless the graph
itself cannot be read.

Only IPs already in the graph are probed: no sweeps, no discovery.

Probe method per node
  * endpoint with an ``agent_id``, Wazuh credentials available -> ``agent``:
    one Manager API request per pass lists every agent's status and
    lastKeepAlive. Active with a check-in no older than ``--agent-max-age``
    seconds is a reply (agent 000, the manager, always is); active with an
    older check-in is a miss; disconnected / pending / never_connected makes
    the node inactive at once. If the login or request fails or takes longer
    than 5 s, these nodes are left as they were for the pass.
  * pollable device with an IP, SNMP credentials available -> ``snmp``
    (a credential that resolves is a reply; a failure is "snmp, no reply")
  * any other node with an IP (endpoints, devices without credentials or not
    pollable) -> ``icmp``: ``ping -c 1 -W 1 <ip>``, exit 0 is a reply
  * no IP, an invalid IP, or an IP shared by more than one non-stale node -> no
    probe (state ``unknown``, method null)

State rules per node: a reply makes it ``active`` (misses 0, ``last_seen`` now,
method proven). Silence on a proven method adds a miss and, at ``threshold``
misses, makes it ``inactive``; below that the state is unchanged. Silence on a
never-proven method proves nothing (Windows blocks ping), so nothing changes;
``agent`` counts as proven from the start (a stale check-in is real evidence).

Port layer: each pollable device that answered SNMP in this pass has its port
status read with the crawler's ``collect_port_status``. An endpoint whose link
to that device uses a port that is now ``down`` becomes ``inactive`` at once
with method ``port``, and ``port_down.since`` records when that port was first
seen down. A ping or SNMP reply in the same pass still wins. An agent check-in
is a stored time, not a live reply: on a down port it counts only if
``lastKeepAlive`` is later than ``since`` (the machine reconnected some other
way). The node gets its earlier state back once the port is up again or a new
scan places it elsewhere. An ``up`` port never makes a node active by itself.

Rescan suggestion: the port states are remembered between passes (``ports``).
A pass sets ``rescan_suggested`` (with short ``rescan_reasons``) when a port
went from down to up and no graph edge uses that port, or when the Manager
API lists an active agent (other than 000) that is not in the graph. A port
coming back up for a node already linked there is recovery, not a reason. The
suggestion stands until a new scan replaces the graph (``graph_scan_time``).
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import logging
import sys
import threading
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

from .schema import canonical_mac

log = logging.getLogger("vulnmapper.liveness")

DEFAULT_THRESHOLD = 2
MAX_IN_FLIGHT = 32
EDGE_ENDPOINT_LINK = "endpoint_link"

# Wazuh agent check-in (method "agent")
AGENT_MAX_AGE_S = 30            # a check-in older than this is a miss
AGENT_TIMEOUT_S = 5.0           # login + agent list, or the method is skipped
AGENT_DOWN = {"disconnected", "pending", "never_connected"}
MANAGER_AGENT_ID = "000"        # reports a far-future lastKeepAlive
# Methods whose silence counts as a miss before any reply was ever seen. The
# scan found a host's MAC in its switch's table, so its absence there is
# evidence too.
PROVEN_FROM_START = {"agent", "mac-table"}

# MAC-table confirmation (method "mac-table"): a wired host that no faster
# method has ever proven is looked up in its switch's forwarding table. A
# switch keeps a MAC for minutes after its host goes quiet, so this confirms
# presence and is slow to show absence; the port layer stays the fast signal.
FAST_METHODS = {"icmp", "snmp", "agent", "wifi"}
MAC_TABLE_BUDGET_S = 2.0        # per switch per pass, or it is skipped this pass

# Wi-Fi clients (method "wifi"): a node linked to an access point with
# confidence "wifi" is checked against the AP's client list. In a port_down
# mark, a Wi-Fi link has this as its "port".
CONF_WIFI = "wifi"
WIFI_LINK = "wifi"
ROLE_ACCESS_POINT = "access-point"
MAX_RESCAN_REASONS = 10


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

    def __init__(self, credentials: list, agent_source=None) -> None:
        self.has_snmp = bool(credentials)
        self._snmp = None
        if credentials:
            from .network.snmp import SnmpClient
            self._snmp = SnmpClient(credentials, timeout=1.0, retries=1)
        # The agent method needs the Wazuh password (WAZUH_PASS, environment only).
        self._agent_source = agent_source
        if agent_source is None:
            from .schema import WazuhConfig
            self.has_agents = bool(WazuhConfig.from_env().password)
        else:
            self.has_agents = True

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

    async def mac_lookup(self, ip: str, entries: list, per_vlan_context: bool = False) -> dict:
        """``{(vlan, mac): port name or None}`` from GETs of those entries only."""
        from .network.parse import lookup_fdb_ports
        return await lookup_fdb_ports(self._snmp, ip, entries, per_vlan_context)

    async def wifi_clients(self, ip: str) -> set:
        """The canonical MACs an access point lists as associated (one column).

        A walk that stops early also returns no rows, so an empty list counts
        only if the AP's own per-radio client counters say it is empty;
        otherwise this raises and the pass leaves its clients unchanged.
        """
        from .network.parse import (DOT11_ACTIVE_CLIENTS_BASE, DOT11_CLIENT_BASE,
                                    DOT11_CLIENT_PARENT_COL, parse_wifi_clients)
        rows = await self._snmp.walk(ip, f"{DOT11_CLIENT_BASE}.{DOT11_CLIENT_PARENT_COL}")
        macs = {canonical_mac(c["mac"]) for c in parse_wifi_clients(rows, {})}
        if not macs:
            counts = await self._snmp.walk(ip, DOT11_ACTIVE_CLIENTS_BASE)
            if not counts or any(str(v).strip() not in ("0", "") for _o, v in counts):
                raise RuntimeError("client list unreadable")
        return macs

    async def agents(self) -> list:
        """Every agent's id, status and lastKeepAlive from the Manager API.

        The blocking requests run in a daemon thread, so a pass that gives up
        on them (the time box) neither waits for them nor is kept alive by them.
        """
        loop = asyncio.get_running_loop()
        future = loop.create_future()
        source = self._agent_source
        if source is None:
            from .endpoints import WazuhSource
            source = WazuhSource()

        def settle(result, error):
            if not future.done():
                future.set_exception(error) if error else future.set_result(result)

        def work():
            try:
                result, error = source.agent_status(), None
            except Exception as e:
                result, error = None, e
            try:
                loop.call_soon_threadsafe(settle, result, error)
            except RuntimeError:
                pass                # the pass already finished and closed its loop

        threading.Thread(target=work, name="liveness-agents", daemon=True).start()
        return await future


# ---------------------------------------------------------------------------
# One pass (pure apart from the injected prober)
# ---------------------------------------------------------------------------

def _valid_ip(ip) -> bool:
    try:
        ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return False
    return True


def _parse_time(text) -> Optional[datetime]:
    if not isinstance(text, str):
        return None
    try:
        t = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def _agent_verdict(row: dict, now: datetime, max_age: float) -> tuple:
    """``(replied, down)`` for one Manager API agent row."""
    status = str(row.get("status") or "").lower()
    if status in AGENT_DOWN:
        return False, True
    if status != "active":
        return False, False
    if str(row.get("id")) == MANAGER_AGENT_ID:
        return True, False
    seen = _parse_time(row.get("lastKeepAlive"))
    return seen is not None and (now - seen).total_seconds() <= max_age, False


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


def _carry(old: dict, now: str) -> dict:
    """A fresh record carrying the fields that survive across passes."""
    rec = {
        "state": old.get("state") or "unknown",
        "method": old.get("method"),
        "misses": old.get("misses") if isinstance(old.get("misses"), int) else 0,
        "last_seen": old.get("last_seen"),
        "last_checked": now,
        "proven_methods": list(old.get("proven_methods") or []),   # a copy, never shared
    }
    if isinstance(old.get("port_down"), dict):
        rec["port_down"] = dict(old["port_down"])
    if isinstance(old.get("agent"), dict):
        rec["agent"] = dict(old["agent"])       # the last known check-in
    return rec


def _apply_probe(rec: dict, method: str, replied: bool, threshold: int, now: str,
                 down: bool = False) -> None:
    rec["method"] = method
    if replied:
        rec.update(state="active", misses=0, last_seen=now)
        if method not in rec["proven_methods"]:
            rec["proven_methods"].append(method)
    elif down:                  # the source says outright that it is gone
        rec["misses"] += 1
        rec["state"] = "inactive"
    elif method in rec["proven_methods"] or method in PROVEN_FROM_START:
        rec["misses"] += 1
        if rec["misses"] >= threshold:
            rec["state"] = "inactive"
    # silence on a never-proven method: nothing changes


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


_agent_max_age = _threshold     # whole seconds, at least 1


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
    parser.add_argument("--agent-max-age", type=_agent_max_age, default=AGENT_MAX_AGE_S,
                        metavar="SECONDS",
                        help="oldest Wazuh agent check-in that still counts as a reply")
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
    doc = asyncio.run(liveness_pass(graph, load_state(args.state), prober, args.threshold,
                                    agent_max_age=args.agent_max_age))
    sys.stdout.write(json.dumps(doc, indent=2) + "\n")
    sys.stdout.flush()
    counts = defaultdict(int)
    for rec in doc["nodes"].values():
        counts[rec["state"]] += 1
    log.info("liveness pass: %d node(s): %s", len(doc["nodes"]),
             ", ".join(f"{k} {v}" for k, v in sorted(counts.items())) or "none")
    if doc["rescan_suggested"]:
        log.info("rescan suggested: %s", "; ".join(doc["rescan_reasons"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
