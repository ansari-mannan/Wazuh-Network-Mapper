"""One liveness pass over graph.json (``LivenessMonitor``): probe every node
by its best method, read the switch ports and access point client lists,
and work out each node's new state. Pure apart from its prober.
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

from ..schema import CONF_WIFI, EDGE_ENDPOINT_LINK, ROLE_ACCESS_POINT, canonical_mac
from .prober import ProbeUnavailable
from .records import (AGENT_MAX_AGE_S, MANAGER_AGENT_ID, _agent_verdict, _apply_probe, _carry,
                      _parse_time, _valid_ip)

log = logging.getLogger("vulnmapper.liveness")

# Probe method per node
#   * endpoint with an ``agent_id``, Wazuh credentials available -> ``agent``:
#     one Manager API request per pass lists every agent's status and
#     lastKeepAlive. Active with a check-in no older than ``--agent-max-age``
#     seconds is a reply (agent 000, the manager, always is); active with an
#     older check-in is a miss; disconnected / pending / never_connected makes
#     the node inactive at once. If the login or request fails or takes longer
#     than 5 s, these nodes are left as they were for the pass.
#   * pollable device with an IP, SNMP credentials available -> ``snmp``
#     (a credential that resolves is a reply; a failure is "snmp, no reply")
#   * any other node with an IP (endpoints, devices without credentials or not
#     pollable) -> ``icmp``: one ping with a one-second wait (prober.ping_argv,
#     per OS and address family), exit 0 is a reply; without a ping binary
#     the node is left as it was (reason ``icmp_unavailable``)
#   * no IP, an invalid IP, or an IP shared by more than one non-stale node -> no
#     probe (state ``unknown``, method null)
#
# State rules per node: a reply makes it ``active`` (misses 0, ``last_seen`` now,
# method proven). Silence on a proven method adds a miss and, at ``threshold``
# misses, makes it ``inactive``; below that the state is unchanged. Silence on a
# never-proven method proves nothing (Windows blocks ping), so nothing changes;
# ``agent`` counts as proven from the start (a stale check-in is real evidence).
#
# Port layer: each pollable device that answered SNMP in this pass has its port
# status read with the crawler's ``collect_port_status``. An endpoint whose link
# to that device uses a port that is now ``down`` becomes ``inactive`` at once
# with method ``port``, and ``port_down.since`` records when that port was first
# seen down. A ping or SNMP reply in the same pass still wins. An agent check-in
# is a stored time, not a live reply: on a down port it counts only if
# ``lastKeepAlive`` is later than ``since`` (the machine reconnected some other
# way). The node gets its earlier state back once the port is up again or a new
# scan places it elsewhere. An ``up`` port never makes a node active by itself.
#
# Rescan suggestion: the port states are remembered between passes (``ports``).
# A pass sets ``rescan_suggested`` (with short ``rescan_reasons``) when a port
# went from down to up and no graph edge uses that port, or when the Manager
# API lists an active agent (other than 000) that is not in the graph. A port
# coming back up for a node already linked there is recovery, not a reason. The
# suggestion stands until a new scan replaces the graph (``graph_scan_time``).

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


class LivenessMonitor:
    """Re-checks whether the nodes of a graph still answer, one pass at a time.

    It holds what carries over from one pass to the next: the last state
    document (each node's record, and the port states it remembered), the
    miss threshold, the rules for a Wazuh agent's check-in, and the prober
    (``SystemProber`` unless a test hands it another). ``check`` runs a pass,
    returns the new state document and keeps it for the next pass.
    """

    def __init__(self, prober=None, threshold: int = DEFAULT_THRESHOLD,
                 previous: Optional[dict] = None, *, agent_max_age: float = AGENT_MAX_AGE_S,
                 agent_timeout: float = AGENT_TIMEOUT_S) -> None:
        if prober is None:
            from ..network.config import load_credentials
            from .prober import SystemProber
            prober = SystemProber(load_credentials(None))
        self.prober = prober
        self.threshold = threshold
        self.agent_max_age = agent_max_age
        self.agent_timeout = agent_timeout
        self.state: dict = previous if isinstance(previous, dict) else {}

    @property
    def ports(self) -> dict:
        """The port states remembered from the last pass, by device."""
        ports = self.state.get("ports")
        return ports if isinstance(ports, dict) else {}

    async def check(self, graph: dict, now: Optional[str] = None) -> dict:
        """One pass over ``graph`` (neither it nor the carried state is changed
        in place). Returns the new state document."""
        self._begin(graph, now or datetime.now(timezone.utc).isoformat())
        # one Manager API request for the whole pass, alongside the probes
        agent_task = asyncio.ensure_future(_fetch_agents(self.prober, self.agent_timeout)) \
            if self._use_agents else None
        self._plan()
        await self._probe()
        agent_rows, agent_error = (await agent_task) if agent_task else ({}, None)
        if agent_error:
            log.warning("%s; agent endpoints left unchanged this pass", agent_error)
        await self._read_links()
        self._apply_agents(agent_rows)
        self._apply_wifi()
        await self._confirm_by_mac_table()
        self._recover_links()
        self._mark_links_down()

        ports_now, reasons = self._port_memory_and_rescan(agent_rows)
        doc = {"checked_at": self._now, "threshold": self.threshold, "nodes": self._records,
               "ports": ports_now, "graph_scan_time": _scan_time(graph),
               "rescan_suggested": bool(reasons), "rescan_reasons": reasons}
        if agent_error:
            doc["agent_error"] = agent_error
        self.state = doc
        return doc

    # ---- setting up a pass ----------------------------------------------------

    def _begin(self, graph: dict, now: str) -> None:
        self._graph = graph
        self._now = now
        self._use_agents = bool(getattr(self.prober, "has_agents", False))
        old_nodes = self.state.get("nodes")
        self._old_nodes = old_nodes if isinstance(old_nodes, dict) else {}
        self._nodes = [n for n in graph.get("nodes") or []
                       if isinstance(n, dict) and n.get("node_id")]
        self._by_id: dict = {}
        for node in self._nodes:
            self._by_id.setdefault(node["node_id"], node)
        self._mac_of = {n["node_id"]: canonical_mac(n.get("mac")) for n in self._nodes}
        self._shared = self._shared_addresses()
        self._link_of = self._links()
        # Access points whose client list can be read this pass (SNMP, an address).
        self._access_points = {n["node_id"]: n for n in self._nodes
                               if n.get("role") == ROLE_ACCESS_POINT and n.get("pollable")
                               and _valid_ip(n.get("ip")) and self.prober.has_snmp}
        self._records: dict = {}
        self._had_state: set = set()     # nodes that had a state before this pass
        self._replied_now: set = set()
        self._snmp_up: list = []         # devices that answered SNMP this pass
        self._statuses: dict = {}        # device -> port states read this pass
        self._present: dict = {}         # access point -> client MACs read this pass

    def _shared_addresses(self) -> set:
        """Nodes not to probe by address: a stale node steps aside for a live
        one on the same IP, and an IP still shared is probed for nobody."""
        by_ip: dict = defaultdict(list)
        for node in self._nodes:
            if _valid_ip(node.get("ip")):
                by_ip[node["ip"]].append(node)
        shared: set = set()
        for group in by_ip.values():
            if len(group) < 2:
                continue
            live = [n for n in group if not n.get("stale")]
            shared.update(n["node_id"] for n in group if n.get("stale") or len(live) > 1)
        return shared

    def _links(self) -> dict:
        """Each endpoint's link: (device, port) for a wired one, (access point,
        WIFI_LINK) for a Wi-Fi client."""
        link_of: dict = {}
        for edge in self._graph.get("edges") or []:
            if not isinstance(edge, dict) or edge.get("type") != EDGE_ENDPOINT_LINK:
                continue
            if edge.get("confidence") == CONF_WIFI:
                link_of.setdefault(edge.get("source"), (edge.get("target"), WIFI_LINK))
            elif edge.get("local_port"):
                link_of.setdefault(edge.get("source"), (edge.get("target"), edge["local_port"]))
        return link_of

    def _on_wifi(self, nid: str) -> Optional[str]:
        """The access point a node is a Wi-Fi client of, if its list is readable."""
        here = self._link_of.get(nid)
        if here and here[1] == WIFI_LINK and here[0] in self._access_points \
                and self._mac_of.get(nid):
            return here[0]
        return None

    def _plan(self) -> None:
        """Carry each node's record forward and pick how it is checked: by its
        agent's check-in, by its access point's client list, or by a probe."""
        self._to_probe: list = []
        self._by_agent: list = []        # endpoints checked by agent check-in
        self._by_wifi: list = []         # other Wi-Fi clients: checked by the AP's list
        for node in self._nodes:
            nid = node["node_id"]
            old = self._old_nodes.get(nid)
            old = old if isinstance(old, dict) else {}
            rec = _carry(old, self._now)
            self._records[nid] = rec
            if old.get("state"):
                self._had_state.add(nid)
            if self._use_agents and node.get("kind") == "endpoint" and node.get("agent_id"):
                self._by_agent.append(node)        # identified by agent id, not by address
                continue
            if self._on_wifi(nid):
                self._by_wifi.append(node)         # identified by MAC, in place of ping
                continue
            # A node made inactive by a down port stays so until the port layer
            # restores it, even when it cannot be probed.
            unprobed = {} if "port_down" in rec else {"state": "unknown", "method": None}
            if nid in self._shared:
                rec.update(unprobed, reason="shared_ip")
            elif not node.get("ip"):
                rec.update(unprobed)
            elif not _valid_ip(node["ip"]):
                log.warning("%s: invalid IP in graph; not probed", nid)
                rec.update(unprobed, reason="invalid_ip")
            else:
                self._to_probe.append((node, _method_for(node, self.prober.has_snmp)))
        self._probed_by = {node["node_id"]: method for node, method in self._to_probe}
        self._probed_by.update((node["node_id"], "agent") for node in self._by_agent)
        self._probed_by.update((node["node_id"], "wifi") for node in self._by_wifi)

    # ---- the evidence -----------------------------------------------------------

    def _settle(self, node: dict, method: str, replied, down: bool = False,
                live: bool = True) -> None:
        """Apply one method's verdict. A ``live`` reply (the host itself
        answered) also overrides a down port this pass; a MAC-table entry is
        not live, so a down port still wins over it."""
        rec = self._records[node["node_id"]]
        if replied and live:
            rec.pop("port_down", None)
        elif "port_down" in rec:
            return          # the down port explains the silence
        _apply_probe(rec, method, bool(replied), self.threshold, self._now, down)
        if replied and live:
            self._replied_now.add(node["node_id"])
            if method == "snmp":
                self._snmp_up.append(node)

    async def _probe(self) -> None:
        """Ping or SNMP every node due a probe, at most MAX_IN_FLIGHT at once."""
        semaphore = asyncio.Semaphore(MAX_IN_FLIGHT)
        prober = self.prober

        async def probe(node, method):
            async with semaphore:
                try:
                    fn = prober.snmp if method == "snmp" else prober.icmp
                    return node, method, await fn(node["ip"]), None
                except Exception as e:          # one node must not abort the pass
                    return node, method, None, e

        for node, method, replied, error in await asyncio.gather(
                *(probe(n, m) for n, m in self._to_probe)):
            if isinstance(error, ProbeUnavailable):   # logged once by the prober
                self._records[node["node_id"]].update(method=method, reason="icmp_unavailable")
                continue
            if error is not None:
                log.warning("%s: %s probe failed: %s", node["node_id"], method, error)
                self._records[node["node_id"]].update(method=method, reason="probe_error")
                continue
            self._settle(node, method, replied)

    async def _read_links(self) -> None:
        """The port states of every device that answered SNMP (a new host can
        turn up on any port, linked or not), and the client list of every
        access point among them, once per pass."""
        prober = self.prober

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

        statuses, lists = await asyncio.gather(
            asyncio.gather(*(ports(d) for d in self._snmp_up)),
            asyncio.gather(*(client_list(d) for d in self._snmp_up
                             if d["node_id"] in self._access_points)))
        self._statuses = {dev: st for dev, st in statuses if isinstance(st, dict)}
        self._present = {ap: {canonical_mac(m) for m in macs} - {None}
                         for ap, macs in lists if macs is not None}

    def _link_state(self, nid: str):
        """``(link, "up" | "down" | None)``; None when it was not read this pass."""
        here = self._link_of.get(nid)
        if here is None:
            return None, None
        device, port = here
        if port == WIFI_LINK:
            if device not in self._present:
                return here, None
            return here, "up" if self._mac_of.get(nid) in self._present[device] else "down"
        return here, self._statuses[device].get(port) if device in self._statuses else None

    def _down_since(self, nid: str, rec: dict) -> Optional[str]:
        """When the node's link went down (port down, or gone from its AP's
        client list); None if it is not down.

        Read down now: since its first observation (this pass if new). Not read
        (the switch or AP did not answer) but already marked down: still down.
        """
        here, state = self._link_state(nid)
        if here is None:
            return None
        mark = rec.get("port_down")
        marked_here = isinstance(mark, dict) and (mark.get("device"), mark.get("port")) == here
        if state == "down" or (state is None and marked_here):
            # a mark from before "since" existed: first observed now (strict)
            return (mark.get("since") if marked_here else None) or self._now
        return None

    def _apply_agents(self, agent_rows: Optional[dict]) -> None:
        """Agent check-ins. If the Manager API could not be read, these nodes
        keep the state they had: no falling back to ping, which Windows hosts
        would not answer."""
        now_dt = _parse_time(self._now) or datetime.now(timezone.utc)
        for node in self._by_agent:
            rec = self._records[node["node_id"]]
            row = agent_rows.get(str(node["agent_id"])) if agent_rows is not None else None
            if row is None:
                rec["reason"] = "agent_unavailable" if agent_rows is None else "agent_not_listed"
                continue
            rec["agent"] = {"status": row.get("status"), "last_keepalive": row.get("lastKeepAlive")}
            replied, down = _agent_verdict(row, now_dt, self.agent_max_age)
            since = self._down_since(node["node_id"], rec) if replied else None
            if since is not None:
                seen, went_down = _parse_time(row.get("lastKeepAlive")), _parse_time(since)
                if seen is None or went_down is None or seen <= went_down:
                    continue    # checked in before the port went down: the port decides
            self._settle(node, "agent", replied, down)

    def _apply_wifi(self) -> None:
        """A node in its access point's client list replied (agent or not); one
        missing from it is handled with the down ports."""
        by_wifi = {n["node_id"] for n in self._by_wifi}
        for nid, rec in self._records.items():
            here, state = self._link_state(nid)
            if here is None or here[1] != WIFI_LINK:
                continue
            if state == "up":
                self._settle(self._by_id[nid], "wifi", True)
            elif state is None and nid in by_wifi:
                rec["reason"] = "wifi_unavailable"

    async def _confirm_by_mac_table(self) -> None:
        """A wired host no faster method has proven, on a switch that answered
        SNMP this pass, is looked up in that switch's forwarding table."""
        switches = {d["node_id"]: d for d in self._snmp_up}
        agent_ids = {n["node_id"] for n in self._by_agent}
        by_switch: dict = defaultdict(list)
        for node in self._nodes:
            nid = node["node_id"]
            rec = self._records[nid]
            here = self._link_of.get(nid)
            if node.get("kind") != "endpoint" or nid in agent_ids or nid in self._replied_now \
                    or "port_down" in rec or not self._mac_of.get(nid) or here is None \
                    or here[1] == WIFI_LINK or here[0] not in switches \
                    or set(rec["proven_methods"]) & FAST_METHODS:
                continue
            vlan = node.get("vlan") if isinstance(node.get("vlan"), int) else None
            by_switch[here[0]].append((node, (vlan, self._mac_of[nid]), here[1]))

        prober = self.prober

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
                    self._records[node["node_id"]]["reason"] = "mac_table_unavailable"
                else:
                    self._settle(node, "mac-table", found.get(entry) == port, live=False)

    def _recover_links(self) -> None:
        """The port that went down is up again, or a new scan placed the node
        elsewhere. Its earlier state comes back (an up port never makes a node
        active by itself); misses restart from 0."""
        for nid, rec in self._records.items():
            down = rec.get("port_down")
            if not down:
                continue
            where = (down.get("device"), down.get("port"))
            here, state = self._link_state(nid)
            if here != where or state == "up":
                del rec["port_down"]
                rec.update(state=down.get("previous_state") or "unknown", misses=0,
                           method=self._probed_by.get(nid))

    def _mark_links_down(self) -> None:
        """A link that is down now (port down, or gone from the AP's client
        list): inactive at once, remembering the state before."""
        for nid, rec in self._records.items():
            here, state = self._link_state(nid)
            if state != "down" or nid in self._replied_now:
                continue
            mark = rec.get("port_down")
            if not mark or (mark.get("device"), mark.get("port")) != here:
                rec["port_down"] = {"device": here[0], "port": here[1],
                                    "previous_state": rec["state"] if nid in self._had_state
                                    or rec["state"] != "unknown" else None,
                                    "since": self._now}
            elif not mark.get("since"):
                mark["since"] = self._now       # a mark written before "since" existed
            rec.update(state="inactive", method=CONF_WIFI if here[1] == WIFI_LINK else "port")

    # ---- what the pass leaves behind --------------------------------------------

    def _port_memory_and_rescan(self, agent_rows: Optional[dict]) -> tuple:
        """``(ports to remember, rescan reasons)`` for the end of a pass."""
        nodes, previous = self._nodes, self.state
        names = {n["node_id"]: n.get("hostname") or n["node_id"]
                 for n in nodes if n.get("kind") == "device"}
        old_ports = self.ports
        remembered: dict = {}
        for dev in names:       # a device that did not answer keeps what it had
            if dev in self._statuses:
                remembered[dev] = dict(self._statuses[dev])
            elif isinstance(old_ports.get(dev), dict):
                remembered[dev] = dict(old_ports[dev])

        reasons: list = []
        linked = _linked_ports(self._graph)
        for dev, now_ports in self._statuses.items():
            before = old_ports.get(dev) if isinstance(old_ports.get(dev), dict) else {}
            for port, state in now_ports.items():
                if state == "up" and before.get(port) == "down" and port not in linked[dev]:
                    reasons.append(f"port {port} on {names.get(dev, dev)} came up with "
                                   "nothing linked to it")
        known_macs = {canonical_mac(n.get("mac")) for n in nodes} - {None}
        for ap, macs in self._present.items():
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
        if previous.get("graph_scan_time") == _scan_time(self._graph) \
                and isinstance(previous.get("rescan_reasons"), list):
            reasons = [r for r in previous["rescan_reasons"] if isinstance(r, str)] + reasons
        return remembered, list(dict.fromkeys(reasons))[:MAX_RESCAN_REASONS]


async def liveness_pass(graph: dict, previous: dict, prober, threshold: int,
                        now: Optional[str] = None, agent_max_age: float = AGENT_MAX_AGE_S,
                        agent_timeout: float = AGENT_TIMEOUT_S) -> dict:
    """One pass with a fresh monitor: the new state document from ``graph`` and
    the ``previous`` one ({} when there is none). The inputs are not modified."""
    monitor = LivenessMonitor(prober, threshold, previous, agent_max_age=agent_max_age,
                              agent_timeout=agent_timeout)
    return await monitor.check(graph, now)
