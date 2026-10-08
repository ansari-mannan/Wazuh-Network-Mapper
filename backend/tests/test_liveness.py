"""Liveness heartbeat: one pass over graph.json with injected (fake) probers.

No network access: every probe goes through FakeProber.
"""

import asyncio
import contextlib
import copy
import io
import json
import os
import tempfile
import time
import unittest
from unittest import mock

from vulnmapper.endpoints import WazuhSource
from vulnmapper.liveness import SystemProber, liveness_pass, load_state, main
from vulnmapper.schema import WazuhConfig

T0 = "2026-10-07T09:00:00+00:00"
T1 = "2026-10-07T09:00:20+00:00"


class FakeProber:
    """Answers from tables; records every probe. ``boom`` IPs raise."""

    def __init__(self, icmp=None, snmp=None, ports=None, has_snmp=True, boom=(),
                 agents=None, agent_error=None, agent_delay=0.0, wifi=None, mac_tables=None):
        self.icmp_replies = icmp or {}
        self.snmp_replies = snmp or {}
        self.ports = ports or {}
        self.has_snmp = has_snmp
        self.boom = set(boom)
        # Manager API agent list: None = no Wazuh credentials (no agent method)
        self.has_agents = agents is not None or agent_error is not None
        self.agent_list = agents or []
        self.agent_error = agent_error
        self.agent_delay = agent_delay
        # access point IP -> the client MACs it lists (an exception is raised)
        self.wifi = wifi or {}
        # switch IP -> {(vlan, mac): port} answered by a MAC-table lookup, or an
        # exception to raise, or a delay in seconds (float) before answering
        self.mac_tables = mac_tables or {}
        self.calls = []
        self.in_flight = 0
        self.max_in_flight = 0

    async def _probe(self, kind, ip, table):
        self.calls.append((kind, ip))
        self.in_flight += 1
        self.max_in_flight = max(self.max_in_flight, self.in_flight)
        try:
            await asyncio.sleep(0)
            if ip in self.boom:
                raise OSError("probe exploded")
            return table.get(ip, False)
        finally:
            self.in_flight -= 1

    async def icmp(self, ip):
        return await self._probe("icmp", ip, self.icmp_replies)

    async def snmp(self, ip):
        return await self._probe("snmp", ip, self.snmp_replies)

    async def port_status(self, ip):
        self.calls.append(("ports", ip))
        return self.ports.get(ip, {})

    async def wifi_clients(self, ip):
        self.calls.append(("wifi", ip))
        answer = self.wifi.get(ip, set())
        if isinstance(answer, Exception):
            raise answer
        return set(answer)

    async def mac_lookup(self, ip, entries, per_vlan_context=False):
        """``entries`` = [(vlan, mac)] -> {(vlan, mac): port or None}."""
        self.calls.append(("mac_lookup", ip, tuple(entries), per_vlan_context))
        table = self.mac_tables.get(ip, {})
        if isinstance(table, Exception):
            raise table
        if isinstance(table, float):
            await asyncio.sleep(table)
            table = {}
        return {e: table.get(e) for e in entries}

    async def agents(self):
        self.calls.append(("agents",))
        await asyncio.sleep(self.agent_delay)
        if self.agent_error is not None:
            raise self.agent_error
        return self.agent_list


def host(node_id, ip, kind="endpoint", **extra):
    return {"node_id": node_id, "kind": kind, "ip": ip,
            "discovery_method": "snmp_fdb" if kind == "endpoint" else "snmp_lldp", **extra}


def switch(node_id="device:sw", ip="10.0.0.2", pollable=True):
    return host(node_id, ip, kind="device", pollable=pollable)


def graph(*nodes, edges=()):
    return {"nodes": list(nodes), "edges": list(edges), "metadata": {}}


def link(source, target, port):
    return {"source": source, "target": target, "type": "endpoint_link", "local_port": port}


def run(g, previous=None, prober=None, threshold=3, now=T1, **kw):
    return asyncio.run(liveness_pass(g, previous or {}, prober or FakeProber(), threshold,
                                     now=now, **kw))


def prev(**nodes):
    return {"checked_at": T0, "threshold": 3, "nodes": nodes}


def was(state, misses=0, proven=("icmp",), method="icmp", last_seen=T0):
    return {"state": state, "method": method, "misses": misses, "last_seen": last_seen,
            "last_checked": T0, "proven_methods": list(proven)}


H = host("host:a", "10.0.0.10")


class TestStateRules(unittest.TestCase):
    def test_reply_makes_active_resets_misses_records_method(self):
        doc = run(graph(H), prev(**{"host:a": was("active", misses=2)}),
                  FakeProber(icmp={"10.0.0.10": True}))
        node = doc["nodes"]["host:a"]
        self.assertEqual(node, {"state": "active", "method": "icmp", "misses": 0,
                                "last_seen": T1, "last_checked": T1,
                                "proven_methods": ["icmp"]})

    def test_first_reply_proves_the_method(self):
        doc = run(graph(H), prober=FakeProber(icmp={"10.0.0.10": True}))
        self.assertEqual(doc["nodes"]["host:a"]["proven_methods"], ["icmp"])

    def test_proven_method_two_misses_still_active_third_inactive(self):
        state = prev(**{"host:a": was("active")})
        for expected_misses, expected_state in ((1, "active"), (2, "active"), (3, "inactive")):
            state = run(graph(H), state)
            node = state["nodes"]["host:a"]
            self.assertEqual((node["misses"], node["state"]), (expected_misses, expected_state))
        self.assertEqual(node["last_seen"], T0)          # survives the misses

    def test_below_threshold_state_does_not_change(self):
        # proven by icmp but currently unknown (e.g. was shared): a miss below
        # the threshold must not invent "active"
        doc = run(graph(H), prev(**{"host:a": was("unknown")}))
        self.assertEqual(doc["nodes"]["host:a"]["state"], "unknown")
        self.assertEqual(doc["nodes"]["host:a"]["misses"], 1)

    def test_never_proven_method_any_misses_stays_unknown(self):
        state = {}
        for _ in range(6):
            state = run(graph(H), state)
        node = state["nodes"]["host:a"]
        self.assertEqual((node["state"], node["misses"], node["proven_methods"]),
                         ("unknown", 0, []))
        self.assertEqual(node["method"], "icmp")

    def test_never_proven_silence_keeps_previous_state(self):
        doc = run(graph(H), prev(**{"host:a": was("active", proven=())}))
        self.assertEqual(doc["nodes"]["host:a"]["state"], "active")

    def test_inactive_node_replies_again(self):
        doc = run(graph(H), prev(**{"host:a": was("inactive", misses=5)}),
                  FakeProber(icmp={"10.0.0.10": True}))
        self.assertEqual((doc["nodes"]["host:a"]["state"], doc["nodes"]["host:a"]["misses"]),
                         ("active", 0))

    def test_device_proven_by_snmp_then_icmp_silence_not_inactive(self):
        sw = switch()
        state = prev(**{"device:sw": was("active", misses=2, proven=("snmp",), method="snmp")})
        doc = run(graph(sw), state, FakeProber(has_snmp=False))
        node = doc["nodes"]["device:sw"]
        self.assertEqual((node["state"], node["method"], node["misses"]), ("active", "icmp", 2))

    def test_previous_state_not_mutated(self):
        state = prev(**{"host:a": was("active", proven=("snmp",))})
        snapshot = copy.deepcopy(state)
        run(graph(H), state, FakeProber(icmp={"10.0.0.10": True}))
        self.assertEqual(state, snapshot)

    def test_node_removed_from_graph_dropped(self):
        doc = run(graph(H), prev(**{"host:a": was("active"), "host:gone": was("active")}))
        self.assertEqual(list(doc["nodes"]), ["host:a"])

    def test_output_document_shape(self):
        doc = run(graph(H), threshold=4)
        self.assertEqual(set(doc), {"checked_at", "threshold", "nodes", "ports",
                                    "graph_scan_time", "rescan_suggested", "rescan_reasons"})
        self.assertEqual((doc["checked_at"], doc["threshold"]), (T1, 4))
        self.assertEqual((doc["rescan_suggested"], doc["rescan_reasons"]), (False, []))


class TestNoProbe(unittest.TestCase):
    def test_no_ip_unknown_no_probe(self):
        prober = FakeProber()
        doc = run(graph(host("device:hamza", None, kind="device", pollable=False)),
                  prev(**{"device:hamza": was("active")}), prober)
        node = doc["nodes"]["device:hamza"]
        self.assertEqual((node["state"], node["method"]), ("unknown", None))
        self.assertEqual(node["proven_methods"], ["icmp"])   # survives
        self.assertEqual(node["last_seen"], T0)
        self.assertEqual(prober.calls, [])

    def test_invalid_ip_not_probed_no_exception(self):
        prober = FakeProber()
        doc = run(graph(host("host:bad", "10.0.0.999"), host("host:cmd", "1.2.3.4; rm -rf /")),
                  prober=prober)
        for nid in ("host:bad", "host:cmd"):
            self.assertEqual((doc["nodes"][nid]["state"], doc["nodes"][nid]["method"]),
                             ("unknown", None))
        self.assertEqual(prober.calls, [])


class TestSharedIp(unittest.TestCase):
    def test_stale_node_skipped_the_other_probed(self):
        prober = FakeProber(icmp={"10.0.0.20": True})
        doc = run(graph(host("endpoint:new", "10.0.0.20", kind="endpoint", stale=False),
                        host("endpoint:old", "10.0.0.20", kind="endpoint", stale=True)),
                  prober=prober)
        self.assertEqual(doc["nodes"]["endpoint:new"]["state"], "active")
        self.assertEqual(doc["nodes"]["endpoint:old"]["state"], "unknown")
        self.assertEqual(prober.calls, [("icmp", "10.0.0.20")])

    def test_two_non_stale_both_unknown_shared_ip(self):
        prober = FakeProber(icmp={"10.0.0.30": True})
        doc = run(graph(host("endpoint:001", "10.0.0.30"), host("host:x", "10.0.0.30")),
                  prev(**{"endpoint:001": was("active")}), prober)
        for nid in ("endpoint:001", "host:x"):
            node = doc["nodes"][nid]
            self.assertEqual((node["state"], node["method"], node["reason"]),
                             ("unknown", None, "shared_ip"))
        self.assertEqual(prober.calls, [])

    def test_reason_cleared_once_no_longer_shared(self):
        state = prev(**{"host:a": dict(was("unknown"), reason="shared_ip")})
        doc = run(graph(H), state, FakeProber(icmp={"10.0.0.10": True}))
        self.assertNotIn("reason", doc["nodes"]["host:a"])


class TestMethodChoice(unittest.TestCase):
    def test_pollable_device_with_credentials_probed_by_snmp(self):
        prober = FakeProber(snmp={"10.0.0.2": True})
        doc = run(graph(switch()), prober=prober)
        self.assertEqual(doc["nodes"]["device:sw"]["method"], "snmp")
        self.assertEqual(doc["nodes"]["device:sw"]["state"], "active")
        self.assertNotIn(("icmp", "10.0.0.2"), prober.calls)

    def test_failed_snmp_is_snmp_no_reply_never_falls_back_to_ping(self):
        # A dead switch that never answered ping must still go inactive.
        state = prev(**{"device:sw": was("active", proven=("snmp",), method="snmp")})
        prober = FakeProber(icmp={"10.0.0.2": True})     # ping would (wrongly) save it
        for _ in range(3):
            state = run(graph(switch()), state, prober)
        node = state["nodes"]["device:sw"]
        self.assertEqual((node["method"], node["state"], node["misses"]), ("snmp", "inactive", 3))
        self.assertNotIn(("icmp", "10.0.0.2"), prober.calls)

    def test_without_credentials_device_probed_by_ping(self):
        prober = FakeProber(icmp={"10.0.0.2": True}, has_snmp=False)
        doc = run(graph(switch()), prober=prober)
        self.assertEqual(doc["nodes"]["device:sw"]["method"], "icmp")
        self.assertEqual(prober.calls, [("icmp", "10.0.0.2")])

    def test_non_pollable_device_with_ip_probed_by_ping(self):
        prober = FakeProber()
        run(graph(switch(pollable=False)), prober=prober)
        self.assertEqual(prober.calls, [("icmp", "10.0.0.2")])

    def test_endpoint_probed_by_ping(self):
        prober = FakeProber()
        run(graph(H), prober=prober)
        self.assertEqual(prober.calls, [("icmp", "10.0.0.10")])


class TestPortDown(unittest.TestCase):
    """Phase 4: an endpoint on a port that is now down is inactive at once."""

    PC = host("endpoint:pc", "10.0.0.50", discovery_method="wazuh")
    PHONE = host("host:phone", "10.0.0.51")

    def g(self, port="Gi1/0/5"):
        return graph(switch(), self.PC, self.PHONE,
                     edges=[link("endpoint:pc", "device:sw", port),
                            link("host:phone", "device:sw", "Gi1/0/9"),
                            {"source": "device:sw", "target": "device:core", "type": "lldp",
                             "local_port": "Gi1/0/5"}])

    def test_port_down_marks_endpoint_inactive_immediately(self):
        prober = FakeProber(snmp={"10.0.0.2": True}, ports={"10.0.0.2": {"Gi1/0/5": "down",
                                                                        "Gi1/0/9": "up"}})
        doc = run(self.g(), prober=prober)
        pc = doc["nodes"]["endpoint:pc"]
        self.assertEqual((pc["state"], pc["method"]), ("inactive", "port"))
        self.assertEqual(pc["misses"], 0)
        self.assertEqual(pc["proven_methods"], [])
        self.assertIn(("ports", "10.0.0.2"), prober.calls)

    def test_port_up_changes_nothing(self):
        prober = FakeProber(snmp={"10.0.0.2": True}, ports={"10.0.0.2": {"Gi1/0/9": "up"}})
        doc = run(self.g(), prev(**{"host:phone": was("active", misses=1)}), prober)
        phone = doc["nodes"]["host:phone"]
        self.assertEqual((phone["state"], phone["method"], phone["misses"]),
                         ("active", "icmp", 2))

    def test_port_up_does_not_revive_inactive(self):
        prober = FakeProber(snmp={"10.0.0.2": True}, ports={"10.0.0.2": {"Gi1/0/9": "up"}})
        doc = run(self.g(), prev(**{"host:phone": was("inactive", misses=4)}), prober)
        self.assertEqual(doc["nodes"]["host:phone"]["state"], "inactive")

    def test_ports_only_read_from_devices_that_answered_snmp(self):
        prober = FakeProber(snmp={"10.0.0.2": False}, ports={"10.0.0.2": {"Gi1/0/5": "down"}})
        doc = run(self.g(), prober=prober)
        self.assertNotIn(("ports", "10.0.0.2"), prober.calls)
        self.assertEqual(doc["nodes"]["endpoint:pc"]["state"], "unknown")

    def test_reply_this_pass_beats_a_down_port(self):
        # the graph's port is stale (the host moved); a reply is direct proof
        prober = FakeProber(snmp={"10.0.0.2": True}, icmp={"10.0.0.50": True},
                            ports={"10.0.0.2": {"Gi1/0/5": "down"}})
        doc = run(self.g(), prober=prober)
        self.assertEqual(doc["nodes"]["endpoint:pc"]["state"], "active")

    def test_port_down_applies_to_endpoint_without_ip(self):
        g = graph(switch(), host("host:noip", None),
                  edges=[link("host:noip", "device:sw", "Gi1/0/7")])
        prober = FakeProber(snmp={"10.0.0.2": True}, ports={"10.0.0.2": {"Gi1/0/7": "down"}})
        node = run(g, prober=prober)["nodes"]["host:noip"]
        self.assertEqual((node["state"], node["method"]), ("inactive", "port"))

    def test_port_status_failure_ignored(self):
        class Broken(FakeProber):
            async def port_status(self, ip):
                raise OSError("walk failed")
        doc = run(self.g(), prober=Broken(snmp={"10.0.0.2": True}))
        self.assertEqual(doc["nodes"]["device:sw"]["state"], "active")
        self.assertEqual(doc["nodes"]["endpoint:pc"]["state"], "unknown")


class TestPortRecovery(unittest.TestCase):
    """A node made inactive by a down port gets its earlier state back once the
    port is up again or a new scan places it elsewhere."""

    SW_UP = {"10.0.0.2": True}

    def g(self, port="Gi1/0/5", target="device:sw", extra=()):
        return graph(switch(), switch("device:sw2", "10.0.0.3"),
                     host("endpoint:pc", "10.0.0.50", discovery_method="wazuh"), *extra,
                     edges=[link("endpoint:pc", target, port)])

    def passes(self, state, *port_states, graphs=None, snmp=None):
        for i, ports in enumerate(port_states):
            prober = FakeProber(snmp=snmp or self.SW_UP, ports={"10.0.0.2": ports})
            state = run((graphs or [self.g()] * len(port_states))[i], state, prober)
        return state["nodes"]["endpoint:pc"], state

    def test_ping_silent_host_returns_to_earlier_state_on_port_up(self):
        start = prev(**{"endpoint:pc": was("active", misses=1, proven=("icmp",))})
        node, state = self.passes(start, {"Gi1/0/5": "down"})
        self.assertEqual((node["state"], node["method"]), ("inactive", "port"))
        self.assertEqual(node["port_down"], {"device": "device:sw", "port": "Gi1/0/5",
                                             "previous_state": "active", "since": T1})
        node, state = self.passes(state, {"Gi1/0/5": "down"})       # still down
        self.assertEqual((node["state"], node["method"], node["misses"]),
                         ("inactive", "port", 2))
        node, _ = self.passes(state, {"Gi1/0/5": "up"})
        self.assertEqual((node["state"], node["misses"], node["proven_methods"]),
                         ("active", 0, ["icmp"]))
        self.assertNotIn("port_down", node)
        self.assertNotEqual(node["method"], "port")

    def test_no_earlier_state_returns_to_unknown(self):
        node, state = self.passes({}, {"Gi1/0/5": "down"})
        self.assertEqual(node["port_down"]["previous_state"], None)
        node, _ = self.passes(state, {"Gi1/0/5": "up"})
        self.assertEqual((node["state"], node["misses"]), ("unknown", 0))
        self.assertNotIn("port_down", node)

    def test_replaced_by_a_new_scan_is_restored(self):
        start = prev(**{"endpoint:pc": was("active", proven=("icmp",))})
        _, state = self.passes(start, {"Gi1/0/5": "down"})
        for moved in (self.g(port="Gi1/0/8"), self.g(target="device:sw2")):
            with self.subTest(moved=moved["edges"][0]):
                # the old port is still down, and sw2's ports are never read
                node, _ = self.passes(state, {"Gi1/0/5": "down", "Gi1/0/8": "up"},
                                      graphs=[moved])
                self.assertEqual((node["state"], node["misses"]), ("active", 0))
                self.assertNotIn("port_down", node)

    def test_replaced_onto_another_down_port_stays_inactive(self):
        start = prev(**{"endpoint:pc": was("active", proven=("icmp",))})
        _, state = self.passes(start, {"Gi1/0/5": "down"})
        node, _ = self.passes(state, {"Gi1/0/5": "down", "Gi1/0/8": "down"},
                              graphs=[self.g(port="Gi1/0/8")])
        self.assertEqual((node["state"], node["method"]), ("inactive", "port"))
        self.assertEqual(node["port_down"], {"device": "device:sw", "port": "Gi1/0/8",
                                             "previous_state": "active", "since": T1})

    def test_switch_not_answering_keeps_it_inactive(self):
        _, state = self.passes({}, {"Gi1/0/5": "down"})
        node, _ = self.passes(state, {"Gi1/0/5": "up"}, snmp={"10.0.0.2": False})
        self.assertEqual((node["state"], node["method"]), ("inactive", "port"))

    def test_reply_while_port_down_marks_active(self):
        _, state = self.passes({}, {"Gi1/0/5": "down"})
        prober = FakeProber(snmp=self.SW_UP, icmp={"10.0.0.50": True},
                            ports={"10.0.0.2": {"Gi1/0/5": "down"}})
        node = run(self.g(), state, prober)["nodes"]["endpoint:pc"]
        self.assertEqual((node["state"], node["method"]), ("active", "icmp"))
        self.assertNotIn("port_down", node)

    def test_up_port_never_promotes_unknown_to_active(self):
        node, state = self.passes({}, {"Gi1/0/5": "up"})
        self.assertEqual(node["state"], "unknown")
        _, state = self.passes(state, {"Gi1/0/5": "down"})
        node, state = self.passes(state, {"Gi1/0/5": "up"})        # restored: unknown
        node, _ = self.passes(state, {"Gi1/0/5": "up"})            # and it stays so
        self.assertEqual(node["state"], "unknown")


def agent(agent_id, status="active", keepalive="2026-10-07T09:00:12+00:00"):
    row = {"id": agent_id, "status": status}
    if keepalive is not None:
        row["lastKeepAlive"] = keepalive
    return row


def pc(agent_id="004", ip="10.0.0.60", **extra):
    return host(f"endpoint:{agent_id}", ip, discovery_method="wazuh", agent_id=agent_id, **extra)


FRESH = "2026-10-07T09:00:12+00:00"      # 8 s before T1
STALE = "2026-10-07T08:58:00+00:00"      # 140 s before T1


class TestAgentMethod(unittest.TestCase):
    """Item 4: endpoints with an agent_id are checked by Wazuh agent check-in."""

    def test_active_and_fresh_replied(self):
        prober = FakeProber(agents=[agent("004", keepalive=FRESH)])
        node = run(graph(pc()), prober=prober)["nodes"]["endpoint:004"]
        self.assertEqual((node["state"], node["method"], node["misses"], node["last_seen"]),
                         ("active", "agent", 0, T1))
        self.assertEqual(node["proven_methods"], ["agent"])
        self.assertEqual(node["agent"], {"status": "active", "last_keepalive": FRESH})

    def test_agent_endpoint_is_not_pinged(self):
        prober = FakeProber(agents=[agent("004")], icmp={"10.0.0.60": True})
        run(graph(pc(), H), prober=prober)
        self.assertNotIn(("icmp", "10.0.0.60"), prober.calls)
        self.assertIn(("icmp", "10.0.0.10"), prober.calls)        # the plain host still is
        self.assertEqual(prober.calls.count(("agents",)), 1)      # one request per pass

    def test_max_age_is_configurable(self):
        prober = FakeProber(agents=[agent("004", keepalive=STALE)])
        node = run(graph(pc()), prober=prober, agent_max_age=300)["nodes"]["endpoint:004"]
        self.assertEqual(node["state"], "active")

    def test_active_but_stale_is_a_miss_under_the_threshold(self):
        prober = FakeProber(agents=[agent("004", keepalive=STALE)])
        node = run(graph(pc()), prev(**{"endpoint:004": was("active", proven=(), method="agent")}),
                   prober)["nodes"]["endpoint:004"]
        self.assertEqual((node["state"], node["method"], node["misses"]), ("active", "agent", 1))
        self.assertEqual(node["last_seen"], T0)

    def test_active_but_stale_over_the_threshold_is_inactive(self):
        # "agent" counts as proven from the start: no earlier reply is needed
        prober = FakeProber(agents=[agent("004", keepalive=STALE)])
        state = {}
        for expected in ((1, "unknown"), (2, "unknown"), (3, "inactive")):
            state = run(graph(pc()), state, prober)
            node = state["nodes"]["endpoint:004"]
            self.assertEqual((node["misses"], node["state"]), expected)

    def test_disconnected_pending_never_connected_inactive_at_once(self):
        for status in ("disconnected", "pending", "never_connected"):
            with self.subTest(status=status):
                prober = FakeProber(agents=[agent("004", status=status,
                                                  keepalive=None if status == "never_connected"
                                                  else STALE)])
                node = run(graph(pc()), prev(**{"endpoint:004": was("active", proven=("agent",),
                                                                    method="agent")}),
                           prober)["nodes"]["endpoint:004"]
                self.assertEqual((node["state"], node["method"]), ("inactive", "agent"))
                self.assertEqual(node["agent"]["status"], status)

    def test_agent_000_far_future_keepalive_replied(self):
        prober = FakeProber(agents=[agent("000", keepalive="9999-12-31T23:59:59+00:00")])
        node = run(graph(pc("000", "10.0.0.1")), prober=prober)["nodes"]["endpoint:000"]
        self.assertEqual((node["state"], node["method"]), ("active", "agent"))

    def test_api_failure_leaves_agent_nodes_unchanged(self):
        before = prev(**{"endpoint:004": was("active", misses=1, proven=("agent",), method="agent"),
                         "host:a": was("active")})
        prober = FakeProber(agent_error=OSError("connection refused"), icmp={"10.0.0.10": True})
        doc = run(graph(pc(), H), before, prober)
        node = doc["nodes"]["endpoint:004"]
        self.assertEqual((node["state"], node["method"], node["misses"], node["last_seen"]),
                         ("active", "agent", 1, T0))
        self.assertEqual(node["reason"], "agent_unavailable")
        self.assertIn("connection refused", doc["agent_error"])
        self.assertNotIn(("icmp", "10.0.0.60"), prober.calls)     # no fallback to ping
        self.assertEqual(doc["nodes"]["host:a"]["state"], "active")

    def test_slow_login_is_time_boxed(self):
        before = prev(**{"endpoint:004": was("inactive", misses=3, proven=("agent",),
                                             method="agent")})
        prober = FakeProber(agents=[agent("004")], agent_delay=2.0)
        started = time.monotonic()
        doc = run(graph(pc()), before, prober, agent_timeout=0.2)
        self.assertLess(time.monotonic() - started, 1.5)
        node = doc["nodes"]["endpoint:004"]
        self.assertEqual((node["state"], node["misses"], node["reason"]),
                         ("inactive", 3, "agent_unavailable"))
        self.assertIn("timed out", doc["agent_error"])

    def test_no_credentials_falls_back_to_ping(self):
        prober = FakeProber(icmp={"10.0.0.60": True})          # has_agents False
        doc = run(graph(pc()), prober=prober)
        node = doc["nodes"]["endpoint:004"]
        self.assertEqual((node["state"], node["method"]), ("active", "icmp"))
        self.assertNotIn(("agents",), prober.calls)
        self.assertNotIn("agent_error", doc)

    def test_agent_not_listed_by_the_manager_unchanged(self):
        before = prev(**{"endpoint:004": was("active", proven=("agent",), method="agent")})
        doc = run(graph(pc()), before, FakeProber(agents=[agent("009")]))
        node = doc["nodes"]["endpoint:004"]
        self.assertEqual((node["state"], node["misses"], node["reason"]),
                         ("active", 0, "agent_not_listed"))

    def test_agent_checked_even_without_a_usable_ip(self):
        # the agent is identified by its id, not its address
        g = graph(pc("004", None), pc("005", "10.0.0.70"), pc("006", "10.0.0.70"))
        prober = FakeProber(agents=[agent("004"), agent("005"), agent("006")])
        doc = run(g, prober=prober)
        for nid in ("endpoint:004", "endpoint:005", "endpoint:006"):
            self.assertEqual((doc["nodes"][nid]["state"], doc["nodes"][nid]["method"]),
                             ("active", "agent"))

    def test_port_layer_still_applies(self):
        g = graph(switch(), pc(), edges=[link("endpoint:004", "device:sw", "Gi1/0/5")])
        prober = FakeProber(snmp={"10.0.0.2": True}, ports={"10.0.0.2": {"Gi1/0/5": "down"}},
                            agents=[agent("004", keepalive=STALE)])
        node = run(g, prev(**{"endpoint:004": was("active", proven=("agent",), method="agent")}),
                   prober)["nodes"]["endpoint:004"]
        self.assertEqual((node["state"], node["method"]), ("inactive", "port"))
        # a check-in that is fresh but older than the port going down (this
        # pass) is a stored time, not a live reply: the down port wins
        prober = FakeProber(snmp={"10.0.0.2": True}, ports={"10.0.0.2": {"Gi1/0/5": "down"}},
                            agents=[agent("004", keepalive=FRESH)])
        node = run(g, prober=prober)["nodes"]["endpoint:004"]
        self.assertEqual((node["state"], node["method"]), ("inactive", "port"))


T2 = "2026-10-07T09:00:30+00:00"          # the pass after T1


class TestAgentCheckInVsDownPort(unittest.TestCase):
    """A stored check-in time is not a live reply: with the node's port down,
    the agent counts only if it checked in after the port went down."""

    G = graph(switch(), pc(), edges=[link("endpoint:004", "device:sw", "Gi1/0/5")])

    def pass_at(self, now, state, keepalive, port="down", snmp=True, icmp=None):
        prober = FakeProber(snmp={"10.0.0.2": snmp}, ports={"10.0.0.2": {"Gi1/0/5": port}},
                            agents=[agent("004", keepalive=keepalive)], icmp=icmp)
        doc = run(self.G, state, prober, now=now)
        return doc["nodes"]["endpoint:004"], doc

    def down_at_t1(self):
        before = prev(**{"endpoint:004": was("active", proven=("agent",), method="agent")})
        return self.pass_at(T1, before, FRESH)          # check-in 8 s before T1

    def test_check_in_from_before_the_port_went_down_is_inactive_at_once(self):
        node, _ = self.down_at_t1()
        self.assertEqual((node["state"], node["method"]), ("inactive", "port"))
        self.assertEqual(node["port_down"], {"device": "device:sw", "port": "Gi1/0/5",
                                             "previous_state": "active", "since": T1})
        self.assertEqual(node["misses"], 0)
        self.assertEqual(node["last_seen"], T0)          # the old check-in proves nothing

    def test_check_in_after_the_port_went_down_is_active(self):
        _, state = self.down_at_t1()
        node, _ = self.pass_at(T2, state, "2026-10-07T09:00:25+00:00")
        self.assertEqual((node["state"], node["method"], node["last_seen"]), ("active", "agent", T2))
        self.assertNotIn("port_down", node)

    def test_port_still_down_and_no_newer_check_in_stays_inactive(self):
        _, state = self.down_at_t1()
        node, _ = self.pass_at(T2, state, "2026-10-07T09:00:15+00:00")  # fresh, but before T1
        self.assertEqual((node["state"], node["method"]), ("inactive", "port"))
        self.assertEqual(node["port_down"]["since"], T1)                # first observation kept

    def test_newer_check_in_revives_while_the_switch_is_silent(self):
        # the switch did not answer, so the port is unknown: a check-in after
        # the port went down still shows the machine reconnected another way
        _, state = self.down_at_t1()
        node, _ = self.pass_at(T2, state, "2026-10-07T09:00:25+00:00", snmp=False)
        self.assertEqual((node["state"], node["method"]), ("active", "agent"))
        node, _ = self.pass_at(T2, state, "2026-10-07T09:00:15+00:00", snmp=False)
        self.assertEqual((node["state"], node["method"]), ("inactive", "port"))

    def test_port_up_restores_as_before(self):
        _, state = self.down_at_t1()
        node, _ = self.pass_at(T2, state, "2026-10-07T09:00:15+00:00", port="up")
        self.assertEqual(node["state"], "active")
        self.assertNotIn("port_down", node)

    def test_check_in_counts_normally_on_an_up_port(self):
        node, _ = self.pass_at(T1, {}, FRESH, port="up")
        self.assertEqual((node["state"], node["method"]), ("active", "agent"))

    def test_ping_reply_with_the_port_down_is_active(self):
        g = graph(switch(), H, edges=[link("host:a", "device:sw", "Gi1/0/5")])
        prober = FakeProber(snmp={"10.0.0.2": True}, icmp={"10.0.0.10": True},
                            ports={"10.0.0.2": {"Gi1/0/5": "down"}})
        node = run(g, prober=prober)["nodes"]["host:a"]
        self.assertEqual((node["state"], node["method"]), ("active", "icmp"))
        self.assertNotIn("port_down", node)

    def test_state_from_before_since_existed_is_strict(self):
        # an older liveness.json has port_down without "since": no stored
        # check-in can be shown to be newer, so the node stays inactive
        _, state = self.down_at_t1()
        del state["nodes"]["endpoint:004"]["port_down"]["since"]
        node, _ = self.pass_at(T2, state, "2026-10-07T09:00:25+00:00")
        self.assertEqual((node["state"], node["method"]), ("inactive", "port"))
        self.assertEqual(node["port_down"]["since"], T2)

    def test_default_max_age_is_30_seconds(self):
        old = "2026-10-07T08:59:45+00:00"          # 35 s before T1
        doc = run(graph(pc()), prev(**{"endpoint:004": was("active", proven=("agent",),
                                                           method="agent")}),
                  FakeProber(agents=[agent("004", keepalive=old)]))
        self.assertEqual(doc["nodes"]["endpoint:004"]["misses"], 1)     # a miss, not a reply


AP_IP = "10.0.0.5"
PHONE_MAC = "7a:bd:06:18:06:2c"
LAPTOP_MAC = "e4:a7:a0:25:ce:ac"


def wifi_link(source, radio="Do0"):
    return {"source": source, "target": "device:ap", "type": "endpoint_link",
            "local_port": radio, "confidence": "wifi"}


class TestWifiLiveness(unittest.TestCase):
    """Part 4: a node under an access point is checked by its client list."""

    def g(self):
        ap = dict(switch("device:ap", AP_IP), role="access-point", hostname="AP1")
        phone = host("host:phone", "10.0.0.81", mac=PHONE_MAC)
        laptop = pc("001", "10.0.0.83", mac=LAPTOP_MAC)
        return graph(switch(), ap, phone, laptop,
                     edges=[wifi_link("host:phone"), wifi_link("endpoint:001", "Do1"),
                            {"source": "device:sw", "target": "device:ap", "type": "lldp",
                             "local_port": "Fa1/0/15", "protocol": "cdp"}])

    def pass_at(self, now, state, clients, keepalive=FRESH, snmp=True, **kw):
        prober = FakeProber(snmp={"10.0.0.2": True, AP_IP: snmp}, wifi={AP_IP: clients},
                            agents=[agent("001", keepalive=keepalive)], **kw)
        doc = run(self.g(), state, prober, now=now)
        return doc, prober

    def test_client_in_the_list_replied(self):
        doc, prober = self.pass_at(T1, {}, {PHONE_MAC, LAPTOP_MAC})
        phone = doc["nodes"]["host:phone"]
        self.assertEqual((phone["state"], phone["method"], phone["proven_methods"]),
                         ("active", "wifi", ["wifi"]))
        self.assertNotIn(("icmp", "10.0.0.81"), prober.calls)         # in place of ping
        self.assertEqual(prober.calls.count(("wifi", AP_IP)), 1)       # once per pass

    def test_client_missing_from_the_list_is_inactive_at_once(self):
        before = prev(**{"host:phone": was("active", proven=("wifi",), method="wifi")})
        doc, _ = self.pass_at(T1, before, {LAPTOP_MAC})
        phone = doc["nodes"]["host:phone"]
        self.assertEqual((phone["state"], phone["method"]), ("inactive", "wifi"))
        self.assertEqual(phone["port_down"], {"device": "device:ap", "port": "wifi",
                                              "previous_state": "active", "since": T1})

    def test_missing_then_back_is_active(self):
        before = prev(**{"host:phone": was("active", proven=("wifi",), method="wifi")})
        _, _ = self.pass_at(T1, before, {LAPTOP_MAC})
        state = self.pass_at(T1, before, {LAPTOP_MAC})[0]
        doc, _ = self.pass_at(T2, state, {PHONE_MAC, LAPTOP_MAC})
        phone = doc["nodes"]["host:phone"]
        self.assertEqual((phone["state"], phone["method"]), ("active", "wifi"))
        self.assertNotIn("port_down", phone)

    def test_agent_missing_from_the_list_with_an_older_check_in_is_inactive(self):
        before = prev(**{"endpoint:001": was("active", proven=("agent",), method="agent")})
        doc, _ = self.pass_at(T1, before, {PHONE_MAC})            # FRESH is before T1
        node = doc["nodes"]["endpoint:001"]
        self.assertEqual((node["state"], node["method"]), ("inactive", "wifi"))

    def test_agent_check_in_after_it_left_the_list_makes_it_active(self):
        before = prev(**{"endpoint:001": was("active", proven=("agent",), method="agent")})
        state, _ = self.pass_at(T1, before, {PHONE_MAC})
        doc, _ = self.pass_at(T2, state, {PHONE_MAC}, keepalive="2026-10-07T09:00:25+00:00")
        node = doc["nodes"]["endpoint:001"]
        self.assertEqual((node["state"], node["method"]), ("active", "agent"))
        self.assertNotIn("port_down", node)

    def test_access_point_not_answering_changes_nothing(self):
        before = prev(**{"host:phone": was("active", proven=("wifi",), method="wifi")})
        doc, prober = self.pass_at(T1, before, {LAPTOP_MAC}, snmp=False)
        phone = doc["nodes"]["host:phone"]
        self.assertEqual((phone["state"], phone["misses"], phone["reason"]),
                         ("active", 0, "wifi_unavailable"))
        self.assertNotIn(("wifi", AP_IP), prober.calls)

    def test_client_list_failure_changes_nothing(self):
        before = prev(**{"host:phone": was("active", proven=("wifi",), method="wifi")})
        doc, _ = self.pass_at(T1, before, OSError("walk failed"))
        self.assertEqual(doc["nodes"]["host:phone"]["state"], "active")

    def test_radio_interface_status_is_not_a_wired_port(self):
        doc, _ = self.pass_at(T1, {}, {PHONE_MAC, LAPTOP_MAC},
                              ports={AP_IP: {"Do0": "down", "Do1": "down"}})
        self.assertEqual(doc["nodes"]["host:phone"]["state"], "active")

    def test_without_snmp_credentials_clients_are_pinged(self):
        prober = FakeProber(has_snmp=False, icmp={"10.0.0.81": True})
        node = run(self.g(), prober=prober)["nodes"]["host:phone"]
        self.assertEqual((node["state"], node["method"]), ("active", "icmp"))

    def test_unknown_client_suggests_a_rescan(self):
        doc, _ = self.pass_at(T1, {}, {PHONE_MAC, LAPTOP_MAC, "02:11:22:33:44:55"})
        self.assertTrue(doc["rescan_suggested"])
        self.assertIn("Wi-Fi client 02:11:22:33:44:55 on AP1 is not in the graph",
                      doc["rescan_reasons"])

    def test_known_clients_suggest_nothing(self):
        doc, _ = self.pass_at(T1, {}, {PHONE_MAC, LAPTOP_MAC})
        self.assertFalse(doc["rescan_suggested"])


class TestSystemProberWifi(unittest.TestCase):
    """The real prober reads one column; an empty list must be a real one."""

    def prober(self, rows):
        from snmp_fakes import FakeSnmpClient
        prober = SystemProber([], agent_source=object())
        prober.has_snmp, prober._snmp = True, FakeSnmpClient({AP_IP: rows})
        return prober

    def test_reads_the_client_macs(self):
        from snmp_fakes import load_rows
        macs = asyncio.run(self.prober(load_rows("cisco_ap_c1140.snmp")).wifi_clients(AP_IP))
        self.assertEqual(macs, {"7abd0618062c", "e4a7a025ceac"})

    def test_empty_list_counts_only_when_the_counters_agree(self):
        counters = "1.3.6.1.4.1.9.9.273.1.1.2.1.1"
        empty = [(f"{counters}.1", "0"), (f"{counters}.2", "0")]
        self.assertEqual(asyncio.run(self.prober(empty).wifi_clients(AP_IP)), set())
        busy = [(f"{counters}.1", "0"), (f"{counters}.2", "3")]       # walk lost the rows
        with self.assertRaises(RuntimeError):
            asyncio.run(self.prober(busy).wifi_clients(AP_IP))
        with self.assertRaises(RuntimeError):                           # nothing answered
            asyncio.run(self.prober([("1.3.6.1.2.1.1.5.0", "AP")]).wifi_clients(AP_IP))


Q_MAC = "28:f1:0e:31:3f:0c"
Q_KEY = (20, "28f10e313f0c")


class TestMacTable(unittest.TestCase):
    """Part 6: a wired host no faster method has proven is confirmed by its
    switch's forwarding table."""

    def g(self, vendor="Cisco", **quiet):
        sw = dict(switch(), vendor=vendor)
        node = dict(host("host:quiet", "10.0.0.40", mac=Q_MAC, vlan=20), **quiet)
        return graph(sw, node, edges=[link("host:quiet", "device:sw", "Gi1/0/7")])

    def run_with(self, table=None, state=None, ports=None, g=None, **kw):
        prober = FakeProber(snmp={"10.0.0.2": True}, ports={"10.0.0.2": ports or {}},
                            mac_tables={"10.0.0.2": {} if table is None else table}, **kw)
        doc = run(g or self.g(), state, prober)
        return doc["nodes"]["host:quiet"], doc, prober

    def test_found_on_its_port_replied(self):
        node, _, prober = self.run_with({Q_KEY: "Gi1/0/7"})
        self.assertEqual((node["state"], node["method"], node["proven_methods"]),
                         ("active", "mac-table", ["mac-table"]))
        self.assertEqual(node["last_seen"], T1)
        self.assertEqual([c for c in prober.calls if c[0] == "mac_lookup"],
                         [("mac_lookup", "10.0.0.2", (Q_KEY,), True)])   # Cisco: per VLAN

    def test_other_vendors_use_the_default_context(self):
        _, _, prober = self.run_with({Q_KEY: "Gi1/0/7"}, g=self.g(vendor="HP"))
        self.assertFalse([c for c in prober.calls if c[0] == "mac_lookup"][0][3])

    def test_missing_under_and_over_the_threshold(self):
        state = prev(**{"host:quiet": was("active", proven=("mac-table",), method="mac-table")})
        for expected in ((1, "active"), (2, "active"), (3, "inactive")):
            node, state, _ = self.run_with({}, state)
            self.assertEqual((node["misses"], node["state"], node["method"]),
                             expected + ("mac-table",))

    def test_missing_counts_before_any_reply(self):
        # the scan found it in this table, so its absence is evidence
        node, _, _ = self.run_with({})
        self.assertEqual((node["state"], node["misses"]), ("unknown", 1))

    def test_on_another_port_is_not_found(self):
        node, _, _ = self.run_with({Q_KEY: "Gi1/0/9"}, prev(**{"host:quiet": was(
            "active", proven=("mac-table",), method="mac-table")}))
        self.assertEqual(node["misses"], 1)

    def test_port_down_still_wins(self):
        node, _, _ = self.run_with({Q_KEY: "Gi1/0/7"}, ports={"Gi1/0/7": "down"})
        self.assertEqual((node["state"], node["method"]), ("inactive", "port"))

    def test_marked_down_port_is_not_looked_up(self):
        _, state, _ = self.run_with({}, ports={"Gi1/0/7": "down"})
        _, _, prober = self.run_with({Q_KEY: "Gi1/0/7"}, state, ports={"Gi1/0/7": "down"})
        self.assertFalse([c for c in prober.calls if c[0] == "mac_lookup"])

    def test_host_without_an_ip_is_confirmed(self):
        node, _, _ = self.run_with({Q_KEY: "Gi1/0/7"}, g=self.g(ip=None))
        self.assertEqual((node["state"], node["method"]), ("active", "mac-table"))

    def test_ping_that_ever_proved_itself_is_used_instead(self):
        state = prev(**{"host:quiet": was("active", proven=("icmp",))})
        _, _, prober = self.run_with({Q_KEY: "Gi1/0/7"}, state)
        self.assertFalse([c for c in prober.calls if c[0] == "mac_lookup"])

    def test_ping_reply_first_then_no_lookup(self):
        node, _, prober = self.run_with({Q_KEY: "Gi1/0/7"}, icmp={"10.0.0.40": True})
        self.assertEqual(node["method"], "icmp")
        self.assertFalse([c for c in prober.calls if c[0] == "mac_lookup"])

    def test_agent_and_wifi_nodes_are_not_looked_up(self):
        g = graph(dict(switch(), vendor="Cisco"), pc("004", "10.0.0.60", mac=Q_MAC, vlan=20),
                  edges=[link("endpoint:004", "device:sw", "Gi1/0/7")])
        prober = FakeProber(snmp={"10.0.0.2": True}, agents=[agent("004")],
                            mac_tables={"10.0.0.2": {Q_KEY: "Gi1/0/7"}})
        run(g, prober=prober)
        self.assertFalse([c for c in prober.calls if c[0] == "mac_lookup"])

    def test_switch_not_answering_snmp_is_not_asked(self):
        prober = FakeProber(snmp={"10.0.0.2": False}, mac_tables={"10.0.0.2": {Q_KEY: "Gi1/0/7"}})
        node = run(self.g(), prober=prober)["nodes"]["host:quiet"]
        self.assertEqual(node["state"], "unknown")
        self.assertFalse([c for c in prober.calls if c[0] == "mac_lookup"])

    def test_slow_or_failing_device_is_skipped(self):
        from vulnmapper import liveness
        state = prev(**{"host:quiet": was("active", proven=("mac-table",), method="mac-table")})
        for table in (0.5, OSError("timeout")):
            with self.subTest(table=table), \
                    mock.patch.object(liveness, "MAC_TABLE_BUDGET_S", 0.1):
                node, _, _ = self.run_with(table, state)
                self.assertEqual((node["state"], node["misses"], node["reason"]),
                                 ("active", 0, "mac_table_unavailable"))

    def test_one_lookup_per_switch_per_pass(self):
        g = self.g()
        g["nodes"].append(host("host:b", None, mac="02:00:00:00:00:0b", vlan=30))
        g["edges"].append(link("host:b", "device:sw", "Gi1/0/8"))
        _, _, prober = self.run_with({Q_KEY: "Gi1/0/7"}, g=g)
        (call,) = [c for c in prober.calls if c[0] == "mac_lookup"]
        self.assertEqual(set(call[2]), {Q_KEY, (30, "02000000000b")})


class TestRescanSuggestion(unittest.TestCase):
    """Item 6: a pass suggests a rescan when something new appears."""

    SW = dict(switch(), hostname="L3-Switch")
    UP = {"10.0.0.2": True}

    def g(self, *extra_nodes, edges=(), scan_time="S1"):
        doc = graph(self.SW, *extra_nodes, edges=list(edges))
        doc["metadata"] = {"scan_time": scan_time}
        return doc

    def two_passes(self, before, after, g=None, **prober):
        g = g or self.g()
        state = run(g, prober=FakeProber(snmp=self.UP, ports={"10.0.0.2": before}, **prober))
        return run(g, state, FakeProber(snmp=self.UP, ports={"10.0.0.2": after}, **prober))

    def test_ports_remembered_for_every_polled_device(self):
        doc = run(self.g(), prober=FakeProber(snmp=self.UP, ports={"10.0.0.2": {"Gi1/0/9": "down"}}))
        self.assertEqual(doc["ports"], {"device:sw": {"Gi1/0/9": "down"}})

    def test_unlinked_port_down_to_up_suggests_a_rescan(self):
        doc = self.two_passes({"Gi1/0/9": "down"}, {"Gi1/0/9": "up"})
        self.assertTrue(doc["rescan_suggested"])
        self.assertEqual(doc["rescan_reasons"],
                         ["port Gi1/0/9 on L3-Switch came up with nothing linked to it"])

    def test_recovery_of_a_linked_node_is_not_a_reason(self):
        g = self.g(host("host:phone", "10.0.0.51"),
                   edges=[link("host:phone", "device:sw", "Gi1/0/9")])
        doc = self.two_passes({"Gi1/0/9": "down"}, {"Gi1/0/9": "up"}, g)
        self.assertEqual((doc["rescan_suggested"], doc["rescan_reasons"]), (False, []))

    def test_a_port_used_by_a_device_link_is_linked_at_either_end(self):
        for edge in ({"source": "device:sw", "target": "device:x", "type": "lldp",
                      "local_port": "Gi1/0/9", "remote_port": "Gi0/1"},
                     {"source": "device:x", "target": "device:sw", "type": "lldp",
                      "local_port": "Gi0/1", "remote_port": "Gi1/0/9"}):
            with self.subTest(edge=edge):
                doc = self.two_passes({"Gi1/0/9": "down"}, {"Gi1/0/9": "up"},
                                      self.g(switch("device:x", "10.0.0.3"), edges=[edge]))
                self.assertFalse(doc["rescan_suggested"])

    def test_no_transition_no_suggestion(self):
        for before, after in (({"Gi1/0/9": "up"}, {"Gi1/0/9": "up"}),
                              ({"Gi1/0/9": "down"}, {"Gi1/0/9": "down"}),
                              ({"Gi1/0/9": "up"}, {"Gi1/0/9": "down"}),
                              ({}, {"Gi1/0/9": "up"})):           # never seen before
            with self.subTest(before=before, after=after):
                self.assertFalse(self.two_passes(before, after)["rescan_suggested"])

    def test_first_pass_has_nothing_to_compare(self):
        doc = run(self.g(), prober=FakeProber(snmp=self.UP, ports={"10.0.0.2": {"Gi1/0/9": "up"}}))
        self.assertFalse(doc["rescan_suggested"])

    def test_device_not_answering_keeps_its_remembered_ports(self):
        state = run(self.g(), prober=FakeProber(snmp=self.UP, ports={"10.0.0.2": {"Gi1/0/9": "down"}}))
        state = run(self.g(), state, FakeProber(snmp={"10.0.0.2": False}))
        self.assertEqual(state["ports"], {"device:sw": {"Gi1/0/9": "down"}})
        doc = run(self.g(), state, FakeProber(snmp=self.UP, ports={"10.0.0.2": {"Gi1/0/9": "up"}}))
        self.assertTrue(doc["rescan_suggested"])

    def test_port_status_failure_keeps_remembered_ports(self):
        class Broken(FakeProber):
            async def port_status(self, ip):
                raise OSError("walk failed")
        state = run(self.g(), prober=FakeProber(snmp=self.UP, ports={"10.0.0.2": {"Gi1/0/9": "up"}}))
        doc = run(self.g(), state, Broken(snmp=self.UP))
        self.assertEqual(doc["ports"], {"device:sw": {"Gi1/0/9": "up"}})

    def test_removed_device_is_forgotten(self):
        state = run(self.g(), prober=FakeProber(snmp=self.UP, ports={"10.0.0.2": {"Gi1/0/9": "up"}}))
        doc = run(graph(H), state)
        self.assertEqual(doc["ports"], {})

    def test_new_active_agent_suggests_a_rescan(self):
        g = self.g(pc("004"))
        doc = run(g, prober=FakeProber(agents=[agent("004"), agent("007")]))
        self.assertTrue(doc["rescan_suggested"])
        self.assertEqual(doc["rescan_reasons"], ["active Wazuh agent 007 is not in the graph"])

    def test_agents_that_do_not_count(self):
        g = self.g(pc("004"))
        rows = [agent("004"), agent("008", status="disconnected"),
                agent("009", status="never_connected", keepalive=None),
                agent("000", keepalive="9999-12-31T23:59:59+00:00")]   # manager left out
        doc = run(g, prober=FakeProber(agents=rows))
        self.assertEqual((doc["rescan_suggested"], doc["rescan_reasons"]), (False, []))

    def test_suggestion_stands_until_a_new_scan(self):
        doc = self.two_passes({"Gi1/0/9": "down"}, {"Gi1/0/9": "up"})
        again = run(self.g(), doc, FakeProber(snmp=self.UP, ports={"10.0.0.2": {"Gi1/0/9": "up"}}))
        self.assertTrue(again["rescan_suggested"])
        self.assertEqual(len(again["rescan_reasons"]), 1)          # not repeated
        rescanned = run(self.g(scan_time="S2"), again,
                        FakeProber(snmp=self.UP, ports={"10.0.0.2": {"Gi1/0/9": "up"}}))
        self.assertEqual((rescanned["rescan_suggested"], rescanned["rescan_reasons"]), (False, []))
        self.assertEqual(rescanned["graph_scan_time"], "S2")

    def test_graph_without_metadata(self):
        for meta in (None, [], "x"):
            with self.subTest(meta=meta):
                g = dict(self.g(), metadata=meta)
                self.assertIsNone(run(g)["graph_scan_time"])

    def test_reasons_are_a_short_list(self):
        before = {f"Gi1/0/{i}": "down" for i in range(1, 30)}
        after = {p: "up" for p in before}
        doc = self.two_passes(before, after)
        self.assertTrue(doc["rescan_suggested"])
        self.assertLessEqual(len(doc["rescan_reasons"]), 10)


class SlowSource:
    """A WazuhSource stand-in whose login hangs."""

    def __init__(self, delay):
        self.delay = delay

    def agent_status(self):
        time.sleep(self.delay)
        return []


class TestSystemProberAgents(unittest.TestCase):
    def test_no_wazuh_password_means_no_agent_method(self):
        with mock.patch.dict(os.environ, {"WAZUH_PASS": ""}):
            self.assertFalse(SystemProber([]).has_agents)

    def test_wazuh_password_enables_agent_method(self):
        with mock.patch.dict(os.environ, {"WAZUH_PASS": "x"}):
            self.assertTrue(SystemProber([]).has_agents)

    def test_hung_login_does_not_hold_up_the_pass(self):
        prober = SystemProber([], agent_source=SlowSource(3.0))
        started = time.monotonic()
        doc = run(graph(pc()), prober=prober, agent_timeout=0.2)
        self.assertLess(time.monotonic() - started, 1.5)
        self.assertEqual(doc["nodes"]["endpoint:004"]["reason"], "agent_unavailable")


class TestAgentStatusHelper(unittest.TestCase):
    """The read-only Manager API helper: one login, paged /agents requests."""

    def source(self):
        return WazuhSource(WazuhConfig(host="wazuh", port="55000", user="u", password="p"),
                           indexer=mock.Mock())

    def test_logs_in_once_and_pages_through_agents(self):
        src = self.source()
        pages = [[agent(f"{i:03d}") for i in range(500)], [agent("500")]]
        with mock.patch.object(WazuhSource, "_authenticate") as auth, \
                mock.patch.object(WazuhSource, "_get", side_effect=pages) as get:
            rows = src.agent_status()
        self.assertEqual(auth.call_count, 1)
        self.assertEqual(len(rows), 501)
        self.assertEqual(get.call_args_list[0], mock.call(
            "/agents", params={"select": "id,status,lastKeepAlive", "limit": 500, "offset": 0}))
        self.assertEqual(get.call_args_list[1].kwargs["params"]["offset"], 500)

    def test_single_short_page_is_one_request(self):
        src = self.source()
        with mock.patch.object(WazuhSource, "_authenticate"), \
                mock.patch.object(WazuhSource, "_get", return_value=[agent("000")]) as get:
            self.assertEqual(src.agent_status(), [agent("000")])
        self.assertEqual(get.call_count, 1)


class TestRobustness(unittest.TestCase):
    def test_one_probe_failure_does_not_abort_the_pass(self):
        prober = FakeProber(icmp={"10.0.0.11": True}, boom={"10.0.0.10"})
        doc = run(graph(H, host("host:b", "10.0.0.11")),
                  prev(**{"host:a": was("active", misses=2)}), prober)
        a = doc["nodes"]["host:a"]
        self.assertEqual((a["state"], a["misses"], a["reason"]), ("active", 2, "probe_error"))
        self.assertEqual(doc["nodes"]["host:b"]["state"], "active")

    def test_at_most_32_probes_in_flight(self):
        nodes = [host(f"host:{i}", f"10.1.{i // 250}.{i % 250 + 1}") for i in range(100)]
        prober = FakeProber()
        run(graph(*nodes), prober=prober)
        self.assertEqual(len(prober.calls), 100)
        self.assertLessEqual(prober.max_in_flight, 32)

    def test_malformed_previous_state_entries_ignored(self):
        doc = run(graph(H), {"nodes": {"host:a": "garbage"}},
                  FakeProber(icmp={"10.0.0.10": True}))
        self.assertEqual(doc["nodes"]["host:a"]["state"], "active")


class TestStateFileAndCli(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        # no Wazuh credentials: the CLI must not try the Manager API in tests
        env = mock.patch.dict(os.environ, {"WAZUH_PASS": ""})
        env.start()
        self.addCleanup(env.stop)

    def tearDown(self):
        for name in os.listdir(self.tmp):
            os.unlink(os.path.join(self.tmp, name))
        os.rmdir(self.tmp)

    def path(self, name, text=None):
        p = os.path.join(self.tmp, name)
        if text is not None:
            with open(p, "w") as f:
                f.write(text)
        return p

    def test_missing_state_file_is_empty(self):
        self.assertEqual(load_state(self.path("nope.json")), {})
        self.assertEqual(load_state(None), {})

    def test_corrupt_state_file_is_empty(self):
        for text in ("{not json", "[]", '{"nodes": []}', '"x"', ""):
            with self.subTest(text=text):
                self.assertEqual(load_state(self.path("s.json", text)), {})

    def test_valid_state_file_loaded(self):
        doc = prev(**{"host:a": was("active")})
        self.assertEqual(load_state(self.path("s.json", json.dumps(doc))), doc)

    def run_main(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_cli_prints_valid_document_and_exits_0(self):
        # nodes without an IP: no probe, so no network access
        g = self.path("g.json", json.dumps(graph(host("device:hamza", None, kind="device"))))
        code, out, _ = self.run_main(["--graph", g, "--state", self.path("missing.json"),
                                      "--threshold", "2"])
        self.assertEqual(code, 0)
        doc = json.loads(out)
        self.assertEqual(doc["threshold"], 2)
        self.assertEqual(doc["nodes"]["device:hamza"]["state"], "unknown")

    def test_cli_default_threshold_is_2(self):
        g = self.path("g.json", json.dumps(graph(host("device:hamza", None, kind="device"))))
        code, out, _ = self.run_main(["--graph", g])
        self.assertEqual((code, json.loads(out)["threshold"]), (0, 2))

    def test_cli_unreadable_graph_exits_nonzero(self):
        code, out, err = self.run_main(["--graph", self.path("missing-graph.json")])
        self.assertNotEqual(code, 0)
        self.assertEqual(out, "")
        self.assertIn("cannot read graph", err)

    def test_cli_rejects_threshold_below_one(self):
        g = self.path("g.json", json.dumps(graph()))
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            main(["--graph", g, "--threshold", "0"])


if __name__ == "__main__":
    unittest.main()
