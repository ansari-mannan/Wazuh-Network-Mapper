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
                 agents=None, agent_error=None, agent_delay=0.0):
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
        self.assertEqual(set(doc), {"checked_at", "threshold", "nodes"})
        self.assertEqual((doc["checked_at"], doc["threshold"]), (T1, 4))


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
                                             "previous_state": "active"})
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
                                             "previous_state": "active"})

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
        # a fresh check-in in the same pass beats the down port
        prober = FakeProber(snmp={"10.0.0.2": True}, ports={"10.0.0.2": {"Gi1/0/5": "down"}},
                            agents=[agent("004", keepalive=FRESH)])
        node = run(g, prober=prober)["nodes"]["endpoint:004"]
        self.assertEqual((node["state"], node["method"]), ("active", "agent"))


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
