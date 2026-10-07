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
import unittest

from vulnmapper.liveness import liveness_pass, load_state, main

T0 = "2026-10-07T09:00:00+00:00"
T1 = "2026-10-07T09:00:20+00:00"


class FakeProber:
    """Answers from tables; records every probe. ``boom`` IPs raise."""

    def __init__(self, icmp=None, snmp=None, ports=None, has_snmp=True, boom=()):
        self.icmp_replies = icmp or {}
        self.snmp_replies = snmp or {}
        self.ports = ports or {}
        self.has_snmp = has_snmp
        self.boom = set(boom)
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


def host(node_id, ip, kind="endpoint", **extra):
    return {"node_id": node_id, "kind": kind, "ip": ip,
            "discovery_method": "snmp_fdb" if kind == "endpoint" else "snmp_lldp", **extra}


def switch(node_id="device:sw", ip="10.0.0.2", pollable=True):
    return host(node_id, ip, kind="device", pollable=pollable)


def graph(*nodes, edges=()):
    return {"nodes": list(nodes), "edges": list(edges), "metadata": {}}


def link(source, target, port):
    return {"source": source, "target": target, "type": "endpoint_link", "local_port": port}


def run(g, previous=None, prober=None, threshold=3, now=T1):
    return asyncio.run(liveness_pass(g, previous or {}, prober or FakeProber(), threshold, now=now))


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
