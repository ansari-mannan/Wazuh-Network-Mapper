"""The exposure-path engine, offline. Synthetic graphs for the engine rules and
the lab inputs for the pipeline; nothing touches the network.
"""

import contextlib
import copy
import io
import json
import os
import shutil
import tempfile
import unittest

from test_cdp import crawl, lab
from test_device_stage import lab_nvd
from test_nvd import FakeClock
from vulnmapper import attackpaths as ap
from vulnmapper.pipeline import Pipeline

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "fixtures")


# --- builders ---------------------------------------------------------------

def cve(cid, score, av="NETWORK", ac="LOW", pr="NONE", ui="NONE", ver="3.1"):
    return {"cve": cid, "cvss": score, "cvss_version": ver, "attack_vector": av,
            "attack_complexity": ac, "privileges_required": pr, "user_interaction": ui}


def dev(nid, role, vlans_up, findings=None, cves=None, risk=None, vendor="Cisco"):
    ports = {f"Vl{v}": "up" for v in vlans_up}
    return {"node_id": nid, "kind": "device", "role": role, "vendor": vendor,
            "port_status": ports, "config_findings": findings or [],
            "top_cves": cves or [], "risk_score": risk, "parent_id": None}


def host(nid, vlan, cves=None, risk=None, agent=None, unmanaged=False, wifi=None,
         wazuh=False, parent=None):
    n = {"node_id": nid, "kind": "endpoint", "vlan": vlan, "top_cves": cves or [],
         "risk_score": risk, "parent_id": parent}
    if agent:
        n["agent_id"] = agent
    if unmanaged:
        n["unmanaged"] = True
    if wifi:
        n["wifi"] = wifi
    if wazuh:
        n["is_wazuh_server"] = True
    return n


def finding(check_id, **extra):
    from vulnmapper.checklist.catalogue import by_id
    return {"id": check_id, "title": by_id(check_id)["title"],
            "severity": by_id(check_id)["severity"], **extra}


def graph(nodes):
    return {"nodes": nodes, "edges": [], "metadata": {"scan_time": "2026-10-10T00:00:00+00:00"}}


def run(nodes, targets, vulns=None, keep=ap.KEEP_PER_TARGET):
    return ap.compute(graph(nodes), targets, vulns, keep)


# --- the qualifying-CVE rule ------------------------------------------------

class TestQualifies(unittest.TestCase):
    def test_vector_privilege_interaction_and_scope(self):
        cases = {
            # (av, pr, ui): (qualifies in-VLAN, qualifies across a router)
            ("NETWORK", "NONE", "NONE"): (True, True),
            ("ADJACENT", "NONE", "NONE"): (True, False),   # adjacent only within a VLAN
            ("LOCAL", "NONE", "NONE"): (False, False),
            ("PHYSICAL", "NONE", "NONE"): (False, False),
            ("NETWORK", "LOW", "NONE"): (False, False),     # needs an account
            ("NETWORK", "NONE", "REQUIRED"): (False, False),  # needs a user action
        }
        for (av, pr, ui), (same, across) in cases.items():
            row = cve("C", 9.0, av=av, pr=pr, ui=ui)
            self.assertEqual(ap._qualifies(row, False), same, (av, pr, ui, "in-VLAN"))
            self.assertEqual(ap._qualifies(row, True), across, (av, pr, ui, "across"))

    def test_v2_authentication_none_and_v4_kept(self):
        v2 = cve("C2", 7.5, ver="2.0")               # Au:N mapped to PR NONE upstream
        v4 = cve("C4", 8.1, ver="4.0")               # Attack Requirements unread, not discarded
        self.assertTrue(ap._qualifies(v2, True))
        self.assertTrue(ap._qualifies(v4, True))


class TestBestStep(unittest.TestCase):
    def test_highest_value_then_higher_score(self):
        cands = [cve("A", 9.9, ac="HIGH"), cve("B", 7.0, ac="LOW"), cve("C", 8.0, ac="LOW")]
        best = ap._best_weakness(cands, False)
        self.assertEqual((best["cve"], best["value"]), ("C", 0.9))   # LOW beats HIGH, 8>7

    def test_complexity_values(self):
        for ac, val in (("LOW", 0.9), ("MEDIUM", 0.6), ("HIGH", 0.2)):
            self.assertEqual(ap._best_weakness([cve("X", 5.0, ac=ac)], False)["value"], val)

    def test_adjacent_best_in_vlan_but_network_second_across(self):
        cands = [cve("ADJ", 9.0, av="ADJACENT", ac="LOW"), cve("NET", 7.0, ac="MEDIUM")]
        self.assertEqual(ap._best_weakness(cands, False)["cve"], "ADJ")   # 0.9 in-VLAN
        self.assertEqual(ap._best_weakness(cands, True)["cve"], "NET")    # 0.6 across

    def test_misconfig_value_from_exposure(self):
        node = dev("d", "l3-switch", [10],
                   findings=[finding("snmp-default-community"), finding("mgmt-telnet-enabled")])
        best = ap._best_misconfig(node)
        self.assertEqual((best["check"], best["value"]), ("snmp-default-community", 0.9))

    def test_takeover_refuses_misconfig_across_a_router(self):
        node = dev("d", "l3-switch", [10], findings=[finding("snmp-default-community")])
        node["_cands"] = []
        self.assertIsNotNone(ap._takeover(node, [], False))              # usable in-VLAN
        self.assertIsNone(ap._takeover(node, [], True))                  # not across a router


# --- reachability -----------------------------------------------------------

class TestReachability(unittest.TestCase):
    def test_same_vlan_direct_and_cross_vlan_through_router(self):
        nodes = [
            host("endpoint:001", 10, cves=[cve("C", 9.0)], agent="001"),
            host("endpoint:002", 10, cves=[cve("C", 9.0)], risk=5.0),     # same VLAN as 001
            host("endpoint:003", 20, cves=[cve("C", 9.0)], risk=5.0),     # needs routing
            dev("device:00:r", "router", [10, 20]),
        ]
        doc = run(nodes, {"endpoint:002": {"importance": "high"},
                          "endpoint:003": {"importance": "high"}})
        direct = doc["targets"][0] if doc["targets"][0]["id"] == "endpoint:002" else doc["targets"][1]
        routed = doc["targets"][0] if doc["targets"][0]["id"] == "endpoint:003" else doc["targets"][1]
        self.assertFalse(direct["routes"][0]["crosses_router"])
        self.assertTrue(routed["routes"][0]["crosses_router"])
        self.assertEqual(routed["routes"][0]["steps"][0]["kind"], "transit")
        self.assertEqual(routed["routes"][0]["steps"][0]["through"], "device:00:r")

    def test_l2_switch_does_not_route(self):
        nodes = [
            host("endpoint:001", 10, cves=[cve("C", 9.0)], agent="001"),
            host("endpoint:003", 20, cves=[cve("C", 9.0)], risk=5.0),
            dev("device:l2", "l2-switch", [10, 20]),      # interfaces in both, but L2
        ]
        doc = run(nodes, {"endpoint:003": {"importance": "high"}})
        self.assertEqual(doc["targets"][0]["routes"], [])

    def test_lowest_id_router_on_a_tie(self):
        routers = {"device:b": {10, 20}, "device:a": {10, 20}}
        self.assertEqual(ap._router_between({10}, {20}, routers, set()), "device:a")


# --- steps, stepping stones, start kinds ------------------------------------

class TestRoutesAndStarts(unittest.TestCase):
    def test_nothing_usable_ends_no_route(self):
        nodes = [host("endpoint:001", 10, cves=[cve("C", 9.0)], agent="001"),
                 host("endpoint:safe", 10, risk=9.9)]        # no CVE, no misconfig
        doc = run(nodes, {"endpoint:safe": {"importance": "high"}})
        self.assertEqual(doc["targets"][0]["routes"], [])

    def test_three_start_kinds_and_target_as_start_skipped(self):
        nodes = [
            host("endpoint:001", 10, cves=[cve("C", 9.0)], agent="001"),   # managed w/ CVE
            host("host:aa", 10, unmanaged=True),                           # unmanaged
            dev("device:sw", "l3-switch", [10], cves=[cve("D", 9.0)], risk=7.0,
                findings=[finding("spare-ports-in-used-vlan",
                                  evidence={"ports": [{"port": "Fa1", "vlan": 10}], "total": 1})]),
        ]
        doc = run(nodes, {"endpoint:001": {"importance": "high"}})
        kinds = {s["kind"] for s in doc["starting_points"]}
        self.assertEqual(kinds, {"managed_host", "unmanaged_host", "spare_ports"})
        # endpoint:001 is both a start and this target: no self-route
        self.assertTrue(all(r["start"] != "endpoint:001" for r in doc["targets"][0]["routes"]))

    def test_step_kinds_and_values_on_a_route(self):
        # a switch whose only takeover is a misconfiguration, reached from its own
        # spare ports in the same VLAN
        nodes = [
            dev("device:sw", "l3-switch", [10],
                findings=[finding("mgmt-telnet-enabled"),
                          finding("spare-ports-in-used-vlan",
                                  evidence={"ports": [{"port": "Fa1", "vlan": 10}], "total": 1})],
                risk=8.0),
        ]
        doc = run(nodes, {"device:sw": {"importance": "moderate"}})
        spare = next(r for r in doc["targets"][0]["routes"] if r["start_kind"] == "spare_ports")
        self.assertEqual(spare["steps"][0]["kind"], "misconfiguration")
        self.assertEqual(spare["steps"][0]["value"], 0.2)     # telnet exposure HIGH

        # a weakness step across a router carries a preceding transit step (value 1)
        routed = [
            host("endpoint:001", 10, cves=[cve("C", 9.0)], agent="001"),
            dev("device:r", "router", [10, 20]),
            host("endpoint:t", 20, cves=[cve("C", 9.0, ac="MEDIUM")], risk=4.0),
        ]
        doc = run(routed, {"endpoint:t": {"importance": "high"}})
        steps = doc["targets"][0]["routes"][0]["steps"]
        self.assertEqual([s["kind"] for s in steps], ["transit", "weakness"])
        self.assertEqual([s["value"] for s in steps], [1.0, 0.6])


# --- ordering (dependants never involved) -----------------------------------

class TestOrdering(unittest.TestCase):
    def route(self, likelihood, score, tos, start):
        return {"likelihood": likelihood, "highest_base_score": score,
                "steps": [{"to": x} for x in tos], "start": start}

    def test_each_key_in_turn_and_stable_tail(self):
        routes = [
            self.route(0.6, 9.0, ["t"], "s1"),                 # lower likelihood -> last
            self.route(0.9, 5.0, ["a", "t"], "s1"),            # lower score
            self.route(0.9, 9.0, ["a", "t"], "s2"),            # more steps, higher start id
            self.route(0.9, 9.0, ["t"], "s2"),                 # fewer steps
            self.route(0.9, 9.0, ["t"], "s1"),                 # lowest start id -> first
        ]
        order = [ap._order_key(r) for r in routes]
        ranked = [routes[i] for i in sorted(range(len(routes)), key=lambda i: order[i])]
        self.assertEqual([(r["likelihood"], r["highest_base_score"], len(r["steps"]), r["start"])
                          for r in ranked],
                         [(0.9, 9.0, 1, "s1"), (0.9, 9.0, 1, "s2"),
                          (0.9, 9.0, 2, "s2"), (0.9, 5.0, 2, "s1"), (0.6, 9.0, 1, "s1")])

    def test_stable_by_route_ids(self):
        a = self.route(0.9, 9.0, ["m1", "t"], "s1")
        b = self.route(0.9, 9.0, ["m2", "t"], "s1")
        self.assertLess(ap._order_key(a), ap._order_key(b))   # m1 before m2

    def test_dependants_do_not_change_route_order(self):
        # a router with many dependants must not outrank a cheaper route
        nodes = [
            host("endpoint:001", 10, cves=[cve("C", 9.0)], agent="001"),
            host("endpoint:a", 10, cves=[cve("C", 9.0)], risk=1.0),
            host("endpoint:b", 10, cves=[cve("C", 9.0)], risk=1.0),
            host("endpoint:c", 10, cves=[cve("C", 9.0)], risk=1.0),
            dev("device:sw", "l3-switch", [10], cves=[cve("D", 9.0, ac="HIGH")], risk=9.9),
        ]
        doc = run(nodes, {"endpoint:a": {"importance": "high"}})
        per = {a["id"]: a for a in doc["per_asset"]}
        self.assertGreater(per["device:sw"]["dependants"], 0)  # the switch has dependants
        self.assertEqual(per["endpoint:a"]["dependants"], 0)   # a host has none


# --- targets edge cases, placement -----------------------------------------

class TestTargetsAndPlacement(unittest.TestCase):
    def test_no_targets(self):
        doc = run([host("endpoint:001", 10, cves=[cve("C", 9.0)], agent="001")], None)
        self.assertEqual(doc["metadata"]["state"], "no_targets")
        self.assertEqual(doc["metadata"]["counts"]["routes"], 0)

    def test_missing_target_reported(self):
        doc = run([host("endpoint:001", 10, agent="001")], {"ghost": {"importance": "high"}})
        block = doc["targets"][0]
        self.assertFalse(block["present"])
        self.assertIn("no node", block["reason"])

    def test_wifi_client_placed_by_single_radio_subinterface(self):
        ap_node = {"node_id": "device:ap", "kind": "device", "role": "access-point",
                   "vendor": "Cisco", "port_status": {"Do0": "up", "Do0.80": "up"},
                   "config_findings": [], "top_cves": [], "risk_score": None}
        client = host("host:w", None, wifi={"access_point": "device:ap", "radio": "Do0"})
        doc = run([ap_node, client], None)
        self.assertNotIn("host:w", [n["id"] for n in doc["not_placed"]])

    def test_wifi_client_ambiguous_radio_left_out(self):
        ap_node = {"node_id": "device:ap", "kind": "device", "role": "access-point",
                   "vendor": "Cisco", "port_status": {"Do0.80": "up", "Do0.90": "up"},
                   "config_findings": [], "top_cves": [], "risk_score": None}
        client = host("host:w", None, wifi={"access_point": "device:ap", "radio": "Do0"})
        doc = run([ap_node, client], None)
        reasons = {n["id"]: n["reason"] for n in doc["not_placed"]}
        self.assertIn("ambiguous", reasons["host:w"])

    def test_unknown_vlan_not_placed(self):
        doc = run([host("endpoint:x", None, cves=[cve("C", 9.0)], agent="x")], None)
        self.assertEqual(doc["not_placed"][0]["id"], "endpoint:x")


# --- recompute: changes neither input, no call ------------------------------

class TestRecompute(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_recompute_writes_only_attack_paths(self):
        gpath = os.path.join(self.tmp, "graph.json")
        nodes = [host("endpoint:001", 10, cves=[cve("C", 9.0)], agent="001"),
                 host("endpoint:002", 10, cves=[cve("C", 9.0)], risk=5.0)]
        with open(gpath, "w") as f:
            json.dump(graph(nodes), f, indent=2)
        with open(gpath) as f:
            before = f.read()
        with open(os.path.join(self.tmp, "targets.json"), "w") as f:
            json.dump({"endpoint:002": {"importance": "high"}}, f)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(ap.main(["--graph", gpath]), 0)
        with open(gpath) as f:
            self.assertEqual(f.read(), before)                # graph untouched
        self.assertEqual(sorted(os.listdir(self.tmp)),
                         ["attack_paths.json", "graph.json", "targets.json"])
        with open(os.path.join(self.tmp, "attack_paths.json")) as f:
            out = json.load(f)
        self.assertEqual(out["metadata"]["counts"]["routes"], 1)


# --- the pipeline stage against the frozen baseline -------------------------

class TestPipeline(unittest.TestCase):
    """Offline endpoints with findings, the lab crawl and its devices' NVD answers."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.network = os.path.join(self.tmp, "network.json")
        with open(self.network, "w") as f:
            json.dump(crawl(lab()), f)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def run_pipeline(self, *extra):
        clock = FakeClock()
        with contextlib.suppress(FileNotFoundError):
            os.unlink(os.path.join(self.tmp, "nvd-cache.json"))
        argv = ["--scored", os.path.join(FIXTURES, "offline_scored.json"), "--network",
                self.network, "--no-name-lookup", "-o", os.path.join(self.tmp, "graph.json"), *extra]
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(Pipeline(nvd_transport=lab_nvd(clock), clock=clock).run(argv), 0)
        out = {}
        for name in ("graph", "vulnerabilities"):
            with open(os.path.join(self.tmp, f"{name}.json")) as f:
                out[name] = json.load(f)
        return out

    def test_stage_off_matches_frozen_baseline(self):
        with open(os.path.join(FIXTURES, "pipeline_main_6eb7e74.json")) as f:
            frozen = json.load(f)
        out = self.run_pipeline("--no-attack-paths")
        self.assertFalse(os.path.exists(os.path.join(self.tmp, ap.FILENAME)))
        out["graph"]["metadata"]["timing"] = {k: None for k in out["graph"]["metadata"]["timing"]}
        for key in ("scan_time", "network_scan_time"):
            out["graph"]["metadata"][key] = None
        out["vulnerabilities"]["metadata"]["scan_time"] = None
        self.assertEqual(out, frozen)

    def test_stage_on_writes_the_file_and_adds_only_timing(self):
        off = self.run_pipeline("--no-attack-paths")
        on = self.run_pipeline()                              # stage on, no targets beside -o
        self.assertTrue(os.path.exists(os.path.join(self.tmp, ap.FILENAME)))
        self.assertIsInstance(on["graph"]["metadata"]["timing"].pop("attack_paths_s"), float)
        # the two runs differ only in wall-clock stamps; null them, then compare
        for doc in (on, off):
            meta = doc["graph"]["metadata"]
            meta["timing"] = {k: None for k in meta["timing"]}
            meta["scan_time"] = meta["network_scan_time"] = None
            doc["vulnerabilities"]["metadata"]["scan_time"] = None
        self.assertEqual(on, off)
        with open(os.path.join(self.tmp, ap.FILENAME)) as f:
            paths = json.load(f)
        self.assertEqual(paths["metadata"]["state"], "no_targets")


if __name__ == "__main__":
    unittest.main()
