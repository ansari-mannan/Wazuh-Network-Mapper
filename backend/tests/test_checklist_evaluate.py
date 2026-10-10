"""Evaluating the configuration checks, and the pipeline stage that runs them.

Capture fixtures through the fake SNMP client for the lab devices, small
hand-made configurations for each result; nothing touches the network.
"""

import asyncio
import contextlib
import copy
import io
import json
import os
import shutil
import tempfile
import unittest

from snmp_fakes import FakeSnmpClient, load_rows
from test_cdp import L3_CID, lab
from vulnmapper.checklist import tables as t
from vulnmapper.checklist.catalogue import CATALOGUE
from vulnmapper.checklist.collect import collect_config
from vulnmapper.checklist.evaluate import (EVIDENCE_CAP, access_ports, evaluate_device,
                                           l3_vlans, port_key)
from vulnmapper.checklist.stage import run_stage
from vulnmapper.network.crawl import Crawler, build_document
from vulnmapper.pipeline import Pipeline

IP = "10.0.0.2"
IDS = [c["id"] for c in CATALOGUE]


def captured(name, vendor, **fake_kw):
    client = FakeSnmpClient({IP: load_rows(f"checklist_{name}.snmp")}, **fake_kw)
    return asyncio.run(collect_config(client, IP, vendor))


def results(out):
    return {c["id"]: c["result"] for c in out["config_checks"]}


def finding(out, check_id):
    return next(f for f in out["config_findings"] if f["id"] == check_id)


def switch(vendor="Cisco", uplinks=("Gi0/1",)):
    return {"role": "l2-switch", "vendor": vendor, "uplink_ports": list(uplinks)}


def iface(name, admin=t.UP, oper=t.UP, last_change=0, if_type=6):
    return {"name": name, "type": if_type, "admin": admin, "oper": oper,
            "last_change": last_change}


def config(**over):
    """A small Cisco switch: Fa0/1-3 access ports, Gi0/1 an uplink, Vlan1."""
    c = {
        "snmp": {"version": "v3", "default_name": None},
        "probe": None,
        "uptime": 10_000_000,
        "tcp": {"read": True, "ports": [22]},
        "interfaces": {1: iface("FastEthernet0/1"), 2: iface("FastEthernet0/2"),
                       3: iface("FastEthernet0/3"), 10: iface("GigabitEthernet0/1"),
                       100: iface("Vlan1", if_type=53)},
        "bridge_ports": {1: 1, 2: 2, 3: 3, 10: 10},
        "pvid": {1: 10, 2: 10, 3: 20, 10: 1},
        "vm_vlan": {1: 10, 2: 10, 3: 20},
        "port_security": {"global": True, "ports": {1: True, 2: True, 3: True, 10: False}},
        "bpdu": {"global_guard": False, "global_portfast": 2,
                 "ports": {bp: {"portfast": 1, "guard": 1} for bp in (1, 2, 3)}},
    }
    c.update(over)
    return c


class TestLabCaptures(unittest.TestCase):
    """What the checks find in the captures of 8 October."""

    def test_cisco_l3_switch(self):
        out = evaluate_device({"role": "l3-switch", "vendor": "Cisco",
                               "uplink_ports": ["Fa1/0/1", "Fa1/0/2", "Fa1/0/6"]},
                              captured("l3", "Cisco"), False, "cisco_ios")
        self.assertEqual(results(out), {
            "mgmt-telnet-enabled": "unknown", "mgmt-http-enabled": "unknown",
            "snmp-no-auth": "fail", "snmp-default-community": "not_checked",
            "spare-ports-in-used-vlan": "fail", "access-ports-default-vlan": "fail",
            "bpdu-guard-missing": "fail", "port-security-disabled": "fail"})
        spare = finding(out, "spare-ports-in-used-vlan")["evidence"]
        self.assertEqual(spare["ports"][0], {"port": "FastEthernet1/0/5", "vlan": 40})
        self.assertEqual((spare["total"], spare["enabled"], spare["shut_down"]), (19, 18, 1))
        # its own Vlan10..Vlan100 interfaces are up, except Vlan1 and Vlan50
        self.assertEqual(spare["unused_vlans"], [50])
        self.assertEqual(finding(out, "access-ports-default-vlan")["evidence"],
                         {"ports": ["GigabitEthernet1/0/1", "GigabitEthernet1/0/2"],
                          "total": 2, "with_link": 0})
        self.assertEqual(finding(out, "bpdu-guard-missing")["evidence"]["total"], 22)
        self.assertEqual(out["config_summary"]["findings"],
                         {"high": 0, "medium": 4, "low": 0, "advisory": 1})
        refs = finding(out, "bpdu-guard-missing")["references"]
        self.assertEqual(refs[0]["rule_id"], "V-220630")

    def test_cisco_l2_switch(self):
        out = evaluate_device({"role": "l2-switch", "vendor": "Cisco", "uplink_ports": ["Fa0/1"]},
                              captured("l2", "Cisco"), False, "cisco_ios")
        # VLANs 10 and 99 (its own address, management) have up VLAN interfaces:
        # every spare port is in a VLAN in use, and none is taken for parking
        spare = finding(out, "spare-ports-in-used-vlan")["evidence"]
        self.assertEqual((spare["total"], len(spare["ports"])), (48, EVIDENCE_CAP))
        self.assertEqual(spare["unused_vlans"], [])
        self.assertIn({"port": "FastEthernet0/3", "vlan": 10}, spare["ports"])
        self.assertEqual(finding(out, "port-security-disabled")["evidence"]["total"], 48)

    def test_hp_switch(self):
        out = evaluate_device({"role": "l3-switch", "vendor": "HP",
                               "uplink_ports": ["GigabitEthernet1/0/1"]},
                              captured("hp", "HP"), False, None)
        self.assertEqual(results(out), {
            "mgmt-telnet-enabled": "fail", "mgmt-http-enabled": "fail",
            "snmp-no-auth": "fail", "snmp-default-community": "not_checked",
            "spare-ports-in-used-vlan": "unknown", "access-ports-default-vlan": "unknown",
            "bpdu-guard-missing": "not_applicable", "port-security-disabled": "not_applicable"})
        # not a Cisco IOS device: the SRG reference, not the Cisco STIG
        refs = finding(out, "mgmt-telnet-enabled")["references"]
        self.assertEqual([r["rule_id"] for r in refs], ["V-202118"])

    def test_access_point(self):
        out = evaluate_device({"role": "access-point", "vendor": "Cisco", "uplink_ports": ["Gi0"]},
                              captured("ap", "Cisco"), False, "cisco_ios")
        self.assertEqual(results(out), {
            "mgmt-telnet-enabled": "pass", "mgmt-http-enabled": "fail",
            "snmp-no-auth": "fail", "snmp-default-community": "not_checked",
            "spare-ports-in-used-vlan": "not_applicable", "access-ports-default-vlan": "not_applicable",
            "bpdu-guard-missing": "not_applicable", "port-security-disabled": "not_applicable"})
        self.assertEqual(out["config_checks"][4]["reason"], "applies to switches")


class TestAccessPorts(unittest.TestCase):
    def test_ethernet_switch_ports_that_are_not_uplinks(self):
        ports, reason = access_ports(config(), ["Gi0/1"], "Cisco")
        self.assertEqual((ports, reason), ([1, 2, 3], None))

    def test_trunks_are_not_access_ports_on_cisco(self):
        ports, _ = access_ports(config(vm_vlan={1: 10}), [], "Cisco")
        self.assertEqual(ports, [1])

    def test_other_vendors_use_bridge_ports(self):
        ports, _ = access_ports(config(vm_vlan=None), ["GigabitEthernet0/1"], "HP")
        self.assertEqual(ports, [1, 2, 3])

    def test_non_ethernet_and_uplinks_fall_out(self):
        c = config(bridge_ports={1: 1, 10: 10, 100: 100})
        ports, _ = access_ports(c, ["Gi0/1"], "HP")
        self.assertEqual(ports, [1])

    def test_no_table_gives_a_reason_not_an_empty_list(self):
        self.assertEqual(access_ports(config(vm_vlan=None), [], "Cisco"),
                         (None, "the VLAN membership table was not read"))
        self.assertEqual(access_ports(config(bridge_ports=None), [], "HP"),
                         (None, "the bridge port table was not read"))
        self.assertEqual(access_ports(config(interfaces=None), [], "HP"),
                         (None, "the interface table was not read"))

    def test_port_names_compare_in_any_form(self):
        self.assertEqual(port_key("FastEthernet1/0/3"), port_key("Fa1/0/3"))
        self.assertEqual(port_key("GigabitEthernet0"), port_key("Gi0"))
        self.assertNotEqual(port_key("Gi1/0/1"), port_key("Gi1/0/10"))


class TestChecks(unittest.TestCase):
    def check(self, check_id, cfg, node=None, probe=False):
        out = evaluate_device(node or switch(), cfg, probe, "cisco_ios")
        entry = next(c for c in out["config_checks"] if c["id"] == check_id)
        found = [f for f in out["config_findings"] if f["id"] == check_id]
        return entry["result"], entry.get("reason"), found[0]["evidence"] if found else None

    def test_clean_switch_passes_every_check_it_can(self):
        out = evaluate_device(switch(), config(probe={"public": False, "private": False}),
                              True, "cisco_ios")
        self.assertEqual(set(results(out).values()), {"pass"})
        self.assertEqual(out["config_findings"], [])

    def test_telnet_and_http(self):
        for check_id, port in (("mgmt-telnet-enabled", 23), ("mgmt-http-enabled", 80)):
            self.assertEqual(self.check(check_id, config())[0], "pass")
            self.assertEqual(self.check(check_id, config(tcp={"read": True, "ports": [port]})),
                             ("fail", None, {"port": port}))
            self.assertEqual(self.check(check_id, config(tcp={"read": False, "ports": []}))[0],
                             "unknown")
            self.assertEqual(self.check(check_id, config(tcp=None))[0], "unknown")

    def test_connection_test_outcomes(self):
        silent = {"read": False, "ports": []}
        for check_id, port in (("mgmt-telnet-enabled", 23), ("mgmt-http-enabled", 80)):
            self.assertEqual(
                self.check(check_id, config(tcp=silent, connect={port: "accepted"})),
                ("fail", None, {"port": port,
                                "found_by": "the port answered a connection test"}))
            self.assertEqual(self.check(check_id, config(tcp=silent,
                                                         connect={port: "refused"}))[0], "pass")
            self.assertEqual(self.check(check_id, config(tcp=silent, connect={port: "no_answer"})),
                             ("unknown", "no answer from the scanner's position", None))
            self.assertIn("connection test is not enabled", self.check(check_id, config(tcp=silent))[1])
            # a device that lists its listeners is judged by the list alone
            self.assertEqual(self.check(check_id, config(connect={port: "accepted"}))[0], "pass")
        # read back from JSON, the port numbers are strings
        cfg = json.loads(json.dumps(config(tcp=silent, connect={23: "accepted", 80: "refused"})))
        self.assertEqual(results(evaluate_device(switch(), cfg, False, "cisco_ios"))
                         ["mgmt-telnet-enabled"], "fail")

    def test_snmp_without_authentication(self):
        self.assertEqual(self.check("snmp-no-auth", config())[0], "pass")
        self.assertEqual(self.check("snmp-no-auth", config(snmp={"version": "v2c"})),
                         ("fail", None, {"snmp_version": "v2c"}))
        self.assertEqual(self.check("snmp-no-auth", config(snmp={}))[0], "unknown")

    def test_default_community(self):
        cid = "snmp-default-community"
        self.assertEqual(self.check(cid, config()), ("not_checked", "probe not enabled", None))
        self.assertEqual(self.check(cid, config(probe={"public": False, "private": False}),
                                    probe=True)[0], "pass")
        self.assertEqual(self.check(cid, config(probe={"public": False, "private": True}),
                                    probe=True),
                         ("fail", None, {"communities": ["private"],
                                         "found_by": "the default-name probe"}))
        self.assertEqual(self.check(cid, config(), probe=True)[0], "unknown")
        # the scan's own credential is a factory name: raised with the probe off
        own = config(snmp={"version": "v2c", "default_name": "public"})
        self.assertEqual(self.check(cid, own)[0], "fail")
        self.assertEqual(self.check(cid, own)[2]["found_by"], "the scan's own credential")

    def test_spare_ports_in_a_vlan_in_use(self):
        cid = "spare-ports-in-used-vlan"
        self.assertEqual(self.check(cid, config())[0], "pass")
        ifs = config()["interfaces"]
        ifs[2] = iface("FastEthernet0/2", oper=t.DOWN, last_change=1000)   # spare, VLAN 10 live
        self.assertEqual(self.check(cid, config(interfaces=ifs)),
                         ("fail", None, {"ports": [{"port": "FastEthernet0/2", "vlan": 10}],
                                         "total": 1, "enabled": 1, "shut_down": 0,
                                         "down_recently_not_counted": 0,
                                         "unused_vlans": []}))
        # shut down or not, the same result; only the detail differs
        ifs[2] = iface("FastEthernet0/2", admin=t.DOWN, oper=t.DOWN, last_change=1000)
        result = self.check(cid, config(interfaces=ifs))
        self.assertEqual((result[0], result[2]["enabled"], result[2]["shut_down"]),
                         ("fail", 0, 1))

    def test_spare_port_in_an_unused_vlan_passes(self):
        cid = "spare-ports-in-used-vlan"
        ifs = config()["interfaces"]
        ifs[3] = iface("FastEthernet0/3", oper=t.DOWN, last_change=1000)   # alone in VLAN 20
        self.assertEqual(self.check(cid, config(interfaces=ifs))[0], "pass")
        # ... unless a host was learned on VLAN 20 somewhere
        out = evaluate_device(switch(), config(interfaces=ifs), False, "cisco_ios",
                              vlans_in_use={20})
        self.assertEqual(results(out)[cid], "fail")

    def test_a_management_vlan_is_in_use(self):
        # VLAN 99 has no live access port and no host, but a VLAN interface
        # that is up: the switch's own address lives there
        cid = "spare-ports-in-used-vlan"
        ifs = config()["interfaces"]
        ifs[3] = iface("FastEthernet0/3", oper=t.DOWN, last_change=1000)
        mgmt = config(interfaces=ifs, vm_vlan={1: 10, 2: 10, 3: 99})
        self.assertEqual(self.check(cid, mgmt), ("pass", None, None))      # alone: unused
        for name in ("Vlan99", "Vl99", "Vlan-interface99"):
            own = {**ifs, 199: iface(name, if_type=53)}
            result = self.check(cid, config(interfaces=own, vm_vlan={1: 10, 2: 10, 3: 99}))
            self.assertEqual((result[0], result[2]["ports"]),
                             ("fail", [{"port": "FastEthernet0/3", "vlan": 99}]), name)
        # a VLAN interface that is down proves nothing
        down = {**ifs, 199: iface("Vlan99", oper=t.DOWN, if_type=53)}
        self.assertEqual(self.check(cid, config(interfaces=down,
                                                vm_vlan={1: 10, 2: 10, 3: 99}))[0], "pass")
        # another polled device's up interface counts too (the stage passes it)
        out = evaluate_device(switch(), mgmt, False, "cisco_ios", vlans_in_use={99})
        self.assertEqual(results(out)[cid], "fail")

    def test_a_true_parking_vlan_passes_and_is_named(self):
        cid = "spare-ports-in-used-vlan"
        ifs = config()["interfaces"]
        ifs[3] = iface("FastEthernet0/3", admin=t.DOWN, oper=t.DOWN, last_change=1000)
        out = evaluate_device(switch(), config(interfaces=ifs, vm_vlan={1: 10, 2: 10, 3: 999}),
                              False, "cisco_ios", vlans_in_use={20, 99})
        entry = next(c for c in out["config_checks"] if c["id"] == cid)
        self.assertEqual(entry, {"id": cid, "title": "Spare access ports in a VLAN in use",
                                 "result": "pass", "unused_vlans": [999]})

    def test_layer_3_vlan_names(self):
        named = {1: iface("Vlan10", if_type=53), 2: iface("Vl20", if_type=53),
                 3: iface("Vlan-interface30", if_type=136), 4: iface("GigabitEthernet0.40"),
                 5: iface("Dot11Radio0.50"), 6: iface("Vlan60", oper=t.DOWN),
                 7: iface("FastEthernet0/1"), 8: iface("Port-channel1"), 9: iface("BVI1"),
                 10: iface("GigabitEthernet1/0/1")}
        self.assertEqual(l3_vlans({"interfaces": named}), {10, 20, 30, 40, 50})
        self.assertEqual(l3_vlans(None), set())

    def test_vlan_1_is_always_in_use(self):
        ifs = config()["interfaces"]
        ifs[3] = iface("FastEthernet0/3", oper=t.DOWN, last_change=1000)
        result = self.check("spare-ports-in-used-vlan",
                            config(interfaces=ifs, vm_vlan={1: 10, 2: 10, 3: 1}))
        self.assertEqual(result[2]["ports"], [{"port": "FastEthernet0/3", "vlan": 1}])

    def test_recently_down_ports_are_not_counted(self):
        ifs = config()["interfaces"]
        ifs[2] = iface("FastEthernet0/2", oper=t.DOWN, last_change=5_000_000)   # after boot
        self.assertEqual(self.check("spare-ports-in-used-vlan", config(interfaces=ifs))[0], "pass")
        ifs[1] = iface("FastEthernet0/1", oper=t.DOWN, last_change=0)
        ifs[3] = iface("FastEthernet0/3", oper=t.UP)
        result = self.check("spare-ports-in-used-vlan",
                            config(interfaces=ifs, vm_vlan={1: 10, 2: 10, 3: 10}))
        self.assertEqual((result[2]["total"], result[2]["down_recently_not_counted"]), (1, 1))

    def test_spare_ports_unknown_without_vlan_or_state(self):
        cid = "spare-ports-in-used-vlan"
        self.assertEqual(self.check(cid, config(vm_vlan=None, pvid=None), switch("HP")),
                         ("unknown", "the VLAN of each port was not read", None))
        ifs = config()["interfaces"]
        ifs[3] = iface("FastEthernet0/3", admin=None, oper=None)
        self.assertEqual(self.check(cid, config(interfaces=ifs))[0], "unknown")
        ifs[3] = iface("FastEthernet0/3", oper=t.DOWN, last_change=1000)
        self.assertEqual(self.check(cid, config(interfaces=ifs, uptime=None))[0], "unknown")

    def test_default_vlan_lists_linked_ports_first(self):
        cid = "access-ports-default-vlan"
        self.assertEqual(self.check(cid, config())[0], "pass")
        ifs = config()["interfaces"]
        ifs[1] = iface("FastEthernet0/1", oper=t.DOWN)
        result = self.check(cid, config(interfaces=ifs, vm_vlan={1: 1, 2: 10, 3: 1}))
        self.assertEqual(result, ("fail", None, {"ports": ["FastEthernet0/3", "FastEthernet0/1"],
                                                 "total": 2, "with_link": 1}))

    def test_default_vlan_from_pvid_elsewhere(self):
        cid = "access-ports-default-vlan"
        hp = switch("HP")
        self.assertEqual(self.check(cid, config(vm_vlan=None), hp)[0], "pass")
        self.assertEqual(self.check(cid, config(vm_vlan=None, pvid={1: 1, 2: 10, 3: 20}), hp)[0],
                         "fail")
        # PVID 0 (an access point's bridge) or no PVID at all: not known
        self.assertEqual(self.check(cid, config(vm_vlan=None, pvid={1: 0, 2: 0, 3: 0}), hp)[0],
                         "unknown")
        self.assertEqual(self.check(cid, config(vm_vlan=None, pvid=None), hp)[0], "unknown")

    def test_bpdu_guard(self):
        cid = "bpdu-guard-missing"
        self.assertEqual(self.check(cid, config())[0], "pass")
        off = {"global_guard": False, "global_portfast": 2,
               "ports": {bp: {"portfast": 4, "guard": 3} for bp in (1, 2, 3)}}
        self.assertEqual(self.check(cid, config(bpdu=off))[2]["total"], 3)
        # ports differ: each access port is looked up through its bridge port
        mixed = copy.deepcopy(off)
        mixed["ports"][2]["guard"] = 1
        self.assertEqual(self.check(cid, config(bpdu=mixed))[2]["ports"],
                         ["FastEthernet0/1", "FastEthernet0/3"])
        self.assertEqual(self.check(cid, config(bpdu=None))[0], "unknown")
        # ports differ and a port's bridge port is not known
        on = copy.deepcopy(mixed)
        on["ports"] = {1: {"portfast": 1, "guard": 1}, 2: {"portfast": 1, "guard": 2}}
        self.assertEqual(self.check(cid, config(bpdu=on, bridge_ports={1: 1, 2: 10}))[0],
                         "unknown")

    def test_port_security(self):
        cid = "port-security-disabled"
        self.assertEqual(self.check(cid, config())[0], "pass")
        self.assertEqual(self.check(cid, config(port_security={"global": True,
                                                               "ports": {1: True, 2: False,
                                                                         3: True}}))[2],
                         {"ports": ["FastEthernet0/2"], "total": 1})
        # enabled per port, but switched off globally
        self.assertEqual(self.check(cid, config(port_security={"global": False,
                                                               "ports": {1: True, 2: True,
                                                                         3: True}}))[0], "fail")
        self.assertEqual(self.check(cid, config(port_security=None))[0], "unknown")
        self.assertEqual(self.check(cid, config(port_security={"global": True,
                                                               "ports": {1: True}}))[0],
                         "unknown")

    def test_not_applicable(self):
        router = {"role": "router", "vendor": "Cisco", "uplink_ports": []}
        out = evaluate_device(router, config(), False, "cisco_ios")
        for cid in IDS[4:]:
            self.assertEqual(results(out)[cid], "not_applicable", cid)
        hp = evaluate_device(switch("HP"), config(vm_vlan=None), False, None)
        self.assertEqual(results(hp)["bpdu-guard-missing"], "not_applicable")
        self.assertEqual(results(hp)["port-security-disabled"], "not_applicable")


class TestMissingDataIsNeverAPass(unittest.TestCase):
    def test_no_data_at_all(self):
        for cfg, reason in ((None, "configuration data was not collected"),
                            ({"failed": True}, "reading the configuration tables failed")):
            out = evaluate_device(switch(), cfg, False, "cisco_ios")
            self.assertEqual(set(results(out).values()), {"unknown"})
            self.assertEqual({c["reason"] for c in out["config_checks"]}, {reason})

    def test_every_table_empty(self):
        empty = {"snmp": {}, "probe": None, "uptime": None, "tcp": None, "interfaces": None,
                 "bridge_ports": None, "pvid": None, "vm_vlan": None, "port_security": None,
                 "bpdu": None}
        out = evaluate_device(switch(), empty, True, "cisco_ios")
        self.assertNotIn("pass", results(out).values())
        self.assertEqual(out["config_findings"], [])

    def test_each_table_missing_on_its_own(self):
        for key in ("tcp", "interfaces", "bridge_ports", "pvid", "vm_vlan",
                    "port_security", "bpdu"):
            for vendor in ("Cisco", "HP"):
                out = evaluate_device(switch(vendor), config(**{key: None}), False, None)
                clean = evaluate_device(switch(vendor), config(), False, None)
                for cid, result in results(out).items():
                    if result == "pass":
                        self.assertEqual(results(clean)[cid], "pass", (key, vendor, cid))


class TestEvidenceCap(unittest.TestCase):
    def test_at_most_twenty_names_with_the_total(self):
        ifs = {i: iface(f"FastEthernet0/{i}", oper=t.DOWN) for i in range(1, 31)}
        cfg = config(interfaces=ifs, vm_vlan={i: 10 for i in ifs},
                     bridge_ports={i: i for i in ifs})
        out = evaluate_device(switch(uplinks=()), cfg, False, "cisco_ios", vlans_in_use={10})
        evidence = finding(out, "spare-ports-in-used-vlan")["evidence"]
        self.assertEqual(len(evidence["ports"]), EVIDENCE_CAP)
        self.assertEqual(evidence["total"], 30)
        self.assertEqual(evidence["ports"][0], {"port": "FastEthernet0/1", "vlan": 10})


class TestFinding(unittest.TestCase):
    def test_fields_and_summary(self):
        out = evaluate_device(switch(), config(snmp={"version": "v2c", "default_name": None}),
                              False, "cisco_ios")
        f = finding(out, "snmp-no-auth")
        self.assertEqual(set(f), {"id", "title", "severity", "why", "remediation",
                                  "references", "cwe", "evidence"})
        self.assertTrue(all("scope" not in r for r in f["references"]))
        self.assertEqual(out["config_summary"], {
            "checks": 8,
            "results": {"pass": 6, "fail": 1, "not_applicable": 0, "unknown": 0,
                        "not_checked": 1},
            "findings": {"high": 0, "medium": 1, "low": 0, "advisory": 0}})

    def test_json_round_trip_gives_the_same_result(self):
        cfg = captured("l3", "Cisco")
        node = {"role": "l3-switch", "vendor": "Cisco", "uplink_ports": ["Fa1/0/1"]}
        direct = evaluate_device(node, cfg, False, "cisco_ios")
        via_json = evaluate_device(node, json.loads(json.dumps(cfg)), False, "cisco_ios")
        self.assertEqual(direct, via_json)


class TestStage(unittest.TestCase):
    def graph(self):
        return {"nodes": [
            {"node_id": "device:aa", "kind": "device", "pollable": True, "chassis_id": "aa",
             "role": "l2-switch", "vendor": "Cisco", "uplink_ports": ["Gi0/1"],
             "risk_score": 3.0},
            {"node_id": "device:bb", "kind": "device", "pollable": True, "chassis_id": "bb",
             "role": "router", "vendor": "Cisco", "uplink_ports": []},
            {"node_id": "device:cc", "kind": "device", "pollable": False, "chassis_id": "cc",
             "role": "unknown"},
            {"node_id": "endpoint:1", "kind": "endpoint"},
        ]}

    def test_polled_devices_only(self):
        graph = self.graph()
        network = {"nodes": [{"chassis_id": "aa", "config_data": config()},
                             {"chassis_id": "bb", "config_data": {"failed": True}}]}
        stage = run_stage(graph, network, False)
        aa, bb, cc, ep = graph["nodes"]
        self.assertIn("config_checks", aa)
        self.assertEqual(aa["risk_score"], 3.0)
        self.assertEqual(bb["config_summary"]["results"]["unknown"], 4)
        self.assertNotIn("config_checks", cc)
        self.assertNotIn("config_checks", ep)
        self.assertEqual(stage.warnings, [{"type": "checklist_unreadable",
                                           "node_ids": ["device:bb"]}])
        self.assertEqual(stage.block["devices_checked"], 2)
        self.assertEqual(stage.block["probe_enabled"], False)
        self.assertEqual(stage.block["source"], "scan")
        self.assertEqual(stage.block["results"]["not_checked"], 1)   # bb: unknown, not "not checked"

    def test_vlans_in_use_come_from_hosts_and_l3_interfaces(self):
        ifs = config()["interfaces"]
        ifs[3] = iface("FastEthernet0/3", oper=t.DOWN, last_change=1000)    # alone in VLAN 20
        network = {"nodes": [{"chassis_id": "aa", "config_data": config(interfaces=ifs)}]}
        result = lambda g: next(c["result"] for c in g["nodes"][0]["config_checks"]  # noqa: E731
                                if c["id"] == "spare-ports-in-used-vlan")
        graph = self.graph()
        run_stage(graph, network, False)
        self.assertEqual(result(graph), "pass")
        graph = self.graph()
        graph["nodes"][3]["vlan"] = 20
        run_stage(graph, network, False)
        self.assertEqual(result(graph), "fail")
        # an up VLAN interface on another polled device (bb, the router)
        graph = self.graph()
        router = config(interfaces={20: iface("Vlan20", if_type=53)})
        run_stage(graph, {"nodes": network["nodes"] + [{"chassis_id": "bb",
                                                         "config_data": router}]}, False)
        self.assertEqual(result(graph), "fail")

    def test_data_missing_is_warned(self):
        graph = self.graph()
        stage = run_stage(graph, {"nodes": [{"chassis_id": "aa"}]}, False)
        self.assertEqual(stage.warnings, [{"type": "checklist_data_missing",
                                           "node_ids": ["device:aa", "device:bb"]}])
        self.assertEqual(stage.block["findings"], {"high": 0, "medium": 0, "low": 0,
                                                   "advisory": 0})


NEW_DEVICE_FIELDS = {"config_checks", "config_findings", "config_summary"}


class TestPipeline(unittest.TestCase):
    def setUp(self):
        async def go():
            crawler = Crawler(lab(), concurrency=4, max_nodes=50, queue_maxsize=50,
                              checklist=True)
            await crawler.seed(["172.20.20.254"])
            return await crawler.run()
        self.tmp = tempfile.mkdtemp()
        self.network = os.path.join(self.tmp, "network.json")
        with open(self.network, "w") as f:
            json.dump(build_document(*asyncio.run(go())), f)
        self.graph_path = os.path.join(self.tmp, "graph.json")

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def run_pipeline(self, *extra):
        argv = ["--no-endpoints", "--no-device-cves", "--no-cve-vectors", "--no-name-lookup", "--network", self.network,
                "-o", self.graph_path, *extra]
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(Pipeline().run(argv), 0)
        with open(self.graph_path) as f:
            return json.load(f)

    def test_off_gives_todays_document(self):
        graph = self.run_pipeline("--no-checklist")
        self.assertNotIn("checklist", graph["metadata"])
        self.assertNotIn("checklist_s", graph["metadata"]["timing"])
        for node in graph["nodes"]:
            self.assertFalse(set(node) & NEW_DEVICE_FIELDS, node["node_id"])
            self.assertNotIn("config_data", node)

    def test_on_adds_exactly_the_documented_fields(self):
        before = self.run_pipeline("--no-checklist")
        after = self.run_pipeline()
        old = {n["node_id"]: n for n in before["nodes"]}
        checked = 0
        for node in after["nodes"]:
            was = old[node["node_id"]]
            if node["kind"] == "device" and node.get("pollable"):
                self.assertEqual(set(node) - set(was), NEW_DEVICE_FIELDS, node["node_id"])
                node = {k: v for k, v in node.items() if k not in NEW_DEVICE_FIELDS}
                checked += 1
            self.assertEqual(node, was, node["node_id"])
        self.assertEqual(after["edges"], before["edges"])
        self.assertGreater(checked, 0)
        meta = {k: v for k, v in after["metadata"].items() if k != "checklist"}
        meta_before = dict(before["metadata"])
        for m in (meta, meta_before):
            m["timing"] = {k: v for k, v in m["timing"].items() if not k.endswith("_s")
                           and k not in ("started_at", "finished_at")}
            m.pop("scan_time")
        self.assertEqual(meta, meta_before)
        self.assertIsInstance(after["metadata"]["timing"]["checklist_s"], float)
        self.assertEqual(set(after["metadata"]["checklist"]),
                         {"devices_checked", "results", "findings", "probe_enabled",
                          "port_test_enabled", "source"})
        self.assertFalse(after["metadata"]["checklist"]["port_test_enabled"])
        self.assertEqual(after["metadata"]["checklist"]["devices_checked"], checked)
        self.assertFalse(after["metadata"]["checklist"]["probe_enabled"])

    def test_connection_test_flag_is_recorded(self):
        graph = self.run_pipeline("--check-management-ports")
        self.assertTrue(graph["metadata"]["checklist"]["port_test_enabled"])
        l3 = next(n for n in graph["nodes"] if n["node_id"] == f"device:{L3_CID}")
        telnet = next(c for c in l3["config_checks"] if c["id"] == "mgmt-telnet-enabled")
        # a --network file from a scan without the test: says so, never a pass
        self.assertIn("results were not collected", telnet["reason"])

    def test_raw_tables_stay_off_the_graph(self):
        graph = self.run_pipeline()
        l3 = next(n for n in graph["nodes"] if n["node_id"] == f"device:{L3_CID}")
        self.assertNotIn("config_data", l3)
        self.assertEqual(len(l3["config_checks"]), 8)


if __name__ == "__main__":
    unittest.main()
