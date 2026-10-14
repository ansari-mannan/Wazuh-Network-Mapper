"""The per-device ``ports`` list: the IF-MIB columns behind it and each port's
state (up, link_lost, unused, shutdown). Synthetic rows only."""

import offline  # noqa: F401  (no test reaches the internet)
import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest

from vulnmapper.assemble import assemble
from vulnmapper.assemble.ports import set_port_states
from vulnmapper.network import parse

IF = "1.3.6.1.2.1.2.2.1"
IFX = "1.3.6.1.2.1.31.1.1.1"


def rows(column, values):
    return [(f"{column}.{index}", value) for index, value in values.items()]


class TestBuildPorts(unittest.TestCase):
    def test_columns_join_on_ifindex_in_ifindex_order(self):
        ports = parse.build_ports(
            rows(f"{IF}.8", {"10": "1", "2": "2", "100": "down(2)"}),
            rows(f"{IF}.7", {"10": "1", "2": "up(1)", "100": "2"}),
            rows(f"{IF}.3", {"10": "6", "2": "ethernetCsmacd(6)", "100": "53"}),
            rows(f"{IFX}.15", {"10": "1000", "2": "100"}),
            rows(f"{IFX}.18", {"10": "to core", "2": "  "}),
            rows(f"{IFX}.1", {"2": "Fa0/2", "10": "Gi0/1", "100": "Vl100"}))
        self.assertEqual(ports, [
            {"name": "Fa0/2", "oper": "down", "admin": "up", "type": 6, "speed_mbps": 100,
             "alias": None},
            {"name": "Gi0/1", "oper": "up", "admin": "up", "type": 6, "speed_mbps": 1000,
             "alias": "to core"},
            {"name": "Vl100", "oper": "down", "admin": "down", "type": 53, "speed_mbps": None,
             "alias": None}])

    def test_missing_columns_leave_fields_empty(self):
        (port,) = parse.build_ports(rows(f"{IF}.8", {"7": "1"}))
        self.assertEqual(port, {"name": "7", "oper": "up", "admin": None, "type": None,
                                "speed_mbps": None, "alias": None})


def graph(ports, neighbor_ports=(), port_status=None):
    return {"nodes": [{"node_id": "device:x", "neighbor_ports": list(neighbor_ports),
                       "port_status": port_status or {},
                       "ports": [dict(p) for p in ports]}]}


def port(name, oper="down", admin="up", alias=None):
    return {"name": name, "oper": oper, "admin": admin, "alias": alias}


def states(doc):
    return {p["name"]: p["state"] for p in doc["nodes"][0]["ports"]}


class TestPortStates(unittest.TestCase):
    PORTS = [port("FastEthernet0/1", oper="up"), port("FastEthernet0/2"),
             port("FastEthernet0/3"), port("FastEthernet0/4", admin="down"),
             port("FastEthernet0/5", oper="up", admin="down"), port("port7", alias="WAN-up")]

    def test_states_without_history(self):
        doc = graph(self.PORTS, neighbor_ports=["Fa0/2", "WAN-up"])
        set_port_states(doc)
        self.assertEqual(states(doc), {
            "FastEthernet0/1": "up",
            "FastEthernet0/2": "link_lost",   # a neighbour is listed on it
            "FastEthernet0/3": "unused",
            "FastEthernet0/4": "shutdown",
            "FastEthernet0/5": "shutdown",    # admin down wins over oper
            "port7": "link_lost"})            # neighbour names it by alias

    def test_up_in_the_previous_scan_means_link_lost(self):
        doc = graph(self.PORTS)
        previous = graph([], port_status={"Fa0/3": "up", "Fa0/4": "up"})
        set_port_states(doc, previous)
        self.assertEqual(states(doc)["FastEthernet0/3"], "link_lost")
        self.assertEqual(states(doc)["FastEthernet0/4"], "shutdown")
        self.assertEqual(states(doc)["FastEthernet0/2"], "unused")

    def test_another_nodes_history_does_not_count(self):
        doc = graph(self.PORTS)
        previous = {"nodes": [{"node_id": "device:y", "port_status": {"Fa0/3": "up"}}]}
        set_port_states(doc, previous)
        self.assertEqual(states(doc)["FastEthernet0/3"], "unused")


class TestPreviousGraphOption(unittest.TestCase):
    """--previous-graph reaches the assembler; a missing file is no history."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.network = os.path.join(self.tmp, "network.json")
        node = {"chassis_id": "00:00:5e:00:53:01", "ip": "192.0.2.1", "status": "online",
                "pollable": True, "lldp_cap_enabled": "0x0004", "neighbor_ports": [],
                "port_status": {"Gi0/1": "down"},
                "ports": [{"name": "Gi0/1", "oper": "down", "admin": "up", "type": 6,
                           "speed_mbps": 1000, "alias": None}]}
        with open(self.network, "w") as f:
            json.dump({"nodes": [node], "edges": []}, f)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def state(self, *extra):
        from vulnmapper.pipeline import Pipeline
        out = os.path.join(self.tmp, "graph.json")
        argv = ["--no-endpoints", "--network", self.network, "--no-device-cves",
                "--no-cve-vectors", "--no-checklist", "--no-attack-paths", "--no-name-lookup",
                "-o", out, *extra]
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(Pipeline().run(argv), 0)
        with open(out) as f:
            (node,) = [n for n in json.load(f)["nodes"] if n.get("ports")]
        return node["ports"][0]["state"]

    def test_previous_graph_turns_unused_into_link_lost(self):
        previous = os.path.join(self.tmp, "previous.json")
        with open(previous, "w") as f:
            json.dump({"nodes": [{"node_id": "device:00:00:5e:00:53:01",
                                  "port_status": {"Gi0/1": "up"}}]}, f)
        self.assertEqual(self.state(), "unused")
        self.assertEqual(self.state("--previous-graph", previous), "link_lost")
        self.assertEqual(self.state("--previous-graph", os.path.join(self.tmp, "none.json")),
                         "unused")

    def test_assemble_without_history(self):
        with open(self.network) as f:
            doc = assemble([], json.load(f))
        (node,) = doc["nodes"]
        self.assertEqual(node["ports"][0]["state"], "unused")


if __name__ == "__main__":
    unittest.main()
