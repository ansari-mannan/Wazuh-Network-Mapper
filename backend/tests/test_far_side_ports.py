"""Ports known only from the far side of a link: a device that answers SNMP
but lists no LLDP neighbours (FortiOS) still gets the uplink port its
neighbour names, marked as inferred. Synthetic chassis ids only."""

import unittest

from vulnmapper.assemble import assemble
from vulnmapper.network.crawl import infer_far_side_ports
from vulnmapper.network.document import build_document
from vulnmapper.network.model import Device, Link

SW, FW, PEER, PHONE, AP = ("0c:00:00:00:aa:01", "0c:00:00:00:aa:02", "0c:00:00:00:aa:03",
                           "0c:00:00:00:aa:04", "0c:00:00:00:aa:05")


def devices():
    return {
        SW: Device(chassis_id=SW, ip="10.20.0.1", hostname="core-sw", pollable=True,
                   neighbor_ports=["Gi1/0/1", "Gi1/0/2", "Gi1/0/3"], uplink_ports=["Gi1/0/1", "Gi1/0/2"]),
        FW: Device(chassis_id=FW, ip="10.20.0.254", hostname="edge-fw", vendor="Fortinet",
                   pollable=True, port_status={"port1": "up", "wan1": "up"}),
        PEER: Device(chassis_id=PEER, ip="10.20.0.2", hostname="access-sw", pollable=True,
                     neighbor_ports=["Gi0/1"], uplink_ports=["Gi0/1"]),
        PHONE: Device(chassis_id=PHONE, hostname="phone", pollable=False),
        # reported its uplink over CDP only ("Gi0"); the crawl keeps no CDP link
        # for a pair LLDP already linked, so no reverse link exists for it
        AP: Device(chassis_id=AP, ip="10.20.0.30", hostname="ap", pollable=True,
                   neighbor_ports=["Gi0"], uplink_ports=["Gi0"]),
    }


LINKS = [
    Link(SW, FW, local_port="Gi1/0/1", remote_port="to-core-sw"),   # only the switch sees it
    Link(SW, PEER, local_port="Gi1/0/2", remote_port="Gi0/1"),          # both ends report
    Link(PEER, SW, local_port="Gi0/1", remote_port="Gi1/0/2"),
    Link(SW, PHONE, local_port="Gi1/0/3", remote_port="LAN"),            # an unpolled neighbour
    Link(SW, AP, local_port="Gi1/0/4", remote_port="GigabitEthernet0"),
]


class TestInferFarSidePorts(unittest.TestCase):
    def test_a_device_without_lldp_gets_the_port_its_neighbour_names(self):
        devs = devices()
        infer_far_side_ports(devs, LINKS)
        fw = devs[FW]
        self.assertEqual((fw.neighbor_ports, fw.uplink_ports, fw.inferred_ports),
                         (["to-core-sw"], ["to-core-sw"], ["to-core-sw"]))

    def test_a_device_that_reports_the_link_keeps_its_own_ports(self):
        devs = devices()
        infer_far_side_ports(devs, LINKS)
        self.assertEqual((devs[PEER].neighbor_ports, devs[PEER].inferred_ports), (["Gi0/1"], []))
        self.assertEqual(devs[SW].inferred_ports, [])
        self.assertEqual(devs[PHONE].neighbor_ports, [])                  # never polled: no ports

    def test_a_device_that_reported_over_cdp_is_not_given_a_second_name(self):
        devs = devices()
        infer_far_side_ports(devs, LINKS)
        self.assertEqual((devs[AP].neighbor_ports, devs[AP].inferred_ports), (["Gi0"], []))

    def test_the_mark_reaches_the_graph(self):
        devs = devices()
        infer_far_side_ports(devs, LINKS)
        doc = build_document(list(devs.values()), LINKS)
        fw = next(n for n in assemble([], doc)["nodes"] if n["node_id"] == f"device:{FW}")
        self.assertEqual(fw["inferred_ports"], ["to-core-sw"])
        self.assertEqual(fw["uplink_ports"], ["to-core-sw"])
        sw = next(n for n in assemble([], doc)["nodes"] if n["node_id"] == f"device:{SW}")
        self.assertNotIn("inferred_ports", sw)


if __name__ == "__main__":
    unittest.main()
