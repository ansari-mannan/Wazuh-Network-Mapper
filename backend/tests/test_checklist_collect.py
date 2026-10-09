"""Collecting the configuration-check tables while a device is polled.

Fake SNMP client over the capture fixtures: no network. Every request is
recorded, so the cost per device and the probe's behaviour are asserted.
"""

import asyncio
import unittest
from collections import Counter
from unittest import mock

from snmp_fakes import FakeSnmpClient, load_rows
from vulnmapper.checklist import tables as t
from vulnmapper.checklist import collect as c
from vulnmapper.checklist.collect import collect_config
from vulnmapper.network import parse
from vulnmapper.network.crawl import Crawler, build_document

IP = "10.0.0.2"
CISCO_TABLES = {t.VM_VLAN, t.CPS_IF_ENABLE, t.STPX_PORT_MODE, t.STPX_PORT_BPDU_GUARD}


def collect(name, vendor, probe=False, **fake_kw):
    client = FakeSnmpClient({IP: load_rows(f"checklist_{name}.snmp")}, **fake_kw)
    data = asyncio.run(collect_config(client, IP, vendor, probe=probe))
    return data, client


def kinds(client):
    return Counter(c[0] for c in client.calls)


class TestCollect(unittest.TestCase):
    def test_cisco_switch(self):
        data, client = collect("l3", "Cisco")
        self.assertEqual(data["snmp"], {"version": "v2c", "default_name": None})
        self.assertEqual(data["uptime"], 2733082)
        self.assertEqual(data["tcp"], {"read": False, "ports": []})
        self.assertEqual(len(data["interfaces"]), 40)
        self.assertEqual(len(data["vm_vlan"]), 23)
        self.assertTrue(data["port_security"]["global"])
        self.assertNotIn("port_ifindex", data["bpdu"])      # every port alike: no mapping needed
        self.assertIsNone(data["probe"])
        # 14 walks (ifName empty in the capture, so ifDescr too) and 2 GETs
        self.assertEqual(kinds(client), {"walk": 14, "get": 2})

    def test_hp_switch_reads_no_cisco_tables(self):
        data, client = collect("hp", "HP")
        self.assertEqual(data["tcp"]["ports"], [23, 80])
        self.assertIsNone(data["vm_vlan"])
        self.assertIsNone(data["port_security"])
        self.assertIsNone(data["bpdu"])
        walked = {c[2] for c in client.calls if c[0] == "walk"}
        self.assertFalse(walked & CISCO_TABLES)
        self.assertEqual(kinds(client), {"walk": 10, "get": 1})

    def test_table_not_answered_costs_one_request_and_is_none(self):
        rows = [r for r in load_rows("checklist_l3.snmp") if not r[0].startswith(t.CPS_IF_ENABLE)]
        client = FakeSnmpClient({IP: rows})
        data = asyncio.run(collect_config(client, IP, "Cisco"))
        self.assertIsNone(data["port_security"])
        self.assertEqual(len([c for c in client.calls if c[0] == "walk"
                              and c[2] == t.CPS_IF_ENABLE]), 1)

    def test_mixed_bpdu_guard_reads_each_access_vlans_bridge_ports(self):
        rows = [(o, "1") if o == f"{t.STPX_PORT_BPDU_GUARD}.5" else (o, v)
                for o, v in load_rows("checklist_l3.snmp")]
        vlan_rows = {(IP, 40): [(f"{t.DOT1D_BASE_PORT_IFINDEX}.5", "10003")],
                     (IP, 10): [(f"{t.DOT1D_BASE_PORT_IFINDEX}.10", "10008")]}
        client = FakeSnmpClient({IP: rows}, vlan_rows=vlan_rows)
        data = asyncio.run(collect_config(client, IP, "Cisco"))
        self.assertEqual(data["bpdu"]["port_ifindex"], {5: 10003, 10: 10008})
        vlans = sorted(c[3] for c in client.calls if c[0] == "walk_vlan")
        self.assertEqual(vlans, [1, 10, 20, 30, 40, 50, 99, 100])   # every access VLAN once


class TestProbe(unittest.TestCase):
    def test_off_by_default_makes_no_probe_request(self):
        _data, client = collect("l3", "Cisco", probe_answers={IP: ("public",)})
        self.assertEqual([c for c in client.calls if c[0] == "probe"], [])

    def test_on_makes_exactly_two_reads_never_a_write(self):
        data, client = collect("l3", "Cisco", probe=True, probe_answers={IP: ("public",)})
        probes = [c for c in client.calls if c[0] == "probe"]
        self.assertEqual([(c[2], c[3]) for c in probes],
                         [("public", t.SYS_NAME), ("private", t.SYS_NAME)])
        self.assertTrue(all(c[4] <= 1.0 for c in probes))
        self.assertEqual(data["probe"], {"public": True, "private": False})
        self.assertEqual(set(kinds(client)), {"walk", "get", "probe"})   # reads only

    def test_working_default_name_is_reported_without_a_probe(self):
        data, client = collect("l3", "Cisco", default_name={IP: "public"})
        self.assertEqual(data["snmp"]["default_name"], "public")
        self.assertNotIn("probe", kinds(client))


class TestCrawl(unittest.TestCase):
    L3 = "172.20.20.254"

    def crawl(self, **kw):
        rows = load_rows("cisco_l3_switch.snmp") + load_rows("checklist_l3.snmp")
        rows = [r for r in rows if not r[0].startswith(parse.CDP_CACHE_BASE)]
        client = FakeSnmpClient({self.L3: rows})

        async def go():
            crawler = Crawler(client, concurrency=1, max_nodes=5, queue_maxsize=5, **kw)
            await crawler.seed([self.L3])
            return await crawler.run()
        devices, links = asyncio.run(go())
        return build_document(devices, links), client

    def test_off_reads_nothing_and_adds_nothing(self):
        doc, client = self.crawl()
        self.assertNotIn("config_data", doc["nodes"][0])
        walked = {c[2] for c in client.calls if c[0] == "walk"}
        self.assertFalse(walked & {t.TCP_CONN_STATE, t.IF_ADMIN_STATUS, t.VM_VLAN})

    def test_on_records_the_data_on_the_crawl_node(self):
        doc, client = self.crawl(checklist=True)
        data = doc["nodes"][0]["config_data"]
        self.assertEqual(len(data["vm_vlan"]), 23)
        self.assertIsNone(data["probe"])
        self.assertNotIn("probe", kinds(client))

    def test_probe_only_when_chosen(self):
        doc, client = self.crawl(checklist=True, check_default_communities=True)
        self.assertEqual(doc["nodes"][0]["config_data"]["probe"],
                         {"public": False, "private": False})
        self.assertEqual(kinds(client)["probe"], 2)


    def test_connection_test_only_when_chosen(self):
        calls = []

        async def connect(ip, port):
            calls.append((ip, port))
            return c.REFUSED
        doc, _ = self.crawl(checklist=True)
        self.assertNotIn("connect", doc["nodes"][0]["config_data"])
        self.assertEqual(calls, [])
        doc, _ = self.crawl(checklist=True, port_connect=connect)
        self.assertEqual(doc["nodes"][0]["config_data"]["connect"],
                         {23: c.REFUSED, 80: c.REFUSED})
        self.assertEqual(sorted(calls), [(self.L3, 23), (self.L3, 80)])


class TestConnectionTest(unittest.TestCase):
    """The optional TCP 23/80 test, with the connector or the socket layer faked."""

    def run_collect(self, name, vendor):
        calls = []

        async def connect(ip, port):
            calls.append((ip, port))
            return c.ACCEPTED
        client = FakeSnmpClient({IP: load_rows(f"checklist_{name}.snmp")})
        return asyncio.run(collect_config(client, IP, vendor, connect=connect)), calls

    def test_only_devices_without_listener_data(self):
        data, calls = self.run_collect("hp", "HP")         # lists its listeners
        self.assertNotIn("connect", data)
        self.assertEqual(calls, [])
        data, calls = self.run_collect("l3", "Cisco")       # does not
        self.assertEqual(data["connect"], {23: c.ACCEPTED, 80: c.ACCEPTED})
        self.assertEqual(sorted(calls), [(IP, 23), (IP, 80)])

    def test_outcomes_and_nothing_is_sent(self):
        class Writer:
            def __init__(self):
                self.closed, self.written = False, []

            def write(self, data):
                self.written.append(data)

            def close(self):
                self.closed = True
        writer = Writer()

        def opener(outcome):
            async def open_connection(ip, port):
                if isinstance(outcome, BaseException):
                    raise outcome
                return object(), writer
            return open_connection
        for outcome, expected in ((None, c.ACCEPTED), (ConnectionRefusedError(), c.REFUSED),
                                  (asyncio.TimeoutError(), c.NO_ANSWER),
                                  (OSError("unreachable"), c.NO_ANSWER)):
            with mock.patch.object(c.asyncio, "open_connection", opener(outcome)):
                self.assertEqual(asyncio.run(c.tcp_connect(IP, 23)), expected)
        self.assertTrue(writer.closed)
        self.assertEqual(writer.written, [])

    def test_timeout_is_about_a_second(self):
        async def never(ip, port):
            await asyncio.sleep(3600)
        with mock.patch.object(c.asyncio, "open_connection", never), \
                mock.patch.object(c, "CONNECT_TIMEOUT_S", 0.01):
            self.assertEqual(asyncio.run(c.tcp_connect(IP, 80, 0.01)), c.NO_ANSWER)
        self.assertEqual(c.CONNECT_TIMEOUT_S, 1.0)


if __name__ == "__main__":
    unittest.main()
