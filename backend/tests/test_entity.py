"""Exact device identity from the standard inventory table (ENTITY-MIB).

Hand-written minimal tables for the switches (no lab capture of their
inventory table is available here) and the access point fixture's real rows,
which have no class column.
"""

import asyncio
import unittest

from snmp_fakes import FakeSnmpClient, load_rows
from vulnmapper.network import entity
from vulnmapper.network.crawl import fetch

ENT = entity.ENT_PHYSICAL_ENTRY
IP = "10.0.0.2"


def table(*entries):
    """Rows for entries ``(index, class, model, serial[, contained_in])``."""
    rows = []
    for e in entries:
        index, cls, model, serial = e[:4]
        if cls is not None:
            rows.append((f"{ENT}.5.{index}", str(cls)))
        if len(e) > 4:
            rows.append((f"{ENT}.4.{index}", str(e[4])))
        rows.append((f"{ENT}.11.{index}", serial))
        rows.append((f"{ENT}.13.{index}", model))
    return rows


def base(descr, object_id):
    return [("1.3.6.1.2.1.1.1.0", descr), ("1.3.6.1.2.1.1.2.0", object_id),
            ("1.3.6.1.2.1.1.5.0", "sw1")]


IOS = ("Cisco IOS Software, C3750 Software (C3750-IPSERVICESK9-M), "
       "Version 12.2(55)SE12, RELEASE SOFTWARE (fc2)")


def inventory(rows):
    client = FakeSnmpClient({IP: rows})
    return asyncio.run(entity.collect_inventory(client, IP)), client


class TestChassisChoice(unittest.TestCase):
    def test_single_chassis(self):
        inv, _ = inventory(table((1, 3, "WS-C3750-48TS-S", "SERIAL-PLACEHOLDER-1"),
                                 (2, 9, "", ""), (3, 10, "", "")))
        self.assertEqual(inv, {"model": "WS-C3750-48TS-S", "serial": "SERIAL-PLACEHOLDER-1"})

    def test_chassis_not_first_in_the_table(self):
        inv, _ = inventory(table((1, 6, "PWR-C1", "SERIAL-PLACEHOLDER-9"),
                                 (2, 3, "JG927A", "SERIAL-PLACEHOLDER-2")))
        self.assertEqual(inv["model"], "JG927A")

    def test_stack_takes_its_first_member(self):
        # a stack entry (class 11) holds the members (class 3), lowest index first
        inv, _ = inventory(table((1, 11, "", "", 0),
                                 (2001, 3, "WS-C3750-24P-S", "SERIAL-PLACEHOLDER-B", 1),
                                 (1001, 3, "WS-C3750-48TS-S", "SERIAL-PLACEHOLDER-A", 1),
                                 (1002, 10, "", "", 1001)))
        self.assertEqual(inv, {"model": "WS-C3750-48TS-S", "serial": "SERIAL-PLACEHOLDER-A"})

    def test_named_class_values(self):
        rows = [(f"{ENT}.5.7", "chassis(3)"), (f"{ENT}.11.7", "SERIAL-PLACEHOLDER-7"),
                (f"{ENT}.13.7", "X1")]
        self.assertEqual(inventory(rows)[0]["model"], "X1")

    def test_no_class_column_falls_back_to_the_first_named_entry(self):
        # the access point fixture: no entPhysicalClass rows
        inv, _ = inventory(load_rows("cisco_ap_c1140.snmp"))
        self.assertEqual(inv, {"model": "AIR-LAP1142N-A-K9", "serial": "SERIAL-PLACEHOLDER-1"})

    def test_no_table_gives_nothing(self):
        inv, _ = inventory(base(IOS, "1.3.6.1.4.1.9.1.516"))
        self.assertEqual(inv, {})

    def test_blank_values_are_not_identity(self):
        inv, _ = inventory(table((1, 3, "  ", "")))
        self.assertEqual(inv, {})

    def test_request_count_is_small(self):
        # one bounded page of the class column, one GET for the chosen entry
        _, client = inventory(table((1, 3, "M", "S"), *[(i, 10, "", "") for i in range(2, 950)]))
        self.assertEqual(len(client.calls), 2)
        # without a class column: one page of the model column, then the GET
        _, client = inventory(load_rows("cisco_ap_c1140.snmp"))
        self.assertEqual(len([c for c in client.calls if c[0] in ("walk", "get")]), 3)


class TestIdentityMerge(unittest.TestCase):
    def fetch(self, rows):
        client = FakeSnmpClient({IP: rows})
        asyncio.run(client.resolve_credential(IP))
        return asyncio.run(fetch(client, IP))

    def test_cisco_model_becomes_the_product_and_serial_is_filled(self):
        info = self.fetch(base(IOS, "1.3.6.1.4.1.9.1.516")
                          + table((1, 3, "WS-C3750-48TS-S", "SERIAL-PLACEHOLDER-1")))
        self.assertEqual((info["vendor"], info["model"], info["firmware"], info["serial"]),
                         ("Cisco", "WS-C3750-48TS-S", "12.2(55)SE12", "SERIAL-PLACEHOLDER-1"))

    def test_device_without_the_table_loses_nothing(self):
        info = self.fetch(base(IOS, "1.3.6.1.4.1.9.1.516"))
        self.assertEqual((info["model"], info["firmware"], info["serial"]),
                         ("C3750", "12.2(55)SE12", None))

    def test_fortinet_keeps_its_own_model_and_serial(self):
        rows = [("1.3.6.1.2.1.1.1.0", ""), ("1.3.6.1.2.1.1.2.0", "1.3.6.1.4.1.12356.101.1.2005"),
                ("1.3.6.1.4.1.12356.101.4.1.1.0", "v6.0.16,build0505,221215 (GA)"),
                ("1.3.6.1.4.1.12356.100.1.1.1.0", "SERIAL-PLACEHOLDER-FG")]
        rows += table((1, 3, "FGT_200D", "SERIAL-PLACEHOLDER-ENT"))
        info = self.fetch(rows)
        self.assertEqual(info["serial"], "SERIAL-PLACEHOLDER-FG")
        self.assertEqual(info["model"], "FortiGate 200D")

    def test_comware_keeps_its_model_name_and_gains_a_serial(self):
        descr = ("1920-48G Switch Software Version 5.20.99, Release 1107 "
                 "Copyright(c)2010-2015 Hewlett-Packard Development Company, L.P.")
        info = self.fetch(base(descr, "1.3.6.1.4.1.25506.11.1.169")
                          + table((1, 3, "JG927A", "SERIAL-PLACEHOLDER-HP")))
        self.assertEqual((info["model"], info["serial"]), ("HP 1920-48G", "SERIAL-PLACEHOLDER-HP"))


if __name__ == "__main__":
    unittest.main()
