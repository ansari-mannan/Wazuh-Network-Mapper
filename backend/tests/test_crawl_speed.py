"""The crawl polls several devices at once but asks each one thing at a time;
the interface columns are walked together; a device whose GETBULK fails is
read a row at a time (GETNEXT) from then on, but not one whose answer only has
a non-increasing OID (Comware's forwarding table)."""

import offline  # noqa: F401  (no test reaches the internet)
import asyncio
import os
import unittest
from collections import Counter
from unittest import mock

from pysnmp.proto import errind
from test_cdp import crawl, lab
from test_comware import _load_rows
from test_golden import normalise
from vulnmapper.network import snmp
from vulnmapper.network.model import Credential

ASYNC = ("resolve_credential", "get_many", "walk", "walk_columns", "walk_vlan_context",
         "get_many_vlan_context", "answers_to_community")


class Slow:
    """The fake client with a short wait in every request, counting the
    requests in flight per device and overall."""

    def __init__(self, client):
        self._client = client
        self.now, self.peak = Counter(), Counter()
        self.total = self.peak_total = 0

    def __getattr__(self, name):
        attr = getattr(self._client, name)
        if name not in ASYNC:
            return attr

        async def call(ip, *a, **kw):
            self.now[ip] += 1
            self.total += 1
            self.peak[ip] = max(self.peak[ip], self.now[ip])
            self.peak_total = max(self.peak_total, self.total)
            try:
                await asyncio.sleep(0.002)
                return await attr(ip, *a, **kw)
            finally:
                self.now[ip] -= 1
                self.total -= 1
        return call


class TestCrawlConcurrency(unittest.TestCase):
    def test_devices_at_once_one_request_per_device(self):
        slow = Slow(lab())
        doc = crawl(slow)
        self.assertEqual(normalise(doc), normalise(crawl(lab())))      # same document
        self.assertEqual(set(slow.peak.values()), {1})         # never two at one device
        self.assertGreater(slow.peak_total, 1)                 # several devices at once


class Agent:
    """A fake SNMP agent behind bulk_cmd / next_cmd (pysnmp's object wrappers
    patched out, so OIDs are plain strings). Each column is served in the
    agent's own order, which need not be increasing (as Comware's FDB is);
    ``rejects_bulk`` answers every GETBULK with that error (an error indication,
    or ``(error status, index)``). ``flags_order`` reports a GETBULK answer
    whose OIDs do not increase the way a pysnmp that checks it does: the
    answer, with OidNotIncreasing."""

    END = "9.9.9.9"

    def __init__(self, columns, rejects_bulk=None, flags_order=False):
        self.columns, self.rejects_bulk, self.flags_order = columns, rejects_bulk, flags_order
        self.bulk, self.next = [], []          # the OIDs of each request

    def successor(self, oid):
        for base, rows in self.columns.items():
            if oid == base or oid.startswith(base + "."):
                oids = [o for o, _ in rows]
                i = 0 if oid == base else oids.index(oid) + 1
                return rows[i] if i < len(rows) else (self.END, "end")
        return (self.END, "end")

    def answer(self, oids, reps):
        cur, out = list(oids), []
        for _ in range(reps):
            for k, oid in enumerate(cur):
                cur[k], value = self.successor(oid)
                out.append((Oid(cur[k]), Value(value)))
        return out

    async def bulk_cmd(self, engine, auth, transport, context, non_rep, max_rep, *oids):
        self.bulk.append(list(oids))
        if isinstance(self.rejects_bulk, tuple):
            return None, *self.rejects_bulk, []
        if self.rejects_bulk:
            return self.rejects_bulk, 0, 0, []
        answer = self.answer(oids, max_rep)
        seq = [list(oids)] + [[str(o) for o, _ in answer[i:i + len(oids)]]
                              for i in range(0, len(answer), len(oids))]
        increasing = all(_key(b) > _key(a) for prev, cur in zip(seq, seq[1:])
                         for a, b in zip(prev, cur) if b != self.END)
        return (None if increasing or not self.flags_order else errind.oidNotIncreasing), \
            0, 0, answer

    async def next_cmd(self, engine, auth, transport, context, *oids, **options):
        self.next.append(list(oids))
        return None, 0, 0, self.answer(oids, 1)


def _key(oid):
    return tuple(int(p) for p in oid.split("."))


class Oid(str):
    pass


class Value:
    def __init__(self, text):
        self.text = text

    def prettyPrint(self):
        return self.text


IF = "1.3.6.1.2.1.2.2.1"
COLUMNS = {f"{IF}.{c}": [(f"{IF}.{c}.{i}", f"v{c}.{i}") for i in range(1, 4)]
           for c in (8, 7, 3, 5, 9, 6)}            # six interface columns, three ports


def client_for(agent):
    client = snmp.SnmpClient([Credential(version="v2c", index=1, community="x")])

    async def no_transport(ip):
        return None
    client._transport = no_transport
    client._resolved["10.0.0.1"] = client._credentials[0]
    return client


def run(agent, coro):
    with mock.patch.object(snmp, "bulk_cmd", agent.bulk_cmd), \
            mock.patch.object(snmp, "next_cmd", agent.next_cmd), \
            mock.patch.object(snmp, "ObjectType", lambda x: x), \
            mock.patch.object(snmp, "ObjectIdentity", lambda oid: oid):
        return asyncio.run(coro)


class TestMultiColumnWalk(unittest.TestCase):
    def test_six_columns_in_one_request_sequence(self):
        agent = Agent(COLUMNS)
        client = client_for(agent)
        got = run(agent, client.walk_columns("10.0.0.1", list(COLUMNS)))
        self.assertEqual(got, COLUMNS)
        self.assertEqual(agent.bulk, [list(COLUMNS)])      # one GETBULK, every column in it
        self.assertEqual(agent.next, [])

    def test_the_crawl_reads_the_port_columns_once_per_device(self):
        from vulnmapper.network.parse import collect

        fake = lab()
        crawl(fake)
        six = (collect.IFOPERSTATUS_BASE, collect.IFNAME_BASE, collect.IFADMINSTATUS_BASE,
               collect.IFTYPE_BASE, collect.IFHIGHSPEED_BASE, collect.IFALIAS_BASE)
        polled = {c[1] for c in fake.calls if c[0] == "walk_columns"}
        self.assertTrue(polled)
        for ip in polled:
            self.assertEqual([c[2] for c in fake.calls if c[0] == "walk_columns" and c[1] == ip], [six])
            # ifName is also read on its own where LLDP names a port by number or
            # MAC (Comware/HP, collect_ifname_map); the other five never are
            self.assertFalse([c for c in fake.calls if c[0] == "walk" and c[1] == ip
                              and c[2] in six and c[2] != collect.IFNAME_BASE])

    def test_out_of_order_rows_are_read_whole(self):
        base = "1.3.6.1.2.1.17.7.1.2.2.1.2"
        rows = [(f"{base}.1.0.9", "3"), (f"{base}.1.0.2", "1"), (f"{base}.1.0.5", "2")]  # by MAC
        for rejects in (None, "requestTimedOut"):
            agent = Agent({base: rows}, rejects_bulk=rejects)
            self.assertEqual(run(agent, client_for(agent).walk("10.0.0.1", base)), rows)


class TestBulkFallback(unittest.TestCase):
    def test_a_device_that_rejects_getbulk_is_read_a_row_at_a_time_from_then_on(self):
        agent = Agent(COLUMNS, rejects_bulk="requestTimedOut")
        client = client_for(agent)

        async def two_walks():
            first = await client.walk("10.0.0.1", f"{IF}.8")
            return first, await client.walk_columns("10.0.0.1", [f"{IF}.7", f"{IF}.3"])

        first, second = run(agent, two_walks())
        self.assertEqual(first, COLUMNS[f"{IF}.8"])
        self.assertEqual(second, {b: COLUMNS[b] for b in (f"{IF}.7", f"{IF}.3")})
        self.assertEqual(len(agent.bulk), 1)                # never asked with GETBULK again
        self.assertEqual(agent.next[-1], [f"{IF}.7.3", f"{IF}.3.3"])   # GETNEXT, both columns
        self.assertTrue(client.used_fallback("10.0.0.1"))


class TestComwareBulk(unittest.TestCase):
    """The HP 1920's forwarding table, from the saved capture, in its own
    (MAC-sorted, non-increasing) order."""

    FDB = "1.3.6.1.2.1.17.7.1.2.2.1.2"

    def setUp(self):
        fixture = os.path.join(os.path.dirname(__file__), "fixtures", "comware_hp1920_cyfor.snmp")
        self.rows = [r for r in _load_rows(fixture) if r[0].startswith(self.FDB + ".")]
        self.assertGreater(len(self.rows), 6)

    def walk(self, agent, max_repetitions=4):
        client = client_for(agent)
        rows = run(agent, client.walk("10.0.0.1", self.FDB, max_repetitions=max_repetitions))
        return rows, client

    def test_non_increasing_oids_keep_getbulk_and_the_rows(self):
        row_at_a_time, _ = self.walk(Agent({self.FDB: self.rows}, rejects_bulk="requestTimedOut"))
        agent = Agent({self.FDB: self.rows}, flags_order=True)
        rows, client = self.walk(agent)
        self.assertEqual(rows, row_at_a_time)                  # the output is unchanged
        self.assertEqual(rows, self.rows)                      # the whole table
        self.assertFalse(client.used_fallback("10.0.0.1"))     # GETBULK kept
        self.assertEqual(agent.next, [])
        self.assertGreater(len(agent.bulk), 1)

    def test_a_real_error_still_falls_back(self):
        for error in ("requestTimedOut", (1, 0), (5, 0), (2, 1)):   # timeout, tooBig, genErr, noSuchName
            with self.subTest(error=error):
                agent = Agent({self.FDB: self.rows}, rejects_bulk=error)
                rows, client = self.walk(agent)
                self.assertEqual(rows, self.rows)
                self.assertTrue(client.used_fallback("10.0.0.1"))
                self.assertEqual(len(agent.bulk), 1)


if __name__ == "__main__":
    unittest.main()
