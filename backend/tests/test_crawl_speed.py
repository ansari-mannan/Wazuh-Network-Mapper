"""The crawl polls several devices at once but asks each one thing at a time,
and a GETBULK that fails is asked again a row at a time."""

import offline  # noqa: F401  (no test reaches the internet)
import asyncio
import unittest
from collections import Counter
from unittest import mock

from test_cdp import crawl, lab
from test_golden import normalise
from vulnmapper.network import snmp
from vulnmapper.network.model import Credential

ASYNC = ("resolve_credential", "get_many", "walk", "walk_vlan_context",
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


class TestBulkFallback(unittest.TestCase):
    def test_a_failed_getbulk_goes_on_a_row_at_a_time(self):
        base = "1.3.6.1.2.1.2.2.1.2"
        rows = [(f"{base}.{i}", f"Gi0/{i}") for i in range(1, 4)]
        asked = []

        class Oid(str):
            pass

        class Value:
            def __init__(self, text):
                self.text = text

            def prettyPrint(self):
                return self.text

        async def bulk_cmd(engine, auth, transport, context, non_rep, max_rep, obj):
            start = obj                                      # ObjectType/Identity patched out
            asked.append(max_rep)
            if max_rep > 1:
                return "requestTimedOut", 0, 0, []         # a large response is dropped
            after = [r for r in rows if tuple(map(int, r[0].split("."))) >
                     tuple(map(int, start.split(".")))][:max_rep]
            nxt = after or [("1.3.6.1.2.1.2.2.1.3.1", "x")]   # past the subtree
            return None, 0, 0, [(Oid(o), Value(v)) for o, v in nxt]

        client = snmp.SnmpClient([Credential(version="v2c", index=1, community="x")])

        async def no_transport(ip):
            return None
        client._transport = no_transport
        client._resolved["10.0.0.1"] = client._credentials[0]
        with mock.patch.object(snmp, "bulk_cmd", bulk_cmd), \
                mock.patch.object(snmp, "ObjectType", lambda x: x), \
                mock.patch.object(snmp, "ObjectIdentity", lambda oid: oid):
            got = asyncio.run(client.walk("10.0.0.1", base))
        self.assertEqual(got, rows)
        self.assertEqual(asked, [25, 1, 1, 1, 1])


if __name__ == "__main__":
    unittest.main()
