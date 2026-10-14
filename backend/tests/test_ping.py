"""The liveness ping: flags per OS and address family, and a missing ping
binary logged once and treated as ICMP unavailable."""

import asyncio
import unittest
from unittest import mock

from vulnmapper.liveness import prober as prober_mod
from vulnmapper.liveness.prober import ProbeUnavailable, SystemProber, ping_argv


class TestPingArgv(unittest.TestCase):
    def test_flags_per_system_and_family(self):
        self.assertEqual(ping_argv("10.0.0.1", "Linux"), ["ping", "-c", "1", "-W", "1", "10.0.0.1"])
        self.assertEqual(ping_argv("fe80::1", "Linux"), ["ping", "-6", "-c", "1", "-W", "1", "fe80::1"])
        self.assertEqual(ping_argv("10.0.0.1", "Darwin"), ["ping", "-c", "1", "-W", "1000", "10.0.0.1"])
        self.assertEqual(ping_argv("fe80::1", "FreeBSD"), ["ping6", "-c", "1", "fe80::1"])
        self.assertEqual(ping_argv("10.0.0.1", "Windows"), ["ping", "-n", "1", "-w", "1000", "10.0.0.1"])
        self.assertEqual(ping_argv("fe80::1", "Windows"), ["ping", "-6", "-n", "1", "-w", "1000", "fe80::1"])

    def test_rejects_anything_but_an_address(self):
        with self.assertRaises(ValueError):
            ping_argv("-c 9 10.0.0.1", "Linux")


class TestSystemProberIcmp(unittest.TestCase):
    def prober(self, system="Linux"):
        p = SystemProber([], agent_source=object())
        p._system = system
        return p

    def test_runs_the_argv_for_this_system(self):
        seen = []

        async def fake_exec(*argv, **kw):
            seen.append(list(argv))
            return mock.Mock(wait=mock.AsyncMock(return_value=0))

        with mock.patch.object(prober_mod.asyncio, "create_subprocess_exec", fake_exec):
            self.assertTrue(asyncio.run(self.prober("Darwin").icmp("10.0.0.1")))
        self.assertEqual(seen, [["ping", "-c", "1", "-W", "1000", "10.0.0.1"]])

    def test_missing_ping_is_logged_once_then_unavailable(self):
        calls = []

        async def missing(*argv, **kw):
            calls.append(argv)
            raise FileNotFoundError("ping")

        p = self.prober()
        with mock.patch.object(prober_mod.asyncio, "create_subprocess_exec", missing), \
                self.assertLogs("vulnmapper.liveness", "WARNING") as logs:
            for _ in range(3):
                with self.assertRaises(ProbeUnavailable):
                    asyncio.run(p.icmp("10.0.0.1"))
        self.assertEqual(len(calls), 1)                 # not tried again
        self.assertEqual(len(logs.output), 1)
        self.assertFalse(p.has_icmp)


if __name__ == "__main__":
    unittest.main()
