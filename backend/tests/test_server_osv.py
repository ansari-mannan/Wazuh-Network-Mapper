"""The Wazuh server's own CVEs: its syscollector package list (Wazuh never
indexes agent 000) matched with OSV.dev through a fake transport."""

import offline  # noqa: F401  (no test reaches the internet)
import unittest
from unittest import mock

from vulnmapper.endpoints import WazuhSource
from vulnmapper.endpoints.osv import ecosystem
from vulnmapper.schema import IndexerConfig, WazuhConfig


def os_item(name, platform, version, major=None, minor=None):
    return [{"os": {"name": name, "platform": platform, "version": version,
                    **({"major": major} if major else {}), **({"minor": minor} if minor else {})}}]


class TestServerInventory(unittest.TestCase):
    def test_packages_are_paged_and_the_os_read(self):
        src = WazuhSource(WazuhConfig(host="w", port="55000", user="u", password="p"),
                          IndexerConfig(host="i", port="9200", user="u", password="p"))
        src._token = "T"
        calls = []

        def fake_get(path, params=None):
            calls.append((path, params))
            if path.endswith("/os"):
                return os_item("Ubuntu", "ubuntu", "22.04.4 LTS", "22", "04")
            n = (src.AGENT_PAGE, 7)[params["offset"] // src.AGENT_PAGE]
            return [{"name": f"p{params['offset'] + i}", "version": "1", "format": "deb"}
                    for i in range(n)]

        with mock.patch.object(src, "_get", fake_get):
            os_items, packages = src.server_inventory()
        self.assertEqual(os_items[0]["os"]["platform"], "ubuntu")
        self.assertEqual(len(packages), src.AGENT_PAGE + 7)
        pkg_calls = [p for path, p in calls if path == "/syscollector/000/packages"]
        self.assertEqual([p["offset"] for p in pkg_calls], [0, src.AGENT_PAGE])
        self.assertEqual(pkg_calls[0]["select"], "name,version,architecture,format")


class TestEcosystem(unittest.TestCase):
    def test_ubuntu_lts(self):
        self.assertEqual(ecosystem(os_item("Ubuntu", "ubuntu", "22.04.4 LTS", "22", "04")),
                         ("Ubuntu:22.04:LTS", None))
        self.assertEqual(ecosystem(os_item("Ubuntu", "ubuntu", "24.04.1 LTS (Noble Numbat)")),
                         ("Ubuntu:24.04:LTS", None))

    def test_ubuntu_interim_has_no_lts(self):
        self.assertEqual(ecosystem(os_item("Ubuntu", "ubuntu", "23.10", "23", "10")),
                         ("Ubuntu:23.10", None))

    def test_debian(self):
        self.assertEqual(ecosystem(os_item("Debian GNU/Linux", "debian", "12", "12")),
                         ("Debian:12", None))

    def test_unknown_os_gives_a_reason(self):
        eco, reason = ecosystem(os_item("Rocky Linux", "rocky", "9.3", "9", "3"))
        self.assertIsNone(eco)
        self.assertIn("Rocky Linux 9.3", reason)

    def test_unexpected_shape_is_logged_without_values(self):
        with self.assertLogs("vulnmapper.endpoints", "WARNING") as logs:
            eco, reason = ecosystem({"os": "secret-value"})
        self.assertIsNone(eco)
        self.assertIn("not in the syscollector inventory", reason)
        self.assertNotIn("secret-value", logs.output[0])
        self.assertIn("os: str", logs.output[0])


if __name__ == "__main__":
    unittest.main()
