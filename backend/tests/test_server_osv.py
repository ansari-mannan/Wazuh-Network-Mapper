"""The Wazuh server's own CVEs: its syscollector package list (Wazuh never
indexes agent 000) matched with OSV.dev through a fake transport."""

import offline  # noqa: F401  (no test reaches the internet)
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_nvd import FakeClock  # noqa: E402
from vulnmapper.endpoints import WazuhSource, osv  # noqa: E402
from vulnmapper.endpoints.osv import OsvClient, OsvUnavailable, ecosystem, match  # noqa: E402
from vulnmapper.schema import IndexerConfig, WazuhConfig  # noqa: E402

_FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")

# A synthetic Wazuh server: Ubuntu 22.04 and four packages (no lab data).
SERVER_OS = [{"os": {"name": "Ubuntu", "platform": "ubuntu", "version": "22.04.4 LTS",
                     "major": "22", "minor": "04"}}]
SERVER_PACKAGES = [
    {"name": "libsynth0", "version": "1.0-1ubuntu0.1", "architecture": "amd64", "format": "deb"},
    {"name": "synth-tools", "version": "2:2.0-3", "architecture": "amd64", "format": "deb"},
    {"name": "synth-clean", "version": "0.9", "architecture": "all", "format": "deb"},
    {"name": "synth-snap", "version": "5", "architecture": "amd64", "format": "snap"},
]
# OSV's answers: a UBUNTU-CVE id, a USN that names two CVEs (one twice) and a
# GHSA with no CVE at all.
OSV_VULNS = {
    "libsynth0": ["UBUNTU-CVE-2026-90002", "USN-9999-1"],
    "synth-tools": ["GHSA-aaaa-bbbb-cccc"],
}
OSV_RECORDS = {
    "USN-9999-1": {"id": "USN-9999-1", "aliases": [], "upstream": ["CVE-2026-90002",
                                                                   "CVE-2026-90000"]},
    "GHSA-aaaa-bbbb-cccc": {"id": "GHSA-aaaa-bbbb-cccc", "aliases": []},
}


def server_inventory():
    return SERVER_OS, SERVER_PACKAGES


class FakeOsv:
    """OSV.dev from tables. ``cost_s`` advances ``clock`` per request;
    ``down`` makes every request fail."""

    def __init__(self, vulns=None, records=None, clock=None, cost_s=0.0, down=False):
        self.vulns = OSV_VULNS if vulns is None else vulns
        self.records = OSV_RECORDS if records is None else records
        self.clock, self.cost_s, self.down = clock, cost_s, down
        self.calls = []

    def __call__(self, url, body, timeout):
        self.calls.append((url, body, timeout))
        if self.clock:
            self.clock.advance(self.cost_s)
        if self.down:
            raise OsvUnavailable("ConnectionError")
        if url.endswith("/querybatch"):
            return {"results": [{"vulns": [{"id": i, "modified": "2026-01-01T00:00:00Z"}
                                           for i in self.vulns.get(q["package"]["name"], [])]}
                                if self.vulns.get(q["package"]["name"]) else {}
                                for q in body["queries"]]}
        return self.records[url.rsplit("/", 1)[1]]


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


class TestMatch(unittest.TestCase):
    def run_match(self, fake=None, clock=None, store=None):
        clock = clock or FakeClock()
        fake = fake or FakeOsv()
        store = store or osv.cache(None, clock)
        return match(SERVER_PACKAGES, "Ubuntu:22.04:LTS", OsvClient(clock, fake), store), fake

    def test_batch_parsing_with_direct_ids_and_alias_lookups(self):
        (rows, n_pkgs, hits), fake = self.run_match()
        self.assertEqual(n_pkgs, 3)            # the snap is not a deb
        self.assertEqual(hits, 0)
        self.assertEqual([(r["package"], r["cve"]) for r in rows],
                         [("libsynth0", "CVE-2026-90000"), ("libsynth0", "CVE-2026-90002")])
        self.assertTrue(all(r["source"] == "osv" and r["confidence"] == "potential"
                            and r["version"] == "1.0-1ubuntu0.1" for r in rows))
        batch = fake.calls[0]
        self.assertTrue(batch[0].endswith("/v1/querybatch"))
        self.assertEqual(batch[1]["queries"][0], {"package": {"name": "libsynth0",
                                                              "ecosystem": "Ubuntu:22.04:LTS"},
                                                  "version": "1.0-1ubuntu0.1"})
        self.assertEqual(batch[2], osv.READ_TIMEOUT_S)
        # the UBUNTU-CVE id needs no lookup; the USN and the GHSA do
        self.assertEqual(sorted(u.rsplit("/", 1)[1] for u, _b, _t in fake.calls[1:]),
                         ["GHSA-aaaa-bbbb-cccc", "USN-9999-1"])

    def test_more_than_a_batch_is_split(self):
        clock = FakeClock()
        many = [{"name": f"p{i:04d}", "version": "1", "format": "deb"} for i in range(1500)]
        fake = FakeOsv(vulns={}, records={})
        match(many, "Debian:12", OsvClient(clock, fake), osv.cache(None, clock))
        self.assertEqual([len(b["queries"]) for _u, b, _t in fake.calls], [1000, 500])

    def test_cache_hit_then_expiry(self):
        clock = FakeClock()
        with tempfile.TemporaryDirectory() as tmp:
            self.run_match(clock=clock, store=osv.cache(tmp, clock))
            self.assertTrue(os.path.exists(os.path.join(tmp, "osv-cache.json")))
            (rows, _n, hits), fake = self.run_match(clock=clock, store=osv.cache(tmp, clock))
            self.assertEqual((hits, fake.calls, len(rows)), (3, [], 2))
            clock.advance(days=1, seconds=1)
            (_rows, _n, hits), fake = self.run_match(clock=clock, store=osv.cache(tmp, clock))
            self.assertEqual(hits, 0)
            self.assertTrue(fake.calls)

    def test_budget_overrun_raises_and_keeps_what_finished(self):
        clock = FakeClock()
        store = osv.cache(None, clock)
        fake = FakeOsv(clock=clock, cost_s=osv.BUDGET_S + 1)
        with self.assertRaisesRegex(OsvUnavailable, "time budget"):
            match(SERVER_PACKAGES, "Ubuntu:22.04:LTS", OsvClient(clock, fake), store)
        # synth-clean had no vulns, so it was settled by the batch alone
        self.assertEqual(sorted(store.entries), ["Ubuntu:22.04:LTS|synth-clean|0.9"])


def scored_with_server(tmp):
    """offline_scored.json plus a Wazuh server the indexer has no packages for."""
    with open(os.path.join(_FIXTURES, "offline_scored.json"), encoding="utf-8") as f:
        doc = json.load(f)
    doc["endpoints"].append({
        "agent_id": "000", "hostname": "wazuh-server", "ip": "10.10.0.2",
        "mac": "d4:be:d9:00:00:02", "vendor": "ubuntu", "model": "Ubuntu", "firmware": "22.04.4 LTS",
        "status": "active", "discovery_method": "wazuh", "is_wazuh_server": True,
        "unscored_reason": "no_inventory", "risk_score": None, "max_cvss": None,
        "top_cves": [], "cve_summary": None, "findings": None})
    doc["warnings"].append({"type": "not_yet_inventoried", "agents": ["000"],
                            "node_ids": ["endpoint:000"]})
    path = os.path.join(tmp, "scored.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f)
    return path


class TestPipeline(unittest.TestCase):
    def scan(self, fake, inventory=server_inventory):
        fake.clock = fake.clock or FakeClock()
        from vulnmapper.pipeline import Pipeline

        with tempfile.TemporaryDirectory() as tmp:
            graph = os.path.join(tmp, "graph.json")
            with contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                Pipeline(clock=fake.clock, server_inventory=inventory, osv_transport=fake).run(
                    ["--scored", scored_with_server(tmp), "--no-network", "--no-cve-vectors",
                     "--no-device-cves", "-o", graph])
            out = {}
            for name in ("graph", "vulnerabilities"):
                with open(os.path.join(tmp, f"{name}.json"), encoding="utf-8") as f:
                    out[name] = json.load(f)
        node = next(n for n in out["graph"]["nodes"] if n["node_id"] == "endpoint:000")
        stage = next((s for s in out["graph"]["metadata"]["stages"]
                      if s["name"] == "Wazuh server via OSV"), None)
        return out, node, stage

    def test_findings_are_potential_and_the_stage_is_recorded(self):
        out, node, stage = self.scan(FakeOsv())
        self.assertEqual(stage["status"], "ran")
        self.assertEqual(stage["note"], "3 packages, 2 CVEs, 0.0 s (cache hits 0)")
        self.assertNotIn("unscored_reason", node)
        self.assertEqual(node["osv"], {"status": "ok", "reason": None,
                                       "ecosystem": "Ubuntu:22.04:LTS", "packages": 3})
        self.assertEqual(node["cve_summary"]["total"], 2)
        findings = out["vulnerabilities"]["hosts"]["endpoint:000"]["findings"]
        self.assertEqual({(f["cve"], f["source"], f["confidence"]) for f in findings},
                         {("CVE-2026-90000", "osv", "potential"),
                          ("CVE-2026-90002", "osv", "potential")})
        self.assertFalse(any(w["type"] == "not_yet_inventoried"
                             for w in out["graph"]["metadata"]["warnings"]))

    def test_osv_down_leaves_the_server_unscored_with_a_reason(self):
        _out, node, stage = self.scan(FakeOsv(down=True))
        self.assertEqual(node["unscored_reason"], "no_inventory")
        self.assertIsNone(node["cve_summary"])
        self.assertEqual(node["osv"]["reason"], "OSV unavailable")
        self.assertEqual(stage["note"], "OSV unavailable (ConnectionError)")

    def test_budget_overrun_leaves_the_server_unscored_with_a_reason(self):
        clock = FakeClock()
        _out, node, stage = self.scan(FakeOsv(clock=clock, cost_s=osv.BUDGET_S + 1))
        self.assertIsNone(node["cve_summary"])
        self.assertEqual(node["osv"]["status"], "unavailable")
        self.assertIn("time budget", stage["note"])

    def test_unknown_os_is_skipped_with_a_reason(self):
        _out, node, stage = self.scan(FakeOsv(), lambda: (
            [{"os": {"name": "Rocky Linux", "platform": "rocky", "version": "9.3"}}], []))
        self.assertEqual(stage["status"], "skipped")
        self.assertIn("Rocky Linux 9.3", stage["note"])
        self.assertEqual(node["osv"]["status"], "skipped")
        self.assertIsNone(node["cve_summary"])


if __name__ == "__main__":
    unittest.main()
