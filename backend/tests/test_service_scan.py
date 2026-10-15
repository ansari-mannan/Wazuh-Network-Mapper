"""The optional service scan of unmanaged hosts, entirely offline.

nmap never runs: a FakeRunner serves saved XML (or signals missing/timeout),
and every NVD reply comes from FakeNvd (test_nvd). The clock is a FakeClock.
"""

import offline  # noqa: F401  (no test reaches the internet)
import contextlib
import io
import json
import os
import tempfile
import unittest
import unittest.mock

from test_cdp import crawl, lab
from test_nvd import FakeClock, FakeNvd, listed, metric, record
from vulnmapper.devicecves import nvd
from vulnmapper.devicecves.cache import Cache
from vulnmapper.pipeline import Pipeline
from vulnmapper.servicescan import nmap as nmapmod
from vulnmapper.servicescan.nmap import NmapBudgetExceeded, NmapRunner, parse_nmap_xml
from vulnmapper.servicescan import stage as stagemod
from vulnmapper.servicescan.stage import idents_from_ports, run_stage

SSH_CPE = "cpe:2.3:a:openbsd:openssh:8.2p1:*:*:*:*:*:*:*"
SSH_CVES = [record("CVE-2020-0001", metric("3.1", 9.8, severity="CRITICAL")),
            record("CVE-2020-0002", metric("3.1", 5.3, severity="MEDIUM"))]
HTTPD_CPE = "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*"
HTTPD_CVES = [record("CVE-2021-0003", metric("3.1", 7.5, severity="HIGH")),
              record("CVE-2020-0002", metric("3.1", 5.3, severity="MEDIUM"))]   # shared


def host_xml(ip, ports="", scripts=""):
    return f'<host><address addr="{ip}" addrtype="ipv4"/><ports>{ports}</ports>{scripts}</host>'


def port(portid, state="open", service=""):
    svc = f"<service {service}/>" if service else ""
    return f'<port protocol="tcp" portid="{portid}"><state state="{state}"/>{svc}</port>'


# A service element with a child <cpe> needs its own open tag; build it directly.
SSH_SERVICE_PORT = (
    '<port protocol="tcp" portid="22"><state state="open"/>'
    '<service name="ssh" product="OpenSSH" version="8.2p1">'
    '<cpe>cpe:/a:openbsd:openssh:8.2p1</cpe></service></port>')
HTTPD_PORT = (
    '<port protocol="tcp" portid="80"><state state="open"/>'
    '<service name="http" product="Apache httpd" version="2.4.41">'
    '<cpe>cpe:/a:apache:http_server:2.4.41</cpe></service></port>')
IPP_PORT = '<port protocol="tcp" portid="631"><state state="open"/><service name="ipp"/></port>'
NBSTAT = '<hostscript><script id="nbstat" output="NetBIOS name: PRINT01, NetBIOS MAC: x"/></hostscript>'


def nmaprun(*hosts):
    return '<?xml version="1.0"?><nmaprun>' + "".join(hosts) + "</nmaprun>"


class FakeRunner:
    """Stands in for nmap: records the IPs it was handed and returns saved XML."""

    def __init__(self, xml="", available=True, timeout=False):
        self.xml, self._available, self._timeout = xml, available, timeout
        self.seen = None

    @property
    def available(self):
        return self._available

    def scan(self, ips, budget_s, per_host_timeout_s=60.0):
        self.seen = list(ips)
        if self._timeout:
            raise NmapBudgetExceeded()
        return self.xml


def endpoint(node_id, ip=None, unmanaged=True, **f):
    n = {"node_id": node_id, "kind": "endpoint", "agent_id": None if unmanaged else "001",
         "unmanaged": unmanaged, "risk_score": None, "max_cvss": None}
    if ip:
        n["ip"] = ip
    n.update(f)
    return n


def graph(*nodes):
    return {"nodes": list(nodes), "edges": [], "metadata": {"warnings": []}}


def lab_nvd(clock):
    return FakeNvd(clock=clock, cves={SSH_CPE: SSH_CVES, HTTPD_CPE: HTTPD_CVES},
                   dictionary={SSH_CPE: listed(SSH_CPE), HTTPD_CPE: listed(HTTPD_CPE)})


class TestParsing(unittest.TestCase):
    def test_ports_services_versions(self):
        scans = parse_nmap_xml(nmaprun(host_xml("10.0.0.5", SSH_SERVICE_PORT + IPP_PORT, NBSTAT)))
        h = scans["10.0.0.5"]
        self.assertEqual(h["open_ports"][0],
                         {"port": 22, "protocol": "tcp", "service": "ssh",
                          "product": "OpenSSH", "version": "8.2p1",
                          "cpes": ["cpe:/a:openbsd:openssh:8.2p1"]})
        self.assertEqual(h["netbios"], "PRINT01")
        self.assertEqual(h["device_hint"], "printer")       # from the ipp service

    def test_open_port_without_version(self):
        scans = parse_nmap_xml(nmaprun(host_xml("10.0.0.6", port(80, service='name="http"'))))
        p = scans["10.0.0.6"]["open_ports"][0]
        self.assertEqual((p["service"], p["product"], p["version"]), ("http", None, None))
        self.assertEqual(idents_from_ports(scans["10.0.0.6"]["open_ports"]), [])  # no CPE -> no lookup

    def test_host_that_did_not_answer_has_no_open_ports(self):
        scans = parse_nmap_xml(nmaprun(host_xml("10.0.0.9", port(80, state="closed"))))
        self.assertEqual(scans["10.0.0.9"]["open_ports"], [])

    def test_hardware_cpe_gives_the_device_hint(self):
        p = ('<port protocol="tcp" portid="80"><state state="open"/>'
             '<service name="http"><cpe>cpe:/h:axis:p3225</cpe></service></port>')
        scans = parse_nmap_xml(nmaprun(host_xml("10.0.0.7", p)))
        self.assertEqual(scans["10.0.0.7"]["device_hint"], "axis p3225")

    def test_bad_xml_is_tolerated(self):
        self.assertEqual(parse_nmap_xml("not xml"), {})


class TestStage(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()

    def client(self, budget=180.0):
        return nvd.NvdClient(transport=lab_nvd(self.clock), clock=self.clock, api_key="",
                             budget_s=budget, use_env_key=False)

    def run_it(self, g, runner, cache=None, **kw):
        return run_stage(g, self.client(), cache or Cache(None, self.clock), runner=runner, **kw)

    def test_only_unmanaged_hosts_with_an_ip_are_scanned(self):
        g = graph(endpoint("ep:managed", ip="10.0.0.1", unmanaged=False),
                  endpoint("ep:unmanaged", ip="10.0.0.5"),
                  endpoint("ep:noip"),
                  {"node_id": "device:x", "kind": "device", "unmanaged": True, "ip": "10.0.0.2"})
        runner = FakeRunner(nmaprun())
        self.run_it(g, runner)
        self.assertEqual(runner.seen, ["10.0.0.5"])         # the one eligible host only

    def test_detected_service_becomes_a_potential_cve(self):
        node = endpoint("ep:unmanaged", ip="10.0.0.5")
        self.run_it(graph(node), FakeRunner(nmaprun(host_xml("10.0.0.5", SSH_SERVICE_PORT))))
        self.assertEqual(node["max_cvss"], 9.8)
        self.assertEqual(node["cve_lookup"]["status"], "ok")
        self.assertEqual(node["cve_lookup"]["source"], "nmap")
        self.assertTrue(node["cve_lookup"]["potential"])
        self.assertEqual(node["cve_summary"]["total"], 2)
        self.assertTrue(node["unmanaged"])                  # data, not an agent
        self.assertEqual(node["open_ports"][0]["port"], 22)
        self.assertNotIn("cpes", node["open_ports"][0])     # internal field dropped

    def test_answered_without_a_known_service_keeps_only_open_ports(self):
        node = endpoint("ep:unmanaged", ip="10.0.0.6")
        self.run_it(graph(node), FakeRunner(nmaprun(host_xml("10.0.0.6", port(80, service='name="http"')))))
        self.assertEqual(node["open_ports"][0]["service"], "http")
        self.assertNotIn("cve_lookup", node)
        self.assertIsNone(node["risk_score"])

    def test_netbios_fills_empty_hostname_but_not_a_set_one(self):
        empty = endpoint("ep:a", ip="10.0.0.5")
        named = endpoint("ep:b", ip="10.0.0.8", hostname="KNOWN", name_source="dns")
        self.run_it(graph(empty, named),
                    FakeRunner(nmaprun(host_xml("10.0.0.5", "", NBSTAT),
                                       host_xml("10.0.0.8", "", NBSTAT))))
        self.assertEqual((empty["hostname"], empty["name_source"]), ("PRINT01", "netbios"))
        self.assertEqual((named["hostname"], named["name_source"]), ("KNOWN", "dns"))

    def test_device_hint_never_overwrites_a_known_role(self):
        node = endpoint("ep:a", ip="10.0.0.5", role="workstation")
        self.run_it(graph(node), FakeRunner(nmaprun(host_xml("10.0.0.5", IPP_PORT))))
        self.assertEqual(node["role"], "workstation")
        self.assertNotIn("device_hint", node)

    def test_cap_leaves_the_rest_for_next_time(self):
        nodes = [endpoint(f"ep:{i}", ip=f"10.0.0.{i}") for i in range(3)]
        runner = FakeRunner(nmaprun())
        result = self.run_it(graph(*nodes), runner, cap=2)
        self.assertEqual(len(runner.seen), 2)
        self.assertTrue(result.block["cap_reached"])
        self.assertIn({"type": "nmap_cap_reached", "cap": 2}, result.warnings)

    def test_budget_exceeded_warns_and_skips(self):
        node = endpoint("ep:a", ip="10.0.0.5")
        result = self.run_it(graph(node), FakeRunner(timeout=True))
        self.assertTrue(result.block["budget_exceeded"])
        self.assertIn({"type": "nmap_budget_exceeded", "budget_s": 300.0}, result.warnings)
        self.assertNotIn("open_ports", node)

    def test_nmap_missing_warns_and_is_skipped(self):
        node = endpoint("ep:a", ip="10.0.0.5")
        result = self.run_it(graph(node), FakeRunner(available=False))
        self.assertIn({"type": "nmap_not_installed"}, result.warnings)
        self.assertNotIn("open_ports", node)

    def test_warm_cache_makes_no_request(self):
        cache = Cache(None, self.clock)
        xml = nmaprun(host_xml("10.0.0.5", SSH_SERVICE_PORT))
        self.run_it(graph(endpoint("ep:a", ip="10.0.0.5")), FakeRunner(xml), cache=cache)
        client = self.client()
        run_stage(graph(endpoint("ep:a", ip="10.0.0.5")), client, cache, runner=FakeRunner(xml))
        self.assertEqual(client.requests, 0)

    def test_every_versioned_service_is_looked_up(self):
        node = endpoint("ep:a", ip="10.0.0.5")
        self.run_it(graph(node), FakeRunner(nmaprun(host_xml("10.0.0.5", SSH_SERVICE_PORT + HTTPD_PORT))))
        self.assertEqual(node["cve_summary"]["total"], 3)          # the shared CVE once
        self.assertEqual(node["cve_lookup"]["product"], "OpenSSH 8.2p1; Apache httpd 2.4.41")
        self.assertEqual(node["cve_lookup"]["cpe"], f"{SSH_CPE}, {HTTPD_CPE}")
        self.assertEqual(node["cve_lookup"]["total"], 3)

    def test_a_batch_over_budget_keeps_the_batches_that_finished(self):
        nodes = [endpoint(f"ep:{i}", ip=f"10.0.{i}.5") for i in range(3)]

        class SecondTimesOut(FakeRunner):
            def scan(self, ips, budget_s, per_host_timeout_s=60.0):
                if "10.0.2.5" in ips:                    # the second batch
                    raise NmapBudgetExceeded()
                return nmaprun(*(host_xml(ip, SSH_SERVICE_PORT) for ip in ips))

        runner = SecondTimesOut()
        with unittest.mock.patch.object(stagemod, "BATCH_SIZE", 2):
            result = self.run_it(graph(*nodes), runner)
        self.assertEqual([("open_ports" in n) for n in nodes], [True, True, False])
        self.assertEqual(nodes[0]["max_cvss"], 9.8)
        self.assertTrue(result.block["budget_exceeded"])
        self.assertEqual((result.block["scanned"], result.block["nmap_requests"]), (2, 2))

    def test_block_counts(self):
        node = endpoint("ep:a", ip="10.0.0.5")
        result = self.run_it(graph(node, endpoint("ep:b", ip="10.0.0.6")),
                             FakeRunner(nmaprun(host_xml("10.0.0.5", SSH_SERVICE_PORT, NBSTAT))))
        self.assertEqual(result.block["eligible"], 2)
        self.assertEqual(result.block["scanned"], 2)
        self.assertEqual(result.block["answered"], 1)
        self.assertEqual(result.block["with_cves"], 1)
        self.assertEqual(result.block["named"], 1)


class TestSpeed(unittest.TestCase):
    """nmap-cache.json and the batches run side by side."""

    def setUp(self):
        self.clock = FakeClock()
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, stagemod.CACHE_FILENAME)
        self.g = graph(endpoint("ep:a", ip="10.0.0.5"), endpoint("ep:b", ip="10.0.0.6"))

    def tearDown(self):
        import shutil
        shutil.rmtree(self.dir)

    def scan(self, **kw):
        runner = FakeRunner(nmaprun(host_xml("10.0.0.5", SSH_SERVICE_PORT)))   # .6 is silent
        _, scans, out = stagemod.scan_hosts(self.g, runner=runner,
                                            cache=stagemod.nmap_cache(self.path, self.clock), **kw)
        return runner.seen, sorted(scans), out.block["cached"]

    def test_cache_hit_miss_expiry_and_fresh(self):
        self.assertEqual(self.scan(), (["10.0.0.5", "10.0.0.6"], ["10.0.0.5"], 0))    # miss
        # hit: only the host that did not answer is asked again
        self.assertEqual(self.scan(), (["10.0.0.6"], ["10.0.0.5"], 1))
        self.assertEqual(self.scan(fresh=True), (["10.0.0.5", "10.0.0.6"], ["10.0.0.5"], 0))
        self.clock.advance(seconds=23 * 3600)
        self.assertEqual(self.scan()[2], 1)
        self.clock.advance(seconds=2 * 3600)                   # 25 h after the fresh scan
        self.assertEqual(self.scan(), (["10.0.0.5", "10.0.0.6"], ["10.0.0.5"], 0))   # expired

    def test_at_most_two_nmap_runs_at_once(self):
        import threading
        import time

        nodes = [endpoint(f"ep:{i}", ip=f"10.0.{i}.5") for i in range(10)]
        lock, now, peak, batches = threading.Lock(), [0], [0], []

        class Slow(FakeRunner):
            def scan(self, ips, budget_s, per_host_timeout_s=60.0):
                with lock:
                    now[0] += 1
                    peak[0] = max(peak[0], now[0])
                    batches.append(list(ips))
                time.sleep(0.05)
                with lock:
                    now[0] -= 1
                return nmaprun(*(host_xml(ip) for ip in ips))

        with unittest.mock.patch.object(stagemod, "BATCH_SIZE", 2):
            _, scans, out = stagemod.scan_hosts(graph(*nodes), runner=Slow())
        self.assertEqual((peak[0], len(batches), len(scans)), (2, 5, 10))
        self.assertEqual(out.block["nmap_requests"], 5)


class TestNoSecretInNmapArgs(unittest.TestCase):
    """The host list holds IPs only, and no secret reaches nmap's argv."""

    def test_host_list_file_and_argv(self):
        captured = {}

        def fake_run(args, **kw):
            captured["args"] = args
            listfile = args[args.index("-iL") + 1]
            with open(listfile) as f:
                captured["list"] = f.read()

            class P:
                returncode, stdout, stderr = 0, nmaprun(), ""
            return P()

        import unittest.mock as mock
        with mock.patch.object(nmapmod.subprocess, "run", fake_run):
            NmapRunner(nmap="/usr/bin/nmap").scan(["10.0.0.5", "10.0.0.6"], budget_s=300.0)
        self.assertEqual(captured["list"].split(), ["10.0.0.5", "10.0.0.6"])
        argv = captured["args"]
        self.assertEqual(argv[:7], ["/usr/bin/nmap", "-sV", "-T4", "--max-retries", "1",
                                    "--version-intensity", "5"])
        self.assertEqual(argv[argv.index("--host-timeout") + 1], "60s")
        for secret in ("public", "private", "NVD_API_KEY", "password"):
            self.assertNotIn(secret, " ".join(captured["args"]))


class TestPipelineGate(unittest.TestCase):
    """Flag off: the document gains nothing. Flag on: it wires through."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.network = os.path.join(self.tmp, "network.json")
        with open(self.network, "w") as f:
            json.dump(crawl(lab()), f)
        self.graph_path = os.path.join(self.tmp, "graph.json")
        self.clock = FakeClock()

    def run_pipeline(self, *extra, runner=None):
        argv = ["--no-endpoints", "--no-name-lookup", "--no-device-cves", "--no-cve-vectors",
                "--no-checklist", "--no-attack-paths", "--network", self.network,
                "-o", self.graph_path, *extra]
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = Pipeline(nvd_transport=lab_nvd(self.clock), clock=self.clock,
                            nmap_runner=runner).run(argv)
        self.assertEqual(code, 0)
        with open(self.graph_path) as f:
            return json.load(f)

    def test_off_adds_nothing(self):
        g = self.run_pipeline()
        self.assertNotIn("nmap", g["metadata"])
        self.assertNotIn("nmap_s", g["metadata"]["timing"])
        self.assertFalse(any("open_ports" in n for n in g["nodes"]))

    def test_on_is_wired_and_never_fails_when_nmap_is_missing(self):
        g = self.run_pipeline("--nmap-unmanaged", runner=FakeRunner(available=False))
        self.assertIn("nmap", g["metadata"])
        self.assertIsInstance(g["metadata"]["timing"]["nmap_s"], float)
        self.assertIn("nmap_not_installed", [w["type"] for w in g["metadata"]["warnings"]])
        stage = next(st for st in g["metadata"]["stages"] if st["name"] == "nmap service scan")
        self.assertEqual((stage["status"], stage["note"]), ("skipped", "nmap not installed"))


if __name__ == "__main__":
    unittest.main()
