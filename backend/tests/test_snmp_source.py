"""C1: the community typed in the scan form is tried first, the server's SNMP
settings after it; the graph records which one each device answered (a label,
never the value) and warns when a typed community fell back."""

import offline  # noqa: F401  (no test reaches the internet)
import asyncio
import json
import unittest
from unittest import mock

from snmp_fakes import FakeSnmpClient
from test_cdp import AP_IP, L3_IPS, lab
from vulnmapper.liveness.monitor import LivenessMonitor
from vulnmapper.network import crawl
from vulnmapper.network.config import Config, load_credentials

TYPED = "typed-secret"
SERVER = "server-secret"
L2_IP, HP_IP = "172.20.10.100", "172.20.99.4"


def credentials(env):
    with mock.patch.dict("os.environ", env, clear=True):
        return load_credentials(None)


def run(env, sources):
    """A crawl of the CDP lab, each IP answering the credential source given
    (default "entered")."""
    client = lab()
    client.sources = {ip: "entered" for ip in client.devices}
    client.sources.update(sources)
    with mock.patch.object(crawl, "discover_seeds", lambda explicit: [L3_IPS[0]]), \
            mock.patch.object(crawl, "SnmpClient", lambda *a, **k: client):
        return asyncio.run(crawl.run(Config(credentials=credentials(env), seeds=[])))


def fallbacks(doc):
    return [w for w in doc.get("warnings") or [] if w["type"] == "snmp_fallback"]


class TestOrder(unittest.TestCase):
    def test_typed_first_then_server_labelled(self):
        creds = credentials({"VULNMAPPER_SNMP_COMMUNITY": TYPED, "SNMP_COMMUNITY": SERVER,
                             "SNMP_V3_USER": "u"})
        self.assertEqual([(c.community, c.source) for c in creds],
                         [(TYPED, "entered"), (SERVER, "server"), (None, "server")])

    def test_empty_form_is_server_only(self):
        self.assertEqual([c.source for c in credentials({"SNMP_COMMUNITY": SERVER})], ["server"])

    def test_typed_equal_to_server_counts_as_entered(self):
        creds = credentials({"VULNMAPPER_SNMP_COMMUNITY": SERVER, "SNMP_COMMUNITY": SERVER})
        self.assertEqual([c.source for c in creds], ["entered"])

    def test_liveness_after_a_typed_scan_tries_typed_then_server(self):
        env = {"VULNMAPPER_SNMP_COMMUNITY": TYPED, "SNMP_COMMUNITY": SERVER}
        with mock.patch.dict("os.environ", env, clear=True), \
                mock.patch("vulnmapper.network.snmp.SnmpClient") as client:
            LivenessMonitor()
        self.assertEqual([c.community for c in client.call_args.args[0]], [TYPED, SERVER])


class TestCrawl(unittest.TestCase):
    TYPED_ENV = {"VULNMAPPER_SNMP_COMMUNITY": TYPED, "SNMP_COMMUNITY": SERVER}

    def test_typed_works_everywhere_no_warning(self):
        doc = run(self.TYPED_ENV, {})
        self.assertEqual(fallbacks(doc), [])
        self.assertEqual(doc["snmp"]["server"], [])
        self.assertEqual(len(doc["snmp"]["entered"]), sum(n["pollable"] for n in doc["nodes"]))

    def test_typed_fails_on_one_device(self):
        doc = run(self.TYPED_ENV, {HP_IP: "server"})
        hp = next(n for n in doc["nodes"] if n["ip"] == HP_IP)
        self.assertEqual(doc["snmp"]["server"], [f"device:{hp['chassis_id']}"])
        self.assertEqual(fallbacks(doc), [{"type": "snmp_fallback", "devices": [hp["hostname"]]}])
        text = json.dumps(doc)
        self.assertNotIn(TYPED, text)
        self.assertNotIn(SERVER, text)

    def test_empty_form_env_only_no_warning(self):
        doc = run({"SNMP_COMMUNITY": SERVER}, {ip: "server" for ip in (*L3_IPS, L2_IP, AP_IP, HP_IP)})
        self.assertEqual(fallbacks(doc), [])
        self.assertEqual(doc["snmp"]["entered"], [])
        self.assertTrue(doc["snmp"]["server"])

    def test_nothing_answers_is_the_empty_crawl(self):
        with mock.patch.object(crawl, "discover_seeds", lambda explicit: ["192.0.2.1"]), \
                mock.patch.object(crawl, "SnmpClient", lambda *a, **k: FakeSnmpClient({})), \
                self.assertLogs(level="ERROR"):
            doc = asyncio.run(crawl.run(Config(credentials=credentials(self.TYPED_ENV), seeds=[])))
        self.assertEqual(doc["warnings"], [{"type": "crawl_empty", "reason": "no device answered"}])


if __name__ == "__main__":
    unittest.main()
