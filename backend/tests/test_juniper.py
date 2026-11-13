"""Juniper's CVE records: the index, the record cache, and Junos devices
decided from them in the device CVE stage.

NVD is served by FakeNvd and cve.org by FakeCveOrg; nothing touches the network.
"""

import offline  # noqa: F401  (no test reaches the internet)
import json
import os
import tempfile
import unittest
from datetime import timedelta

from test_junos import JUNIPER_DIR, cna_record
from test_nvd import T0, FakeClock, FakeNvd, metric, record
from vulnmapper.devicecves import families, juniper, nvd
from vulnmapper.devicecves.cache import Cache
from vulnmapper.devicecves.lookup import SOURCE_JUNIPER, lookup
from vulnmapper.devicecves.stage import run_stage
from vulnmapper.scoring.feeds import FeedUnavailable

SOURCE = juniper.SOURCE_ID
# for JUNOS 20.2R2-S3.4 on an MX: CVE-2021-31353 affected (20.2 from 20.2R2-S3),
# CVE-2022-22210 unaffected (before 20.3R1), CVE-2023-28985 undecided (SigPack)
IDS = ["CVE-2021-31353", "CVE-2022-22210", "CVE-2023-28985"]
JUNOS_FW = "JUNOS 20.2R2-S3.4"
JUNOS_CPE = "cpe:2.3:o:juniper:junos:20.2:r2-s3:*:*:*:*:*:*"
EVO_FW = "JUNOS 21.1R1-S1.2-EVO"
EVO_CPE = "cpe:2.3:o:juniper:junos_os_evolved:21.1:r1-s1:*:*:*:*:*:*"


def nvd_index(*ids):
    return {SOURCE: [record(i) for i in ids]}


def cna_doc(cve_id, versions=(), metrics=(), state="PUBLISHED", product="Junos OS"):
    """A minimal CVE JSON 5 record."""
    cna = {"descriptions": [{"lang": "en", "value": f"{cve_id} in Junos OS."}],
           "references": [{"url": f"https://example.invalid/{cve_id}"}],
           "affected": [{"vendor": "Juniper Networks", "product": product,
                         "versions": list(versions)}],
           "metrics": list(metrics)}
    return {"cveMetadata": {"cveId": cve_id, "state": state, "datePublished": "2024-01-10T17:00:00Z"},
            "containers": {"cna": cna}}


class FakeCveOrg:
    """Serves CVE Services ``/api/cve/{id}`` from ``docs``; an id not in it is
    404. ``script``: per id, a status to answer once, or "down" to raise."""

    def __init__(self, docs=None, script=None):
        self.docs = docs if docs is not None else {i: cna_record(i) for i in IDS}
        self.script = dict(script or {})
        self.calls = []

    def __call__(self, url, timeout, progress=None):
        cve_id = url.rsplit("/", 1)[-1]
        self.calls.append(cve_id)
        action = self.script.pop(cve_id, None)
        if action == "down":
            raise FeedUnavailable("ConnectionError")
        if action is not None:
            return action, b""
        doc = self.docs.get(cve_id)
        if doc is None:
            return 404, b'{"error": "CVE_RECORD_DNE"}'
        return 200, json.dumps(doc).encode()


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, juniper.FILENAME)
        self.clock = FakeClock()
        self.index_nvd = FakeNvd(cves=nvd_index(*IDS), clock=self.clock)
        self.cveorg = FakeCveOrg()

    def tearDown(self):
        for name in os.listdir(self.tmp):
            os.unlink(os.path.join(self.tmp, name))
        os.rmdir(self.tmp)

    def records(self, concurrency=1, **kw):
        def index_client():
            return nvd.NvdClient(transport=self.index_nvd, clock=self.clock, api_key="k",
                                 budget_s=juniper.INDEX_BUDGET_S, use_env_key=False)
        return juniper.JuniperRecords(juniper.records_cache(self.path, self.clock), self.clock,
                                      index_client, self.cveorg, concurrency=concurrency, **kw)

    def index_entry(self):
        with open(self.path, encoding="utf-8") as f:
            return json.load(f)["entries"][juniper.INDEX_KEY]["data"]


class TestTrimRecord(unittest.TestCase):
    def test_published_record(self):
        r = juniper.trim_record(cna_record("CVE-2021-31353"))
        self.assertEqual((r["id"], r["state"]), ("CVE-2021-31353", "PUBLISHED"))
        self.assertEqual(r["descriptions"][0]["lang"], "en")
        self.assertTrue(r["references"][0]["url"].startswith("https://"))
        # Junos OS and Junos OS Evolved blocks are kept apart
        self.assertEqual([b["product"] for b in r["blocks"]], ["Junos OS"])
        self.assertEqual([b["product"] for b in r["evo_blocks"]], ["Junos OS Evolved"])
        (key,) = r["metrics"]
        self.assertIn(key, ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40"))
        entry = r["metrics"][key][0]
        self.assertEqual((entry["source"], entry["type"]), (SOURCE, "Secondary"))
        self.assertIsNotNone(entry["cvssData"]["baseScore"])

    def test_metric_names_follow_nvd(self):
        doc = cna_doc("CVE-2024-0001", metrics=[
            {"cvssV3_1": {"version": "3.1", "baseScore": 7.5, "baseSeverity": "HIGH"}},
            {"cvssV4_0": {"version": "4.0", "baseScore": 8.7, "baseSeverity": "HIGH"}},
            {"other": {"content": {}}}])
        r = juniper.trim_record(doc)
        self.assertEqual(sorted(r["metrics"]), ["cvssMetricV31", "cvssMetricV40"])
        row = nvd.parse_cve(r, package="P", version="V", detected_at="T")
        self.assertEqual((row["cvss"], row["cvss_version"]), (7.5, "3.1"))

    def test_rejected_record(self):
        doc = {"cveMetadata": {"cveId": "CVE-2024-0002", "state": "REJECTED"},
               "containers": {"cna": {"rejectedReasons": [{"lang": "en", "value": "Duplicate."}]}}}
        r = juniper.trim_record(doc)
        self.assertEqual((r["state"], r["blocks"], r["metrics"]), ("REJECTED", [], {}))

    def test_not_a_record(self):
        for doc in ({}, {"cveMetadata": {}}, {"cveMetadata": [], "containers": {}}):
            with self.assertRaises(ValueError):
                juniper.trim_record(doc)


class TestPrepare(Base):
    def test_first_scan_fetches_index_and_every_record(self):
        jr = self.records(concurrency=4)
        self.assertTrue(jr.prepare())
        self.assertEqual((jr.complete, jr.stale, jr.reason), (True, False, None))
        self.assertEqual(sorted(jr.records), IDS)
        self.assertEqual(sorted(self.cveorg.calls), IDS)
        self.assertEqual(jr.block()["index"], "full")
        self.assertEqual((jr.stats["fetched"], jr.stats["requests"], jr.stats["pending"]), (3, 3, 0))
        call = self.index_nvd.calls[0]
        self.assertEqual(call["params"]["sourceIdentifier"], SOURCE)
        self.assertNotIn("lastModStartDate", call["params"])
        self.assertEqual(jr.fetched_at["CVE-2021-31353"], T0.isoformat())
        # once per scan
        self.assertTrue(jr.prepare())
        self.assertEqual(len(self.cveorg.calls), 3)

    def test_next_scan_within_six_hours_asks_nothing(self):
        self.records().prepare()
        self.clock.advance(seconds=3600)
        jr = self.records()
        self.assertTrue(jr.prepare())
        self.assertEqual((len(self.index_nvd.calls), len(self.cveorg.calls)), (1, 3))
        self.assertEqual(jr.block()["index"], "fresh")
        self.assertFalse(jr.stale)

    def test_id_unknown_to_cve_org_is_a_known_answer(self):
        self.index_nvd.cves = nvd_index(*IDS, "CVE-2024-9999")
        jr = self.records()
        self.assertTrue(jr.prepare())
        self.assertEqual(jr.stats["not_found"], 1)
        self.assertNotIn("CVE-2024-9999", jr.records)

    def test_no_answer_stops_fetching_and_leaves_the_set_incomplete(self):
        self.cveorg.script = {IDS[0]: "down"}
        jr = self.records()
        self.assertFalse(jr.prepare())
        self.assertEqual(jr.reason, "juniper_records_incomplete")
        self.assertEqual(self.cveorg.calls, [IDS[0]])
        self.assertEqual((jr.stats["unanswered"], jr.stats["requests"], jr.stats["pending"]),
                         (1, 1, 3))
        cache = juniper.records_cache(self.path, self.clock)
        # only the id actually asked waits out the retry delay
        self.assertTrue(cache.failed_recently(IDS[0]))
        self.assertFalse(cache.failed_recently(IDS[1]))

    def test_rate_limit_stops_fetching(self):
        self.cveorg.script = {IDS[0]: 429}
        jr = self.records()
        self.assertFalse(jr.prepare())
        self.assertEqual(self.cveorg.calls, [IDS[0]])
        self.assertEqual(jr.reason, "juniper_records_incomplete")

    def test_a_later_scan_completes_the_set(self):
        self.cveorg.script = {IDS[1]: "down"}
        self.assertFalse(self.records().prepare())
        self.clock.advance(seconds=2 * 3600)       # past the retry delay, index still fresh
        jr = self.records()
        self.assertTrue(jr.prepare())
        self.assertEqual(sorted(jr.records), IDS)
        self.assertEqual(len(self.index_nvd.calls), 1)

    def test_no_index_and_nvd_down(self):
        self.index_nvd.script = ["down"]
        jr = self.records()
        self.assertFalse(jr.prepare())
        self.assertEqual(jr.reason, "juniper_index_unavailable")
        self.assertEqual(jr.block()["index"], "unanswered")
        self.assertEqual(self.cveorg.calls, [])

    def test_empty_full_index_is_no_index(self):
        self.index_nvd.cves = {}
        jr = self.records()
        self.assertFalse(jr.prepare())
        self.assertEqual((jr.reason, jr.block()["index"]), ("juniper_index_unavailable", "empty"))

    def test_incremental_sync_refetches_changed_records(self):
        self.records().prepare()
        self.clock.advance(seconds=7 * 3600)
        self.index_nvd.cves = nvd_index(IDS[0], "CVE-2024-9999")
        self.cveorg.calls.clear()
        jr = self.records()
        self.assertTrue(jr.prepare())
        self.assertEqual(jr.block()["index"], "incremental")
        params = self.index_nvd.calls[-1]["params"]
        self.assertEqual(params["lastModStartDate"], "2026-10-09T07:00:00.000Z")
        self.assertEqual(params["lastModEndDate"], "2026-10-09T15:00:00.000Z")
        # the new id first (never fetched), then the changed record although fresh
        self.assertEqual(self.cveorg.calls, ["CVE-2024-9999", IDS[0]])
        self.assertEqual(jr.ids, IDS + ["CVE-2024-9999"])
        self.assertEqual(self.index_entry()["changed"], {})

    def test_changed_record_not_refetched_stays_pending(self):
        self.records().prepare()
        self.clock.advance(seconds=7 * 3600)
        self.index_nvd.cves = nvd_index(IDS[0])
        self.cveorg.script = {IDS[0]: "down"}
        jr = self.records()
        self.assertTrue(jr.prepare())               # the older record still serves
        self.assertTrue(jr.stale)
        self.assertIn(IDS[0], self.index_entry()["changed"])

    def strip_evo_blocks(self):
        """The cache as an older release kept it: records without evo_blocks."""
        with open(self.path, encoding="utf-8") as f:
            doc = json.load(f)
        for cve_id in IDS:
            doc["entries"][cve_id]["data"].pop("evo_blocks", None)
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(doc, f)

    def test_records_kept_without_evolved_blocks_are_fetched_again(self):
        self.records().prepare()
        self.strip_evo_blocks()
        self.cveorg.calls.clear()
        jr = self.records()
        self.assertTrue(jr.prepare())
        self.assertEqual(sorted(self.cveorg.calls), IDS)
        self.assertEqual((jr.complete, jr.evo_complete, jr.stats["evo_pending"]), (True, True, 0))
        self.assertEqual(len(jr.records[IDS[0]]["evo_blocks"]), 1)

    def test_evolved_blocks_not_fetched_again_leave_the_set_incomplete_for_evolved(self):
        self.records().prepare()
        self.strip_evo_blocks()
        self.cveorg.script = {i: "down" for i in IDS}
        jr = self.records()
        self.assertTrue(jr.prepare())
        self.assertEqual((jr.complete, jr.evo_complete), (True, False))
        self.assertEqual(jr.block()["evo_complete"], False)
        self.assertGreater(jr.stats["evo_pending"], 0)

    def test_full_sync_after_119_days(self):
        self.records().prepare()
        self.clock.advance(days=120)
        self.cveorg.calls.clear()
        jr = self.records()
        self.assertTrue(jr.prepare())
        self.assertEqual(jr.block()["index"], "full")
        self.assertNotIn("lastModStartDate", self.index_nvd.calls[-1]["params"])
        self.assertEqual(sorted(self.cveorg.calls), IDS)        # expired after 30 days

    def test_index_not_synced_for_a_day_is_stale(self):
        self.records().prepare()
        self.clock.advance(days=2)
        self.index_nvd.script = ["down"]
        jr = self.records()
        self.assertTrue(jr.prepare())
        self.assertEqual(jr.block()["index"], "unanswered")
        self.assertTrue(jr.stale)

    def test_rejected_records_are_not_assessed(self):
        self.cveorg.docs[IDS[0]] = {**cna_record(IDS[0]),
                                    "cveMetadata": {"cveId": IDS[0], "state": "REJECTED"}}
        jr = self.records()
        jr.prepare()
        from vulnmapper.devicecves import junos
        affected, undecided = jr.assess(junos.parse_device(JUNOS_FW), "mx204")
        self.assertNotIn(IDS[0], [r["id"] for r in affected])

    def test_same_release_and_model_assessed_once(self):
        from unittest import mock
        from vulnmapper.devicecves import junos
        jr = self.records()
        jr.prepare()
        v = junos.parse_device(JUNOS_FW)
        with mock.patch.object(junos, "decide", wraps=junos.decide) as decide:
            first = jr.assess(v, "mx204")
            calls = decide.call_count
            first[0].clear()
            first[1].clear()                   # a caller's lists are its own
            again = jr.assess(junos.parse_device(JUNOS_FW), "mx204")
            self.assertEqual(decide.call_count, calls)
            self.assertEqual([r["id"] for r in again[0]], ["CVE-2021-31353"])
            self.assertEqual(again[1], ["CVE-2023-28985"])
            jr.assess(v, "ex4300-48t")         # another model is assessed on its own
            self.assertEqual(decide.call_count, 2 * calls)


def junos_node(firmware=JUNOS_FW, model="mx204", node_id="device:00:00:5e:00:53:01"):
    return {"node_id": node_id, "kind": "device", "pollable": True, "status": "online",
            "vendor": "Juniper Networks", "model": model, "firmware": firmware,
            "software_family": "juniper_junos_evolved" if firmware.endswith("-EVO") else "juniper_junos",
            "risk_score": 0, "max_cvss": None}


def nvd_hit(cve_id, *metrics_, criteria=None, status="Analyzed", **match):
    """An NVD CVE item with one vulnerable Junos criterion."""
    item = record(cve_id, *metrics_, status=status)
    cpe_match = {"vulnerable": True,
                 "criteria": criteria or "cpe:2.3:o:juniper:junos:20.2:r2-s3:*:*:*:*:*:*", **match}
    item["cve"]["configurations"] = [{"nodes": [{"operator": "OR", "cpeMatch": [cpe_match]}]}]
    return item


class TestJunosLookup(Base):
    def ident(self, firmware=JUNOS_FW, model="mx204"):
        return families.identify(junos_node(firmware, model))

    def junos(self, nvd_items=(), firmware=JUNOS_FW, model="mx204", jr=None):
        fake = FakeNvd(cves={JUNOS_CPE: list(nvd_items)}, clock=self.clock)
        client = nvd.NvdClient(transport=fake, clock=self.clock, api_key="k", use_env_key=False)
        cache = Cache(os.path.join(self.tmp, "nvd-cache.json"), self.clock)
        jr = jr or self.records()
        return lookup(self.ident(firmware, model), client, cache, jr, model), fake

    def test_identity(self):
        ident = self.ident()
        self.assertEqual((ident["family"], ident["match"], ident["cpe"]),
                         ("juniper_junos", "cpe", JUNOS_CPE))

    def test_cna_records_decide_and_nvd_adds_what_juniper_did_not_assign(self):
        items = [nvd_hit(IDS[0], metric("3.1", 1.0)),                     # in the index: CNA decides
                 nvd_hit("CVE-2016-0001", metric("3.1", 6.1, severity="MEDIUM"),
                         criteria="cpe:2.3:o:juniper:junos:*:*:*:*:*:*:*:*",
                         versionEndExcluding="21.1"),                     # bounded: kept
                 nvd_hit("CVE-2004-0001", criteria="cpe:2.3:o:juniper:junos:*:*:*:*:*:*:*:*"),
                 nvd_hit("CVE-2016-0002", status="Rejected")]
        result, fake = self.junos(items)
        self.assertEqual((result.status, result.source), ("ok", SOURCE_JUNIPER))
        rows = {r["cve"]: r for r in result.rows}
        self.assertEqual(sorted(rows), ["CVE-2016-0001", IDS[0]])
        self.assertNotEqual(rows[IDS[0]]["cvss"], 1.0)           # the CNA's score, not NVD's
        self.assertEqual(rows[IDS[0]]["detected_at"], T0.isoformat())
        self.assertEqual(rows["CVE-2016-0001"]["cvss"], 6.1)
        self.assertEqual(result.undecided, ["CVE-2023-28985"])
        # CVE-2022-22210 is fixed in 20.2 for this release: neither row nor undecided
        self.assertNotIn(IDS[1], rows)
        self.assertEqual(fake.calls[0]["params"]["cpeName"], JUNOS_CPE)
        self.assertEqual(set(fake.calls[0]["flags"]), {"isVulnerable", "noRejected"})

    def test_record_without_a_cna_score_takes_nvds(self):
        self.cveorg.docs[IDS[0]] = cna_doc(IDS[0], versions=[
            {"version": "20.2", "status": "affected", "lessThan": "20.2R3", "versionType": "custom"}])
        result, _ = self.junos([nvd_hit(IDS[0], metric("3.1", 7.5))])
        (row,) = [r for r in result.rows if r["cve"] == IDS[0]]
        self.assertEqual(row["cvss"], 7.5)

    def test_release_outside_the_regular_trains(self):
        result, fake = self.junos(firmware="JUNOS 15.1X49-D200.5", model="srx345")
        self.assertEqual((result.status, result.reason), ("unverified", "version_not_comparable"))
        self.assertEqual((fake.calls, self.cveorg.calls), ([], []))

    def test_incomplete_records_leave_the_device_unavailable(self):
        self.cveorg.script = {IDS[0]: "down"}
        result, fake = self.junos()
        self.assertEqual((result.status, result.reason), ("unavailable", "juniper_records_incomplete"))
        self.assertEqual(fake.calls, [])

    def test_stale_records_mark_the_answer_stale(self):
        self.records().prepare()
        self.clock.advance(days=2)
        self.index_nvd.script = ["down"]
        result, _ = self.junos()
        self.assertEqual(result.status, "ok")
        self.assertTrue(result.stale)

    def test_evolved_device_decided_from_the_evolved_blocks(self):
        fake = FakeNvd(cves={EVO_CPE: [
            nvd_hit("CVE-2016-0003", metric("3.1", 6.1, severity="MEDIUM"),
                    criteria="cpe:2.3:o:juniper:junos_os_evolved:*:*:*:*:*:*:*:*",
                    versionEndExcluding="22.1"),                     # bounded: kept
            nvd_hit("CVE-2016-0004", criteria="cpe:2.3:o:juniper:junos:*:*:*:*:*:*:*:*",
                    versionEndExcluding="22.1")]},                   # another product: dropped
            clock=self.clock)
        client = nvd.NvdClient(transport=fake, clock=self.clock, api_key="k", use_env_key=False)
        ident = self.ident(EVO_FW, "ptx10008")
        self.assertEqual((ident["family"], ident["cpe"]), ("juniper_junos_evolved", EVO_CPE))
        result = lookup(ident, client, Cache(None, self.clock), self.records(), "ptx10008")
        self.assertEqual((result.status, result.source), ("ok", SOURCE_JUNIPER))
        # CVE-2021-31353's Evolved block: 21.1 before 21.1R2
        self.assertEqual(sorted(r["cve"] for r in result.rows), ["CVE-2016-0003", IDS[0]])

    def test_evolved_device_unavailable_without_every_evolved_block(self):
        self.records().prepare()
        TestPrepare.strip_evo_blocks(self)
        self.cveorg.script = {i: "down" for i in IDS}
        result, _ = self.junos(firmware=EVO_FW, model="ptx10008")
        self.assertEqual((result.status, result.reason), ("unavailable", "juniper_records_incomplete"))
        # a Junos OS device is still answered
        self.cveorg.script = {i: "down" for i in IDS}
        result, _ = self.junos()
        self.assertEqual(result.status, "ok")

    def test_without_juniper_records_nvd_alone_answers(self):
        fake = FakeNvd(cves={JUNOS_CPE: []}, dictionary={JUNOS_CPE: [
            {"cpe": {"cpeName": JUNOS_CPE, "deprecated": False}}]}, clock=self.clock)
        client = nvd.NvdClient(transport=fake, clock=self.clock, api_key="k", use_env_key=False)
        result = lookup(self.ident(), client, Cache(None, self.clock))
        self.assertEqual((result.status, result.source, result.undecided), ("ok", "nvd", None))


class TestJunosStage(Base):
    def stage(self, *nodes, nvd_items=()):
        graph = {"nodes": list(nodes), "edges": [], "metadata": {}}
        fake = FakeNvd(cves={JUNOS_CPE: list(nvd_items)}, clock=self.clock)
        client = nvd.NvdClient(transport=fake, clock=self.clock, api_key="k", use_env_key=False)
        jr = self.records()
        return graph["nodes"], run_stage(graph, client, Cache(None, self.clock), jr)

    def test_junos_device_answered_from_juniper_records(self):
        (node,), result = self.stage(junos_node())
        lk = node["cve_lookup"]
        self.assertEqual((lk["status"], lk["source"], lk["undecided"]),
                         ("ok", SOURCE_JUNIPER, ["CVE-2023-28985"]))
        self.assertEqual(lk["total"], 1)
        self.assertNotIn("reason", lk)
        self.assertEqual([c["cve"] for c in node["top_cves"]], [IDS[0]])
        block = result.block["juniper"]
        self.assertEqual((block["complete"], block["ids"], block["fetched"]), (True, 3, 3))
        self.assertEqual(result.warnings, [])

    def test_records_unavailable_warning(self):
        self.index_nvd.script = ["down"]
        (node,), result = self.stage(junos_node())
        lk = node["cve_lookup"]
        self.assertEqual((lk["status"], lk["source"], lk["reason"]),
                         ("unavailable", SOURCE_JUNIPER, "juniper_index_unavailable"))
        self.assertEqual(result.warnings, [{"type": "juniper_records_unavailable",
                                            "node_ids": [node["node_id"]]}])
        self.assertEqual(result.block["juniper"]["reason"], "juniper_index_unavailable")

    def test_no_junos_device_asks_nothing(self):
        graph = {"nodes": [], "edges": [], "metadata": {}}
        client = nvd.NvdClient(transport=FakeNvd(clock=self.clock), clock=self.clock, api_key="k",
                               use_env_key=False)
        result = run_stage(graph, client, Cache(None, self.clock), self.records())
        self.assertNotIn("juniper", result.block)
        self.assertEqual((self.index_nvd.calls, self.cveorg.calls), ([], []))


if __name__ == "__main__":
    unittest.main()
