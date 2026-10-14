"""OVSS: the formula, tiers and overrides, the inputs (exposure, dependency,
CVSS selection), the node roll-up, the threat feeds and the CVE-record cache."""

import offline  # noqa: F401  (no test reaches the internet)
import gzip
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from test_nvd import FakeClock
from vulnmapper.scoring import cvss_select, feeds, ovss, stage
from vulnmapper.scoring.cvss_select import CveRecords, records_cache, select, trim_record

KEV_URL, EPSS_URL = feeds.KEV_URL, feeds.EPSS_URL
REAL_HTTP_GET = offline.REAL_HTTP_GET


def finding(cvss, exposure=0.5, dependency=0.0, kev=False, epss=0.0, confidence="confirmed",
            cve="CVE-1", record=None, tool_version="3.1"):
    return ovss.finding_record(cve, cvss, tool_version, record,
                               kev_ids={cve} if kev else set(), epss_scores={cve: epss},
                               exposure=exposure, dependency=dependency, confidence=confidence)


class TestWorkedExamples(unittest.TestCase):
    """The spec's three worked examples (inputs reconstructed from its results)."""

    def test_l3_switch_cve_2017_12240(self):
        # KEV; internal (0.5); 16 of the other 44 nodes depend on it
        dependency, _ = ovss.dependency_of(16, 45, None)
        r = finding(9.8, exposure=0.5, dependency=dependency, kev=True, cve="CVE-2017-12240",
                    confidence="potential")
        self.assertEqual((r["score"], r["tier"]), (7.016, "P0"))

    def test_firewall_cve_2019_5591_kev_egress(self):
        exposure, _ = ovss.exposure_of({"role": "router"}, None, set())
        r = finding(6.5, exposure=exposure, kev=True, cve="CVE-2019-5591", confidence="potential")
        self.assertEqual(r["score"], 4.875)
        self.assertEqual(ovss.tier(4.875, kev=False, potential=True, exposure=1.0), "P1")
        self.assertEqual(r["tier"], "P0")                       # KEV on the egress device

    def test_leaf_host_cve_2007_4559(self):
        # EPSS 0.271 is above the 0.1 saturation, so T = 1.0: 9.8 x 0.625 x 1.0.
        # The old spec's T = EPSS gave 9.8 x 0.625 x (0.5 + 0.5 x 0.271) = 3.892.
        r = finding(9.8, exposure=0.5, dependency=0.0, epss=0.271, cve="CVE-2007-4559")
        self.assertEqual((r["score"], r["tier"]), (6.125, "P1"))


class TestFormula(unittest.TestCase):
    def test_epss_saturates_at_0_1(self):
        self.assertEqual(ovss.threat(False, 0.05), 0.5)
        self.assertEqual(ovss.threat(False, 0.1), 1.0)
        self.assertEqual(ovss.threat(False, 0.9), 1.0)
        self.assertEqual(ovss.threat(False, None), 0.0)
        self.assertEqual(ovss.threat(True, 0.0), 1.0)

    def test_floors_and_ceiling(self):
        self.assertEqual(ovss.ovss(10.0, 0.0, 0.0, False, 0.0), 2.5)     # 10 x 0.5 x 0.5
        self.assertEqual(ovss.ovss(10.0, 1.0, 1.0, True, 0.0), 10.0)     # never above CVSS_B

    def test_tier_cuts(self):
        for score, want in ((6.75, "P0"), (6.749, "P1"), (4.5, "P1"), (2.5, "P2"), (2.499, "P3")):
            self.assertEqual(ovss.tier(score, kev=False, potential=False, exposure=0.5), want)

    def test_potential_only_cap(self):
        self.assertEqual(ovss.tier(9.0, kev=False, potential=True, exposure=0.5), "P1")
        self.assertEqual(ovss.tier(9.0, kev=True, potential=True, exposure=0.5), "P0")

    def test_kev_floor_is_p1(self):
        self.assertEqual(ovss.tier(1.0, kev=True, potential=False, exposure=0.5), "P1")
        self.assertEqual(ovss.tier(1.0, kev=True, potential=True, exposure=1.0), "P0")

    def test_unrated(self):
        r = finding(None, tool_version=None)
        self.assertEqual((r["score"], r["tier"], r["cvss_src"]), (None, "Unrated", None))


class TestInputs(unittest.TestCase):
    def test_exposure_router_first_even_unplaced(self):
        self.assertEqual(ovss.exposure_of({"role": "router"}, None, set()), (1.0, None))

    def test_exposure_isolated_internal_unknown(self):
        self.assertEqual(ovss.exposure_of({"role": "host"}, {30}, {10, 20}), (0.3, None))
        self.assertEqual(ovss.exposure_of({"role": "host"}, {10}, {10, 20}), (0.5, None))
        self.assertEqual(ovss.exposure_of({"role": "host"}, None, {10}),
                         (0.5, "exposure_unknown"))

    def test_dependency_is_max_of_topology_and_importance(self):
        self.assertEqual(ovss.dependency_of(2, 5, None), (0.5, 0.0))
        self.assertEqual(ovss.dependency_of(2, 5, "high"), (1.0, 1.0))
        self.assertEqual(ovss.dependency_of(0, 5, "low"), (0.25, 0.25))
        self.assertEqual(ovss.dependency_of(9, 5, None), (1.0, 0.0))      # capped
        self.assertEqual(ovss.dependency_of(0, 1, None), (0.0, 0.0))      # lone node

    def test_importance_raises_the_score(self):
        self.assertGreater(finding(7.5, dependency=ovss.dependency_of(0, 9, "moderate")[0])["score"],
                           finding(7.5, dependency=0.0)["score"])


def record(cna=(), adp=()):
    """A CVE JSON 5 record with ``(key, score)`` metric blocks."""
    return {"containers": {"cna": {"metrics": [{k: {"baseScore": s}} for k, s in cna]},
                           "adp": [{"metrics": [{k: {"baseScore": s}} for k, s in adp]}]}}


class TestCvssSelection(unittest.TestCase):
    def test_cna_then_adp_then_tool(self):
        both = trim_record(record(cna=[("cvssV3_1", 9.1)], adp=[("cvssV3_1", 5.0)]))
        self.assertEqual(select(both, 7.5, "3.1"), (9.1, "CNA", "3.1"))
        adp = trim_record(record(adp=[("cvssV3_1", 5.0)]))
        self.assertEqual(select(adp, 7.5, "3.1"), (5.0, "ADP", "3.1"))
        self.assertEqual(select(None, 7.5, "3.1"), (7.5, "tool", "3.1"))
        self.assertEqual(select(trim_record({}), None, None), (None, None, None))

    def test_highest_version_within_a_source(self):
        rec = trim_record(record(cna=[("cvssV3_1", 9.8), ("cvssV4_0", 8.7), ("cvssV2_0", 10.0)]))
        self.assertEqual(select(rec, None, None), (8.7, "CNA", "4.0"))

    def test_block_version_beats_key_and_unscored_blocks_skip(self):
        rec = trim_record({"containers": {"cna": {"metrics": [
            {"cvssV3_0": {"version": "3.0", "baseScore": 6.1}},
            {"cvssV3_1": {"vectorString": "no score"}},
            {"other": {"baseScore": 1.0}}]}}})
        self.assertEqual(select(rec, None, None), (6.1, "CNA", "3.0"))

    def test_conflict(self):
        rec = trim_record(record(cna=[("cvssV3_1", 9.8)]))
        self.assertEqual(finding(7.5, record=rec)["conflict"], 1)
        self.assertEqual(finding(9.0, record=rec)["conflict"], 0)                  # under 1.0
        self.assertEqual(finding(7.5, record=rec, tool_version="2.0")["conflict"], 0)
        self.assertEqual(finding(7.5)["conflict"], 0)                              # tool only
        self.assertEqual(finding(None, record=rec, tool_version=None)["conflict"], 0)


class TestNodeRecord(unittest.TestCase):
    def rollup(self, records, lookup=None):
        return ovss.node_record(records, cve_lookup=lookup, exposure=0.5, exposure_flag=None,
                                dependency=0.0, importance=0.0)

    def test_assessed(self):
        recs = [finding(9.8, kev=True, cve="A"), finding(5.0, cve="B"),
                finding(None, cve="C", tool_version=None)]
        n = self.rollup(recs)
        self.assertEqual(n["ovss_status"], "assessed")
        self.assertEqual(n["risk_score"], recs[0]["score"])
        self.assertEqual(n["node_tier"], "P1")                  # 6.125, a KEV CVE
        self.assertEqual(n["ovss_hist"], {"P0": 0, "P1": 1, "P2": 0, "P3": 1, "Unrated": 1})
        self.assertEqual((n["kev_count"], n["max_cvss"]), (1, 9.8))

    def test_unrated(self):
        n = self.rollup([finding(None, tool_version=None)])
        self.assertEqual((n["ovss_status"], n["risk_score"], n["node_tier"]),
                         ("Unrated", None, None))

    def test_unassessed_reasons(self):
        n = self.rollup([], {"match": "cpe", "total": 0})
        self.assertEqual((n["ovss_status"], n["ovss_reason"]),
                         ("Unassessed", "cpe match returned 0 CVEs"))
        self.assertEqual(self.rollup([], None)["ovss_reason"], "no findings returned")
        self.assertEqual(self.rollup([], {"match": "cpe", "total": None})["ovss_reason"],
                         "no findings returned")


KEV_BODY = json.dumps({"dateReleased": "2026-10-12T15:00:00Z",
                       "vulnerabilities": [{"cveID": "CVE-2019-5591"}]}).encode()
EPSS_BODY = gzip.compress(b"#model_version:v2025.03.14,score_date:2026-10-12T12:55:00Z\n"
                          b"cve,epss,percentile\nCVE-2007-4559,0.271,0.97\n")


class FakeFeeds:
    def __init__(self, bodies=None, down=False):
        self.bodies = bodies if bodies is not None else {KEV_URL: KEV_BODY, EPSS_URL: EPSS_BODY}
        self.down = down
        self.asked = []

    def __call__(self, url, timeout):
        self.asked.append(url)
        if self.down:
            raise feeds.FeedUnavailable("ConnectTimeout")
        return (200, self.bodies[url]) if url in self.bodies else (404, b"")


class TestFeeds(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.clock = FakeClock()

    def tearDown(self):
        shutil.rmtree(self.dir)

    def test_fresh_download_then_reuse_within_a_day(self):
        fake = FakeFeeds()
        t = feeds.load_threat(self.dir, self.clock, fake)
        self.assertEqual((t.kev, t.epss), ({"CVE-2019-5591"}, {"CVE-2007-4559": 0.271}))
        self.assertEqual(t.block, {"kev": "fresh", "epss": "fresh",
                                   "kev_date": "2026-10-12T15:00:00Z",
                                   "epss_date": "2026-10-12T12:55:00Z"})
        self.clock.advance(seconds=3600)
        feeds.load_threat(self.dir, self.clock, fake)
        self.assertEqual(len(fake.asked), 2)                  # no second download

    def test_stale_copy_when_download_fails(self):
        feeds.load_threat(self.dir, self.clock, FakeFeeds())
        self.clock.advance(days=3)
        t = feeds.load_threat(self.dir, self.clock, FakeFeeds(down=True))
        self.assertEqual((t.block["kev"], t.block["epss"]), ("stale", "stale"))
        self.assertEqual(t.kev, {"CVE-2019-5591"})

    def test_unavailable_without_any_copy(self):
        t = feeds.load_threat(self.dir, self.clock, FakeFeeds(down=True))
        self.assertEqual((t.kev, t.epss), (set(), {}))
        self.assertEqual((t.block["kev"], t.block["epss"]), ("unavailable", "unavailable"))

    def test_a_bad_body_is_a_failed_download(self):
        t = feeds.load_threat(self.dir, self.clock,
                              FakeFeeds({KEV_URL: b"<html>", EPSS_URL: b"no,columns\n"}))
        self.assertEqual((t.block["kev"], t.block["epss"]), ("unavailable", "unavailable"))
        self.assertFalse(os.listdir(self.dir))                 # nothing bad was kept


class SlowLink:
    """A feed transport on a dead or slow link: every call gives no answer
    (as http_get does after its read timeout or its budget), and is recorded."""

    def __init__(self):
        self.asked = []

    def __call__(self, url, timeout):
        self.asked.append((url, timeout))
        raise feeds.FeedUnavailable("ReadTimeout")


class TestFeedDownloadsNeverStall(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.clock = FakeClock()

    def tearDown(self):
        shutil.rmtree(self.dir)

    def test_one_attempt_per_feed_within_its_budget(self):
        slow = SlowLink()
        t = feeds.load_threat(self.dir, self.clock, slow)
        self.assertEqual(slow.asked, [(KEV_URL, 20.0), (EPSS_URL, 20.0)])     # no retry
        self.assertEqual((t.block["kev"], t.block["epss"]), ("unavailable", "unavailable"))

    def test_a_slow_link_falls_back_to_the_stale_copy(self):
        feeds.load_threat(self.dir, self.clock, FakeFeeds())
        self.clock.advance(days=2)
        t = feeds.load_threat(self.dir, self.clock, SlowLink())
        self.assertEqual((t.block["kev"], t.block["epss"], t.kev), ("stale", "stale", {"CVE-2019-5591"}))

    def test_logs_the_download_time_and_size(self):
        with self.assertLogs("vulnmapper.scoring", "INFO") as logs:
            feeds.load_threat(self.dir, self.clock, FakeFeeds())
        self.assertIn(f"CISA KEV downloaded in 0.0 s, {len(KEV_BODY)} bytes", "\n".join(logs.output))


class TestFeedRefreshCommand(unittest.TestCase):
    """python -m vulnmapper.scoring.feeds: fill the cache outside a scan."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.clock = FakeClock()

    def tearDown(self):
        shutil.rmtree(self.dir)

    def run_main(self, *argv, transport=None):
        import contextlib
        import io
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = feeds.main([*argv, "--cache-dir", self.dir], transport=transport, clock=self.clock)
        return code, out.getvalue(), err.getvalue()

    def file(self, name, body):
        path = os.path.join(self.dir, name)
        with open(path, "wb") as f:
            f.write(body)
        return path

    def test_refresh_fills_the_cache_the_scan_reads_as_fresh(self):
        seen = []

        def slow_but_whole(url, timeout, progress=None):
            seen.append(timeout)
            body = {KEV_URL: KEV_BODY, EPSS_URL: EPSS_BODY}[url]
            progress(len(body))
            return 200, body
        code, out, _ = self.run_main("--refresh", transport=slow_but_whole)
        self.assertEqual((code, seen), (0, [600.0, 600.0]))           # no scan budget
        self.assertIn("CISA KEV: 2026-10-12T15:00:00Z", out)
        self.assertIn("FIRST EPSS: 2026-10-12T12:55:00Z", out)
        never = FakeFeeds(down=True)
        t = feeds.load_threat(self.dir, self.clock, never)
        self.assertEqual((t.block["kev"], t.block["epss"], never.asked), ("fresh", "fresh", []))
        self.assertEqual(t.epss, {"CVE-2007-4559": 0.271})

    def test_import_from_files_fetched_elsewhere(self):
        kev = self.file("dl-kev.json", KEV_BODY)
        epss = self.file("dl-epss.csv", gzip.decompress(EPSS_BODY))         # plain CSV too
        code, out, _ = self.run_main("--from-kev", kev, "--from-epss", epss)
        self.assertEqual(code, 0)
        t = feeds.load_threat(self.dir, self.clock, FakeFeeds(down=True))
        self.assertEqual((t.block["kev"], t.block["epss"], t.kev), ("fresh", "fresh", {"CVE-2019-5591"}))

    def test_import_rejects_a_malformed_file_and_keeps_the_cache(self):
        self.run_main("--from-kev", self.file("good.json", KEV_BODY))
        cached = os.path.join(self.dir, feeds.KEV_FILENAME)
        before = os.path.getmtime(cached)
        self.clock.advance(seconds=60)
        for bad in (b"<html>not json</html>", b'{"vulnerabilities": "no"}'):
            code, _, err = self.run_main("--from-kev", self.file("bad.json", bad))
            self.assertEqual(code, 1)
            self.assertIn("failed", err)
        code, _, _ = self.run_main("--from-epss", self.file("bad.csv", b"id,score\nx,1\n"))
        self.assertEqual(code, 1)
        self.assertFalse(os.path.exists(os.path.join(self.dir, feeds.EPSS_FILENAME)))
        with open(cached, "rb") as f:
            self.assertEqual(f.read(), KEV_BODY)
        self.assertEqual(os.path.getmtime(cached), before)

    def test_a_failed_download_leaves_the_cache_and_exits_1(self):
        code, _, err = self.run_main("--refresh", transport=lambda url, timeout, progress=None: (503, b""))
        self.assertEqual(code, 1)
        self.assertIn("HTTP 503", err)
        self.assertEqual(os.listdir(self.dir), [])

    def test_needs_an_action(self):
        import contextlib
        import io
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            feeds.main(["--cache-dir", self.dir])


class FakeResponse:
    """A streamed reply whose every chunk takes ``per_chunk`` seconds to arrive."""

    def __init__(self, chunks, per_chunk, clock):
        self.chunks, self.per_chunk, self.clock, self.status_code = chunks, per_chunk, clock, 200

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def iter_content(self, size):
        for c in self.chunks:
            self.clock[0] += self.per_chunk
            yield c


class TestHttpGet(unittest.TestCase):
    """The real transport, with requests and the monotonic clock faked."""

    def get(self, chunks, per_chunk, budget):
        now = [0.0]
        calls = []

        def fake_get(url, timeout, stream):
            calls.append(timeout)
            return FakeResponse(chunks, per_chunk, now)
        with mock.patch("requests.get", fake_get), \
                mock.patch.object(feeds.time, "monotonic", lambda: now[0]):
            try:
                return REAL_HTTP_GET("https://feed", budget, progress=self.seen.append), calls
            except feeds.FeedUnavailable as e:
                return e, calls

    def test_a_trickling_body_is_abandoned_at_the_budget(self):
        out, calls = self.get([b"x"] * 100, per_chunk=8.0, budget=20.0)
        self.assertIsInstance(out, feeds.FeedUnavailable)
        self.assertEqual(calls, [(10.0, 10.0)])           # connect and read timeout

    def setUp(self):
        self.seen = []

    def test_a_body_inside_the_budget_is_returned_whole(self):
        out, calls = self.get([b"ab", b"cd"], per_chunk=1.0, budget=20.0)
        self.assertEqual(out, (200, b"abcd"))
        self.assertEqual(self.seen, [2, 4])                  # progress after each read

    def test_the_read_timeout_never_exceeds_the_budget(self):
        _, calls = self.get([b"a"], per_chunk=0.0, budget=5.0)
        self.assertEqual(calls, [(5.0, 5.0)])

    def test_no_answer_is_feed_unavailable(self):
        import requests
        with mock.patch("requests.get", side_effect=requests.ConnectTimeout()):
            with self.assertRaises(feeds.FeedUnavailable):
                REAL_HTTP_GET("https://feed", 20.0)


def cve_record(score):
    return json.dumps(record(cna=[("cvssV3_1", score)])).encode()


class FakeCveOrg:
    """Serves ``records[id]``; an id in ``slow`` raises (no answer)."""

    def __init__(self, records=None, slow=(), status=None):
        self.records = records or {}
        self.slow = set(slow)
        self.status = status
        self.asked = []

    def __call__(self, url, timeout):
        cve_id = url.rsplit("/", 1)[1]
        self.asked.append(cve_id)
        if cve_id in self.slow:
            raise feeds.FeedUnavailable("ReadTimeout")
        if self.status:
            return self.status, b""
        return (200, cve_record(self.records[cve_id])) if cve_id in self.records else (404, b"")


class TestCveRecords(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, cvss_select.FILENAME)
        self.clock = FakeClock()

    def tearDown(self):
        shutil.rmtree(self.dir)

    def load(self, fake, ids, **kw):
        client = CveRecords(records_cache(self.path, self.clock), self.clock, fake,
                            concurrency=1, **kw)
        return client.load(ids), client.stats

    def test_miss_then_hit(self):
        got, stats = self.load(FakeCveOrg({"CVE-A": 9.8}), ["CVE-A", "CVE-B"])
        self.assertEqual(got, {"CVE-A": {"cna": [{"version": "3.1", "score": 9.8}], "adp": []}})
        self.assertEqual((stats["fetched"], stats["not_found"]), (1, 1))
        fake = FakeCveOrg()
        again, stats = self.load(fake, ["CVE-A", "CVE-B"])
        self.assertEqual((again, stats["hits"], fake.asked), (got, 2, []))

    def test_expired_entries_refetch_and_not_found_expires_sooner(self):
        self.load(FakeCveOrg({"CVE-A": 9.8}), ["CVE-A", "CVE-B"])
        self.clock.advance(days=2)
        fake = FakeCveOrg({"CVE-B": 5.0})
        got, _ = self.load(fake, ["CVE-A", "CVE-B"])
        self.assertEqual(fake.asked, ["CVE-B"])              # 1 day for not found, 30 for a record
        self.assertEqual(got["CVE-B"]["cna"][0]["score"], 5.0)
        self.clock.advance(days=31)
        got, stats = self.load(FakeCveOrg(slow={"CVE-A"}), ["CVE-A"])
        self.assertEqual((got["CVE-A"]["cna"][0]["score"], stats["expired_used"]), (9.8, 1))

    def test_dead_link_stops_all_requests(self):
        fake = FakeCveOrg({"CVE-B": 5.0}, slow={"CVE-A"})
        got, stats = self.load(fake, ["CVE-A", "CVE-B", "CVE-C"])
        self.assertEqual((got, fake.asked, stats["unanswered"]), ({}, ["CVE-A"], 3))

    def test_rate_limit_stops_too(self):
        fake = FakeCveOrg(status=429)
        _, stats = self.load(fake, ["CVE-A", "CVE-B"])
        self.assertEqual((fake.asked, stats["unanswered"]), (["CVE-A"], 2))

    def test_budget(self):
        fake = FakeCveOrg({"CVE-A": 9.8})
        got, stats = self.load(fake, ["CVE-A"], budget_s=0)
        self.assertEqual((got, fake.asked, stats["unanswered"]), ({}, [], 1))
        self.assertIsNone(records_cache(self.path, self.clock).get("CVE-A"))   # nothing cached

    def test_unanswered_falls_back_to_the_tool_score(self):
        got, _ = self.load(FakeCveOrg(slow={"CVE-A"}), ["CVE-A"])
        self.assertEqual(select(got.get("CVE-A"), 7.5, "3.1"), (7.5, "tool", "3.1"))


if __name__ == "__main__":
    unittest.main()


class TestTopCves(unittest.TestCase):
    """top_cves: the node's worst CVEs by OVSS, then CVSS, built from the findings."""

    def setUp(self):
        # eleven 9.x CVEs fill the old CVSS top 10; a 5.0 KEV CVE sets the node's score
        self.catalogue = {f"CVE-H{i}": {"cvss": 9.0 + i / 100, "cvss_version": "3.1",
                                        "severity": "Critical", "description": "d",
                                        "reference": None, "published_at": None}
                          for i in range(11)}
        self.catalogue["CVE-KEV"] = {"cvss": 5.0, "cvss_version": "3.1", "severity": "Medium",
                                     "description": "kev", "reference": "https://x",
                                     "published_at": None, "attack_vector": "NETWORK"}
        self.findings = [{"cve": c, "package": "p", "version": "1", "detected_at": None}
                         for c in self.catalogue]
        self.per_cve = {c: finding(e["cvss"], cve=c, kev=c == "CVE-KEV")
                        for c, e in self.catalogue.items()}
        old_top = [{"cve": c, **self.catalogue[c], **self.per_cve[c]}
                   for c in sorted(self.catalogue, key=lambda c: -self.catalogue[c]["cvss"])[:10]]
        self.rows = stage.top_cves(old_top, self.findings, self.per_cve, self.catalogue)

    def test_the_cve_that_sets_the_score_is_listed_first(self):
        self.assertEqual(len(self.rows), 10)
        self.assertEqual(self.rows[0]["cve"], "CVE-KEV")
        self.assertEqual(self.rows[0]["score"], max(r["score"] for r in self.per_cve.values()))

    def test_a_new_row_has_the_row_shape(self):
        self.assertEqual(list(self.rows[0])[:10], ["cve", "cvss", "cvss_version", "severity",
                                                   "package", "version", "description",
                                                   "reference", "published_at", "detected_at"])
        self.assertEqual((self.rows[0]["attack_vector"], self.rows[0]["kev"]), ("NETWORK", True))

    def test_then_by_cvss(self):
        rest = self.rows[1:]
        self.assertEqual([r["cvss"] for r in rest], sorted((r["cvss"] for r in rest), reverse=True))

    def test_without_findings_rows_are_only_reordered(self):
        rows = [{"cve": "A", "score": 1.0, "cvss": 9.8}, {"cve": "B", "score": 4.0, "cvss": 5.0},
                {"cve": "C", "score": None, "cvss": None}]
        self.assertEqual([r["cve"] for r in stage.top_cves(rows, None, {}, {})], ["B", "A", "C"])


# --- for the tests that compare a pipeline run with output frozen before OVSS ---

OVSS_NODE_FIELDS = set(ovss.node_record([], cve_lookup=None, exposure=0, exposure_flag=None,
                                        dependency=0, importance=0)) - {"max_cvss"}
OVSS_FINDING_FIELDS = set(finding(None))


def strip_ovss(doc):
    """A graph or vulnerabilities document without what the OVSS stage adds
    (and without risk_score, which it replaces), in place; returns it."""
    meta = doc.get("metadata") or {}
    for key in ("ovss", "threat_feeds"):
        meta.pop(key, None)
    (meta.get("timing") or {}).pop("ovss_s", None)
    if "warnings" in meta:
        meta["warnings"] = [w for w in meta["warnings"]
                            if w.get("type") != "threat_feeds_unavailable"]
    if "stages" in meta:
        meta["stages"] = [s for s in meta["stages"] if s["name"] != "OVSS scoring"]
    rows = [f for h in (doc.get("hosts") or {}).values() for f in h.get("findings") or []]
    for node in doc.get("nodes") or []:
        for key in OVSS_NODE_FIELDS:
            node.pop(key, None)
        rows += node.get("top_cves") or []
    for row in rows:
        for key in OVSS_FINDING_FIELDS:
            row.pop(key, None)
    return doc
