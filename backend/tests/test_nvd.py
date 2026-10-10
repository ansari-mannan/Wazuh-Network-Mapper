"""The NVD client, its cache and one device's lookup, from saved replies.

No test here touches the network: every reply comes from FakeNvd, and the
clock is a FakeClock that tests move forward.
"""

import copy
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qsl, urlsplit

from vulnmapper.devicecves import families, nvd
from vulnmapper.devicecves.cache import Cache
from vulnmapper.devicecves.lookup import lookup

HERE = os.path.dirname(os.path.abspath(__file__))
NVD_DIR = os.path.join(HERE, "fixtures", "nvd")
IOS_CPE = r"cpe:2.3:o:cisco:ios:12.2\(55\)se12:*:*:*:*:*:*:*"
FORTIOS_CPE = "cpe:2.3:o:fortinet:fortios:6.0.16:*:*:*:*:*:*:*"
T0 = datetime(2026, 10, 9, 8, 0, tzinfo=timezone.utc)
# The CVE answer arrives one request spacing (6 s, no key) after the dictionary check.
FETCHED = (T0 + timedelta(seconds=6)).isoformat()


def saved(name):
    with open(os.path.join(NVD_DIR, name), encoding="utf-8") as f:
        return json.load(f)


class FakeClock:
    def __init__(self, now=T0):
        self._now = now
        self._mono = 1000.0
        self.sleeps = []

    def now(self):
        return self._now

    def monotonic(self):
        return self._mono

    def sleep(self, seconds):
        self.sleeps.append(round(seconds, 3))
        self.advance(seconds)

    def advance(self, seconds=0, days=0):
        self._mono += seconds + days * 86400
        self._now += timedelta(seconds=seconds, days=days)


class FakeNvd:
    """Serves NVD from tables: ``cves[cpe or keyword]`` and ``dictionary[cpe]``.

    ``page`` caps a page whatever resultsPerPage asks (NVD may send fewer).
    ``script`` is a list of statuses returned, in order, before real answers.
    """

    def __init__(self, cves=None, dictionary=None, page=None, script=(), clock=None,
                 latency=0.0):
        self.cves = cves or {}
        self.dictionary = dictionary or {}
        self.page = page
        self.script = list(script)
        self.calls = []
        self.clock = clock
        self.latency = latency

    def __call__(self, url, headers, timeout):
        parts = urlsplit(url)
        params = dict(parse_qsl(parts.query, keep_blank_values=True))
        flags = [p for p in parts.query.split("&") if "=" not in p]
        self.calls.append({"path": parts.path, "params": params, "flags": flags,
                           "headers": dict(headers), "url": url, "timeout": timeout})
        if self.clock is not None and self.latency:
            self.clock.advance(self.latency)
        if self.script:
            status = self.script.pop(0)
            if status == "down":
                raise nvd.NvdUnavailable("ConnectionError")
            if status == 404:
                return 404, None, {"message": "Invalid cpeName parameter, see documentation."}
            return status, None, {}
        start = int(params.get("startIndex", 0))
        size = int(params.get("resultsPerPage", 2000))
        if self.page:
            size = min(size, self.page)
        if parts.path.endswith("/cpes/2.0"):
            items = self.dictionary.get(params["cpeMatchString"], [])
            key = "products"
        else:
            items = self.cves.get(params.get("cpeName") or params.get("keywordSearch"), [])
            key = "vulnerabilities"
        page = items[start:start + size]
        return 200, {"resultsPerPage": len(page), "startIndex": start,
                     "totalResults": len(items), key: page}, {}


def ios_cves():
    return saved("cves_cpe_ios_12.2-55-se12.json")["vulnerabilities"]


def listed(cpe):
    return [{"cpe": {"cpeName": cpe, "deprecated": False}}]


def ident_for(cpe=IOS_CPE, product="Cisco IOS 12.2(55)SE12", version="12.2(55)SE12"):
    return {"match": "cpe", "cpe": cpe, "product": product, "version": version}


def metric(version, score, kind="Primary", severity="HIGH"):
    key = {"3.1": "cvssMetricV31", "3.0": "cvssMetricV30", "4.0": "cvssMetricV40",
           "2.0": "cvssMetricV2"}[version]
    entry = {"type": kind, "cvssData": {"version": version, "baseScore": score}}
    if version == "2.0":
        entry["baseSeverity"] = severity
    else:
        entry["cvssData"]["baseSeverity"] = severity
    return key, entry


def record(cve_id, *metrics_, status="Analyzed"):
    m = {}
    for key, entry in metrics_:
        m.setdefault(key, []).append(entry)
    return {"cve": {"id": cve_id, "vulnStatus": status, "published": "2020-01-02T03:04:05.000",
                    "descriptions": [{"lang": "es", "value": "Una"}, {"lang": "en", "value": "An issue."}],
                    "references": [{"url": "https://example.invalid/a"}], "metrics": m}}


class TestParsing(unittest.TestCase):
    def row(self, *metrics_):
        return nvd.parse_cve(record("CVE-2020-0001", *metrics_)["cve"], package="P", version="V",
                             detected_at="T")

    def test_v31_preferred_and_primary_before_secondary(self):
        r = self.row(metric("2.0", 10.0), metric("3.0", 9.0), metric("3.1", 6.5, "Secondary"),
                     metric("3.1", 7.5, "Primary"))
        self.assertEqual((r["cvss"], r["cvss_version"], r["severity"]), (7.5, "3.1", "High"))

    def test_v30_then_v40_then_v2(self):
        self.assertEqual(self.row(metric("2.0", 5.0), metric("3.0", 6.1, severity="MEDIUM"))["cvss"], 6.1)
        self.assertEqual(self.row(metric("2.0", 5.0), metric("4.0", 8.7))["cvss_version"], "4.0")
        r = self.row(metric("2.0", 5.0, severity="MEDIUM"))
        self.assertEqual((r["cvss"], r["cvss_version"], r["severity"]), (5.0, "2.0", "Medium"))

    def test_secondary_used_when_it_is_all_there_is(self):
        self.assertEqual(self.row(metric("3.1", 4.4, "Secondary"))["cvss"], 4.4)

    def test_no_score(self):
        r = self.row()
        self.assertEqual((r["cvss"], r["cvss_version"], r["severity"]), (None, None, None))

    def test_row_shape_matches_hosts(self):
        r = self.row(metric("3.1", 9.8, severity="CRITICAL"))
        self.assertEqual(set(r), {"cve", "cvss", "cvss_version", "severity", "package", "version",
                                  "description", "reference", "published_at", "detected_at",
                                  *nvd.VECTOR_KEYS})
        self.assertEqual((r["description"], r["reference"], r["published_at"], r["severity"]),
                         ("An issue.", "https://example.invalid/a", "2020-01-02T03:04:05.000Z",
                          "Critical"))

    def test_saved_reply(self):
        rows = [nvd.parse_cve(v["cve"], package="Cisco IOS 12.2(55)SE12", version="12.2(55)SE12",
                              detected_at="T") for v in ios_cves()]
        self.assertEqual(len(rows), 8)
        self.assertEqual(rows[3]["cve"], "CVE-2006-4950")
        self.assertEqual((rows[3]["cvss"], rows[3]["cvss_version"]), (10.0, "2.0"))


def vector(cve_id, version, score, vector_string, **data):
    """A record with one Primary metric carrying exploitability fields."""
    key, entry = metric(version, score)
    entry["cvssData"]["vectorString"] = vector_string
    entry["cvssData"].update({k: v for k, v in data.items() if k != "ui_required"})
    if "ui_required" in data:
        entry["userInteractionRequired"] = data["ui_required"]
    return record(cve_id, (key, entry))


class TestVectorFields(unittest.TestCase):
    def fields(self, rec):
        r = nvd.parse_cve(rec["cve"], package=None, version=None, detected_at=None)
        return {k: r[k] for k in nvd.VECTOR_KEYS}

    def test_v31(self):
        self.assertEqual(self.fields(vector(
            "CVE-1", "3.1", 8.8, "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            attackVector="ADJACENT_NETWORK", attackComplexity="LOW", privilegesRequired="NONE",
            userInteraction="NONE")), {
            "attack_vector": "ADJACENT", "attack_complexity": "LOW", "privileges_required": "NONE",
            "user_interaction": "NONE",
            "cvss_vector": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cvss_vector_version": "3.1"})

    def test_v4(self):
        f = self.fields(vector(
            "CVE-1", "4.0", 7.1, "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            attackVector="ADJACENT", attackComplexity="LOW", attackRequirements="NONE",
            privilegesRequired="LOW", userInteraction="PASSIVE"))
        self.assertEqual((f["attack_vector"], f["attack_complexity"], f["privileges_required"],
                          f["user_interaction"], f["cvss_vector_version"]),
                         ("ADJACENT", "LOW", "LOW", "PASSIVE", "4.0"))

    def test_v2_mapping(self):
        f = self.fields(vector("CVE-1", "2.0", 6.8, "AV:N/AC:M/Au:S/C:P/I:P/A:P",
                               accessVector="NETWORK", accessComplexity="MEDIUM",
                               authentication="SINGLE", ui_required=True))
        self.assertEqual((f["attack_vector"], f["attack_complexity"], f["privileges_required"],
                          f["user_interaction"], f["cvss_vector"], f["cvss_vector_version"]),
                         ("NETWORK", "MEDIUM", "LOW", "REQUIRED", "AV:N/AC:M/Au:S/C:P/I:P/A:P", "2.0"))
        f = self.fields(vector("CVE-1", "2.0", 4.6, "AV:A/AC:H/Au:M/C:P/I:N/A:N",
                               accessVector="ADJACENT_NETWORK", accessComplexity="HIGH",
                               authentication="MULTIPLE"))
        self.assertEqual((f["attack_vector"], f["attack_complexity"], f["privileges_required"],
                          f["user_interaction"]), ("ADJACENT", "HIGH", "HIGH", None))

    def test_same_metric_as_the_score(self):
        rec = vector("CVE-1", "3.1", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                     attackVector="NETWORK", attackComplexity="LOW", privilegesRequired="NONE",
                     userInteraction="NONE")
        key, v2 = metric("2.0", 10.0)
        v2["cvssData"].update(vectorString="AV:L/AC:L/Au:N/C:C/I:C/A:C", accessVector="LOCAL")
        rec["cve"]["metrics"][key] = [v2]
        r = nvd.parse_cve(rec["cve"], package=None, version=None, detected_at=None)
        self.assertEqual((r["cvss"], r["attack_vector"], r["cvss_vector_version"]),
                         (9.8, "NETWORK", "3.1"))

    def test_no_metric(self):
        self.assertEqual(set(self.fields(record("CVE-1"))[k] for k in nvd.VECTOR_KEYS), {None})

    def test_saved_replies(self):
        ios = {v["cve"]["id"]: v["cve"] for v in ios_cves()}
        f = nvd.vector_fields(ios["CVE-2006-4950"]["metrics"])
        self.assertEqual((f["attack_vector"], f["attack_complexity"], f["privileges_required"],
                          f["user_interaction"]), ("NETWORK", "LOW", "NONE", "NONE"))
        forti = saved("cves_cpe_fortios_6.0.16.json")["vulnerabilities"][0]["cve"]
        self.assertEqual(nvd.vector_fields(forti["metrics"])["cvss_vector"],
                         "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "nvd-cache.json")
        self.clock = FakeClock()

    def tearDown(self):
        for name in os.listdir(self.tmp):
            os.unlink(os.path.join(self.tmp, name))
        os.rmdir(self.tmp)

    def nvd(self, **kw):
        kw.setdefault("cves", {IOS_CPE: ios_cves()})
        kw.setdefault("dictionary", {IOS_CPE: listed(IOS_CPE)})
        return FakeNvd(clock=self.clock, **kw)

    def run_lookup(self, fake, ident=None, budget=180.0, key=None, cache=None):
        client = nvd.NvdClient(transport=fake, clock=self.clock, api_key=key or "",
                               budget_s=budget, use_env_key=False)
        cache = cache or Cache(self.path, self.clock)
        result = lookup(ident or ident_for(), client, cache)
        cache.save()
        return result, client


class TestQueries(Base):
    def test_cpe_query_is_checked_in_the_dictionary_then_asked(self):
        fake = self.nvd()
        result, client = self.run_lookup(fake)
        self.assertEqual((result.status, result.match, len(result.rows)), ("ok", "cpe", 8))
        self.assertEqual([c["path"] for c in fake.calls],
                         ["/rest/json/cpes/2.0", "/rest/json/cves/2.0"])
        cves = fake.calls[1]
        self.assertEqual(cves["params"]["cpeName"], IOS_CPE)
        self.assertEqual(set(cves["flags"]), {"isVulnerable", "noRejected"})
        self.assertEqual(client.requests, 2)
        self.assertEqual(result.rows[0]["package"], "Cisco IOS 12.2(55)SE12")
        self.assertEqual(result.rows[0]["version"], "12.2(55)SE12")
        self.assertEqual(result.rows[0]["detected_at"], FETCHED)

    def test_a_cpe_nvd_never_listed_is_unverified_and_not_asked(self):
        # NVD answers a made-up version with every CVE whose range includes it
        fake = self.nvd(dictionary={})
        result, _ = self.run_lookup(fake)
        self.assertEqual((result.status, result.reason, result.rows), ("unverified", "not_in_dictionary", None))
        self.assertEqual(len(fake.calls), 1)
        self.assertEqual(saved("cpes_not_listed.json")["totalResults"], 0)

    def test_malformed_query_is_unverified(self):
        result, _ = self.run_lookup(self.nvd(script=[404]))
        self.assertEqual((result.status, result.reason), ("unverified", "invalid_query"))

    def test_rejected_cves_are_skipped(self):
        cves = ios_cves()[:2] + [record("CVE-2020-9999", metric("3.1", 9.8), status="Rejected")]
        result, _ = self.run_lookup(self.nvd(cves={IOS_CPE: cves}))
        self.assertEqual([r["cve"] for r in result.rows], [c["cve"]["id"] for c in ios_cves()[:2]])

    def test_paging_across_more_than_one_page(self):
        fake = self.nvd(page=3)
        result, client = self.run_lookup(fake)
        self.assertEqual(len(result.rows), 8)
        starts = [int(c["params"]["startIndex"]) for c in fake.calls if c["path"].endswith("cves/2.0")]
        self.assertEqual(starts, [0, 3, 6])
        self.assertEqual(client.requests, 4)

    def test_answered_with_nothing_is_ok_and_empty(self):
        result, _ = self.run_lookup(self.nvd(cves={IOS_CPE: []}))
        self.assertEqual((result.status, result.rows), ("ok", []))

    def test_keyword_query_keeps_only_what_the_rule_accepts(self):
        kw = families.identify({"kind": "device", "pollable": True, "vendor": "HP",
                                "model": "HP 1920-48G", "firmware": "5.20.99 Release 1107",
                                "software_family": "hp_comware"})
        fake = self.nvd(cves={"1920": saved("cves_keyword_1920.json")["vulnerabilities"]})
        result, _ = self.run_lookup(fake, ident=kw)
        self.assertEqual((result.status, result.match, result.rows), ("ok", "keyword", []))
        self.assertEqual(fake.calls[0]["params"]["keywordSearch"], "1920")
        self.assertIn("noRejected", fake.calls[0]["flags"])


class TestRateLimit(Base):
    def test_requests_are_spaced_without_a_key(self):
        _, client = self.run_lookup(self.nvd())
        self.assertEqual(client.spacing_s, 6.0)
        self.assertEqual(self.clock.sleeps, [6.0])

    def test_with_a_key_spacing_is_shorter_and_the_key_is_a_header(self):
        fake = self.nvd()
        _, client = self.run_lookup(fake, key="TEST-KEY-NOT-REAL")
        self.assertEqual(self.clock.sleeps, [0.8])
        for call in fake.calls:
            self.assertEqual(call["headers"], {"apiKey": "TEST-KEY-NOT-REAL"})
            self.assertNotIn("TEST-KEY-NOT-REAL", call["url"])

    def test_rate_limit_backs_off_and_retries(self):
        fake = self.nvd(script=[403, 429])
        result, client = self.run_lookup(fake)
        self.assertEqual(result.status, "ok")
        self.assertEqual(client.requests, 4)              # 2 refused + dictionary + CVEs
        self.assertEqual(self.clock.sleeps[:2], [10.0, 30.0])

    def test_a_fixed_number_of_retries_then_unavailable(self):
        fake = self.nvd(script=[503, 503, 503, 503])
        result, client = self.run_lookup(fake)
        self.assertEqual((result.status, result.reason), ("unavailable", "unreachable"))
        self.assertEqual(client.requests, 3)

    def test_a_client_error_is_not_retried(self):
        result, client = self.run_lookup(self.nvd(script=[400]))
        self.assertEqual((result.status, client.requests), ("unavailable", 1))

    def test_time_budget(self):
        fake = self.nvd(script=[403, 403])
        result, client = self.run_lookup(fake, budget=20.0)   # the 30 s back-off does not fit
        self.assertEqual((result.status, result.reason), ("unavailable", "budget"))
        self.assertEqual(client.requests, 2)
        self.assertLessEqual(sum(self.clock.sleeps), 20.0)

    def test_budget_counts_time_spent_waiting_for_nvd(self):
        # each answer takes 15 s: the second page would start past the budget
        fake = self.nvd(latency=15.0, page=3)
        result, client = self.run_lookup(fake, budget=20.0)
        self.assertEqual((result.status, result.reason), ("unavailable", "budget"))
        self.assertEqual(client.requests, 2)
        # and no request may wait longer than the budget that is left
        self.assertEqual([c["timeout"] for c in fake.calls], [20.0, 5.0])


class TestCache(Base):
    def test_warm_cache_makes_zero_requests(self):
        self.run_lookup(self.nvd())
        fake = self.nvd()
        result, client = self.run_lookup(fake)
        self.assertEqual((result.status, len(result.rows), result.stale), ("ok", 8, False))
        self.assertTrue(result.from_cache)
        self.assertEqual((client.requests, fake.calls), (0, []))

    def test_cached_cves_keep_their_fetch_time(self):
        self.run_lookup(self.nvd())
        self.clock.advance(days=2)
        result, _ = self.run_lookup(self.nvd())
        self.assertEqual(result.fetched_at, FETCHED)

    def test_found_answer_expires_after_7_days(self):
        self.run_lookup(self.nvd())
        self.clock.advance(days=6, seconds=86000)
        self.assertEqual(self.run_lookup(self.nvd())[1].requests, 0)
        self.clock.advance(seconds=1000)
        result, client = self.run_lookup(self.nvd())
        self.assertEqual(client.requests, 2)
        self.assertEqual(result.fetched_at, self.clock.now().isoformat())

    def test_empty_answer_expires_after_1_day(self):
        self.run_lookup(self.nvd(cves={IOS_CPE: []}))
        self.clock.advance(seconds=12 * 3600)
        self.assertEqual(self.run_lookup(self.nvd(cves={IOS_CPE: []}))[1].requests, 0)
        self.clock.advance(seconds=13 * 3600)
        # the dictionary hit is still fresh; only the empty CVE answer is asked again
        self.assertEqual(self.run_lookup(self.nvd(cves={IOS_CPE: []}))[1].requests, 1)

    def test_not_listed_is_asked_again_after_a_day(self):
        self.run_lookup(self.nvd(dictionary={}))
        self.clock.advance(days=1, seconds=1)
        self.assertEqual(self.run_lookup(self.nvd())[0].status, "ok")

    def test_stale_entry_used_when_nvd_is_down(self):
        self.run_lookup(self.nvd())
        self.clock.advance(days=30)
        result, _ = self.run_lookup(self.nvd(script=["down"] * 10))
        self.assertEqual((result.status, len(result.rows), result.stale), ("ok", 8, True))
        self.assertEqual(result.fetched_at, FETCHED)

    def test_nothing_cached_and_nvd_down_is_unavailable(self):
        result, _ = self.run_lookup(self.nvd(script=["down"] * 10))
        self.assertEqual((result.status, result.rows, result.reason), ("unavailable", None, "unreachable"))

    def test_corrupt_cache_is_ignored_and_rebuilt(self):
        for text in ("{not json", "[]", '{"entries": 5}', ""):
            with self.subTest(text=text):
                with open(self.path, "w") as f:
                    f.write(text)
                cache = Cache(self.path, self.clock)
                self.assertTrue(cache.corrupt)
                result, _ = self.run_lookup(self.nvd(), cache=cache)
                self.assertEqual(result.status, "ok")
                with open(self.path) as f:
                    self.assertIn(f"cves:{IOS_CPE}", json.load(f)["entries"])

    def test_two_devices_on_the_same_software_share_one_entry(self):
        fake = self.nvd()
        client = nvd.NvdClient(transport=fake, clock=self.clock, api_key="", use_env_key=False)
        cache = Cache(self.path, self.clock)
        a = lookup(ident_for(), client, cache)
        b = lookup(ident_for(), client, cache)
        self.assertEqual((a.status, b.status, client.requests), ("ok", "ok", 2))
        self.assertEqual(len([k for k in cache.entries if k.startswith("cves:")]), 1)

    def test_written_atomically_and_compact(self):
        self.run_lookup(self.nvd())
        self.assertEqual(sorted(os.listdir(self.tmp)), ["nvd-cache.json"])
        with open(self.path) as f:
            doc = json.load(f)
        self.assertEqual(doc["format"], 1)

    def test_a_cache_without_a_path_stays_in_memory(self):
        cache = Cache(None, self.clock)
        result, _ = self.run_lookup(self.nvd(), cache=cache)
        self.assertEqual(result.status, "ok")
        self.assertEqual(os.listdir(self.tmp), [])


class TestUnidentified(Base):
    def test_no_request_for_an_unidentified_device(self):
        fake = self.nvd()
        result, client = self.run_lookup(fake, ident={"match": "unidentified", "product": None})
        self.assertEqual((result.status, client.requests), ("unidentified", 0))


if __name__ == "__main__":
    unittest.main()
