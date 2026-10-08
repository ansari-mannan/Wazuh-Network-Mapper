"""The full-CVE score stage: paging, the safety cap, distinct counting, optional
fields, indexer failures, and the shared catalogue at scale. HTTP is mocked."""

import contextlib
import io
import os
import sys
import tempfile
import unittest
from unittest import mock

import requests

from vulnmapper import endpoints as ep_mod
from vulnmapper import vulnfile
from vulnmapper.endpoints import WazuhSource, enrich_agent, parse_hit
from vulnmapper.schema import IndexerConfig, WazuhConfig


def doc(cve, cvss, package="pkg", version="1.0", description=None, **vuln_extra):
    """One raw vulnerability document (the ``_source`` of a hit)."""
    vuln = {"id": cve, "severity": "x",
            "description": description or f"Description of {cve}.", **vuln_extra}
    if cvss is not None:
        vuln["score"] = {"base": cvss, "version": "3.1"}
    return {"vulnerability": vuln, "package": {"name": package, "version": version}}


class FakeIndexer:
    """Stands in for ``requests.post`` against ``_search``.

    Serves each agent's documents in the given order, honouring ``size`` and
    ``search_after`` (a hit's sort value is its position). ``fail`` maps an agent
    id to the exception its query raises.
    """

    def __init__(self, docs_by_agent, fail=None):
        self.docs = docs_by_agent
        self.fail = fail or {}
        self.bodies = []

    def __call__(self, url, json=None, **_kw):
        self.bodies.append(json)
        agent = json["query"]["term"]["agent.id"]
        if agent in self.fail:
            raise self.fail[agent]
        docs = self.docs.get(agent, [])
        start = json["search_after"][0] + 1 if "search_after" in json else 0
        page = docs[start:start + json["size"]]
        resp = mock.Mock()
        resp.raise_for_status.return_value = None
        resp.json.return_value = {"hits": {"hits": [
            {"_source": d, "sort": [start + i]} for i, d in enumerate(page)]}}
        return resp


def source():
    return WazuhSource(WazuhConfig("w", "55000", "u", "p"),
                       IndexerConfig("i", "9200", "u", "p"))


class FakeManager:
    """Stands in for ``requests.get`` against the Manager API.

    ``routes`` maps a path to its ``affected_items`` list, or to a list of
    outcomes served one per call (an exception instance is raised). Any
    ``/syscollector/<id>/packages`` path not in ``routes`` returns one package.
    """

    def __init__(self, routes=None):
        self.routes = dict(routes or {})
        self.calls = []

    def __call__(self, url, params=None, **_kw):
        path = url.split(":55000", 1)[-1]
        self.calls.append((path, params))
        if path in self.routes:
            outcome = self.routes[path]
            if isinstance(outcome, Outcomes):
                outcome = outcome.next()
        elif path.endswith("/packages"):
            outcome = [{"name": "bash"}]
        else:
            outcome = []
        if isinstance(outcome, Exception):
            raise outcome
        resp = mock.Mock()
        resp.raise_for_status.return_value = None
        resp.json.return_value = {"data": {"affected_items": outcome}}
        return resp


class Outcomes:
    """A sequence of per-call outcomes for one FakeManager route."""

    def __init__(self, *items):
        self.items = list(items)

    def next(self):
        return self.items.pop(0)


def http_error(status):
    return requests.HTTPError(f"{status} Error", response=mock.Mock(status_code=status))


def score(agents, fake, manager=None):
    """Run WazuhSource.score against ``fake``; returns (source, scored agents)."""
    src = source()
    src._token = "t"
    with mock.patch.object(ep_mod.requests, "post", fake), \
            mock.patch.object(ep_mod.requests, "get", manager or FakeManager()), \
            mock.patch.object(ep_mod.time, "sleep"), \
            contextlib.redirect_stderr(io.StringIO()):
        return src, src.score(agents)


class TestPaging(unittest.TestCase):
    def test_pages_until_exhausted(self):
        docs = [doc(f"CVE-2026-{i:05d}", 9.0, package=f"p{i}") for i in range(2500)]
        fake = FakeIndexer({"001": docs})
        src, (agent,) = score([{"agent_id": "001", "hostname": "h"}], fake)

        self.assertEqual([b["size"] for b in fake.bodies], [1000, 1000, 1000])
        self.assertNotIn("search_after", fake.bodies[0])
        self.assertEqual(fake.bodies[1]["search_after"], [999])
        self.assertEqual(fake.bodies[2]["search_after"], [1999])
        self.assertEqual(len(agent["findings"]), 2500)
        self.assertEqual(agent["cve_summary"]["total"], 2500)
        self.assertEqual(len(src.cves), 2500)
        self.assertEqual(src.warnings, [])

    def test_query_sort_and_fields(self):
        fake = FakeIndexer({"001": [doc("CVE-1", 5.0)]})
        score([{"agent_id": "001"}], fake)
        body = fake.bodies[0]
        self.assertEqual(body["query"], {"term": {"agent.id": "001"}})
        self.assertEqual(body["sort"][0]["vulnerability.score.base"]["order"], "desc")
        self.assertEqual(body["sort"][1], {"vulnerability.id": {"order": "asc"}})
        for field in ("vulnerability.reference", "vulnerability.published_at",
                      "vulnerability.detected_at"):
            self.assertIn(field, body["_source"])

    def test_exact_page_multiple_needs_one_empty_page(self):
        docs = [doc(f"CVE-{i}", 5.0) for i in range(2000)]
        fake = FakeIndexer({"001": docs})
        _src, (agent,) = score([{"agent_id": "001"}], fake)
        self.assertEqual(len(fake.bodies), 3)
        self.assertEqual(len(agent["findings"]), 2000)

    def test_safety_cap_stops_and_warns_naming_the_agent(self):
        docs = [doc(f"CVE-{i:03d}", 5.0) for i in range(30)]
        fake = FakeIndexer({"001": docs, "002": docs[:25]})
        with mock.patch.object(ep_mod, "PAGE_SIZE", 10), \
                mock.patch.object(ep_mod, "MAX_DOCS_PER_AGENT", 25):
            src, (a1, a2) = score([{"agent_id": "001", "hostname": "big"},
                                   {"agent_id": "002", "hostname": "exact"}], fake)

        self.assertEqual(len(a1["findings"]), 25)
        self.assertEqual(len(a2["findings"]), 25)
        sizes = [b["size"] for b in fake.bodies if b["query"]["term"]["agent.id"] == "001"]
        self.assertEqual(sizes, [10, 10, 5, 1])        # last one is the probe
        self.assertEqual(src.warnings, [{
            "type": "cve_cap_reached", "agent_id": "001", "node_id": "endpoint:001",
            "hostname": "big", "cap": 25}])            # 002 has exactly 25: no warning


class TestDistinctAndSummary(unittest.TestCase):
    def setUp(self):
        self.docs = [
            doc("CVE-A", 9.8, package="openssl"),
            doc("CVE-A", 9.1, package="libssl"),       # same CVE, second package
            doc("CVE-B", 7.5),
            doc("CVE-C", 5.0),
            doc("CVE-F", 4.2, package="one"),
            doc("CVE-D", 2.0),
            doc("CVE-E", None),                        # no score -> unknown
            doc("CVE-F", None, package="two"),         # scored elsewhere -> medium
        ]
        self.src, (self.agent,) = score([{"agent_id": "001"}], FakeIndexer({"001": self.docs}))

    def test_summary_counts_distinct_cves(self):
        self.assertEqual(self.agent["cve_summary"], {
            "total": 6, "critical": 1, "high": 1, "medium": 2, "low": 1,
            "unknown": 1, "max_cvss": 9.8})
        self.assertEqual(self.agent["max_cvss"], 9.8)

    def test_one_finding_per_cve_and_package(self):
        self.assertEqual(len(self.agent["findings"]), 8)
        self.assertEqual(set(self.agent["findings"][0]),
                         {"cve", "package", "version", "detected_at"})

    def test_top_cves_distinct_worst_first(self):
        top = self.agent["top_cves"]
        self.assertEqual([c["cve"] for c in top],
                         ["CVE-A", "CVE-B", "CVE-C", "CVE-F", "CVE-D", "CVE-E"])
        self.assertEqual(top[0]["package"], "openssl")  # its highest-scoring row
        self.assertEqual(top[0]["cvss"], 9.8)

    def test_catalogue_once_per_cve_at_highest_score(self):
        self.assertEqual(sorted(self.src.cves), ["CVE-A", "CVE-B", "CVE-C", "CVE-D",
                                                 "CVE-E", "CVE-F"])
        self.assertEqual(self.src.cves["CVE-A"]["cvss"], 9.8)
        self.assertEqual(self.src.cves["CVE-F"]["cvss"], 4.2)
        self.assertNotIn("package", self.src.cves["CVE-A"])

    def test_band_boundaries(self):
        cves = [{"cve": f"C{v}", "cvss": v} for v in (9.0, 8.9, 7.0, 6.9, 4.0, 3.9, 0.0)]
        s = enrich_agent({}, cves)["cve_summary"]
        self.assertEqual((s["critical"], s["high"], s["medium"], s["low"]), (1, 2, 2, 2))

    def test_top_cves_capped_at_ten(self):
        cves = [{"cve": f"CVE-{i:02d}", "cvss": i / 2} for i in range(14)]
        agent = enrich_agent({}, cves)
        self.assertEqual(len(agent["top_cves"]), 10)
        self.assertEqual(agent["top_cves"][0]["cve"], "CVE-13")
        self.assertEqual(agent["cve_summary"]["total"], 14)

    def test_scanned_with_nothing_found(self):
        _src, (agent,) = score([{"agent_id": "001"}], FakeIndexer({}))
        self.assertEqual(agent["risk_score"], 0.0)
        self.assertEqual(agent["findings"], [])
        self.assertEqual(agent["cve_summary"]["total"], 0)
        self.assertIsNone(agent["cve_summary"]["max_cvss"])


class TestOptionalFields(unittest.TestCase):
    def test_missing_optional_fields_parse_as_none(self):
        row = parse_hit({"_source": doc("CVE-1", 7.0)})
        self.assertEqual(row["cve"], "CVE-1")
        for key in ("reference", "published_at", "detected_at"):
            self.assertIn(key, row)
            self.assertIsNone(row[key])

    def test_sparse_documents_do_not_fail(self):
        for hit in ({}, {"_source": None}, {"_source": {"vulnerability": None}},
                    {"_source": {"vulnerability": {"id": "CVE-1", "score": None}}}):
            row = parse_hit(hit)
            self.assertIsNone(row["cvss"])
            self.assertIsNone(row["detected_at"])

    def test_present_optional_fields_carried_through(self):
        d = doc("CVE-1", 9.8, reference="https://example.org/CVE-1",
                published_at="2026-01-02T00:00:00Z", detected_at="2026-09-30T10:00:00Z")
        src, (agent,) = score([{"agent_id": "001"}], FakeIndexer({"001": [d]}))
        top = agent["top_cves"][0]
        self.assertEqual(top["reference"], "https://example.org/CVE-1")
        self.assertEqual(top["published_at"], "2026-01-02T00:00:00Z")
        self.assertEqual(top["detected_at"], "2026-09-30T10:00:00Z")
        self.assertEqual(agent["findings"][0]["detected_at"], "2026-09-30T10:00:00Z")
        self.assertEqual(src.cves["CVE-1"]["reference"], "https://example.org/CVE-1")
        self.assertEqual(src.cves["CVE-1"]["published_at"], "2026-01-02T00:00:00Z")


class TestIndexerFailure(unittest.TestCase):
    AGENTS = [{"agent_id": "001", "hostname": "a"}, {"agent_id": "002", "hostname": "b"},
              {"agent_id": "003", "hostname": "c"}]

    def test_unreachable_leaves_endpoints_unscored_with_one_warning(self):
        fake = FakeIndexer({"001": [doc("CVE-1", 9.8)]},
                           fail={"002": requests.ConnectionError("connection refused")})
        src, out = score(self.AGENTS, fake)

        self.assertEqual(out[0]["cve_summary"]["total"], 1)        # scored before the failure
        for agent in out[1:]:
            self.assertIsNone(agent["risk_score"])
            self.assertIsNone(agent["cve_summary"])
            self.assertIsNone(agent["max_cvss"])
            self.assertIsNone(agent["findings"])
            self.assertEqual(agent["top_cves"], [])
        # once the indexer stops answering, 003 is not even tried
        self.assertNotIn("003", [b["query"]["term"]["agent.id"] for b in fake.bodies])
        self.assertEqual(len(src.warnings), 1)
        w = src.warnings[0]
        self.assertEqual(w["type"], "indexer_unreachable")
        self.assertEqual(w["agents"], ["002", "003"])
        self.assertEqual(w["node_ids"], ["endpoint:002", "endpoint:003"])
        self.assertIn("connection refused", w["error"])

    def test_http_error_unscores_only_that_agent(self):
        fake = FakeIndexer({"001": [doc("CVE-1", 9.8)], "003": [doc("CVE-2", 5.0)]},
                           fail={"002": requests.HTTPError("500 Server Error")})
        src, out = score(self.AGENTS, fake)
        self.assertIsNone(out[1]["risk_score"])
        self.assertIsNotNone(out[0]["risk_score"])
        self.assertIsNotNone(out[2]["risk_score"])
        self.assertEqual(src.warnings[0]["agents"], ["002"])

    def test_failure_mid_paging_leaves_no_partial_score(self):
        docs = [doc(f"CVE-{i}", 9.0) for i in range(1500)]
        calls = {"n": 0}
        good = FakeIndexer({"001": docs})

        def flaky(url, json=None, **kw):
            calls["n"] += 1
            if calls["n"] == 2:
                raise requests.Timeout("read timed out")
            return good(url, json=json, **kw)

        src, (agent,) = score([{"agent_id": "001"}], flaky)
        self.assertIsNone(agent["risk_score"])
        self.assertEqual(src.cves, {})


class TestScale(unittest.TestCase):
    HOSTS, CVES = 200, 300

    def test_each_description_stored_once(self):
        descriptions = [f"Synthetic description number {i:05d} for the scale test."
                        for i in range(self.CVES)]
        shared = [doc(f"CVE-2026-{i:05d}", round(1 + (i % 90) / 10, 1),
                      package=f"pkg{i % 40}", description=descriptions[i])
                  for i in range(self.CVES)]
        agents = [{"agent_id": f"{n:03d}", "hostname": f"host-{n:03d}"}
                  for n in range(1, self.HOSTS + 1)]
        fake = FakeIndexer({a["agent_id"]: shared for a in agents})
        src, scored = score(agents, fake)

        document = vulnfile.build_document(scored, src.cves, "2026-10-07T00:00:00+00:00")
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, vulnfile.FILENAME)
            vulnfile.write_atomic(path, document)
            with open(path, encoding="utf-8") as f:
                text = f.read()
            self.size = os.path.getsize(path)

        self.assertEqual(document["metadata"]["counts"],
                         {"hosts": self.HOSTS, "devices": 0, "cves": self.CVES,
                          "findings": self.HOSTS * self.CVES})
        for description in descriptions:
            self.assertEqual(text.count(description), 1, description)
        print(f"\n  scale test: {self.HOSTS} hosts x {self.CVES} CVEs -> "
              f"vulnerabilities.json {self.size:,} bytes", file=sys.stderr)


if __name__ == "__main__":
    unittest.main()
