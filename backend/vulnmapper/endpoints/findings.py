"""CVE rows for a host: parsing the indexer's vulnerability documents, one
row per distinct CVE, the per-band summary and the base score, and the shapes
vulnerabilities.json stores them in. Shared by the Wazuh endpoints and the
NVD lookups for devices. No I/O.
"""

from __future__ import annotations

from ..scoring import CRITICAL_MIN, HIGH_MIN, MEDIUM_MIN, base_score

# How many of a host's worst distinct CVEs ride on its graph node as ``top_cves``.
TOP_CVES = 10


def parse_hit(hit):
    """Flatten one raw OpenSearch vulnerability document into a plain CVE dict.

    ``reference``, ``published_at`` and ``detected_at`` are optional: a document
    without them parses with those keys set to None.
    """
    src = hit.get("_source", {}) or {}
    vuln = src.get("vulnerability", {}) or {}
    score = vuln.get("score", {}) or {}
    pkg = src.get("package", {}) or {}

    return {
        "cve":          vuln.get("id"),
        "cvss":         score.get("base"),
        "cvss_version": score.get("version"),
        "severity":     vuln.get("severity"),
        "package":      pkg.get("name"),
        "version":      pkg.get("version"),
        "description":  vuln.get("description"),
        "reference":    vuln.get("reference"),
        "published_at": vuln.get("published_at"),
        "detected_at":  vuln.get("detected_at"),
    }


def distinct_cves(cves):
    """One row per distinct CVE id (its highest-scoring row), worst first.

    The index holds one document per CVE *and package*; totals count CVEs, not
    documents. A row without a score sorts after every scored row, and a row
    without an id is kept on its own.
    """
    best: dict = {}
    for i, row in enumerate(cves):
        key = row.get("cve") or ("#row", i)
        cvss = row.get("cvss")
        kept = best.get(key)
        if kept is None or (cvss is not None and (kept.get("cvss") is None
                                                  or cvss > kept["cvss"])):
            best[key] = row
    return sorted(best.values(),
                  key=lambda r: (r.get("cvss") is None, -(r.get("cvss") or 0),
                                 r.get("cve") or ""))


def summarize_cves(distinct):
    """``cve_summary`` for a host from its :func:`distinct_cves` rows.

    Counts use the CVSS v3 bands (critical 9.0+, high 7.0-8.9, medium 4.0-6.9,
    low below 4.0); a CVE with no score counts as ``unknown``.
    """
    summary = {"total": len(distinct), "critical": 0, "high": 0, "medium": 0,
               "low": 0, "unknown": 0, "max_cvss": None}
    for row in distinct:
        cvss = row.get("cvss")
        if cvss is None:
            band = "unknown"
        elif cvss >= CRITICAL_MIN:
            band = "critical"
        elif cvss >= HIGH_MIN:
            band = "high"
        elif cvss >= MEDIUM_MIN:
            band = "medium"
        else:
            band = "low"
        summary[band] += 1
        if cvss is not None and (summary["max_cvss"] is None or cvss > summary["max_cvss"]):
            summary["max_cvss"] = cvss
    return summary


def enrich_agent(agent, cves):
    """Add ``risk_score``, ``max_cvss``, ``top_cves`` and ``cve_summary`` to an agent.

    ``cves`` is every CVE row for the agent (one per CVE and package), or None
    when the agent could not be scored. ``risk_score`` is the base score from
    :func:`vulnmapper.scoring.base_score`; ``max_cvss`` stays the raw worst CVSS;
    ``top_cves`` holds the :data:`TOP_CVES` worst distinct CVEs. An unscored
    agent gets None for the score, the max and the summary, and no CVEs.
    """
    if cves is None:
        return {**agent, "risk_score": None, "max_cvss": None, "top_cves": [],
                "cve_summary": None}
    distinct = distinct_cves(cves)
    summary = summarize_cves(distinct)
    return {**agent, "risk_score": base_score(cves), "max_cvss": summary["max_cvss"],
            "top_cves": distinct[:TOP_CVES], "cve_summary": summary}


def slim_findings(cves):
    """The per-host finding rows for vulnerabilities.json (no CVE text)."""
    return [{"cve": c.get("cve"), "package": c.get("package"),
             "version": c.get("version"), "detected_at": c.get("detected_at")}
            for c in cves]


def catalogue_entry(row):
    """The shared, once-per-CVE text for vulnerabilities.json's ``cves`` section."""
    return {k: row.get(k) for k in
            ("cvss", "cvss_version", "severity", "description", "reference",
             "published_at")}


def merge_catalogue(catalogue: dict, rows: list) -> None:
    """Add each row's CVE text to the catalogue; when a CVE is already there,
    the higher-scored entry wins."""
    for row in rows:
        cve_id = row.get("cve")
        if not cve_id:
            continue
        known = catalogue.get(cve_id)
        if known is None or (row.get("cvss") is not None and (
                known.get("cvss") is None or row["cvss"] > known["cvss"])):
            catalogue[cve_id] = catalogue_entry(row)
