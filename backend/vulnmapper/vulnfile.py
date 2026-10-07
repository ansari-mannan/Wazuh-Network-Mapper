"""vulnerabilities.json — every CVE finding for every scanned endpoint.

The graph carries only each endpoint's summary and its worst CVEs; the complete
list goes here. Hosts on one network mostly share the same CVEs, so a CVE's text
is stored once and each host lists slim findings that point at it::

    {
      "metadata": {"scan_time": ..., "counts": {"hosts", "cves", "findings"}},
      "cves":  {"<CVE id>": {cvss, cvss_version, severity, description,
                             reference, published_at}},
      "hosts": {"<node_id>": {hostname, agent_id,
                              findings: [{cve, package, version, detected_at}]}}
    }

Host keys are the graph's ``node_id`` values. ``findings`` is null when the full
list is not available: the host could not be scored, or it came from an
old-shape ``--scored`` file. The file is compact JSON (no indentation) because it
grows with hosts x CVEs.
"""

from __future__ import annotations

import json
import os
import tempfile
from typing import Optional

from .schema import endpoint_node_id

FILENAME = "vulnerabilities.json"


def default_path(graph_path: str) -> str:
    """vulnerabilities.json in the same folder as the graph file."""
    return os.path.join(os.path.dirname(os.path.abspath(graph_path)), FILENAME)


def build_document(endpoints: list[dict], cves: Optional[dict], scan_time: str) -> dict:
    """Build the document from scored endpoint dicts and the shared CVE catalogue."""
    catalogue = cves or {}
    hosts: dict = {}
    used: set = set()
    n_findings = 0
    for ep in endpoints:
        agent_id = ep.get("agent_id")
        if agent_id is None:
            continue
        findings = ep.get("findings")
        if findings is not None:
            n_findings += len(findings)
            used.update(f["cve"] for f in findings if f.get("cve"))
        hosts[endpoint_node_id(agent_id)] = {
            "hostname": ep.get("hostname"),
            "agent_id": agent_id,
            "findings": findings,
        }
    section = {cve: catalogue[cve] for cve in sorted(used) if cve in catalogue}
    return {
        "metadata": {
            "scan_time": scan_time,
            "counts": {"hosts": len(hosts), "cves": len(section), "findings": n_findings},
        },
        "cves": section,
        "hosts": hosts,
    }


def write_atomic(path: str, document: dict) -> None:
    """Write via a temp file in the same folder, then rename over ``path``."""
    folder = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=".vulnerabilities.", suffix=".tmp", dir=folder)
    try:
        # mkstemp creates 0600; give the file the mode a plain open() would.
        umask = os.umask(0)
        os.umask(umask)
        os.chmod(tmp, 0o666 & ~umask)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            json.dump(document, f, separators=(",", ":"))
            f.write("\n")
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
