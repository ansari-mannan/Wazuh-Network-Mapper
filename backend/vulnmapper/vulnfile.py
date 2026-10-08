"""vulnerabilities.json — every CVE finding for every scanned endpoint and device.

The graph carries only each node's summary and its worst CVEs; the complete
list goes here. Hosts on one network mostly share the same CVEs, so a CVE's text
is stored once and each entry lists slim findings that point at it::

    {
      "metadata": {"scan_time": ...,
                   "counts": {"hosts", "devices", "cves", "findings"}},
      "cves":  {"<CVE id>": {cvss, cvss_version, severity, description,
                             reference, published_at}},
      "hosts": {"<node_id>": {kind: "endpoint", hostname, agent_id,
                              findings: [{cve, package, version, detected_at}]},
                "<node_id>": {kind: "device", hostname, agent_id: null,
                              cve_lookup: {status, match, product, cpe, source,
                                           fetched_at, stale, total},
                              findings: [...]}}
    }

Keys of ``hosts`` are the graph's ``node_id`` values; endpoints (Wazuh agents)
and network devices share the map so a page can list them together, and
``kind`` tells them apart. ``counts.hosts`` counts the endpoint entries and
``counts.devices`` the device entries. A device's findings come from NVD
(vulnmapper.devicecves): the package is the product label ("Cisco IOS
12.2(55)SE12"), the version is the firmware and ``detected_at`` is when NVD was
asked. ``cves`` takes NVD's text for CVEs Wazuh did not report; when both know
a CVE, the higher-scored entry is kept.

``findings`` is null when the full list is not available: the host could not
be scored, it came from an old-shape ``--scored`` file, or the device lookup did
not succeed. The file is compact JSON (no indentation) because it grows with
hosts x CVEs.
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


def build_document(endpoints: list[dict], cves: Optional[dict], scan_time: str,
                   devices: Optional[dict] = None) -> dict:
    """Build the document from scored endpoint dicts and the shared CVE catalogue.

    ``devices`` maps a device node_id to its entry (devicecves.stage).
    """
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
            "kind": "endpoint",
            "hostname": ep.get("hostname"),
            "agent_id": agent_id,
            "findings": findings,
        }
    n_hosts = len(hosts)
    for node_id, entry in (devices or {}).items():
        findings = entry.get("findings")
        if findings is not None:
            n_findings += len(findings)
            used.update(f["cve"] for f in findings if f.get("cve"))
        hosts[node_id] = entry
    section = {cve: catalogue[cve] for cve in sorted(used) if cve in catalogue}
    return {
        "metadata": {
            "scan_time": scan_time,
            "counts": {"hosts": n_hosts, "devices": len(hosts) - n_hosts,
                       "cves": len(section), "findings": n_findings},
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
