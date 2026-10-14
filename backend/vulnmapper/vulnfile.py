"""vulnerabilities.json: every CVE finding of every scanned host and device.

Written by the pipeline beside graph.json; the vulnerability report and the
attack-path stage read the full lists from it.
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
    """The document, from scored endpoints, the shared CVE catalogue and the
    entries of everything looked up in NVD (``devices``, by node_id)::

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

    Hosts on one network mostly share their CVEs, so a CVE's text is stored
    once, in ``cves``, and each finding only points at it. Endpoints and
    devices share ``hosts`` so a page can list them together; ``kind`` tells
    them apart. A host without an agent that answered SNMP was looked up like
    a device, so its entry has the device shape with kind "endpoint". For a
    device the package is the product ("Cisco IOS 12.2(55)SE12"), the version
    its firmware and ``detected_at`` when NVD was asked.

    ``findings`` is null when the full list is not known: the host could not
    be scored, it came from an old-shape ``--scored`` file, or the device
    lookup failed.
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
    for node_id, entry in (devices or {}).items():
        findings = entry.get("findings")
        if findings is not None:
            n_findings += len(findings)
            used.update(f["cve"] for f in findings if f.get("cve"))
        hosts[node_id] = entry
    n_devices = sum(e["kind"] == "device" for e in hosts.values())
    section = {cve: catalogue[cve] for cve in sorted(used) if cve in catalogue}
    return {
        "metadata": {
            "scan_time": scan_time,
            "counts": {"hosts": len(hosts) - n_devices, "devices": n_devices,
                       "cves": len(section), "findings": n_findings},
        },
        "cves": section,
        "hosts": hosts,
    }


def write_atomic(path: str, document: dict, indent: Optional[int] = None) -> None:
    """Write via a temp file in the same folder, then rename over ``path``.
    Compact JSON unless ``indent``: the file grows with hosts times CVEs."""
    folder = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=".vulnerabilities.", suffix=".tmp", dir=folder)
    try:
        # mkstemp creates 0600; give the file the mode a plain open() would.
        umask = os.umask(0)
        os.umask(umask)
        os.chmod(tmp, 0o666 & ~umask)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            json.dump(document, f, indent=indent, separators=None if indent else (",", ":"))
            f.write("\n")
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
