#!/usr/bin/env python3
"""NORMALIZE LAYER — pure data-shaping for the endpoint side. No I/O.

Consolidates the two previously-duplicated normalizers into one module:

  * :func:`normalize_agent` — raw Wazuh agent + syscollector -> shared node dict
    (was NTM/normalizer.py). Now also carries ``agent_id`` through, which is the
    hard join key used to query the indexer and to build the endpoint node_id.
  * :func:`parse_hit` / :func:`enrich_agent` — raw OpenSearch hit -> CVE dict and
    risk enrichment (was APA/normalizer.py).

MAC values go through the single canonicalizer so endpoint MACs compare cleanly
against switch forwarding-table MACs in the linker.
"""

from __future__ import annotations

from ..common.mac import canonical_mac, format_mac

_JUNK_SERIALS = {"", "unknown", "0", "To be filled by O.E.M.", "Not Specified"}

# Case-insensitive substrings that mark a virtual / software / non-physical
# adapter. Matched against the interface name and description.
_VIRTUAL_IFACE_NEEDLES = (
    "loopback", "npcap", "vmware", "virtualbox", "vbox", "hyper-v", "vethernet",
    "veth", "docker", "wsl", "tap", "tun", "bluetooth", "vpn", "npf",
)


def is_locally_administered(mac) -> bool:
    """True if a MAC has the locally-administered bit set (``first_octet & 0x02``).

    Burned-in NIC MACs are globally administered (that bit clear). Virtual,
    loopback and most VM/Hyper-V adapters set it — e.g. the Npcap loopback
    ``02:00:4c:4f:4f:50`` ("\\x02" + "LOOP"). A value that isn't a parseable MAC
    is treated as locally administered so it can never be selected.
    """
    canonical = canonical_mac(mac)
    if canonical is None:
        return True
    return bool(int(canonical[:2], 16) & 0x02)


def is_physical_iface(name, mac) -> bool:
    """True if an interface looks like a real physical NIC.

    Rejects anything with a locally-administered (or unparseable) MAC, and
    anything whose name/description matches the virtual-adapter blocklist.
    """
    if is_locally_administered(mac):
        return False
    text = (name or "").lower()
    return not any(needle in text for needle in _VIRTUAL_IFACE_NEEDLES)


def _ipv4_by_iface(netaddr) -> dict:
    """Join the netaddr endpoint to interfaces by name: ``iface -> [ipv4, ...]``.

    /syscollector/{id}/netiface has no IPv4 — it lives in /netaddr, keyed by the
    interface name. APIPA (169.254.x.x) addresses are dropped here so they can't
    qualify an interface in :func:`select_mac`.
    """
    out: dict[str, list] = {}
    for addr in netaddr or []:
        if (addr.get("proto") or "").lower() != "ipv4":
            continue
        ip = addr.get("address")
        if not ip or ip.startswith("169.254."):
            continue
        out.setdefault(addr.get("iface"), []).append(ip)
    return out


def select_mac(netiface, netaddr, agent_ip):
    """Select the real physical NIC's MAC for an agent (or None).

    1. Drop virtual/software/loopback interfaces (:func:`is_physical_iface`).
    2. Drop interfaces with no MAC or no non-APIPA IPv4 (joined via /netaddr).
    3. Prefer the interface whose IPv4 equals the agent's known IP; tie-break on
       state == "up"; else the first survivor.
    Returns the canonicalized colon-form MAC, or None if nothing survives.
    """
    ipv4_by_iface = _ipv4_by_iface(netaddr)

    survivors = []  # (mac, ipv4s, is_up)
    for iface in netiface or []:
        raw_mac = iface.get("mac")
        mac = format_mac(raw_mac)
        if not mac or not is_physical_iface(iface.get("name"), raw_mac):
            continue
        ipv4s = ipv4_by_iface.get(iface.get("name"), [])
        if not ipv4s:
            continue
        survivors.append((mac, ipv4s, (iface.get("state") or "").lower() == "up"))

    if not survivors:
        return None
    if agent_ip:
        for mac, ipv4s, _up in survivors:
            if agent_ip in ipv4s:
                return mac
    for mac, _ipv4s, up in survivors:
        if up:
            return mac
    return survivors[0][0]


def _serial(hardware):
    if not hardware:
        return None
    s = hardware[0].get("board_serial")
    return None if (not s or s in _JUNK_SERIALS) else s


def normalize_agent(agent, netiface, hardware, netaddr=None):
    """Map a raw Wazuh agent + syscollector data into the shared node schema."""
    os_info = agent.get("os", {}) or {}
    return {
        "agent_id":         agent.get("id"),       # hard join key + node_id source
        "ip":               agent.get("ip"),
        "hostname":         agent.get("name"),
        "vendor":           os_info.get("platform"),
        "model":            os_info.get("name"),
        "firmware":         os_info.get("version"),
        "serial":           _serial(hardware),
        "mac":              select_mac(netiface, netaddr, agent.get("ip")),
        "discovery_method": "wazuh",
        "status":           agent.get("status"),
    }


def parse_hit(hit):
    """Flatten one raw OpenSearch vulnerability document into a plain CVE dict."""
    src = hit.get("_source", {})
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
    }


def enrich_agent(agent, top_cves):
    """Add ``risk_score`` (max CVSS) and ``top_cves`` to an agent dict."""
    risk = 0
    # CVEs arrive sorted descending by CVSS, so index 0 is the worst score.
    if top_cves and top_cves[0].get("cvss") is not None:
        risk = top_cves[0]["cvss"]
    return {**agent, "risk_score": risk, "top_cves": top_cves}
