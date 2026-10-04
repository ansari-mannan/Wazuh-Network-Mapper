"""The Wazuh endpoint side of the pipeline — collect + score in one module.

Folds the former fetch / normalize / orchestrate modules (``wazuh_client``,
``indexer_client``, ``normalize``, ``collect``, ``score``) into:

  * pure data-shaping functions — ``normalize_agent`` / ``parse_hit`` /
    ``enrich_agent`` / ``select_mac`` / ``is_physical_iface`` /
    ``is_locally_administered`` (no I/O), and
  * one I/O class, :class:`WazuhSource`, with ``collect()`` (Manager API, port
    55000) and ``score()`` (Indexer, port 9200) methods.

What each stage fetches and how it authenticates is unchanged; the indexer join
key is ``agent.id`` (hard + unique). The standalone entry points
``python -m vulnmapper.endpoints.collect`` / ``...score`` are preserved as thin
shim modules that call this class.
"""

from __future__ import annotations

import sys

import requests

from ..schema import IndexerConfig, WazuhConfig, canonical_mac, format_mac

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
    """Add ``risk_score`` (max CVSS), ``max_cvss`` and ``top_cves`` to an agent.

    ``risk_score`` stays the field of record for ranking; ``max_cvss`` is the same
    value exposed explicitly for consumers that key on raw CVSS (it is computed as
    the max across all CVEs rather than trusting the sort, so it is correct even if
    the input order ever changes).
    """
    risk = 0
    # CVEs arrive sorted descending by CVSS, so index 0 is the worst score.
    if top_cves and top_cves[0].get("cvss") is not None:
        risk = top_cves[0]["cvss"]
    max_cvss = max((c.get("cvss") for c in top_cves if c.get("cvss") is not None),
                   default=None)
    return {**agent, "risk_score": risk, "max_cvss": max_cvss, "top_cves": top_cves}


class WazuhSource:
    """The endpoint two-stage source: Manager-API ``collect`` + Indexer ``score``.

    Connection settings come from the environment via
    :class:`~vulnmapper.schema.WazuhConfig` / :class:`~vulnmapper.schema.IndexerConfig`
    (built from env on construction). No network call happens until ``collect`` /
    ``score`` is invoked.
    """

    # The OpenSearch index pattern that holds all vulnerability states.
    INDEX = "wazuh-states-vulnerabilities-*"

    def __init__(self, wazuh: "WazuhConfig | None" = None,
                 indexer: "IndexerConfig | None" = None) -> None:
        self._wcfg = wazuh or WazuhConfig.from_env()
        self._icfg = indexer or IndexerConfig.from_env()
        self._wbase = f"https://{self._wcfg.host}:{self._wcfg.port}"
        self._ibase = f"https://{self._icfg.host}:{self._icfg.port}"
        self._token = None

    # ---- Manager API (collect stage) --------------------------------------

    def _authenticate(self) -> None:
        r = requests.post(
            f"{self._wbase}/security/user/authenticate",
            auth=(self._wcfg.user, self._wcfg.password),
            verify=self._wcfg.verify,
            timeout=15,
        )
        if not r.ok:
            raise requests.HTTPError(
                f"Auth failed: {r.status_code} {r.reason} — {r.text[:500]}",
                response=r,
            )
        self._token = r.json()["data"]["token"]

    def _get(self, path, params=None):
        r = requests.get(
            f"{self._wbase}{path}",
            headers={"Authorization": f"Bearer {self._token}"},
            params=params,
            verify=self._wcfg.verify,
            timeout=30,
        )
        r.raise_for_status()
        return r.json().get("data", {}).get("affected_items", [])

    def collect(self) -> list[dict]:
        """Authenticate, fetch every agent + syscollector, normalize.

        Returns the list of normalized node dicts. One agent's missing
        syscollector data must not abort the run.
        """
        self._authenticate()

        nodes: list[dict] = []
        agents = self._get(
            "/agents",
            params={
                "limit": 1000,
                "select": "id,name,ip,os.name,os.version,os.platform,status",
            },
        )
        for agent in agents:
            if agent["id"] == "000":  # 000 is the manager itself, not an endpoint
                continue
            try:
                netiface = self._get(f"/syscollector/{agent['id']}/netiface")
                hardware = self._get(f"/syscollector/{agent['id']}/hardware")
                netaddr = self._get(f"/syscollector/{agent['id']}/netaddr")
            except requests.HTTPError as e:
                print(f"  ! syscollector failed for agent {agent['id']}: {e}",
                      file=sys.stderr)
                netiface, hardware, netaddr = [], [], []
            nodes.append(normalize_agent(agent, netiface, hardware, netaddr))
        return nodes

    # ---- Indexer (score stage) --------------------------------------------

    def _top_cves(self, agent_id, k=3):
        """Return the top-``k`` CVE docs for ``agent_id``, worst CVSS first."""
        body = {
            "size": k,
            "query": {"term": {"agent.id": agent_id}},      # hard join key
            "sort": [{"vulnerability.score.base": {"order": "desc"}}],
            "_source": [
                "vulnerability.id",
                "vulnerability.score.base",
                "vulnerability.score.version",
                "vulnerability.severity",
                "vulnerability.description",
                "package.name",
                "package.version",
            ],
        }
        r = requests.post(
            f"{self._ibase}/{self.INDEX}/_search",
            json=body,
            auth=(self._icfg.user, self._icfg.password),
            verify=self._icfg.verify,
            timeout=30,
        )
        r.raise_for_status()
        return r.json().get("hits", {}).get("hits", [])

    def score(self, agents: list[dict]) -> list[dict]:
        """Enrich each agent with its top CVEs + risk score. Returns the new list."""
        out: list[dict] = []
        for agent in agents:
            agent_id = agent.get("agent_id")  # hard join key carried from collect
            try:
                raw_hits = self._top_cves(agent_id, k=3) if agent_id else []
            except requests.HTTPError as e:
                print(f"  ! query failed for agent {agent_id}: {e}", file=sys.stderr)
                raw_hits = []

            cves = [parse_hit(h) for h in raw_hits]
            enriched = enrich_agent(agent, cves)
            out.append(enriched)
            print(f"  agent {agent_id} ({agent.get('hostname')}): "
                  f"{len(cves)} CVE(s), risk={enriched['risk_score']}", file=sys.stderr)
        return out
