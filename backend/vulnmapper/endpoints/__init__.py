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

import ipaddress
import sys
import time

import requests

from ..schema import (IndexerConfig, WazuhConfig, canonical_mac, endpoint_node_id,
                      format_mac)
from ..scoring import CRITICAL_MIN, HIGH_MIN, MEDIUM_MIN, base_score

_JUNK_SERIALS = {"", "unknown", "0", "To be filled by O.E.M.", "Not Specified"}

# Case-insensitive substrings that mark a virtual / software / non-physical
# adapter. Matched against the interface name and description.
_VIRTUAL_IFACE_NEEDLES = (
    "loopback", "npcap", "vmware", "virtualbox", "vbox", "hyper-v", "vethernet",
    "veth", "docker", "wsl", "tap", "tun", "bluetooth", "vpn", "npf",
)

# Vulnerability query: page size, the per-agent safety cap, and how many of the
# worst distinct CVEs ride on each graph node as ``top_cves``.
PAGE_SIZE = 1000
MAX_DOCS_PER_AGENT = 20000
TOP_CVES = 10

# Agent 000 is the Wazuh server itself; the Manager API reports it as 127.0.0.1.
SERVER_AGENT_ID = "000"
# Interface-name prefixes of container / VM bridges, never the server's address.
_BRIDGE_IFACE_PREFIXES = (
    "docker", "br-", "veth", "virbr", "cni", "flannel", "cali", "podman",
    "lxcbr", "lxdbr", "kube", "weave", "vxlan",
)
# A busy Manager API answers syscollector requests with a 5xx after ~10 s:
# wait this long and retry once.
INVENTORY_RETRY_DELAY_S = 3


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


def _usable_ipv4(ip) -> bool:
    try:
        addr = ipaddress.IPv4Address(ip)
    except (ipaddress.AddressValueError, ValueError):
        return False
    return not (addr.is_loopback or addr.is_link_local or addr.is_unspecified)


def server_ipv4(netaddr, netproto):
    """The Wazuh server's real IPv4 from its syscollector inventory, or None.

    Prefers an address on the interface that has a default gateway (netproto);
    otherwise the first IPv4 that is not loopback, link-local or on a container
    bridge.
    """
    ipv4s = [(a.get("iface") or "", a.get("address")) for a in netaddr or []
             if (a.get("proto") or "").lower() == "ipv4" and _usable_ipv4(a.get("address"))]
    ipv4s = [(iface, ip) for iface, ip in ipv4s
             if not iface.lower().startswith(_BRIDGE_IFACE_PREFIXES)]
    gateway_ifaces = [p.get("iface") for p in netproto or []
                      if (p.get("type") or "").lower() == "ipv4"
                      and _usable_ipv4((p.get("gateway") or "").strip())]
    for gw_iface in gateway_ifaces:
        for iface, ip in ipv4s:
            if iface == gw_iface:
                return ip
    return ipv4s[0][1] if ipv4s else None


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
        self.collect_warnings: list = []   # set by collect()
        self.warnings: list = []           # set by score()
        self.cves: dict = {}               # set by score()

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

    def _get_inventory(self, path, params=None):
        """``_get`` for syscollector data: a 5xx or a timeout is retried once."""
        try:
            return self._get(path, params)
        except (requests.HTTPError, requests.Timeout) as e:
            status = getattr(getattr(e, "response", None), "status_code", None)
            if isinstance(e, requests.HTTPError) and not (status and status >= 500):
                raise
            time.sleep(INVENTORY_RETRY_DELAY_S)
            return self._get(path, params)

    def _server_node(self, agent, netiface, hardware, netaddr, netproto):
        """Normalize agent 000 with its real IPv4 in place of 127.0.0.1, or None.

        The address is what lets the assembler merge the server with the host
        found in the switch tables. Its MAC is picked only among the interfaces
        that carry that address, so a second NIC the switches never see can't
        stop the address match.
        """
        ip = server_ipv4(netaddr, netproto)
        if ip is None:
            return None
        ifaces = {a.get("iface") for a in netaddr or [] if a.get("address") == ip}
        node = normalize_agent({**agent, "ip": ip},
                               [i for i in netiface or [] if i.get("name") in ifaces],
                               hardware, netaddr)
        node["is_wazuh_server"] = True
        return node

    def collect(self) -> list[dict]:
        """Authenticate, fetch every agent + syscollector, normalize.

        Returns the list of normalized node dicts. One agent's missing
        syscollector data must not abort the run: the agent is kept, and listed
        in an ``inventory_unavailable`` warning (in :attr:`collect_warnings`).

        Agent 000 (the Wazuh server) is included with its real IPv4 and
        ``is_wazuh_server: true``. If no real address can be found it is left
        out, with a ``wazuh_server_skipped`` note, rather than emitted as an
        unmatched duplicate of the host the switch tables already show.
        """
        if not self._wcfg.password:
            raise SystemExit("vulnmapper: WAZUH_PASS is not set; export it to collect "
                             "endpoints (or run with --no-endpoints or --scored PATH).")
        self._authenticate()
        self.collect_warnings: list = []
        unavailable: list = []

        nodes: list[dict] = []
        agents = self._get(
            "/agents",
            params={
                "limit": 1000,
                "select": "id,name,ip,os.name,os.version,os.platform,status",
            },
        )
        for agent in agents:
            agent_id = agent["id"]
            is_server = agent_id == SERVER_AGENT_ID
            failed = False
            try:
                netiface = self._get_inventory(f"/syscollector/{agent_id}/netiface")
                hardware = self._get_inventory(f"/syscollector/{agent_id}/hardware")
                netaddr = self._get_inventory(f"/syscollector/{agent_id}/netaddr")
                netproto = (self._get_inventory(f"/syscollector/{agent_id}/netproto")
                            if is_server else [])
            except requests.RequestException as e:
                print(f"  ! syscollector failed for agent {agent_id}: {e}",
                      file=sys.stderr)
                failed = True
                netiface, hardware, netaddr, netproto = [], [], [], []

            if not is_server:
                if failed:
                    unavailable.append(agent_id)
                nodes.append(normalize_agent(agent, netiface, hardware, netaddr))
                continue
            node = self._server_node(agent, netiface, hardware, netaddr, netproto)
            if node is None:
                reason = ("its syscollector inventory could not be read" if failed else
                          "no IPv4 address other than loopback, link-local or a "
                          "container bridge in its syscollector inventory")
                print(f"  ! Wazuh server (agent 000) left out of this scan: {reason}",
                      file=sys.stderr)
                self.collect_warnings.append({
                    "type": "wazuh_server_skipped",
                    "agent_id": agent_id,
                    "hostname": agent.get("name"),
                    "reason": reason,
                })
            else:
                nodes.append(node)

        if unavailable:
            self.collect_warnings.append({
                "type": "inventory_unavailable",
                "agents": unavailable,
                "node_ids": [endpoint_node_id(a) for a in unavailable],
            })
        return nodes

    # ---- Manager API: agent check-in (read-only, for the liveness pass) ----

    # Agents per /agents request; the list is paged until a short page.
    AGENT_STATUS_PAGE = 500
    AGENT_STATUS_MAX_PAGES = 100

    def agent_status(self) -> list[dict]:
        """``id``, ``status`` and ``lastKeepAlive`` of every agent. Read-only.

        Logs in with the same code as :meth:`collect` and pages through
        ``/agents``. Raises on any failure; nothing is logged or written.
        """
        self._authenticate()
        rows: list = []
        for _ in range(self.AGENT_STATUS_MAX_PAGES):
            page = self._get("/agents", params={"select": "id,status,lastKeepAlive",
                                                "limit": self.AGENT_STATUS_PAGE,
                                                "offset": len(rows)})
            rows.extend(page)
            if len(page) < self.AGENT_STATUS_PAGE:
                break
        return rows

    # ---- Indexer (score stage) --------------------------------------------

    # Every field a CVE row is built from; the last three are optional.
    _SOURCE = [
        "vulnerability.id",
        "vulnerability.score.base",
        "vulnerability.score.version",
        "vulnerability.severity",
        "vulnerability.description",
        "vulnerability.reference",
        "vulnerability.published_at",
        "vulnerability.detected_at",
        "package.name",
        "package.version",
    ]
    # Worst score first, then CVE id. There is one document per CVE *and
    # package*, so (score, id) alone is not unique and search_after would skip
    # the rest of a tie that straddles a page boundary; the package fields break
    # those ties.
    _SORT = [
        {"vulnerability.score.base": {"order": "desc", "missing": "_last"}},
        {"vulnerability.id": {"order": "asc"}},
        {"package.name": {"order": "asc", "missing": "_last", "unmapped_type": "keyword"}},
        {"package.version": {"order": "asc", "missing": "_last", "unmapped_type": "keyword"}},
    ]

    def _search(self, body) -> list:
        r = requests.post(
            f"{self._ibase}/{self.INDEX}/_search",
            json=body,
            auth=(self._icfg.user, self._icfg.password),
            verify=self._icfg.verify,
            timeout=30,
        )
        r.raise_for_status()
        return r.json().get("hits", {}).get("hits", [])

    def _agent_cves(self, agent_id):
        """Every CVE row for ``agent_id``, worst first, paged with search_after.

        Returns ``(rows, capped)``; ``capped`` is True when the agent has more
        than :data:`MAX_DOCS_PER_AGENT` documents and the rest were not read.
        """
        rows: list = []
        after = None
        while True:
            size = min(PAGE_SIZE, MAX_DOCS_PER_AGENT - len(rows))
            body = {
                "size": max(size, 1),
                "query": {"term": {"agent.id": agent_id}},      # hard join key
                "sort": self._SORT,
                "_source": self._SOURCE,
            }
            if after is not None:
                body["search_after"] = after
            hits = self._search(body)
            if size == 0:              # at the cap: this was a one-row probe
                return rows, bool(hits)
            rows.extend(parse_hit(h) for h in hits)
            if len(hits) < size:
                return rows, False
            after = hits[-1].get("sort")

    def score(self, agents: list[dict]) -> list[dict]:
        """Enrich each agent with its CVEs + base score. Returns the new list.

        Agents are processed one at a time; only the shared CVE catalogue
        (:attr:`cves`), each agent's slim ``findings`` and its summary are kept.
        Problems for the graph metadata are collected in :attr:`warnings`.

        A failed request leaves that agent unscored. If the indexer does not
        answer at all (connection error or timeout), the remaining agents are
        left unscored too rather than each waiting out its own timeout.

        An agent with no vulnerability documents is only scored 0.0 if Wazuh
        has a package inventory for it (one Manager API request); without one
        it has not been examined yet, so it is left unscored and listed in a
        ``not_yet_inventoried`` warning.
        """
        if not self._icfg.password:
            raise SystemExit("vulnmapper: INDEXER_PASS is not set; export it to score "
                             "endpoints (or run with --no-endpoints or --scored PATH).")
        if not self._wcfg.password:
            raise SystemExit("vulnmapper: WAZUH_PASS is not set; the score stage needs "
                             "it to tell unexamined agents from clean ones (or run "
                             "with --no-endpoints or --scored PATH).")
        self.cves: dict = {}
        self.warnings: list = []
        unscored: list = []            # indexer failures
        not_inventoried: list = []     # no CVE documents and no package inventory
        inventory_failed: list = []    # the package check itself failed
        error = None
        down = False

        out: list[dict] = []
        for agent in agents:
            agent_id = agent.get("agent_id")  # hard join key carried from collect
            cves = None
            if down:
                unscored.append(agent_id)
            else:
                try:
                    cves, capped = self._agent_cves(agent_id) if agent_id else ([], False)
                except requests.RequestException as e:
                    error = error or e
                    down = isinstance(e, (requests.ConnectionError, requests.Timeout))
                    unscored.append(agent_id)
                    print(f"  ! indexer request failed for agent {agent_id}: {e}"
                          + ("; leaving the remaining endpoints unscored" if down else ""),
                          file=sys.stderr)
                    capped = False
                if capped:
                    self.warnings.append({
                        "type": "cve_cap_reached",
                        "agent_id": agent_id,
                        "node_id": endpoint_node_id(agent_id),
                        "hostname": agent.get("hostname"),
                        "cap": MAX_DOCS_PER_AGENT,
                    })
                    print(f"  ! agent {agent_id}: more than {MAX_DOCS_PER_AGENT} "
                          "vulnerability documents; the rest were not read",
                          file=sys.stderr)
                if cves == [] and agent_id:
                    try:
                        if not self._has_packages(agent_id):
                            not_inventoried.append(agent_id)
                            cves = None
                    except requests.RequestException as e:
                        print(f"  ! package inventory check failed for agent "
                              f"{agent_id}: {e}", file=sys.stderr)
                        inventory_failed.append(agent_id)
                        cves = None

            enriched = enrich_agent(agent, cves)
            if cves is None:
                enriched["findings"] = None
            else:
                for row in cves:
                    cve_id = row.get("cve")
                    if not cve_id:
                        continue
                    known = self.cves.get(cve_id)
                    if known is None or (row.get("cvss") is not None and (
                            known["cvss"] is None or row["cvss"] > known["cvss"])):
                        self.cves[cve_id] = catalogue_entry(row)
                enriched["findings"] = slim_findings(cves)
            out.append(enriched)
            summary = enriched["cve_summary"]
            print(f"  agent {agent_id} ({agent.get('hostname')}): "
                  + (f"{summary['total']} CVE(s), risk={enriched['risk_score']}"
                     if summary is not None else "unscored"), file=sys.stderr)

        if unscored:
            self.warnings.append({
                "type": "indexer_unreachable",
                "error": str(error),
                "agents": unscored,
                "node_ids": [endpoint_node_id(a) for a in unscored],
            })
        for kind, ids in (("not_yet_inventoried", not_inventoried),
                          ("inventory_unavailable", inventory_failed)):
            if ids:
                self.warnings.append({
                    "type": kind,
                    "agents": ids,
                    "node_ids": [endpoint_node_id(a) for a in ids],
                })
        return out

    def _has_packages(self, agent_id) -> bool:
        """True if the Manager API holds any package inventory for the agent."""
        if self._token is None:
            self._authenticate()
        return bool(self._get_inventory(f"/syscollector/{agent_id}/packages",
                                        params={"limit": 1}))
