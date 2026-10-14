"""The Wazuh side of a scan: ``WazuhSource`` lists the agents and their
inventory from the Manager API (collect) and reads each agent's CVEs from the
Indexer (score). The first two stages of the pipeline; the indexer is joined
on ``agent.id``.
"""

from __future__ import annotations

import sys
import time

import requests

from ..schema import IndexerConfig, WazuhConfig, endpoint_node_id
from .findings import enrich_agent, merge_catalogue, parse_hit, slim_findings
from .inventory import normalize_agent, server_ipv4

# Vulnerability query: page size, and the per-agent safety cap.
PAGE_SIZE = 1000
MAX_DOCS_PER_AGENT = 20000

# Agent 000 is the Wazuh server itself; the Manager API reports it as 127.0.0.1.
SERVER_AGENT_ID = "000"
# A busy Manager API answers syscollector requests with a 5xx after ~10 s:
# wait this long and retry once.
INVENTORY_RETRY_DELAY_S = 3
# For hours after the Wazuh server restarts, its API refuses or times out the
# login. Try this many times, this far apart, then fail the scan with one line.
LOGIN_ATTEMPTS = 3
LOGIN_RETRY_DELAY_S = 5


class WazuhSource:
    """The endpoint two-stage source: Manager-API ``collect`` + Indexer ``score``.

    Connection settings come from the environment via
    :class:`~vulnmapper.schema.WazuhConfig` / :class:`~vulnmapper.schema.IndexerConfig`
    (built from env on construction). No network call happens until ``collect`` /
    ``score`` is invoked.
    """

    # The OpenSearch index pattern that holds all vulnerability states.
    INDEX = "wazuh-states-vulnerabilities-*"
    # ... and the one holding each agent's package inventory, which the
    # vulnerability detector works from.
    PACKAGES_INDEX = "wazuh-states-inventory-packages-*"

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

    def _login(self) -> None:
        """Log in to the Manager API, retrying a login that gets no answer.

        A refused connection or a timeout is retried (LOGIN_ATTEMPTS in all);
        then the scan ends with one plain message, so the plugin keeps the
        previous graph rather than one that has lost every endpoint. A rejected
        login (HTTP 401 or 403) is not retried: the scan ends at once with one
        plain message that names neither the password nor the server's reply.
        """
        for attempt in range(1, LOGIN_ATTEMPTS + 1):
            try:
                self._authenticate()
                return
            except requests.HTTPError as e:
                status = getattr(e.response, "status_code", None)
                if status in (401, 403):
                    raise SystemExit(
                        f"vulnmapper: the Wazuh Manager API at {self._wcfg.host}:{self._wcfg.port} "
                        f"rejected the login (HTTP {status}); check WAZUH_USER and WAZUH_PASS."
                    ) from None
                raise
            except (requests.ConnectionError, requests.Timeout) as e:
                what = "timed out" if isinstance(e, requests.Timeout) else "refused the connection"
                if attempt < LOGIN_ATTEMPTS:
                    print(f"  ! Wazuh Manager API login {what} (attempt {attempt} of "
                          f"{LOGIN_ATTEMPTS}); retrying in {LOGIN_RETRY_DELAY_S} s", file=sys.stderr)
                    time.sleep(LOGIN_RETRY_DELAY_S)
        raise SystemExit(
            f"vulnmapper: the Wazuh Manager API at {self._wcfg.host}:{self._wcfg.port} did not "
            f"answer the login ({what}, {LOGIN_ATTEMPTS} tries); is the Wazuh server up?")

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
        """Log in, then fetch and normalise every agent with its inventory.

        An agent whose syscollector data cannot be read is kept, and listed in
        an ``inventory_unavailable`` warning (in :attr:`collect_warnings`).
        Agent 000, the Wazuh server, is included with its real IPv4 and
        ``is_wazuh_server: true``; with no real address it is left out with a
        ``wazuh_server_skipped`` note rather than shown as an unmatched twin of
        the host the switch tables already have.
        """
        if not self._wcfg.password:
            raise SystemExit("vulnmapper: WAZUH_PASS is not set; export it to collect "
                             "endpoints (or run with --no-endpoints or --scored PATH).")
        self._login()
        self.collect_warnings: list = []
        unavailable: list = []

        nodes: list[dict] = []
        agents = self._agents("id,name,ip,os.name,os.version,os.platform,status")
        for agent in agents:
            agent_id = agent["id"]
            is_server = agent_id == SERVER_AGENT_ID
            netiface, hardware, netaddr, netproto, failed = self._inventory(agent_id, is_server)
            if not is_server:
                if failed:
                    unavailable.append(agent_id)
                nodes.append(normalize_agent(agent, netiface, hardware, netaddr))
                continue
            node = self._server_node(agent, netiface, hardware, netaddr, netproto)
            if node is None:
                self._skip_server(agent, failed)
            else:
                nodes.append(node)

        if unavailable:
            self.collect_warnings.append({
                "type": "inventory_unavailable",
                "agents": unavailable,
                "node_ids": [endpoint_node_id(a) for a in unavailable],
            })
        return nodes

    def _inventory(self, agent_id, is_server: bool) -> tuple:
        """``(netiface, hardware, netaddr, netproto, failed)`` for one agent;
        empty lists and ``failed`` when syscollector could not be read."""
        try:
            netiface = self._get_inventory(f"/syscollector/{agent_id}/netiface")
            hardware = self._get_inventory(f"/syscollector/{agent_id}/hardware")
            netaddr = self._get_inventory(f"/syscollector/{agent_id}/netaddr")
            netproto = (self._get_inventory(f"/syscollector/{agent_id}/netproto")
                        if is_server else [])
        except requests.RequestException as e:
            print(f"  ! syscollector failed for agent {agent_id}: {e}", file=sys.stderr)
            return [], [], [], [], True
        return netiface, hardware, netaddr, netproto, False

    def _skip_server(self, agent: dict, failed: bool) -> None:
        reason = ("its syscollector inventory could not be read" if failed else
                  "no IPv4 address other than loopback, link-local or a "
                  "container bridge in its syscollector inventory")
        print(f"  ! Wazuh server (agent 000) left out of this scan: {reason}", file=sys.stderr)
        self.collect_warnings.append({
            "type": "wazuh_server_skipped",
            "agent_id": agent["id"],
            "hostname": agent.get("name"),
            "reason": reason,
        })

    # ---- Manager API: agent check-in (read-only, for the liveness pass) ----

    # Agents per /agents request; the list is paged until a short page.
    AGENT_PAGE = 500
    AGENT_MAX_PAGES = 100

    def _agents(self, select: str) -> list[dict]:
        """Every agent from ``/agents`` (the ``select``ed fields), page by page."""
        rows: list = []
        for _ in range(self.AGENT_MAX_PAGES):
            page = self._get("/agents", params={"select": select, "limit": self.AGENT_PAGE,
                                                "offset": len(rows)})
            rows.extend(page)
            if len(page) < self.AGENT_PAGE:
                break
        return rows

    def agent_status(self) -> list[dict]:
        """``id``, ``status`` and ``lastKeepAlive`` of every agent. Read-only.

        Logs in with the same code as :meth:`collect` and pages through
        ``/agents``. Raises on any failure; nothing is logged or written.
        """
        self._authenticate()
        return self._agents("id,status,lastKeepAlive")

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
        """Each agent with its CVEs and base score; returns the new list.

        Agents are read one at a time, and only the shared CVE catalogue
        (:attr:`cves`), each agent's slim ``findings`` and its summary are
        kept. Problems for the graph metadata go in :attr:`warnings`.

        A failed request leaves that agent unscored. If the indexer does not
        answer at all (connection error or timeout), the remaining agents are
        left unscored too rather than each waiting out its own timeout.

        An agent with no vulnerability documents scores 0.0 only if Wazuh has a
        package inventory for it (:meth:`_has_packages`). Without one it has
        not been examined yet: it stays unscored with ``unscored_reason``
        "no_inventory" and is listed in a ``not_yet_inventoried`` warning.
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
            agent_id = agent.get("agent_id")  # the join key carried from collect
            cves = None
            if down:
                unscored.append(agent_id)
            else:
                try:
                    cves = self._read_cves(agent)
                except requests.RequestException as e:
                    error = error or e
                    down = isinstance(e, (requests.ConnectionError, requests.Timeout))
                    unscored.append(agent_id)
                    print(f"  ! indexer request failed for agent {agent_id}: {e}"
                          + ("; leaving the remaining endpoints unscored" if down else ""),
                          file=sys.stderr)
                if cves == [] and agent_id:
                    try:
                        if not self._has_packages(agent_id):
                            not_inventoried.append(agent_id)
                            cves = None
                            agent = {**agent, "unscored_reason": "no_inventory"}
                    except requests.RequestException as e:
                        print(f"  ! package inventory check failed for agent "
                              f"{agent_id}: {e}", file=sys.stderr)
                        inventory_failed.append(agent_id)
                        cves = None
            out.append(self._scored(agent, cves))

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

    def _read_cves(self, agent: dict) -> list:
        """Every CVE row for one agent, with a warning when it hit the cap."""
        agent_id = agent.get("agent_id")
        if not agent_id:
            return []
        cves, capped = self._agent_cves(agent_id)
        if capped:
            self.warnings.append({
                "type": "cve_cap_reached",
                "agent_id": agent_id,
                "node_id": endpoint_node_id(agent_id),
                "hostname": agent.get("hostname"),
                "cap": MAX_DOCS_PER_AGENT,
            })
            print(f"  ! agent {agent_id}: more than {MAX_DOCS_PER_AGENT} "
                  "vulnerability documents; the rest were not read", file=sys.stderr)
        return cves

    def _scored(self, agent: dict, cves) -> dict:
        """The agent enriched with its CVEs (None: unscored), its rows added
        to the shared catalogue."""
        enriched = enrich_agent(agent, cves)
        if cves is None:
            enriched["findings"] = None
        else:
            merge_catalogue(self.cves, cves)
            enriched["findings"] = slim_findings(cves)
        summary = enriched["cve_summary"]
        print(f"  agent {agent.get('agent_id')} ({agent.get('hostname')}): "
              + (f"{summary['total']} CVE(s), max CVSS {enriched['max_cvss']}"
                 if summary is not None else "unscored"), file=sys.stderr)
        return enriched

    def _has_packages(self, agent_id) -> bool:
        """True if Wazuh holds any package inventory for the agent.

        The indexer's package states are what vulnerability detection reads, so
        they decide; the Manager API's syscollector is asked only when no index
        matches (a Wazuh without those states). The Wazuh server itself can
        have the latter and none of the former.
        """
        r = requests.post(
            f"{self._ibase}/{self.PACKAGES_INDEX}/_count",
            json={"query": {"term": {"agent.id": agent_id}}},
            auth=(self._icfg.user, self._icfg.password),
            verify=self._icfg.verify,
            timeout=30,
        )
        r.raise_for_status()
        body = r.json()
        if (body.get("_shards") or {}).get("total"):
            return body.get("count", 0) > 0
        if self._token is None:
            self._authenticate()
        return bool(self._get_inventory(f"/syscollector/{agent_id}/packages",
                                        params={"limit": 1}))
