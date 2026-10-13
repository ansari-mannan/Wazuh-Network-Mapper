"""The Wazuh endpoints: who the agents are and which CVEs each one has. The
first stage of a scan; ``python -m vulnmapper.endpoints.collect`` / ``.score``
run its two calls alone.
"""

#   wazuh       WazuhSource: the Manager API (collect) and Indexer (score) calls
#   inventory   an agent's node fields from its syscollector inventory
#   findings    CVE rows, their summary and base score, vulnerabilities.json shapes

from .findings import (TOP_CVES, catalogue_entry, distinct_cves, enrich_agent, merge_catalogue,
                       parse_hit, slim_findings, summarize_cves)
from .inventory import (is_locally_administered, is_physical_iface, normalize_agent,
                        select_mac, server_ipv4)
from .wazuh import WazuhSource

__all__ = [
    "TOP_CVES", "catalogue_entry", "distinct_cves", "enrich_agent", "merge_catalogue",
    "parse_hit", "slim_findings", "summarize_cves",
    "is_locally_administered", "is_physical_iface", "normalize_agent", "select_mac",
    "server_ipv4",
    "WazuhSource",
]
