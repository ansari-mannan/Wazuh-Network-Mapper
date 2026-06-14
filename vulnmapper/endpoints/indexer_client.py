#!/usr/bin/env python3
"""FETCH LAYER — all HTTP communication with the Wazuh Indexer (OpenSearch).

No business logic; only sends queries and returns raw hit lists.

The one behavioral change from the original APA fetch layer: the vulnerability
documents are filtered on ``agent.id`` rather than ``agent.name``. Wazuh
vulnerability docs carry both, and the id is the hard, unique join key — keying
on the name was the known hostname-join fragility.
"""

from __future__ import annotations

import requests

from ..common.config import IndexerConfig


class IndexerClient:
    # The OpenSearch index pattern that holds all vulnerability states.
    INDEX = "wazuh-states-vulnerabilities-*"

    def __init__(self, config: IndexerConfig):
        self.base = f"https://{config.host}:{config.port}"
        self.auth = (config.user, config.password)
        self.verify = config.verify

    def top_cves(self, agent_id, k=3):
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
            f"{self.base}/{self.INDEX}/_search",
            json=body,
            auth=self.auth,
            verify=self.verify,
            timeout=30,
        )
        r.raise_for_status()
        return r.json().get("hits", {}).get("hits", [])
