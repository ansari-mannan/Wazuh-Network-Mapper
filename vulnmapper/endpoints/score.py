#!/usr/bin/env python3
"""ORCHESTRATION — the APA score stage (was wazuh_cvss_collector.py).

Reads ``agents.json``, queries the indexer for each agent's top CVEs (joined on
``agent.id``), and writes ``scored_agents.json`` with a ``risk_score`` per
endpoint. Thin: fetch via :class:`IndexerClient`, shape via ``parse_hit`` /
``enrich_agent``, tolerate per-agent failures.

Progress goes to stderr; the output filename and env var names (``INDEXER_*``,
``AGENTS_IN``, ``SCORED_OUT``) are preserved.

    python -m vulnmapper.endpoints.score
"""

from __future__ import annotations

import json
import os
import sys

import requests

from ..schema import IndexerConfig
from .indexer_client import IndexerClient
from .normalize import enrich_agent, parse_hit


def score_agents(indexer: IndexerClient, agents: list[dict]) -> list[dict]:
    """Enrich each agent with its top CVEs + risk score. Returns the new list."""
    out: list[dict] = []
    for agent in agents:
        agent_id = agent.get("agent_id")  # hard join key carried from collect
        try:
            raw_hits = indexer.top_cves(agent_id, k=3) if agent_id else []
        except requests.HTTPError as e:
            print(f"  ! query failed for agent {agent_id}: {e}", file=sys.stderr)
            raw_hits = []

        cves = [parse_hit(h) for h in raw_hits]
        enriched = enrich_agent(agent, cves)
        out.append(enriched)
        print(f"  agent {agent_id} ({agent.get('hostname')}): "
              f"{len(cves)} CVE(s), risk={enriched['risk_score']}", file=sys.stderr)
    return out


def main() -> int:
    config = IndexerConfig.from_env()
    agents_in = os.environ.get("AGENTS_IN", "agents.json")
    out_path = os.environ.get("SCORED_OUT", "scored_agents.json")

    with open(agents_in) as f:
        agents = json.load(f)

    out = score_agents(IndexerClient(config), agents)

    with open(out_path, "w") as f:
        json.dump(out, f, indent=2)

    print(f"Wrote {len(out)} scored agents to {out_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
