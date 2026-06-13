#!/usr/bin/env python3
"""ORCHESTRATION — the NTM collect stage (was wazuh_agent_collector.py).

Pulls endpoint inventory from the Wazuh Manager API and writes ``agents.json``
(a list of normalized node dicts) for the score stage. Thin: fetch via
:class:`WazuhClient`, shape via :func:`normalize_agent`, tolerate per-agent
failures, write the file.

Progress goes to stderr; the output filename and env var names (``WAZUH_*``,
``AGENTS_OUT``) are preserved from the original script.

    python -m vulnmapper.endpoints.collect
"""

from __future__ import annotations

import json
import os
import sys

import requests

from ..schema import WazuhConfig
from .normalize import normalize_agent
from .wazuh_client import WazuhClient


def collect_agents(client: WazuhClient) -> list[dict]:
    """Authenticate, fetch every agent, normalize. Returns the node list."""
    client.authenticate()

    nodes: list[dict] = []
    for agent in client.get_agents():
        if agent["id"] == "000":      # 000 is the manager itself, not an endpoint
            continue
        try:
            netiface = client.get_netiface(agent["id"])
            hardware = client.get_hardware(agent["id"])
            netaddr = client.get_netaddr(agent["id"])
        except requests.HTTPError as e:
            # One agent's missing syscollector data must not abort the run.
            print(f"  ! syscollector failed for agent {agent['id']}: {e}",
                  file=sys.stderr)
            netiface, hardware, netaddr = [], [], []
        nodes.append(normalize_agent(agent, netiface, hardware, netaddr))
    return nodes


def main() -> int:
    config = WazuhConfig.from_env()
    out_path = os.environ.get("AGENTS_OUT", "agents.json")

    nodes = collect_agents(WazuhClient(config))

    with open(out_path, "w") as f:
        json.dump(nodes, f, indent=2)

    print(f"Wrote {len(nodes)} agents to {out_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
