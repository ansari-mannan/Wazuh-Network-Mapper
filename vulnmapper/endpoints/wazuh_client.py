#!/usr/bin/env python3
"""FETCH LAYER — all HTTP communication with the Wazuh Manager API.

No business logic; only authenticates and returns raw API responses. This is
the unchanged fetch behavior from the original NTM collector, now taking its
connection settings from :class:`WazuhConfig` instead of reading os.environ
directly.
"""

from __future__ import annotations

import requests

from ..schema import WazuhConfig


class WazuhClient:
    def __init__(self, config: WazuhConfig):
        self._cfg = config
        self.base = f"https://{config.host}:{config.port}"
        self.token = None

    def authenticate(self):
        r = requests.post(
            f"{self.base}/security/user/authenticate",
            auth=(self._cfg.user, self._cfg.password),
            verify=self._cfg.verify,
            timeout=15,
        )
        if not r.ok:
            raise requests.HTTPError(
                f"Auth failed: {r.status_code} {r.reason} — {r.text[:500]}",
                response=r,
            )
        self.token = r.json()["data"]["token"]

    def _get(self, path, params=None):
        r = requests.get(
            f"{self.base}{path}",
            headers={"Authorization": f"Bearer {self.token}"},
            params=params,
            verify=self._cfg.verify,
            timeout=30,
        )
        r.raise_for_status()
        return r.json().get("data", {}).get("affected_items", [])

    def get_agents(self):
        return self._get(
            "/agents",
            params={
                "limit": 1000,
                "select": "id,name,ip,os.name,os.version,os.platform,status",
            },
        )

    def get_netiface(self, agent_id):
        return self._get(f"/syscollector/{agent_id}/netiface")

    def get_netaddr(self, agent_id):
        # IPv4 addresses live here, not in netiface; joined by interface name.
        return self._get(f"/syscollector/{agent_id}/netaddr")

    def get_hardware(self, agent_id):
        return self._get(f"/syscollector/{agent_id}/hardware")
