"""How a liveness pass reaches the network: the system ``ping``, the
crawler's SNMP client and the Wazuh Manager API. Tests replace it with a fake
that has the same methods.
"""

from __future__ import annotations

import asyncio
import ipaddress
import threading

from ..schema import canonical_mac


class SystemProber:
    """Probes through the system ``ping`` binary and the existing SnmpClient.

    The SNMP community comes only from the environment (``load_credentials``)
    and is never logged or placed in argv.
    """

    def __init__(self, credentials: list, agent_source=None) -> None:
        self.has_snmp = bool(credentials)
        self._snmp = None
        if credentials:
            from ..network.snmp import SnmpClient
            self._snmp = SnmpClient(credentials, timeout=1.0, retries=1)
        # The agent method needs the Wazuh password (WAZUH_PASS, environment only).
        self._agent_source = agent_source
        if agent_source is None:
            from ..schema import WazuhConfig
            self.has_agents = bool(WazuhConfig.from_env().password)
        else:
            self.has_agents = True

    async def icmp(self, ip: str) -> bool:
        ipaddress.ip_address(ip)          # validated again right before argv
        proc = await asyncio.create_subprocess_exec(
            "ping", "-c", "1", "-W", "1", ip,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        return await proc.wait() == 0

    async def snmp(self, ip: str) -> bool:
        return await self._snmp.resolve_credential(ip) is not None

    async def port_status(self, ip: str) -> dict:
        from ..network.parse import collect_port_status
        return await collect_port_status(self._snmp, ip)

    async def mac_lookup(self, ip: str, entries: list, per_vlan_context: bool = False) -> dict:
        """``{(vlan, mac): port name or None}`` from GETs of those entries only."""
        from ..network.parse import lookup_fdb_ports
        return await lookup_fdb_ports(self._snmp, ip, entries, per_vlan_context)

    async def wifi_clients(self, ip: str) -> set:
        """The canonical MACs an access point lists as associated (one column).

        A walk that stops early also returns no rows, so an empty list counts
        only if the AP's own per-radio client counters say it is empty;
        otherwise this raises and the pass leaves its clients unchanged.
        """
        from ..network.parse import (DOT11_ACTIVE_CLIENTS_BASE, DOT11_CLIENT_BASE,
                                    DOT11_CLIENT_PARENT_COL, parse_wifi_clients)
        rows = await self._snmp.walk(ip, f"{DOT11_CLIENT_BASE}.{DOT11_CLIENT_PARENT_COL}")
        macs = {canonical_mac(c["mac"]) for c in parse_wifi_clients(rows, {})}
        if not macs:
            counts = await self._snmp.walk(ip, DOT11_ACTIVE_CLIENTS_BASE)
            if not counts or any(str(v).strip() not in ("0", "") for _o, v in counts):
                raise RuntimeError("client list unreadable")
        return macs

    async def agents(self) -> list:
        """Every agent's id, status and lastKeepAlive from the Manager API.

        The blocking requests run in a daemon thread, so a pass that gives up
        on them (the time box) neither waits for them nor is kept alive by them.
        """
        loop = asyncio.get_running_loop()
        future = loop.create_future()
        source = self._agent_source
        if source is None:
            from ..endpoints import WazuhSource
            source = WazuhSource()

        def settle(result, error):
            if not future.done():
                future.set_exception(error) if error else future.set_result(result)

        def work():
            try:
                result, error = source.agent_status(), None
            except Exception as e:
                result, error = None, e
            try:
                loop.call_soon_threadsafe(settle, result, error)
            except RuntimeError:
                pass                # the pass already finished and closed its loop

        threading.Thread(target=work, name="liveness-agents", daemon=True).start()
        return await future
