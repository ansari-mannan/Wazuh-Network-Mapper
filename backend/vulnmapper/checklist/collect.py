"""Read what the configuration checks need while a device is being polled.

Column walks only, through the crawl's own SNMP client and the credential it
already resolved. A table the device does not answer costs one request and
is recorded as None (not read). Read-only: GETs and walks, never a SET.

Requests per device (each walk is one or more GETBULKs):

  every device   1 GET (sysUpTime), 2 walks TCP-MIB, 5 walks IF-MIB
                 (ifName, or ifDescr when ifName is empty: one more),
                 2 walks BRIDGE-MIB / Q-BRIDGE-MIB              = 10
  Cisco          + 1 walk VLAN membership, 1 GET (three scalars),
                 1 walk port security, 2 walks STP extensions    = 15
                 + one walk per access VLAN, only when BPDU guard differs
                 between ports (to map Cisco bridge ports to interfaces)
  probe (opt-in) + 2 GETs with the factory names, no retry
"""

from __future__ import annotations

import logging

from . import tables as t

log = logging.getLogger("vulnmapper.checklist")

PROBE_NAMES = ("public", "private")
PROBE_TIMEOUT_S = 1.0


async def probe_default_communities(client, ip: str) -> dict:
    """One read of sysName with each factory name. Never a write."""
    out = {}
    for name in PROBE_NAMES:
        try:
            out[name] = await client.answers_to_community(ip, name, t.SYS_NAME, PROBE_TIMEOUT_S)
        except Exception:      # an unreachable or refusing device simply did not answer
            out[name] = False
    return out


async def _bridge_port_ifindex(client, ip: str, vlans) -> dict:
    """Cisco numbers bridge ports device-wide but lists, in each VLAN's
    community@vlan context, only that VLAN's members: read every access VLAN."""
    out: dict = {}
    for vlan in sorted(vlans):
        rows = await client.walk_vlan_context(ip, t.DOT1D_BASE_PORT_IFINDEX, vlan)
        out.update(t.parse_index_map(rows, t.DOT1D_BASE_PORT_IFINDEX) or {})
    return out


async def collect_config(client, ip: str, vendor, probe: bool = False) -> dict:
    """The parsed ``config_data`` for one polled device (see tables.py)."""
    walk = lambda base: client.walk(ip, base)   # noqa: E731
    data: dict = {"snmp": client.credential_summary(ip),
                  "probe": await probe_default_communities(client, ip) if probe else None}

    scalars = await client.get_many(ip, [t.SYS_UPTIME]) or {}
    data["uptime"] = t.as_int(scalars.get(t.SYS_UPTIME))
    data["tcp"] = t.parse_tcp(await walk(t.TCP_CONN_STATE), await walk(t.TCP_LISTENER_PROCESS))

    names = await walk(t.IF_NAME)
    descr = [] if names else await walk(t.IF_DESCR)
    data["interfaces"] = t.parse_interfaces(
        await walk(t.IF_TYPE), await walk(t.IF_ADMIN_STATUS), await walk(t.IF_OPER_STATUS),
        await walk(t.IF_LAST_CHANGE), names, descr)
    data["bridge_ports"] = t.parse_index_map(await walk(t.DOT1D_BASE_PORT_IFINDEX),
                                             t.DOT1D_BASE_PORT_IFINDEX)
    data["pvid"] = t.parse_index_map(await walk(t.DOT1Q_PVID), t.DOT1Q_PVID)

    data["vm_vlan"] = data["port_security"] = data["bpdu"] = None
    if vendor == "Cisco":
        data["vm_vlan"] = t.parse_index_map(await walk(t.VM_VLAN), t.VM_VLAN)
        g = await client.get_many(ip, [t.CPS_GLOBAL_ENABLE, t.STPX_BPDU_GUARD_GLOBAL,
                                       t.STPX_FAST_START_DEFAULT]) or {}
        data["port_security"] = t.parse_port_security(g.get(t.CPS_GLOBAL_ENABLE),
                                                      await walk(t.CPS_IF_ENABLE))
        bpdu = t.parse_bpdu(g.get(t.STPX_BPDU_GUARD_GLOBAL), g.get(t.STPX_FAST_START_DEFAULT),
                            await walk(t.STPX_PORT_MODE), await walk(t.STPX_PORT_BPDU_GUARD))
        if bpdu is not None:
            # Only when ports differ does each bridge port need its interface.
            states = {t.bpdu_guard_on(bpdu, bp) for bp in bpdu["ports"]}
            if len(states) > 1 and data["vm_vlan"] and client.is_v2c(ip):
                bpdu["port_ifindex"] = await _bridge_port_ifindex(
                    client, ip, set(data["vm_vlan"].values()))
        data["bpdu"] = bpdu
    return data
