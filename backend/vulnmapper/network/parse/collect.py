"""The SNMP reads behind the parsers: each ``collect_*`` walks the tables one
job needs through an open ``SnmpClient`` and hands the rows to a parser.
"""

from __future__ import annotations

import logging
from typing import Optional

from .bridge import (
    ARP_BASE,
    DOT1D_BASEPORT_IFINDEX_BASE,
    DOT1D_FDB_PORT_BASE,
    DOT1Q_FDB_PORT_BASE,
    DOT1Q_VLAN_STATIC_NAME_BASE,
    IFDESCR_BASE,
    IFNAME_BASE,
    IFOPERSTATUS_BASE,
    IFPHYS_BASE,
    VTP_VLAN_STATE_BASE,
    assemble_dot1d_per_vlan,
    build_fdb,
    build_port_status,
    parse_arp,
    parse_ifnames,
    parse_ifphys_ifindex,
    parse_own_macs,
    parse_vlan_static_names,
    parse_vtp_vlans,
)
from .wifi import (
    DOT11_CLIENT_BASE,
    DOT11_CLIENT_IP_COL,
    DOT11_CLIENT_PARENT_COL,
    DOT11_CLIENT_VLAN_COL,
    parse_wifi_clients,
)


_log_fdb = logging.getLogger("discovery.fdb")

_MAX_VLANS = 256

async def collect_fdb(client, ip: str) -> list[dict]:
    """Return ``[{mac, port, vlan}, ...]`` for the switch at ``ip`` (maybe empty)."""
    ifname_rows = await client.walk(ip, IFNAME_BASE)
    ifdescr_rows = await client.walk(ip, IFDESCR_BASE) if not ifname_rows else []

    # --- Cisco per-VLAN path: VTP enumeration + community@vlan dot1d reads ---
    if client.is_v2c(ip):
        vlans = parse_vtp_vlans(await client.walk(ip, VTP_VLAN_STATE_BASE))
        if not vlans:
            # No VTP (non-Cisco-ish): fall back to the 802.1Q static VLAN list.
            vlans = sorted(parse_vlan_static_names(
                await client.walk(ip, DOT1Q_VLAN_STATIC_NAME_BASE)))

        if vlans:
            _log_fdb.info("%s: walking %d VLAN(s): %s", ip, len(vlans), vlans[:_MAX_VLANS])
        per_vlan: dict[int, dict] = {}
        for vlan in vlans[:_MAX_VLANS]:
            fdb_rows = await client.walk_vlan_context(ip, DOT1D_FDB_PORT_BASE, vlan)
            if not fdb_rows:
                continue
            baseport_rows = await client.walk_vlan_context(
                ip, DOT1D_BASEPORT_IFINDEX_BASE, vlan)
            per_vlan[vlan] = {"fdb": fdb_rows, "baseport": baseport_rows}

        if per_vlan:
            entries = assemble_dot1d_per_vlan(per_vlan, ifname_rows, ifdescr_rows)
            _log_fdb.info("%s: FDB has %d entr(ies) across %d VLAN(s)",
                     ip, len(entries), len(per_vlan))
            return entries

    # --- Default-context fallback (non-Cisco / v3 / no VLANs / empty per-VLAN) ---
    dot1q_rows = await client.walk(ip, DOT1Q_FDB_PORT_BASE)
    dot1d_rows = await client.walk(ip, DOT1D_FDB_PORT_BASE) if not dot1q_rows else None
    baseport_rows = await client.walk(ip, DOT1D_BASEPORT_IFINDEX_BASE)

    entries = build_fdb(
        dot1q_rows=dot1q_rows or None,
        dot1d_rows=dot1d_rows or None,
        baseport_rows=baseport_rows,
        ifname_rows=ifname_rows,
        ifdescr_rows=ifdescr_rows,
    )
    _log_fdb.info("%s: FDB has %d entr(ies) (default context)", ip, len(entries))
    return entries


async def collect_arp(client, ip: str) -> dict:
    """Return ``{canonical_mac: ip}`` from the device's ARP table (plain community).

    The router's ARP table is global, not per-VLAN-indexed, so it is read with the
    plain community (no ``@vlan``). Gives an IP for every MAC the device has
    routed recently — joined to the forwarding table by MAC.
    """
    arp = parse_arp(await client.walk(ip, ARP_BASE))
    _log_fdb.info("%s: ARP has %d IP<->MAC mapping(s)", ip, len(arp))
    return arp


async def collect_own_macs(client, ip: str) -> list:
    """Return the device's own interface MACs (ifPhysAddress) for filtering."""
    return sorted(parse_own_macs(await client.walk(ip, IFPHYS_BASE)))


async def collect_ifname_map(client, ip: str) -> dict:
    """Return ``{ifIndex: ifName}`` (ifDescr fallback) for ``ip``."""
    ifname_rows = await client.walk(ip, IFNAME_BASE)
    if ifname_rows:
        return parse_ifnames(ifname_rows)
    ifdescr_rows = await client.walk(ip, IFDESCR_BASE)
    return parse_ifnames(ifdescr_rows, base=IFDESCR_BASE)


async def collect_ifindex_by_mac(client, ip: str) -> dict:
    """Return ``{canonical_mac: ifIndex}`` from ifPhysAddress for ``ip``.

    Lets an LLDP local-port id advertised as a port's own MAC (Comware) resolve
    back to a port name.
    """
    return parse_ifphys_ifindex(await client.walk(ip, IFPHYS_BASE))


# OIDs per GET when looking up specific forwarding-table entries.
MAC_LOOKUP_BATCH = 20


def _decimal_mac(mac: str) -> str:
    return ".".join(str(int(mac[i:i + 2], 16)) for i in range(0, 12, 2))


async def _get_in_batches(client, ip: str, oids: list[str], vlan: Optional[int] = None) -> dict:
    """GET ``oids`` (default context, or the per-VLAN one) in small batches."""
    out: dict = {}
    for i in range(0, len(oids), MAC_LOOKUP_BATCH):
        chunk = oids[i:i + MAC_LOOKUP_BATCH]
        got = await (client.get_many_vlan_context(ip, chunk, vlan) if vlan is not None
                     else client.get_many(ip, chunk))
        out.update(got or {})
    return out


async def lookup_fdb_ports(
    client, ip: str, entries: list[tuple[Optional[int], str]], per_vlan_context: bool
) -> dict:
    """Where specific MACs sit in a switch's forwarding table, without walking it.

    ``entries`` are ``(vlan, canonical mac)``; returns ``{entry: port name or
    None}``. The tables are the ones :func:`collect_fdb` reads: with
    ``per_vlan_context`` (Cisco) the 802.1D table in each VLAN's
    community@vlan context, otherwise the 802.1Q table (802.1D when the VLAN is
    unknown) in the default context. The bridge port is resolved through
    dot1dBasePortIfIndex and ifName, as in the scan.
    """
    bridge: dict = {}          # entry -> (bridge port, context vlan or None)
    if per_vlan_context:
        by_vlan: dict = {}
        for vlan, mac in entries:
            if vlan is not None:
                by_vlan.setdefault(vlan, []).append(mac)
        for vlan, macs in by_vlan.items():
            got = await _get_in_batches(
                client, ip, [f"{DOT1D_FDB_PORT_BASE}.{_decimal_mac(m)}" for m in macs], vlan)
            for mac in macs:
                port = got.get(f"{DOT1D_FDB_PORT_BASE}.{_decimal_mac(mac)}")
                if port and port != "0":
                    bridge[(vlan, mac)] = (port, vlan)
    else:
        oid_of = {(vlan, mac): (f"{DOT1Q_FDB_PORT_BASE}.{vlan}.{_decimal_mac(mac)}"
                                if vlan is not None
                                else f"{DOT1D_FDB_PORT_BASE}.{_decimal_mac(mac)}")
                  for vlan, mac in entries}
        got = await _get_in_batches(client, ip, list(oid_of.values()))
        for entry, oid in oid_of.items():
            port = got.get(oid)
            if port and port != "0":
                bridge[entry] = (port, None)

    if_index: dict = {}        # (bridge port, context) -> ifIndex
    for context in {ctx for _p, ctx in bridge.values()}:
        ports = sorted({p for p, ctx in bridge.values() if ctx == context})
        got = await _get_in_batches(
            client, ip, [f"{DOT1D_BASEPORT_IFINDEX_BASE}.{p}" for p in ports], context)
        for p in ports:
            if got.get(f"{DOT1D_BASEPORT_IFINDEX_BASE}.{p}"):
                if_index[(p, context)] = got[f"{DOT1D_BASEPORT_IFINDEX_BASE}.{p}"]
    indexes = sorted(set(if_index.values()))
    names = await _get_in_batches(client, ip, [f"{IFNAME_BASE}.{i}" for i in indexes])

    out: dict = {}
    for entry in entries:
        found = bridge.get(entry)
        index = if_index.get(found) if found else None
        out[entry] = (names.get(f"{IFNAME_BASE}.{index}") or index) if index else None
    return out


async def collect_wifi_clients(client, ip: str) -> list[dict]:
    """An access point's associated clients (three column walks, no full rows)."""
    rows = await client.walk(ip, f"{DOT11_CLIENT_BASE}.{DOT11_CLIENT_PARENT_COL}")
    if not rows:
        return []
    rows += await client.walk(ip, f"{DOT11_CLIENT_BASE}.{DOT11_CLIENT_IP_COL}")
    rows += await client.walk(ip, f"{DOT11_CLIENT_BASE}.{DOT11_CLIENT_VLAN_COL}")
    clients = parse_wifi_clients(rows, await collect_ifname_map(client, ip))
    _log_fdb.info("%s: %d wireless client(s)", ip, len(clients))
    return clients


async def collect_port_status(client, ip: str) -> dict:
    """Return ``{port_name: "up"|"down"}`` from a real IF-MIB ifOperStatus walk.

    Independent of LLDP — this is the configured state of every interface, named
    via the global ifName (ifDescr fallback) chain. Best-effort: a device with no
    IF-MIB yields an empty map rather than failing.
    """
    oper_rows = await client.walk(ip, IFOPERSTATUS_BASE)
    ifname_rows = await client.walk(ip, IFNAME_BASE)
    ifdescr_rows = await client.walk(ip, IFDESCR_BASE) if not ifname_rows else []
    status = build_port_status(oper_rows, ifname_rows, ifdescr_rows)
    _log_fdb.info("%s: port_status has %d port(s)", ip, len(status))
    return status
