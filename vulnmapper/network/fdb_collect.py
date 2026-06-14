"""Collect a switch's MAC forwarding table over SNMP, then hand to :mod:`fdb`.

This is the thin I/O orchestration around the pure parser. It runs in the same
SNMP session the crawler already opened for a device (the credential is already
resolved), just issuing more walks.

On Cisco v2c gear (the lab case) the per-VLAN forwarding tables are only
reachable via the **community-context trick** — the bridge MIB returns a given
VLAN's table when the community is suffixed ``community@<vlan-id>``. A plain read
returns VLAN 1 only, and the lab hosts live in VLANs 10/20/30/99, so we must:

  1. Enumerate VLANs from the Cisco VTP table (vtpVlanState).
  2. For each VLAN, in its ``community@<vlan>`` context, walk dot1dTpFdbPort
     (MAC -> bridge port) and dot1dBasePortIfIndex (bridge port -> ifIndex).
  3. Resolve ifIndex -> ifName (global) for human port names.

Anything non-Cisco / v3 / VLAN-less falls back to a single default-context read
(dot1q first, then flat dot1d). Every walk is best-effort: an unsupported table
returns no rows and yields an empty FDB rather than failing.
"""

from __future__ import annotations

import logging

from . import fdb

log = logging.getLogger("discovery.fdb")

# Defensive cap so a misreported VLAN table can't trigger thousands of walks.
_MAX_VLANS = 256


async def collect_fdb(client, ip: str) -> list[dict]:
    """Return ``[{mac, port, vlan}, ...]`` for the switch at ``ip`` (maybe empty)."""
    ifname_rows = await client.walk(ip, fdb.IFNAME_BASE)
    ifdescr_rows = await client.walk(ip, fdb.IFDESCR_BASE) if not ifname_rows else []

    # --- Cisco per-VLAN path: VTP enumeration + community@vlan dot1d reads ---
    if client.is_v2c(ip):
        vlans = fdb.parse_vtp_vlans(await client.walk(ip, fdb.VTP_VLAN_STATE_BASE))
        if not vlans:
            # No VTP (non-Cisco-ish): fall back to the 802.1Q static VLAN list.
            vlans = sorted(fdb.parse_vlan_static_names(
                await client.walk(ip, fdb.DOT1Q_VLAN_STATIC_NAME_BASE)))

        if vlans:
            log.info("%s: walking %d VLAN(s): %s", ip, len(vlans), vlans[:_MAX_VLANS])
        per_vlan: dict[int, dict] = {}
        for vlan in vlans[:_MAX_VLANS]:
            fdb_rows = await client.walk_vlan_context(ip, fdb.DOT1D_FDB_PORT_BASE, vlan)
            if not fdb_rows:
                continue
            baseport_rows = await client.walk_vlan_context(
                ip, fdb.DOT1D_BASEPORT_IFINDEX_BASE, vlan)
            per_vlan[vlan] = {"fdb": fdb_rows, "baseport": baseport_rows}

        if per_vlan:
            entries = fdb.assemble_dot1d_per_vlan(per_vlan, ifname_rows, ifdescr_rows)
            log.info("%s: FDB has %d entr(ies) across %d VLAN(s)",
                     ip, len(entries), len(per_vlan))
            return entries

    # --- Default-context fallback (non-Cisco / v3 / no VLANs / empty per-VLAN) ---
    dot1q_rows = await client.walk(ip, fdb.DOT1Q_FDB_PORT_BASE)
    dot1d_rows = await client.walk(ip, fdb.DOT1D_FDB_PORT_BASE) if not dot1q_rows else None
    baseport_rows = await client.walk(ip, fdb.DOT1D_BASEPORT_IFINDEX_BASE)

    entries = fdb.build_fdb(
        dot1q_rows=dot1q_rows or None,
        dot1d_rows=dot1d_rows or None,
        baseport_rows=baseport_rows,
        ifname_rows=ifname_rows,
        ifdescr_rows=ifdescr_rows,
    )
    log.info("%s: FDB has %d entr(ies) (default context)", ip, len(entries))
    return entries


async def collect_arp(client, ip: str) -> dict:
    """Return ``{canonical_mac: ip}`` from the device's ARP table (plain community).

    The router's ARP table is global, not per-VLAN-indexed, so it is read with the
    plain community (no ``@vlan``). Gives an IP for every MAC the device has
    routed recently — joined to the forwarding table by MAC.
    """
    arp = fdb.parse_arp(await client.walk(ip, fdb.ARP_BASE))
    log.info("%s: ARP has %d IP<->MAC mapping(s)", ip, len(arp))
    return arp


async def collect_own_macs(client, ip: str) -> list:
    """Return the device's own interface MACs (ifPhysAddress) for filtering."""
    return sorted(fdb.parse_own_macs(await client.walk(ip, fdb.IFPHYS_BASE)))


async def collect_port_status(client, ip: str) -> dict:
    """Return ``{port_name: "up"|"down"}`` from a real IF-MIB ifOperStatus walk.

    Independent of LLDP — this is the configured state of every interface, named
    via the global ifName (ifDescr fallback) chain. Best-effort: a device with no
    IF-MIB yields an empty map rather than failing.
    """
    oper_rows = await client.walk(ip, fdb.IFOPERSTATUS_BASE)
    ifname_rows = await client.walk(ip, fdb.IFNAME_BASE)
    ifdescr_rows = await client.walk(ip, fdb.IFDESCR_BASE) if not ifname_rows else []
    status = fdb.build_port_status(oper_rows, ifname_rows, ifdescr_rows)
    log.info("%s: port_status has %d port(s)", ip, len(status))
    return status
