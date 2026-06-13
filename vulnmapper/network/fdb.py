"""Pure parsing of switch MAC forwarding tables (FDB). No I/O, no SNMP.

A switch's FDB answers the question the endpoint linker needs: *which port did I
learn this MAC on?* Two MIB worlds carry it, and which one a switch speaks
varies, so the crawler tries the 802.1Q table first and falls back to the flat
802.1D one:

  * 802.1Q (dot1qTpFdbTable, ``1.3.6.1.2.1.17.7.1.2.2``) — per-VLAN. The VLAN id
    is part of the OID *index*, not a column. The value is a *bridge port*.
  * 802.1D (dot1dTpFdbTable, ``1.3.6.1.2.1.17.4.3``) — flat, no VLAN. The value
    is a *bridge port*.

A bridge port is not a human port name. Two more tables translate it:

  * dot1dBasePortIfIndex (``1.3.6.1.2.1.17.1.4.1.2``)  bridge-port -> ifIndex
  * ifName (``1.3.6.1.2.1.31.1.1.1.1``)                 ifIndex   -> "Gi0/3"

This module only transforms ``[(oid, value), ...]`` walk rows, so the fiddly
index decoding (especially the dotted-decimal MAC buried in the OID) is unit
testable without a live switch.
"""

from __future__ import annotations

from typing import Optional

from ..schema import canonical_mac

# Walk bases (no trailing dot).
DOT1Q_FDB_PORT_BASE = "1.3.6.1.2.1.17.7.1.2.2.1.2"   # dot1qTpFdbPort
DOT1D_FDB_PORT_BASE = "1.3.6.1.2.1.17.4.3.1.2"        # dot1dTpFdbPort
DOT1D_BASEPORT_IFINDEX_BASE = "1.3.6.1.2.1.17.1.4.1.2"  # dot1dBasePortIfIndex
IFNAME_BASE = "1.3.6.1.2.1.31.1.1.1.1"                # ifName
IFDESCR_BASE = "1.3.6.1.2.1.2.2.1.2"                  # ifDescr (fallback)
IFOPERSTATUS_BASE = "1.3.6.1.2.1.2.2.1.8"             # ifOperStatus (port up/down)
DOT1Q_VLAN_STATIC_NAME_BASE = "1.3.6.1.2.1.17.7.1.4.3.1.1"  # dot1qVlanStaticName
VTP_VLAN_STATE_BASE = "1.3.6.1.4.1.9.9.46.1.3.1.1.2"  # Cisco vtpVlanState (VLAN list)
ARP_BASE = "1.3.6.1.2.1.4.22.1.2"                     # ipNetToMediaPhysAddress (IP<->MAC)
IFPHYS_BASE = "1.3.6.1.2.1.2.2.1.6"                   # ifPhysAddress (device's own MACs)

# vtpVlanState value 1 == operational; reserved VLANs 1002-1005 are skipped.
_VTP_OPERATIONAL = "1"


def _index_after(oid: str, base: str) -> Optional[str]:
    """Return the OID arcs below ``base`` (the table index), or None if outside."""
    prefix = base.rstrip(".") + "."
    if not oid.startswith(prefix):
        return None
    return oid[len(prefix):]


def _mac_from_decimal_octets(octets: list[str]) -> Optional[str]:
    """Join 6 dotted-decimal OID arcs into a canonical 12-hex MAC."""
    if len(octets) != 6:
        return None
    try:
        return "".join(f"{int(o):02x}" for o in octets)
    except ValueError:
        return None


def parse_baseport_ifindex(rows: list[tuple[str, Optional[str]]]) -> dict[str, str]:
    """``bridge-port -> ifIndex`` from dot1dBasePortIfIndex."""
    out: dict[str, str] = {}
    for oid, value in rows:
        index = _index_after(oid, DOT1D_BASEPORT_IFINDEX_BASE)
        if index is None or value is None:
            continue
        out[index] = value
    return out


def parse_ifnames(rows: list[tuple[str, Optional[str]]], base: str = IFNAME_BASE) -> dict[str, str]:
    """``ifIndex -> port name`` from ifName (or ifDescr with ``base`` override)."""
    out: dict[str, str] = {}
    for oid, value in rows:
        index = _index_after(oid, base)
        if index is None or value is None:
            continue
        out[index] = value
    return out


def parse_vlan_static_names(rows: list[tuple[str, Optional[str]]]) -> dict[int, str]:
    """``vlan-id -> name`` from dot1qVlanStaticName (also yields the VLAN list)."""
    out: dict[int, str] = {}
    for oid, value in rows:
        index = _index_after(oid, DOT1Q_VLAN_STATIC_NAME_BASE)
        if index is None:
            continue
        try:
            out[int(index.split(".")[0])] = value if value is not None else ""
        except ValueError:
            continue
    return out


def parse_arp(rows: list[tuple[str, Optional[str]]]) -> dict[str, str]:
    """ipNetToMediaPhysAddress rows -> ``{canonical_mac: ip}``.

    Index is ``<ifIndex>.<a>.<b>.<c>.<d>`` (the last four arcs are the IPv4
    address); the value is the MAC. Keyed on MAC because that's the join key for
    the forwarding table. A MAC that resolves to several IPs keeps the last seen.
    """
    out: dict[str, str] = {}
    for oid, value in rows:
        index = _index_after(oid, ARP_BASE)
        if index is None:
            continue
        mac = canonical_mac(value)
        if mac is None:
            continue
        parts = index.split(".")
        if len(parts) < 5:
            continue
        out[mac] = ".".join(parts[-4:])
    return out


def parse_own_macs(rows: list[tuple[str, Optional[str]]]) -> set[str]:
    """ifPhysAddress rows -> the set of the device's own interface MACs.

    These are the polling device's own NIC/SVI/gateway MACs (canonical). They are
    subtracted from FDB/ARP discoveries so a router's own SVI gateway MACs (the
    ``.1``/``.254`` of every subnet) never become phantom "host" nodes.
    """
    macs: set[str] = set()
    for _oid, value in rows:
        mac = canonical_mac(value)
        if mac is not None:
            macs.add(mac)
    return macs


def parse_ifphys_ifindex(rows: list[tuple[str, Optional[str]]]) -> dict[str, str]:
    """ifPhysAddress rows -> ``{canonical_mac: ifIndex}``.

    The inverse of "a port's own MAC": maps each interface's ifPhysAddress back to
    its ifIndex, so an LLDP local-port id advertised as a MAC (Comware's
    macAddress subtype) can be resolved to a port name.
    """
    out: dict[str, str] = {}
    for oid, value in rows:
        index = _index_after(oid, IFPHYS_BASE)
        if index is None:
            continue
        mac = canonical_mac(value)
        if mac:
            out[mac] = index
    return out


def parse_oper_status(rows: list[tuple[str, Optional[str]]]) -> dict[str, str]:
    """ifOperStatus rows -> ``{ifIndex: "up"|"down"}``.

    ifOperStatus is an enum: 1 = up, 2 = down, and everything else (testing,
    dormant, lowerLayerDown, ...) is treated as "down" since the node only cares
    whether the port is actually forwarding. The value may render as the raw
    integer or, with a compiled MIB, as ``up(1)`` — both are handled.
    """
    out: dict[str, str] = {}
    for oid, value in rows:
        index = _index_after(oid, IFOPERSTATUS_BASE)
        if index is None or value is None:
            continue
        v = str(value).strip().lower()
        out[index] = "up" if v == "1" or v.startswith("up") else "down"
    return out


def build_port_status(
    operstatus_rows: list[tuple[str, Optional[str]]],
    ifname_rows: Optional[list[tuple[str, Optional[str]]]] = None,
    ifdescr_rows: Optional[list[tuple[str, Optional[str]]]] = None,
) -> dict[str, str]:
    """Assemble ifOperStatus + ifName into ``{port_name: "up"|"down"}``.

    Independent of LLDP: this is the real, configured port state for every
    interface, keyed on the human port name via the same ifName/ifDescr chain the
    FDB uses. Falls back to the raw ifIndex if a name can't be resolved.
    """
    ifnames = parse_ifnames(ifname_rows or [])
    if not ifnames and ifdescr_rows:
        ifnames = parse_ifnames(ifdescr_rows, base=IFDESCR_BASE)

    status: dict[str, str] = {}
    for ifindex, state in parse_oper_status(operstatus_rows).items():
        status[ifnames.get(ifindex, ifindex)] = state
    return status


def parse_vtp_vlans(rows: list[tuple[str, Optional[str]]]) -> list[int]:
    """Operational VLAN ids from Cisco vtpVlanState.

    Index is ``<managementDomain>.<vlanId>``; value is the state (1 ==
    operational). Returns the operational, non-reserved (<1002) VLAN ids sorted
    ascending — the set to walk the per-VLAN FDB for via the community context.
    """
    vlans: set[int] = set()
    for oid, value in rows:
        index = _index_after(oid, VTP_VLAN_STATE_BASE)
        if index is None or value != _VTP_OPERATIONAL:
            continue
        try:
            vlan = int(index.split(".")[-1])
        except ValueError:
            continue
        if 1 <= vlan < 1002:
            vlans.add(vlan)
    return sorted(vlans)


def assemble_dot1d_per_vlan(
    per_vlan: dict,
    ifname_rows: Optional[list[tuple[str, Optional[str]]]] = None,
    ifdescr_rows: Optional[list[tuple[str, Optional[str]]]] = None,
) -> list[dict]:
    """Assemble per-VLAN dot1d FDB walks into ``[{mac, port, vlan}, ...]``.

    ``per_vlan`` maps a VLAN id to ``{"fdb": dot1dTpFdbPort rows, "baseport":
    dot1dBasePortIfIndex rows}`` — both read in that VLAN's community context, so
    the bridge-port numbering is the VLAN's own. ``ifName`` is global. The VLAN
    id is the context it was read under, not decoded from the index.
    """
    ifnames = parse_ifnames(ifname_rows or [])
    if not ifnames and ifdescr_rows:
        ifnames = parse_ifnames(ifdescr_rows, base=IFDESCR_BASE)

    entries: list[dict] = []
    for vlan, tables in per_vlan.items():
        baseport = parse_baseport_ifindex(tables.get("baseport") or [])
        for mac, bridge_port in parse_dot1d_fdb(tables.get("fdb") or []):
            entries.append({
                "mac": mac,
                "port": resolve_port(bridge_port, baseport, ifnames),
                "vlan": vlan,
            })
    return entries


def parse_dot1q_fdb(rows: list[tuple[str, Optional[str]]]) -> list[tuple[int, str, str]]:
    """dot1qTpFdbPort rows -> ``[(vlan, mac_canonical, bridge_port), ...]``.

    Index is ``<fdbId/vlan>.<m1>.<m2>.<m3>.<m4>.<m5>.<m6>``; value is the bridge
    port. When the table was read via the per-VLAN community context the fdbId
    arc may be 0 — callers can pass the contextual VLAN through separately, but
    the in-index VLAN is returned here as-is.
    """
    out: list[tuple[int, str, str]] = []
    for oid, value in rows:
        index = _index_after(oid, DOT1Q_FDB_PORT_BASE)
        if index is None or value is None:
            continue
        parts = index.split(".")
        if len(parts) < 7:
            continue
        try:
            vlan = int(parts[0])
        except ValueError:
            continue
        mac = _mac_from_decimal_octets(parts[1:7])
        if mac is None:
            continue
        out.append((vlan, mac, value))
    return out


def parse_dot1d_fdb(rows: list[tuple[str, Optional[str]]]) -> list[tuple[str, str]]:
    """dot1dTpFdbPort rows -> ``[(mac_canonical, bridge_port), ...]`` (no VLAN)."""
    out: list[tuple[str, str]] = []
    for oid, value in rows:
        index = _index_after(oid, DOT1D_FDB_PORT_BASE)
        if index is None or value is None:
            continue
        parts = index.split(".")
        if len(parts) < 6:
            continue
        mac = _mac_from_decimal_octets(parts[:6])
        if mac is None:
            continue
        out.append((mac, value))
    return out


def resolve_port(
    bridge_port: str,
    baseport_ifindex: dict[str, str],
    ifnames: dict[str, str],
) -> str:
    """Translate a bridge port to a human port name, best-effort.

    bridge-port -> ifIndex -> ifName. If either hop is missing, fall back to the
    ifIndex, then to the raw bridge-port number — never lose the location.
    """
    ifindex = baseport_ifindex.get(bridge_port)
    if ifindex is None:
        return bridge_port
    return ifnames.get(ifindex, ifindex)


def build_fdb(
    *,
    dot1q_rows_by_vlan: Optional[dict[int, list[tuple[str, Optional[str]]]]] = None,
    dot1q_rows: Optional[list[tuple[str, Optional[str]]]] = None,
    dot1d_rows: Optional[list[tuple[str, Optional[str]]]] = None,
    baseport_rows: Optional[list[tuple[str, Optional[str]]]] = None,
    ifname_rows: Optional[list[tuple[str, Optional[str]]]] = None,
    ifdescr_rows: Optional[list[tuple[str, Optional[str]]]] = None,
) -> list[dict]:
    """Assemble FDB walk rows into ``[{mac, port, vlan}, ...]`` for one switch.

    Prefer the 802.1Q data (``dot1q_rows_by_vlan`` keyed by the VLAN the rows
    were read under, or a single ``dot1q_rows`` walk) and fall back to the flat
    802.1D ``dot1d_rows`` only when no 802.1Q rows are present — mirroring the
    crawler's "try dot1q first" probe. Ports are resolved to names via the
    bridge-port/ifIndex/ifName chain.
    """
    baseport_ifindex = parse_baseport_ifindex(baseport_rows or [])
    ifnames = parse_ifnames(ifname_rows or [])
    if not ifnames and ifdescr_rows:
        ifnames = parse_ifnames(ifdescr_rows, base=IFDESCR_BASE)

    entries: list[dict] = []

    has_dot1q = bool(dot1q_rows_by_vlan) or bool(dot1q_rows)
    if has_dot1q:
        if dot1q_rows_by_vlan:
            for ctx_vlan, rows in dot1q_rows_by_vlan.items():
                for in_vlan, mac, bridge_port in parse_dot1q_fdb(rows):
                    vlan = ctx_vlan if ctx_vlan else in_vlan
                    entries.append({
                        "mac": mac,
                        "port": resolve_port(bridge_port, baseport_ifindex, ifnames),
                        "vlan": vlan or None,
                    })
        if dot1q_rows:
            for vlan, mac, bridge_port in parse_dot1q_fdb(dot1q_rows):
                entries.append({
                    "mac": mac,
                    "port": resolve_port(bridge_port, baseport_ifindex, ifnames),
                    "vlan": vlan or None,
                })
    elif dot1d_rows:
        for mac, bridge_port in parse_dot1d_fdb(dot1d_rows):
            entries.append({
                "mac": mac,
                "port": resolve_port(bridge_port, baseport_ifindex, ifnames),
                "vlan": None,
            })

    return entries
