"""Pure network-side parsing + thin SNMP collect wrappers (no pysnmp here).

Consolidates the former ``lldp`` / ``fdb`` / ``fdb_collect`` / ``utils`` modules:

  * String helpers — chassis-id canonicalisation, whitespace collapsing.
  * FDB parsing — switch MAC-forwarding tables (dot1q/dot1d) -> {mac, port, vlan},
    plus ARP / ifName / ifPhysAddress / port-status decoding.
  * LLDP parsing — raw walk rows -> :class:`Neighbor` records, and local-port
    label resolution (MAC / bare-integer -> interface name).
  * ``collect_*`` — the thin async wrappers that issue the SNMP walks (via the
    already-opened :class:`~vulnmapper.network.snmp.SnmpClient`) and hand the rows
    to the pure parsers above. The only network I/O in this module is delegated to
    that client; nothing here imports pysnmp.

Two loggers are kept with their original names so stderr output is unchanged:
``discovery.lldp`` and ``discovery.fdb``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
import re
from typing import Optional, Union

from ..schema import canonical_mac, format_mac

normalize_mac = format_mac  # single source of truth (colon form), historic name

_log_lldp = logging.getLogger("discovery.lldp")
_log_fdb = logging.getLogger("discovery.fdb")


# ===========================================================================
# String helpers (was network/utils.py)
# ===========================================================================

_WHITESPACE = re.compile(r"\s+")


def normalize_chassis_id(value: Union[bytes, bytearray, str, None]) -> Optional[str]:
    """Canonicalize an LLDP chassis ID into a stable, comparable key.

    LLDP chassis IDs are *usually* a MAC, so try :func:`normalize_mac` first and
    reuse its canonical colon form. When the chassis ID is not a MAC (a network
    address or interface/local name subtype), fall back to a lowercased,
    separator-light string so it is still a stable key, just not a MAC.
    """
    mac = normalize_mac(value)
    if mac is not None:
        return mac

    if isinstance(value, (bytes, bytearray)):
        try:
            value = value.decode("ascii", "replace")
        except AttributeError:
            return None

    if value is None:
        return None
    s = str(value).strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    s = _WHITESPACE.sub(" ", s).strip()
    return s or None


def collapse_whitespace(value: Optional[str]) -> Optional[str]:
    """Collapse embedded newlines/runs of whitespace to single spaces.

    Cisco sysDescr strings span multiple lines; flatten them so stored values
    stay single-line.
    """
    if value is None:
        return None
    return _WHITESPACE.sub(" ", value).strip()


# ===========================================================================
# FDB / IF-MIB parsing (was network/fdb.py)
# ===========================================================================

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


# ===========================================================================
# LLDP parsing + local-port resolution (was network/lldp.py)
# ===========================================================================

# A local-port id that is unusable as a human port name: a 12-hex MAC (the
# Comware macAddress subtype, optionally ``0x``-prefixed) or a bare integer.
_MAC_TOKEN_RE = re.compile(r"^(?:0x)?[0-9a-fA-F]{12}$")
_BARE_INT_RE = re.compile(r"^\d+$")

# Bases (no trailing dot).
LLDP_REM_BASE = "1.0.8802.1.1.2.1.4.1.1"
LLDP_REM_MAN_ADDR_BASE = "1.0.8802.1.1.2.1.4.2.1"
LLDP_LOC_PORT_BASE = "1.0.8802.1.1.2.1.3.7.1"

# lldpRemTable column number (first arc after the base) -> field name. Columns 11
# and 12 are the system-capabilities bitmaps (supported / enabled), which feed the
# device-role derivation in :mod:`vulnmapper.network.roles`.
_REM_COLUMNS = {
    "5": "chassis_id",
    "7": "port_id",
    "8": "port_descr",
    "9": "sys_name",
    "10": "sys_descr",
    "11": "cap_supported",
    "12": "cap_enabled",
}

# lldpLocPortTable: column 3 is lldpLocPortId.
_LOC_PORT_ID_COLUMN = "3"

# IANA address-family numbers used as the management-address subtype.
_AF_IPV4 = 1
_AF_IPV6 = 2


@dataclass
class Neighbor:
    """One parsed LLDP neighbor (a device directly cabled to the polled one)."""

    local_port_num: str
    rem_index: str
    chassis_id: Optional[str]            # normalized stable identity (join key)
    chassis_mac: Optional[str]           # normalized MAC iff the chassis id is one
    port_id: Optional[str]
    port_descr: Optional[str]
    sys_name: Optional[str]
    sys_descr: Optional[str]
    mgmt_ip: Optional[str]               # routable management IP, if advertised
    local_port: Optional[str]            # readable local port id, if known
    cap_enabled: Optional[str] = None    # raw lldpRemSysCapEnabled bitmap
    cap_supported: Optional[str] = None  # raw lldpRemSysCapSupported bitmap

    @property
    def remote_port(self) -> Optional[str]:
        """Best label for the neighbor's own port."""
        return self.port_id or self.port_descr


def _strip(oid: str, base: str) -> Optional[str]:
    """Return the index portion of ``oid`` below ``base``, or None if outside."""
    prefix = base.rstrip(".") + "."
    if not oid.startswith(prefix):
        return None
    return oid[len(prefix):]


def parse_loc_port_table(rows: list[tuple[str, Optional[str]]]) -> dict[str, str]:
    """Map ``localPortNum -> readable local port id`` from lldpLocPortTable."""
    out: dict[str, str] = {}
    for oid, value in rows:
        remainder = _strip(oid, LLDP_LOC_PORT_BASE)
        if remainder is None or value is None:
            continue
        parts = remainder.split(".")
        if parts[0] != _LOC_PORT_ID_COLUMN or len(parts) < 2:
            continue
        local_port_num = parts[1]
        out[local_port_num] = value
    return out


def parse_man_addr_table(
    rows: list[tuple[str, Optional[str]]]
) -> dict[tuple[str, str], str]:
    """Decode neighbor management IPs, keyed by ``(localPortNum, remIndex)``.

    The management address is encoded *in the OID index*, not the value. The
    lldpRemManAddrTable index is::

        <timeMark>.<localPortNum>.<remIndex>.<addrSubtype>.<addrLen>.<addr...>

    where ``addrSubtype`` is the IANA address family (1 = IPv4, 2 = IPv6),
    ``addrLen`` is the octet count, and the address bytes follow. We pull the
    IPv4 address out of those trailing bytes. IPv4 is preferred over IPv6 since
    it is what we actually route to in these labs.
    """
    out: dict[tuple[str, str], str] = {}
    for oid, _value in rows:
        remainder = _strip(oid, LLDP_REM_MAN_ADDR_BASE)
        if remainder is None:
            continue
        parts = remainder.split(".")
        # column + timeMark + localPort + remIndex + subtype + len = 6 minimum
        if len(parts) < 6:
            continue
        # parts[0] is the column number; the index starts at parts[1].
        _column, time_mark, local_port, rem_index, subtype, addr_len = parts[:6]
        addr_bytes = parts[6:]
        try:
            subtype_i = int(subtype)
            addr_len_i = int(addr_len)
        except ValueError:
            continue
        if len(addr_bytes) < addr_len_i:
            continue
        addr_bytes = addr_bytes[:addr_len_i]

        key = (local_port, rem_index)
        if subtype_i == _AF_IPV4 and addr_len_i == 4:
            ip = ".".join(addr_bytes)
            out[key] = ip  # IPv4 wins; overwrite any earlier IPv6 guess
        elif subtype_i == _AF_IPV6 and key not in out:
            # Keep a colon-joined hex form only as a last resort.
            out[key] = ":".join(f"{int(b):02x}" for b in addr_bytes)
    return out


def parse_rem_table(
    rows: list[tuple[str, Optional[str]]]
) -> dict[tuple[str, str], dict[str, Optional[str]]]:
    """Group lldpRemTable cells into ``{(localPortNum, remIndex): {field: val}}``.

    Each OID is ``<base>.<column>.<timeMark>.<localPortNum>.<remIndex>``. We key
    on ``(localPortNum, remIndex)`` — dropping the timeMark, which is volatile —
    so all the cells describing one neighbor land together.
    """
    groups: dict[tuple[str, str], dict[str, Optional[str]]] = {}
    for oid, value in rows:
        remainder = _strip(oid, LLDP_REM_BASE)
        if remainder is None:
            continue
        parts = remainder.split(".")
        if len(parts) < 4:
            continue
        column = parts[0]
        field = _REM_COLUMNS.get(column)
        if field is None:
            continue  # a column we don't care about
        # parts[1] = timeMark, parts[2] = localPortNum, parts[3] = remIndex
        key = (parts[2], parts[3])
        groups.setdefault(key, {})[field] = value
    return groups


def needs_port_resolution(value: Optional[str]) -> bool:
    """Whether a local-port label is a raw MAC / bare integer (not a port name)."""
    if not value:
        return False
    s = str(value)
    return bool(_MAC_TOKEN_RE.match(s) or _BARE_INT_RE.match(s))


# Internal alias kept for readability at the call sites in this module.
_is_unresolvable_port = needs_port_resolution


def normalize_local_port(
    value: Optional[str],
    local_port_num: Optional[str],
    ifname_by_index: dict[str, str],
    ifindex_by_mac: dict[str, str],
) -> tuple[Optional[str], bool]:
    """Resolve an LLDP local-port label to an interface name.

    Returns ``(resolved, ok)``. A label that already looks like an interface name
    (anything that isn't a bare MAC or integer) is returned unchanged — so Cisco /
    Fortinet, which advertise proper ``lldpLocPortId`` strings, are never touched.
    Only the unusable Comware forms are resolved, via the chain:

      1. ``lldpRemLocalPortNum`` -> ifIndex -> ifName (primary; on Comware the
         local-port number equals the ifIndex, sidestepping the bad advertised
         value). Only consulted for an already-unusable label, so the Comware
         invariant is the only place it is relied on.
      2. the advertised MAC (a port's own ifPhysAddress) -> ifIndex -> ifName.
      3. a bare integer treated directly as an ifIndex -> ifName.

    ``ok`` is False when nothing resolved; the caller keeps the raw token and logs.
    """
    s = "" if value is None else str(value)
    if not _is_unresolvable_port(s):
        return (value, True)  # already a usable name (or empty) — leave as-is

    # 1. lldpRemLocalPortNum -> ifIndex -> ifName
    if local_port_num is not None:
        name = ifname_by_index.get(str(local_port_num))
        if name:
            return (name, True)

    # 2. advertised MAC -> ifPhysAddress -> ifIndex -> ifName
    if _MAC_TOKEN_RE.match(s):
        idx = ifindex_by_mac.get(canonical_mac(s))
        if idx and ifname_by_index.get(idx):
            return (ifname_by_index[idx], True)

    # 3. bare integer is itself an ifIndex
    if _BARE_INT_RE.match(s):
        name = ifname_by_index.get(s)
        if name:
            return (name, True)

    return (value, False)


def normalize_neighbor_ports(
    neighbors: list["Neighbor"],
    ifname_by_index: dict[str, str],
    ifindex_by_mac: dict[str, str],
    *,
    node_label: str = "",
) -> list[Neighbor]:
    """Resolve every neighbor's ``local_port`` to an ifName in place.

    Returns the list unchanged (mutated). An unresolved token is kept as-is and a
    warning is logged naming the node and the reason — a raw MAC/integer is never
    silently emitted as a port.
    """
    for nb in neighbors:
        if not _is_unresolvable_port(nb.local_port):
            continue
        resolved, ok = normalize_local_port(
            nb.local_port, nb.local_port_num, ifname_by_index, ifindex_by_mac
        )
        if ok:
            nb.local_port = resolved
        else:
            _log_lldp.warning(
                "%s: could not resolve LLDP local port %r (localPortNum=%s) to an "
                "interface name; keeping raw token",
                node_label or "device", nb.local_port, nb.local_port_num,
            )
    return neighbors


def build_neighbors(
    rem_rows: list[tuple[str, Optional[str]]],
    man_addr_rows: list[tuple[str, Optional[str]]],
    loc_port_rows: list[tuple[str, Optional[str]]],
) -> list[Neighbor]:
    """Combine the three walks into a list of :class:`Neighbor` records."""
    cells = parse_rem_table(rem_rows)
    mgmt = parse_man_addr_table(man_addr_rows)
    loc_ports = parse_loc_port_table(loc_port_rows)

    neighbors: list[Neighbor] = []
    for (local_port_num, rem_index), fields in cells.items():
        raw_chassis = fields.get("chassis_id")
        neighbors.append(
            Neighbor(
                local_port_num=local_port_num,
                rem_index=rem_index,
                chassis_id=normalize_chassis_id(raw_chassis),
                chassis_mac=normalize_mac(raw_chassis),
                port_id=fields.get("port_id") or None,
                port_descr=fields.get("port_descr") or None,
                sys_name=fields.get("sys_name") or None,
                sys_descr=collapse_whitespace(fields.get("sys_descr")) or None,
                mgmt_ip=mgmt.get((local_port_num, rem_index)),
                local_port=loc_ports.get(local_port_num, local_port_num),
                cap_enabled=fields.get("cap_enabled") or None,
                cap_supported=fields.get("cap_supported") or None,
            )
        )
    return neighbors


# ===========================================================================
# SNMP collect wrappers (was network/fdb_collect.py)
# ===========================================================================

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
