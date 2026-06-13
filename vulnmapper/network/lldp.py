"""Pure LLDP-MIB parsing: raw walk rows -> neighbor records. No I/O, no SNMP.

Three tables feed a neighbor record, and all three are keyed by the same
``(localPortNum, remIndex)`` pair so they join cleanly:

  * lldpRemTable (``...4.1.1``)      — the neighbor's chassis id, ports, names.
  * lldpRemManAddrTable (``...4.2.1``) — the neighbor's management IP, which is
    what we actually need to be able to poll it next.
  * lldpLocPortTable (``...3.7.1``)  — maps our local port number to a readable
    local port id, so an edge's ``local_port`` is a name, not a bare integer.

Keeping this module pure (it only transforms lists of ``(oid, value)`` tuples)
makes the index-decoding logic trivially unit-testable without a live network.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Optional

from ..common.mac import canonical_mac
from .utils import collapse_whitespace, normalize_chassis_id, normalize_mac

log = logging.getLogger("discovery.lldp")

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
            log.warning(
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
