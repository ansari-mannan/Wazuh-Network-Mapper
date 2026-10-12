"""Cisco's CDP neighbour table (CISCO-CDP-MIB cdpCacheTable), read into the
same ``Neighbor`` records as LLDP.
"""

from __future__ import annotations

from typing import Optional

from .lldp import Neighbor
from .text import collapse_whitespace, index_after, octets

CDP_CACHE_BASE = "1.3.6.1.4.1.9.9.23.1.2.1.1"

# cdpCacheEntry column -> field. The index is ``<local ifIndex>.<deviceIndex>``.
_CDP_COLUMNS = {
    "3": "address_type",   # 1 = IPv4
    "4": "address",
    "5": "version",        # the neighbour's own sysDescr-like text
    "6": "device_id",      # its name
    "7": "device_port",    # its port facing us
    "8": "platform",       # e.g. "cisco WS-C2960-48TT-L"
    "9": "capabilities",   # 32-bit bitmap
}
_CDP_ADDRESS_IPV4 = "1"

# CDP capability bits.
CDP_CAP_ROUTER = 0x01
CDP_CAP_TRANS_BRIDGE = 0x02
CDP_CAP_SR_BRIDGE = 0x04
CDP_CAP_SWITCH = 0x08
CDP_CAP_HOST = 0x10
CDP_CAP_REPEATER = 0x40
CDP_CAP_PHONE = 0x80

# CDP bit -> LLDP capability bit (first octet, most significant bit first:
# repeater 0x40, bridge 0x20, router 0x08, telephone 0x04, station 0x01), so a
# CDP-only device gets a role from the same LLDP-based rules.
_CDP_TO_LLDP_BITS = (
    (CDP_CAP_ROUTER, 0x08),
    (CDP_CAP_TRANS_BRIDGE, 0x20),
    (CDP_CAP_SR_BRIDGE, 0x20),
    (CDP_CAP_SWITCH, 0x20),
    (CDP_CAP_HOST, 0x01),
    (CDP_CAP_REPEATER, 0x40),
    (CDP_CAP_PHONE, 0x04),
)


def _cdp_capability_bits(raw: Optional[str]) -> int:
    data = octets(raw)
    return int.from_bytes(data, "big") if data else 0


def translate_cdp_capabilities(raw: Optional[str]) -> Optional[str]:
    """A CDP capability bitmap as the LLDP-style bitmap the role rules read."""
    bits = _cdp_capability_bits(raw)
    lldp = 0
    for cdp_bit, lldp_bit in _CDP_TO_LLDP_BITS:
        if bits & cdp_bit:
            lldp |= lldp_bit
    return f"0x{lldp:02x}" if lldp else None


def cdp_is_infrastructure(raw: Optional[str]) -> bool:
    """Whether a CDP neighbour is network equipment (router or switch).

    Unlike LLDP, a CDP neighbour always advertises an address, and IP phones and
    access points speak CDP too, so the address is no sign of infrastructure;
    only the router / switch capability is. A bridge-only device (an access
    point) is therefore not an uplink, and the hosts behind it stay visible.
    """
    return bool(_cdp_capability_bits(raw) & (CDP_CAP_ROUTER | CDP_CAP_SWITCH))


def _cdp_address(address_type: Optional[str], address: Optional[str]) -> Optional[str]:
    if address_type not in (None, _CDP_ADDRESS_IPV4):
        return None
    data = octets(address)
    if len(data) != 4 or data == b"\0\0\0\0":
        return None
    return ".".join(str(b) for b in data)


def parse_cdp_cache(
    rows: list[tuple[str, Optional[str]]], ifname_by_index: dict[str, str]
) -> list[Neighbor]:
    """cdpCacheTable rows -> :class:`Neighbor` records (``protocol="cdp"``).

    The local port is the index's ifIndex resolved through ``ifname_by_index``
    (the raw ifIndex if unknown). ``chassis_id`` is None: CDP identifies a
    neighbour by name, so the crawler matches it by address or name.
    """
    cells: dict[tuple[str, str], dict[str, Optional[str]]] = {}
    for oid, value in rows:
        remainder = index_after(oid, CDP_CACHE_BASE)
        if remainder is None:
            continue
        parts = remainder.split(".")
        if len(parts) < 3:
            continue
        field = _CDP_COLUMNS.get(parts[0])
        if field is not None:
            cells.setdefault((parts[1], parts[2]), {})[field] = value

    neighbors: list[Neighbor] = []
    for (if_index, device_index), f in sorted(cells.items()):
        mgmt_ip = _cdp_address(f.get("address_type"), f.get("address"))
        name = (f.get("device_id") or "").strip() or None
        if name is None and mgmt_ip is None:
            continue
        neighbors.append(Neighbor(
            local_port_num=if_index,
            rem_index=device_index,
            chassis_id=None,
            chassis_mac=None,
            port_id=f.get("device_port") or None,
            port_descr=None,
            sys_name=name,
            sys_descr=collapse_whitespace(f.get("version")) or None,
            mgmt_ip=mgmt_ip,
            local_port=ifname_by_index.get(if_index, if_index),
            cap_enabled=translate_cdp_capabilities(f.get("capabilities")),
            protocol="cdp",
            platform=(f.get("platform") or "").strip() or None,
            cdp_capabilities=f.get("capabilities") or None,
        ))
    return neighbors
