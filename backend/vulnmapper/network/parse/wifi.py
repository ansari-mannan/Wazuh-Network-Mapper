"""Wireless access points (CISCO-DOT11-ASSOCIATION-MIB): whether a device is
one, and the clients associated with it.
"""

from __future__ import annotations

import re
from typing import Optional

from ...schema import format_mac
from .text import index_after, mac_from_decimal_octets, octets

# cDot11ActiveWirelessClients, one row per radio: present on an access point
# even with no client associated, absent on anything else.
DOT11_ACTIVE_CLIENTS_BASE = "1.3.6.1.4.1.9.9.273.1.1.2.1.1"

# Name evidence, used only when the device itself gives none: a Cisco AP
# platform ("cisco AIR-AP1142N-A-K9", "AIR-LAP..."), "Aironet", "access point",
# or an autonomous / lightweight AP image name (C1140-K9W7-M, ...-K9W8-M).
_ACCESS_POINT_RE = re.compile(
    r"\bAIR-[A-Z]*AP\d|\baironet\b|\baccess[ -]point\b|-K9W[78]-", re.IGNORECASE)


def looks_like_access_point(sys_descr: Optional[str], platform: Optional[str]) -> bool:
    """Whether a system description or CDP platform names an access point."""
    return any(text and _ACCESS_POINT_RE.search(text) for text in (sys_descr, platform))


# cDot11ClientConfigInfoEntry: one row per associated client, indexed by
# ``<radio ifIndex>.<SSID length>.<SSID octets>.<client MAC, 6 octets>``.
DOT11_CLIENT_BASE = "1.3.6.1.4.1.9.9.273.1.2.1.1"
DOT11_CLIENT_PARENT_COL = "2"     # cDot11ClientParentAddress: every client has one
DOT11_CLIENT_IP_COL = "16"        # cDot11ClientIpAddress (when the AP knows it)
DOT11_CLIENT_VLAN_COL = "17"      # cDot11ClientVlanId


def _dot11_client_key(index: str) -> Optional[tuple[str, str, str]]:
    """``(radio ifIndex, ssid, canonical mac)`` from a client-table index."""
    parts = index.split(".")
    try:
        ssid_len = int(parts[1])
        ssid = bytes(int(b) for b in parts[2:2 + ssid_len]).decode("utf-8", "replace")
    except (IndexError, ValueError):
        return None
    mac = mac_from_decimal_octets(parts[2 + ssid_len:])
    return (parts[0], ssid, mac) if mac else None


def parse_wifi_clients(
    rows: list[tuple[str, Optional[str]]], ifname_by_index: dict[str, str]
) -> list[dict]:
    """Client-table rows -> ``[{mac, ip, ssid, radio, vlan}, ...]``.

    ``rows`` hold at least the parent-address column (the client list) and,
    where the access point provides them, the IP and VLAN columns. ``radio`` is
    the radio's interface name (the raw ifIndex if unknown).
    """
    clients: dict[tuple, dict] = {}
    for oid, value in rows:
        remainder = index_after(oid, DOT11_CLIENT_BASE)
        if remainder is None:
            continue
        column, _, index = remainder.partition(".")
        key = _dot11_client_key(index)
        if key is None:
            continue
        if_index, ssid, mac = key
        client = clients.setdefault(key, {
            "mac": format_mac(mac), "ip": None, "ssid": ssid or None,
            "radio": ifname_by_index.get(if_index, if_index), "vlan": None})
        if column == DOT11_CLIENT_IP_COL:
            data = octets(value)
            if len(data) == 4 and any(data):
                client["ip"] = ".".join(str(b) for b in data)
        elif column == DOT11_CLIENT_VLAN_COL:
            try:
                client["vlan"] = int(value) or None
            except (TypeError, ValueError):
                pass
    return list(clients.values())
