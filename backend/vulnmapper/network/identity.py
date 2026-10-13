"""Who a polled device is (name, vendor, model, firmware, serial, MAC), read
for each device the crawl reaches. The sysObjectID's enterprise number picks
the vendor module; the standard inventory table (entity.py) fills the rest.
"""

from __future__ import annotations

import logging
from collections import Counter
from typing import Optional

from ..devicecves.families import detect_family
from ..schema import canonical_mac, format_mac
from . import entity
from .parse import collapse_whitespace, normalize_chassis_id, normalize_mac
from .snmp import (
    OID_LLDP_LOC_CHASSIS_ID,
    OID_LLDP_LOC_SYS_CAP_ENABLED,
    OID_SYS_DESCR,
    OID_SYS_NAME,
    OID_SYS_OBJECT_ID,
)
from .vendors import VENDOR_BY_ENTERPRISE

log = logging.getLogger("discovery.crawler")

_ENTERPRISE_PREFIX = "1.3.6.1.4.1."


def enterprise_number(sys_object_id: Optional[str]) -> Optional[str]:
    """"1.3.6.1.4.1.9.1.516" -> "9"; "1.3.6.1.4.1.12356.101.1.2005" -> "12356"."""
    if not sys_object_id or not sys_object_id.startswith(_ENTERPRISE_PREFIX):
        return None
    return sys_object_id[len(_ENTERPRISE_PREFIX):].split(".")[0] or None


def base_mac(own_macs) -> Optional[str]:
    """A device's base MAC from its own interface MACs, for when LLDP gives none.

    All-zero, broadcast, multicast and locally administered MACs are skipped.
    VLAN and sub-interfaces repeat the bridge MAC, so the MAC most interfaces
    share wins, and a tie goes to the lowest. The same interfaces always give
    the same answer, which keeps the node id stable across scans.
    """
    counts = Counter()
    for raw in own_macs or []:
        mac = canonical_mac(raw)
        if mac is None or mac in ("000000000000", "ffffffffffff"):
            continue
        if int(mac[:2], 16) & 0x03:          # multicast or locally administered
            continue
        counts[mac] += 1
    if not counts:
        return None
    return format_mac(min(counts, key=lambda m: (-counts[m], m)))


def vendor_from_descr(sys_descr: Optional[str]) -> Optional[str]:
    """A vendor guessed from free text: for a neighbour that was never polled,
    the system description it advertised is all there is."""
    if not sys_descr:
        return None
    lowered = sys_descr.lower()
    for needle, name in (("cisco", "Cisco"), ("fortigate", "Fortinet"),
                         ("fortinet", "Fortinet"), ("juniper", "Juniper"),
                         ("arista", "Arista"), ("mikrotik", "MikroTik")):
        if needle in lowered:
            return name
    return None


async def fetch(snmp_client, ip: str) -> Optional[dict]:
    """The identity of a device whose credential is already resolved, or None
    if it does not answer the system group."""
    base = await snmp_client.get_many(
        ip,
        [OID_SYS_DESCR, OID_SYS_OBJECT_ID, OID_SYS_NAME, OID_LLDP_LOC_CHASSIS_ID,
         OID_LLDP_LOC_SYS_CAP_ENABLED],
    )
    if base is None:
        return None

    sys_descr = collapse_whitespace(base.get(OID_SYS_DESCR))
    sys_object_id = base.get(OID_SYS_OBJECT_ID)
    raw_chassis = base.get(OID_LLDP_LOC_CHASSIS_ID)

    vendor_entry = VENDOR_BY_ENTERPRISE.get(enterprise_number(sys_object_id))
    if vendor_entry is not None:
        vendor_name, vendor_module = vendor_entry
        specifics = await vendor_module.identify(sys_descr, sys_object_id, snmp_client, ip)
    else:
        vendor_name = vendor_from_descr(sys_descr) or "unknown vendor"
        specifics = {"model": None, "firmware": None, "serial": None}
    try:
        inventory = await entity.collect_inventory(snmp_client, ip)
    except Exception:              # an unsupported table must not cost the device
        log.exception("inventory table read failed for %s", ip)
        inventory = {}
    specifics = entity.merge(specifics, inventory)

    return {
        "hostname": base.get(OID_SYS_NAME),
        "vendor": vendor_name,
        "model": specifics.get("model"),
        "firmware": specifics.get("firmware"),
        "serial": specifics.get("serial"),
        "mac": normalize_mac(raw_chassis),
        "chassis_id": normalize_chassis_id(raw_chassis),
        "cap_enabled": base.get(OID_LLDP_LOC_SYS_CAP_ENABLED),
        "sys_descr": sys_descr,
        "software_family": detect_family(vendor_name, sys_descr, sys_object_id),
    }
