"""Fetch and parse a device's system scalars into node identity fields.

This reads sysDescr / sysObjectID / sysName plus the device's own LLDP chassis
id in one PDU, derives the vendor from the sysObjectID enterprise number, and
delegates model/firmware/serial extraction to the matching vendor plug-in under
``vendors/``. The vendor identification code is reused as-is — this module only
orchestrates it.
"""

from __future__ import annotations

from typing import Optional

from .snmp_client import (
    OID_LLDP_LOC_CHASSIS_ID,
    OID_LLDP_LOC_SYS_CAP_ENABLED,
    OID_SYS_DESCR,
    OID_SYS_NAME,
    OID_SYS_OBJECT_ID,
)
from .parse import collapse_whitespace, normalize_chassis_id, normalize_mac
from .vendors import VENDOR_BY_ENTERPRISE

_ENTERPRISE_PREFIX = "1.3.6.1.4.1."


def enterprise_number(sys_object_id: Optional[str]) -> Optional[str]:
    """Pull the enterprise (vendor) arc out of a sysObjectID.

    "1.3.6.1.4.1.9.1.516" -> "9";  "1.3.6.1.4.1.12356.101.1.2005" -> "12356".
    """
    if not sys_object_id or not sys_object_id.startswith(_ENTERPRISE_PREFIX):
        return None
    remainder = sys_object_id[len(_ENTERPRISE_PREFIX):]
    return remainder.split(".")[0] or None


def vendor_from_descr(sys_descr: Optional[str]) -> Optional[str]:
    """Best-effort vendor guess from a free-text sysDescr.

    Used only for *unpollable* neighbors, where all we have is the sysDescr that
    LLDP carried — there is no sysObjectID to dispatch on.
    """
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
    """Poll a device's identity fields. Returns None if it does not answer.

    The caller is expected to have already resolved a working credential for
    ``ip`` (so ``snmp_client.get_many`` uses it). Returns a dict with
    ``hostname, vendor, model, firmware, serial, mac, chassis_id``.
    """
    base = await snmp_client.get_many(
        ip,
        [OID_SYS_DESCR, OID_SYS_OBJECT_ID, OID_SYS_NAME, OID_LLDP_LOC_CHASSIS_ID,
         OID_LLDP_LOC_SYS_CAP_ENABLED],
    )
    if base is None:
        return None

    sys_descr = collapse_whitespace(base.get(OID_SYS_DESCR))
    sys_object_id = base.get(OID_SYS_OBJECT_ID)
    hostname = base.get(OID_SYS_NAME)
    raw_chassis = base.get(OID_LLDP_LOC_CHASSIS_ID)
    cap_enabled = base.get(OID_LLDP_LOC_SYS_CAP_ENABLED)

    enterprise = enterprise_number(sys_object_id)
    vendor_entry = VENDOR_BY_ENTERPRISE.get(enterprise)
    if vendor_entry is not None:
        vendor_name, vendor_module = vendor_entry
        specifics = await vendor_module.identify(sys_descr, sys_object_id, snmp_client, ip)
    else:
        vendor_name = vendor_from_descr(sys_descr) or "unknown vendor"
        specifics = {"model": None, "firmware": None, "serial": None}

    return {
        "hostname": hostname,
        "vendor": vendor_name,
        "model": specifics.get("model"),
        "firmware": specifics.get("firmware"),
        "serial": specifics.get("serial"),
        "mac": normalize_mac(raw_chassis),
        "chassis_id": normalize_chassis_id(raw_chassis),
        "cap_enabled": cap_enabled,
    }
