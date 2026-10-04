"""Vendor identification plug-ins.

Each vendor exposes::

    async def identify(sys_descr, sys_object_id, snmp_client, ip) -> dict

returning the device-specific fields (model, firmware, serial), and is registered
by its enterprise number (the arc after ``1.3.6.1.4.1.``) in
:data:`VENDOR_BY_ENTERPRISE`.

Cisco and Fortinet are small enough to live here as module-level ``identify``
strategy functions; they are exposed under the ``cisco`` / ``fortinet`` names
(via a tiny namespace) so the registry stays ``(name, module-like)`` and existing
references are unchanged. Comware stays its own module (it carries a model table
and is independently imported as ``vulnmapper.network.vendors.comware``).
"""

from __future__ import annotations

import json
import os
import re
from functools import lru_cache
from types import SimpleNamespace
from typing import Optional

from . import comware

# ===========================================================================
# Cisco — sysDescr is rich and self-describing; model + IOS version parse out of
# it with regex (no extra SNMP round-trips). Typical sysDescr:
#   Cisco IOS Software, C2960S Software (C2960S-UNIVERSALK9-M), Version 12.2(55)SE5, ...
# ===========================================================================

# Model token: the platform word that precedes "Software", e.g. "C2960S".
_CISCO_MODEL_RE = re.compile(r"\b([A-Z0-9][A-Z0-9\-]+)\s+Software\b")
# Version string after the literal "Version", e.g. "12.2(55)SE5" or "15.0(2)".
_CISCO_VERSION_RE = re.compile(r"\bVersion\s+([0-9][0-9A-Za-z.()\-]*)")


def _cisco_parse_model(sys_descr: str) -> Optional[str]:
    # The first "<token> Software" is the platform; "Cisco IOS Software" comes
    # first in the string, so skip a leading "IOS" match.
    for match in _CISCO_MODEL_RE.finditer(sys_descr):
        token = match.group(1)
        if token.upper() == "IOS":
            continue
        return token
    return None


def _cisco_parse_version(sys_descr: str) -> Optional[str]:
    match = _CISCO_VERSION_RE.search(sys_descr)
    if match:
        # Strip a trailing comma/period the regex may have grabbed.
        return match.group(1).rstrip(",.")
    return None


async def _cisco_identify(sys_descr, sys_object_id, snmp_client, ip) -> dict:
    """Return Cisco-specific fields parsed from sysDescr.

    ``snmp_client`` and ``ip`` are accepted for interface symmetry with other
    vendors (Cisco needs no extra queries). Serial is left null here.
    """
    sys_descr = sys_descr or ""
    return {
        "model": _cisco_parse_model(sys_descr),
        "firmware": _cisco_parse_version(sys_descr),
        "serial": None,
    }


# ===========================================================================
# Fortinet (FortiGate) — sysDescr is EMPTY, so everything comes from SNMP:
#   model    -> last arc of sysObjectID, looked up in fortinet_models.json
#   firmware -> fgSysVersion (1.3.6.1.4.1.12356.101.4.1.1.0)
#   serial   -> fnSysSerial  (1.3.6.1.4.1.12356.100.1.1.1.0)
# ===========================================================================

OID_FG_SYS_VERSION = "1.3.6.1.4.1.12356.101.4.1.1.0"
OID_FN_SYS_SERIAL = "1.3.6.1.4.1.12356.100.1.1.1.0"

# fortinet_models.json lives at the network/ level (one dir above this package);
# dirname(dirname(__file__)) == network/ from here, as it did from the old
# vendors/fortinet.py, so the path constant is unchanged.
_FORTINET_MODELS_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "fortinet_models.json"
)

# Firmware looks like "v6.0.16,build0505,221215 (GA)" — grab the dotted version
# after the leading "v", before the first comma.
_FORTINET_FIRMWARE_RE = re.compile(r"v?(\d+\.\d+(?:\.\d+)?)")


@lru_cache(maxsize=1)
def _fortinet_models() -> dict:
    """Load (and cache) the number->model-name map from fortinet_models.json."""
    with open(_FORTINET_MODELS_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _fortinet_model_from_object_id(sys_object_id: Optional[str]) -> Optional[str]:
    if not sys_object_id:
        return None
    last_arc = sys_object_id.rstrip(".").split(".")[-1]
    return _fortinet_models().get(last_arc)


def _fortinet_parse_firmware(raw: Optional[str]) -> Optional[str]:
    if not raw:
        return None
    match = _FORTINET_FIRMWARE_RE.search(raw)
    return match.group(1) if match else None


async def _fortinet_identify(sys_descr, sys_object_id, snmp_client, ip) -> dict:
    """Return FortiGate-specific fields via extra SNMP GETs."""
    extra = await snmp_client.get_many(
        ip, [OID_FG_SYS_VERSION, OID_FN_SYS_SERIAL]
    )
    extra = extra or {}

    return {
        "model": _fortinet_model_from_object_id(sys_object_id),
        "firmware": _fortinet_parse_firmware(extra.get(OID_FG_SYS_VERSION)),
        "serial": extra.get(OID_FN_SYS_SERIAL),
    }


# Expose Cisco/Fortinet under the same ``<vendor>.identify`` shape as the comware
# module, so the registry below and its consumer (sysinfo) treat all three alike.
cisco = SimpleNamespace(identify=_cisco_identify)
fortinet = SimpleNamespace(identify=_fortinet_identify)

# Enterprise number (the arc after 1.3.6.1.4.1.) -> (vendor name, identifier).
# 25506 is the H3C/HP/3Com arc used by HP Comware switches (e.g. the HP 1920).
VENDOR_BY_ENTERPRISE = {
    "9": ("Cisco", cisco),
    "12356": ("Fortinet", fortinet),
    "25506": ("HP", comware),
}

__all__ = ["VENDOR_BY_ENTERPRISE", "cisco", "comware", "fortinet"]
