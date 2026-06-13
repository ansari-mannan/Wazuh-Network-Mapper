"""Network-side string helpers (chassis-id canonicalization, whitespace).

MAC canonicalization itself lives in :mod:`vulnmapper.schema` — the single
source of truth shared with the endpoint linker. ``normalize_mac`` is re-exported
from there so this module's historic callers (lldp/sysinfo) are unchanged, and
``normalize_chassis_id`` is built on top of it so a device's own
``lldpLocChassisId`` and a neighbor's reported chassis id line up exactly.
"""

from __future__ import annotations

import re
from typing import Optional, Union

from ..schema import format_mac as normalize_mac  # single source of truth

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
