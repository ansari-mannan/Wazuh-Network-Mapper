"""Cisco device identification.

Cisco's sysDescr is rich and self-describing, so model and IOS version are
parsed straight out of it with regex — no extra SNMP round-trips needed.

Typical sysDescr::

    Cisco IOS Software, C2960S Software (C2960S-UNIVERSALK9-M), Version 12.2(55)SE5, ...
"""

from __future__ import annotations

import re
from typing import Optional

# Model token: the platform word that precedes "Software", e.g. "C2960S".
# Cisco model tokens are alphanumeric (letters, digits, dashes).
_MODEL_RE = re.compile(r"\b([A-Z0-9][A-Z0-9\-]+)\s+Software\b")

# Version string after the literal "Version", e.g. "12.2(55)SE5" or "15.0(2)".
_VERSION_RE = re.compile(r"\bVersion\s+([0-9][0-9A-Za-z.()\-]*)")


def _parse_model(sys_descr: str) -> Optional[str]:
    # The first "<token> Software" is the platform; "Cisco IOS Software" comes
    # first in the string, so skip a leading "IOS" match.
    for match in _MODEL_RE.finditer(sys_descr):
        token = match.group(1)
        if token.upper() == "IOS":
            continue
        return token
    return None


def _parse_version(sys_descr: str) -> Optional[str]:
    match = _VERSION_RE.search(sys_descr)
    if match:
        # Strip a trailing comma/period the regex may have grabbed.
        return match.group(1).rstrip(",.")
    return None


async def identify(
    sys_descr: Optional[str],
    sys_object_id: Optional[str],
    snmp_client,
    ip: str,
) -> dict:
    """Return Cisco-specific fields parsed from sysDescr.

    ``snmp_client`` and ``ip`` are accepted for interface symmetry with other
    vendors (Cisco needs no extra queries). Serial is left null here.
    """
    sys_descr = sys_descr or ""
    return {
        "model": _parse_model(sys_descr),
        "firmware": _parse_version(sys_descr),
        "serial": None,
    }
