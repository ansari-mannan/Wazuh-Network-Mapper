"""Shared helpers used across discovery phases.

The MAC normalizer is critical: Phase 1 reads each device's own LLDP chassis
MAC, Phase 3 matches neighbor chassis IDs against those MACs, and the two only
line up if both sides are canonicalized identically.
"""

from __future__ import annotations

import re
from typing import Optional, Union

# Exactly six hex octets once all separators are stripped.
_HEX12 = re.compile(r"^[0-9a-f]{12}$")
_SEPARATORS = re.compile(r"[\s:.\-]")
_WHITESPACE = re.compile(r"\s+")


def normalize_mac(value: Union[bytes, bytearray, str, None]) -> Optional[str]:
    """Canonicalize any SNMP chassis/MAC value to ``aa:bb:cc:dd:ee:ff``.

    Handles the forms SNMP actually hands back:
      * raw 6-byte OctetString (``b'\\x00#\\xac\\xe5t\\x00'``)
      * Hex-STRING ``"00 23 AC E5 74 00"`` (net-snmp style)
      * pysnmp prettyPrint ``"0x0023ace57400"``
      * Cisco dotted ``"0023.ace5.7400"`` and colon/dash forms

    Returns the lowercase colon form, or None if the value isn't a 6-byte MAC
    (e.g. an LLDP chassis ID that's a name or network address rather than a
    MAC) — so the MAC fallback match never false-positives on a non-MAC.
    """
    if value is None:
        return None

    if isinstance(value, (bytes, bytearray)):
        if len(value) == 6:
            return ":".join(f"{b:02x}" for b in value)
        # Could be ASCII-encoded hex inside the octet string; fall through.
        try:
            value = value.decode("ascii")
        except (UnicodeDecodeError, AttributeError):
            return None

    s = str(value).strip().lower()
    if not s:
        return None
    if s.startswith("0x"):
        s = s[2:]

    cleaned = _SEPARATORS.sub("", s)
    if _HEX12.match(cleaned):
        return ":".join(cleaned[i : i + 2] for i in range(0, 12, 2))
    return None


def collapse_whitespace(value: Optional[str]) -> Optional[str]:
    """Collapse embedded newlines/runs of whitespace to single spaces.

    Cisco sysDescr strings span multiple lines; flatten them so stored values
    stay single-line.
    """
    if value is None:
        return None
    return _WHITESPACE.sub(" ", value).strip()
