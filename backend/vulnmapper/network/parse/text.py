"""Helpers every table parser here shares: chassis ids, whitespace and the
pieces of an OID index.
"""

from __future__ import annotations

import re
from typing import Optional, Union

from ...schema import format_mac

normalize_mac = format_mac  # the colon form; the older name is kept for its callers

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


def index_after(oid: str, base: str) -> Optional[str]:
    """The arcs of ``oid`` below ``base`` (the table index), or None if outside it."""
    prefix = base.rstrip(".") + "."
    if not oid.startswith(prefix):
        return None
    return oid[len(prefix):]


def mac_from_decimal_octets(octets: list[str]) -> Optional[str]:
    """Six dotted-decimal OID arcs as a canonical 12-hex MAC."""
    if len(octets) != 6:
        return None
    try:
        return "".join(f"{int(o):02x}" for o in octets)
    except ValueError:
        return None


def octets(value: Optional[str]) -> bytes:
    """Raw bytes of a rendered OctetString: ``0x<hex>``, or printable text."""
    if not value:
        return b""
    s = str(value)
    if s[:2].lower() == "0x":
        try:
            return bytes.fromhex(s[2:])
        except ValueError:
            return b""
    return s.encode("latin-1", "ignore")
