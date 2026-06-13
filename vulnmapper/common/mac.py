"""The single source of truth for MAC address handling.

Two worlds feed MACs into this pipeline and they must compare identically:

  * Endpoints (Wazuh syscollector) report MACs as ``e4:a7:a0:25:ce:ad``.
  * Switch forwarding tables (SNMP dot1q/dot1d) return raw hex strings such as
    ``"E4 A7 A0 25 CE AD"``, ``"0xe4a7a025cead"`` or a 6-byte OctetString.

If either side is compared without canonicalizing, every FDB match silently
fails. So all comparison happens on :func:`canonical_mac` (separator-stripped,
lowercase 12-hex) and all display uses :func:`format_mac` (the colon form).

``normalize_mac`` is kept as the network crawler's existing entry point (colon
form, or ``None`` when the value isn't a 6-byte MAC) so the LLDP/chassis code
that depends on that exact contract is unchanged.
"""

from __future__ import annotations

import re
from typing import Optional, Union

MacInput = Union[bytes, bytearray, str, None]

# Exactly six hex octets once all separators are stripped.
_HEX12 = re.compile(r"^[0-9a-f]{12}$")
_SEPARATORS = re.compile(r"[\s:.\-]")


def canonical_mac(value: MacInput) -> Optional[str]:
    """Canonicalize any MAC representation to bare lowercase 12-hex.

    This is the comparison key — ``e4:a7:a0:25:ce:ad``, ``E4-A7-A0-25-CE-AD``,
    ``0xe4a7a025cead``, ``e4a7.a025.cead`` and the raw 6-byte OctetString all
    collapse to ``"e4a7a025cead"``. Returns ``None`` when the value is not a
    6-byte MAC (e.g. an LLDP chassis id that is a name or network address), so a
    non-MAC never false-matches.
    """
    if value is None:
        return None

    if isinstance(value, (bytes, bytearray)):
        if len(value) == 6:
            return "".join(f"{b:02x}" for b in value)
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
    return cleaned if _HEX12.match(cleaned) else None


def format_mac(value: MacInput) -> Optional[str]:
    """Canonicalize to the lowercase colon form ``aa:bb:cc:dd:ee:ff``.

    The human/display form. Returns ``None`` for non-MAC values, same as
    :func:`canonical_mac`.
    """
    canonical = canonical_mac(value)
    if canonical is None:
        return None
    return ":".join(canonical[i : i + 2] for i in range(0, 12, 2))


# The network crawler historically imported ``normalize_mac`` expecting the
# colon form; keep that name pointed at the single implementation.
normalize_mac = format_mac
