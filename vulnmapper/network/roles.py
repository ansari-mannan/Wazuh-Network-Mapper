"""Derive a device *role* (what a node IS) from LLDP capabilities + fallbacks.

This is pure (no I/O, no SNMP) so the bitmap decode and the fallback ladder are
trivially unit-testable. It is read from two places:

  * :mod:`vulnmapper.network.crawler` — to decide whether an LLDP neighbor is
    *infrastructure* (a switch/router) versus an *end host/station*, which is the
    neighbor-port -> uplink-port split.
  * :mod:`vulnmapper.assemble.merge` — to stamp a ``role`` on every node.

``role`` is deliberately distinct from ``kind`` (which records *which track*
found the node: endpoint=Wazuh, device=SNMP/LLDP, host=FDB). ``role`` answers a
different question — *what is this thing?* — independent of how it was found.

PRIMARY SOURCE — the LLDP system-capabilities bitmap (lldpRemSysCapEnabled /
lldpRemSysCapSupported). It is a BITS field; per the LLDP-MIB the bits are, in
1-based order:

    1 Other  2 Repeater  3 Bridge  4 WLAN-AP  5 Router  6 Telephone  7 DOCSIS
    8 Station

A BITS value is encoded most-significant-bit-first, so capability *i* (1-based)
is bit ``(i-1)`` counting from the MSB of the first octet — i.e. a Router+Bridge
device (an L3 switch) advertises ``0x28`` (bits 3 and 5).
"""

from __future__ import annotations

from typing import Optional

# Capability index (1-based, per the LLDP-MIB BITS definition) -> name.
_CAP_NAMES = {
    1: "other",
    2: "repeater",
    3: "bridge",
    4: "wlan-ap",
    5: "router",
    6: "telephone",
    7: "docsis",
    8: "station",
}

# Capabilities that mark a neighbor as infrastructure (a thing other devices
# transit through), as opposed to an end host that terminates a single port.
_INFRA_CAPS = {"bridge", "router", "wlan-ap"}


def _to_bytes(raw) -> bytes:
    """Best-effort decode of a pysnmp-rendered OctetString bitmap to raw bytes.

    Handles the common renderings: a ``0x2800`` hex string, bare/space/colon
    separated hex, or an actual ``bytes`` value. Anything that isn't clean even-
    length hex yields no bytes (caps simply unknown — never a false positive).
    """
    if raw is None:
        return b""
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw)
    s = str(raw).strip()
    if s[:2].lower() == "0x":
        s = s[2:]
    s = s.replace(" ", "").replace(":", "")
    if s and len(s) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in s):
        try:
            return bytes.fromhex(s)
        except ValueError:
            return b""
    return b""


def decode_capabilities(raw) -> set[str]:
    """Decode an LLDP capabilities bitmap into the set of capability names."""
    data = _to_bytes(raw)
    if not data:
        return set()
    out: set[str] = set()
    for index, name in _CAP_NAMES.items():
        byte_index, bit_in_byte = divmod(index - 1, 8)
        if byte_index < len(data) and data[byte_index] & (0x80 >> bit_in_byte):
            out.add(name)
    return out


def role_from_capabilities(caps: set[str]) -> Optional[str]:
    """Map a decoded capability set to a role string, or None if undecidable."""
    if "router" in caps and "bridge" in caps:
        return "l3-switch"
    if "bridge" in caps:
        return "l2-switch"
    if "router" in caps:
        return "router"
    if "wlan-ap" in caps:
        return "access-point"
    if "telephone" in caps:
        return "phone"
    if "station" in caps:
        return "station"
    return None


# Label for a polled device we cannot positively classify. We deliberately do
# NOT guess a type from the vendor (e.g. "Fortinet must be a firewall") — that is
# an inference, not evidence. If a device doesn't tell us what it is via LLDP, we
# say so honestly.
UNKNOWN_DEVICE = "Unknown Network Device"


def _fallback_role(kind: Optional[str]) -> str:
    """Role when no usable LLDP capabilities were advertised.

    End hosts don't advertise caps, so the Wazuh/FDB tracks default to ``host``;
    a polled device that advertised nothing usable is an honest
    ``Unknown Network Device`` rather than a vendor-based guess.
    """
    if kind == "endpoint":
        return "host"
    return UNKNOWN_DEVICE


def derive_role(
    *,
    capabilities=None,
    vendor: Optional[str] = None,
    model: Optional[str] = None,
    mac: Optional[str] = None,
    kind: Optional[str] = None,
) -> str:
    """Resolve a node's role from its LLDP capability bitmap, else a fallback.

    No vendor/model guessing: the role is taken from what the device actually
    advertised over LLDP. A device that advertised nothing decodable falls back to
    ``host`` (endpoint tracks) or ``Unknown Network Device`` (polled devices).
    The ``vendor`` / ``model`` / ``mac`` args are accepted for call-site
    stability but no longer influence the result.
    """
    role = role_from_capabilities(decode_capabilities(capabilities))
    if role is not None:
        return role
    return _fallback_role(kind)


def neighbor_is_infrastructure(mgmt_ip: Optional[str], capabilities=None) -> bool:
    """Whether an LLDP neighbor is infrastructure (uplink) vs an end host.

    A neighbor that has a management IP is pollable infrastructure (the existing
    signal). Beyond that, a neighbor that *advertises* a bridge/router/AP
    capability is infrastructure even if it never offered a management address
    (e.g. an access switch still being configured). A bare station/phone/other
    is an end host, so its port is an access port, not an uplink.
    """
    if mgmt_ip:
        return True
    return bool(decode_capabilities(capabilities) & _INFRA_CAPS)
