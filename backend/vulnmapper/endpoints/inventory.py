"""What an agent is, from the Manager API's agent record and syscollector
inventory: its node fields, the MAC of its real network card, and the Wazuh
server's own address. No I/O.
"""

from __future__ import annotations

import ipaddress

from ..schema import canonical_mac, format_mac

_JUNK_SERIALS = {"", "unknown", "0", "To be filled by O.E.M.", "Not Specified"}

# Case-insensitive substrings that mark a virtual / software / non-physical
# adapter. Matched against the interface name and description.
_VIRTUAL_IFACE_NEEDLES = (
    "loopback", "npcap", "vmware", "virtualbox", "vbox", "hyper-v", "vethernet",
    "veth", "docker", "wsl", "tap", "tun", "bluetooth", "vpn", "npf",
)

# Interface-name prefixes of container / VM bridges, never the server's address.
_BRIDGE_IFACE_PREFIXES = (
    "docker", "br-", "veth", "virbr", "cni", "flannel", "cali", "podman",
    "lxcbr", "lxdbr", "kube", "weave", "vxlan",
)


def is_locally_administered(mac) -> bool:
    """True if a MAC has the locally-administered bit set (``first_octet & 0x02``).

    Burned-in NIC MACs are globally administered (that bit clear). Virtual,
    loopback and most VM/Hyper-V adapters set it — e.g. the Npcap loopback
    ``02:00:4c:4f:4f:50`` ("\\x02" + "LOOP"). A value that isn't a parseable MAC
    is treated as locally administered so it can never be selected.
    """
    canonical = canonical_mac(mac)
    if canonical is None:
        return True
    return bool(int(canonical[:2], 16) & 0x02)


def is_physical_iface(name, mac) -> bool:
    """True if an interface looks like a real physical NIC.

    Rejects anything with a locally-administered (or unparseable) MAC, and
    anything whose name/description matches the virtual-adapter blocklist.
    """
    if is_locally_administered(mac):
        return False
    text = (name or "").lower()
    return not any(needle in text for needle in _VIRTUAL_IFACE_NEEDLES)


def _ipv4_by_iface(netaddr) -> dict:
    """Join the netaddr endpoint to interfaces by name: ``iface -> [ipv4, ...]``.

    /syscollector/{id}/netiface has no IPv4 — it lives in /netaddr, keyed by the
    interface name. APIPA (169.254.x.x) addresses are dropped here so they can't
    qualify an interface in :func:`select_mac`.
    """
    out: dict[str, list] = {}
    for addr in netaddr or []:
        if (addr.get("proto") or "").lower() != "ipv4":
            continue
        ip = addr.get("address")
        if not ip or ip.startswith("169.254."):
            continue
        out.setdefault(addr.get("iface"), []).append(ip)
    return out


def _usable_ipv4(ip) -> bool:
    try:
        addr = ipaddress.IPv4Address(ip)
    except (ipaddress.AddressValueError, ValueError):
        return False
    return not (addr.is_loopback or addr.is_link_local or addr.is_unspecified)


def server_ipv4(netaddr, netproto):
    """The Wazuh server's real IPv4 from its syscollector inventory, or None.

    Prefers an address on the interface that has a default gateway (netproto);
    otherwise the first IPv4 that is not loopback, link-local or on a container
    bridge.
    """
    ipv4s = [(a.get("iface") or "", a.get("address")) for a in netaddr or []
             if (a.get("proto") or "").lower() == "ipv4" and _usable_ipv4(a.get("address"))]
    ipv4s = [(iface, ip) for iface, ip in ipv4s
             if not iface.lower().startswith(_BRIDGE_IFACE_PREFIXES)]
    gateway_ifaces = [p.get("iface") for p in netproto or []
                      if (p.get("type") or "").lower() == "ipv4"
                      and _usable_ipv4((p.get("gateway") or "").strip())]
    for gw_iface in gateway_ifaces:
        for iface, ip in ipv4s:
            if iface == gw_iface:
                return ip
    return ipv4s[0][1] if ipv4s else None


def select_mac(netiface, netaddr, agent_ip):
    """Select the real physical NIC's MAC for an agent (or None).

    1. Drop virtual/software/loopback interfaces (:func:`is_physical_iface`).
    2. Drop interfaces with no MAC or no non-APIPA IPv4 (joined via /netaddr).
    3. Prefer the interface whose IPv4 equals the agent's known IP; tie-break on
       state == "up"; else the first survivor.
    Returns the canonicalized colon-form MAC, or None if nothing survives.
    """
    ipv4_by_iface = _ipv4_by_iface(netaddr)

    survivors = []  # (mac, ipv4s, is_up)
    for iface in netiface or []:
        raw_mac = iface.get("mac")
        mac = format_mac(raw_mac)
        if not mac or not is_physical_iface(iface.get("name"), raw_mac):
            continue
        ipv4s = ipv4_by_iface.get(iface.get("name"), [])
        if not ipv4s:
            continue
        survivors.append((mac, ipv4s, (iface.get("state") or "").lower() == "up"))

    if not survivors:
        return None
    if agent_ip:
        for mac, ipv4s, _up in survivors:
            if agent_ip in ipv4s:
                return mac
    for mac, _ipv4s, up in survivors:
        if up:
            return mac
    return survivors[0][0]


def _serial(hardware):
    if not hardware:
        return None
    s = hardware[0].get("board_serial")
    return None if (not s or s in _JUNK_SERIALS) else s


def normalize_agent(agent, netiface, hardware, netaddr=None):
    """Map a raw Wazuh agent + syscollector data into the shared node schema."""
    os_info = agent.get("os", {}) or {}
    return {
        "agent_id":         agent.get("id"),       # hard join key + node_id source
        "ip":               agent.get("ip"),
        "hostname":         agent.get("name"),
        "vendor":           os_info.get("platform"),
        "model":            os_info.get("name"),
        "firmware":         os_info.get("version"),
        "serial":           _serial(hardware),
        "mac":              select_mac(netiface, netaddr, agent.get("ip")),
        "discovery_method": "wazuh",
        "status":           agent.get("status"),
    }
