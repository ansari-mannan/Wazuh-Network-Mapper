"""Seed discovery: where to start the crawl when no subnet is given.

The scanner host is an endpoint, not network gear, so its own IP is not a
pollable device. We need a first *device*, in priority order:

  1. The default gateway from the host routing table — a router/L3 switch that
     almost certainly speaks SNMP and has a populated LLDP table. Primary seed.
  2. The host's own LLDP neighbor (the switch this machine is plugged into) via
     a local ``lldpctl``/``lldpcli``, if ``lldpd`` is running. Most direct hop.
  3. An explicit ``--seed <ip>`` override, handled by the caller.

All sources are merged; the crawl's chassis-ID dedup collapses overlaps. Every
helper here is best-effort and swallows its own errors — a missing tool or an
unparsable routing table yields no seed, never a crash.
"""

from __future__ import annotations

import ipaddress
import logging
import platform
import re
import shutil
import subprocess

log = logging.getLogger("discovery.seed")

_IPV4 = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")

# Adapter descriptions for virtual / non-physical NICs whose default gateway is
# a host-only/NAT stub (e.g. VMware VMnet8, Hyper-V Default Switch, VirtualBox
# Host-Only) — never the real network's router. Such gateways are skipped as
# seeds so the crawl doesn't waste a timeout on a dead virtual gateway.
_VIRTUAL_ADAPTER = re.compile(
    r"vmware|vmnet|virtualbox|vbox|host-only|hyper-v|vethernet|virtual ethernet|"
    r"loopback|bluetooth|npcap",
    re.IGNORECASE,
)


def _run(cmd: list[str], timeout: float = 5.0) -> str:
    """Run a command, returning stdout (empty string on any failure)."""
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
        return proc.stdout or ""
    except (OSError, subprocess.SubprocessError) as exc:
        log.debug("seed helper %s failed: %s", cmd[0], exc)
        return ""


def _windows_gateways() -> list[str]:
    """Windows default gateways, with virtual-adapter gateways filtered out.

    Uses ``Get-NetRoute`` joined to ``Get-NetAdapter`` so each gateway carries
    its adapter description; gateways belonging to a virtual adapter (see
    :data:`_VIRTUAL_ADAPTER`) are dropped. Falls back to parsing ``route print``
    (unfiltered) only if PowerShell is unavailable.
    """
    ps_cmd = (
        "Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | "
        "Sort-Object RouteMetric | ForEach-Object { "
        "$a = Get-NetAdapter -InterfaceIndex $_.ifIndex -ErrorAction SilentlyContinue; "
        "Write-Output ($_.NextHop + '|' + $a.InterfaceDescription) }"
    )
    out = _run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd]
    )

    gateways: list[str] = []
    if out.strip():
        for line in out.splitlines():
            parts = line.split("|", 1)
            gw = parts[0].strip()
            desc = parts[1].strip() if len(parts) > 1 else ""
            if not _is_routable_gateway(gw):
                continue
            if desc and _VIRTUAL_ADAPTER.search(desc):
                log.info("skipping virtual-adapter gateway %s (%s)", gw, desc)
                continue
            gateways.append(gw)
        return gateways

    # Fallback: `route print -4` default routes (0.0.0.0 mask 0.0.0.0, col 3 = gw).
    out = _run(["route", "print", "-4"])
    for line in out.splitlines():
        cols = line.split()
        if len(cols) >= 3 and cols[0] == "0.0.0.0" and cols[1] == "0.0.0.0":
            if _is_routable_gateway(cols[2]):
                gateways.append(cols[2])
    return gateways


def _is_routable_gateway(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_unspecified or addr.is_loopback or addr.is_multicast)


def default_gateways() -> list[str]:
    """Return default-gateway IPs parsed from the host routing table."""
    system = platform.system()
    gateways: list[str] = []

    if system == "Windows":
        gateways = _windows_gateways()
    else:
        # Linux: `ip route show default` -> "default via 192.168.1.1 dev eth0".
        out = _run(["ip", "-4", "route", "show", "default"])
        for line in out.splitlines():
            if "via" in line:
                match = _IPV4.search(line.split("via", 1)[1])
                if match and _is_routable_gateway(match.group(1)):
                    gateways.append(match.group(1))
        if not gateways:
            # macOS / BSD fallback: `netstat -rn` default line.
            out = _run(["netstat", "-rn"])
            for line in out.splitlines():
                cols = line.split()
                if cols and cols[0] in ("default", "0.0.0.0") and len(cols) >= 2:
                    match = _IPV4.search(cols[1])
                    if match and _is_routable_gateway(match.group(1)):
                        gateways.append(match.group(1))

    # De-dupe, preserve order.
    seen: dict[str, None] = {}
    for gw in gateways:
        seen.setdefault(gw, None)
    result = list(seen)
    if result:
        log.info("default gateway seed(s): %s", ", ".join(result))
    else:
        log.info("no default gateway found in routing table")
    return result


def local_lldp_neighbors() -> list[str]:
    """Return management IPs of this host's own LLDP neighbors, if lldpd is up.

    Parses ``lldpctl -f keyvalue`` lines like
    ``lldp.eth0.chassis.mgmt-ip=172.20.99.4``. Absent on hosts without lldpd
    (e.g. Windows), where it simply returns an empty list.
    """
    tool = shutil.which("lldpctl") or shutil.which("lldpcli")
    if not tool:
        return []
    if tool.endswith("lldpcli"):
        out = _run([tool, "-f", "keyvalue", "show", "neighbors"])
    else:
        out = _run([tool, "-f", "keyvalue"])

    ips: list[str] = []
    for line in out.splitlines():
        if "chassis.mgmt-ip=" in line:
            value = line.split("=", 1)[1].strip()
            match = _IPV4.search(value)
            if match and _is_routable_gateway(match.group(1)):
                ips.append(match.group(1))

    seen: dict[str, None] = {}
    for ip in ips:
        seen.setdefault(ip, None)
    result = list(seen)
    if result:
        log.info("local LLDP neighbor seed(s): %s", ", ".join(result))
    return result


def discover_seeds(explicit: list[str] | None = None) -> list[str]:
    """Merge all seed sources (explicit overrides first), de-duplicated."""
    seeds: list[str] = []

    def _add(ip: str) -> None:
        if ip and ip not in seeds:
            seeds.append(ip)

    for ip in explicit or []:
        _add(ip)
    for ip in default_gateways():
        _add(ip)
    for ip in local_lldp_neighbors():
        _add(ip)

    return seeds
