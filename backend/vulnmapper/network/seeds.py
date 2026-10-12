"""Where a crawl starts: the operator's ``--seed`` addresses, then this host's
default gateways, then its own LLDP neighbours (when lldpd runs here).
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

# Virtual adapters (VMware VMnet8, Hyper-V Default Switch, VirtualBox
# host-only, ...) have a NAT or host-only stub as their gateway, never the real
# router, so their gateways are not used as seeds.
_VIRTUAL_ADAPTER = re.compile(
    r"vmware|vmnet|virtualbox|vbox|host-only|hyper-v|vethernet|virtual ethernet|"
    r"loopback|bluetooth|npcap",
    re.IGNORECASE,
)


def _run(cmd: list[str], timeout: float = 5.0) -> str:
    """A command's stdout, or "" if it fails in any way."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return proc.stdout or ""
    except (OSError, subprocess.SubprocessError) as exc:
        log.debug("seed helper %s failed: %s", cmd[0], exc)
        return ""


def _is_routable_gateway(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_unspecified or addr.is_loopback or addr.is_multicast)


def _windows_gateways() -> list[str]:
    """Default gateways from Get-NetRoute, each with its adapter's description
    so virtual adapters can be dropped; ``route print`` (unfiltered) only when
    PowerShell is missing."""
    ps_cmd = (
        "Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | "
        "Sort-Object RouteMetric | ForEach-Object { "
        "$a = Get-NetAdapter -InterfaceIndex $_.ifIndex -ErrorAction SilentlyContinue; "
        "Write-Output ($_.NextHop + '|' + $a.InterfaceDescription) }"
    )
    out = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd])

    gateways: list[str] = []
    if out.strip():
        for line in out.splitlines():
            gw, _, desc = (part.strip() for part in line.partition("|"))
            if not _is_routable_gateway(gw):
                continue
            if desc and _VIRTUAL_ADAPTER.search(desc):
                log.info("skipping virtual-adapter gateway %s (%s)", gw, desc)
                continue
            gateways.append(gw)
        return gateways

    # `route print -4`: a default route is "0.0.0.0 0.0.0.0 <gateway> ..."
    for line in _run(["route", "print", "-4"]).splitlines():
        cols = line.split()
        if len(cols) >= 3 and cols[0] == "0.0.0.0" and cols[1] == "0.0.0.0" \
                and _is_routable_gateway(cols[2]):
            gateways.append(cols[2])
    return gateways


def _unix_gateways() -> list[str]:
    """Linux ``ip route show default``, else the macOS/BSD ``netstat -rn`` line."""
    gateways = []
    for line in _run(["ip", "-4", "route", "show", "default"]).splitlines():
        if "via" in line:          # "default via 192.168.1.1 dev eth0"
            match = _IPV4.search(line.split("via", 1)[1])
            if match and _is_routable_gateway(match.group(1)):
                gateways.append(match.group(1))
    if gateways:
        return gateways
    for line in _run(["netstat", "-rn"]).splitlines():
        cols = line.split()
        if cols and cols[0] in ("default", "0.0.0.0") and len(cols) >= 2:
            match = _IPV4.search(cols[1])
            if match and _is_routable_gateway(match.group(1)):
                gateways.append(match.group(1))
    return gateways


def default_gateways() -> list[str]:
    gateways = _windows_gateways() if platform.system() == "Windows" else _unix_gateways()
    result = list(dict.fromkeys(gateways))
    if result:
        log.info("default gateway seed(s): %s", ", ".join(result))
    else:
        log.info("no default gateway found in routing table")
    return result


def local_lldp_neighbors() -> list[str]:
    """Management addresses of this host's own LLDP neighbours, read from
    ``lldpctl -f keyvalue`` lines such as ``lldp.eth0.chassis.mgmt-ip=172.20.99.4``.
    Empty where lldpd is not installed (Windows, most desktops)."""
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
            match = _IPV4.search(line.split("=", 1)[1].strip())
            if match and _is_routable_gateway(match.group(1)):
                ips.append(match.group(1))
    result = list(dict.fromkeys(ips))
    if result:
        log.info("local LLDP neighbor seed(s): %s", ", ".join(result))
    return result


def discover_seeds(explicit: list[str] | None = None) -> list[str]:
    seeds = [ip for ip in explicit or [] if ip]
    seeds += default_gateways() + local_lldp_neighbors()
    return list(dict.fromkeys(seeds))
