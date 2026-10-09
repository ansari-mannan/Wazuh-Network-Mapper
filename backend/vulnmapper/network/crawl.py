"""The network crawl subsystem: seed discovery, the BFS worker pool, per-device
identity, the output document builder, the dataclasses, and the CLI.

Consolidates the former ``models`` / ``config`` / ``seed`` / ``sysinfo`` /
``output`` / ``crawler`` / ``runner`` / ``cli`` modules. The only network I/O
goes through :class:`~vulnmapper.network.snmp.SnmpClient` (the sole pysnmp
importer) and the local seed-discovery subprocesses.

Public surface used by the pipeline and the ``python -m vulnmapper.network`` CLI:
  * :func:`crawl_document` — run a crawl, return the topology document.
  * :func:`parse_config` — argv -> :class:`Config`.
  * :func:`emit` / :func:`write` — stdout / file JSON output.

Three loggers keep their original names so stderr output is unchanged:
``discovery.seed`` / ``discovery.crawler`` / ``discovery`` (runner).
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import logging
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from ..schema import canonical_mac, format_mac
from .roles import neighbor_is_infrastructure
from .snmp import (
    OID_LLDP_LOC_CHASSIS_ID,
    OID_LLDP_LOC_SYS_CAP_ENABLED,
    OID_SYS_DESCR,
    OID_SYS_NAME,
    OID_SYS_OBJECT_ID,
    SnmpClient,
)
from .parse import (
    CDP_CACHE_BASE,
    DOT11_ACTIVE_CLIENTS_BASE,
    LLDP_LOC_PORT_BASE,
    LLDP_REM_BASE,
    LLDP_REM_MAN_ADDR_BASE,
    Neighbor,
    build_neighbors,
    cdp_is_infrastructure,
    collapse_whitespace,
    collect_arp,
    collect_fdb,
    collect_ifindex_by_mac,
    collect_ifname_map,
    collect_own_macs,
    collect_port_status,
    collect_wifi_clients,
    needs_port_resolution as _needs_port_resolution,
    normalize_chassis_id,
    normalize_mac,
    looks_like_access_point,
    normalize_neighbor_ports,
    parse_cdp_cache,
)
from ..devicecves.families import detect_family
from . import entity
from .vendors import VENDOR_BY_ENTERPRISE

_log_seed = logging.getLogger("discovery.seed")
_log_crawler = logging.getLogger("discovery.crawler")
_log_runner = logging.getLogger("discovery")



# =========================================================================
# Dataclasses: Credential / Device / Link (was models.py)
# =========================================================================

# discovery_method value stamped on every node this tool emits: a seed or a
# device first reached through an LLDP neighbour entry...
DISCOVERY_METHOD = "snmp_lldp"
# ...or one first reached through a CDP neighbour entry (polled or not).
DISCOVERY_METHOD_CDP = "snmp_cdp"

# Node status values.
STATUS_ONLINE = "online"            # polled successfully over SNMP
STATUS_UNREACHABLE = "unreachable"  # an IP we tried but no credential worked
STATUS_DISCOVERED = "discovered"    # known only from a neighbor table (not polled)


@dataclass
class Credential:
    """One operator-supplied SNMP credential to *try* against a device.

    Credentials are never discovered or brute-forced — this only ever holds
    what the operator passed on the CLI or via the environment. ``index`` is a
    stable, secret-free label used in stderr logs so community strings and auth
    keys are never written to the logs.
    """

    version: str  # "v2c" or "v3"
    index: int = 0
    # v2c
    community: Optional[str] = None
    # v3
    user: Optional[str] = None
    auth_protocol: Optional[str] = None
    auth_key: Optional[str] = None
    priv_protocol: Optional[str] = None
    priv_key: Optional[str] = None

    @property
    def label(self) -> str:
        """Secret-free identifier for logs."""
        if self.version == "v3":
            return f"v3#{self.index}(user={self.user})"
        return f"v2c#{self.index}"


@dataclass
class Device:
    """A discovered node — a switch or router, never an endpoint.

    Keyed on :attr:`chassis_id`. A device may be fully polled (``pollable`` and
    ``status == 'online'``) or merely seen in a neighbor's LLDP table without a
    usable management address / working credential (``pollable == False``).
    """

    chassis_id: str
    ip: Optional[str] = None
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    model: Optional[str] = None
    firmware: Optional[str] = None
    serial: Optional[str] = None
    mac: Optional[str] = None
    discovery_method: str = DISCOVERY_METHOD
    status: str = STATUS_DISCOVERED
    pollable: bool = False
    # Forwarding-table rows ``[{mac, port, vlan}, ...]`` learned from this switch.
    fdb: list = field(default_factory=list)
    # Three distinct port concepts (do NOT conflate — see network/crawler.py):
    #   neighbor_ports : every local port that has ANY LLDP neighbor (display).
    #   uplink_ports   : the infrastructure-facing subset of neighbor_ports (a
    #                    neighbor that is itself a switch/router/pollable device,
    #                    NOT an end host). This is what Tier-2 FDB parenting
    #                    subtracts, so it must exclude access ports to hosts.
    #   port_status    : port_name -> "up"/"down" from a real ifOperStatus walk,
    #                    independent of LLDP.
    neighbor_ports: list = field(default_factory=list)
    uplink_ports: list = field(default_factory=list)
    port_status: dict = field(default_factory=dict)
    # Raw LLDP system-capabilities bitmap advertised for this device (collected
    # from neighbors' remote tables); decoded into ``role`` at assembly.
    lldp_cap_enabled: Optional[str] = None
    # IP<->MAC from this device's ARP table ({canonical_mac: ip}) and the device's
    # own interface MACs (ifPhysAddress) — both feed the FDB/ARP host-discovery
    # track (ARP supplies IPs; own_macs filter out the device's SVI/gateway MACs).
    arp: dict = field(default_factory=dict)
    own_macs: list = field(default_factory=list)
    # The platform string a neighbour's CDP table reported for this device.
    platform: Optional[str] = None
    # A wireless access point (it answers the association MIB, or failing that
    # its platform / system description names one).
    access_point: bool = False
    # Its associated clients ``[{mac, ip, ssid, radio, vlan}]``; None when the
    # device has no association table to read them from.
    wifi_clients: Optional[list] = None
    # The software family decided when it was identified ("cisco_ios", ...;
    # vulnmapper.devicecves.families); None when not known.
    software_family: Optional[str] = None
    # What the configuration checks read (vulnmapper.checklist.tables), only
    # when the checklist stage is on. Evaluated by the pipeline; it never
    # reaches the graph.
    config_data: Optional[dict] = None

    def to_node(self) -> dict:
        """Render to the output node schema (field order is intentional).

        Fields that only CDP / wireless discovery fill are emitted only when
        set, so a network without them produces exactly the old document.
        """
        node = {
            "ip": self.ip,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "model": self.model,
            "firmware": self.firmware,
            "serial": self.serial,
            "mac": self.mac,
            "chassis_id": self.chassis_id,
            "discovery_method": self.discovery_method,
            "status": self.status,
            "pollable": self.pollable,
            "neighbor_ports": sorted(self.neighbor_ports),
            "uplink_ports": sorted(self.uplink_ports),
            "port_status": self.port_status,
            "lldp_cap_enabled": self.lldp_cap_enabled,
            "fdb": self.fdb,
            "arp": self.arp,
            "own_macs": self.own_macs,
        }
        if self.platform is not None:
            node["platform"] = self.platform
        if self.access_point:
            node["access_point"] = True
        if self.wifi_clients is not None:
            node["wifi_clients"] = self.wifi_clients
        if self.software_family is not None:
            node["software_family"] = self.software_family
        if self.config_data is not None:
            node["config_data"] = self.config_data
        return node


@dataclass(frozen=True)
class Link:
    """A directed adjacency learned from one device's LLDP neighbor table.

    ``source`` walked its table and reported ``target`` as a neighbor seen on
    ``local_port``; ``remote_port`` is the neighbor's own port. The reverse
    direction (target reporting source) is collapsed into a single edge at
    output time.
    """

    source_chassis_id: str
    target_chassis_id: str
    local_port: Optional[str] = None
    remote_port: Optional[str] = None
    protocol: str = "lldp"          # which neighbour table reported it


# =========================================================================
# Run configuration + credential loading (was config.py)
# =========================================================================

# ---- Defaults (override via CLI flags) ------------------------------------

# Worker coroutines pulling from the crawl queue. This is the real bound on
# in-flight work: at most this many devices are being polled at once, so the
# heavy state (SNMP requests, MIB decoding) is capped regardless of network
# size. 32 polls real infrastructure comfortably without overrunning the OS
# UDP receive buffer.
DEFAULT_CONCURRENCY = 32

# Per-request timeout (seconds). Kept tight so an unreachable device frees its
# worker in ~one timeout instead of being held for many seconds.
DEFAULT_TIMEOUT = 1.0

# SNMP retries per request. SNMP is UDP, so 1 retry absorbs a single dropped
# packet without turning every probe into a multi-second stall.
DEFAULT_RETRIES = 1

# Safety cap on total nodes. A misconfigured or hostile environment cannot push
# the crawl past this many devices.
DEFAULT_MAX_NODES = 5000

DEFAULT_PORT = 161

# Environment variable names. Communities are loaded from the environment to
# match how the project's other collectors take credentials from the env rather
# than only from the command line.
ENV_COMMUNITIES = "SNMP_COMMUNITIES"   # comma/space separated list
ENV_COMMUNITY = "SNMP_COMMUNITY"       # single string
ENV_V3_USER = "SNMP_V3_USER"
ENV_V3_AUTH_PROTO = "SNMP_V3_AUTH_PROTO"
ENV_V3_AUTH_KEY = "SNMP_V3_AUTH_KEY"
ENV_V3_PRIV_PROTO = "SNMP_V3_PRIV_PROTO"
ENV_V3_PRIV_KEY = "SNMP_V3_PRIV_KEY"


@dataclass
class Config:
    """Resolved run configuration handed to the crawler."""

    credentials: list[Credential]
    seeds: list[str]
    concurrency: int = DEFAULT_CONCURRENCY
    timeout: float = DEFAULT_TIMEOUT
    retries: int = DEFAULT_RETRIES
    max_nodes: int = DEFAULT_MAX_NODES
    port: int = DEFAULT_PORT
    pollable_only: bool = False
    output_path: Optional[str] = None
    # Read the configuration-check tables while polling (vulnmapper.checklist),
    # and, only if the owner chose it, try the factory community names.
    checklist: bool = False
    check_default_communities: bool = False

    @property
    def queue_maxsize(self) -> int:
        """Backpressure bound for the crawl queue.

        The queue only ever holds lightweight ``(ip, chassis_id)`` next-hop
        tuples, and dedup on chassis ID plus the ``max_nodes`` cap bound how
        many can ever exist. Sizing it to ``max_nodes`` keeps the queue from
        being a second, conflicting limit (and avoids a producer/consumer
        deadlock, since the workers that fill the queue also drain it) while the
        real in-flight memory bound stays the worker pool.
        """
        return self.max_nodes


def _split(raw: Optional[str]) -> list[str]:
    """Split a comma/whitespace separated credential list, dropping blanks."""
    if not raw:
        return []
    # Allow either "a,b,c" or "a b c"; shlex handles quoted strings too.
    return [tok for chunk in raw.split(",") for tok in shlex.split(chunk) if tok]


def load_credentials(cli_communities: Optional[list[str]]) -> list[Credential]:
    """Assemble the credential trial set from CLI flags and the environment.

    Order: CLI ``--community`` values first (operator's explicit intent), then
    any from ``$SNMP_COMMUNITIES`` / ``$SNMP_COMMUNITY``, then a single v3
    credential if the ``$SNMP_V3_*`` variables are set. Duplicates collapse.
    """
    seen: set[tuple] = set()
    creds: list[Credential] = []

    def _add_community(community: str) -> None:
        key = ("v2c", community)
        if community and key not in seen:
            seen.add(key)
            creds.append(Credential(version="v2c", index=len(creds) + 1, community=community))

    for community in cli_communities or []:
        _add_community(community)
    for community in _split(os.environ.get(ENV_COMMUNITIES)):
        _add_community(community)
    for community in _split(os.environ.get(ENV_COMMUNITY)):
        _add_community(community)

    v3_user = os.environ.get(ENV_V3_USER)
    if v3_user:
        creds.append(
            Credential(
                version="v3",
                index=len(creds) + 1,
                user=v3_user,
                auth_protocol=os.environ.get(ENV_V3_AUTH_PROTO),
                auth_key=os.environ.get(ENV_V3_AUTH_KEY),
                priv_protocol=os.environ.get(ENV_V3_PRIV_PROTO),
                priv_key=os.environ.get(ENV_V3_PRIV_KEY),
            )
        )

    return creds


def add_v3_credential(
    creds: list[Credential],
    *,
    user: str,
    auth_protocol: Optional[str],
    auth_key: Optional[str],
    priv_protocol: Optional[str],
    priv_key: Optional[str],
) -> None:
    """Append a v3 credential supplied via CLI flags."""
    creds.append(
        Credential(
            version="v3",
            index=len(creds) + 1,
            user=user,
            auth_protocol=auth_protocol,
            auth_key=auth_key,
            priv_protocol=priv_protocol,
            priv_key=priv_key,
        )
    )


# =========================================================================
# Seed discovery (was seed.py)
# =========================================================================

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
        _log_seed.debug("seed helper %s failed: %s", cmd[0], exc)
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
                _log_seed.info("skipping virtual-adapter gateway %s (%s)", gw, desc)
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
        _log_seed.info("default gateway seed(s): %s", ", ".join(result))
    else:
        _log_seed.info("no default gateway found in routing table")
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
        _log_seed.info("local LLDP neighbor seed(s): %s", ", ".join(result))
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


# =========================================================================
# Per-device identity / vendor dispatch (was sysinfo.py)
# =========================================================================

_ENTERPRISE_PREFIX = "1.3.6.1.4.1."


def enterprise_number(sys_object_id: Optional[str]) -> Optional[str]:
    """Pull the enterprise (vendor) arc out of a sysObjectID.

    "1.3.6.1.4.1.9.1.516" -> "9";  "1.3.6.1.4.1.12356.101.1.2005" -> "12356".
    """
    if not sys_object_id or not sys_object_id.startswith(_ENTERPRISE_PREFIX):
        return None
    remainder = sys_object_id[len(_ENTERPRISE_PREFIX):]
    return remainder.split(".")[0] or None


def base_mac(own_macs) -> Optional[str]:
    """A device's base MAC from its own interface MACs (ifPhysAddress).

    Used when LLDP gives the device no MAC. All-zero, broadcast, multicast
    and locally administered MACs are skipped; of the rest, the MAC the most
    interfaces share wins (VLAN and sub-interfaces repeat the bridge MAC), and
    a tie goes to the numerically lowest. The same interfaces always give the
    same answer, so the node id stays stable across scans. Colon form, or None.
    """
    counts = Counter()
    for raw in own_macs or []:
        mac = canonical_mac(raw)
        if mac is None or mac in ("000000000000", "ffffffffffff"):
            continue
        if int(mac[:2], 16) & 0x03:          # multicast or locally administered
            continue
        counts[mac] += 1
    if not counts:
        return None
    best = min(counts, key=lambda m: (-counts[m], m))
    return format_mac(best)


def vendor_from_descr(sys_descr: Optional[str]) -> Optional[str]:
    """Best-effort vendor guess from a free-text sysDescr.

    Used only for *unpollable* neighbors, where all we have is the sysDescr that
    LLDP carried — there is no sysObjectID to dispatch on.
    """
    if not sys_descr:
        return None
    lowered = sys_descr.lower()
    for needle, name in (("cisco", "Cisco"), ("fortigate", "Fortinet"),
                         ("fortinet", "Fortinet"), ("juniper", "Juniper"),
                         ("arista", "Arista"), ("mikrotik", "MikroTik")):
        if needle in lowered:
            return name
    return None


async def fetch(snmp_client, ip: str) -> Optional[dict]:
    """Poll a device's identity fields. Returns None if it does not answer.

    The caller is expected to have already resolved a working credential for
    ``ip`` (so ``snmp_client.get_many`` uses it). Returns a dict with
    ``hostname, vendor, model, firmware, serial, mac, chassis_id``. Model and
    serial are completed from the standard inventory table
    (:mod:`vulnmapper.network.entity`) where the vendor code leaves them open.
    """
    base = await snmp_client.get_many(
        ip,
        [OID_SYS_DESCR, OID_SYS_OBJECT_ID, OID_SYS_NAME, OID_LLDP_LOC_CHASSIS_ID,
         OID_LLDP_LOC_SYS_CAP_ENABLED],
    )
    if base is None:
        return None

    sys_descr = collapse_whitespace(base.get(OID_SYS_DESCR))
    sys_object_id = base.get(OID_SYS_OBJECT_ID)
    hostname = base.get(OID_SYS_NAME)
    raw_chassis = base.get(OID_LLDP_LOC_CHASSIS_ID)
    cap_enabled = base.get(OID_LLDP_LOC_SYS_CAP_ENABLED)

    enterprise = enterprise_number(sys_object_id)
    vendor_entry = VENDOR_BY_ENTERPRISE.get(enterprise)
    if vendor_entry is not None:
        vendor_name, vendor_module = vendor_entry
        specifics = await vendor_module.identify(sys_descr, sys_object_id, snmp_client, ip)
    else:
        vendor_name = vendor_from_descr(sys_descr) or "unknown vendor"
        specifics = {"model": None, "firmware": None, "serial": None}
    try:
        inventory = await entity.collect_inventory(snmp_client, ip)
    except Exception:              # an unsupported table must not cost the device
        _log_crawler.exception("inventory table read failed for %s", ip)
        inventory = {}
    specifics = entity.merge(specifics, inventory)

    return {
        "hostname": hostname,
        "vendor": vendor_name,
        "model": specifics.get("model"),
        "firmware": specifics.get("firmware"),
        "serial": specifics.get("serial"),
        "mac": normalize_mac(raw_chassis),
        "chassis_id": normalize_chassis_id(raw_chassis),
        "cap_enabled": cap_enabled,
        "sys_descr": sys_descr,
        "software_family": detect_family(vendor_name, sys_descr, sys_object_id),
    }


# =========================================================================
# Output document builder (was output.py)
# =========================================================================

def _dedupe_edges(links: list[Link]) -> list[dict]:
    """Collapse the two directions of each physical link into one edge.

    The same cable is reported from both ends (A lists B as a neighbor and B
    lists A). Keying on the *unordered* chassis-id pair merges them; we keep the
    best port label seen for each endpoint from either direction.
    """
    merged: dict[tuple[str, str], dict] = {}
    protocols: dict[tuple[str, str], set] = {}
    for link in links:
        a, b = link.source_chassis_id, link.target_chassis_id
        # Canonical orientation: source = the smaller chassis id.
        if a <= b:
            key = (a, b)
            local, remote = link.local_port, link.remote_port
        else:
            key = (b, a)
            local, remote = link.remote_port, link.local_port

        protocols.setdefault(key, set()).add(link.protocol)
        edge = merged.get(key)
        if edge is None:
            merged[key] = {
                "source_chassis_id": key[0],
                "target_chassis_id": key[1],
                "local_port": local,
                "remote_port": remote,
            }
        else:
            # Fill any port label still missing from the reverse direction.
            edge["local_port"] = edge["local_port"] or local
            edge["remote_port"] = edge["remote_port"] or remote

    # Only a link no LLDP table reported says which protocol found it.
    for key, edge in merged.items():
        if "lldp" not in protocols[key]:
            edge["protocol"] = sorted(protocols[key])[0]
    return list(merged.values())


def build_document(
    devices: list[Device], links: list[Link], *, pollable_only: bool = False
) -> dict:
    """Build the output document (nodes + deduplicated edges).

    When ``pollable_only`` is set, every node that could not be polled
    (no working credential or no usable management address) is dropped, along
    with any edge that touches one — leaving only the actual SNMP-polled
    infrastructure backbone.
    """
    if pollable_only:
        devices = [d for d in devices if d.pollable]
        keep = {d.chassis_id for d in devices}
        links = [
            link
            for link in links
            if link.source_chassis_id in keep and link.target_chassis_id in keep
        ]

    return {
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "discovery_method": "snmp_lldp",
        "nodes": [d.to_node() for d in devices],
        "edges": _dedupe_edges(links),
    }


def emit(document: dict) -> None:
    """Write the document as JSON to stdout — and nothing else goes there."""
    json.dump(document, sys.stdout, indent=2)
    sys.stdout.write("\n")
    sys.stdout.flush()


def write(document: dict, path: str) -> None:
    """Write the document as UTF-8 JSON to ``path`` (no BOM, LF-terminated).

    Used when the tool writes the result file itself instead of relying on a
    shell redirect — which on PowerShell would otherwise produce UTF-16+BOM that
    a downstream JSON parser can choke on.
    """
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(document, fh, indent=2)
        fh.write("\n")


# =========================================================================
# The BFS crawl worker pool (was crawler.py)
# =========================================================================

# Sentinel pushed once per worker to signal shutdown after the queue drains.
_STOP = object()


class Crawler:
    """Owns the shared crawl state and the worker pool."""

    def __init__(self, client: SnmpClient, *, concurrency: int, max_nodes: int,
                 queue_maxsize: int, checklist: bool = False,
                 check_default_communities: bool = False) -> None:
        self._client = client
        self._checklist = checklist
        self._probe_defaults = check_default_communities
        self._concurrency = concurrency
        self._max_nodes = max_nodes
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=queue_maxsize)
        self._lock = asyncio.Lock()

        # Shared result + bookkeeping state, all guarded by ``self._lock``.
        self._devices: dict[str, Device] = {}     # chassis_id -> Device
        self._links: list[Link] = []
        self._seen: set[str] = set()              # chassis ids reserved/finalized
        self._enqueued_ips: set[str] = set()      # ips already queued (seed dedup)
        self._reserved = 0                        # count toward the max-nodes cap
        # chassis_id -> raw LLDP capability bitmap, aggregated from whatever a
        # device's neighbors advertised about it (a device's own role).
        self._caps: dict[str, str] = {}
        # CDP names a neighbour instead of giving its chassis id, so CDP links
        # are kept aside and resolved once every device has been polled: by the
        # address it was polled at, else by its name.
        self._cid_by_ip: dict[str, str] = {}
        self._cid_by_name: dict[str, str] = {}
        self._cdp_links: list[tuple[str, Neighbor]] = []
        # Platform strings CDP neighbours reported, by the address they gave.
        self._platform_by_ip: dict[str, str] = {}

    # ---- enqueue helpers (must hold the lock) -----------------------------

    def _cap_reached(self) -> bool:
        return self._reserved >= self._max_nodes

    async def _enqueue(self, ip: str, chassis_id: Optional[str], via: str = "lldp") -> bool:
        """Reserve and queue a next-hop. Returns False if skipped (dup/cap).

        ``via`` is the neighbour table that first named the address ("lldp",
        also used for seeds, or "cdp"); it becomes the device's discovery label.
        """
        if ip in self._enqueued_ips:
            return False
        if chassis_id is not None and chassis_id in self._seen:
            return False
        if self._cap_reached():
            _log_crawler.warning("max-nodes cap (%d) reached; not enqueuing %s",
                        self._max_nodes, ip)
            return False
        self._enqueued_ips.add(ip)
        if chassis_id is not None:
            self._seen.add(chassis_id)
        self._reserved += 1
        # Queue is sized to max_nodes, so this never blocks before the cap.
        self._queue.put_nowait((ip, chassis_id, via))
        return True

    async def seed(self, ips: list[str]) -> int:
        """Enqueue the initial seed IPs. Returns how many were queued."""
        queued = 0
        async with self._lock:
            for ip in ips:
                if await self._enqueue(ip, None):
                    queued += 1
        return queued

    # ---- the crawl --------------------------------------------------------

    async def run(self) -> tuple[list[Device], list[Link]]:
        workers = [
            asyncio.create_task(self._worker(i))
            for i in range(self._concurrency)
        ]
        # Wait for the queue to fully drain, then tell each worker to stop.
        await self._queue.join()
        for _ in workers:
            self._queue.put_nowait(_STOP)
        await asyncio.gather(*workers, return_exceptions=True)

        async with self._lock:
            self._resolve_cdp_links()
            # Stamp each device with the capability bitmap its neighbors reported
            # for it (a device's own advertised role), filled in now that every
            # device node exists regardless of crawl order.
            for cid, caps in self._caps.items():
                dev = self._devices.get(cid)
                if dev is not None and not dev.lldp_cap_enabled:
                    dev.lldp_cap_enabled = caps
            return list(self._devices.values()), list(self._links)

    async def _worker(self, worker_id: int) -> None:
        while True:
            item = await self._queue.get()
            if item is _STOP:
                self._queue.task_done()
                return
            ip, expected_cid, via = item
            try:
                await self._process(ip, expected_cid, via)
            except Exception:  # never let one device kill a worker
                _log_crawler.exception("error processing %s", ip)
            finally:
                self._queue.task_done()

    async def _process(self, ip: str, expected_cid: Optional[str], via: str = "lldp") -> None:
        """Poll one device, record it, and enqueue its pollable neighbors."""
        cred = await self._client.resolve_credential(ip)
        if cred is None:
            await self._record_unpollable_ip(ip, expected_cid)
            return

        info = await fetch(self._client, ip)
        if info is None:
            # Answered the credential probe but not the full GET — treat as
            # unpollable rather than stalling.
            await self._record_unpollable_ip(ip, expected_cid)
            return

        # The device's own interface MACs: a base MAC when LLDP gives none, and
        # the filter that keeps its SVI/gateway MACs from becoming hosts.
        try:
            own_macs = await collect_own_macs(self._client, ip)
        except Exception:
            _log_crawler.exception("interface MAC read failed for %s", ip)
            own_macs = []
        if not info.get("mac"):
            info["mac"] = base_mac(own_macs)
        # An address names the device only when no MAC can be read at all.
        chassis_id = info["chassis_id"] or expected_cid or info["mac"] or f"ip:{ip}"
        info["discovery_method"] = DISCOVERY_METHOD_CDP if via == "cdp" else DISCOVERY_METHOD
        if not await self._record_polled_device(ip, chassis_id, info):
            # The same device, reached at another of its addresses (a CDP
            # neighbour advertises the address facing it): polled already.
            _log_crawler.info("%s is %s, already polled", ip, chassis_id)
            return

        neighbors = await self._walk_neighbors(ip)
        cdp = [nb for nb in await self._walk_cdp(ip) if not _same_neighbor(nb, neighbors)]
        _log_crawler.info("%s (%s): %d LLDP neighbor(s), %d more over CDP",
                 info.get("hostname") or ip, chassis_id, len(neighbors), len(cdp))

        # neighbor_ports = every local port with an LLDP neighbor (for display).
        # uplink_ports = the INFRASTRUCTURE-facing subset: a neighbor that is
        # itself a switch/router/pollable device, NOT an end host/station. The
        # host-discovery/Tier-2 linker subtracts ONLY this subset, so a host on an
        # access port (whose neighbor is a station) isn't mistaken for transit
        # crossing a trunk.
        neighbor_ports = {nb.local_port for nb in neighbors if nb.local_port}
        uplink_ports = {
            nb.local_port for nb in neighbors
            if nb.local_port and neighbor_is_infrastructure(nb.mgmt_ip, nb.cap_enabled)
        }
        neighbor_ports |= {nb.local_port for nb in cdp if nb.local_port}
        uplink_ports |= {nb.local_port for nb in cdp
                         if nb.local_port and cdp_is_infrastructure(nb.cdp_capabilities)}

        # An access point: the device's own association MIB is the evidence;
        # its name is the fallback.
        async with self._lock:
            platform = self._platform_by_ip.get(ip)
        has_association_table = bool(await self._client.walk(ip, DOT11_ACTIVE_CLIENTS_BASE))
        access_point = has_association_table \
            or looks_like_access_point(info.get("sys_descr"), platform)
        if access_point:
            clients = None
            if has_association_table:
                try:
                    clients = await collect_wifi_clients(self._client, ip)
                except Exception:
                    _log_crawler.exception("wireless client list failed for %s", ip)
            await self._mark_access_point(chassis_id, clients)
        try:
            # An access point's clients come from its association table; its
            # bridge table (clients on radio sub-interfaces, upstream MACs on
            # Ethernet sub-interfaces) is not used for host placement.
            fdb_entries = [] if access_point else await collect_fdb(self._client, ip)
            arp = await collect_arp(self._client, ip)
            port_status = await collect_port_status(self._client, ip)
        except Exception:  # an unsupported MIB must not abort the device
            _log_crawler.exception("FDB/ARP collection failed for %s", ip)
            fdb_entries, arp, port_status = [], {}, {}
        await self._record_fdb_uplinks(
            chassis_id, fdb_entries, neighbor_ports, uplink_ports, arp, own_macs,
            port_status,
        )
        if self._checklist:
            from ..checklist.collect import collect_config
            try:
                config = await collect_config(self._client, ip, info.get("vendor"),
                                              probe=self._probe_defaults)
            except Exception:  # never lose the device over its checklist data
                _log_crawler.exception("configuration-check tables failed for %s", ip)
                config = {"failed": True}
            async with self._lock:
                self._devices[chassis_id].config_data = config

        for nb in neighbors:
            await self._handle_neighbor(chassis_id, nb)
        for nb in cdp:
            await self._handle_cdp_neighbor(chassis_id, nb)

    async def _walk_cdp(self, ip: str) -> list[Neighbor]:
        """The CDP neighbour table: one walk, plus the port names if it has rows."""
        rows = await self._client.walk(ip, CDP_CACHE_BASE)
        if not rows:
            return []
        return parse_cdp_cache(rows, await collect_ifname_map(self._client, ip))

    async def _walk_neighbors(self, ip: str) -> list[Neighbor]:
        rem = await self._client.walk(ip, LLDP_REM_BASE)
        if not rem:
            return []
        man = await self._client.walk(ip, LLDP_REM_MAN_ADDR_BASE)
        loc = await self._client.walk(ip, LLDP_LOC_PORT_BASE)
        neighbors = build_neighbors(rem, man, loc)

        # Resolve any local-port label that came through as a raw MAC / bare integer
        # (Comware's inconsistent lldpLocPortId subtypes) to a real interface name.
        # Only fetch the resolution tables when something actually needs them, so
        # Cisco/Fortinet — which advertise proper port names — do zero extra walks.
        if any(nb.local_port and _needs_port_resolution(nb.local_port) for nb in neighbors):
            ifname_by_index = await collect_ifname_map(self._client, ip)
            ifindex_by_mac = await collect_ifindex_by_mac(self._client, ip)
            normalize_neighbor_ports(
                neighbors, ifname_by_index, ifindex_by_mac, node_label=ip
            )
        return neighbors

    # ---- state mutations (each takes the lock) ----------------------------

    async def _record_polled_device(self, ip: str, chassis_id: str, info: dict) -> bool:
        """Record a polled device; False if it was already polled (same chassis)."""
        async with self._lock:
            self._seen.add(chassis_id)
            self._cid_by_ip.setdefault(ip, chassis_id)
            dev = self._devices.get(chassis_id)
            if dev is not None and dev.pollable:
                return False
            if info.get("hostname"):
                self._cid_by_name.setdefault(_name_key(info["hostname"]), chassis_id)
            if dev is None:
                dev = Device(chassis_id=chassis_id)
                self._devices[chassis_id] = dev
            dev.ip = ip
            dev.hostname = info.get("hostname")
            dev.vendor = info.get("vendor")
            dev.model = info.get("model")
            dev.firmware = info.get("firmware")
            dev.serial = info.get("serial")
            dev.mac = info.get("mac")
            dev.software_family = info.get("software_family")
            dev.discovery_method = info.get("discovery_method") or DISCOVERY_METHOD
            dev.status = STATUS_ONLINE
            dev.pollable = True
            # A polled device's OWN advertised capabilities are the most reliable
            # source of its role; they take precedence over whatever a neighbor
            # reported about it (applied as a fallback in run()).
            if info.get("cap_enabled"):
                dev.lldp_cap_enabled = info.get("cap_enabled")
            return True

    async def _record_fdb_uplinks(
        self, chassis_id: str, fdb_entries: list[dict], neighbor_ports: set,
        uplink_ports: set, arp: dict, own_macs: list, port_status: dict,
    ) -> None:
        async with self._lock:
            dev = self._devices.get(chassis_id)
            if dev is not None:
                dev.fdb = fdb_entries
                dev.neighbor_ports = sorted(neighbor_ports)
                dev.uplink_ports = sorted(uplink_ports)
                dev.port_status = port_status
                dev.arp = arp
                dev.own_macs = own_macs

    async def _record_unpollable_ip(self, ip: str, expected_cid: Optional[str]) -> None:
        """A seed/neighbor IP that answered no credential (or no full GET)."""
        chassis_id = expected_cid or f"ip:{ip}"
        async with self._lock:
            self._seen.add(chassis_id)
            self._cid_by_ip.setdefault(ip, chassis_id)
            dev = self._devices.get(chassis_id)
            if dev is None:
                dev = Device(chassis_id=chassis_id, ip=ip,
                             status=STATUS_UNREACHABLE, pollable=False)
                self._devices[chassis_id] = dev
            elif not dev.pollable:
                dev.ip = dev.ip or ip
                dev.status = STATUS_UNREACHABLE
        _log_crawler.info("%s unpollable (no working credential)", ip)

    async def _handle_neighbor(self, source_cid: str, nb: Neighbor) -> None:
        """Record the edge to a neighbor and enqueue it if it is pollable."""
        target_cid = nb.chassis_id or (nb.sys_name and f"name:{nb.sys_name}") \
            or (nb.mgmt_ip and f"ip:{nb.mgmt_ip}") or "unknown"

        async with self._lock:
            self._links.append(
                Link(
                    source_chassis_id=source_cid,
                    target_chassis_id=target_cid,
                    local_port=nb.local_port,
                    remote_port=nb.remote_port,
                )
            )
            # Remember what this neighbor advertised about itself — that is the
            # neighbor's OWN role, used whether or not it is ever polled.
            if nb.cap_enabled and target_cid not in self._caps:
                self._caps[target_cid] = nb.cap_enabled
            known = target_cid in self._devices or target_cid in self._seen

            if nb.mgmt_ip and not known:
                # Pollable neighbor: enqueue it (reserves the chassis id).
                await self._enqueue(nb.mgmt_ip, target_cid)
                return

            # No management address (or already known): record a placeholder
            # node so the edge has both endpoints, but never enqueue it.
            if target_cid not in self._devices:
                self._devices[target_cid] = Device(
                    chassis_id=target_cid,
                    ip=nb.mgmt_ip,
                    hostname=nb.sys_name,
                    vendor=vendor_from_descr(nb.sys_descr),
                    mac=nb.chassis_mac,
                    status=STATUS_DISCOVERED,
                    pollable=False,
                )
                self._seen.add(target_cid)


    async def _mark_access_point(self, chassis_id: str, clients: Optional[list]) -> None:
        async with self._lock:
            dev = self._devices.get(chassis_id)
            if dev is not None:
                dev.access_point = True
                dev.wifi_clients = clients

    async def _handle_cdp_neighbor(self, source_cid: str, nb: Neighbor) -> None:
        """Keep a CDP link for resolution and enqueue the neighbour if it is new."""
        async with self._lock:
            self._cdp_links.append((source_cid, nb))
            if nb.mgmt_ip and nb.platform:
                self._platform_by_ip.setdefault(nb.mgmt_ip, nb.platform)
            if self._cdp_target(nb) is None and nb.mgmt_ip:
                await self._enqueue(nb.mgmt_ip, None, via="cdp")

    def _cdp_target(self, nb: Neighbor) -> Optional[str]:
        """The chassis id of a known device a CDP entry describes (or None)."""
        if nb.mgmt_ip and nb.mgmt_ip in self._cid_by_ip:
            return self._cid_by_ip[nb.mgmt_ip]
        if nb.sys_name:
            return self._cid_by_name.get(_name_key(nb.sys_name))
        return None

    def _resolve_cdp_links(self) -> None:
        """Turn the kept CDP entries into links (must hold the lock).

        A neighbour that was polled (or tried) is matched by address or name; one
        that never was becomes a placeholder like an unpollable LLDP neighbour. A
        pair LLDP already links gets no second link.
        """
        linked = {frozenset((l.source_chassis_id, l.target_chassis_id)) for l in self._links}
        for source_cid, nb in self._cdp_links:
            target = self._cdp_target(nb) or f"cdp:{nb.sys_name or nb.mgmt_ip}"
            dev = self._devices.get(target)
            if dev is None:
                dev = self._devices[target] = Device(
                    chassis_id=target, ip=nb.mgmt_ip, status=STATUS_DISCOVERED,
                    discovery_method=DISCOVERY_METHOD_CDP, pollable=False)
                self._seen.add(target)
            if not dev.pollable:          # fill what the CDP entry tells about it
                dev.hostname = dev.hostname or nb.sys_name
                dev.vendor = dev.vendor or vendor_from_descr(nb.sys_descr or nb.platform)
                dev.model = dev.model or _platform_model(nb.platform)
            dev.platform = dev.platform or nb.platform
            if not dev.pollable and looks_like_access_point(nb.sys_descr, nb.platform):
                dev.access_point = True   # name evidence is all there is
            if nb.cap_enabled and target not in self._caps:
                self._caps[target] = nb.cap_enabled
            pair = frozenset((source_cid, target))
            if target == source_cid or (pair in linked and not self._cdp_only(pair)):
                continue
            linked.add(pair)
            self._links.append(Link(source_chassis_id=source_cid, target_chassis_id=target,
                                    local_port=nb.local_port, remote_port=nb.remote_port,
                                    protocol="cdp"))

    def _cdp_only(self, pair: frozenset) -> bool:
        return all(l.protocol == "cdp" for l in self._links
                   if frozenset((l.source_chassis_id, l.target_chassis_id)) == pair)


def _name_key(name: str) -> str:
    """A device name for matching: case-insensitive, without a domain suffix."""
    return name.strip().split(".")[0].lower()


def _same_neighbor(cdp_nb: Neighbor, lldp_neighbors: list[Neighbor]) -> bool:
    """Whether an LLDP entry of the same device already describes this neighbour."""
    for nb in lldp_neighbors:
        if cdp_nb.local_port and cdp_nb.local_port == nb.local_port:
            return True
        if cdp_nb.mgmt_ip and cdp_nb.mgmt_ip == nb.mgmt_ip:
            return True
        if cdp_nb.sys_name and nb.sys_name and _name_key(cdp_nb.sys_name) == _name_key(nb.sys_name):
            return True
    return False


def _platform_model(platform: Optional[str]) -> Optional[str]:
    """``"cisco WS-C2960-48TT-L"`` -> ``"WS-C2960-48TT-L"``."""
    if not platform:
        return None
    words = platform.split()
    return " ".join(words[1:]) if len(words) > 1 and words[0].lower() == "cisco" else platform


# =========================================================================
# Programmatic entry point (was runner.py)
# =========================================================================

async def run(cfg: Config) -> dict:
    """Run the crawl described by ``cfg`` and return the output document."""
    if not cfg.credentials:
        _log_runner.error(
            "no SNMP credentials supplied. Pass --community / --v3-user (or set "
            "$SNMP_COMMUNITIES). Emitting empty topology."
        )
        return build_document([], [])

    seeds = discover_seeds(cfg.seeds)
    if not seeds:
        _log_runner.error(
            "no seed device found (no default gateway, no local LLDP neighbor, "
            "no --seed). Emitting empty topology."
        )
        return build_document([], [])

    _log_runner.info("seeds: %s", ", ".join(seeds))
    _log_runner.info(
        "crawl config: concurrency=%d timeout=%.1fs retries=%d max_nodes=%d port=%d "
        "credentials=%s",
        cfg.concurrency, cfg.timeout, cfg.retries, cfg.max_nodes, cfg.port,
        ", ".join(c.label for c in cfg.credentials),
    )

    client = SnmpClient(
        cfg.credentials, port=cfg.port, timeout=cfg.timeout, retries=cfg.retries
    )
    crawler = Crawler(
        client,
        concurrency=cfg.concurrency,
        max_nodes=cfg.max_nodes,
        queue_maxsize=cfg.queue_maxsize,
        checklist=cfg.checklist,
        check_default_communities=cfg.check_default_communities,
    )
    await crawler.seed(seeds)
    devices, links = await crawler.run()
    return build_document(devices, links, pollable_only=cfg.pollable_only)


def crawl_document(cfg: Config) -> dict:
    """Synchronous wrapper: run the crawl and always return a valid document."""
    if not cfg.credentials:
        raise SystemExit("vulnmapper: no SNMP credentials; pass --community or set "
                         "SNMP_COMMUNITIES (or the SNMP_V3_* variables).")
    try:
        return asyncio.run(run(cfg))
    except Exception:
        _log_runner.exception("crawl failed; emitting empty topology")
        return build_document([], [])


# =========================================================================
# Command-line interface (was cli.py)
# =========================================================================

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="discovery_module",
        description="Seed-based LLDP topology crawler for network infrastructure "
                    "(routers/switches via SNMP/LLDP). Endpoints are out of scope.",
    )
    parser.add_argument(
        "--community",
        action="append",
        metavar="STRING",
        help="SNMPv2c community to TRY (repeatable). Also read from "
             f"${ENV_COMMUNITIES}/${ENV_COMMUNITY}. Operator-known "
             "strings only — community strings are never brute-forced.",
    )
    parser.add_argument(
        "--seed",
        action="append",
        metavar="IP",
        help="explicit seed device IP (repeatable). Optional override for when "
             "gateway detection fails or a specific start point is wanted.",
    )
    # SNMPv3 (alternative to community strings).
    parser.add_argument("--v3-user", metavar="USER", help="SNMPv3 security name")
    parser.add_argument("--v3-auth-protocol", metavar="PROTO",
                        help="SNMPv3 auth protocol (MD5/SHA/SHA256/SHA384/SHA512)")
    parser.add_argument("--v3-auth-key", metavar="KEY", help="SNMPv3 auth key")
    parser.add_argument("--v3-priv-protocol", metavar="PROTO",
                        help="SNMPv3 priv protocol (DES/AES/AES192/AES256)")
    parser.add_argument("--v3-priv-key", metavar="KEY", help="SNMPv3 priv key")

    parser.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY,
                        help=f"worker pool size (default {DEFAULT_CONCURRENCY})")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help=f"per-request timeout in s (default {DEFAULT_TIMEOUT})")
    parser.add_argument("--retries", type=int, default=DEFAULT_RETRIES,
                        help=f"SNMP retries per request (default {DEFAULT_RETRIES})")
    parser.add_argument("--max-nodes", type=int, default=DEFAULT_MAX_NODES,
                        help=f"safety cap on total nodes (default {DEFAULT_MAX_NODES})")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help=f"SNMP UDP port (default {DEFAULT_PORT})")
    parser.add_argument("--pollable-only", action="store_true",
                        help="emit only SNMP-polled infrastructure: drop every "
                             "unpollable node (no credential / no management "
                             "address) and any edge touching one.")
    parser.add_argument("-o", "--output", metavar="PATH",
                        help="write the JSON document to PATH (UTF-8, no BOM) "
                             "instead of stdout. Avoids the UTF-16 a PowerShell "
                             "'> file' redirect would produce.")
    return parser


def parse_config(argv: Optional[list[str]] = None) -> Config:
    """Parse argv into a resolved :class:`Config` (raises SystemExit on bad args)."""
    parser = build_parser()
    args = parser.parse_args(argv)

    credentials = load_credentials(args.community)
    if args.v3_user:
        add_v3_credential(
            credentials,
            user=args.v3_user,
            auth_protocol=args.v3_auth_protocol,
            auth_key=args.v3_auth_key,
            priv_protocol=args.v3_priv_protocol,
            priv_key=args.v3_priv_key,
        )

    return Config(
        credentials=credentials,
        seeds=list(args.seed or []),
        concurrency=args.concurrency,
        timeout=args.timeout,
        retries=args.retries,
        max_nodes=args.max_nodes,
        port=args.port,
        pollable_only=args.pollable_only,
        output_path=args.output,
    )
