"""The network crawl: a breadth-first walk over LLDP and CDP neighbour tables
from the seeds, polling each device found once (``Crawler``). The first stage
of the network side (``crawl_document``); its document goes to assembly.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

from .config import DEFAULT_CONCURRENCY, DEFAULT_MAX_NODES, Config
from .document import build_document
from .identity import base_mac, fetch, vendor_from_descr
from .model import (
    DISCOVERY_METHOD,
    DISCOVERY_METHOD_CDP,
    STATUS_DISCOVERED,
    STATUS_ONLINE,
    STATUS_UNREACHABLE,
    Device,
    Link,
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
    collect_arp,
    collect_fdb,
    collect_ifindex_by_mac,
    collect_ifname_map,
    collect_own_macs,
    collect_port_status,
    collect_wifi_clients,
    looks_like_access_point,
    needs_port_resolution,
    normalize_neighbor_ports,
    parse_cdp_cache,
)
from .roles import neighbor_is_infrastructure
from .seeds import discover_seeds
from .snmp import SnmpClient

log = logging.getLogger("discovery.crawler")
_log_runner = logging.getLogger("discovery")

# Pushed once per worker to stop it after the queue drains.
_STOP = object()


class Crawler:
    """The shared crawl state and the worker pool that fills it."""

    def __init__(self, client: SnmpClient, *, concurrency: int, max_nodes: int,
                 queue_maxsize: int, checklist: bool = False,
                 check_default_communities: bool = False, port_connect=None) -> None:
        self._client = client
        self._checklist = checklist
        self._probe_defaults = check_default_communities
        # The connection test's connector (checklist.collect.tcp_connect); None when off.
        self._port_connect = port_connect
        self._concurrency = concurrency
        self._max_nodes = max_nodes
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=queue_maxsize)

        # Everything below is shared between workers and guarded by the lock.
        self._lock = asyncio.Lock()
        self._devices: dict[str, Device] = {}     # chassis_id -> Device
        self._links: list[Link] = []
        self._seen: set[str] = set()              # chassis ids reserved or recorded
        self._enqueued_ips: set[str] = set()
        self._reserved = 0                        # counts toward max_nodes
        # chassis_id -> the LLDP capability bitmap its neighbours advertised for it
        self._caps: dict[str, str] = {}
        # CDP names a neighbour instead of giving its chassis id, so CDP links
        # wait until every device is polled and are then resolved by the
        # address the device was polled at, else by its name.
        self._cid_by_ip: dict[str, str] = {}
        self._cid_by_name: dict[str, str] = {}
        self._cdp_links: list[tuple[str, Neighbor]] = []
        # Platform strings CDP neighbours reported, by the address they gave.
        self._platform_by_ip: dict[str, str] = {}

    # ---- queueing (callers hold the lock) ---------------------------------

    async def _enqueue(self, ip: str, chassis_id: Optional[str], via: str = "lldp") -> bool:
        """Reserve and queue a next hop; False if it is a duplicate or over the cap.

        ``via`` is the neighbour table that first named the address ("lldp",
        also used for seeds, or "cdp"); it becomes the device's discovery method.
        """
        if ip in self._enqueued_ips:
            return False
        if chassis_id is not None and chassis_id in self._seen:
            return False
        if self._reserved >= self._max_nodes:
            log.warning("max-nodes cap (%d) reached; not enqueuing %s", self._max_nodes, ip)
            return False
        self._enqueued_ips.add(ip)
        if chassis_id is not None:
            self._seen.add(chassis_id)
        self._reserved += 1
        # the queue is sized to max_nodes, so this never blocks before the cap
        self._queue.put_nowait((ip, chassis_id, via))
        return True

    def know(self, nodes: list[dict]) -> None:
        """Treat the devices of an earlier crawl's document as already seen, so
        a crawl from new seeds links to them instead of polling them again."""
        for node in nodes:
            cid = node.get("chassis_id")
            if not cid:
                continue
            self._seen.add(cid)
            if node.get("ip"):
                self._enqueued_ips.add(node["ip"])
                self._cid_by_ip.setdefault(node["ip"], cid)
            if node.get("hostname"):
                self._cid_by_name.setdefault(_name_key(node["hostname"]), cid)

    async def seed(self, ips: list[str]) -> int:
        """Queue the seed addresses; returns how many were queued."""
        queued = 0
        async with self._lock:
            for ip in ips:
                if await self._enqueue(ip, None):
                    queued += 1
        return queued

    # ---- the crawl --------------------------------------------------------

    async def run(self) -> tuple[list[Device], list[Link]]:
        workers = [asyncio.create_task(self._worker()) for _ in range(self._concurrency)]
        await self._queue.join()
        for _ in workers:
            self._queue.put_nowait(_STOP)
        await asyncio.gather(*workers, return_exceptions=True)

        async with self._lock:
            self._resolve_cdp_links()
            # What neighbours advertised for a device is its role only when the
            # device did not advertise its own; applied now that every device
            # exists, whatever order they were polled in.
            for cid, caps in self._caps.items():
                dev = self._devices.get(cid)
                if dev is not None and not dev.lldp_cap_enabled:
                    dev.lldp_cap_enabled = caps
            return list(self._devices.values()), list(self._links)

    async def _worker(self) -> None:
        while True:
            item = await self._queue.get()
            if item is _STOP:
                self._queue.task_done()
                return
            ip, expected_cid, via = item
            try:
                await self._process(ip, expected_cid, via)
            except Exception:  # never let one device kill a worker
                log.exception("error processing %s", ip)
            finally:
                self._queue.task_done()

    async def _process(self, ip: str, expected_cid: Optional[str], via: str = "lldp") -> None:
        """Poll one device, record it and queue its neighbours."""
        polled = await self._identify(ip, expected_cid, via)
        if polled is None:
            return
        chassis_id, info, own_macs = polled

        neighbors = await self._walk_neighbors(ip)
        cdp = [nb for nb in await self._walk_cdp(ip) if not _same_neighbor(nb, neighbors)]
        log.info("%s (%s): %d LLDP neighbor(s), %d more over CDP",
                 info.get("hostname") or ip, chassis_id, len(neighbors), len(cdp))
        neighbor_ports, uplink_ports = _port_roles(neighbors, cdp)

        access_point = await self._check_access_point(ip, chassis_id, info)
        await self._read_tables(ip, chassis_id, access_point, neighbor_ports, uplink_ports,
                                own_macs)
        if self._checklist:
            await self._read_config(ip, chassis_id, info)

        for nb in neighbors:
            await self._handle_neighbor(chassis_id, nb)
        for nb in cdp:
            await self._handle_cdp_neighbor(chassis_id, nb)

    async def _identify(self, ip: str, expected_cid: Optional[str], via: str):
        """``(chassis_id, identity, own MACs)`` for a device polled here for the
        first time; None when it does not answer or was polled already."""
        if await self._client.resolve_credential(ip) is None:
            await self._record_unpollable_ip(ip, expected_cid)
            return None
        info = await fetch(self._client, ip)
        if info is None:
            # answered the credential probe but not the full GET
            await self._record_unpollable_ip(ip, expected_cid)
            return None

        # The device's own interface MACs give a base MAC when LLDP has none,
        # and keep its SVI and gateway MACs from becoming hosts.
        try:
            own_macs = await collect_own_macs(self._client, ip)
        except Exception:
            log.exception("interface MAC read failed for %s", ip)
            own_macs = []
        if not info.get("mac"):
            info["mac"] = base_mac(own_macs)
        # An address names the device only when no MAC can be read at all.
        chassis_id = info["chassis_id"] or expected_cid or info["mac"] or f"ip:{ip}"
        info["discovery_method"] = DISCOVERY_METHOD_CDP if via == "cdp" else DISCOVERY_METHOD
        if not await self._record_polled_device(ip, chassis_id, info):
            # the same device at another of its addresses (a CDP neighbour
            # advertises the address that faces it)
            log.info("%s is %s, already polled", ip, chassis_id)
            return None
        return chassis_id, info, own_macs

    async def _check_access_point(self, ip: str, chassis_id: str, info: dict) -> bool:
        """Whether the device is a wireless access point; if so, record its clients.

        The device's own association table is the evidence, and its name the
        fallback when it has none.
        """
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
                    log.exception("wireless client list failed for %s", ip)
            await self._mark_access_point(chassis_id, clients)
        return access_point

    async def _read_tables(self, ip: str, chassis_id: str, access_point: bool,
                           neighbor_ports: set, uplink_ports: set, own_macs: list) -> None:
        """The forwarding, ARP and port-status tables host placement reads."""
        try:
            # An access point's clients come from its association table. Its
            # bridge table (clients on radio sub-interfaces, upstream MACs on
            # Ethernet sub-interfaces) would misplace them, so it is not read.
            fdb_entries = [] if access_point else await collect_fdb(self._client, ip)
            arp = await collect_arp(self._client, ip)
            port_status = await collect_port_status(self._client, ip)
        except Exception:  # an unsupported MIB must not abort the device
            log.exception("FDB/ARP collection failed for %s", ip)
            fdb_entries, arp, port_status = [], {}, {}
        async with self._lock:
            dev = self._devices.get(chassis_id)
            if dev is not None:
                dev.fdb = fdb_entries
                dev.neighbor_ports = sorted(neighbor_ports)
                dev.uplink_ports = sorted(uplink_ports)
                dev.port_status = port_status
                dev.arp = arp
                dev.own_macs = own_macs

    async def _read_config(self, ip: str, chassis_id: str, info: dict) -> None:
        """The configuration-check tables (only when the checklist is on)."""
        from ..checklist.collect import collect_config
        try:
            config = await collect_config(self._client, ip, info.get("vendor"),
                                          probe=self._probe_defaults,
                                          connect=self._port_connect)
        except Exception:  # never lose the device over its checklist data
            log.exception("configuration-check tables failed for %s", ip)
            config = {"failed": True}
        async with self._lock:
            self._devices[chassis_id].config_data = config

    async def _walk_cdp(self, ip: str) -> list[Neighbor]:
        """The CDP neighbour table, plus the port names when it has rows."""
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

        # Comware mixes lldpLocPortId subtypes, so a local port can arrive as a
        # raw MAC or a bare number. The interface tables that turn those into
        # names are only read when needed: Cisco and Fortinet advertise proper
        # port names and cost no extra walks.
        if any(nb.local_port and needs_port_resolution(nb.local_port) for nb in neighbors):
            ifname_by_index = await collect_ifname_map(self._client, ip)
            ifindex_by_mac = await collect_ifindex_by_mac(self._client, ip)
            normalize_neighbor_ports(neighbors, ifname_by_index, ifindex_by_mac, node_label=ip)
        return neighbors

    # ---- recording (each takes the lock) -----------------------------------

    async def _record_polled_device(self, ip: str, chassis_id: str, info: dict) -> bool:
        """Record a polled device; False if this chassis was polled already."""
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
            # A device's own advertised capabilities beat whatever a neighbour
            # reported about it (that is only the fallback, applied in run()).
            if info.get("cap_enabled"):
                dev.lldp_cap_enabled = info.get("cap_enabled")
            return True

    async def _record_unpollable_ip(self, ip: str, expected_cid: Optional[str]) -> None:
        """An address that answered no credential (or not the full GET)."""
        chassis_id = expected_cid or f"ip:{ip}"
        async with self._lock:
            self._seen.add(chassis_id)
            self._cid_by_ip.setdefault(ip, chassis_id)
            dev = self._devices.get(chassis_id)
            if dev is None:
                self._devices[chassis_id] = Device(chassis_id=chassis_id, ip=ip,
                                                   status=STATUS_UNREACHABLE, pollable=False)
            elif not dev.pollable:
                dev.ip = dev.ip or ip
                dev.status = STATUS_UNREACHABLE
        log.info("%s unpollable (no working credential)", ip)

    async def _mark_access_point(self, chassis_id: str, clients: Optional[list]) -> None:
        async with self._lock:
            dev = self._devices.get(chassis_id)
            if dev is not None:
                dev.access_point = True
                dev.wifi_clients = clients

    async def _handle_neighbor(self, source_cid: str, nb: Neighbor) -> None:
        """Record the link to an LLDP neighbour and queue it if it has an address."""
        target_cid = nb.chassis_id or (nb.sys_name and f"name:{nb.sys_name}") \
            or (nb.mgmt_ip and f"ip:{nb.mgmt_ip}") or "unknown"

        async with self._lock:
            self._links.append(Link(source_chassis_id=source_cid, target_chassis_id=target_cid,
                                    local_port=nb.local_port, remote_port=nb.remote_port))
            # what the neighbour advertised about itself is its own role,
            # whether or not it is ever polled
            if nb.cap_enabled and target_cid not in self._caps:
                self._caps[target_cid] = nb.cap_enabled
            known = target_cid in self._devices or target_cid in self._seen

            if nb.mgmt_ip and not known:
                await self._enqueue(nb.mgmt_ip, target_cid)
                return

            # No address, or known already: a placeholder node gives the edge
            # both of its ends, and is never polled.
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

    async def _handle_cdp_neighbor(self, source_cid: str, nb: Neighbor) -> None:
        """Keep a CDP entry for resolution, and queue the neighbour if it is new."""
        async with self._lock:
            self._cdp_links.append((source_cid, nb))
            if nb.mgmt_ip and nb.platform:
                self._platform_by_ip.setdefault(nb.mgmt_ip, nb.platform)
            if self._cdp_target(nb) is None and nb.mgmt_ip:
                await self._enqueue(nb.mgmt_ip, None, via="cdp")

    def _cdp_target(self, nb: Neighbor) -> Optional[str]:
        """The chassis id of the known device a CDP entry describes, if any."""
        if nb.mgmt_ip and nb.mgmt_ip in self._cid_by_ip:
            return self._cid_by_ip[nb.mgmt_ip]
        if nb.sys_name:
            return self._cid_by_name.get(_name_key(nb.sys_name))
        return None

    def _resolve_cdp_links(self) -> None:
        """Turn the kept CDP entries into links (the caller holds the lock).

        A neighbour that was polled, or tried, is matched by address or name;
        one that never was becomes a placeholder like an unpolled LLDP
        neighbour. A pair LLDP already links gets no second link.
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
            if not dev.pollable:          # fill in what the CDP entry tells about it
                dev.hostname = dev.hostname or nb.sys_name
                dev.vendor = dev.vendor or vendor_from_descr(nb.sys_descr or nb.platform)
                dev.model = dev.model or _platform_model(nb.platform)
            dev.platform = dev.platform or nb.platform
            if not dev.pollable and looks_like_access_point(nb.sys_descr, nb.platform):
                dev.access_point = True   # its name is the only evidence there is
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


def _port_roles(neighbors: list[Neighbor], cdp: list[Neighbor]) -> tuple[set, set]:
    """``(neighbor_ports, uplink_ports)``: every local port with a neighbour,
    and the ones whose neighbour is network equipment (see ``Device``)."""
    neighbor_ports = {nb.local_port for nb in neighbors + cdp if nb.local_port}
    uplink_ports = {nb.local_port for nb in neighbors
                    if nb.local_port and neighbor_is_infrastructure(nb.mgmt_ip, nb.cap_enabled)}
    uplink_ports |= {nb.local_port for nb in cdp
                     if nb.local_port and cdp_is_infrastructure(nb.cdp_capabilities)}
    return neighbor_ports, uplink_ports


def _name_key(name: str) -> str:
    """A device name for matching: case-insensitive, without a domain suffix."""
    return name.strip().split(".")[0].lower()


def _same_neighbor(cdp_nb: Neighbor, lldp_neighbors: list[Neighbor]) -> bool:
    """Whether one of the device's LLDP entries already describes this CDP neighbour."""
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


# ---- entry points -----------------------------------------------------------

async def run(cfg: Config) -> dict:
    """Run the crawl ``cfg`` describes and return its document."""
    if not cfg.credentials:
        _log_runner.error("no SNMP credentials supplied. Pass --community / --v3-user (or set "
                          "$SNMP_COMMUNITIES). Emitting empty topology.")
        return build_document([], [])

    seeds = discover_seeds(cfg.seeds)
    if not seeds:
        _log_runner.error("no seed device found (no default gateway, no local LLDP neighbor, "
                          "no --seed). Emitting empty topology.")
        return build_document([], [])

    _log_runner.info("seeds: %s", ", ".join(seeds))
    _log_runner.info(
        "crawl config: concurrency=%d timeout=%.1fs retries=%d max_nodes=%d port=%d "
        "credentials=%s",
        cfg.concurrency, cfg.timeout, cfg.retries, cfg.max_nodes, cfg.port,
        ", ".join(c.label for c in cfg.credentials),
    )

    from ..checklist.collect import tcp_connect
    client = SnmpClient(cfg.credentials, port=cfg.port, timeout=cfg.timeout, retries=cfg.retries)
    crawler = Crawler(
        client,
        concurrency=cfg.concurrency,
        max_nodes=cfg.max_nodes,
        queue_maxsize=cfg.queue_maxsize,
        checklist=cfg.checklist,
        check_default_communities=cfg.check_default_communities,
        port_connect=tcp_connect if cfg.check_management_ports else None,
    )
    await crawler.seed(seeds)
    devices, links = await crawler.run()
    return build_document(devices, links, pollable_only=cfg.pollable_only)


async def crawl_more(client, seeds: list[str], known: dict, **crawler_kw) -> dict:
    """Crawl from ``seeds`` without polling again what ``known`` (an earlier
    network document) holds; combine the two with ``document.merge_documents``."""
    crawler = Crawler(client, concurrency=DEFAULT_CONCURRENCY, max_nodes=DEFAULT_MAX_NODES,
                      queue_maxsize=DEFAULT_MAX_NODES, **crawler_kw)
    crawler.know(known.get("nodes") or [])
    await crawler.seed(seeds)
    devices, links = await crawler.run()
    return build_document(devices, links)


def crawl_document(cfg: Config) -> dict:
    """Run the crawl and always return a valid document (empty if it fails)."""
    if not cfg.credentials:
        raise SystemExit("vulnmapper: no SNMP credentials; pass --community or set "
                         "SNMP_COMMUNITIES (or the SNMP_V3_* variables).")
    try:
        return asyncio.run(run(cfg))
    except Exception:
        _log_runner.exception("crawl failed; emitting empty topology")
        return build_document([], [])
