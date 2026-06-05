"""The BFS LLDP crawl: a bounded worker pool over a queue of next-hops.

Start from the seeds, poll each device for its LLDP neighbor table, enqueue the
neighbors that have a usable management address, and repeat until the queue
drains. The crawl only ever touches real devices (never an address space), so it
terminates naturally and fails fast on an unreachable seed.

Memory discipline:
  * A fixed set of worker coroutines (``concurrency``) pulls from an
    ``asyncio.Queue``. At most that many devices are in flight at once, so the
    heavy state (SNMP/MIB decoding) is bounded by the pool, not the topology.
  * The queue holds only lightweight ``(ip, chassis_id|None)`` tuples.
  * A ``max_nodes`` cap stops a misconfigured or hostile environment from
    crawling unbounded.

Dedup is keyed on **chassis ID**, never IP: a device reachable via several
neighbors or several IPs is reserved once and polled once.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

import sysinfo
from lldp import (
    LLDP_LOC_PORT_BASE,
    LLDP_REM_BASE,
    LLDP_REM_MAN_ADDR_BASE,
    Neighbor,
    build_neighbors,
)
from models import (
    DISCOVERY_METHOD,
    STATUS_DISCOVERED,
    STATUS_ONLINE,
    STATUS_UNREACHABLE,
    Device,
    Link,
)
from snmp_client import SnmpClient

log = logging.getLogger("discovery.crawler")

# Sentinel pushed once per worker to signal shutdown after the queue drains.
_STOP = object()


class Crawler:
    """Owns the shared crawl state and the worker pool."""

    def __init__(self, client: SnmpClient, *, concurrency: int, max_nodes: int,
                 queue_maxsize: int) -> None:
        self._client = client
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

    # ---- enqueue helpers (must hold the lock) -----------------------------

    def _cap_reached(self) -> bool:
        return self._reserved >= self._max_nodes

    async def _enqueue(self, ip: str, chassis_id: Optional[str]) -> bool:
        """Reserve and queue a next-hop. Returns False if skipped (dup/cap)."""
        if ip in self._enqueued_ips:
            return False
        if chassis_id is not None and chassis_id in self._seen:
            return False
        if self._cap_reached():
            log.warning("max-nodes cap (%d) reached; not enqueuing %s",
                        self._max_nodes, ip)
            return False
        self._enqueued_ips.add(ip)
        if chassis_id is not None:
            self._seen.add(chassis_id)
        self._reserved += 1
        # Queue is sized to max_nodes, so this never blocks before the cap.
        self._queue.put_nowait((ip, chassis_id))
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
            return list(self._devices.values()), list(self._links)

    async def _worker(self, worker_id: int) -> None:
        while True:
            item = await self._queue.get()
            if item is _STOP:
                self._queue.task_done()
                return
            ip, expected_cid = item
            try:
                await self._process(ip, expected_cid)
            except Exception:  # never let one device kill a worker
                log.exception("error processing %s", ip)
            finally:
                self._queue.task_done()

    async def _process(self, ip: str, expected_cid: Optional[str]) -> None:
        """Poll one device, record it, and enqueue its pollable neighbors."""
        cred = await self._client.resolve_credential(ip)
        if cred is None:
            await self._record_unpollable_ip(ip, expected_cid)
            return

        info = await sysinfo.fetch(self._client, ip)
        if info is None:
            # Answered the credential probe but not the full GET — treat as
            # unpollable rather than stalling.
            await self._record_unpollable_ip(ip, expected_cid)
            return

        chassis_id = info["chassis_id"] or expected_cid or f"ip:{ip}"
        await self._record_polled_device(ip, chassis_id, info)

        neighbors = await self._walk_neighbors(ip)
        log.info("%s (%s): %d LLDP neighbor(s)",
                 info.get("hostname") or ip, chassis_id, len(neighbors))
        for nb in neighbors:
            await self._handle_neighbor(chassis_id, nb)

    async def _walk_neighbors(self, ip: str) -> list[Neighbor]:
        rem = await self._client.walk(ip, LLDP_REM_BASE)
        if not rem:
            return []
        man = await self._client.walk(ip, LLDP_REM_MAN_ADDR_BASE)
        loc = await self._client.walk(ip, LLDP_LOC_PORT_BASE)
        return build_neighbors(rem, man, loc)

    # ---- state mutations (each takes the lock) ----------------------------

    async def _record_polled_device(self, ip: str, chassis_id: str, info: dict) -> None:
        async with self._lock:
            self._seen.add(chassis_id)
            dev = self._devices.get(chassis_id)
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
            dev.discovery_method = DISCOVERY_METHOD
            dev.status = STATUS_ONLINE
            dev.pollable = True

    async def _record_unpollable_ip(self, ip: str, expected_cid: Optional[str]) -> None:
        """A seed/neighbor IP that answered no credential (or no full GET)."""
        chassis_id = expected_cid or f"ip:{ip}"
        async with self._lock:
            self._seen.add(chassis_id)
            dev = self._devices.get(chassis_id)
            if dev is None:
                dev = Device(chassis_id=chassis_id, ip=ip,
                             status=STATUS_UNREACHABLE, pollable=False)
                self._devices[chassis_id] = dev
            elif not dev.pollable:
                dev.ip = dev.ip or ip
                dev.status = STATUS_UNREACHABLE
        log.info("%s unpollable (no working credential)", ip)

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
                    vendor=sysinfo.vendor_from_descr(nb.sys_descr),
                    mac=nb.chassis_mac,
                    status=STATUS_DISCOVERED,
                    pollable=False,
                )
                self._seen.add(target_cid)
