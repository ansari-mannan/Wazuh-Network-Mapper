"""SNMP client wrapper around pysnmp 7.x (async-only LeXtudio fork).

pysnmp 7.x exposes only the asyncio v3arch HLAPI. All command functions
(get_cmd, next_cmd, bulk_cmd) are awaitable coroutines, and even building a
UdpTransportTarget is async (``await UdpTransportTarget.create(...)``), because
it resolves the address on the event loop.

This wrapper hides those details and exposes a small, sync-looking surface:
build a client once with a community string, then ``await client.get(ip, oid)``
or ``await client.get_many(ip, [oids])``.
"""

from __future__ import annotations

from typing import Iterable, Optional

from pysnmp.hlapi.v3arch.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    bulk_cmd,
    get_cmd,
)

# Common system-group OIDs, exported so callers don't sprinkle magic strings.
OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
OID_SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"

# LLDP: the device's own chassis id (its LLDP MAC).
OID_LLDP_LOC_CHASSIS_ID = "1.0.8802.1.1.2.1.3.2.0"

# Sentinel value classes pysnmp returns for absent OIDs / end of a walk.
_ABSENT = ("NoSuchObject", "NoSuchInstance", "EndOfMibView")
# OID-valued types: prettyPrint() does a MIB lookup, but vendor dispatch needs
# the raw numeric form, which str() gives.
_OID_TYPES = ("ObjectIdentity", "ObjectIdentifier", "ObjectName")


def _render_value(value) -> Optional[str]:
    """Render a pysnmp value to a string (or None for absent OIDs).

    Shared by GET and WALK so both phases see identical value formatting.
    """
    value_type = value.__class__.__name__
    if value_type in _ABSENT:
        return None
    if value_type in _OID_TYPES:
        return str(value)
    return value.prettyPrint()


class SnmpClient:
    """Minimal async SNMPv2c client.

    A FRESH SnmpEngine is created per operation rather than shared. A single
    shared engine's asyncio transport dispatcher saturates under high-concurrency
    fan-out (256 hosts at once) and silently drops responses — devices get
    missed and subsequent walks return nothing, even after the burst. A
    per-operation engine keeps each request isolated. The lightweight auth and
    context objects are safely reused.
    """

    def __init__(
        self,
        community: str,
        *,
        port: int = 161,
        timeout: float = 1.0,
        retries: int = 0,
    ) -> None:
        self._community = community
        self._port = port
        self._timeout = timeout
        self._retries = retries
        # mpModel=1 selects SNMPv2c (0 would be v1).
        self._auth = CommunityData(community, mpModel=1)
        self._context = ContextData()

    async def get_many(
        self, ip: str, oids: Iterable[str]
    ) -> Optional[dict[str, Optional[str]]]:
        """GET one or more OIDs from a host in a single PDU.

        Returns a ``{oid: value}`` dict (values as strings, or None for a
        ``noSuchObject``/``noSuchInstance`` result), or None if the host did
        not answer / SNMP reported an error — i.e. "not a live SNMP device".
        """
        oids = list(oids)
        transport = await UdpTransportTarget.create(
            (ip, self._port), timeout=self._timeout, retries=self._retries
        )

        error_indication, error_status, _error_index, var_binds = await get_cmd(
            SnmpEngine(),
            self._auth,
            transport,
            self._context,
            *[ObjectType(ObjectIdentity(oid)) for oid in oids],
        )

        # error_indication: transport-level problem (timeout, no route, ...).
        # error_status: SNMP-level error reported by the agent.
        if error_indication or error_status:
            return None

        result: dict[str, Optional[str]] = {}
        for var_bind in var_binds:
            oid, value = var_bind
            result[str(oid)] = _render_value(value)
        return result

    async def get(self, ip: str, oid: str) -> Optional[str]:
        """GET a single OID; convenience wrapper over :meth:`get_many`."""
        result = await self.get_many(ip, [oid])
        if result is None:
            return None
        return result.get(oid)

    async def walk(
        self, ip: str, base_oid: str, *, max_repetitions: int = 25
    ) -> list[tuple[str, Optional[str]]]:
        """WALK an OID subtree, returning ``[(oid, value), ...]`` in order.

        Uses GETBULK (bulk_cmd) and re-issues from the last OID until the walk
        leaves ``base_oid``'s subtree or the agent signals end-of-MIB. Returns
        an empty list if the subtree is absent (e.g. a device with no LLDP) or
        the host doesn't answer — callers treat "no rows" as "no data", never an
        error, so a device without LLDP still survives as a node.
        """
        transport = await UdpTransportTarget.create(
            (ip, self._port), timeout=self._timeout, retries=self._retries
        )

        prefix = base_oid.rstrip(".") + "."
        rows: list[tuple[str, Optional[str]]] = []
        next_oid = base_oid
        # One engine for the whole walk (it issues several GETBULKs in sequence).
        engine = SnmpEngine()

        while True:
            error_indication, error_status, _idx, var_binds = await bulk_cmd(
                engine,
                self._auth,
                transport,
                self._context,
                0,
                max_repetitions,
                ObjectType(ObjectIdentity(next_oid)),
            )

            if error_indication or error_status or not var_binds:
                break

            ended = False
            for oid, value in var_binds:
                oid_str = str(oid)
                # Left the subtree, or end-of-MIB sentinel -> walk is done.
                if not oid_str.startswith(prefix):
                    ended = True
                    break
                if value.__class__.__name__ == "EndOfMibView":
                    ended = True
                    break
                rows.append((oid_str, _render_value(value)))
                next_oid = oid_str

            if ended:
                break

        return rows
