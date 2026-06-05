"""Async SNMP wrapper around pysnmp 7.x — the only module that imports pysnmp.

pysnmp 7.x exposes only the asyncio v3arch HLAPI: ``get_cmd`` / ``bulk_cmd`` are
coroutines and even ``UdpTransportTarget.create`` is awaitable. This wrapper
hides that and exposes a small surface:

  * :meth:`resolve_credential` — try the operator-supplied credentials against a
    device once and remember the first that works (no brute-forcing).
  * :meth:`get_many` / :meth:`get` — GET scalars using the device's resolved
    credential.
  * :meth:`walk` — GETBULK-backed table walk.

A *single* shared :class:`SnmpEngine` is reused for the whole crawl. The engine
carries MIB and datastore state and is heavy, so one is built per run and shared
across all workers — never one per target. This is safe here because the crawl
is a bounded worker pool (~32) over the real topology, not a wide sweep of a
whole address space.
"""

from __future__ import annotations

import logging
from typing import Iterable, Optional

from pysnmp.hlapi.v3arch.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    bulk_cmd,
    get_cmd,
    usmAesCfb128Protocol,
    usmAesCfb192Protocol,
    usmAesCfb256Protocol,
    usmDESPrivProtocol,
    usmHMACMD5AuthProtocol,
    usmHMACSHAAuthProtocol,
    usmHMAC192SHA256AuthProtocol,
    usmHMAC256SHA384AuthProtocol,
    usmHMAC384SHA512AuthProtocol,
    usmNoAuthProtocol,
    usmNoPrivProtocol,
)

from models import Credential

log = logging.getLogger("discovery.snmp")

# ---- Common OIDs (exported so nothing else sprinkles magic strings) --------

OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
OID_SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"

# LLDP local device: its own chassis id (the stable hardware identity).
OID_LLDP_LOC_CHASSIS_ID = "1.0.8802.1.1.2.1.3.2.0"
# LLDP local port table — maps local port number -> a human port id.
OID_LLDP_LOC_PORT_TABLE = "1.0.8802.1.1.2.1.3.7.1"
# LLDP remote neighbor table.
OID_LLDP_REM_TABLE = "1.0.8802.1.1.2.1.4.1.1"
# LLDP remote management-address table (carries neighbors' management IPs).
OID_LLDP_REM_MAN_ADDR_TABLE = "1.0.8802.1.1.2.1.4.2.1"

# Sentinel value classes pysnmp returns for absent OIDs / end of a walk.
_ABSENT = ("NoSuchObject", "NoSuchInstance", "EndOfMibView")
# OID-valued types: prettyPrint() does a MIB lookup, but vendor dispatch needs
# the raw numeric form, which str() gives.
_OID_TYPES = ("ObjectIdentity", "ObjectIdentifier", "ObjectName")

_AUTH_PROTOCOLS = {
    "MD5": usmHMACMD5AuthProtocol,
    "SHA": usmHMACSHAAuthProtocol,
    "SHA1": usmHMACSHAAuthProtocol,
    "SHA256": usmHMAC192SHA256AuthProtocol,
    "SHA384": usmHMAC256SHA384AuthProtocol,
    "SHA512": usmHMAC384SHA512AuthProtocol,
    "NONE": usmNoAuthProtocol,
}
_PRIV_PROTOCOLS = {
    "DES": usmDESPrivProtocol,
    "AES": usmAesCfb128Protocol,
    "AES128": usmAesCfb128Protocol,
    "AES192": usmAesCfb192Protocol,
    "AES256": usmAesCfb256Protocol,
    "NONE": usmNoPrivProtocol,
}


def _render_value(value) -> Optional[str]:
    """Render a pysnmp value to a string (or None for an absent OID)."""
    value_type = value.__class__.__name__
    if value_type in _ABSENT:
        return None
    if value_type in _OID_TYPES:
        return str(value)
    return value.prettyPrint()


def _build_auth(cred: Credential):
    """Translate a :class:`Credential` into a pysnmp auth-data object."""
    if cred.version == "v3":
        auth_proto = _AUTH_PROTOCOLS.get((cred.auth_protocol or "NONE").upper())
        priv_proto = _PRIV_PROTOCOLS.get((cred.priv_protocol or "NONE").upper())
        if auth_proto is None:
            raise ValueError(f"unknown v3 auth protocol {cred.auth_protocol!r}")
        if priv_proto is None:
            raise ValueError(f"unknown v3 priv protocol {cred.priv_protocol!r}")
        return UsmUserData(
            cred.user,
            authKey=cred.auth_key,
            privKey=cred.priv_key,
            authProtocol=auth_proto,
            privProtocol=priv_proto,
        )
    # mpModel=1 selects SNMPv2c (0 would be v1); v2c is required for GETBULK.
    return CommunityData(cred.community, mpModel=1)


class SnmpClient:
    """Async SNMP client with a shared engine and per-device credential memory."""

    def __init__(
        self,
        credentials: Iterable[Credential],
        *,
        port: int = 161,
        timeout: float = 1.0,
        retries: int = 1,
    ) -> None:
        self._credentials = list(credentials)
        self._auth_by_cred = {id(c): _build_auth(c) for c in self._credentials}
        self._port = port
        self._timeout = timeout
        self._retries = retries
        self._context = ContextData()
        # One heavy engine for the whole run (see module docstring).
        self._engine = SnmpEngine()
        # Per-IP: the credential that worked, so vendor follow-up GETs reuse it.
        self._resolved: dict[str, Credential] = {}

    async def _transport(self, ip: str):
        # Built per call because the target address differs per device; the
        # create() is async because it resolves the address on the event loop.
        return await UdpTransportTarget.create(
            (ip, self._port), timeout=self._timeout, retries=self._retries
        )

    async def _get_with_auth(
        self, auth, ip: str, oids: list[str]
    ) -> Optional[dict[str, Optional[str]]]:
        transport = await self._transport(ip)
        error_indication, error_status, _error_index, var_binds = await get_cmd(
            self._engine,
            auth,
            transport,
            self._context,
            *[ObjectType(ObjectIdentity(oid)) for oid in oids],
        )
        if error_indication or error_status:
            return None
        result: dict[str, Optional[str]] = {}
        for oid, value in var_binds:
            result[str(oid)] = _render_value(value)
        return result

    async def resolve_credential(self, ip: str) -> Optional[Credential]:
        """Find the first supplied credential that this device answers to.

        Tries each operator-supplied credential exactly once (a single GET of
        sysDescr) — this is *trial of operator-known strings*, never a brute
        force. The winner is cached for ``ip`` so later GETs reuse it. Returns
        None if the device answers none of them (discovered-but-unpollable).
        """
        cached = self._resolved.get(ip)
        if cached is not None:
            return cached
        for cred in self._credentials:
            auth = self._auth_by_cred[id(cred)]
            result = await self._get_with_auth(auth, ip, [OID_SYS_DESCR])
            if result is not None:
                log.debug("%s answered credential %s", ip, cred.label)
                self._resolved[ip] = cred
                return cred
        return None

    async def get_many(
        self, ip: str, oids: Iterable[str]
    ) -> Optional[dict[str, Optional[str]]]:
        """GET one or more OIDs in a single PDU using ``ip``'s resolved credential."""
        cred = self._resolved.get(ip)
        if cred is None:
            return None
        return await self._get_with_auth(self._auth_by_cred[id(cred)], ip, list(oids))

    async def get(self, ip: str, oid: str) -> Optional[str]:
        """GET a single OID; convenience wrapper over :meth:`get_many`."""
        result = await self.get_many(ip, [oid])
        return None if result is None else result.get(oid)

    async def walk(
        self, ip: str, base_oid: str, *, max_repetitions: int = 25
    ) -> list[tuple[str, Optional[str]]]:
        """GETBULK-walk an OID subtree using ``ip``'s resolved credential.

        Returns ``[(oid, value), ...]`` in order, or an empty list if the
        subtree is absent (e.g. a device with no LLDP) or the host stops
        answering — callers treat "no rows" as "no data", never an error.
        """
        cred = self._resolved.get(ip)
        if cred is None:
            return []
        auth = self._auth_by_cred[id(cred)]
        transport = await self._transport(ip)

        prefix = base_oid.rstrip(".") + "."
        rows: list[tuple[str, Optional[str]]] = []
        next_oid = base_oid

        while True:
            error_indication, error_status, _idx, var_binds = await bulk_cmd(
                self._engine,
                auth,
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
