"""Dataclasses for the crawl: credentials, device nodes, and link edges.

The node schema deliberately matches the device schema used elsewhere in the
project (``ip, hostname, vendor, model, firmware, serial, mac,
discovery_method, status``) and adds the two fields the LLDP crawler needs to
carry through: ``chassis_id`` (the stable hardware join key) and ``pollable``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

# discovery_method value stamped on every node this tool emits.
DISCOVERY_METHOD = "snmp_lldp"

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

    def to_node(self) -> dict:
        """Render to the output node schema (field order is intentional)."""
        return {
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
        }


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
