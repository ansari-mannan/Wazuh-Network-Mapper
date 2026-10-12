"""What the crawl records: the credentials it tries, the devices it finds and
the links between them. Plain dataclasses; ``Device.to_node`` is the shape of
a node in the network document the assembler reads.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

# discovery_method of a seed or a device first reached through an LLDP
# neighbour entry, and of one first reached through a CDP entry.
DISCOVERY_METHOD = "snmp_lldp"
DISCOVERY_METHOD_CDP = "snmp_cdp"

STATUS_ONLINE = "online"            # polled over SNMP
STATUS_UNREACHABLE = "unreachable"  # tried, but no credential worked
STATUS_DISCOVERED = "discovered"    # known only from a neighbour table


@dataclass
class Credential:
    """One SNMP credential the operator supplied, to try against each device.

    Credentials are never guessed. ``label`` names one in the logs without
    its community string or keys.
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
        if self.version == "v3":
            return f"v3#{self.index}(user={self.user})"
        return f"v2c#{self.index}"


@dataclass
class Device:
    """A switch, router or access point, keyed on its chassis id.

    A device is either polled (``pollable``, status online) or only seen in a
    neighbour's table, without a usable address or a working credential.
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
    # Forwarding-table rows [{mac, port, vlan}] read from this switch.
    fdb: list = field(default_factory=list)
    # Three port lists that must not be confused:
    #   neighbor_ports: every local port with any neighbour (for display);
    #   uplink_ports:   the subset facing infrastructure (a switch, router or
    #                   polled device, never an end host). Host placement
    #                   ignores MACs learned on these, so an access port with
    #                   a station behind it must not be in here;
    #   port_status:    port name -> "up"/"down" from ifOperStatus.
    neighbor_ports: list = field(default_factory=list)
    uplink_ports: list = field(default_factory=list)
    port_status: dict = field(default_factory=dict)
    # The LLDP capability bitmap advertised for this device; the assembler
    # decodes it into a role.
    lldp_cap_enabled: Optional[str] = None
    # {mac: ip} from the ARP table, and the device's own interface MACs, which
    # keep its SVI and gateway MACs from turning into hosts.
    arp: dict = field(default_factory=dict)
    own_macs: list = field(default_factory=list)
    # The platform string a neighbour's CDP table gave for this device.
    platform: Optional[str] = None
    # A wireless access point, and its associated clients
    # [{mac, ip, ssid, radio, vlan}] (None when there is no table to read).
    access_point: bool = False
    wifi_clients: Optional[list] = None
    # The software family found when it was identified ("cisco_ios", ...).
    software_family: Optional[str] = None
    # What the configuration checks read, when the checklist is on. The
    # pipeline evaluates it; it never reaches the graph.
    config_data: Optional[dict] = None

    def to_node(self) -> dict:
        """The network-document node (field order is part of the format).

        Fields only CDP or wireless discovery fill are left out when unset, so
        a network without either gives the same document as before they existed.
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
    """One device's report of a neighbour on ``local_port``.

    The other end usually reports the same cable back; the document builder
    merges the two directions into one edge.
    """

    source_chassis_id: str
    target_chassis_id: str
    local_port: Optional[str] = None
    remote_port: Optional[str] = None
    protocol: str = "lldp"          # the neighbour table that reported it
