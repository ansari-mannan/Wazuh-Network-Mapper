"""Reading SNMP tables into plain Python values, one module per MIB family:

  text      chassis ids, whitespace and OID index helpers the others share
  bridge    forwarding table, ARP, interface names, MACs and link state
  lldp      LLDP neighbours, and port ids that arrive as a MAC or a number
  cdp       Cisco CDP neighbours, as the same records as LLDP
  wifi      wireless access points and their associated clients
  collect   the SNMP walks that feed the parsers (the only module doing I/O)

Callers import from ``vulnmapper.network.parse``; everything public is here.
"""

from .text import (
    collapse_whitespace,
    index_after,
    mac_from_decimal_octets,
    normalize_chassis_id,
    normalize_mac,
    octets,
)
from .bridge import (
    ARP_BASE,
    DOT1D_BASEPORT_IFINDEX_BASE,
    DOT1D_FDB_PORT_BASE,
    DOT1Q_FDB_PORT_BASE,
    DOT1Q_VLAN_STATIC_NAME_BASE,
    IFDESCR_BASE,
    IFNAME_BASE,
    IFOPERSTATUS_BASE,
    IFPHYS_BASE,
    VTP_VLAN_STATE_BASE,
    assemble_dot1d_per_vlan,
    build_fdb,
    build_port_status,
    parse_arp,
    parse_baseport_ifindex,
    parse_dot1d_fdb,
    parse_dot1q_fdb,
    parse_ifnames,
    parse_ifphys_ifindex,
    parse_oper_status,
    parse_own_macs,
    parse_vlan_static_names,
    parse_vtp_vlans,
    resolve_port,
)
from .lldp import (
    LLDP_LOC_PORT_BASE,
    LLDP_REM_BASE,
    LLDP_REM_MAN_ADDR_BASE,
    build_neighbors,
    needs_port_resolution,
    Neighbor,
    normalize_local_port,
    normalize_neighbor_ports,
    parse_loc_port_table,
    parse_man_addr_table,
    parse_rem_table,
)
from .cdp import (
    CDP_CACHE_BASE,
    CDP_CAP_HOST,
    CDP_CAP_PHONE,
    CDP_CAP_REPEATER,
    CDP_CAP_ROUTER,
    CDP_CAP_SR_BRIDGE,
    CDP_CAP_SWITCH,
    CDP_CAP_TRANS_BRIDGE,
    cdp_is_infrastructure,
    parse_cdp_cache,
    translate_cdp_capabilities,
)
from .wifi import (
    DOT11_ACTIVE_CLIENTS_BASE,
    DOT11_CLIENT_BASE,
    DOT11_CLIENT_IP_COL,
    DOT11_CLIENT_PARENT_COL,
    DOT11_CLIENT_VLAN_COL,
    looks_like_access_point,
    parse_wifi_clients,
)
from .collect import (
    MAC_LOOKUP_BATCH,
    collect_arp,
    collect_fdb,
    collect_ifindex_by_mac,
    collect_ifname_map,
    collect_own_macs,
    collect_port_status,
    collect_wifi_clients,
    lookup_fdb_ports,
)
