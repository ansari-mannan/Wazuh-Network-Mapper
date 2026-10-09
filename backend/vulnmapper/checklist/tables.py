"""The SNMP tables the configuration checks read, and their parsers.

Every column below was resolved from its MIB definition (TCP-MIB, IF-MIB,
BRIDGE-MIB, Q-BRIDGE-MIB, CISCO-VLAN-MEMBERSHIP-MIB, CISCO-PORT-SECURITY-MIB,
CISCO-STP-EXTENSIONS-MIB) and confirmed against captures from real devices.
Each table is read as a column walk; the parsers are pure, so they are tested
against captured rows.

What the crawl keeps per device (``config_data`` on the crawl's own node, never
on the graph) is the compact, already-parsed result:

  snmp:        {"version": "v2c" | "v3" | None, "default_name": "public" | ...}
  probe:       None, or {"public": answered, "private": answered}
  uptime:      sysUpTime in hundredths of a second
  tcp:         {"read": bool, "ports": [local TCP ports in use or listening]}
  interfaces:  {ifIndex: {name, type, admin, oper, last_change}}
  bridge_ports {bridge port: ifIndex} (default context)
  pvid:        {bridge port: VLAN} (802.1Q)
  vm_vlan:     {ifIndex: VLAN} for Cisco access ports (trunks are not listed)
  port_security {"global": bool | None, "ports": {ifIndex: bool}}
  bpdu:        {"global_guard": bool | None, "global_portfast": int | None,
                "ports": {bridge port: {"portfast": mode, "guard": mode}},
                "port_ifindex": {bridge port: ifIndex} when it had to be read}

An empty or missing table is recorded as None (not read), never as "nothing
configured".
"""

from __future__ import annotations

from typing import Optional

# --- TCP-MIB ---------------------------------------------------------------
# tcpConnState: index <localAddr 4>.<localPort>.<remAddr 4>.<remPort>
TCP_CONN_STATE = "1.3.6.1.2.1.6.13.1.1"
# tcpListenerProcess, the only readable column of tcpListenerTable: index
# <addrType>.<addrLen>.<addr...>.<localPort>
TCP_LISTENER_PROCESS = "1.3.6.1.2.1.6.20.1.4"

# --- system / IF-MIB ---------------------------------------------------------
SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
SYS_NAME = "1.3.6.1.2.1.1.5.0"
IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
IF_TYPE = "1.3.6.1.2.1.2.2.1.3"
IF_ADMIN_STATUS = "1.3.6.1.2.1.2.2.1.7"
IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"
IF_LAST_CHANGE = "1.3.6.1.2.1.2.2.1.9"
IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"

# --- BRIDGE-MIB / Q-BRIDGE-MIB ----------------------------------------------
DOT1D_BASE_PORT_IFINDEX = "1.3.6.1.2.1.17.1.4.1.2"
DOT1Q_PVID = "1.3.6.1.2.1.17.7.1.4.5.1.1"

# --- Cisco -------------------------------------------------------------------
VM_VLAN = "1.3.6.1.4.1.9.9.68.1.2.2.1.2"                 # vmVlan, index ifIndex
CPS_GLOBAL_ENABLE = "1.3.6.1.4.1.9.9.315.1.1.3.0"        # cpsGlobalPortSecurityEnable
CPS_IF_ENABLE = "1.3.6.1.4.1.9.9.315.1.2.1.1.1"          # cpsIfPortSecurityEnable, ifIndex
STPX_BPDU_GUARD_GLOBAL = "1.3.6.1.4.1.9.9.82.1.9.1.0"    # stpxFastStartBpduGuardEnable
STPX_FAST_START_DEFAULT = "1.3.6.1.4.1.9.9.82.1.9.4.0"   # stpxFastStartGlobalDefaultMode
STPX_PORT_MODE = "1.3.6.1.4.1.9.9.82.1.9.3.1.3"          # stpxFastStartPortMode, bridge port
STPX_PORT_BPDU_GUARD = "1.3.6.1.4.1.9.9.82.1.9.3.1.4"    # stpxFastStartPortBpduGuardMode

# ifType values that are physical Ethernet ports: ethernetCsmacd(6) and the
# obsolete fastEther(62), fastEtherFX(69), gigabitEthernet(117).
ETHERNET_TYPES = frozenset({6, 62, 69, 117})

# IF-MIB enums
UP, DOWN = 1, 2
# TruthValue
TRUE, FALSE = 1, 2
# stpxFastStartPortMode: enable(1) disable(2) enableForTrunk(3) default(4) network(5)
PORTFAST_ENABLE, PORTFAST_DISABLE, PORTFAST_TRUNK, PORTFAST_DEFAULT = 1, 2, 3, 4
# stpxFastStartPortBpduGuardMode: enable(1) disable(2) default(3)
GUARD_ENABLE, GUARD_DISABLE, GUARD_DEFAULT = 1, 2, 3
# stpxFastStartGlobalDefaultMode: enable(1) disable(2) network(3)
GLOBAL_PORTFAST_ENABLE = 1


def _index(oid: str, base: str) -> Optional[str]:
    prefix = base + "."
    return oid[len(prefix):] if oid.startswith(prefix) else None


def as_int(value) -> Optional[int]:
    try:
        return int(str(value).strip().split("(")[-1].rstrip(")")) if "(" in str(value) \
            else int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _column(rows, base: str) -> dict:
    """``{index: value}`` for one column walk; the value as an int where it is one."""
    out = {}
    for oid, value in rows or []:
        index = _index(oid, base)
        if index is not None:
            out[index] = value
    return out


def _int_column(rows, base: str) -> dict:
    return {k: v for k, v in ((k, as_int(v)) for k, v in _column(rows, base).items())
            if v is not None}


def parse_tcp(conn_rows, listener_rows) -> dict:
    """Local TCP ports a device lists as listening or serving.

    ``read`` is False when neither table has a row: the device does not list
    its TCP sockets, which is not the same as having none.
    """
    ports: set = set()
    for index in _column(conn_rows, TCP_CONN_STATE):
        parts = index.split(".")
        if len(parts) == 10 and parts[4].isdigit():
            ports.add(int(parts[4]))
    for index in _column(listener_rows, TCP_LISTENER_PROCESS):
        last = index.split(".")[-1]
        if last.isdigit():
            ports.add(int(last))
    read = bool(_column(conn_rows, TCP_CONN_STATE) or _column(listener_rows, TCP_LISTENER_PROCESS))
    return {"read": read, "ports": sorted(ports)}


def parse_interfaces(type_rows, admin_rows, oper_rows, last_change_rows,
                     name_rows, descr_rows=None) -> dict:
    """``{ifIndex: {name, type, admin, oper, last_change}}`` (None when not read)."""
    types = _int_column(type_rows, IF_TYPE)
    if not types:
        return None
    admin = _int_column(admin_rows, IF_ADMIN_STATUS)
    oper = _int_column(oper_rows, IF_OPER_STATUS)
    last = _int_column(last_change_rows, IF_LAST_CHANGE)
    names = _column(name_rows, IF_NAME) or _column(descr_rows, IF_DESCR)
    return {int(i): {"name": names.get(i) or i, "type": t, "admin": admin.get(i),
                     "oper": oper.get(i), "last_change": last.get(i)}
            for i, t in types.items() if i.isdigit()}


def parse_index_map(rows, base: str) -> Optional[dict]:
    """``{int index: int value}`` for a one-column table, None when empty."""
    out = {int(k): v for k, v in _int_column(rows, base).items() if k.isdigit()}
    return out or None


def parse_port_security(global_value, rows) -> Optional[dict]:
    ports = parse_index_map(rows, CPS_IF_ENABLE)
    if ports is None:
        return None
    g = as_int(global_value)
    return {"global": None if g is None else g == TRUE,
            "ports": {i: v == TRUE for i, v in ports.items()}}


def parse_bpdu(guard_global, portfast_default, mode_rows, guard_rows) -> Optional[dict]:
    modes = parse_index_map(mode_rows, STPX_PORT_MODE)
    guards = parse_index_map(guard_rows, STPX_PORT_BPDU_GUARD)
    if modes is None and guards is None:
        return None
    g = as_int(guard_global)
    ports = {}
    for bp in sorted(set(modes or {}) | set(guards or {})):
        ports[bp] = {"portfast": (modes or {}).get(bp), "guard": (guards or {}).get(bp)}
    return {"global_guard": None if g is None else g == TRUE,
            "global_portfast": as_int(portfast_default),
            "ports": ports}


def bpdu_guard_on(bpdu: dict, bridge_port: int) -> Optional[bool]:
    """Whether BPDU guard is effective on a bridge port (None: cannot tell).

    Per CISCO-STP-EXTENSIONS-MIB: an explicit enable/disable wins; "default"
    means the global setting applies, and only on a port where port fast is
    operationally on (its own mode enable/enableForTrunk, or default with the
    global port-fast default on).
    """
    port = bpdu["ports"].get(bridge_port)
    if port is None or port["guard"] is None:
        return None
    if port["guard"] == GUARD_ENABLE:
        return True
    if port["guard"] == GUARD_DISABLE:
        return False
    if bpdu["global_guard"] is None:
        return None
    if not bpdu["global_guard"]:
        return False
    mode = port["portfast"]
    if mode in (PORTFAST_ENABLE, PORTFAST_TRUNK):
        return True
    if mode == PORTFAST_DEFAULT:
        if bpdu["global_portfast"] is None:
            return None
        return bpdu["global_portfast"] == GLOBAL_PORTFAST_ENABLE
    return False if mode is not None else None
