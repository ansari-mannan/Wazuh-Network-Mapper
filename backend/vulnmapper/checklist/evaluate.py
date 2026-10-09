"""Evaluate the configuration checks for one polled device. Pure functions.

Each check ends in exactly one result:

  pass            the data was read and the device complies
  fail            the data was read and the device does not comply
  not_applicable  the check does not apply to this kind of device or vendor
  unknown         the check applies but the data could not be read
  not_checked     the owner did not enable it (the default-community probe)

Missing data is never a pass. One definition of an access port is used by
every port check (:func:`access_ports`): a physical Ethernet port that is a
switch port and not an uplink. On Cisco, membership in the VLAN membership
table (which lists access ports and leaves trunks out) decides "switch port";
elsewhere, being a bridge port does. VLAN interfaces, port channels,
loopbacks, null, radio and routed or management-only ports fall out because
of their type or because they are not switch ports.
"""

from __future__ import annotations

import re
from typing import Optional

from . import tables as t
from .catalogue import CATALOGUE, SWITCH_ROLES, references_for

PASS, FAIL, NOT_APPLICABLE, UNKNOWN, NOT_CHECKED = (
    "pass", "fail", "not_applicable", "unknown", "not_checked")
RESULTS = (PASS, FAIL, NOT_APPLICABLE, UNKNOWN, NOT_CHECKED)

EVIDENCE_CAP = 20
# A port whose last change is within this many seconds of the device starting
# has had no link since the device booted.
BOOT_WINDOW_S = 300
# ifOperStatus values that mean "no link": down(2), notPresent(6),
# lowerLayerDown(7).
NO_LINK = frozenset({2, 6, 7})
DEFAULT_VLAN = 1


def port_key(name: str):
    """Compare port names whatever their form: "FastEthernet1/0/3" = "Fa1/0/3"."""
    match = re.match(r"\s*([A-Za-z][A-Za-z-]*)\s*(.*)", str(name or ""))
    if not match:
        return (str(name).lower(), "")
    return (match.group(1)[:2].lower(), match.group(2).strip())


def _intkeys(d) -> Optional[dict]:
    """JSON turns int keys into strings; make them ints again."""
    if d is None:
        return None
    return {int(k): v for k, v in d.items()}


def normalise(config: Optional[dict]) -> Optional[dict]:
    """``config_data`` as read from a JSON file (string keys) or straight from the crawl."""
    if not config or config.get("failed"):
        return config
    c = dict(config)
    c["interfaces"] = _intkeys(c.get("interfaces"))
    for key in ("bridge_ports", "pvid", "vm_vlan", "connect"):
        c[key] = _intkeys(c.get(key))
    if c.get("port_security"):
        c["port_security"] = dict(c["port_security"], ports=_intkeys(c["port_security"]["ports"]))
    if c.get("bpdu"):
        b = dict(c["bpdu"], ports=_intkeys(c["bpdu"]["ports"]))
        if b.get("port_ifindex") is not None:
            b["port_ifindex"] = _intkeys(b["port_ifindex"])
        c["bpdu"] = b
    return c


def _evidence_ports(names: list, extra: Optional[dict] = None) -> dict:
    out = {"ports": names[:EVIDENCE_CAP], "total": len(names)}
    out.update(extra or {})
    return out


def access_ports(config: dict, uplinks, vendor: Optional[str]):
    """``(sorted ifIndexes, None)`` or ``(None, reason)`` when they cannot be told."""
    ifs = config.get("interfaces")
    if not ifs:
        return None, "the interface table was not read"
    if vendor == "Cisco":
        members = set(config["vm_vlan"]) if config.get("vm_vlan") else None
        if members is None:
            return None, "the VLAN membership table was not read"
    else:
        members = set(config["bridge_ports"].values()) if config.get("bridge_ports") else None
        if members is None:
            return None, "the bridge port table was not read"
    up = {port_key(u) for u in uplinks or []}
    return sorted(i for i, x in ifs.items()
                  if x["type"] in t.ETHERNET_TYPES and i in members
                  and port_key(x["name"]) not in up), None


def _name(config: dict, if_index: int) -> str:
    return config["interfaces"][if_index]["name"]


# --- the checks -----------------------------------------------------------------
# Each returns (result, reason, evidence).

def _tcp_port(config: dict, port: int, port_test: bool):
    tcp = config.get("tcp")
    if tcp is None:
        return UNKNOWN, "the TCP tables were not read", None
    if not tcp["read"]:
        outcome = (config.get("connect") or {}).get(port)
        if outcome == "accepted":
            return FAIL, None, {"port": port, "found_by": "the port answered a connection test"}
        if outcome == "refused":
            return PASS, None, None
        if outcome == "no_answer":
            return UNKNOWN, "no answer from the scanner's position", None
        return UNKNOWN, ("the device does not list its TCP listeners over SNMP, and the "
                         + ("connection test results were not collected" if port_test
                            else "connection test is not enabled")), None
    if port in tcp["ports"]:
        return FAIL, None, {"port": port}
    return PASS, None, None


def _snmp_no_auth(config: dict):
    version = (config.get("snmp") or {}).get("version")
    if version is None:
        return UNKNOWN, "the SNMP version in use is not known", None
    if version in ("v1", "v2c"):
        return FAIL, None, {"snmp_version": version}
    return PASS, None, None


def _default_community(config: dict, probe_enabled: bool):
    name = (config.get("snmp") or {}).get("default_name")
    if name:
        return FAIL, None, {"communities": [name], "found_by": "the scan's own credential"}
    probe = config.get("probe")
    if probe is None:
        if probe_enabled:
            return UNKNOWN, "the probe results were not collected", None
        return NOT_CHECKED, "probe not enabled", None
    answered = [n for n in ("public", "private") if probe.get(n)]
    if answered:
        return FAIL, None, {"communities": answered, "found_by": "the default-name probe"}
    return PASS, None, None


def _unused_ports(config: dict, ports: list):
    ifs = config["interfaces"]
    unknown = [i for i in ports if ifs[i]["admin"] is None or ifs[i]["oper"] is None]
    unused = [i for i in ports if i not in unknown
              and ifs[i]["admin"] == t.UP and ifs[i]["oper"] in NO_LINK]
    if unused:
        uptime = config.get("uptime")
        boot, later = 0, 0
        for i in unused:
            last = ifs[i]["last_change"]
            if uptime is None or last is None or last > uptime:
                continue
            if last <= BOOT_WINDOW_S * 100:
                boot += 1
            else:
                later += 1
        return FAIL, None, _evidence_ports([_name(config, i) for i in unused],
                                           {"down_since_boot": boot, "down_later": later})
    if unknown:
        return UNKNOWN, "port state was not read for every access port", None
    return PASS, None, None


def _default_vlan(config: dict, ports: list, vendor: Optional[str]):
    vlan_of: dict = {}
    if vendor == "Cisco" and config.get("vm_vlan"):
        vlan_of = dict(config["vm_vlan"])
    elif config.get("pvid") and config.get("bridge_ports"):
        vlan_of = {config["bridge_ports"][bp]: v for bp, v in config["pvid"].items()
                   if bp in config["bridge_ports"]}
    if not vlan_of:
        return UNKNOWN, "the VLAN of each port was not read", None
    ifs = config["interfaces"]
    in_default = [i for i in ports if vlan_of.get(i) == DEFAULT_VLAN]
    unknown = [i for i in ports if not vlan_of.get(i)]       # missing or 0
    if in_default:
        # ports with a host attached first, then the unused ones
        linked = [i for i in in_default if ifs[i]["oper"] == t.UP]
        ordered = linked + [i for i in in_default if i not in linked]
        return FAIL, None, _evidence_ports([_name(config, i) for i in ordered],
                                           {"with_link": len(linked)})
    if unknown:
        return UNKNOWN, "the VLAN of some access ports was not read", None
    return PASS, None, None


def _bpdu_guard(config: dict, ports: list):
    bpdu = config.get("bpdu")
    if bpdu is None:
        return UNKNOWN, "the spanning-tree extension table was not read", None
    states = {bp: t.bpdu_guard_on(bpdu, bp) for bp in bpdu["ports"]}
    if len(set(states.values())) == 1:
        # every bridge port alike, so every access port is too
        state = next(iter(states.values()))
        per_port = {i: state for i in ports}
    else:
        to_bp = {}
        for bp, if_index in {**(config.get("bridge_ports") or {}),
                             **(bpdu.get("port_ifindex") or {})}.items():
            to_bp[if_index] = bp
        per_port = {i: states.get(to_bp[i]) if i in to_bp else None for i in ports}
    off = [i for i in ports if per_port[i] is False]
    if off:
        return FAIL, None, _evidence_ports([_name(config, i) for i in off])
    if any(per_port[i] is None for i in ports):
        return UNKNOWN, "BPDU guard could not be read for every access port", None
    return PASS, None, None


def _port_security(config: dict, ports: list):
    ps = config.get("port_security")
    if ps is None or ps["global"] is None:
        return UNKNOWN, "the port security table was not read", None
    off = [i for i in ports if i in ps["ports"] and not (ps["global"] and ps["ports"][i])]
    if off:
        return FAIL, None, _evidence_ports([_name(config, i) for i in off])
    if any(i not in ps["ports"] for i in ports):
        return UNKNOWN, "port security was not read for every access port", None
    return PASS, None, None


# --- one device -------------------------------------------------------------------

def _applies(check: dict, role: Optional[str], vendor: Optional[str]):
    roles = check["applies_to"]["roles"]
    if roles != "any" and role not in roles:
        return "applies to switches"
    vendors = check["applies_to"]["vendors"]
    if vendors and vendor not in vendors:
        return "no data source for this vendor"
    return None


def _finding(check: dict, family: Optional[str], evidence: Optional[dict]) -> dict:
    refs = [{k: v for k, v in r.items() if k != "scope"} for r in references_for(check, family)]
    return {
        "id": check["id"],
        "title": check["title"],
        "severity": check["severity"],
        "why": check["why"],
        "remediation": check["remediation"],
        "references": refs,
        "cwe": check["cwe"],
        "evidence": evidence,
    }


def evaluate_device(node: dict, config: Optional[dict], probe_enabled: bool,
                    family: Optional[str] = None, port_test: bool = False) -> dict:
    """``{config_checks, config_findings, config_summary}`` for one polled device.

    ``node`` is the graph's device node (role, vendor, uplink_ports); ``config``
    the crawl's ``config_data`` (None: not collected).
    """
    role, vendor = node.get("role"), node.get("vendor")
    config = normalise(config)
    missing = ("configuration data was not collected" if config is None
               else "reading the configuration tables failed" if config.get("failed")
               else None)
    ports, port_reason = (None, missing) if missing else \
        access_ports(config, node.get("uplink_ports"), vendor)

    checks, findings = [], []
    for check in CATALOGUE:
        reason = _applies(check, role, vendor)
        if reason:
            result, evidence = NOT_APPLICABLE, None
        elif missing:
            result, reason, evidence = UNKNOWN, missing, None
        elif check["id"] == "mgmt-telnet-enabled":
            result, reason, evidence = _tcp_port(config, 23, port_test)
        elif check["id"] == "mgmt-http-enabled":
            result, reason, evidence = _tcp_port(config, 80, port_test)
        elif check["id"] == "snmp-no-auth":
            result, reason, evidence = _snmp_no_auth(config)
        elif check["id"] == "snmp-default-community":
            result, reason, evidence = _default_community(config, probe_enabled)
        elif ports is None:
            result, reason, evidence = UNKNOWN, port_reason, None
        elif check["id"] == "ports-enabled-unused":
            result, reason, evidence = _unused_ports(config, ports)
        elif check["id"] == "access-ports-default-vlan":
            result, reason, evidence = _default_vlan(config, ports, vendor)
        elif check["id"] == "bpdu-guard-missing":
            result, reason, evidence = _bpdu_guard(config, ports)
        else:
            result, reason, evidence = _port_security(config, ports)
        entry = {"id": check["id"], "title": check["title"], "result": result}
        if result not in (PASS, FAIL) and reason:
            entry["reason"] = reason
        checks.append(entry)
        if result == FAIL:
            findings.append(_finding(check, family, evidence))

    results = {r: sum(c["result"] == r for c in checks) for r in RESULTS}
    by_severity = {s: sum(f["severity"] == s for f in findings) for s in ("high", "medium", "low")}
    by_severity["advisory"] = sum(f["severity"] is None for f in findings)
    return {
        "config_checks": checks,
        "config_findings": findings,
        "config_summary": {"checks": len(checks), "results": results, "findings": by_severity},
    }
