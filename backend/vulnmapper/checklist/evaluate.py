"""Evaluates the configuration checks for one polled device (``DeviceChecker``)
from the config_data the crawl read. Called by the checklist stage, and by
the attack-path engine for a device's routed VLANs (``l3_vlans``).
"""

from __future__ import annotations

import re
from typing import Optional

from . import tables as t
from .catalogue import CATALOGUE, references_for

# Each check ends in exactly one result, and missing data is never a pass:
#   pass            the data was read and the device complies
#   fail            the data was read and the device does not comply
#   not_applicable  the check does not apply to this kind of device or vendor
#   unknown         the check applies but the data could not be read
#   not_checked     the owner did not enable it (the default-community probe)
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
    """``(sorted ifIndexes, None)``, or ``(None, reason)`` when they cannot be told.

    Every port check uses this one definition: a physical Ethernet port that
    is a switch port and not an uplink. On Cisco the VLAN membership table
    (which lists access ports and leaves trunks out) decides "switch port";
    elsewhere being a bridge port does. VLAN interfaces, port channels,
    loopbacks, radios and routed or management-only ports fall out by type or
    because they are no switch port.
    """
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


# Layer-3 interface names that carry a VLAN number, as the captures show them:
# Cisco "Vlan99" (ifName "Vl99"), Comware "Vlan-interface99", and a routed
# sub-interface "GigabitEthernet0.99" / "Dot11Radio0.80" (by convention the
# sub-interface number is the VLAN).
L3_VLAN_NAMES = (
    re.compile(r"^(?:vlan-interface|vlan|vl)\s*(\d+)$", re.I),
    re.compile(r"^[a-z][a-z0-9-]*?\s*[\d/]+\.(\d+)$", re.I),
)


def l3_vlans(config: Optional[dict]) -> set:
    """VLANs a device has an up layer-3 interface for, from its interface names."""
    out = set()
    for x in ((config or {}).get("interfaces") or {}).values():
        if x["oper"] != t.UP:
            continue
        for pattern in L3_VLAN_NAMES:
            match = pattern.match(str(x["name"]).strip())
            if match and 1 <= int(match.group(1)) <= 4094:
                out.add(int(match.group(1)))
                break
    return out


class DeviceChecker:
    """The configuration checks for one polled device.

    Holds what every check reads: the device's node (role, vendor, uplinks),
    its ``config_data`` (normalised), the access ports and the scan's options.
    Each check is a method returning ``(result, reason, evidence)``;
    ``evaluate`` runs the catalogue and returns the device's results.
    """

    def __init__(self, node: dict, config: Optional[dict], probe_enabled: bool,
                 family: Optional[str] = None, port_test: bool = False, vlans_in_use=()) -> None:
        self.node = node
        self.role, self.vendor = node.get("role"), node.get("vendor")
        self.config = normalise(config)
        self.probe_enabled = probe_enabled
        self.family = family
        self.port_test = port_test
        self.vlans_in_use = vlans_in_use
        # Why no check can read anything, if that is the case.
        self.missing = ("configuration data was not collected" if self.config is None
                        else "reading the configuration tables failed" if self.config.get("failed")
                        else None)
        self.ports, self.port_reason = (None, self.missing) if self.missing else \
            access_ports(self.config, node.get("uplink_ports"), self.vendor)

    def _port_name(self, if_index: int) -> str:
        return self.config["interfaces"][if_index]["name"]

    def _vlan_of(self) -> dict:
        """``{ifIndex: VLAN}`` for the access ports (empty when not read)."""
        config = self.config
        if self.vendor == "Cisco" and config.get("vm_vlan"):
            return dict(config["vm_vlan"])
        if config.get("pvid") and config.get("bridge_ports"):
            return {config["bridge_ports"][bp]: v for bp, v in config["pvid"].items()
                    if bp in config["bridge_ports"]}
        return {}

    # ---- checks on the whole device ------------------------------------------------

    def telnet(self):
        return self._tcp_port(23)

    def http(self):
        return self._tcp_port(80)

    def _tcp_port(self, port: int):
        config = self.config
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
                             + ("connection test results were not collected" if self.port_test
                                else "connection test is not enabled")), None
        if port in tcp["ports"]:
            return FAIL, None, {"port": port}
        return PASS, None, None

    def snmp_no_auth(self):
        version = (self.config.get("snmp") or {}).get("version")
        if version is None:
            return UNKNOWN, "the SNMP version in use is not known", None
        if version in ("v1", "v2c"):
            return FAIL, None, {"snmp_version": version}
        return PASS, None, None

    def default_community(self):
        name = (self.config.get("snmp") or {}).get("default_name")
        if name:
            return FAIL, None, {"communities": [name], "found_by": "the scan's own credential"}
        probe = self.config.get("probe")
        if probe is None:
            if self.probe_enabled:
                return UNKNOWN, "the probe results were not collected", None
            return NOT_CHECKED, "probe not enabled", None
        answered = [n for n in ("public", "private") if probe.get(n)]
        if answered:
            return FAIL, None, {"communities": answered, "found_by": "the default-name probe"}
        return PASS, None, None

    # ---- checks on the access ports ------------------------------------------------

    def spare_ports(self):
        """Spare access ports (no link since the device booted) in a VLAN in use.

        A VLAN is in use when one of the device's access ports in it has a link,
        when it is in ``vlans_in_use`` (a host was learned on it, or a polled
        device has an up layer-3 interface for it), or when it is VLAN 1. Any
        other VLAN is taken for an unused (parking) VLAN, and the evidence lists
        them, on a pass too. A port that lost its link after boot may be a PC
        that is switched off: it is not counted, only reported. Whether a spare
        port is shut down does not change the result.
        """
        vlan_of = self._vlan_of()
        if not vlan_of:
            return UNKNOWN, "the VLAN of each port was not read", None
        ports = self.ports
        ifs, uptime = self.config["interfaces"], self.config.get("uptime")
        no_link = [i for i in ports if ifs[i]["oper"] in NO_LINK]
        spare, recent, unclear = [], 0, 0
        for i in no_link:
            last = ifs[i]["last_change"]
            if uptime is None or last is None or last > uptime:
                unclear += 1
            elif last <= BOOT_WINDOW_S * 100:
                spare.append(i)
            else:
                recent += 1
        in_use = {DEFAULT_VLAN, *(self.vlans_in_use or ()), *l3_vlans(self.config)}
        in_use |= {vlan_of[i] for i in ports if ifs[i]["oper"] == t.UP and vlan_of.get(i)}
        unused = sorted({vlan_of[i] for i in ports if vlan_of.get(i)} - in_use)
        found = [i for i in spare if vlan_of.get(i) in in_use]
        if found:
            enabled = sum(ifs[i]["admin"] == t.UP for i in found)
            return FAIL, None, {
                "ports": [{"port": self._port_name(i), "vlan": vlan_of[i]}
                          for i in found[:EVIDENCE_CAP]],
                "total": len(found), "enabled": enabled, "shut_down": len(found) - enabled,
                "down_recently_not_counted": recent, "unused_vlans": unused}
        if any(ifs[i]["oper"] is None for i in ports) or unclear \
                or any(not vlan_of.get(i) for i in spare):
            return UNKNOWN, "port state, time of last change or VLAN was not read for every " \
                            "access port", None
        return PASS, None, {"unused_vlans": unused}

    def default_vlan(self):
        vlan_of = self._vlan_of()
        if not vlan_of:
            return UNKNOWN, "the VLAN of each port was not read", None
        ports, ifs = self.ports, self.config["interfaces"]
        in_default = [i for i in ports if vlan_of.get(i) == DEFAULT_VLAN]
        unknown = [i for i in ports if not vlan_of.get(i)]       # missing or 0
        if in_default:
            # ports with a host attached first, then the unused ones
            linked = [i for i in in_default if ifs[i]["oper"] == t.UP]
            ordered = linked + [i for i in in_default if i not in linked]
            return FAIL, None, _evidence_ports([self._port_name(i) for i in ordered],
                                               {"with_link": len(linked)})
        if unknown:
            return UNKNOWN, "the VLAN of some access ports was not read", None
        return PASS, None, None

    def bpdu_guard(self):
        bpdu = self.config.get("bpdu")
        if bpdu is None:
            return UNKNOWN, "the spanning-tree extension table was not read", None
        ports = self.ports
        states = {bp: t.bpdu_guard_on(bpdu, bp) for bp in bpdu["ports"]}
        if len(set(states.values())) == 1:
            # every bridge port alike, so every access port is too
            state = next(iter(states.values()))
            per_port = {i: state for i in ports}
        else:
            to_bp = {}
            for bp, if_index in {**(self.config.get("bridge_ports") or {}),
                                 **(bpdu.get("port_ifindex") or {})}.items():
                to_bp[if_index] = bp
            per_port = {i: states.get(to_bp[i]) if i in to_bp else None for i in ports}
        off = [i for i in ports if per_port[i] is False]
        if off:
            return FAIL, None, _evidence_ports([self._port_name(i) for i in off])
        if any(per_port[i] is None for i in ports):
            return UNKNOWN, "BPDU guard could not be read for every access port", None
        return PASS, None, None

    def port_security(self):
        ps = self.config.get("port_security")
        if ps is None or ps["global"] is None:
            return UNKNOWN, "the port security table was not read", None
        ports = self.ports
        off = [i for i in ports if i in ps["ports"] and not (ps["global"] and ps["ports"][i])]
        if off:
            return FAIL, None, _evidence_ports([self._port_name(i) for i in off])
        if any(i not in ps["ports"] for i in ports):
            return UNKNOWN, "port security was not read for every access port", None
        return PASS, None, None

    # ---- the catalogue -------------------------------------------------------------

    # Check id -> the method that runs it. The port checks need the access
    # ports, so they are only run once those are known.
    DEVICE_CHECKS = {
        "mgmt-telnet-enabled": telnet,
        "mgmt-http-enabled": http,
        "snmp-no-auth": snmp_no_auth,
        "snmp-default-community": default_community,
    }
    PORT_CHECKS = {
        "spare-ports-in-used-vlan": spare_ports,
        "access-ports-default-vlan": default_vlan,
        "bpdu-guard-missing": bpdu_guard,
        "port-security-disabled": port_security,
    }

    def _not_applicable(self, check: dict) -> Optional[str]:
        roles = check["applies_to"]["roles"]
        if roles != "any" and self.role not in roles:
            return "applies to switches"
        vendors = check["applies_to"]["vendors"]
        if vendors and self.vendor not in vendors:
            return "no data source for this vendor"
        return None

    def _run(self, check: dict) -> tuple:
        """``(result, reason, evidence)`` for one catalogue check."""
        reason = self._not_applicable(check)
        if reason:
            return NOT_APPLICABLE, reason, None
        if self.missing:
            return UNKNOWN, self.missing, None
        if check["id"] in self.DEVICE_CHECKS:
            return self.DEVICE_CHECKS[check["id"]](self)
        if self.ports is None:
            return UNKNOWN, self.port_reason, None
        return self.PORT_CHECKS[check["id"]](self)

    def _finding(self, check: dict, evidence: Optional[dict]) -> dict:
        refs = [{k: v for k, v in r.items() if k != "scope"}
                for r in references_for(check, self.family)]
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

    def evaluate(self) -> dict:
        """``{config_checks, config_findings, config_summary}`` for the device."""
        checks, findings = [], []
        for check in CATALOGUE:
            result, reason, evidence = self._run(check)
            entry = {"id": check["id"], "title": check["title"], "result": result}
            if result not in (PASS, FAIL) and reason:
                entry["reason"] = reason
            if result == PASS and evidence:      # what a pass assumed (unused VLANs)
                entry.update(evidence)
            checks.append(entry)
            if result == FAIL:
                findings.append(self._finding(check, evidence))

        results = {r: sum(c["result"] == r for c in checks) for r in RESULTS}
        by_severity = {s: sum(f["severity"] == s for f in findings) for s in ("high", "medium", "low")}
        by_severity["advisory"] = sum(f["severity"] is None for f in findings)
        return {
            "config_checks": checks,
            "config_findings": findings,
            "config_summary": {"checks": len(checks), "results": results, "findings": by_severity},
        }


def evaluate_device(node: dict, config: Optional[dict], probe_enabled: bool,
                    family: Optional[str] = None, port_test: bool = False,
                    vlans_in_use=()) -> dict:
    """``{config_checks, config_findings, config_summary}`` for one polled device.

    ``node`` is the graph's device node (role, vendor, uplink_ports); ``config``
    the crawl's ``config_data`` (None: not collected); ``vlans_in_use`` the VLANs
    in use anywhere in the graph (hosts learned on them, up layer-3 interfaces).
    """
    return DeviceChecker(node, config, probe_enabled, family, port_test, vlans_in_use).evaluate()
