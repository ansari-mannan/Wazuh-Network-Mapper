#!/usr/bin/env python3
"""Phase 0 verification gate for the Comware (HP 1920 / H3C) vendor plugin.

This is a *verification* tool, not part of the pipeline. It polls the live
reference device (the lab HP 1920-48G ``CYFOR-HP-Switch``) and asserts every OID
the planned ``comware.py`` plugin will depend on against the known-good ground
truth in the task spec. It exists to catch a wrong assumption BEFORE any plugin
code is written: a divergence here means the spec is wrong, and the plugin built
on it would be wrong too — so on any FAIL this exits non-zero and you HALT.

Usage::

    python3 tools/verify_comware.py [target] [community] [version]

defaults: 172.20.99.4  cyfor123  v2c

It writes ``tools/comware_verification_report.txt`` with every check + PASS/FAIL
and the resolved mapping tables, and exits non-zero if anything failed.

Design notes
------------
* A single ``SnmpEngine`` is built once and reused for every GET/walk, matching
  the project's snmp_client pattern (the engine is heavy; never one per OID).
* Walks keep the *raw* pysnmp value objects, not pretty-printed strings, because
  several Comware fields can ONLY be read correctly as raw octets:
    - ``lldpRemSysCapEnabled`` 0x28 pretty-prints to the ASCII char ``"("`` and
      would silently decode to no capabilities (the capability-bitmap trap).
    - chassis-ids / port-ids whose subtype is ``macAddress``.
* The project's pure parsers (fdb / lldp / roles) are imported and cross-checked
  so this also proves the existing parsing code already yields the ground truth
  once the walk rows are correct.
"""

from __future__ import annotations

import asyncio
import os
import re
import sys

# Make the project package importable when run from anywhere.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from pysnmp.hlapi.v3arch.asyncio import (  # noqa: E402
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    bulk_walk_cmd,
    get_cmd,
)
from pysnmp.proto import errind  # noqa: E402

from vulnmapper.schema import canonical_mac, format_mac  # noqa: E402
from vulnmapper.network import parse as fdb, parse as lldp  # noqa: E402
from vulnmapper.network.roles import (  # noqa: E402
    decode_capabilities,
    neighbor_is_infrastructure,
    role_from_capabilities,
)

# --- OIDs (no trailing dot for walk bases) ---------------------------------

OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
OID_SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"

IFDESCR = "1.3.6.1.2.1.2.2.1.2"
IFNAME = "1.3.6.1.2.1.31.1.1.1.1"
IFOPERSTATUS = "1.3.6.1.2.1.2.2.1.8"
IFPHYSADDR = "1.3.6.1.2.1.2.2.1.6"

LLDP_LOC_PORT_ID = "1.0.8802.1.1.2.1.3.7.1.3"          # lldpLocPortId
LLDP_LOC_PORT_ID_SUBTYPE = "1.0.8802.1.1.2.1.3.7.1.2"  # lldpLocPortIdSubtype
LLDP_REM = "1.0.8802.1.1.2.1.4.1.1"                    # lldpRemTable
LLDP_REM_MAN_ADDR = "1.0.8802.1.1.2.1.4.2.1"           # lldpRemManAddrTable

DOT1D_BASEPORT_IFINDEX = "1.3.6.1.2.1.17.1.4.1.2"
DOT1Q_FDB_PORT = "1.3.6.1.2.1.17.7.1.2.2.1.2"

COMWARE_ENTERPRISE_PREFIX = "1.3.6.1.4.1.25506"

_VERSION_RE = re.compile(r"Version (\d+\.\d+\.\d+), Release (\d+)")

_ABSENT = {"NoSuchObject", "NoSuchInstance", "EndOfMibView", "Null"}

# Set from CLI in run(); used by the 0.6 project-walk cross-check.
_COMMUNITY = "cyfor123"
# Set from CLI (--capture PATH); when set, a flat fixture is written at the end.
_CAPTURE_PATH = None


# --- value rendering --------------------------------------------------------


def raw_octets(value):
    """Raw bytes of an OctetString-like value, or None for non-octet values."""
    try:
        return bytes(value.asOctets())
    except Exception:
        return None


def to_text(value):
    """Faithful text for display fields; hex for binary OctetStrings.

    NB: a binary octet string that happens to be all-printable (e.g. the 1-byte
    capability map 0x28 == ``"("``) decodes to text here — that is exactly why
    capability/MAC checks below use ``raw_octets`` instead of this.
    """
    cn = value.__class__.__name__
    if cn in _ABSENT:
        return None
    octets = raw_octets(value)
    if octets is not None and cn in ("OctetString", "DisplayString"):
        try:
            return octets.decode("ascii")
        except UnicodeDecodeError:
            return "0x" + octets.hex()
    return value.prettyPrint()


# --- SNMP I/O (single shared engine) ----------------------------------------


class Snmp:
    def __init__(self, target: str, community: str):
        self.target = target
        self.engine = SnmpEngine()
        self.auth = CommunityData(community, mpModel=1)  # v2c, GETBULK-capable
        self.ctx = ContextData()

    async def _transport(self):
        return await UdpTransportTarget.create((self.target, 161), timeout=2.0, retries=2)

    async def get(self, *oids):
        """GET scalars; returns {oid: raw_value_object}. lookupMib=False so OIDs
        render numerically (sysObjectID must be the dotted form)."""
        transport = await self._transport()
        ei, es, _idx, vbs = await get_cmd(
            self.engine, self.auth, transport, self.ctx,
            *[ObjectType(ObjectIdentity(o)) for o in oids],
            lookupMib=False,
        )
        if ei or es:
            raise RuntimeError(f"GET failed: {ei or es}")
        return {str(o): v for o, v in vbs}

    async def walk(self, base, *, ignore_non_increasing=False, lexicographic=False,
                   max_repetitions=25):
        """GETBULK-walk ``base``; returns (rows, aborted_reason).

        ``rows`` is ``[(oid_str, raw_value_object), ...]`` collected before any
        abort. ``aborted_reason`` is a string (e.g. the OidNotIncreasing message)
        when the walk stopped early on an error, else None.

        ``max_repetitions`` matters for the Comware FDB truncation trap: the
        non-increasing-OID abort only fires across a GETBULK *PDU boundary*, so a
        table small enough to fit one PDU never trips it. Lowering this forces the
        boundary and exposes the trap the way the spec describes.
        """
        transport = await self._transport()
        rows: list[tuple[str, object]] = []
        aborted = None
        async for ei, es, _ek, vbs in bulk_walk_cmd(
            self.engine, self.auth, transport, self.ctx, 0, max_repetitions,
            ObjectType(ObjectIdentity(base)),
            lookupMib=False,
            lexicographicMode=lexicographic,
            ignoreNonIncreasingOid=ignore_non_increasing,
        ):
            if ei:
                aborted = ei.__class__.__name__ if isinstance(ei, errind.ErrorIndication) else str(ei)
                break
            if es:
                aborted = f"errorStatus={es.prettyPrint()}"
                break
            for oid, val in vbs:
                rows.append((str(oid), val))
        return rows, aborted


# --- report bookkeeping -----------------------------------------------------


class Report:
    def __init__(self):
        self.lines: list[str] = []
        self.failures = 0
        self.divergences = 0

    def check(self, ok: bool, name: str, detail: str = ""):
        """A VALIDATED-MECHANIC check: this should pass; a FAIL is a real bug
        in our understanding of the protocol/parsing (not a topology change)."""
        status = "PASS" if ok else "FAIL"
        if not ok:
            self.failures += 1
        line = f"[{status}] {name}" + (f" :: {detail}" if detail else "")
        self.lines.append(line)
        print(line)

    def diverge(self, name: str, expected: str, actual: str):
        """A GROUND-TRUTH divergence: the device no longer matches the spec's
        captured state (the lab topology changed). Counts toward HALT, but is
        categorically different from a broken mechanic."""
        self.divergences += 1
        line = f"[DIVERGED] {name}\n           spec : {expected}\n           live : {actual}"
        self.lines.append(line)
        print(line)

    def note(self, text: str):
        line = f"       {text}"
        self.lines.append(line)
        print(line)

    def section(self, title: str):
        bar = "=" * 70
        for line in ("", bar, title, bar):
            self.lines.append(line)
            print(line)


def index_after(oid: str, base: str):
    prefix = base.rstrip(".") + "."
    return oid[len(prefix):] if oid.startswith(prefix) else None


def capture_render(value) -> str:
    """Render a value for the offline fixture in a *parser-faithful* form.

    Text fields (ifName, sysName, sysDescr, an interfaceName port id) stay text;
    MACs, capability bitmaps and other binary octet strings become ``0x<hex>`` so
    the pure parsers and roles.decode_capabilities consume them correctly. This
    deliberately avoids the SNMP printable-octet trap (0x28 -> "(") so the fixture
    carries the capability bytes as raw hex, not the misleading character.
    """
    cn = value.__class__.__name__
    if cn in _ABSENT:
        return ""
    octets = raw_octets(value)
    if octets is not None and cn in ("OctetString", "DisplayString"):
        if len(octets) == 0:
            return ""
        text_ok = all(b in (9, 10, 13) or 32 <= b < 127 for b in octets)
        # <=2 octets is a bitmap; non-text octets (MACs etc.) are binary -> hex.
        if len(octets) <= 2 or not text_ok:
            return "0x" + octets.hex()
        return octets.decode("latin-1")
    return value.prettyPrint()


def write_fixture(path: str, named_rows: dict) -> int:
    """Write a flat ``OID\\tVALUE`` fixture from {label: [(oid, value_obj)]}."""
    lines = ["# Comware HP 1920 (CYFOR-HP-Switch, 172.20.99.4) live SNMP capture",
             "# Format: <oid>\\t<value>  (capability/MAC octets as 0xhex; see capture_render)",
             "# Re-baselined ground truth for offline parser tests."]
    count = 0
    for label, rows in named_rows.items():
        lines.append(f"# --- {label} ---")
        for oid, value in rows:
            lines.append(f"{oid}\t{capture_render(value)}")
            count += 1
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return count


# --- the verification -------------------------------------------------------


async def run(target: str, community: str, version: str) -> int:
    global _COMMUNITY
    _COMMUNITY = community
    rpt = Report()
    rpt.section(f"Comware Phase-0 verification  target={target} community=*** version={version}")

    if version != "v2c":
        rpt.check(False, "version", f"only v2c supported for this gate, got {version}")
        return _finish(rpt)

    snmp = Snmp(target, community)

    # ----- 0.1 identity / version -----
    rpt.section("0.1  Identity / version")
    ident = await snmp.get(OID_SYS_DESCR, OID_SYS_OBJECT_ID, OID_SYS_NAME)
    sys_descr = to_text(ident[OID_SYS_DESCR]) or ""
    sys_descr_flat = re.sub(r"\s+", " ", sys_descr).strip()
    sys_object_id = to_text(ident[OID_SYS_OBJECT_ID]) or ""
    sys_name = to_text(ident[OID_SYS_NAME]) or ""

    rpt.note(f"sysDescr   = {sys_descr_flat!r}")
    rpt.note(f"sysObjectID= {sys_object_id}")
    rpt.note(f"sysName    = {sys_name!r}")

    rpt.check(
        "1920-48G Switch Software Version 5.20.99, Release 1107" in sys_descr_flat
        and "Hewlett-Packard" in sys_descr_flat,
        "sysDescr substring (model/version + Hewlett-Packard)",
    )
    rpt.check(sys_object_id == "1.3.6.1.4.1.25506.11.1.169",
              "sysObjectID exact", sys_object_id)
    rpt.check(sys_name == "CYFOR-HP-Switch", "sysName", sys_name)
    rpt.check(sys_object_id.startswith(COMWARE_ENTERPRISE_PREFIX),
              "vendor route by sysObjectID prefix -> comware (NOT sysDescr keyword)")
    rpt.check("comware" not in sys_descr.lower(),
              "sysDescr contains NO 'Comware' substring (proves prefix routing needed)")
    m = _VERSION_RE.search(sys_descr_flat)
    rpt.check(bool(m) and m.groups() == ("5.20.99", "1107"),
              "version parse regex -> (5.20.99, 1107)",
              str(m.groups()) if m else "no match")

    # ----- 0.2 interface table -----
    rpt.section("0.2  Interface table (IF-MIB)")
    ifdescr_rows, _ = await snmp.walk(IFDESCR)
    ifname_rows, _ = await snmp.walk(IFNAME)
    ifoper_rows, _ = await snmp.walk(IFOPERSTATUS)
    ifphys_rows, _ = await snmp.walk(IFPHYSADDR)

    ifdescr = {index_after(o, IFDESCR): to_text(v) for o, v in ifdescr_rows}
    ifname = {index_after(o, IFNAME): to_text(v) for o, v in ifname_rows}
    ifoper = {index_after(o, IFOPERSTATUS): to_text(v) for o, v in ifoper_rows}
    ifphys = {index_after(o, IFPHYSADDR): raw_octets(v) for o, v in ifphys_rows}

    gi_ok = all(ifname.get(str(i)) == f"GigabitEthernet1/0/{i}" for i in range(1, 53))
    rpt.check(gi_ok, "ifIndex 1..52 -> GigabitEthernet1/0/1..1/0/52")
    rpt.check(ifname.get("53") == "NULL0", "ifIndex 53 -> NULL0", ifname.get("53"))
    rpt.check(ifname.get("54") == "Vlan-interface1", "ifIndex 54 -> Vlan-interface1", ifname.get("54"))
    rpt.check(ifname.get("59") == "Vlan-interface99", "ifIndex 59 -> Vlan-interface99", ifname.get("59"))
    gap_absent = all(str(i) not in ifname for i in range(55, 59))
    rpt.check(gap_absent, "ifIndex 55..58 absent (non-contiguous indexing)")

    up_ports = sorted(int(i) for i, v in ifoper.items() if v == "1" and int(i) <= 52)
    if up_ports == [1, 29]:
        rpt.check(True, "physical ports UP (ifOperStatus==1) == ifIndex {1, 29}", str(up_ports))
    else:
        rpt.diverge("physical ports UP (ifOperStatus==1)", "[1, 29]", str(up_ports))

    phys_oui_ok = True
    bad = []
    for i in range(1, 53):
        octets = ifphys.get(str(i))
        if not octets or len(octets) < 3:
            continue  # absent phys addr on a port is not itself a failure
        if octets[:3].hex() != "5c8a38":
            phys_oui_ok = False
            bad.append(f"if{i}={octets[:3].hex()}")
    rpt.check(phys_oui_ok, "ifPhysAddress OUI == 5C:8A:38 (HP) on physical ports",
              ",".join(bad) if bad else "all 5c:8a:38")

    name_eq_descr = all(ifname.get(k) == ifdescr.get(k) for k in ifname)
    rpt.check(name_eq_descr, "ifName[i] == ifDescr[i] for all i (prefer ifName if they ever diverge)")

    # ----- 0.3 LLDP local port table -----
    rpt.section("0.3  LLDP local port table + ifIndex invariant")
    locid_rows, _ = await snmp.walk(LLDP_LOC_PORT_ID)
    locsub_rows, _ = await snmp.walk(LLDP_LOC_PORT_ID_SUBTYPE)
    loc_portid = {index_after(o, LLDP_LOC_PORT_ID): v for o, v in locid_rows}
    loc_subtype = {index_after(o, LLDP_LOC_PORT_ID_SUBTYPE): to_text(v) for o, v in locsub_rows}

    rpt.note("lldpLocPortNum -> (subtype) value:")
    for pn in sorted(loc_portid, key=lambda x: int(x)):
        st = loc_subtype.get(pn, "?")
        rpt.note(f"   {pn}: subtype={st}  value={to_text(loc_portid[pn])!r}")

    local_ports = sorted(loc_portid, key=int)
    if set(loc_portid) == {"1", "29"}:
        rpt.check(True, "exactly two local LLDP ports: {1, 29}", str(local_ports))
    else:
        rpt.diverge("set of local LLDP ports", "{1, 29}", str(local_ports))

    # MECHANIC (subtype inconsistency): port 1 reports interfaceName (subtype 5,
    # a string); the other local ports report macAddress (subtype 3, the HP's own
    # port MAC). This is the spec's "string-match strategy fails for non-port-1"
    # invariant — still true regardless of which ports are live.
    rpt.check(loc_subtype.get("1") == "5" and to_text(loc_portid.get("1")) == "GigabitEthernet1/0/1",
              "port 1 lldpLocPortId == ifName (interfaceName subtype 5)")
    mac_subtype_ports = [p for p in local_ports if p != "1" and loc_subtype.get(p) == "3"]
    mac_oui_ok = all(canonical_mac(raw_octets(loc_portid.get(p)) or b"").startswith("5c8a38")
                     for p in mac_subtype_ports)
    rpt.check(bool(mac_subtype_ports) and mac_oui_ok,
              "non-port-1 lldpLocPortId is a MAC (subtype 3, HP OUI) -> string-match would FAIL",
              f"mac-subtype ports={mac_subtype_ports}")

    # MECHANIC — the reliable invariant: lldpRemLocalPortNum == ifIndex. For every
    # live local LLDP port, resolving through ifName must agree with the ifIndex
    # table, and the port must be UP (it has a live neighbor).
    inv_ok = all(ifname.get(p) == f"GigabitEthernet1/0/{p}" and ifoper.get(p) == "1"
                 for p in local_ports)
    rpt.check(inv_ok,
              "invariant: every LLDP localPortNum -> ifIndex -> ifName (UP) holds",
              ", ".join(f"{p}->{ifname.get(p)}(oper {ifoper.get(p)})" for p in local_ports))

    # ----- 0.4 LLDP remote table (neighbors) -----
    rpt.section("0.4  LLDP remote table (neighbors)")
    rem_rows, _ = await snmp.walk(LLDP_REM)
    man_rows, _ = await snmp.walk(LLDP_REM_MAN_ADDR)

    # Group raw cells by (column, localPortNum, remIndex) for the ground-truth checks.
    # OID under LLDP_REM = column.timeMark.localPortNum.remIndex
    rem_cells: dict[tuple[str, str], dict[str, object]] = {}
    for oid, val in rem_rows:
        rem = index_after(oid, LLDP_REM)
        parts = rem.split(".")
        if len(parts) < 4:
            continue
        column, _tmark, lpn, ridx = parts[0], parts[1], parts[2], parts[3]
        rem_cells.setdefault((lpn, ridx), {})[column] = val

    def cell_text(key, col):
        v = rem_cells.get(key, {}).get(col)
        return to_text(v) if v is not None else None

    def cell_octets(key, col):
        v = rem_cells.get(key, {}).get(col)
        return raw_octets(v) if v is not None else None

    rpt.note(f"neighbor index keys (localPortNum, remIndex): {sorted(rem_cells)}")

    # Build a flat view of every neighbor keyed by (localPortNum, remIndex).
    neighbor_view = {}
    for key in rem_cells:
        neighbor_view[key] = {
            "chassis": format_mac(cell_octets(key, "5")),
            "chassis_sub": cell_text(key, "4"),
            "portid_mac": format_mac(cell_octets(key, "7")),
            "portid_text": cell_text(key, "7"),
            "portdesc": cell_text(key, "8"),
            "sysname": cell_text(key, "9"),
            "sysdesc": re.sub(r"\s+", " ", cell_text(key, "10") or "").strip(),
            "cap": cell_octets(key, "12"),
        }
    for key in sorted(neighbor_view):
        n = neighbor_view[key]
        cap = n["cap"].hex() if n["cap"] else None
        rpt.note(f"   port {key[0]:>3} remIdx {key[1]}: chassis={n['chassis']} "
                 f"sysName={n['sysname']!r} cap={cap} portId={n['portid_text']!r}")

    # --- Uplink neighbor (the L3-Switch): identified by advertising a sysName /
    # infra caps, NOT by a hardcoded index. This is the part of the spec that is
    # STILL TRUE and the mechanic the plugin depends on. ---
    uplinks = [k for k, n in neighbor_view.items()
               if n["sysname"] or neighbor_is_infrastructure(None, n["cap"])]
    rpt.check(len(uplinks) == 1, "exactly one infrastructure (uplink) neighbor", str(uplinks))
    if uplinks:
        uk = uplinks[0]
        u = neighbor_view[uk]
        uplink_local_port = uk[0]
        rpt.check(uplink_local_port == "1", "uplink is on local port 1", uplink_local_port)
        rpt.check(u["chassis"] == "00:23:ac:e5:74:00", "uplink chassisId == 00:23:AC:E5:74:00", u["chassis"] or "")
        rpt.check(u["portid_text"] == "Fa1/0/2", "uplink lldpRemPortId == Fa1/0/2", u["portid_text"] or "")
        rpt.check(u["portdesc"] == "FastEthernet1/0/2", "uplink lldpRemPortDesc == FastEthernet1/0/2", u["portdesc"] or "")
        rpt.check(u["sysname"] == "L3-Switch", "uplink lldpRemSysName == L3-Switch", u["sysname"] or "")
        rpt.check(all(s in u["sysdesc"] for s in ("Cisco IOS", "C3750", "12.2(55)SE12")),
                  "uplink lldpRemSysDesc contains Cisco IOS / C3750 / 12.2(55)SE12")
        rpt.check(u["cap"] == b"\x28", "uplink lldpRemSysCapEnabled raw byte == 0x28",
                  u["cap"].hex() if u["cap"] else "None")
        caps_u = decode_capabilities(u["cap"])
        rpt.check(caps_u == {"bridge", "router"},
                  "uplink capability bitmap decodes to {bridge, router}", str(sorted(caps_u)))
        # The trap + its fix: 0x28 pretty-prints to the ASCII char '(' (a single
        # printable octet). roles.decode_capabilities now handles BOTH the raw
        # octets and that printable-char rendering, so the device is roled
        # correctly either way. (Before the fix, '(' decoded to nothing.)
        pretty = to_text(rem_cells[uk]["12"])
        caps_pretty = decode_capabilities(pretty)
        rpt.note(f"cap printable-octet rendering = {pretty!r} -> decode = {sorted(caps_pretty)}")
        rpt.check(caps_pretty == {"bridge", "router"},
                  "decode_capabilities recovers {bridge, router} from the printable-octet rendering (fix verified)")
        if uk != ("1", "2"):
            rpt.diverge("uplink neighbor (localPortNum, remIndex)", "('1', '2')", str(uk))

    # --- Endpoint neighbors: every non-uplink neighbor. The CLASSIFICATION
    # mechanic (macAddress chassis + empty sysName/sysDesc + caps 0x00 ->
    # endpoint hint, NOT a device) is what the spec really tests; assert it for
    # each. The *set* of endpoints is where the topology diverged. ---
    endpoint_keys = [k for k in neighbor_view if k not in uplinks]
    classify_ok = True
    for k in endpoint_keys:
        n = neighbor_view[k]
        is_endpoint = (n["chassis_sub"] == "4" and not n["sysname"]
                       and not n["sysdesc"] and not neighbor_is_infrastructure(None, n["cap"]))
        classify_ok = classify_ok and is_endpoint
    rpt.check(bool(endpoint_keys) and classify_ok,
              "every non-uplink neighbor classifies as ENDPOINT hint (mac chassis, empty sysName/sysDesc, caps 0x00)",
              f"{len(endpoint_keys)} endpoint neighbor(s)")

    # Spec ground truth: exactly ONE endpoint, MAC C8:5B:76:54:FF:0D, on local
    # port 29. Compare to live.
    live_endpoints = sorted((neighbor_view[k]["chassis"], k[0]) for k in endpoint_keys)
    spec_endpoints = [("c8:5b:76:54:ff:0d", "29")]
    if live_endpoints != spec_endpoints:
        rpt.diverge("LLDP endpoint neighbors (mac, localPort)",
                    str(spec_endpoints), str(live_endpoints))

    # Cross-check the project's pure LLDP parser builds the same neighbor set.
    rem_str = [(o, to_text(v)) for o, v in rem_rows]
    man_str = [(o, to_text(v)) for o, v in man_rows]
    loc_str = [(o, to_text(v)) for o, v in locid_rows]
    neighbors = lldp.build_neighbors(rem_str, man_str, loc_str)
    by_key = {(n.local_port_num, n.rem_index): n for n in neighbors}
    rpt.check(set(by_key) == set(neighbor_view),
              "project lldp.build_neighbors yields the same neighbor set", str(sorted(by_key)))

    # ----- 0.5 bridge-port -> ifIndex map -----
    rpt.section("0.5  Bridge-port -> ifIndex map")
    base_rows, _ = await snmp.walk(DOT1D_BASEPORT_IFINDEX)
    baseport = fdb.parse_baseport_ifindex([(o, to_text(v)) for o, v in base_rows])
    bp_ok = all(baseport.get(str(i)) == str(i) for i in range(1, 53))
    rpt.check(bp_ok, "dot1dBasePort 1..52 -> ifIndex 1..52 (verified via table, not assumed)")
    rpt.check(baseport.get("1") == "1", "bridge port 1 -> ifIndex 1", baseport.get("1"))

    # ----- 0.6 FDB + truncation trap -----
    rpt.section("0.6  FDB (dot1qTpFdbPort) + non-increasing-OID truncation trap")
    # Comware returns dot1qTpFdbPort sorted by MAC, so a *single* GETBULK PDU that
    # packs many varbinds shows them in non-increasing OID order. The net-snmp CLI
    # (snmpbulkwalk) treats that as "OID not increasing" and ABORTS -- which is what
    # the spec captured. BUT the spec's conclusion ("the pipeline needs an
    # ignoreNonIncreasingOid workaround, the core Comware branch difference") does
    # NOT hold for THIS codebase: the project's walk (snmp_client.py) is a manual
    # bulk_cmd loop that steps from the last-returned OID (GETNEXT-style), so the
    # agent always hands back proper lexicographic successors and no truncation
    # occurs. We prove that by running the REAL pipeline walk at several PDU sizes.
    from vulnmapper.network.snmp_client import SnmpClient  # noqa: E402
    from vulnmapper.network.models import Credential  # noqa: E402
    proj = SnmpClient([Credential(version="v2c", index=0, community=_COMMUNITY)],
                      timeout=2.0, retries=2)
    await proj.resolve_credential(target)
    proj_counts = {}
    for mr in (1, 2, 25):
        rows = await proj.walk(target, DOT1Q_FDB_PORT, max_repetitions=mr)
        proj_counts[mr] = len(rows)
    rpt.note(f"project SnmpClient.walk row counts by max_repetitions: {proj_counts}")
    full_count = max(proj_counts.values())
    rpt.check(full_count > 0 and len(set(proj_counts.values())) == 1,
              "project walk retrieves the FULL Comware FDB at every PDU size "
              "(no ignoreNonIncreasingOid workaround needed)",
              f"counts={proj_counts}")
    rpt.diverge("FDB requires ignoreNonIncreasingOid workaround (spec's core Comware branch)",
                "plain walk truncates after ~3 rows; needs ignoreNonIncreasingOid=True",
                f"project walk already returns all {full_count} rows unmodified; the abort is a "
                "net-snmp CLI artifact, not a pipeline issue -> no Comware FDB branch needed")
    # Use the full table for the resolution checks below.
    full_rows, _ = await snmp.walk(DOT1Q_FDB_PORT, ignore_non_increasing=True, lexicographic=False)
    parsed = fdb.parse_dot1q_fdb([(o, to_text(v)) for o, v in full_rows])
    ifname_map = fdb.parse_ifnames([(o, to_text(v)) for o, v in ifname_rows])
    resolved = []
    for vlan, mac, bridge_port in parsed:
        ifindex = baseport.get(bridge_port)
        portname = fdb.resolve_port(bridge_port, baseport, ifname_map)
        resolved.append((vlan, format_mac(mac), bridge_port, ifindex, portname))
    rpt.note("VLAN | MAC | bridgePort | ifIndex | ifName")
    for row in resolved:
        rpt.note("   " + " | ".join(str(x) for x in row))

    # MECHANIC: every FDB row resolves bridgePort -> ifIndex -> ifName via the
    # tables (this is what the plugin must do; it must NOT assume the integers
    # coincide). Confirm every row resolved to a real GigabitEthernet name.
    resolve_ok = all(ix is not None and nm.startswith("GigabitEthernet")
                     for _v, _m, _bp, ix, nm in resolved)
    rpt.check(bool(resolved) and resolve_ok,
              "every FDB row resolves bridgePort -> ifIndex -> ifName via tables")

    # Spec ground truth: exactly the 6 gateway-only rows, all on port 1.
    spec_fdb = {
        (99, "00:23:ac:e5:74:04"), (99, "00:23:ac:e5:74:47"),
        (40, "00:23:ac:e5:74:04"), (10, "00:23:ac:e5:74:04"),
        (20, "00:23:ac:e5:74:04"), (30, "00:23:ac:e5:74:04"),
    }
    got_fdb = {(vlan, mac) for vlan, mac, _bp, _ix, _nm in resolved}
    if got_fdb != spec_fdb:
        rpt.diverge("FDB (vlan, mac) set",
                    f"6 gateway-only rows on port 1: {sorted(spec_fdb)}",
                    f"{len(got_fdb)} rows: {sorted(got_fdb)}")
    # The gateway MAC riding the trunk on port 1 in every VLAN is still present.
    gw_on_p1 = {v for v, m, _bp, ix, _nm in resolved if m == "00:23:ac:e5:74:04" and ix == "1"}
    rpt.check({10, 20, 30, 40, 99}.issubset(gw_on_p1),
              "gateway MAC 00:23:ac:e5:74:04 learned on port 1 (uplink) in every VLAN",
              str(sorted(gw_on_p1)))

    # ----- 0.7 integration assertion -----
    rpt.section("0.7  Integration assertion (uplink / edge-port subtraction)")
    # Uplink ifIndex set = ifIndex of LLDP infrastructure neighbors. Endpoint
    # neighbors are EXCLUDED (their ports are access ports, not uplinks).
    uplink_ifindex = {k[0] for k in uplinks}  # localPortNum == ifIndex (invariant)
    rpt.check(uplink_ifindex == {"1"}, "uplink ifIndex set (LLDP infra neighbors) == {1}", str(uplink_ifindex))
    # FDB candidate ports = ports where a non-gateway, non-own MAC was learned.
    fdb_ifindex = {ix for _v, _m, _bp, ix, _nm in resolved}
    edge_ports = fdb_ifindex - uplink_ifindex
    rpt.note(f"FDB candidate ifIndex set = {sorted(fdb_ifindex, key=int)}")
    rpt.note(f"edge ports (FDB candidates - uplink ports) = {sorted(edge_ports, key=int) if edge_ports else 'EMPTY'}")

    if edge_ports == set():
        rpt.check(True, "edge ports == EMPTY -> HP owns ZERO endpoints (single switch node)")
    else:
        # Endpoints learned directly on access ports of the HP.
        owned = sorted(
            (m, ix) for _v, m, _bp, ix, _nm in resolved
            if ix in edge_ports and not canonical_mac(m).startswith("0023ac")
        )
        rpt.diverge("HP-owned endpoints (edge-port subtraction)",
                    "EMPTY (spec: HP owns zero endpoints; single switch node, no children)",
                    f"{len(set(owned))} endpoint MAC(s) on access ports: {owned}")

    # MECHANIC: the three numbering spaces resolve to the SAME ifName for port 1
    # via their respective tables (must never depend on raw-int equality).
    via_ifindex = ifname.get("1")
    via_baseport = ifname_map.get(baseport.get("1"))
    via_lldp = ifname.get(uplink_local_port) if uplinks else None
    same = via_ifindex == via_baseport == via_lldp == "GigabitEthernet1/0/1"
    rpt.check(same, "ifIndex / dot1dBasePort / lldpRemLocalPortNum all resolve port 1 to GigabitEthernet1/0/1",
              f"{via_ifindex} / {via_baseport} / {via_lldp}")
    raw_equal = (1 == int(baseport.get("1")) == (int(uplink_local_port) if uplinks else -1))
    rpt.note(f"WARNING: raw integers ifIndex(1)==dot1dBasePort({baseport.get('1')})=="
             f"lldpLocalPortNum({uplink_local_port if uplinks else '?'}) coincide ({raw_equal}). "
             "Code MUST NOT depend on this.")

    # ----- optional fixture capture (Phase 3 re-baseline) -----
    if _CAPTURE_PATH:
        rpt.section("FIXTURE CAPTURE")
        n = write_fixture(_CAPTURE_PATH, {
            "ifName": ifname_rows,
            "ifDescr": ifdescr_rows,
            "ifOperStatus": ifoper_rows,
            "ifPhysAddress": ifphys_rows,
            "lldpLocPortId": locid_rows,
            "lldpRemTable": rem_rows,
            "lldpRemManAddr": man_rows,
            "dot1dBasePortIfIndex": base_rows,
            "dot1qTpFdbPort": full_rows,
        })
        rpt.note(f"wrote {n} rows to {_CAPTURE_PATH}")

    return _finish(rpt)


def _finish(rpt: Report) -> int:
    rpt.section("RESULT")
    passes = len([l for l in rpt.lines if l.startswith("[PASS]")])
    if rpt.failures == 0 and rpt.divergences == 0:
        rpt.note(f"ALL {passes} CHECKS PASSED — ground truth confirmed. Proceed to Phase 1.")
    else:
        rpt.note(f"VALIDATED MECHANICS : {passes} PASS, {rpt.failures} FAIL")
        rpt.note(f"GROUND-TRUTH STATE  : {rpt.divergences} DIVERGENCE(S) from the spec's capture")
        rpt.note("")
        if rpt.failures:
            rpt.note("FAIL = a protocol/parsing assumption is wrong -> the plugin built on it "
                     "would be wrong. HALT.")
        if rpt.divergences:
            rpt.note("DIVERGED = the live lab topology no longer matches the spec's captured "
                     "ground truth. The plugin MECHANICS are validated, but the spec's expected "
                     "DATA (endpoint set, FDB rows, 'zero endpoints' conclusion) is stale and must "
                     "be re-baselined before Phase 1/3 fixtures are written. HALT and report.")

    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "comware_verification_report.txt")
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(rpt.lines) + "\n")
    print(f"\nReport written to {out_path}")
    return 1 if (rpt.failures or rpt.divergences) else 0


def main() -> int:
    global _CAPTURE_PATH
    args = [a for a in sys.argv[1:]]
    # Pull out "--capture PATH" wherever it appears.
    if "--capture" in args:
        i = args.index("--capture")
        _CAPTURE_PATH = args[i + 1]
        del args[i:i + 2]
    target = args[0] if len(args) > 0 else "172.20.99.4"
    community = args[1] if len(args) > 1 else "cyfor123"
    version = args[2] if len(args) > 2 else "v2c"
    try:
        return asyncio.run(run(target, community, version))
    except Exception as exc:  # a poll failure is itself a HALT condition
        print(f"[FAIL] verification aborted with exception: {exc!r}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
