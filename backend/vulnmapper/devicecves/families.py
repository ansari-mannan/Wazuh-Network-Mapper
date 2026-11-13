"""Software families: from a device's identity to the product label and CPE 2.3
name NVD files its CVEs under (``identify``). Used by the device CVE stage and
by the crawler, which records each device's family.
"""

from __future__ import annotations

import re
from typing import Optional

# Cisco families in the order they must be tested: an IOS XE description also
# contains the words "IOS Software", so XE, XR, NX-OS and ASA come first.
# NVD files vulnerabilities under CPE 2.3 names, e.g.
# ``cpe:2.3:o:cisco:ios:12.2\\(55\\)se12:*:*:*:*:*:*:*``. A CPE query returns the
# CVEs whose affected-version ranges include that exact software version. This
# module decides, per device:
#
#   * the software family, when the device is identified (system description,
#     vendor, sysObjectID; see :func:`detect_family`), or for a graph written
#     before families were recorded, by a narrow inference (:func:`family_of`);
#   * the product label ("Cisco IOS 12.2(55)SE12"), the CPE (or none) and the
#     match kind (:func:`identify`): ``cpe`` when a rule builds a full CPE,
#     ``keyword`` when only the fallback applies, ``none`` when the family and
#     version are known but NVD has no product name that can be trusted for it
#     (the device is identified, its CVEs are not looked up), ``unidentified``
#     when vendor, family or version is missing;
#   * for the keyword fallback, whether one CVE really concerns the device
#     (:func:`keyword_accepts`).
#
# The rules are written per vendor and software family, never per device.
#
# Every CPE vendor:product pair below was checked against NVD's CPE dictionary
# (services.nvd.nist.gov/rest/json/cpes/2.0, cpeMatchString) on 9 October 2026.

_CISCO_ORDER = (
    ("cisco_ios_xe", re.compile(r"IOS[ -]?XE", re.I)),
    ("cisco_ios_xr", re.compile(r"IOS[ -]?XR", re.I)),
    ("cisco_nx_os", re.compile(r"NX-OS", re.I)),
    ("cisco_asa", re.compile(r"Adaptive Security Appliance", re.I)),
    ("cisco_ios", re.compile(r"Cisco IOS Software|IOS \(tm\)|Internetwork Operating System", re.I)),
)

# FortiGate's sysObjectID subtree (fnFortiGateMib). FortiSwitch, FortiAP and the
# rest sit elsewhere under 12356 and do not run FortiOS.
_FORTIGATE_OID = "1.3.6.1.4.1.12356.101."
# The Comware vendor module's own version format ("5.20.99 Release 1107").
_COMWARE_DESCR = re.compile(r"Software Version \d+\.\d+\.\d+, Release \d+")
_COMWARE_FIRMWARE = re.compile(r"^\d+\.\d+\.\d+ Release \d+$")
_HP_ENTERPRISE_OID = "1.3.6.1.4.1.25506."
# The HP c-Class GbE2c blade switch's system description.
_GBE2C_DESCR = re.compile(r"\bGbE2c\b.*Blade Switch", re.I)

# CPE vendor names under which NVD files HP / HPE / H3C networking products.
HP_VENDORS = frozenset({"hp", "hpe", "h3c", "hewlett_packard", "hewlett_packard_enterprise"})

# One entry per family. ``cpe`` is (part, vendor, product) or None. A family
# without a CPE rule may carry a ``keyword`` rule: which CPE vendors count as
# the same vendor, and how to find the product line in the device's model.
# ``listed`` says how the CPE dictionary is checked before the CVE query:
# "release" (the default: the exact name must be listed), "product" (the
# product must be listed, any release) or "skip".
FAMILIES: dict = {
    # cpe:2.3:o:cisco:ios (6487 dictionary entries; 12.2(55)SE12 listed)
    "cisco_ios": {"label": "Cisco IOS", "cpe": ("o", "cisco", "ios")},
    # cpe:2.3:o:cisco:ios_xe (1094 entries)
    "cisco_ios_xe": {"label": "Cisco IOS XE", "cpe": ("o", "cisco", "ios_xe")},
    # recognised so it is never taken for IOS; no rule checked yet
    "cisco_ios_xr": {"label": "Cisco IOS XR", "cpe": None},
    # cpe:2.3:o:cisco:nx-os (1033 entries)
    "cisco_nx_os": {"label": "Cisco NX-OS", "cpe": ("o", "cisco", "nx-os")},
    # cpe:2.3:a:cisco:adaptive_security_appliance_software (680 entries)
    "cisco_asa": {"label": "Cisco ASA",
                  "cpe": ("a", "cisco", "adaptive_security_appliance_software")},
    # cpe:2.3:o:fortinet:fortios (271 entries)
    # NVD evaluates versionStart/End ranges for a well-formed FortiOS name even
    # when that exact release is not in the CPE dictionary: no dictionary check.
    "fortinet_fortios": {"label": "Fortinet FortiOS", "cpe": ("o", "fortinet", "fortios"),
                         "listed": "skip"},
    "juniper_junos": {"label": "Juniper Junos", "cpe": ("o", "juniper", "junos")},
    # cpe:2.3:o:juniper:junos_os_evolved (22.2:r3 answered with 103 CVEs,
    # November 2026); decided from Juniper's records like Junos
    "juniper_junos_evolved": {"label": "Juniper Junos OS Evolved",
                              "cpe": ("o", "juniper", "junos_os_evolved")},
    # ArubaOS-Switch (AOS-S) 16.x, shown by the switch as "<train>.16.04.0024"
    # (HPE Aruba advisories write "KA/RA.16.04.0024"). NVD files its CVEs under
    # two names: cpe:2.3:o:hpe:arubaos-switch (71 entries, 15.16 to 16.11) and
    # one per model, cpe:2.3:o:arubanetworks:<line>_firmware, each listing some
    # CVEs the other does not; both are asked (lookup). Neither dictionary
    # lists every release, but NVD evaluates the version ranges for any
    # well-formed name, so the dictionary is checked per product, not per
    # release. Major 15 and older are left to hp_procurve.
    "hp_arubaos_switch": {"label": "ArubaOS-Switch", "cpe": ("o", "hpe", "arubaos-switch"),
                          "listed": "product"},
    # ProCurve software before ArubaOS-Switch 16 (a train letter before the
    # release: "K.15.xx.xxxx").
    # cpe:2.3:o:hp:procurve_switch_software lists releases with the train
    # letters ("h.10.74", "pb.02.07") and NVD compares them as strings, so a
    # release on one train can match ranges stated for another train. No CPE
    # rule.
    "hp_procurve": {"label": "HP ProCurve switch software", "cpe": None},
    # The families below have no product in NVD's CPE dictionary that fits
    # (checked November 2026): Brocade Network OS (VDX; brocade:fabric_os is
    # the Fibre Channel product), DCN switches, IBM Networking OS (only
    # single per-model firmware entries), HP GbE2c.
    "brocade_nos": {"label": "Brocade Network OS", "cpe": None},
    "dcn_switch": {"label": "DCN switch software", "cpe": None},
    "ibm_networking_os": {"label": "IBM Networking OS", "cpe": None},
    "hp_gbe2c": {"label": "HP GbE2c switch software", "cpe": None},
    # No faithful CPE: the dictionary has no h3c:comware or hpe:comware product,
    # only per-part-number entries for some Comware 7 products, and "1920"
    # finds only the HPE OfficeConnect 1920S, a different product. So keyword
    # only, under the strict rule in keyword_accepts.
    "hp_comware": {"label": "HP Comware", "cpe": None,
                   "keyword": {"vendors": HP_VENDORS}},
}


def detect_family(vendor: Optional[str], sys_descr: Optional[str],
                  sys_object_id: Optional[str] = None) -> Optional[str]:
    """The software family of a polled device, or None when it is not known."""
    descr = sys_descr or ""
    if vendor == "Cisco":
        for family, pattern in _CISCO_ORDER:
            if pattern.search(descr):
                return family
        return None
    if vendor == "Fortinet":
        return "fortinet_fortios" if (sys_object_id or "").startswith(_FORTIGATE_OID) else None
    if vendor == "HP":
        if (sys_object_id or "").startswith(_HP_ENTERPRISE_OID) and _COMWARE_DESCR.search(descr):
            return "hp_comware"
        if _GBE2C_DESCR.search(descr):
            return "hp_gbe2c"
    return None


# Classic IOS: "12.2(55)SE12", "15.3(3)JB" -- a release train after the
# parenthesis. IOS XE ("16.9.4"), NX-OS ("9.3(8)", "7.0(3)I7(6)") and ASA
# ("9.8(4)") do not have that shape.
_CLASSIC_IOS = re.compile(r"^\d+\.\d+\(\d+[a-z]?\)[A-Z]+[A-Z0-9]*[a-z]?$")


# Junos "JUNOS 19.4R3-S1.3": train 19.4, update r3-s1, build 3. NVD's CPE
# is juniper:junos:19.4:r3-s1, without the build: the CPE dictionary lists
# Junos releases without one, and NVD returns fewer CVEs for a name with
# the build (175 against 295 for 20.2R2-S3, November 2026). The name has 13
# components; NVD answers HTTP 404 ("Invalid cpeName parameter") for 14.
_JUNOS = re.compile(r"^JUNOS\s+(\d+\.\d+)(R\d+(?:-S\d+)?)(?:\.\d+)?(-EVO)?\s*$", re.I)

# ArubaOS-Switch: "KA.16.04.0024" -> "16.04.0024" (CPE version)
_AOS_S = re.compile(r"^(?:[A-Z]{1,3}\.)?(16\.\d{2}\.\d{4})$")

# A product line word in an ArubaOS-Switch model name: "2620-48" -> "2620",
# "2930F-24G" -> "2930f". Part numbers ("J0000A") are not mapped: a model given
# only as a part number has no line, and the device is not looked up.
_AOS_S_LINE = re.compile(r"^(\d{4}[A-Z]?)(?:-|$)", re.I)


def aos_s_line(model: Optional[str]) -> Optional[str]:
    """The ArubaOS-Switch product line of a model, lower case: "Aruba 2620-48"
    -> "2620"; None when the model names no line."""
    for word in (model or "").replace("(", " ").replace(")", " ").split():
        m = _AOS_S_LINE.match(word)
        if m:
            return m.group(1).lower()
    return None


def family_of(node: dict) -> Optional[str]:
    """The recorded family, else a narrow inference for an older graph.

    Only unambiguous cases are inferred: a classic IOS version string on a
    Cisco device, a FortiGate, a Junos release (``-EVO`` for
    Evolved) on a Juniper device, and the Comware version format on an HP
    device.
    """
    if node.get("software_family"):
        return node["software_family"]
    vendor, model, firmware = node.get("vendor"), node.get("model") or "", node.get("firmware") or ""
    if vendor == "Cisco" and _CLASSIC_IOS.match(firmware):
        return "cisco_ios"
    if vendor == "Fortinet" and model.startswith("FortiGate"):
        return "fortinet_fortios"
    if vendor == "Juniper":
        jm = _JUNOS.match(firmware)
        if jm:
            return "juniper_junos_evolved" if jm.group(3) else "juniper_junos"
    if vendor == "HP" and _COMWARE_FIRMWARE.match(firmware):
        return "hp_comware"
    return None


def cpe_value(text: str) -> str:
    """A CPE 2.3 formatted-string component: lower case, specials escaped.

    Letters, digits and ``. _ -`` stay; a space becomes ``_``; every other
    character is backslash-escaped, as the CPE 2.3 binding requires.
    """
    out = []
    for ch in text.strip().lower():
        if ch.isalnum() or ch in "._-":
            out.append(ch)
        elif ch == " ":
            out.append("_")
        else:
            out.append("\\" + ch)
    return "".join(out)


def product_line(model: Optional[str]) -> Optional[str]:
    """The product line in a model name: "HP 1920-48G" -> "1920".

    The first word with a digit in it, up to its first hyphen.
    """
    for word in (model or "").split():
        if any(c.isdigit() for c in word):
            return word.split("-")[0] or None
    return None


def identify(node: dict) -> dict:
    """``{family, product, cpe, match, keyword}`` for one graph device node, or
    a host that answered SNMP (vulnmapper.hosts)."""
    out = {"family": None, "product": None, "cpe": None, "match": "unidentified",
           "keyword": None, "version": None}
    if not (node.get("kind") == "device" and node.get("pollable")) and not node.get("snmp") \
            and not node.get("software_family"):
        return out                        # seen only in a neighbour's table
    family = family_of(node)
    entry = FAMILIES.get(family)
    firmware = (node.get("firmware") or "").strip()
    if family == "fortinet_fortios":
        # inventory strings look like "v7.4.12,build2902,260505 (GA.M)"; the CPE version is "7.4.12"
        fm = re.match(r"^v?(\d+\.\d+\.\d+)(?:[,\s]|$)", firmware)
        firmware = fm.group(1) if fm else firmware
    if family == "hp_arubaos_switch":
        am = _AOS_S.match(firmware)
        firmware = am.group(1) if am else ""
    if entry is None:
        return out
    out["family"] = family
    if not firmware:
        return out
    out["product"] = f"{entry['label']} {firmware}"
    out["version"] = firmware
    if entry.get("cpe"):
        part, vendor, product = entry["cpe"]
        jm = _JUNOS.match(firmware) if family in ("juniper_junos", "juniper_junos_evolved") else None
        if jm and bool(jm.group(3)) != (family == "juniper_junos_evolved"):
            out["product"] = out["version"] = None
            return out                    # release of the other Junos branch: no claim
        if jm:
            out["cpe"] = f"cpe:2.3:{part}:{vendor}:{product}:{jm.group(1)}:{jm.group(2).lower()}:*:*:*:*:*:*"
            out["match"] = "cpe"
            return out
        out["cpe"] = f"cpe:2.3:{part}:{vendor}:{product}:{cpe_value(firmware)}:*:*:*:*:*:*:*"
        out["match"] = "cpe"
        if family == "hp_arubaos_switch":
            line = aos_s_line(node.get("model"))
            out["extra_cpes"] = [f"cpe:2.3:o:arubanetworks:{line}_firmware:{firmware}:*:*:*:*:*:*:*"] \
                if line else []
    elif entry.get("keyword"):
        line = product_line(node.get("model"))
        if line:
            out["match"] = "keyword"
            out["keyword"] = {"query": line, "vendors": sorted(entry["keyword"]["vendors"]),
                              "line": line, "version": firmware}
    else:
        out["match"] = "none"
    return out


# ---------------------------------------------------------------------------
# The keyword fallback: conservative, because a wrong match puts a false
# critical on the map.
# ---------------------------------------------------------------------------

_VENDOR_WORDS = {
    "hp": r"HP", "hpe": r"HPE", "h3c": r"H3C",
    "hewlett_packard": r"Hewlett[- ]Packard", "hewlett_packard_enterprise": r"Hewlett[- ]Packard",
}


def _tokens(cpe_product: str) -> list:
    return [t for t in re.split(r"[_\-\s\\]+", cpe_product.lower()) if t]


def _numbers(version: Optional[str]) -> Optional[tuple]:
    """Leading dotted numbers of a version ("5.20.99 Release 1107" -> (5, 20, 99))."""
    match = re.match(r"^\s*(\d+(?:\.\d+)*)(?:$|\s)", version or "")
    return tuple(int(p) for p in match.group(1).split(".")) if match else None


def _in_range(device: tuple, m: dict, exact: Optional[str]) -> Optional[bool]:
    """Whether the device version falls in one cpeMatch's versions, or None when
    the two cannot be compared."""
    if exact not in (None, "*", "-", ""):
        other = _numbers(exact)
        return None if other is None else device == other
    bounds = [(k, _numbers(m.get(k))) for k in ("versionStartIncluding", "versionStartExcluding",
                                                 "versionEndIncluding", "versionEndExcluding")
              if m.get(k)]
    if not bounds:
        return None
    if any(v is None for _k, v in bounds):
        return None
    for key, v in bounds:
        if key == "versionStartIncluding" and device < v:
            return False
        if key == "versionStartExcluding" and device <= v:
            return False
        if key == "versionEndIncluding" and device > v:
            return False
        if key == "versionEndExcluding" and device >= v:
            return False
    return True


def keyword_accepts(cve: dict, *, vendors, line: str, version: Optional[str]) -> bool:
    """Whether a keyword-search CVE really concerns this device.

    It counts only when (1) its configuration data lists a CPE of the same
    vendor whose product contains the product line as a whole token, or its
    English description names the vendor and the product line as a whole word
    ("1920" matches "HP 1920-48G", never "1920S"); and (2) where the matching
    configuration entries carry versions that can be compared with the
    device's, the device's version falls inside at least one of them.
    """
    vendors = set(vendors)
    line = line.lower()
    matches = []
    for cfg in cve.get("configurations") or []:
        for node in cfg.get("nodes") or []:
            for m in node.get("cpeMatch") or []:
                parts = (m.get("criteria") or "").split(":")
                if len(parts) < 6:
                    continue
                if parts[3] in vendors and line in _tokens(parts[4]):
                    matches.append((m, parts[5]))

    text = " ".join(d.get("value", "") for d in cve.get("descriptions") or []
                    if d.get("lang") == "en")
    vendor_named = any(re.search(rf"(?<![\w-]){_VENDOR_WORDS[v]}(?![\w-])", text)
                       for v in vendors if v in _VENDOR_WORDS)
    line_named = re.search(rf"(?<![\w]){re.escape(line)}(?![\w])", text, re.I) is not None
    if not matches and not (vendor_named and line_named):
        return False

    device = _numbers(version)
    if device is None or not matches:
        return True
    verdicts = [_in_range(device, m, exact) for m, exact in matches]
    comparable = [v for v in verdicts if v is not None]
    return not comparable or any(comparable)
