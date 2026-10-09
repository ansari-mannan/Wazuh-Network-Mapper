"""The configuration check catalogue: what each check looks for and why it matters.

No severity here is our own. Each one is the severity a recognised body
published for the rule cited with relation "requires":

  * DISA STIG rules for Cisco IOS switches (Cisco IOS Switch NDM STIG V3R9 and
    Cisco IOS Switch L2S STIG V3R3, both dated 2026-09-01), and for every other
    vendor the vendor-neutral requirement each of them implements (Network
    Device Management SRG V5R5, 2026-05-23; Layer 2 Switch SRG V3R4,
    2026-02-12). DISA's categories map CAT I = high, CAT II = medium,
    CAT III = low.
  * NVD for CVE-1999-0517 (default SNMP community names): NVD's own (primary)
    score, CVSS 2.0 7.5 HIGH.

A check with no published severity has severity None and is shown as
Advisory. A reference with relation "related" is shown for context but does
not set the severity: its rule's finding condition is not what the check
tests.

Every rule id, title, severity and CCI below was read on 10 October 2026 from
the rule records of those releases (cyber.trackr.live, which republishes
DISA's XCCDF); the urls point to the same rules on stigviewer.com. NIST SP 800-53 Rev. 5 controls come from
DISA's CCI list (U_CCI_List, 2025-01-23). CWE ids were checked on
cwe.mitre.org, and only ids MITRE allows for mapping are used.

``scope`` says which devices a reference is cited for: "cisco_ios" for the
Cisco IOS software family, "any" for every device (a vendor-neutral SRG
requirement is cited for devices outside the Cisco scope; see
:func:`references_for`).
"""

from __future__ import annotations

from typing import Optional

SEVERITIES = ("high", "medium", "low")

ROLES_ANY = "any"
SWITCH_ROLES = ("l2-switch", "l3-switch")

# Rule pages on stigviewer.com, each checked in a browser to show the same rule
# id and severity (cyber.trackr.live's rule pages answer "Not Found"). Its
# Cisco pages are from the 2026-06-05 (NDM) and 2026-05-01 (L2S) releases.
_VIEWER = "https://www.stigviewer.com/stigs"
NDM_STIG = ("Cisco IOS Switch NDM STIG", "V3R9 (2026-09-01)",
            f"{_VIEWER}/cisco_ios_switch_ndm/2026-06-05/finding")
L2S_STIG = ("Cisco IOS Switch L2S STIG", "V3R3 (2026-09-01)",
            f"{_VIEWER}/cisco_ios_switch_l2s/2026-05-01/finding")
NDM_SRG = ("Network Device Management SRG", "V5R5 (2026-05-23)",
           f"{_VIEWER}/network_device_management_security_requirements_guide/2026-05-23/finding")
L2S_SRG = ("Layer 2 Switch SRG", "V3R4 (2026-02-12)",
           f"{_VIEWER}/layer_2_switch_security_requirements_guide/2026-02-12/finding")

_CATEGORY = {"high": "CAT I", "medium": "CAT II", "low": "CAT III"}


def _disa(doc: tuple, rule_id: str, stig_id: Optional[str], srg_id: str, title: str,
          severity: str, cci: str, nist: str, *, scope: str, relation: str = "requires") -> dict:
    name, release, base = doc
    return {
        "source": "DISA",
        "document": name,
        "release": release,
        "rule_id": rule_id,
        "stig_id": stig_id,
        "srg_id": srg_id,
        "title": title,
        "url": f"{base}/{rule_id}",
        "severity": severity,
        "category": _CATEGORY[severity],
        "cci": cci,
        "nist": nist,
        "scope": scope,
        "relation": relation,
    }


# --- the rules cited (verified, see the module docstring) ------------------

V_220608 = _disa(NDM_STIG, "V-220608", "CISC-ND-001210", "SRG-APP-000412-NDM-000331",
                 "The Cisco switch must be configured to implement cryptographic mechanisms "
                 "to protect the confidentiality of remote maintenance sessions.",
                 "high", "CCI-003123", "MA-4 (6)", scope="cisco_ios")
V_202118 = _disa(NDM_SRG, "V-202118", None, "SRG-APP-000412-NDM-000331",
                 "The network device must be configured to implement cryptographic mechanisms "
                 "using a FIPS 140-2 approved algorithm to protect the confidentiality of "
                 "remote maintenance sessions.",
                 "high", "CCI-003123", "MA-4 (6)", scope="any")
V_220586 = _disa(NDM_STIG, "V-220586", "CISC-ND-000470", "SRG-APP-000142-NDM-000245",
                 "The Cisco switch must be configured to prohibit the use of all unnecessary "
                 "and non-secure functions and services.",
                 "high", "CCI-000382", "CM-7 b", scope="cisco_ios")
V_202049 = _disa(NDM_SRG, "V-202049", None, "SRG-APP-000142-NDM-000245",
                 "The network device must be configured to prohibit the use of all unnecessary "
                 "and/or nonsecure functions, ports, protocols, and/or services.",
                 "high", "CCI-000382", "CM-7 b", scope="any")
V_220604 = _disa(NDM_STIG, "V-220604", "CISC-ND-001130", "SRG-APP-000395-NDM-000310",
                 "The Cisco switch must be configured to authenticate SNMP messages using a "
                 "FIPS-validated Keyed-Hash Message Authentication Code (HMAC).",
                 "medium", "CCI-001967", "IA-3 (1)", scope="cisco_ios")
V_220605 = _disa(NDM_STIG, "V-220605", "CISC-ND-001140", "SRG-APP-000395-NDM-000310",
                 "The Cisco switch must be configured to encrypt SNMP messages using a FIPS "
                 "140-2 approved algorithm.",
                 "medium", "CCI-000068", "AC-17 (2)", scope="cisco_ios")
V_202111 = _disa(NDM_SRG, "V-202111", None, "SRG-APP-000395-NDM-000310",
                 "The network device must be configured to authenticate SNMP messages using a "
                 "FIPS-validated Keyed-Hash Message Authentication Code (HMAC).",
                 "medium", "CCI-001967", "IA-3 (1)", scope="any")
V_220641 = _disa(L2S_STIG, "V-220641", "CISC-L2-000210", "SRG-NET-000512-L2S-000007",
                 "The Cisco switch must have all disabled switch ports assigned to an unused VLAN.",
                 "medium", "CCI-004891", "SC-7 (29)", scope="cisco_ios")
V_206666 = _disa(L2S_SRG, "V-206666", None, "SRG-NET-000512-L2S-000007",
                 "The layer 2 switch must have all disabled switch ports assigned to an unused VLAN.",
                 "medium", "CCI-000366", "CM-6 b", scope="any")
V_220642 = _disa(L2S_STIG, "V-220642", "CISC-L2-000220", "SRG-NET-000512-L2S-000008",
                 "The Cisco switch must not have the default VLAN assigned to any host-facing "
                 "switch ports.",
                 "medium", "CCI-004891", "SC-7 (29)", scope="cisco_ios")
V_206667 = _disa(L2S_SRG, "V-206667", None, "SRG-NET-000512-L2S-000008",
                 "The layer 2 switch must not have the default VLAN assigned to any host-facing "
                 "switch ports.",
                 "medium", "CCI-000366", "CM-6 b", scope="any")
V_220630 = _disa(L2S_STIG, "V-220630", "CISC-L2-000100", "SRG-NET-000362-L2S-000022",
                 "The Cisco switch must have Bridge Protocol Data Unit (BPDU) Guard enabled on "
                 "all user-facing or untrusted access switch ports.",
                 "medium", "CCI-002385", "SC-5 a", scope="cisco_ios")
V_206655 = _disa(L2S_SRG, "V-206655", None, "SRG-NET-000362-L2S-000022",
                 "The layer 2 switch must have BPDU Guard enabled on all user-facing or "
                 "untrusted access switch ports.",
                 "medium", "CCI-002385", "SC-5 a", scope="any")
V_220623 = _disa(L2S_STIG, "V-220623", "CISC-L2-000020", "SRG-NET-000148-L2S-000015",
                 "The Cisco switch must uniquely identify and authenticate all network-connected "
                 "endpoint devices before establishing any connection.",
                 "high", "CCI-000778", "IA-3", scope="cisco_ios", relation="related")

CVE_1999_0517 = {
    "source": "NVD",
    "document": "National Vulnerability Database",
    "release": None,
    "rule_id": "CVE-1999-0517",
    "stig_id": None,
    "srg_id": None,
    "title": "An SNMP community name is the default (e.g. public), null, or missing.",
    "url": "https://nvd.nist.gov/vuln/detail/CVE-1999-0517",
    "severity": "high",
    "category": None,
    # NVD's own (primary) metric; a secondary source scores it CVSS 3.1 5.9 medium
    "cvss": {"version": "2.0", "score": 7.5, "vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
             "source": "nvd@nist.gov"},
    "cci": None,
    "nist": None,
    "scope": "any",
    "relation": "requires",
}


CATALOGUE: list = [
    {
        "id": "mgmt-telnet-enabled",
        "title": "Telnet management enabled",
        "why": "Telnet sends the administrator's password and every command in clear text, "
               "so anyone on the path can read them.",
        "applies_to": {"roles": ROLES_ANY, "vendors": None},
        "references": [V_220608, V_202118],
        "severity": "high",
        "cwe": "CWE-319",
        "remediation": "Turn off Telnet on the management lines and use SSH instead.",
    },
    {
        "id": "mgmt-http-enabled",
        "title": "Plain HTTP management enabled",
        "why": "The web interface on TCP 80 sends logins and settings in clear text.",
        "applies_to": {"roles": ROLES_ANY, "vendors": None},
        "references": [V_220586, V_202049],
        "severity": "high",
        "cwe": "CWE-319",
        "remediation": "Turn off the HTTP server; if web management is needed, use HTTPS only.",
    },
    {
        "id": "snmp-no-auth",
        "title": "SNMP managed with a community string",
        "why": "SNMP v1 and v2c use a shared community string sent in clear text, with no "
               "real authentication and no encryption of what is read.",
        "applies_to": {"roles": ROLES_ANY, "vendors": None},
        "references": [V_220604, V_220605, V_202111],
        "severity": "medium",
        "cwe": "CWE-319",
        "remediation": "Move management to SNMPv3 with authentication and privacy "
                       "(authPriv) and remove the v1/v2c communities.",
    },
    {
        "id": "snmp-default-community",
        "title": "Default SNMP community name",
        "why": "The factory names public and private are the first ones an attacker tries, "
               "and they give read access to the whole device.",
        "applies_to": {"roles": ROLES_ANY, "vendors": None},
        "references": [CVE_1999_0517],
        "severity": "high",
        "cwe": "CWE-1392",
        "remediation": "Remove the public and private communities and use SNMPv3 users.",
    },
    {
        "id": "spare-ports-in-used-vlan",
        "title": "Spare access ports in a VLAN in use",
        "why": "A port nobody uses but that sits in a live VLAN gives anyone who plugs into "
               "the socket, or turns the port on, a place on that VLAN.",
        "applies_to": {"roles": SWITCH_ROLES, "vendors": None},
        # The rule's finding: "If any access switch ports are not in use and not
        # in an inactive VLAN, this is a finding." Its trunk part (the parking
        # VLAN kept off every trunk) and its 802.1x exemption are not read.
        "references": [V_220641, V_206666],
        "severity": "medium",
        "cwe": None,
        "remediation": "Move every access port that is not in use to an unused (parking) "
                       "VLAN that no trunk carries.",
    },
    {
        "id": "access-ports-default-vlan",
        "title": "Access ports in the default VLAN",
        "why": "VLAN 1 carries the switch's own control traffic, so hosts placed in it share "
               "a segment with the infrastructure.",
        "applies_to": {"roles": SWITCH_ROLES, "vendors": None},
        "references": [V_220642, V_206667],
        "severity": "medium",
        "cwe": None,
        "remediation": "Assign every host port to a user VLAN other than VLAN 1.",
    },
    {
        "id": "bpdu-guard-missing",
        "title": "BPDU guard missing on access ports",
        "why": "Without BPDU guard, a switch plugged into an access port can take part in "
               "spanning tree and even become its root.",
        "applies_to": {"roles": SWITCH_ROLES, "vendors": ["Cisco"]},
        "references": [V_220630, V_206655],
        "severity": "medium",
        "cwe": None,
        "remediation": "Enable BPDU guard on every user-facing access port.",
    },
    {
        "id": "port-security-disabled",
        "title": "Port security disabled on access ports",
        "why": "Without port security an access port accepts any number of MAC addresses, "
               "so a rogue switch or a MAC flood goes unchecked.",
        "applies_to": {"roles": SWITCH_ROLES, "vendors": ["Cisco"]},
        # DISA asks for 802.1x endpoint authentication instead (V-220623); port
        # security itself carries no published severity.
        "references": [V_220623],
        "severity": None,
        "cwe": None,
        "remediation": "Enable port security with a small MAC limit, or 802.1x "
                       "authentication, on every access port.",
    },
]

_BY_ID = {c["id"]: c for c in CATALOGUE}


def by_id(check_id: str) -> dict:
    return _BY_ID[check_id]


def references_for(check: dict, family: Optional[str]) -> list:
    """The references to cite for a device of software ``family``.

    A Cisco IOS device gets the Cisco STIG rules; any other device gets the
    vendor-neutral requirements. A reference with scope "any" and no Cisco
    counterpart (NVD) goes to every device.
    """
    cisco = [r for r in check["references"] if r["scope"] == "cisco_ios"]
    if family == "cisco_ios" and cisco:
        return cisco
    return [r for r in check["references"] if r["scope"] == "any"]
