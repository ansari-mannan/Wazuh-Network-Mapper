"""OVSS: one score per finding (one CVE on one node), from its CVSS base
score, where the node sits and what depends on it, and whether the CVE is
being exploited. Pure functions; the stage (stage.py) supplies the inputs.

    OVSS       = CVSS_B x Context x ThreatMult        (0 to 10, never above CVSS_B)
    Context    = 0.5 + 0.5 x (Exposure + Dependency) / 2
    ThreatMult = 0.5 + 0.5 x T
    T          = 1.0 if the CVE is in CISA KEV, else min(EPSS / 0.1, 1.0)
    Node score = max(OVSS of the node's scored findings)

Exposure: 1.0 for the egress device (role "router", checked first), 0.3 for a
node whose VLANs no router routes to another VLAN, 0.5 otherwise, and 0.5
flagged ``exposure_unknown`` when the node could not be placed in a VLAN.
Dependency: max(share of the other nodes that depend on it, the FIPS 199
weight the owner gave it in targets.json).

Tiers: P0 at 6.75 and above, P1 at 4.5, P2 at 2.5, else P3; then, on the tier
only and in this order: a potential (version-match) finding not in KEV is
capped at P1; a KEV finding on the egress device is P0; any KEV finding is at
least P1. The tier is taken from the score as published (3 decimals).
"""

from __future__ import annotations

from typing import Optional

from .cvss_select import conflict, select

# ---- constants: tune OVSS here ------------------------------------------------
CONTEXT_FLOOR = 0.5         # a CVE on an unexposed, unimportant node still counts half
THREAT_FLOOR = 0.5          # no sign of exploitation halves the score, never zeroes it
EPSS_SATURATION = 0.1       # EPSS at or above this counts as full threat (T = 1.0)
EXPOSURE_EGRESS = 1.0       # the egress device (role EGRESS_ROLE)
EXPOSURE_INTERNAL = 0.5     # inside, in a VLAN routed to other VLANs
EXPOSURE_ISOLATED = 0.3     # in VLANs no router connects to any other
EXPOSURE_UNKNOWN = 0.5      # not placed in a VLAN: treated as internal, and flagged
EGRESS_ROLE = "router"
IMPORTANCE_WEIGHT = {"high": 1.0, "moderate": 0.5, "low": 0.25}   # FIPS 199; unmarked 0
TIER_CUTS = (("P0", 6.75), ("P1", 4.5), ("P2", 2.5))              # below the last: P3
# --------------------------------------------------------------------------------

TIERS = ("P0", "P1", "P2", "P3")
UNRATED = "Unrated"
UNASSESSED = "Unassessed"
ASSESSED = "assessed"
EXPOSURE_UNKNOWN_FLAG = "exposure_unknown"
CONFIRMED, POTENTIAL = "confirmed", "potential"


def threat(kev: bool, epss: Optional[float]) -> float:
    """T: 1.0 for a KEV CVE, else EPSS scaled so EPSS_SATURATION reaches 1.0."""
    return 1.0 if kev else min((epss or 0.0) / EPSS_SATURATION, 1.0)


def context(exposure: float, dependency: float) -> float:
    return CONTEXT_FLOOR + (1 - CONTEXT_FLOOR) * (exposure + dependency) / 2


def ovss(cvss_b: float, exposure: float, dependency: float, kev: bool,
         epss: Optional[float]) -> float:
    return cvss_b * context(exposure, dependency) * (THREAT_FLOOR + (1 - THREAT_FLOOR)
                                                     * threat(kev, epss))


def tier(score: float, *, kev: bool, potential: bool, exposure: float) -> str:
    """The finding's tier from its score, then the three overrides in order."""
    base = next((name for name, cut in TIER_CUTS if score >= cut), "P3")
    if potential and not kev and base == "P0":
        base = "P1"
    if kev and exposure == EXPOSURE_EGRESS:
        return "P0"
    if kev and base in ("P2", "P3"):
        return "P1"
    return base


def exposure_of(node: dict, vlans: Optional[set], routed_vlans: set) -> tuple:
    """``(exposure, flag)``. ``vlans`` is the node's placement (None: not placed);
    ``routed_vlans`` the VLANs some router routes to another VLAN."""
    if node.get("role") == EGRESS_ROLE:
        return EXPOSURE_EGRESS, None
    if vlans is None:
        return EXPOSURE_UNKNOWN, EXPOSURE_UNKNOWN_FLAG
    if not vlans & routed_vlans:
        return EXPOSURE_ISOLATED, None
    return EXPOSURE_INTERNAL, None


def dependency_of(dependants: int, n_nodes: int, importance: Optional[str]) -> tuple:
    """``(dependency, importance weight)``."""
    topology = min(dependants / max(n_nodes - 1, 1), 1.0)
    weight = IMPORTANCE_WEIGHT.get(importance, 0.0)
    return max(topology, weight), weight


def finding_record(cve: Optional[str], tool_score, tool_version, record: Optional[dict], *,
                   kev_ids: set, epss_scores: dict, exposure: float, dependency: float,
                   confidence: str) -> dict:
    """The OVSS fields added to one finding in vulnerabilities.json."""
    used, src, ver = select(record, tool_score, tool_version)
    kev = cve in kev_ids
    epss = epss_scores.get(cve, 0.0)
    score = None if used is None else round(ovss(used, exposure, dependency, kev, epss), 3)
    return {
        "score": score,
        "tier": UNRATED if score is None else tier(score, kev=kev, exposure=exposure,
                                                   potential=confidence == POTENTIAL),
        "cvss_tool": tool_score,
        "cvss_used": used,
        "cvss_src": src,
        "cvss_ver": ver,
        "kev": kev,
        "epss": epss,
        "exposure": exposure,
        "dependency": round(dependency, 3),
        "confidence": confidence,
        "conflict": conflict(src, used, ver, tool_score, tool_version),
    }


def node_record(records: list, *, cve_lookup: Optional[dict], exposure: float,
                exposure_flag: Optional[str], dependency: float, importance: float) -> dict:
    """The OVSS fields of one graph node from its findings' records, one per
    distinct CVE (an empty list: nothing was found, or nothing looked up)."""
    hist = dict.fromkeys(TIERS + (UNRATED,), 0)
    for r in records:
        hist[r["tier"]] += 1
    scores = [r["score"] for r in records if r["score"] is not None]
    used = [r["cvss_used"] for r in records if r["cvss_used"] is not None]
    if scores:
        status, reason = ASSESSED, None
    elif records:
        status, reason = UNRATED, None
    else:
        status = UNASSESSED
        lookup = cve_lookup or {}
        reason = (f"{lookup.get('match') or 'version'} match returned 0 CVEs"
                  if lookup.get("total") == 0 else "no findings returned")
    return {
        "risk_score": max(scores) if scores else None,
        "node_tier": next((t for t in TIERS if hist[t]), None),
        "ovss_hist": hist,
        "ovss_status": status,
        "ovss_reason": reason,
        "exposure": exposure,
        "exposure_flag": exposure_flag,
        "dependency": round(dependency, 3),
        "importance": importance,
        "kev_count": sum(1 for r in records if r["kev"]),
        "max_cvss": max(used) if used else None,
    }
