"""Exposure paths: for each asset the owner marked important (targets.json),
the most likely routes to it from a place assumed already compromised, so the
weakest link can be closed first. The scan's last stage; it reads only files
and writes attack_paths.json beside the graph.
"""

from __future__ import annotations

import argparse
import json
import logging
import math
import os
import sys
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional

import networkx as nx

from . import vulnfile
from .checklist import catalogue
from .checklist import tables as t
from .checklist.evaluate import l3_vlans
from .common import StageResult, plural, setup_logging, write_json_atomic

if TYPE_CHECKING:
    from .pipeline import ScanContext

log = logging.getLogger("vulnmapper.attackpaths")

FILENAME = "attack_paths.json"
TARGETS_FILENAME = "targets.json"
KEEP_PER_TARGET = 10
IMPORTANCE = ("high", "moderate", "low")       # FIPS 199 impact levels, no other scale
ROUTER_ROLES = ("router", "l3-switch")
# Wazuh agent states that mean the host is not there: never a starting point
# (the plugin's offline rule, topology/inactive.ts, uses the same two).
AGENT_OFFLINE = ("disconnected", "never_connected")
FOUR = ("attack_vector", "attack_complexity", "privileges_required", "user_interaction")

# NIST IR 7788 likelihood by CVSS attack complexity; the misconfiguration steps
# reuse it on the CVSS v2 Access Complexity rating the catalogue already quotes.
STEP_BY_COMPLEXITY = {"LOW": 0.9, "MEDIUM": 0.6, "HIGH": 0.2}
MISCONFIG_CHECKS = ("snmp-default-community", "mgmt-telnet-enabled",
                    "mgmt-http-enabled", "snmp-no-auth")

_IR7788 = {"title": "NIST IR 7788, Security Risk Analysis of Enterprise Networks "
                    "Using Probabilistic Attack Graphs",
           "url": "https://csrc.nist.gov/pubs/ir/7788/final"}
SOURCES = [
    _IR7788,
    {"title": catalogue.CCSS[0], "url": catalogue.CCSS[1]},
    {"title": catalogue.CVSS2_GUIDE[0], "url": catalogue.CVSS2_GUIDE[1]},
    {"title": "FIPS 199, Standards for Security Categorization of Federal "
              "Information and Information Systems",
     "url": "https://csrc.nist.gov/pubs/fips/199/final"},
]

REACHABILITY = [
    "Assets in the same VLAN reach each other directly.",
    "Assets in different VLANs reach each other only through a device whose role "
    "is router or l3-switch with an up layer-3 interface in both VLANs; the "
    "lowest-id qualifying router is used.",
    "Routed VLANs are derived offline from each device's interface names.",
    "Firewall and access-control rules are not read, so a route that crosses a "
    "router shows only that the two VLANs are routed, not that traffic is "
    "permitted.",
]
LIMITS = [
    "Firewall and access-control rules are not read.",
    "Attacks that need an account (privileges) or a user action are not modelled.",
    "CVSS v4 Attack Requirements cannot be read (no vector string is stored), so "
    "a v4 CVE is judged on its other fields; such CVEs are kept, not discarded.",
    "The NIST IR 7788 mapping is coarse (three values), so many routes tie.",
    "The mapping is applied beyond the CVSS version it was written for.",
    "Only the single highest-likelihood route is kept per target and start.",
    "Spare-port lists are truncated by the checklist, so a start may stand for "
    "more ports than it lists.",
    "Assets with no known VLAN are left out of reachability.",
    "An unverified asset is shown as unverified, not as safe.",
]


# --- step values: the rules that turn a CVE or a finding into a step --------

def _qualifies(row: dict, cross_router: bool) -> bool:
    """A CVE gives a weakness step: no privileges, no user interaction, and a
    reachable attack vector — Network always, Adjacent only within a VLAN."""
    if row["privileges_required"] != "NONE" or row["user_interaction"] != "NONE":
        return False
    if cross_router:
        return row["attack_vector"] == "NETWORK"
    return row["attack_vector"] in ("NETWORK", "ADJACENT")


def _best_weakness(candidates: list, cross_router: bool) -> Optional[dict]:
    """The easiest qualifying CVE: highest step value, ties to the higher score."""
    best = None
    for r in candidates:
        if not _qualifies(r, cross_router):
            continue
        value = STEP_BY_COMPLEXITY.get(r["attack_complexity"])
        if value is None:
            continue
        key = (value, r.get("cvss") or 0.0)
        if best is None or key > best[0]:
            best = (key, r, value)
    if best is None:
        return None
    _, r, value = best
    return {"kind": "weakness", "cve": r["cve"], "attack_vector": r["attack_vector"],
            "attack_complexity": r["attack_complexity"], "value": value, "source": _IR7788}


def _best_misconfig(node: dict) -> Optional[dict]:
    """The easiest of the device's clear-text/default findings (same VLAN only)."""
    best = None
    for f in node.get("config_findings") or []:
        if f["id"] not in MISCONFIG_CHECKS:
            continue
        exposure = catalogue.by_id(f["id"]).get("exposure")
        if not exposure:
            continue
        value = STEP_BY_COMPLEXITY.get(exposure["access_complexity"])
        if value is None:
            continue
        key = (value, f["id"])      # value, then a stable tie-break
        if best is None or key > (best["value"], best["check"]):
            best = {"kind": "misconfiguration", "check": f["id"], "title": f["title"],
                    "access_complexity": exposure["access_complexity"], "value": value,
                    "source": {"title": exposure["source"], "url": exposure["url"]}}
    return best


def _context_findings(node: dict) -> list:
    """The device's other findings, which add no step but are shown as context."""
    return [{"id": f["id"], "title": f["title"], "severity": f.get("severity")}
            for f in node.get("config_findings") or [] if f["id"] not in MISCONFIG_CHECKS]


def _takeover(node: dict, candidates: list, cross_router: bool) -> Optional[dict]:
    """The best way to take ``node`` over in this scope (weakness or, in-VLAN, a
    misconfiguration): higher step value, a CVE winning an exact tie."""
    options = [o for o in (_best_weakness(candidates, cross_router),
                           None if cross_router else _best_misconfig(node)) if o]
    if not options:
        return None
    return max(options, key=lambda o: (o["value"], o["kind"] == "weakness"))


def _order_key(route: dict) -> tuple:
    """Within a target, never a blended score: likelihood, then the highest node
    OVSS along the route, then fewer steps, then start id, then the ids along it."""
    return (-route["likelihood"], -route["highest_ovss"], len(route["steps"]),
            route["start"], tuple(s["to"] for s in route["steps"]))


class AttackPathEngine:
    """The exposure-path computation over one graph.

    Built once from the graph, the owner's targets and the CVE findings, it
    holds what every route needs: the node lookup, each asset's VLANs, the
    routers and the VLANs they route, each asset's usable CVEs, and the way to
    take every placed asset over within a VLAN and across a router. The
    public methods are the computation's steps; ``compute`` runs them all.

    Reachability is decided offline. Assets in one VLAN reach each other
    directly; across VLANs only through a router or l3-switch with an up
    layer-3 interface in both (the lowest node id among them). Firewall rules
    are not read, so a route through a router says so. A host's VLAN is its
    ``vlan``, a Wi-Fi client's that of the one up sub-interface on its radio,
    a device's every VLAN it has an up layer-3 interface for; an asset with
    none is "not placed", never guessed.

    A route's likelihood is the product of its step values (NIST IR 7788):
    crossing a router is 1, taking an asset over is 0.9 / 0.6 / 0.2 by attack
    complexity. Dijkstra on the negative logarithms finds the single most
    likely route for each start and target.
    """

    def __init__(self, graph: dict, targets: Optional[dict], vulns: Optional[dict],
                 keep: int = KEEP_PER_TARGET, liveness: Optional[dict] = None) -> None:
        self.graph = graph
        self.inactive = inactive_hosts(graph, liveness)
        self.targets = targets or {}
        self.vulns = vulns
        self.keep = keep
        self.by_id = {n["node_id"]: n for n in graph["nodes"]}
        self.placed, self.not_placed = self.placement()
        self.candidates = {nid: self._candidates(self.by_id[nid]) for nid in self.placed}
        self.routers = {nid: self._routes(n) for nid, n in self.by_id.items()
                        if n.get("role") in ROUTER_ROLES and self._routes(n)}
        # The best takeover of each placed asset, keyed by whether the attacker
        # crosses a router to reach it (False: same VLAN, True: across).
        self.takeover = {nid: {cross: _takeover(self.by_id[nid], self.candidates[nid], cross)
                               for cross in (False, True)} for nid in self.placed}
        self.starts, self.offline_starts = self.find_starts()
        self.reachability = self.reachability_graph()

    # ---- where each asset sits --------------------------------------------------

    @staticmethod
    def _l3_vlans(node: dict) -> set:
        """VLANs a device has an up layer-3 interface for, via the checklist helper."""
        ps = node.get("port_status") or {}
        config = {"interfaces": {i: {"name": name, "oper": t.UP if state == "up" else 2}
                                 for i, (name, state) in enumerate(ps.items())}}
        return l3_vlans(config)

    def _routes(self, node: dict) -> set:
        return self._l3_vlans(node) if node.get("role") in ROUTER_ROLES else set()

    @staticmethod
    def _radio_vlans(ap: dict, radio: Optional[str]) -> set:
        """VLANs of the up sub-interfaces on ``radio`` (e.g. "Do0" -> "Do0.80")."""
        out = set()
        for name, state in (ap.get("port_status") or {}).items():
            base, _, sub = str(name).partition(".")
            if state == "up" and sub.isdigit() and base == radio:
                out.add(int(sub))
        return out

    def placement(self) -> tuple[dict, list]:
        """``({node_id: {vlan, ...}}, [{"id", "reason"}])``: placed and not placed assets."""
        placed, not_placed = {}, []
        for nid, node in self.by_id.items():
            if node["kind"] == "device":
                vlans = self._l3_vlans(node)
                if vlans:
                    placed[nid] = vlans
                else:
                    not_placed.append({"id": nid,
                                       "reason": "no up layer-3 interface with a VLAN number"})
                continue
            if node.get("vlan"):
                placed[nid] = {int(node["vlan"])}
            elif node.get("wifi"):
                radio = node["wifi"].get("radio")
                ap = self.by_id.get(node["wifi"].get("access_point"))
                vlans = self._radio_vlans(ap, radio) if ap else set()
                if len(vlans) == 1:
                    placed[nid] = set(vlans)
                else:
                    why = (f"the radio {radio} has {len(vlans)} up sub-interfaces; its VLAN "
                           "is ambiguous" if vlans else
                           f"the radio {radio} has no up sub-interface with a VLAN number")
                    not_placed.append({"id": nid, "reason": why})
            else:
                not_placed.append({"id": nid, "reason": "no known VLAN"})
        return placed, not_placed

    def _candidates(self, node: dict) -> list:
        """The node's CVEs that carry the four vector fields (vulnerabilities.json
        when it has the full list, else the graph's top_cves)."""
        nid = node["node_id"]
        host = (self.vulns or {}).get("hosts", {}).get(nid)
        cat = (self.vulns or {}).get("cves", {})
        rows = []
        if host and host.get("findings") is not None:
            for f in host["findings"]:
                c = cat.get(f.get("cve"))
                if c and all(k in c for k in FOUR):
                    rows.append({"cve": f["cve"], "cvss": c.get("cvss"),
                                 **{k: c[k] for k in FOUR}})
        else:
            for r in node.get("top_cves") or []:
                if all(k in r for k in FOUR):
                    rows.append(r)
        return rows

    # ---- the reachability graph -------------------------------------------------

    def _router_between(self, a_vlans: set, b_vlans: set, exclude: set) -> Optional[str]:
        for rid in sorted(self.routers):             # lowest node id among qualifiers
            routed = self.routers[rid]
            if rid not in exclude and routed & a_vlans and routed & b_vlans:
                return rid
        return None

    def reachability_graph(self) -> nx.DiGraph:
        """Directed: an edge u->v means v can be taken over from a compromised u.

        Spare-port starts (``{"id", "membership"}``) get out-edges only: never a
        target, never a stepping stone.
        """
        g = nx.DiGraph()
        members = dict(self.placed)
        for s in self.starts:
            if "membership" in s:
                members[s["id"]] = s["membership"]
        for u, mu in members.items():
            for v, mv in self.placed.items():
                if u == v:
                    continue
                if mu & mv:
                    cross, router = False, None
                else:
                    router = self._router_between(mu, mv, {u, v})
                    if router is None:
                        continue
                    cross = True
                step = self.takeover[v][cross]
                if step is None:
                    continue
                g.add_edge(u, v, weight=-math.log(step["value"]), step=step,
                           cross=cross, router=router)
        return g

    # ---- starting points --------------------------------------------------------

    def find_starts(self) -> tuple[list, list]:
        """``(starts, offline)``. A start is a placed managed host with a CVE, a
        placed unmanaged host, or the spare ports of one VLAN on a switch. A
        managed host whose Wazuh agent is disconnected or never connected, or a
        host a fresh liveness pass marks inactive, is no start; it is listed in
        ``offline`` instead."""
        starts, offline = [], []
        for nid, node in self.by_id.items():
            if node["kind"] == "device" or nid not in self.placed:
                continue
            if node.get("unmanaged"):
                kind = "unmanaged_host"
            elif node.get("agent_id") and node.get("top_cves"):
                kind = "managed_host"
            else:
                continue
            status = (node.get("status") or "").lower()
            if kind == "managed_host" and status in AGENT_OFFLINE:
                offline.append({"id": nid, "kind": kind, "reason": "offline",
                                "detail": f"Wazuh agent {status.replace('_', ' ')}"})
                continue
            if nid in self.inactive:
                offline.append({"id": nid, "kind": kind, "reason": "offline",
                                "detail": "not answering the liveness check"})
                continue
            starts.append({"id": nid, "kind": kind, "vlans": sorted(self.placed[nid])})
        return starts + self._spare_starts(), offline

    def _spare_starts(self) -> list:
        """One start per (switch, VLAN) from each switch's spare-port finding."""
        starts = []
        for nid, node in self.by_id.items():
            if node["kind"] != "device":
                continue
            finding = next((f for f in node.get("config_findings") or []
                            if f["id"] == "spare-ports-in-used-vlan" and f.get("evidence")), None)
            if not finding:
                continue
            ev = finding["evidence"]
            listed = ev.get("ports") or []
            truncated = ev.get("total") is not None and ev["total"] > len(listed)
            by_vlan: dict = {}
            for p in listed:
                by_vlan.setdefault(p["vlan"], []).append(p["port"])
            for vlan, ports in sorted(by_vlan.items()):
                starts.append({"id": f"start:spare-ports:{nid}:{vlan}", "kind": "spare_ports",
                               "switch": nid, "switch_label": self._label(nid),
                               "vlans": [vlan], "ports": ports,
                               "listed_ports": len(ports), "spare_ports_on_switch": ev.get("total"),
                               "list_truncated": truncated, "membership": {vlan}})
        return starts

    # ---- routes -----------------------------------------------------------------

    def _label(self, nid: str) -> str:
        node = self.by_id[nid]
        return node.get("hostname") or node["node_id"]

    def route(self, start: dict, target: str) -> Optional[dict]:
        """The single highest-likelihood route from ``start`` to ``target``, or None."""
        try:
            path = nx.dijkstra_path(self.reachability, start["id"], target)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return None

        steps, likelihood = [], 1.0
        for a, b in zip(path, path[1:]):
            edge = self.reachability.edges[a, b]
            dest = self.by_id[b]
            if edge["cross"]:
                steps.append({"kind": "transit", "from": a, "through": edge["router"], "to": b,
                              "value": 1.0, "source": _IR7788,
                              "note": "firewall and access rules are not read"})
            step = dict(edge["step"])
            likelihood *= step["value"]
            step.update({"from": edge["router"] if edge["cross"] else a, "to": b,
                         "destination_ovss": dest.get("risk_score"),
                         "context_findings": _context_findings(dest)})
            steps.append(step)

        scores = [self.by_id[nid].get("risk_score") for nid in path if nid in self.by_id]
        return {
            "target": target,
            "start": start["id"],
            "start_kind": start["kind"],
            "steps": steps,
            "likelihood": round(likelihood, 6),
            "highest_ovss": max([s for s in scores if s is not None], default=0.0),
            "crosses_router": any(s["kind"] == "transit" for s in steps),
            "narrative": self._narrative(start, steps, target),
        }

    def _narrative(self, start: dict, steps: list, target: str) -> str:
        if start["kind"] == "spare_ports":
            opening = (f"From {start['listed_ports']} spare port(s) in VLAN {start['vlans'][0]} "
                       f"on {start['switch_label']}"
                       + (" (on the target itself)" if start["switch"] == target else ""))
        elif start["kind"] == "unmanaged_host":
            opening = f"From {self._label(start['id'])} (unmanaged, state unknown)"
        else:
            opening = f"From {self._label(start['id'])}, assumed already compromised"
        parts = [opening]
        for s in steps:
            if s["kind"] == "transit":
                parts.append(f"cross into the target's VLAN through {self._label(s['through'])} "
                             "(firewall rules not checked)")
            elif s["kind"] == "weakness":
                parts.append(f"take over {self._label(s['to'])} using {s['cve']} "
                             f"({s['attack_complexity'].lower()} complexity)")
            else:
                parts.append(f"take over {self._label(s['to'])} through {s['title'].lower()}")
        return ", ".join(parts) + "."

    # ---- the document -----------------------------------------------------------

    def _target_blocks(self) -> tuple[list, list, int]:
        """``(target blocks, kept routes, pairs with a route)``, in browse order."""
        all_routes, pairs_with_route, blocks = [], 0, []
        for tid, info in self.targets.items():
            if tid not in self.by_id:
                continue
            importance = info.get("importance")
            # a start that is the target itself is skipped
            routes = [r for r in (self.route(start, tid) for start in self.starts
                                  if start["id"] != tid) if r]
            pairs_with_route += len(routes)
            rank = sorted(routes, key=_order_key)[:self.keep]
            for i, r in enumerate(rank, 1):
                r["rank"] = i
                r["importance"] = importance
            all_routes.extend(rank)
            blocks.append({"id": tid, "importance": importance, "note": info.get("note"),
                           "present": True, "label": self._label(tid), "routes": rank})
        for tid, info in self.targets.items():
            if tid not in self.by_id:
                blocks.append({"id": tid, "importance": info.get("importance"),
                               "note": info.get("note"), "present": False,
                               "reason": "no node with this id in the graph"})
        # stable order: importance, then how many routes, then id
        blocks.sort(key=lambda b: (IMPORTANCE.index(b["importance"])
                                   if b["importance"] in IMPORTANCE else len(IMPORTANCE),
                                   -len(b.get("routes") or []), b["id"]))
        return blocks, all_routes, pairs_with_route

    def dependants(self) -> dict:
        """Hosts that depend on each asset (browse-list order and OVSS
        Dependency, never route order): a switch counts the hosts attached to it, a router also those in
        the VLANs it routes, a host none. A host is any non-device node."""
        hosts = [n for n in self.by_id.values() if n["kind"] != "device"]
        out = {}
        for nid, node in self.by_id.items():
            if node["kind"] != "device":
                out[nid] = 0
                continue
            routed = self._routes(node)
            out[nid] = sum(1 for h in hosts
                           if h.get("parent_id") == nid or (routed and h.get("vlan") in routed))
        return out

    def _per_asset(self, all_routes: list) -> list:
        through = {nid: 0 for nid in self.by_id}
        for r in all_routes:
            for nid in {s["from"] for s in r["steps"]} | {s["to"] for s in r["steps"]}:
                if nid in through:
                    through[nid] += 1
        dependants = self.dependants()
        per_asset = []
        for nid, node in self.by_id.items():
            status = (node.get("reachable_cve") or {}).get("status")
            per_asset.append({"id": nid, "kind": node["kind"], "label": self._label(nid),
                              "dependants": dependants[nid], "verified": status != "unverified",
                              "routes_through": through[nid]})
        per_asset.sort(key=lambda a: (-a["dependants"], a["id"]))     # browse order
        return per_asset

    def _cves_v4(self) -> int:
        """Distinct CVEs scored with CVSS v4 (their Attack Requirements go unread)."""
        seen = set()
        for node in self.by_id.values():
            for r in node.get("top_cves") or []:
                if str(r.get("cvss_version") or "").startswith("4"):
                    seen.add(r.get("cve"))
        return len(seen)

    def compute(self) -> dict:
        """The attack_paths.json document."""
        target_ids = list(self.targets)
        present = [tid for tid in target_ids if tid in self.by_id]
        blocks, all_routes, pairs_with_route = self._target_blocks()
        per_asset = self._per_asset(all_routes)
        most_shared = max(per_asset, key=lambda a: (a["routes_through"], -len(a["id"])),
                          default=None)
        most_shared = most_shared["id"] if most_shared and most_shared["routes_through"] else None
        verified = sum(1 for a in per_asset if a["verified"])
        return {
            "metadata": {
                "computed_at": datetime.now(timezone.utc).isoformat(),
                "source_scan": self.graph.get("metadata", {}).get("scan_time"),
                "state": "no_targets" if not target_ids else "ok",
                "keep_per_target": self.keep,
                "counts": {
                    "targets": len(target_ids), "targets_present": len(present),
                    "targets_missing": len(target_ids) - len(present),
                    "starting_points": len(self.starts),
                    "offline_starts": len(self.offline_starts),
                    "routes": len(all_routes), "pairs_with_route": pairs_with_route,
                    "pairs_total": len(present) * len(self.starts), "placed": len(self.placed),
                    "not_placed": len(self.not_placed), "assets_verified": verified,
                    "assets_unverified": len(per_asset) - verified,
                    "cves_v4_unread": self._cves_v4(),
                },
                "sources": SOURCES,
                "reachability": REACHABILITY,
                "limits": LIMITS,
                "most_shared_asset": most_shared,
            },
            "targets": blocks,
            "starting_points": [{k: v for k, v in s.items() if k != "membership"}
                                for s in self.starts],
            "offline_starts": self.offline_starts,
            "per_asset": per_asset,
            "not_placed": self.not_placed,
        }


def inactive_hosts(graph: dict, liveness: Optional[dict]) -> set:
    """The endpoints a liveness pass marks inactive, if that pass was made for
    this graph (its graph_scan_time is the graph's scan_time); else none, so a
    stale or missing liveness.json changes nothing."""
    scan_time = (graph.get("metadata") or {}).get("scan_time")
    if not liveness or not scan_time or liveness.get("graph_scan_time") != scan_time:
        return set()
    nodes = liveness.get("nodes") if isinstance(liveness.get("nodes"), dict) else {}
    return {nid for nid, rec in nodes.items()
            if isinstance(rec, dict) and rec.get("state") == "inactive"}


def compute(graph: dict, targets: Optional[dict], vulns: Optional[dict],
            keep: int = KEEP_PER_TARGET, liveness: Optional[dict] = None) -> dict:
    """Build the attack_paths document from the graph, targets, CVE findings
    and (optionally) the liveness state."""
    return AttackPathEngine(graph, targets, vulns, keep, liveness).compute()


# --- files, the pipeline stage and the CLI -----------------------------------

def default_path(graph_path: str) -> str:
    return os.path.join(os.path.dirname(os.path.abspath(graph_path)), FILENAME)


def targets_path(graph_path: str) -> str:
    return os.path.join(os.path.dirname(os.path.abspath(graph_path)), TARGETS_FILENAME)


# The graph warning for a targets.json that was ignored.
TARGETS_INVALID = "targets_invalid"


def load_targets(path: Optional[str], warnings: Optional[list] = None) -> Optional[dict]:
    """``{id: {importance, note?}}`` from targets.json; None when there is no
    file, or (with a warning, logged and appended to ``warnings``) when it is
    not that shape, so a hand-edited file cannot fail every scan."""
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            targets = json.load(f)
    except (OSError, ValueError) as exc:
        log.warning("ignoring targets file %s: %s", path, exc)
        targets = None
    if targets is not None and isinstance(targets, dict) and all(
            isinstance(v, dict) and v.get("importance") in IMPORTANCE
            and isinstance(v.get("note", ""), str) for v in targets.values()):
        return targets
    if targets is not None:
        log.warning("ignoring targets file %s: expected {id: {importance: high|moderate|low, "
                    "note?}}", path)
    if warnings is not None:
        warnings.append({"type": TARGETS_INVALID})
    return None


def run_stage(graph: dict, targets: Optional[dict], vulns: Optional[dict],
              paths_out: Optional[str], keep: int = KEEP_PER_TARGET,
              liveness: Optional[dict] = None) -> dict:
    """Compute the document and, when ``paths_out`` is set, write it there.
    The graph gains no fields."""
    document = compute(graph, targets, vulns, keep, liveness)
    if paths_out:
        write_json_atomic(paths_out, document)
        log.info("wrote attack paths to %s", paths_out)
    return document


def run_attack_paths(scan: "ScanContext") -> StageResult:
    """The pipeline's exposure-path stage. It runs last, once the graph's
    scan_time is final, so attack_paths.json's source_scan names this graph,
    on the engine the OVSS stage built and scored the nodes with.
    No liveness here: any liveness.json describes the previous graph."""
    document = scan.engine.compute()
    write_json_atomic(scan.paths_out, document)
    log.info("wrote attack paths to %s", scan.paths_out)
    c = document["metadata"]["counts"]
    return StageResult(note=f"{plural(c['routes'], 'route')} to "
                            f"{plural(c['targets_present'], 'protected asset')}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulnmapper.attackpaths",
        description="Recompute attack_paths.json from a graph, its targets and CVE "
                    "findings. Files only, no network.")
    parser.add_argument("--graph", required=True, metavar="PATH",
                        help="the graph JSON to read (attack_paths.json is written beside it).")
    parser.add_argument("--targets", metavar="PATH",
                        help="targets JSON (default: targets.json beside the graph).")
    parser.add_argument("--paths-out", metavar="PATH",
                        help="where to write (default: attack_paths.json beside the graph).")
    parser.add_argument("--vulns", metavar="PATH",
                        help="vulnerabilities.json for the full CVE list (default: beside the "
                             "graph if present; else each node's top_cves are used).")
    parser.add_argument("--liveness", metavar="PATH",
                        help="liveness.json; hosts it marks inactive are not used as starts "
                             "when it was made for this graph (default: not used).")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    """``python -m vulnmapper.attackpaths --graph PATH``: recompute attack_paths.json
    beside a graph without a rescan (the dashboard runs it when a target is marked).
    Neither input is changed and nothing is sent on the network."""
    setup_logging()
    args = build_parser().parse_args(argv)
    try:
        with open(args.graph, encoding="utf-8") as f:
            graph = json.load(f)
    except (OSError, ValueError) as exc:
        log.error("could not read graph %s: %s", args.graph, exc)
        return 1
    targets = load_targets(args.targets or targets_path(args.graph))
    vulns_path = args.vulns or vulnfile.default_path(args.graph)
    vulns = None
    if os.path.exists(vulns_path):
        with open(vulns_path, encoding="utf-8") as f:
            vulns = json.load(f)
    liveness = None
    if args.liveness and os.path.exists(args.liveness):
        try:
            with open(args.liveness, encoding="utf-8") as f:
                liveness = json.load(f)
        except (OSError, ValueError) as exc:
            log.warning("ignoring liveness state %s: %s", args.liveness, exc)
    out = args.paths_out or default_path(args.graph)
    document = run_stage(graph, targets, vulns, out, liveness=liveness)
    log.info("attack paths: %d route(s) to %d target(s) from %d starting point(s)",
             document["metadata"]["counts"]["routes"],
             document["metadata"]["counts"]["targets_present"],
             document["metadata"]["counts"]["starting_points"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
