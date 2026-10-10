"""Exposure paths: the most likely routes to each important asset.

Given the assets an owner marks as important (targets.json), this lists the most
likely route to each from a starting point assumed already compromised, so the
weakest link can be closed first. It is a graph computation over data the scan
already holds; it reads only files and never touches the network.

The question: if one place on the network were already in an attacker's hands,
which of the owner's important assets could be reached, and how easily?

Reachability (which assets can communicate) is decided offline from the graph:

  * same VLAN -> reachable directly;
  * different VLANs -> only through a device whose role is router or l3-switch
    that has an up layer-3 interface in both VLANs (its routed VLANs derive from
    its interface names, reusing the checklist's :func:`l3_vlans`); the
    lowest-id qualifying router is chosen and named. Firewall and access rules
    are not read, so every route crossing a router carries that note.

An asset's VLANs: a host sits in its ``vlan``; a Wi-Fi client in the VLAN of the
single up sub-interface on its radio (several -> left out); a device in every
VLAN it has an up layer-3 interface for. An asset with no known VLAN is "not
placed" (never guessed).

Step values (the only numbers; NIST IR 7788, with the misconfiguration mapping
from the catalogue's CCSS/CVSS v2 ratings):

  * transit through a router: 1 (a network-access step is not a real step);
  * weakness step (a CVE lets the next asset be taken over): 0.9 / 0.6 / 0.2
    from the CVE's attack complexity (LOW / MEDIUM / HIGH);
  * misconfiguration step: the same mapping, from the finding's exposure rating.

A route's likelihood is the product of its step values. The single
highest-likelihood route per target+start pair is found with Dijkstra on the
negative log of the step values.

Recompute an existing graph without a rescan::

    python -m vulnmapper.attackpaths --graph data/graph.json [--targets PATH]
                                     [--paths-out PATH] [--vulns PATH]

It reads the graph, the targets and vulnerabilities.json if present, rewrites
attack_paths.json beside the graph, changes neither input and makes no network
call.
"""

from __future__ import annotations

import argparse
import json
import logging
import math
import os
import sys
from datetime import datetime, timezone
from typing import Optional

import networkx as nx

from . import vulnfile
from .checklist import catalogue
from .checklist import tables as t
from .checklist.evaluate import l3_vlans

log = logging.getLogger("vulnmapper.attackpaths")

FILENAME = "attack_paths.json"
TARGETS_FILENAME = "targets.json"
KEEP_PER_TARGET = 10
IMPORTANCE = ("high", "moderate", "low")       # FIPS 199 impact levels, no other scale
ROUTER_ROLES = ("router", "l3-switch")
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


# --- VLAN membership and routing (offline, from port_status) -----------------

def _l3_vlans(node: dict) -> set:
    """VLANs a device has an up layer-3 interface for, via the checklist helper."""
    ps = node.get("port_status") or {}
    config = {"interfaces": {i: {"name": name, "oper": t.UP if state == "up" else 2}
                             for i, (name, state) in enumerate(ps.items())}}
    return l3_vlans(config)


def _routes(node: dict) -> set:
    return _l3_vlans(node) if node.get("role") in ROUTER_ROLES else set()


def _radio_vlans(ap: dict, radio: Optional[str]) -> set:
    """VLANs of the up sub-interfaces on ``radio`` (e.g. "Do0" -> "Do0.80")."""
    out = set()
    for name, state in (ap.get("port_status") or {}).items():
        base, _, sub = str(name).partition(".")
        if state == "up" and sub.isdigit() and base == radio:
            out.add(int(sub))
    return out


def _placement(by_id: dict) -> tuple[dict, list]:
    """``({node_id: {vlan, ...}}, [{"id", "reason"}])`` for placed / not-placed assets."""
    placed, not_placed = {}, []
    for nid, node in by_id.items():
        if node["kind"] == "device":
            vlans = _l3_vlans(node)
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
            ap = by_id.get(node["wifi"].get("access_point"))
            vlans = _radio_vlans(ap, radio) if ap else set()
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


# --- step values from the stored CVE fields and catalogue findings -----------

def _candidates(node: dict, vulns: Optional[dict]) -> list:
    """The node's CVEs that carry the four vector fields (vulnerabilities.json
    when it has the full list, else the graph's top_cves)."""
    nid = node["node_id"]
    host = (vulns or {}).get("hosts", {}).get(nid)
    cat = (vulns or {}).get("cves", {})
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


# --- the reachability graph --------------------------------------------------

def _router_between(a_vlans: set, b_vlans: set, routers: dict, exclude: set) -> Optional[str]:
    for rid in sorted(routers):                 # lowest node id among qualifiers
        if rid not in exclude and routers[rid] & a_vlans and routers[rid] & b_vlans:
            return rid
    return None


def _build_graph(placed: dict, by_id: dict, cands: dict, routers: dict,
                 extra_sources: list) -> nx.DiGraph:
    """Directed: an edge u->v means v can be taken over from a compromised u.

    ``extra_sources`` are synthetic spare-port starts (``{"id", "membership"}``);
    they get out-edges only (never a target, never a stepping stone).
    """
    g = nx.DiGraph()
    members = dict(placed)
    for s in extra_sources:
        members[s["id"]] = s["membership"]
    takeover = {nid: {False: _takeover(by_id[nid], cands[nid], False),
                      True: _takeover(by_id[nid], cands[nid], True)} for nid in placed}
    for u, mu in members.items():
        for v, mv in placed.items():
            if u == v:
                continue
            if mu & mv:
                cross, router = False, None
            else:
                router = _router_between(mu, mv, routers, {u, v})
                if router is None:
                    continue
                cross = True
            step = takeover[v][cross]
            if step is None:
                continue
            g.add_edge(u, v, weight=-math.log(step["value"]), step=step,
                       cross=cross, router=router)
    return g


# --- starting points ---------------------------------------------------------

def _host_starts(by_id: dict, placed: dict) -> list:
    """Managed hosts with a CVE, and unmanaged hosts; placed ones only."""
    starts = []
    for nid, node in by_id.items():
        if node["kind"] == "device" or nid not in placed:
            continue
        if node.get("unmanaged"):
            kind = "unmanaged_host"
        elif node.get("agent_id") and node.get("top_cves"):
            kind = "managed_host"
        else:
            continue
        starts.append({"id": nid, "kind": kind, "vlans": sorted(placed[nid])})
    return starts


def _spare_starts(by_id: dict) -> list:
    """One start per (switch, VLAN) from each switch's spare-port finding."""
    starts = []
    for nid, node in by_id.items():
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
                           "switch": nid, "vlans": [vlan], "ports": ports,
                           "listed_ports": len(ports), "spare_ports_on_switch": ev.get("total"),
                           "list_truncated": truncated, "membership": {vlan}})
    return starts


# --- routes ------------------------------------------------------------------

def _label(node: dict) -> str:
    return node.get("hostname") or node["node_id"]


def _route(graph: nx.DiGraph, by_id: dict, start: dict, target: str) -> Optional[dict]:
    """The single highest-likelihood route start->target, or None."""
    try:
        path = nx.dijkstra_path(graph, start["id"], target)
    except (nx.NetworkXNoPath, nx.NodeNotFound):
        return None

    steps, likelihood = [], 1.0
    for a, b in zip(path, path[1:]):
        edge = graph.edges[a, b]
        dest = by_id[b]
        if edge["cross"]:
            steps.append({"kind": "transit", "from": a, "through": edge["router"], "to": b,
                          "value": 1.0, "source": _IR7788,
                          "note": "firewall and access rules are not read"})
        step = dict(edge["step"])
        likelihood *= step["value"]
        step.update({"from": edge["router"] if edge["cross"] else a, "to": b,
                     "destination_base_score": dest.get("risk_score"),
                     "context_findings": _context_findings(dest)})
        steps.append(step)

    owned = [nid for nid in path if nid in by_id]
    scores = [by_id[nid].get("risk_score") for nid in owned]
    return {
        "target": target,
        "start": start["id"],
        "start_kind": start["kind"],
        "steps": steps,
        "likelihood": round(likelihood, 6),
        "highest_base_score": max([s for s in scores if s is not None], default=0.0),
        "crosses_router": any(s["kind"] == "transit" for s in steps),
        "narrative": _narrative(by_id, start, steps),
    }


def _narrative(by_id: dict, start: dict, steps: list) -> str:
    if start["kind"] == "spare_ports":
        opening = (f"From {start['listed_ports']} spare port(s) in VLAN {start['vlans'][0]} "
                   f"on {_label(by_id[start['switch']])}")
    elif start["kind"] == "unmanaged_host":
        opening = f"From {_label(by_id[start['id']])} (unmanaged, state unknown)"
    else:
        opening = f"From {_label(by_id[start['id']])}, assumed already compromised"
    parts = [opening]
    for s in steps:
        if s["kind"] == "transit":
            parts.append(f"cross into the target's VLAN through {_label(by_id[s['through']])} "
                         "(firewall rules not checked)")
        elif s["kind"] == "weakness":
            parts.append(f"take over {_label(by_id[s['to']])} using {s['cve']} "
                         f"({s['attack_complexity'].lower()} complexity)")
        else:
            parts.append(f"take over {_label(by_id[s['to']])} through {s['title'].lower()}")
    return ", ".join(parts) + "."


def _order_key(route: dict) -> tuple:
    """Within a target, never a blended score: likelihood, then highest base score,
    then fewer steps, then start id, then the ids along the route."""
    return (-route["likelihood"], -route["highest_base_score"], len(route["steps"]),
            route["start"], tuple(s["to"] for s in route["steps"]))


# --- dependants (browse-list order only, never route ordering) ---------------

def _dependants(by_id: dict) -> dict:
    """Hosts that depend on each asset: a switch counts hosts attached to it; a
    router also counts hosts in the VLANs it routes; a host counts none. A host
    is any endpoint/host-kind node with a known VLAN."""
    hosts = [n for n in by_id.values() if n["kind"] != "device"]
    out = {}
    for nid, node in by_id.items():
        if node["kind"] != "device":
            out[nid] = 0
            continue
        routed = _routes(node)
        out[nid] = sum(1 for h in hosts
                       if h.get("parent_id") == nid
                       or (routed and h.get("vlan") in routed))
    return out


def _cves_v4(by_id: dict) -> int:
    """Distinct CVEs scored with CVSS v4 (their Attack Requirements go unread)."""
    seen = set()
    for node in by_id.values():
        for r in node.get("top_cves") or []:
            if str(r.get("cvss_version") or "").startswith("4"):
                seen.add(r.get("cve"))
    return len(seen)


# --- the whole computation ---------------------------------------------------

def compute(graph: dict, targets: Optional[dict], vulns: Optional[dict],
            keep: int = KEEP_PER_TARGET) -> dict:
    """Build the attack_paths document from the graph, targets and CVE findings."""
    by_id = {n["node_id"]: n for n in graph["nodes"]}
    placed, not_placed = _placement(by_id)
    cands = {nid: _candidates(by_id[nid], vulns) for nid in placed}
    routers = {nid: _routes(n) for nid, n in by_id.items()
               if n.get("role") in ROUTER_ROLES and _routes(n)}

    spare = _spare_starts(by_id)
    starts = _host_starts(by_id, placed) + spare
    graph_nx = _build_graph(placed, by_id, cands, routers, spare)
    start_by_id = {s["id"]: s for s in starts}

    targets = targets or {}
    target_ids = list(targets)
    present = [tid for tid in target_ids if tid in by_id]
    missing = [tid for tid in target_ids if tid not in by_id]

    all_routes, pairs_with_route = [], 0
    target_blocks = []
    for tid in present:
        info = targets[tid]
        importance = info.get("importance")
        routes = []
        for start in starts:
            if start["id"] == tid:
                continue                        # a start that is the target is skipped
            route = _route(graph_nx, by_id, start, tid)
            if route:
                routes.append(route)
        pairs_with_route += len(routes)
        rank = sorted(routes, key=_order_key)[:keep]
        for i, r in enumerate(rank, 1):
            r["rank"] = i
            r["importance"] = importance
        all_routes.extend(rank)
        target_blocks.append({"id": tid, "importance": importance,
                              "note": info.get("note"), "present": True,
                              "label": _label(by_id[tid]), "routes": rank})
    for tid in missing:
        target_blocks.append({"id": tid, "importance": targets[tid].get("importance"),
                              "note": targets[tid].get("note"), "present": False,
                              "reason": "no node with this id in the graph"})
    # stable order: importance, then how many routes, then id
    target_blocks.sort(key=lambda b: (IMPORTANCE.index(b["importance"])
                                      if b["importance"] in IMPORTANCE else len(IMPORTANCE),
                                      -len(b.get("routes") or []), b["id"]))

    through = {nid: 0 for nid in by_id}
    for r in all_routes:
        for nid in {s["from"] for s in r["steps"]} | {s["to"] for s in r["steps"]}:
            if nid in through:
                through[nid] += 1
    dependants = _dependants(by_id)
    per_asset = []
    for nid, node in by_id.items():
        status = (node.get("reachable_cve") or {}).get("status")
        per_asset.append({"id": nid, "kind": node["kind"], "label": _label(node),
                          "dependants": dependants[nid], "verified": status != "unverified",
                          "routes_through": through[nid]})
    per_asset.sort(key=lambda a: (-a["dependants"], a["id"]))     # browse order
    most_shared = max(per_asset, key=lambda a: (a["routes_through"], -len(a["id"])),
                      default=None)
    most_shared = most_shared["id"] if most_shared and most_shared["routes_through"] else None

    verified = sum(1 for a in per_asset if a["verified"])
    state = "no_targets" if not target_ids else "ok"
    return {
        "metadata": {
            "computed_at": datetime.now(timezone.utc).isoformat(),
            "source_scan": graph.get("metadata", {}).get("scan_time"),
            "state": state,
            "keep_per_target": keep,
            "counts": {
                "targets": len(target_ids), "targets_present": len(present),
                "targets_missing": len(missing), "starting_points": len(starts),
                "routes": len(all_routes), "pairs_with_route": pairs_with_route,
                "pairs_total": len(present) * len(starts), "placed": len(placed),
                "not_placed": len(not_placed), "assets_verified": verified,
                "assets_unverified": len(per_asset) - verified, "cves_v4_unread": _cves_v4(by_id),
            },
            "sources": SOURCES,
            "reachability": REACHABILITY,
            "limits": LIMITS,
            "most_shared_asset": most_shared,
        },
        "targets": target_blocks,
        "starting_points": [{k: v for k, v in s.items() if k != "membership"} for s in starts],
        "per_asset": per_asset,
        "not_placed": not_placed,
    }


# --- file I/O and CLI --------------------------------------------------------

def default_path(graph_path: str) -> str:
    return os.path.join(os.path.dirname(os.path.abspath(graph_path)), FILENAME)


def _targets_path(graph_path: str) -> str:
    return os.path.join(os.path.dirname(os.path.abspath(graph_path)), TARGETS_FILENAME)


def _load_targets(path: Optional[str]) -> Optional[dict]:
    if not path or not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def run_stage(graph: dict, targets: Optional[dict], vulns: Optional[dict],
              paths_out: Optional[str], keep: int = KEEP_PER_TARGET):
    """Pipeline hook: compute and (when ``paths_out`` is set) write the document.

    Returns the ``(document, counts)`` so the pipeline can log a summary. The
    graph gains no fields.
    """
    document = compute(graph, targets, vulns, keep)
    if paths_out:
        vulnfile.write_atomic(paths_out, document)
        log.info("wrote attack paths to %s", paths_out)
    return document


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
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    logging.basicConfig(stream=sys.stderr, level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    args = build_parser().parse_args(argv)
    try:
        with open(args.graph, encoding="utf-8") as f:
            graph = json.load(f)
    except (OSError, ValueError) as exc:
        log.error("could not read graph %s: %s", args.graph, exc)
        return 1
    targets = _load_targets(args.targets or _targets_path(args.graph))
    vulns_path = args.vulns or vulnfile.default_path(args.graph)
    vulns = None
    if os.path.exists(vulns_path):
        with open(vulns_path, encoding="utf-8") as f:
            vulns = json.load(f)
    out = args.paths_out or default_path(args.graph)
    document = run_stage(graph, targets, vulns, out)
    log.info("attack paths: %d route(s) to %d target(s) from %d starting point(s)",
             document["metadata"]["counts"]["routes"],
             document["metadata"]["counts"]["targets_present"],
             document["metadata"]["counts"]["starting_points"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
