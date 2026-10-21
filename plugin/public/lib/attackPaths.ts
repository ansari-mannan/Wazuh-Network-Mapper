// Pure helpers for the attack-paths page (no theme/JSX imports, unit tested).
import {
  AttackPathsDoc,
  AttackRoute,
  AttackStartingPoint,
  AttackStartKind,
  AttackStep,
  AttackTarget,
  GraphNode,
  Importance,
} from '../../common';
import { subnet24 } from '../components/topology/layout';

// Which page-level state to show. 'absent' = no file yet (run a scan); the
// engine's 'no_targets' = nothing marked to protect; 'ok' = show the routes.
export type PageState = 'absent' | 'no_targets' | 'ok';

export function pageState(doc: Pick<AttackPathsDoc, 'metadata'> | null): PageState {
  if (!doc || doc.metadata.state === 'absent') return 'absent';
  if (doc.metadata.state === 'no_targets') return 'no_targets';
  return 'ok';
}

/**
 * Whether attack_paths.json was computed from an older graph than the one shown
 * (its source_scan predates the graph's scan_time), so a rescan would refresh it.
 * Unknown times are never called out of date.
 */
export function isStale(
  doc: Pick<AttackPathsDoc, 'metadata'> | null,
  graphScanTime: string | null | undefined
): boolean {
  if (!doc || doc.metadata.state === 'absent' || !graphScanTime) return false;
  const source = Date.parse(doc.metadata.source_scan || '');
  return Number.isNaN(source) || source < Date.parse(graphScanTime);
}

// A target group's own state: missing from the graph, reachable by no route
// (a calm result, not an error), or routes to show.
export type TargetState = 'missing' | 'no_routes' | 'ok';

export function targetState(target: Pick<AttackTarget, 'present' | 'routes'>): TargetState {
  if (!target.present) return 'missing';
  return (target.routes || []).length === 0 ? 'no_routes' : 'ok';
}

// Target groups are shown in FIPS 199 importance order.
export const IMPORTANCE_RANK: Record<Importance, number> = { high: 0, moderate: 1, low: 2 };

// Importance badge colour, from OUI's semantic names (not new colours).
export const IMPORTANCE_META: Record<Importance, { label: string; color: string }> = {
  high: { label: 'High importance', color: 'danger' },
  moderate: { label: 'Moderate importance', color: 'warning' },
  low: { label: 'Low importance', color: 'hollow' },
};

// The importance choices a control offers, least to most, and their short labels.
export const IMPORTANCE_LEVELS: Importance[] = ['low', 'moderate', 'high'];
export const IMPORTANCE_SHORT: Record<Importance, string> = { low: 'Low', moderate: 'Moderate', high: 'High' };

/**
 * The likelihood scale. A route's likelihood is the product of its step values,
 * which the engine takes from NIST IR 7788's three CVSS-complexity values
 * (low 0.9, medium 0.6, high 0.2). The bands line up with those values so a
 * single-step route lands in its own band; products of steps fall lower.
 *   >= 0.8  Very likely   (a single low-complexity step)
 *   >= 0.5  Likely        (a single medium-complexity step)
 *   >= 0.2  Possible      (a single high-complexity step)
 *   >  0    Unlikely      (a chain of steps)
 */
export function likelihoodLabel(value: number): string {
  if (value >= 0.8) return 'Very likely';
  if (value >= 0.5) return 'Likely';
  if (value >= 0.2) return 'Possible';
  return 'Unlikely';
}

/**
 * Likelihood as the word plus a percentage, e.g. "Very likely · 90%". The
 * percentage is the NIST IR 7788 value (a coarse three-value model), shown as a
 * percent for legibility, not a precise probability — the scoring section says so.
 */
export function likelihoodText(value: number): string {
  return `${likelihoodLabel(value)} · ${Math.round(value * 100)}%`;
}

/**
 * Tile order within a target group: higher likelihood first, then the higher
 * node OVSS along the route (the same order the engine ranks routes in). Target
 * groups themselves are ordered by IMPORTANCE_RANK, so the flattened tiles read
 * importance, then likelihood, then OVSS.
 */
export function compareRoutes(a: AttackRoute, b: AttackRoute): number {
  return b.likelihood - a.likelihood || b.highest_ovss - a.highest_ovss;
}

/**
 * Every graph node a route touches: its target, start and each step's endpoints
 * (and the router it passes through). Used to highlight the route on the map; a
 * pseudo-id such as a spare-ports start is harmless, the map ignores unknown ids.
 */
export function routeNodeIds(route: AttackRoute): string[] {
  const ids = new Set<string>([route.target, route.start]);
  for (const s of route.steps) {
    ids.add(s.from);
    ids.add(s.to);
    if (s.through) ids.add(s.through);
  }
  return [...ids];
}

/**
 * The nodes a route visits in order: its start, then each step's reached asset,
 * or for a transit step the router it crosses. Consecutive entries are the
 * pairs the physical path is drawn between.
 */
export function routeWalk(route: AttackRoute): string[] {
  return [route.start, ...route.steps.map((s) => (s.kind === 'transit' && s.through ? s.through : s.to))];
}

type Edge = { source: string; target: string };

// Shortest path (inclusive) between two nodes along the edges, or [] if there is
// none. The graph is a tree, so the path is unique; BFS finds it.
function shortestPath(from: string, to: string, adj: Map<string, string[]>): string[] {
  if (from === to) return [from];
  const prev = new Map<string, string>();
  const seen = new Set<string>([from]);
  const queue = [from];
  while (queue.length) {
    const node = queue.shift()!;
    for (const next of adj.get(node) || []) {
      if (seen.has(next)) continue;
      seen.add(next);
      prev.set(next, node);
      if (next === to) {
        const path = [to];
        for (let n = node; ; n = prev.get(n)!) {
          path.unshift(n);
          if (n === from) return path;
        }
      }
      queue.push(next);
    }
  }
  return [];
}

/**
 * Where an asset with no edges of its own joins the physical network: the
 * device the map places it under (the first linked device in its /24, as
 * layout.ts infers), else its VLAN's access switch (the device a linked host in
 * the same VLAN hangs off). Null when neither is known.
 */
function attachPoint(node: GraphNode | undefined, nodes: GraphNode[], adj: Map<string, string[]>): string | null {
  if (!node) return null;
  const sub = subnet24(node.ip);
  const placedUnder = sub && nodes.find((d) => d.kind === 'device' && adj.has(d.node_id) && subnet24(d.ip) === sub);
  if (placedUnder) return placedUnder.node_id;
  const vlan = node.kind === 'endpoint' ? node.vlan : undefined;
  if (vlan === undefined) return null;
  const kind = new Map(nodes.map((n) => [n.node_id, n.kind]));
  for (const h of nodes) {
    if (h.kind !== 'endpoint' || h.vlan !== vlan || !adj.has(h.node_id)) continue;
    const sw = adj.get(h.node_id)!.find((id) => kind.get(id) === 'device');
    if (sw) return sw;
  }
  return null;
}

/**
 * Every node to light for a route on the map: the given assets (in `walk` order)
 * plus, between each consecutive pair, the shortest physical path along the graph
 * edges — the switches a same-VLAN hop really crosses, so the highlight is a
 * continuous path instead of leaving an intermediate device dimmed in the middle.
 * A step with no edges (an unparented host) is joined at its attach point (see
 * attachPoint), which is lit too. A pair with no physical path contributes only
 * its two endpoints (never fails). Edges light themselves when both their
 * endpoints are lit, so only node ids are returned; the intermediates (lit here
 * but not in `walk`) are the pass-through set.
 */
export function physicalPathNodeIds(walk: string[], edges: Edge[], nodes: GraphNode[] = []): string[] {
  const lit = new Set<string>(walk);
  for (const segment of physicalSegments(walk, edges, nodes)) for (const id of segment) lit.add(id);
  return [...lit];
}

/**
 * The same path as one ordered walk, start to target: each asset of `walk`,
 * with the devices between it and the next one in between, in the order the
 * traffic crosses them. A node met twice in a row appears once. The map numbers
 * the route's nodes and points its arrows from this.
 */
export function physicalPathWalk(walk: string[], edges: Edge[], nodes: GraphNode[] = []): string[] {
  const segments = physicalSegments(walk, edges, nodes);
  const out: string[] = [];
  const push = (id: string) => {
    if (out[out.length - 1] !== id) out.push(id);
  };
  walk.forEach((id, i) => {
    push(id);
    for (const step of segments[i] || []) push(step);
  });
  return out;
}

// The shortest physical path from each asset of `walk` to the next (empty when
// there is none). An asset with no edges joins at its attach point.
function physicalSegments(walk: string[], edges: Edge[], nodes: GraphNode[]): string[][] {
  const adj = new Map<string, string[]>();
  const link = (a: string, b: string) => (adj.get(a) || adj.set(a, []).get(a)!).push(b);
  for (const e of edges) {
    link(e.source, e.target);
    link(e.target, e.source);
  }
  const byId = new Map(nodes.map((n) => [n.node_id, n]));
  const joinAt = (id: string) => (adj.has(id) ? id : attachPoint(byId.get(id), nodes, adj) || id);
  const segments: string[][] = [];
  for (let i = 0; i + 1 < walk.length; i++) {
    segments.push(shortestPath(joinAt(walk[i]), joinAt(walk[i + 1]), adj));
  }
  return segments;
}

// One step rendered as plain text: a takeover step reaches an asset and names
// what allowed it; a transit step only crosses a router (lighter in the UI).
export type StepText = { kind: AttackStep['kind']; heading: string; detail: string };

/** A step's heading (the asset reached, or the device passed through) and the
 *  weakness/misconfiguration that allowed it. `nameOf` resolves a node id. */
export function stepText(step: AttackStep, nameOf: (id: string) => string): StepText {
  if (step.kind === 'transit') {
    return {
      kind: 'transit',
      heading: `passes through ${nameOf(step.through || step.to)}`,
      detail: step.note || 'firewall rules not checked',
    };
  }
  if (step.kind === 'misconfiguration') {
    return {
      kind: 'misconfiguration',
      heading: nameOf(step.to),
      detail: `${step.title || 'misconfiguration'} · check ${step.check || '—'}`,
    };
  }
  const complexity = step.attack_complexity ? `${step.attack_complexity.toLowerCase()} complexity` : '';
  return {
    kind: 'weakness',
    heading: nameOf(step.to),
    detail: [step.cve, complexity].filter(Boolean).join(' · '),
  };
}

/**
 * Spare entry ports in a map label, compact past `shown` ports
 * ("Fa1/0/7, Fa1/0/8 +3 · VLAN 20"), and in full for its tooltip.
 */
export function entryPortsText(ports: string[], vlan: number, shown = 2): { short: string; full: string } {
  const more = ports.length > shown ? ` +${ports.length - shown}` : '';
  const head = ports.length ? `${ports.slice(0, shown).join(', ')}${more}` : 'spare ports';
  return { short: `${head} · VLAN ${vlan}`, full: `${ports.length ? ports.join(', ') : 'spare ports'} · VLAN ${vlan}` };
}

/** The starting-point kind in words, for "Assumes <start> is already compromised". */
export function startKindLabel(kind: AttackStartKind): string {
  switch (kind) {
    case 'managed_host':
      return 'a managed host';
    case 'unmanaged_host':
      return 'an unmanaged host';
    case 'spare_ports':
      return 'spare switch ports';
    default:
      return kind;
  }
}

/**
 * A spare-ports start in words: "9 spare port(s) in VLAN 20 on L3-Switch",
 * plus "(on the target itself)" when `target` is the switch that holds them.
 */
export function spareStartText(sp: AttackStartingPoint, nameOf: (id: string) => string, target?: string): string {
  const base = `${sp.listed_ports ?? sp.ports?.length ?? 0} spare port(s) in VLAN ${sp.vlans[0]}`;
  if (!sp.switch) return base;
  const self = sp.switch === target ? ' (on the target itself)' : '';
  return `${base} on ${sp.switch_label || nameOf(sp.switch)}${self}`;
}
