// Pure helpers for the attack-paths page (no theme/JSX imports, unit tested).
import { AttackPathsDoc, AttackRoute, AttackStartKind, AttackStep, AttackTarget, Importance } from '../../common';

// Which page-level state to show. 'absent' = no file yet (run a scan); the
// engine's 'no_targets' = nothing marked to protect; 'ok' = show the routes.
export type PageState = 'absent' | 'no_targets' | 'ok';

export function pageState(doc: Pick<AttackPathsDoc, 'metadata'> | null): PageState {
  if (!doc || doc.metadata.state === 'absent') return 'absent';
  if (doc.metadata.state === 'no_targets') return 'no_targets';
  return 'ok';
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
 * Tile order within a target group: higher likelihood first, then higher base
 * score (the same order the engine ranks routes in). Target groups themselves
 * are ordered by IMPORTANCE_RANK, so the flattened tiles read importance, then
 * likelihood, then base score.
 */
export function compareRoutes(a: AttackRoute, b: AttackRoute): number {
  return b.likelihood - a.likelihood || b.highest_base_score - a.highest_base_score;
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
 * The nodes a route visits in order: its start, then each step's reached asset.
 * Consecutive entries are the pairs the physical path is drawn between.
 */
export function routeWalk(route: AttackRoute): string[] {
  return [route.start, ...route.steps.map((s) => s.to)];
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
 * Every node to light for a route on the map: the given assets (in `walk` order)
 * plus, between each consecutive pair, the shortest physical path along the graph
 * edges — the switches a same-VLAN hop really crosses, so the highlight is a
 * continuous path instead of leaving an intermediate device dimmed in the middle.
 * A pair with no physical path contributes only its two endpoints (never fails).
 * Edges light themselves when both their endpoints are lit, so only node ids are
 * returned; the intermediates (lit here but not in `walk`) are the pass-through set.
 */
export function physicalPathNodeIds(walk: string[], edges: Edge[]): string[] {
  const adj = new Map<string, string[]>();
  const link = (a: string, b: string) => (adj.get(a) || adj.set(a, []).get(a)!).push(b);
  for (const e of edges) {
    link(e.source, e.target);
    link(e.target, e.source);
  }
  const lit = new Set<string>(walk);
  for (let i = 0; i + 1 < walk.length; i++) {
    for (const id of shortestPath(walk[i], walk[i + 1], adj)) lit.add(id);
  }
  return [...lit];
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
