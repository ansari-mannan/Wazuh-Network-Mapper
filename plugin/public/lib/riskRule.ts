// The risk rules. A CVE's severity is on the CVSS v3 bands: Critical 9.0-10.0,
// High 7.0-8.9, Medium 4.0-6.9, Low < 4.0; unscored (no score at all) is not
// the same as 0. A node is on its OVSS tier (below). No theme imports, so it is
// unit tested on its own.
import { Tier } from '../../common';

export type RiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'unscored';

export const SCORED_RISK_LEVELS: RiskLevel[] = ['critical', 'high', 'medium', 'low'];

export function riskLevel(score: number | null | undefined): RiskLevel {
  if (score === null || score === undefined || Number.isNaN(score)) return 'unscored';
  if (score >= 9.0) return 'critical';
  if (score >= 7.0) return 'high';
  if (score >= 4.0) return 'medium';
  return 'low';
}

// --- Nodes: the OVSS tier (backend/vulnmapper/scoring/ovss.py) -------------
// A node's risk_score is its OVSS and node_tier its most severe finding tier.
// The CVSS bands above stay the rule for a single CVE's severity.

export type { Tier };
export const TIERS: Tier[] = ['P0', 'P1', 'P2', 'P3'];

/**
 * How a node is shown on the map and in lists: its OVSS tier; with no tier, its
 * worst configuration finding (the published DISA/STIG severity, as before), so
 * a device with findings never falls back to grey; else 'none' (Unrated,
 * Unassessed, or a graph written before OVSS). Advisory findings have no
 * severity and never raise it.
 */
export type NodeLevel = Tier | 'high' | 'medium' | 'low' | 'none';

export interface TierNode {
  kind: string;
  node_tier?: Tier | null;
  ovss_status?: string;
}

export function nodeLevel(node: TierNode, findingSeverity: 'high' | 'medium' | 'low' | null): NodeLevel {
  return node.node_tier || findingSeverity || 'none';
}

const TIER_RANK: Record<Tier, number> = { P0: 4, P1: 3, P2: 2, P3: 1 };

/** Higher for a more severe tier; 0 for none. */
export function tierRank(tier: Tier | null | undefined): number {
  return tier ? TIER_RANK[tier] : 0;
}

/** Nodes (endpoints and devices) per OVSS tier; the tiers plus untiered add up to total. */
export function tierCounts(nodes: TierNode[]) {
  const out = { total: 0, P0: 0, P1: 0, P2: 0, P3: 0, unrated: 0, unassessed: 0, notScored: 0 };
  for (const n of nodes) {
    if (n.kind !== 'device' && n.kind !== 'endpoint') continue;
    out.total += 1;
    if (n.node_tier) out[n.node_tier] += 1;
    else if (n.ovss_status === 'Unrated') out.unrated += 1;
    else if (n.ovss_status === 'Unassessed') out.unassessed += 1;
    else out.notScored += 1; // assessed with no tier cannot happen; a pre-OVSS graph
  }
  return out;
}
