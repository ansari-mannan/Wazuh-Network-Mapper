import { CveLookup } from '../../common';

// The ONE risk-level rule, used by the overview counts, the map node border and
// the detail flyout. CVSS v3 severity bands:
//   Critical 9.0-10.0 · High 7.0-8.9 · Medium 4.0-6.9 · Low < 4.0
// Unscored = no score at all (null/undefined), which is NOT the same as 0.
// Kept free of theme imports so it can be unit tested on its own.
export type RiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'unscored';

export const SCORED_RISK_LEVELS: RiskLevel[] = ['critical', 'high', 'medium', 'low'];

export function riskLevel(score: number | null | undefined): RiskLevel {
  if (score === null || score === undefined || Number.isNaN(score)) return 'unscored';
  if (score >= 9.0) return 'critical';
  if (score >= 7.0) return 'high';
  if (score >= 4.0) return 'medium';
  return 'low';
}

export interface RiskNode {
  kind: string;
  risk_score: number | null;
  max_cvss?: number | null;
  top_cves?: unknown[];
  cve_lookup?: CveLookup | null;
}

/**
 * The risk score to show for a graph node. Endpoints use their risk_score.
 * A network device shows its score when its CVE lookup succeeded
 * (cve_lookup.status "ok"), a real 0.0 included; any other lookup is Unscored.
 * A graph from before device lookups has no cve_lookup, and the scanner then
 * wrote risk_score 0 for every device: such a device is unscored unless it
 * carries CVE data (a non-null max_cvss or a non-empty CVE list), as before.
 */
export function nodeRiskScore(node: RiskNode): number | null {
  if (node.kind !== 'device') return node.risk_score;
  if (node.cve_lookup) {
    return node.cve_lookup.status === 'ok' ? node.risk_score ?? null : null;
  }
  const hasCveData =
    (node.max_cvss !== null && node.max_cvss !== undefined) ||
    (Array.isArray(node.top_cves) && node.top_cves.length > 0);
  if (!hasCveData) return null;
  return node.risk_score ?? node.max_cvss ?? null;
}

/** Nodes (endpoints and devices) per risk level; the five counts add up to total. */
export function riskCounts(nodes: RiskNode[]) {
  const out = {
    total: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    unscored: 0,
    devices: { scored: 0, unscored: 0 },
    endpoints: { scored: 0, unscored: 0 },
  };
  for (const n of nodes) {
    if (n.kind !== 'device' && n.kind !== 'endpoint') continue;
    const level = riskLevel(nodeRiskScore(n));
    out.total += 1;
    out[level] += 1;
    const side = n.kind === 'device' ? out.devices : out.endpoints;
    if (level === 'unscored') side.unscored += 1;
    else side.scored += 1;
  }
  return out;
}
