// Plain words for OVSS (backend/vulnmapper/scoring): a node's score and tier,
// and a finding's threat and CVSS-source details. No theme imports.
import { GraphNode, OvssFinding, ThreatFeeds, Tier } from '../../common';

const num = (n: number) => String(Math.round(n * 1000) / 1000);

/** "P1 · OVSS 6.125", "Unrated: …", "Unassessed: …", or a graph from before OVSS. */
export function ovssLine(node: Pick<GraphNode, 'risk_score' | 'node_tier' | 'ovss_status' | 'ovss_reason'>): string {
  if (node.ovss_status === 'assessed' && node.node_tier && typeof node.risk_score === 'number') {
    return `${node.node_tier} · OVSS ${num(node.risk_score)}`;
  }
  if (node.ovss_status === 'Unrated') return 'Unrated: none of its CVEs has a CVSS score';
  if (node.ovss_status === 'Unassessed') return `Unassessed: ${node.ovss_reason || 'no findings returned'}`;
  return 'Not scored: this graph was written before OVSS';
}

// The score cuts in backend/vulnmapper/scoring/ovss.py (TIER_CUTS); below the last: P3.
const TIER_CUTS: Array<[Tier, number]> = [['P0', 6.75], ['P1', 4.5], ['P2', 2.5]];

type ScoredFinding = OvssFinding & { cve: string };
export type TierReason = { line: string; rule: string };

/** Which tier rule set a finding's tier, in plain words (the tier badge's tooltip). */
export function tierRule(f: ScoredFinding): string {
  const score = f.score ?? 0;
  const base = TIER_CUTS.find(([, cut]) => score >= cut)?.[0] ?? 'P3';
  if (f.tier === 'P1' && base === 'P0' && f.confidence === 'potential' && !f.kev) return 'Potential finding, capped at P1';
  if (f.kev && f.tier === 'P0' && base !== 'P0') return 'Known exploited on the internet edge';
  if (f.kev && f.tier === 'P1' && (base === 'P2' || base === 'P3')) return 'Known exploited (CISA KEV)';
  const i = TIER_CUTS.findIndex(([t]) => t === f.tier);
  return i >= 0 ? `Score ${num(score)}: ${f.tier} at ${TIER_CUTS[i][1]} and above` : `Score ${num(score)}: P3 below 2.5`;
}

/**
 * Why a node has its tier, from its findings (highest score first or not):
 * "P0 · 8.575 · driven by CVE-… (CISA KEV)", or when the highest score and the
 * tier come from different CVEs, "Highest score 8.575 (CVE-…); tier P0 from
 * CVE-… (CISA KEV)". null when no listed finding carries the tier (a graph
 * made before top_cves was ordered by tier may not list a low-scoring setter).
 */
export function tierReason(tier: Tier | null | undefined, findings: ScoredFinding[] | undefined): TierReason | null {
  const scored = (findings || []).filter((f) => typeof f.score === 'number');
  scored.sort((a, b) => (b.score as number) - (a.score as number));
  const top = scored[0];
  const setter = scored.find((f) => f.tier === tier);
  if (!tier || !top || !setter) return null;
  const kev = setter.kev ? ' (CISA KEV)' : '';
  const line =
    setter === top
      ? `${tier} · ${num(top.score as number)} · driven by ${setter.cve}${kev}`
      : `Highest score ${num(top.score as number)} (${top.cve}); tier ${tier} from ${setter.cve}${kev}`;
  return { line, rule: tierRule(setter) };
}

/** "EPSS 27.1%". */
export function epssText(epss: number | null | undefined): string {
  return `EPSS ${Math.round((epss || 0) * 1000) / 10}%`;
}

/** Where the CVSS score OVSS used came from: "CNA · v3.1", "ADP · v4.0", "scanner · v3.1". */
export function cvssSourceText(f: OvssFinding): string {
  if (!f.cvss_src) return '';
  const src = f.cvss_src === 'tool' ? 'scanner' : f.cvss_src;
  return f.cvss_ver ? `${src} · v${f.cvss_ver}` : src;
}

/** The marker's tooltip when a CNA/ADP score and the scanner's disagree. */
export function conflictText(f: OvssFinding): string {
  return f.conflict === 1
    ? `The ${f.cvss_src} score (${f.cvss_used}) differs from the scanner's (${f.cvss_tool}) by 1.0 or more; OVSS uses the ${f.cvss_src} score.`
    : '';
}

/** "Egress (1.0)", "Isolated VLAN (0.3)", "Internal (0.5)", "Unknown placement (0.5)". */
export function exposureText(exposure: number | undefined, flag: string | null | undefined): string {
  if (exposure === undefined) return '';
  if (flag === 'exposure_unknown') return `Unknown placement (${exposure})`;
  if (exposure >= 1) return `Egress device (${exposure})`;
  if (exposure < 0.5) return `Isolated VLAN (${exposure})`;
  return `Internal (${exposure})`;
}

/** The warning when a threat feed was missing for the scan; empty otherwise. */
export function threatFeedWarning(feeds: ThreatFeeds | undefined): string {
  if (!feeds || (feeds.kev !== 'unavailable' && feeds.epss !== 'unavailable')) return '';
  return 'Threat data (KEV/EPSS) unavailable for this scan — scores may be understated.';
}
