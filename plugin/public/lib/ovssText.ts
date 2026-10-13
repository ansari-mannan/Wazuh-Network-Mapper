// Plain words for OVSS (backend/vulnmapper/scoring): a node's score and tier,
// and a finding's threat and CVSS-source details. No theme imports.
import { GraphNode, OvssFinding, ThreatFeeds } from '../../common';

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
