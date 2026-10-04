import { themeVars } from './theme';

// The ONE risk-level rule, used by the overview counts, the map node border and
// the device detail. CVSS v3 severity bands:
//   Critical 9.0-10.0 · High 7.0-8.9 · Medium 4.0-6.9 · Low < 4.0
// Unscored = no score at all (null/undefined), which is NOT the same as 0.
export type RiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'unscored';

export const SCORED_RISK_LEVELS: RiskLevel[] = ['critical', 'high', 'medium', 'low'];

export function riskLevel(score: number | null | undefined): RiskLevel {
  if (score === null || score === undefined || Number.isNaN(score)) return 'unscored';
  if (score >= 9.0) return 'critical';
  if (score >= 7.0) return 'high';
  if (score >= 4.0) return 'medium';
  return 'low';
}

export const RISK_META: Record<RiskLevel, { label: string; color: string }> = {
  critical: { label: 'Critical', color: '#dc2626' },
  high: { label: 'High', color: '#f97316' },
  medium: { label: 'Medium', color: '#eab308' },
  low: { label: 'Low', color: '#22c55e' },
  unscored: { label: 'Unscored', color: themeVars.euiColorMediumShade },
};

/**
 * The risk score to show for a graph node. Endpoints use their risk_score.
 * A network device has no CVE data yet: the scanner still writes risk_score 0
 * for it, which would read as "Low", so a device counts as unscored unless it
 * actually carries CVE data (a non-null max_cvss or a non-empty CVE list).
 */
export function nodeRiskScore(node: {
  kind: string;
  risk_score: number | null;
  max_cvss?: number | null;
  top_cves?: unknown[];
}): number | null {
  if (node.kind !== 'device') return node.risk_score;
  const hasCveData =
    (node.max_cvss !== null && node.max_cvss !== undefined) ||
    (Array.isArray(node.top_cves) && node.top_cves.length > 0);
  if (!hasCveData) return null;
  return node.risk_score ?? node.max_cvss ?? null;
}
