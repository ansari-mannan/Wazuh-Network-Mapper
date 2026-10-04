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
