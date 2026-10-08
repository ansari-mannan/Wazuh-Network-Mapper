import { themeVars } from './theme';

// The risk rule itself lives in riskRule.ts (no theme imports, unit tested);
// this module adds the labels and colours.
import { RiskLevel } from './riskRule';

export { nodeRiskScore, riskCounts, riskLevel, SCORED_RISK_LEVELS } from './riskRule';
export type { RiskLevel } from './riskRule';

export const RISK_META: Record<RiskLevel, { label: string; color: string }> = {
  critical: { label: 'Critical', color: '#dc2626' },
  high: { label: 'High', color: '#f97316' },
  medium: { label: 'Medium', color: '#eab308' },
  low: { label: 'Low', color: '#22c55e' },
  unscored: { label: 'Unscored', color: themeVars.euiColorMediumShade },
};
