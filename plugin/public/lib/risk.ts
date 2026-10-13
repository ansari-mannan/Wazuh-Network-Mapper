// The risk rule itself lives in riskRule.ts (no theme imports, unit tested);
// this module adds the labels and colours.
import { themeVars } from './theme';

import { NodeLevel, RiskLevel, Tier } from './riskRule';

export { nodeLevel, riskLevel, SCORED_RISK_LEVELS, tierCounts, tierRank, TIERS } from './riskRule';
export type { NodeLevel, RiskLevel, Tier } from './riskRule';

export const RISK_META: Record<RiskLevel, { label: string; color: string }> = {
  critical: { label: 'Critical', color: '#dc2626' },
  high: { label: 'High', color: '#f97316' },
  medium: { label: 'Medium', color: '#eab308' },
  low: { label: 'Low', color: '#22c55e' },
  unscored: { label: 'Unscored', color: themeVars.euiColorMediumShade },
};

// OVSS tiers: P0 red, P1 orange, P2 yellow, P3 a calm blue (act on it in time,
// not now). Grey is for a node with no tier.
export const TIER_META: Record<Tier, { label: string; color: string }> = {
  P0: { label: 'P0', color: '#dc2626' },
  P1: { label: 'P1', color: '#f97316' },
  P2: { label: 'P2', color: '#eab308' },
  P3: { label: 'P3', color: '#3b82f6' },
};

// A node's level: its tier, or its worst configuration finding when that is
// more severe (high in the P1 colour, medium in P2's) or there is no tier;
// else grey. A low finding with no tier keeps its green, as before OVSS.
export const NODE_LEVEL_META: Record<NodeLevel, { label: string; color: string }> = {
  ...TIER_META,
  high: { label: 'High finding', color: RISK_META.high.color },
  medium: { label: 'Medium finding', color: RISK_META.medium.color },
  low: { label: 'Low finding', color: RISK_META.low.color },
  none: { label: 'Not assessed', color: RISK_META.unscored.color },
};
