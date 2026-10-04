/**
 * Asset criticality weights for risk calculation.
 */

export const CRITICALITY_WEIGHTS: Record<string, number> = {
  critical: 1.5,
  high: 1.2,
  medium: 1.0,
  low: 0.8,
};

export function getCriticalityWeight(criticality: string): number {
  return CRITICALITY_WEIGHTS[criticality] ?? 1.0;
}
