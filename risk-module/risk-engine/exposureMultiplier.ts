/**
 * Exposure multiplier for risk calculation.
 */

export const EXPOSURE_MULTIPLIERS: Record<string, number> = {
  "internet-facing": 1.5,
  internal: 1.0,
  restricted: 0.8,
};

export function getExposureMultiplier(exposure: string): number {
  return EXPOSURE_MULTIPLIERS[exposure] ?? 1.0;
}
