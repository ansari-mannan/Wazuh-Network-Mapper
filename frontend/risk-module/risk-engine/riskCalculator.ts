/**
 * Pure risk computation. No UI, no HTTP, no React.
 * For MVP: returns hardcoded/mock values.
 */

export function calculateAssetRisk(
  _cvssScore: number,
  _exposureMultiplier: number,
  _criticalityMultiplier: number
): number {
  // Risk Score = CVSS × Exposure × Criticality (simplified for MVP)
  return 0;
}

export function getAggregatedRiskForAsset(_assetId: string): number {
  return 0;
}
