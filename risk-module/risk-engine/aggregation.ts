/**
 * Aggregation logic: e.g. average of top vulnerabilities across asset clusters.
 */

export function aggregateTopVulnerabilities(
  scores: number[],
  topN: number = 3
): number {
  if (scores.length === 0) return 0;
  const sorted = [...scores].sort((a, b) => b - a);
  const top = sorted.slice(0, topN);
  return top.reduce((a, b) => a + b, 0) / top.length;
}
