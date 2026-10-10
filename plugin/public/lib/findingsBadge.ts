import { GraphNode } from '../../common';

// The worst configuration-finding severity on a device, for a small node badge
// (e.g. "2 high") so a device with no CVE score but open telnet does not look
// clean. Null when there is nothing to show. advisory (no severity) is left off.
export type FindingsBadge = { count: number; severity: 'high' | 'medium' | 'low' };

const SEVERITIES = ['high', 'medium', 'low'] as const;

function counts(node: GraphNode): Record<'high' | 'medium' | 'low', number> {
  if (node.kind !== 'device') return { high: 0, medium: 0, low: 0 };
  // config_summary is the device's own tally; fall back to the findings list.
  const summary = node.config_summary?.findings;
  if (summary) return { high: summary.high, medium: summary.medium, low: summary.low };
  const tally = { high: 0, medium: 0, low: 0 };
  for (const f of node.config_findings || []) if (f.severity) tally[f.severity] += 1;
  return tally;
}

export function findingsBadge(node: GraphNode): FindingsBadge | null {
  const tally = counts(node);
  for (const severity of SEVERITIES) {
    if (tally[severity] > 0) return { count: tally[severity], severity };
  }
  return null;
}

/** The badge text, e.g. "2 high". */
export function findingsBadgeText(badge: FindingsBadge): string {
  return `${badge.count} ${badge.severity}`;
}
