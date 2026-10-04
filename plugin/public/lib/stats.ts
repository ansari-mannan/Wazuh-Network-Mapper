import { euiPaletteColorBlind } from '@elastic/eui';
import { GraphResponse } from '../../common';
import { nodeRiskScore, RISK_META, RiskLevel, riskLevel, SCORED_RISK_LEVELS } from './risk';
import { STATUS_COLORS } from '../components/topology/nodeStyle';

// Overview numbers, all derived from the graph the server returned.

export interface Slice {
  label: string;
  value: number;
  color: string;
}

function countBy<T>(items: T[], key: (item: T) => string): Map<string, number> {
  const out = new Map<string, number>();
  for (const item of items) out.set(key(item), (out.get(key(item)) || 0) + 1);
  return out;
}

// Largest first, ties alphabetical, so the donut and legend are stable.
function toSlices(counts: Map<string, number>, color: (label: string, i: number) => string): Slice[] {
  return Array.from(counts.entries())
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .map(([label, value], i) => ({ label, value, color: color(label, i) }));
}

/**
 * Network devices split by type. "Type" is the node `role` exactly as the map
 * shows it under each node (l3-switch, l2-switch, router, ...).
 *
 * Responding rule: the crawler sets a device's status to "online" when it was
 * polled successfully over SNMP and "unreachable" when no credential worked
 * (backend/vulnmapper/network/crawl.py, STATUS_ONLINE / STATUS_UNREACHABLE).
 * So responding = devices with status "online".
 */
export function deviceStats(graph: GraphResponse) {
  const devices = graph.nodes.filter((n) => n.kind === 'device');
  const palette = euiPaletteColorBlind();
  const slices = toSlices(
    countBy(devices, (d) => d.role || 'unknown'),
    (_label, i) => palette[i % palette.length]
  );
  const responding = devices.filter((d) => (d.status || '').toLowerCase() === 'online').length;
  return { total: devices.length, responding, slices };
}

// Colour of each endpoint category; any other status gets a palette colour.
const ENDPOINT_STATUS_COLORS: Record<string, string> = {
  active: STATUS_COLORS.active,
  disconnected: STATUS_COLORS.disconnected,
  stale: '#f59e0b',
  discovered: STATUS_COLORS.discovered,
};

/**
 * Endpoints split by status. A stale endpoint (an old Wazuh agent whose IP now
 * belongs to another live host; flagged `stale: true`) counts as "stale" rather
 * than its raw status, so each endpoint is counted once. Every node with kind
 * "endpoint" is included, so FDB-discovered hosts appear as "discovered".
 */
export function endpointStats(graph: GraphResponse) {
  const endpoints = graph.nodes.filter((n) => n.kind === 'endpoint');
  const palette = euiPaletteColorBlind();
  let extra = 0;
  const slices = toSlices(
    countBy(endpoints, (e) => (e.stale ? 'stale' : (e.status || 'unknown').toLowerCase())),
    (label) => ENDPOINT_STATUS_COLORS[label] || palette[extra++ % palette.length]
  );
  return { total: endpoints.length, slices };
}

/**
 * Hosts by risk level, endpoints only: network devices carry no CVE data yet,
 * so their risk_score is not meaningful.
 */
export function hostRiskStats(graph: GraphResponse) {
  const endpoints = graph.nodes.filter((n) => n.kind === 'endpoint');
  const counts = countBy(endpoints, (e) => riskLevel(nodeRiskScore(e)));
  const levels = SCORED_RISK_LEVELS.map((level: RiskLevel) => ({
    level,
    label: RISK_META[level].label,
    color: RISK_META[level].color,
    value: counts.get(level) || 0,
  }));
  return { total: endpoints.length, levels, unscored: counts.get('unscored') || 0 };
}
