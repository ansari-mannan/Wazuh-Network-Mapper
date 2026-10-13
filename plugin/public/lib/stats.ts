// Overview numbers, all derived from the graph the server returned.
import { euiPaletteColorBlind } from '@elastic/eui';
import { GraphResponse } from '../../common';
import { TIER_META, tierCounts, TIERS } from './risk';
import { STATUS_COLORS } from '../components/topology/nodeStyle';
import { roleLabel } from './roleLabel';


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
    countBy(devices, (d) => roleLabel(d.role || 'unknown')),
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
 * Endpoints and network devices by OVSS tier (riskRule.ts). The four tiers plus
 * the untiered (Unrated, Unassessed, or a graph from before OVSS) add up to total.
 */
export function riskStats(graph: GraphResponse) {
  const c = tierCounts(graph.nodes);
  const levels = TIERS.map((tier) => ({
    level: tier,
    label: TIER_META[tier].label,
    color: TIER_META[tier].color,
    value: c[tier],
  }));
  return { total: c.total, levels, unrated: c.unrated, unassessed: c.unassessed, notScored: c.notScored };
}
