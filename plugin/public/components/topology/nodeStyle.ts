// Node styling helpers: a subtle risk border + liveness dot + offline dimming.
// Risk is shown by the border, never by recoloring the whole node.
// The level comes from the shared nodeLevel() so the map agrees with the overview.
import { NODE_LEVEL_META, NodeLevel } from '../../lib/risk';
import { GraphNode, LivenessResponse, NodeLiveness } from '../../../common';
import { isOfflineHost } from './inactive';

/**
 * LIVENESS -> corner dot color. This is the dot's ONLY meaning — it must never
 * encode risk (a healthy-but-vulnerable host should still read as "up"):
 *   active/online  -> green  (confirmed up)
 *   discovered     -> grey   (FDB-only, liveness unconfirmed)
 *   disconnected/down -> red (known but down)
 */
export const STATUS_COLORS: Record<string, string> = {
  active: '#22c55e',
  online: '#22c55e',
  discovered: '#9ca3af',
  disconnected: '#ef4444',
  down: '#ef4444',
  unreachable: '#ef4444',
};

export function statusDot(status: string | null | undefined, liveness?: NodeLiveness): string {
  if (liveness && liveness.state === 'active') return STATUS_COLORS.active;
  if (liveness && liveness.state === 'inactive') return STATUS_COLORS.disconnected;
  return STATUS_COLORS[(status || '').toLowerCase()] || '#9ca3af';
}

export type RiskBorder = { color: string; width: number };

const BORDER_WIDTH: Record<NodeLevel, number> = {
  P0: 3,
  P1: 2,
  P2: 2,
  P3: 1,
  high: 2,
  medium: 2,
  low: 1,
  none: 1,
};

/** A node level's border (outline) colour and width. */
export function borderForLevel(level: NodeLevel): RiskBorder {
  return { color: NODE_LEVEL_META[level].color, width: BORDER_WIDTH[level] };
}

/**
 * Whether the map dims a node (dashed, faded). A host follows the shared offline
 * rule (inactive.ts), so the map, the report and the recommendations agree. A
 * device is never offline under that rule, since it stays on the map: it is
 * dimmed when liveness reports it inactive, or when it is only known from a
 * neighbour's table.
 */
export function isOffline(node: GraphNode, liveness: LivenessResponse | null | undefined): boolean {
  if (node.kind === 'endpoint') return isOfflineHost(node, liveness);
  const state = liveness?.nodes?.[node.node_id]?.state;
  if (state === 'active') return false;
  if (state === 'inactive') return true;
  const s = (node.status || '').toLowerCase();
  return s === 'disconnected' || s === 'discovered';
}
