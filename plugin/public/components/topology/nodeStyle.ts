// Node styling helpers: a subtle risk border + liveness dot + offline dimming.
// Risk is shown by the border, never by recoloring the whole node.
// Ported from frontend/risk-module/ui/topology/nodeStyle.ts; the risk bands now
// come from the shared riskLevel() so the map agrees with the overview.
import { RISK_META, RiskLevel, riskLevel } from '../../lib/risk';
import { NodeLiveness } from '../../common';

export function riskLabel(score: number | null | undefined): string {
  if (score === null || score === undefined) return 'unknown';
  return String(score);
}

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

const BORDER_WIDTH: Record<RiskLevel, number> = {
  critical: 3,
  high: 2,
  medium: 2,
  low: 1,
  unscored: 1,
};

/**
 * RISK -> node border (outline), independent of liveness. Returns { color, width }.
 * An unscored node gets a neutral thin grey border, not green.
 */
export function riskBorder(r: number | null | undefined): RiskBorder {
  const level = riskLevel(r);
  return { color: RISK_META[level].color, width: BORDER_WIDTH[level] };
}

/**
 * Offline = a host/device that isn't currently present. Endpoints report
 * "disconnected", FDB-discovered hosts "discovered"; online states are "online"
 * (devices) and "active" (endpoints). Offline nodes are dimmed + dashed.
 */
export function isOffline(status: string | null | undefined, liveness?: NodeLiveness): boolean {
  if (liveness && liveness.state === 'active') return false;
  if (liveness && liveness.state === 'inactive') return true;
  const s = (status || '').toLowerCase();
  return s === 'disconnected' || s === 'discovered';
}
