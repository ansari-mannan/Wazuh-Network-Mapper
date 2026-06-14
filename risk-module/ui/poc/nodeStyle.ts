// Node styling helpers: a subtle risk dot/ring + offline dimming. Risk is shown
// by a small colored indicator, never by recoloring the whole node.
// Ported verbatim from gui/frontend/src/nodeStyle.js.

/**
 * Risk -> color. The null case is the important one: an unscored node (e.g. an
 * FDB-discovered host, or a device the NVD stage hasn't reached) is GREY, never
 * green — green is reserved for "scored and clean" (risk_score === 0).
 */
export function riskColor(score: number | null | undefined): string {
  if (score === null || score === undefined) return "#9ca3af"; // grey  — unknown / unscored
  if (score >= 9) return "#dc2626"; // red    — critical (>=9)
  if (score >= 7) return "#ea580c"; // orange — high (7–9)
  if (score > 0) return "#eab308"; // yellow — low/medium (>0 & <7)
  return "#16a34a"; // green  — scored, clean (==0)
}

export function riskLabel(score: number | null | undefined): string {
  if (score === null || score === undefined) return "unknown";
  return String(score);
}

/**
 * Offline = a host/device that isn't currently present. Endpoints report
 * "disconnected", FDB-discovered hosts "discovered"; online states are "online"
 * (devices) and "active" (endpoints). Offline nodes are dimmed + dashed.
 */
export function isOffline(status: string | null | undefined): boolean {
  const s = (status || "").toLowerCase();
  return s === "disconnected" || s === "discovered";
}
