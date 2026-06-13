// Node styling helpers: a subtle risk dot/ring + offline dimming. Risk is shown
// by a small colored indicator, never by recoloring the whole node.

/**
 * Risk -> color. The null case is the important one: an unscored node (e.g. an
 * FDB-discovered host, or a device the NVD stage hasn't reached) is GREY, never
 * green — green is reserved for "scored and clean" (risk_score === 0).
 */
export function riskColor(score) {
  if (score === null || score === undefined) return "#9ca3af"; // grey  — unknown / unscored
  if (score >= 9) return "#dc2626"; // red    — critical (>=9)
  if (score >= 7) return "#ea580c"; // orange — high (7–9)
  if (score > 0) return "#eab308"; // yellow — low/medium (>0 & <7)
  return "#16a34a"; // green  — scored, clean (==0)
}

export function riskLabel(score) {
  if (score === null || score === undefined) return "unknown";
  return String(score);
}

/**
 * LIVENESS -> corner dot color. This is the dot's ONLY meaning — it must never
 * encode risk (a healthy-but-vulnerable host should still read as "up"):
 *   active/online  -> green  (confirmed up)
 *   discovered     -> grey   (FDB-only, liveness unconfirmed)
 *   disconnected/down -> red (known but down)
 */
export function statusDot(status) {
  return (
    {
      active: "#22c55e",
      online: "#22c55e",
      discovered: "#9ca3af",
      disconnected: "#ef4444",
      down: "#ef4444",
    }[(status || "").toLowerCase()] || "#9ca3af"
  );
}

/**
 * RISK -> node border (outline), independent of liveness. Returns { color, width }.
 * null/undefined risk is a neutral thin grey border (unscored), not green.
 */
export function riskBorder(r) {
  if (r === null || r === undefined) return { color: "#d1d5db", width: 1 };
  if (r >= 9.0) return { color: "#dc2626", width: 3 }; // critical
  if (r >= 7.0) return { color: "#f97316", width: 2 }; // high
  if (r >= 4.0) return { color: "#eab308", width: 2 }; // medium
  return { color: "#22c55e", width: 1 }; // low / clean
}

/**
 * Offline = a host/device that isn't currently present. Endpoints report
 * "disconnected", FDB-discovered hosts "discovered"; online states are "online"
 * (devices) and "active" (endpoints). Offline nodes are dimmed + dashed.
 */
export function isOffline(status) {
  const s = (status || "").toLowerCase();
  return s === "disconnected" || s === "discovered";
}
