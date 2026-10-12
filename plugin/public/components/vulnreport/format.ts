// Labels, colours and dates for the vulnerability report.
import { PLUGIN_NAME } from '../../../common';
import { RISK_META } from '../../lib/risk';
import { Severity } from '../../lib/report';

// shortcut: plugin version is mirrored here, not read from opensearch_dashboards.json
// (no JSON module resolution in the build); bump it with the manifest.
export const TOOL = `${PLUGIN_NAME} (vulnmapper 1.0.0)`;

export const SEV_META: Record<Severity, { label: string; color: string }> = {
  critical: RISK_META.critical,
  high: RISK_META.high,
  medium: RISK_META.medium,
  low: RISK_META.low,
  unknown: { label: 'Unknown', color: RISK_META.unscored.color },
};

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const pad2 = (n: number) => String(n).padStart(2, '0');

// A clean, locale-stable date (e.g. "8 Oct 2026", or "8 Oct 2026, 17:58" with a time).
export const prettyDate = (iso?: string, withTime = true) => {
  const t = iso ? Date.parse(iso) : NaN;
  if (Number.isNaN(t)) return 'an unknown date';
  const d = new Date(t);
  const date = `${d.getDate()} ${MONTHS[d.getMonth()]} ${d.getFullYear()}`;
  return withTime ? `${date}, ${pad2(d.getHours())}:${pad2(d.getMinutes())}` : date;
};

// YYYY-MM-DD for the download filename (the scan date, else today).
export const dateStamp = (iso?: string) => {
  const t = iso ? Date.parse(iso) : NaN;
  const d = Number.isNaN(t) ? new Date() : new Date(t);
  return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())}`;
};
