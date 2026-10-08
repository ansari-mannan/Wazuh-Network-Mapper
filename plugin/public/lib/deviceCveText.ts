import { CveLookup } from '../../common';

// Plain words for a network device's CVE lookup (backend/vulnmapper/devicecves),
// for the detail flyout.

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

/** "9 Oct 2026", in the viewer's own time zone. */
export function lookupDate(iso: string | null | undefined): string {
  const t = iso ? Date.parse(iso) : NaN;
  if (Number.isNaN(t)) return 'an unknown date';
  const d = new Date(t);
  return `${d.getDate()} ${MONTHS[d.getMonth()]} ${d.getFullYear()}`;
}

/** Whether a device's lookup has findings to list (a keyword search that
 * matched nothing has none, and says why in unscoredReason instead). */
export function hasDeviceFindings(l: CveLookup | null | undefined): boolean {
  return Boolean(l && l.status === 'ok' && (l.match === 'cpe' || (l.total || 0) > 0));
}

/** "1 device", "2 devices". */
export function plural(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? '' : 's'}`;
}

const NOT_CONFIRMED = 'A version match does not confirm the affected feature is in use.';

/** What a device's findings rest on; empty when nothing was matched. */
export function potentialText(l: CveLookup): string {
  if (l.status !== 'ok') return '';
  const when = lookupDate(l.fetched_at);
  if (l.match === 'keyword') {
    return `Potential: matched by product name and version (${l.product}) in NVD descriptions on ${when}. ${NOT_CONFIRMED}`;
  }
  return `Potential: matched by software version (${l.product}) against NVD on ${when}. ${NOT_CONFIRMED}`;
}

/** One sentence on why a device is Unscored; empty when it is scored. */
export function unscoredReason(node: { kind: string; pollable?: boolean; cve_lookup?: CveLookup | null }): string {
  if (node.kind !== 'device') return '';
  const l = node.cve_lookup;
  if (!l) return 'This graph has no CVE lookup for devices; the next scan adds one.';
  switch (l.status) {
    case 'unidentified':
      return node.pollable === false
        ? 'It was only seen in a neighbour’s table, never polled, so its software is unknown.'
        : 'Its software could not be identified: the vendor, software family or version is missing.';
    case 'unavailable':
      return 'NVD could not be reached and nothing was cached; it will be looked up again on the next scan.';
    case 'unverified':
      return `NVD does not list ${l.product || 'this software version'}, so the lookup could not be confirmed.`;
    case 'ok':
      if (l.match === 'keyword' && !l.total) {
        return `NVD has no exact identifier for ${l.product}, and no NVD entry names this product line and version.`;
      }
      return '';
    default:
      return '';
  }
}

/** A stale result: NVD could not be reached, so an older answer is shown. */
export function staleText(l: CveLookup): string {
  return l.stale ? `NVD could not be reached; this is its answer from ${lookupDate(l.fetched_at)}.` : '';
}
