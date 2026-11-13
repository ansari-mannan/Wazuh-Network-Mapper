// Plain words for a network device's CVE lookup (backend/vulnmapper/devicecves),
// for the detail flyout.
import { CveLookup, OsvMatch } from '../../common';


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

// a Junos device: Juniper's CVE records (cve.org) plus NVD (backend lookup.py)
const JUNIPER = 'juniper-cna+nvd';

const NOT_CONFIRMED = 'A version match does not confirm the affected feature is in use.';

/** What a device's findings rest on; empty when nothing was matched. */
export function potentialText(l: CveLookup): string {
  if (l.status !== 'ok') return '';
  const when = lookupDate(l.fetched_at);
  if (l.source === 'nmap') {
    return `Potential, from service detection: nmap detected ${l.product}, looked up against NVD on ${when}. ${NOT_CONFIRMED}`;
  }
  if (l.source === JUNIPER) {
    return `Potential: matched by software version (${l.product}) against Juniper's own CVE records and NVD on ${when}. ${NOT_CONFIRMED}`;
  }
  if (l.match === 'keyword') {
    return `Potential: matched by product name and version (${l.product}) in NVD descriptions on ${when}. ${NOT_CONFIRMED}`;
  }
  return `Potential: matched by software version (${l.product}) against NVD on ${when}. ${NOT_CONFIRMED}`;
}

/** Where the Wazuh server's findings came from; empty for any other node. */
export function osvText(node: { osv?: OsvMatch }): string {
  return node.osv?.status === 'ok'
    ? "Findings from the server's own package list (Wazuh doesn't index the manager), matched with OSV.dev; potential."
    : '';
}

/** One sentence on why a device is Unscored; empty when it is scored. */
export function unscoredReason(node: {
  kind: string;
  pollable?: boolean;
  cve_lookup?: CveLookup | null;
  unscored_reason?: string;
  osv?: OsvMatch;
}): string {
  if (node.unscored_reason === 'no_inventory') {
    const osv = node.osv?.reason ? ` Its own package list was not matched with OSV.dev: ${node.osv.reason}.` : '';
    return `Wazuh has no software inventory for this host.${osv}`;
  }
  // a host has a lookup only when it answered SNMP (vulnmapper.hosts)
  if (node.kind !== 'device' && !node.cve_lookup) return '';
  const l = node.cve_lookup;
  if (!l) return 'This graph has no CVE lookup for devices; the next scan adds one.';
  switch (l.status) {
    case 'unidentified':
      return node.pollable === false
        ? 'It was only seen in a neighbour’s table, never polled, so its software is unknown.'
        : 'Its software could not be identified: the vendor, software family or version is missing.';
    case 'unavailable':
      if (l.reason === 'juniper_index_unavailable' || l.reason === 'juniper_records_incomplete') {
        return "Juniper's CVE records are not all fetched yet; it will be looked up again on the next scan.";
      }
      return 'NVD could not be reached and nothing was cached; it will be looked up again on the next scan.';
    case 'unverified':
      if (l.reason === 'version_not_comparable') {
        return `${l.product || 'This release'} is not a regular Junos release, so it cannot be compared with Juniper's CVE records.`;
      }
      if (l.reason === 'no_cpe_rule') {
        return `${l.product || 'This software'} is identified, but NVD has no product name that fits it, so its CVEs are not looked up.`;
      }
      if (l.reason === 'model_not_mapped') {
        return `NVD files part of the CVEs for ${l.product || 'this software'} under the switch model, and this model is not known, so the lookup would be incomplete.`;
      }
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
  if (!l.stale) return '';
  if (l.source === JUNIPER) {
    return `Juniper's CVE records or NVD could not all be refreshed; some answers are older (NVD's from ${lookupDate(l.fetched_at)}).`;
  }
  return `NVD could not be reached; this is its answer from ${lookupDate(l.fetched_at)}.`;
}

/** Junos: the CVEs whose Juniper records make no claim for this release
 * (e.g. only signature-pack versions); empty when there are none. */
export function undecidedText(l: CveLookup): string {
  const ids = l.status === 'ok' ? l.undecided || [] : [];
  if (!ids.length) return '';
  return `Juniper's records do not say whether this release is affected by ${plural(ids.length, 'CVE')}: ${ids.join(', ')}. Check them by hand.`;
}
