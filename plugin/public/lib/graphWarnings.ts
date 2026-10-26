// The graph's warnings (metadata.warnings) that the Overview shows, each as
// one plain sentence. Other warning types are shown where they belong, or not
// at all. TLS verification being off is the lab default, so it is a quiet,
// dismissible note (tlsNote) rather than a warning.
import { GraphWarning, Metadata } from '../../common';

type Snmp = Metadata['snmp'];

const CRAWL_EMPTY: Record<string, string> = {
  'no credentials': 'no SNMP credential was set',
  'no seed': 'no starting device was found (set vulnmapper.seeds)',
  'crawl error': 'the crawl stopped with an error',
  'no device answered': 'no device answered SNMP',
};

function sentence(w: GraphWarning, snmp?: Snmp): string | null {
  switch (w.type) {
    case 'crawl_empty':
      return (
        `The network crawl found no devices: ${CRAWL_EMPTY[String(w.reason)] ?? String(w.reason ?? 'unknown reason')}. ` +
        'The map shows hosts only.'
      );
    case 'snmp_fallback':
      return snmpFallbackText(w.devices, snmp);
    case 'stage_failed':
      return `The scan step "${String(w.stage)}" failed (${String(w.error)}), and the scan finished without it.`;
    case 'targets_invalid':
      return 'targets.json is not in the expected form, so no protected assets were used for this scan.';
    default:
      return null;
  }
}

// at most this many names when every device fell back
const MAX_NAMES = 5;

/**
 * The snmp_fallback warning's sentence, for the Overview, the scan result box
 * and the toast. snmp (metadata.snmp) tells whether the typed community worked
 * on no device at all.
 */
export function snmpFallbackText(devices: unknown, snmp?: Snmp): string {
  const names = Array.isArray(devices) ? devices.map(String) : [];
  if (snmp && !snmp.entered?.length && names.length) {
    const shown = names.slice(0, MAX_NAMES).join(', ') + (names.length > MAX_NAMES ? ', …' : '');
    return (
      "The community you entered didn't work on any device. The server's SNMP settings were used for " +
      `${names.length === 1 ? 'it' : `all ${names.length}`} (${shown}).`
    );
  }
  return `The community you entered didn't work on ${names.join(', ') || 'some devices'}; the server's SNMP settings were used for them.`;
}

const devicesWord = (n: number) => `${n} ${n === 1 ? 'device' : 'devices'}`;

/**
 * Scan settings' "SNMP" line: "Community you entered: 0 of 5 devices · server
 * settings: 5" when a community was typed (some device answered it, or the
 * graph has an snmp_fallback warning), else "Server settings on 5 devices";
 * null for a graph without metadata.snmp.
 */
export function snmpSources(snmp: Snmp, warnings?: GraphWarning[]): string | null {
  if (!snmp) return null;
  const entered = snmp.entered?.length ?? 0;
  const server = snmp.server?.length ?? 0;
  const typed = entered > 0 || (warnings || []).some((w) => w.type === 'snmp_fallback');
  if (!typed) return `Server settings on ${devicesWord(server)}`;
  return `Community you entered: ${entered} of ${devicesWord(entered + server)} · server settings: ${server}`;
}

/** The warnings as sentences; snmp (metadata.snmp) words an SNMP fallback. */
export function graphWarnings(warnings: GraphWarning[] | undefined, snmp?: Snmp): string[] {
  return (warnings || []).map((w) => sentence(w, snmp)).filter((s): s is string => s !== null);
}

export const CONNECTION_UNVERIFIED =
  'Wazuh/Indexer certificates not verified (lab default). Set WAZUH_CA_BUNDLE / INDEXER_CA_BUNDLE to verify.';

/**
 * The tls_unverified warning as an info note, or null. Its key names the kind
 * and the services, so dismissing it hides only this note: a new kind of
 * warning, or another service left unverified, shows again.
 */
export function tlsNote(warnings: GraphWarning[] | undefined): { key: string; text: string } | null {
  const w = (warnings || []).find((x) => x.type === 'tls_unverified');
  if (!w) return null;
  const services = Array.isArray(w.services) ? w.services.map(String) : ['Wazuh'];
  return {
    key: `tls_unverified:${[...services].sort().join(',')}`,
    text: `TLS certificates were not verified for the ${services.join(' and ')} during this scan (lab default).`,
  };
}

/** The Scan settings "Connection security" line for the latest graph. */
export function connectionSecurity(warnings: GraphWarning[] | undefined): string {
  return tlsNote(warnings) ? CONNECTION_UNVERIFIED : 'Certificates verified, or Wazuh not contacted in this scan.';
}
