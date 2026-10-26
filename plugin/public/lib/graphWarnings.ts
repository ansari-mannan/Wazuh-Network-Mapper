// The graph's warnings (metadata.warnings) that the Overview shows, each as
// one plain sentence. Other warning types are shown where they belong, or not
// at all. TLS verification being off is the lab default, so it is a quiet,
// dismissible note (tlsNote) rather than a warning.
import { GraphWarning } from '../../common';

const CRAWL_EMPTY: Record<string, string> = {
  'no credentials': 'no SNMP credential was set',
  'no seed': 'no starting device was found (set vulnmapper.seeds)',
  'crawl error': 'the crawl stopped with an error',
  'no device answered': 'no device answered SNMP',
};

function sentence(w: GraphWarning): string | null {
  switch (w.type) {
    case 'crawl_empty':
      return (
        `The network crawl found no devices: ${CRAWL_EMPTY[String(w.reason)] ?? String(w.reason ?? 'unknown reason')}. ` +
        'The map shows hosts only.'
      );
    case 'snmp_fallback':
      return snmpFallbackText(w.devices);
    case 'stage_failed':
      return `The scan step "${String(w.stage)}" failed (${String(w.error)}), and the scan finished without it.`;
    case 'targets_invalid':
      return 'targets.json is not in the expected form, so no protected assets were used for this scan.';
    default:
      return null;
  }
}

/** The snmp_fallback warning's sentence, for the Overview and the scan toast. */
export function snmpFallbackText(devices: unknown): string {
  const names = Array.isArray(devices) ? devices.map(String).join(', ') : 'some devices';
  return `The community you entered didn't work on ${names}; the server's SNMP settings were used for them.`;
}

/** Scan settings' "SNMP" line, e.g. "entered community on 3 devices, server settings on 2"; null before C1 graphs. */
export function snmpSources(snmp: { entered?: string[]; server?: string[] } | undefined): string | null {
  if (!snmp) return null;
  const entered = snmp.entered?.length ?? 0;
  const server = snmp.server?.length ?? 0;
  if (!entered) return `server settings on ${server} ${server === 1 ? 'device' : 'devices'}`;
  return `entered community on ${entered} ${entered === 1 ? 'device' : 'devices'}, server settings on ${server}`;
}

export function graphWarnings(warnings: GraphWarning[] | undefined): string[] {
  return (warnings || []).map(sentence).filter((s): s is string => s !== null);
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
