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
    case 'stage_failed':
      return `The scan step "${String(w.stage)}" failed (${String(w.error)}), and the scan finished without it.`;
    case 'targets_invalid':
      return 'targets.json is not in the expected form, so no protected assets were used for this scan.';
    default:
      return null;
  }
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
