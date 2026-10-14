// The graph's warnings (metadata.warnings) that the Overview shows, each as
// one plain sentence. Other warning types are shown where they belong, or not at all.
import { GraphWarning } from '../../common';

const CRAWL_EMPTY: Record<string, string> = {
  'no credentials': 'no SNMP credential was set',
  'no seed': 'no starting device was found (set vulnmapper.seeds)',
  'crawl error': 'the crawl stopped with an error',
  'no device answered': 'no device answered SNMP',
};

function sentence(w: GraphWarning): string | null {
  switch (w.type) {
    case 'tls_unverified': {
      const services = Array.isArray(w.services) ? w.services.join(' and ') : 'Wazuh';
      return (
        `TLS certificates were not verified for the ${services} during this scan. ` +
        'Set VULNMAPPER_VERIFY_TLS=1 or a CA bundle (WAZUH_CA_BUNDLE, INDEXER_CA_BUNDLE) outside a lab.'
      );
    }
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
