// The graph's tls_unverified warning (metadata.warnings), as one line for the
// Overview: the scan talked to Wazuh without checking its certificate.
import { GraphWarning } from '../../common';

export function tlsWarning(warnings: GraphWarning[] | undefined): string {
  const hit = (warnings || []).find((w) => w.type === 'tls_unverified');
  if (!hit) return '';
  const services = Array.isArray(hit.services) ? hit.services.join(' and ') : 'Wazuh';
  return (
    `TLS certificates were not verified for the ${services} during this scan. ` +
    'Set VULNMAPPER_VERIFY_TLS=1 or a CA bundle (WAZUH_CA_BUNDLE, INDEXER_CA_BUNDLE) outside a lab.'
  );
}
