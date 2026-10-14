import { tlsWarning } from './tlsWarning';

describe('tlsWarning', () => {
  it('names the unverified services', () => {
    expect(tlsWarning([{ type: 'tls_unverified', services: ['Wazuh Manager API', 'Wazuh Indexer'] }])).toMatch(
      /^TLS certificates were not verified for the Wazuh Manager API and Wazuh Indexer during this scan\./
    );
  });

  it('is empty without the warning', () => {
    expect(tlsWarning(undefined)).toBe('');
    expect(tlsWarning([{ type: 'inventory_unavailable' }])).toBe('');
  });
});
