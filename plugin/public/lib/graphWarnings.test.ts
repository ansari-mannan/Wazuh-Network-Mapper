import { CONNECTION_UNVERIFIED, connectionSecurity, graphWarnings, tlsNote } from './graphWarnings';

describe('graphWarnings', () => {
  it('leaves TLS out of the warnings: it is a note', () => {
    expect(graphWarnings([{ type: 'tls_unverified', services: ['Wazuh Manager API'] }])).toEqual([]);
  });

  it('keys the TLS note by its services, so a new one shows again', () => {
    const one = tlsNote([{ type: 'tls_unverified', services: ['Wazuh Manager API'] }]);
    const two = tlsNote([{ type: 'tls_unverified', services: ['Wazuh Manager API', 'Wazuh Indexer'] }]);
    expect(one?.text).toMatch(/^TLS certificates were not verified for the Wazuh Manager API/);
    expect(one?.key).not.toBe(two?.key);
    expect(tlsNote([{ type: 'crawl_empty' }])).toBeNull();
  });

  it('gives the Scan settings connection line', () => {
    expect(connectionSecurity([{ type: 'tls_unverified', services: ['Wazuh Indexer'] }])).toBe(CONNECTION_UNVERIFIED);
    expect(connectionSecurity([])).toMatch(/^Certificates verified/);
  });

  it('explains an empty crawl and a failed stage in plain words', () => {
    expect(
      graphWarnings([
        { type: 'crawl_empty', reason: 'no seed' },
        { type: 'stage_failed', stage: 'Configuration checks', error: 'KeyError' },
      ])
    ).toEqual([
      'The network crawl found no devices: no starting device was found (set vulnmapper.seeds). The map shows hosts only.',
      'The scan step "Configuration checks" failed (KeyError), and the scan finished without it.',
    ]);
  });

  it('skips the warnings it does not explain', () => {
    expect(graphWarnings(undefined)).toEqual([]);
    expect(graphWarnings([{ type: 'inventory_unavailable' }])).toEqual([]);
  });
});
