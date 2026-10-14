import { graphWarnings } from './graphWarnings';

describe('graphWarnings', () => {
  it('names the unverified TLS services', () => {
    expect(graphWarnings([{ type: 'tls_unverified', services: ['Wazuh Manager API', 'Wazuh Indexer'] }])[0]).toMatch(
      /^TLS certificates were not verified for the Wazuh Manager API and Wazuh Indexer during this scan\./
    );
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
