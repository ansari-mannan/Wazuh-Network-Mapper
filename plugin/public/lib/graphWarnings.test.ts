import { CONNECTION_UNVERIFIED, connectionSecurity, graphWarnings, snmpSources, tlsNote } from './graphWarnings';

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

  it('names the devices where a typed community fell back to the server settings', () => {
    expect(graphWarnings([{ type: 'snmp_fallback', devices: ['CYFOR-HP-Switch', 'L2-Switch'] }])).toEqual([
      "The community you entered didn't work on CYFOR-HP-Switch, L2-Switch; the server's SNMP settings were used for them.",
    ]);
  });

  it('says when the typed community worked on no device', () => {
    const names = ['CYFOR-AP1', 'CYFOR-Firewall.cyfor.lab', 'CYFOR-HP-Switch', 'L2-Switch', 'L3-Switch'];
    const snmp = { entered: [], server: names.map((n) => `device:${n}`) };
    expect(graphWarnings([{ type: 'snmp_fallback', devices: names }], snmp)).toEqual([
      "The community you entered didn't work on any device. The server's SNMP settings were used for all 5 " +
        '(CYFOR-AP1, CYFOR-Firewall.cyfor.lab, CYFOR-HP-Switch, L2-Switch, L3-Switch).',
    ]);
    expect(graphWarnings([{ type: 'snmp_fallback', devices: [...names, 'sw6'] }], snmp)[0]).toMatch(/all 6 \(CYFOR-AP1, .*L3-Switch, …\)\.$/);
  });

  it('gives the Scan settings SNMP line with and without a typed community', () => {
    const fallback = [{ type: 'snmp_fallback', devices: ['a'] }];
    expect(snmpSources({ entered: [], server: ['a', 'b', 'c', 'd', 'e'] }, fallback)).toBe(
      'Community you entered: 0 of 5 devices · server settings: 5'
    );
    expect(snmpSources({ entered: ['a', 'b', 'c'], server: ['d', 'e'] }, fallback)).toBe(
      'Community you entered: 3 of 5 devices · server settings: 2'
    );
    expect(snmpSources({ entered: ['a', 'b'], server: [] }, [])).toBe('Community you entered: 2 of 2 devices · server settings: 0');
    expect(snmpSources({ entered: [], server: ['a', 'b', 'c', 'd', 'e'] }, [])).toBe('Server settings on 5 devices');
    expect(snmpSources(undefined)).toBeNull();
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
