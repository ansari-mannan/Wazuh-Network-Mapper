import { failureMessage, scanArgs } from './scan';

const OUT = { vulns: '/tmp/v.json', paths: '/tmp/p.json', targets: '/data/targets.json' };
const FILES = ['--vulns-out', '/tmp/v.json', '--paths-out', '/tmp/p.json', '--targets', '/data/targets.json'];

describe('scanArgs', () => {
  it('runs every stage and no probe by default', () => {
    expect(scanArgs(OUT, {})).toEqual(['-m', 'vulnmapper', ...FILES]);
  });

  it('writes attack paths from the targets beside the graph', () => {
    const args = scanArgs(OUT, {});
    expect(args[args.indexOf('--paths-out') + 1]).toBe('/tmp/p.json');
    expect(args[args.indexOf('--targets') + 1]).toBe('/data/targets.json');
  });

  it('passes the scan form’s choices as flags', () => {
    expect(scanArgs(OUT, { checks: { checkDefaultCommunities: true } })).toContain('--check-default-communities');
    expect(
      scanArgs(OUT, { checks: { checkManagementPorts: true, probeUnmanagedSnmp: true } }).slice(2 + FILES.length)
    ).toEqual(['--check-management-ports', '--probe-unmanaged-snmp']);
    expect(scanArgs(OUT, { checks: { nmapUnmanaged: true } })).toContain('--nmap-unmanaged');
    expect(scanArgs(OUT, { deviceCves: false, checks: { checkDefaultCommunities: false } })).toEqual([
      '-m',
      'vulnmapper',
      ...FILES,
      '--no-device-cves',
    ]);
  });
});

describe('failureMessage', () => {
  it('shows a rejected Wazuh login as its one plain line', () => {
    const stderr =
      '2026-10-10 01:39:38,962 INFO vulnmapper.pipeline: collecting endpoints from the Wazuh Manager API ...\n' +
      'vulnmapper: the Wazuh Manager API at wazuh.example:55000 rejected the login (HTTP 401); check WAZUH_USER and WAZUH_PASS.\n';
    expect(failureMessage(stderr, 1)).toBe(
      'vulnmapper: the Wazuh Manager API at wazuh.example:55000 rejected the login (HTTP 401); check WAZUH_USER and WAZUH_PASS.'
    );
  });
});
