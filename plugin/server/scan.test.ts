import { failureMessage, scanArgs } from './scan';

describe('scanArgs', () => {
  it('runs every stage and no probe by default', () => {
    expect(scanArgs('/tmp/v.json', {})).toEqual(['-m', 'vulnmapper', '--vulns-out', '/tmp/v.json']);
  });

  it('passes the scan form’s choices as flags', () => {
    expect(scanArgs('/tmp/v.json', { checkDefaultCommunities: true })).toContain('--check-default-communities');
    expect(scanArgs('/tmp/v.json', { deviceCves: false, checkDefaultCommunities: false })).toEqual([
      '-m',
      'vulnmapper',
      '--vulns-out',
      '/tmp/v.json',
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
