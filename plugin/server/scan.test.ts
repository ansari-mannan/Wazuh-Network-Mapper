import { scanArgs } from './scan';

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
