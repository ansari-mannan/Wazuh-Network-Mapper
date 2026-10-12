import { mkdtempSync, writeFileSync } from 'fs';
import os from 'os';
import path from 'path';
import { failureMessage, latestStage, onPath, scanArgs } from './scan';

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

describe('latestStage', () => {
  it('takes the last stage the scanner announced', () => {
    const stderr =
      '2026-10-12 10:00:00,000 INFO vulnmapper.pipeline: stage: Crawling the network over SNMP/LLDP\n' +
      '2026-10-12 10:00:05,000 INFO vulnmapper.devicecves: device CVEs: 9 device(s)\n' +
      '2026-10-12 10:00:06,000 INFO vulnmapper.pipeline: stage: Looking up device CVEs in NVD\n';
    expect(latestStage(stderr)).toBe('Looking up device CVEs in NVD');
  });
  it('is null when no stage line is there', () => {
    expect(latestStage('vulnmapper: WAZUH_PASS is not set\n')).toBeNull();
  });
});

describe('onPath', () => {
  it('finds an executable in one of the PATH folders, and only there', () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), 'vm-path-'));
    writeFileSync(path.join(dir, 'nmap'), '#!/bin/sh\n', { mode: 0o755 });
    writeFileSync(path.join(dir, 'notexec'), '', { mode: 0o644 });
    expect(onPath('nmap', ['/nonexistent', dir].join(path.delimiter))).toBe(true);
    expect(onPath('notexec', dir)).toBe(false);
    expect(onPath('nmap', '/nonexistent')).toBe(false);
    expect(onPath('nmap', '')).toBe(false);
  });
});
