import { existsSync, mkdtempSync, writeFileSync } from 'fs';
import os from 'os';
import path from 'path';
import * as history from './history';
import {
  appendTail,
  failureMessage,
  getScan,
  latestStage,
  nvdKeyOf,
  onPath,
  runExclusive,
  scanArgs,
  shouldReplaceGraph,
  startScan,
  STDERR_TAIL,
} from './scan';

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

describe('previous graph', () => {
  it('passes the graph being replaced as --previous-graph', () => {
    expect(scanArgs({ ...OUT, previous: '/data/graph.json' }, {}).slice(2 + FILES.length)).toEqual([
      '--previous-graph',
      '/data/graph.json',
    ]);
  });
});

describe('seeds', () => {
  it('passes each configured seed as --seed=IP', () => {
    expect(scanArgs(OUT, { seeds: ['10.0.0.1', '10.0.0.2'] }).slice(2 + FILES.length)).toEqual([
      '--seed=10.0.0.1',
      '--seed=10.0.0.2',
    ]);
  });
});

describe('shouldReplaceGraph', () => {
  const empty = { nodes: [], metadata: { warnings: [{ type: 'crawl_empty', reason: 'no seed' }] } };
  const mapped = { nodes: [{ kind: 'device' }, { kind: 'endpoint' }], metadata: {} };
  const hostsOnly = { nodes: [{ kind: 'endpoint' }], metadata: {} };

  it('keeps a map with devices when the new crawl polled none', () => {
    expect(shouldReplaceGraph(empty, mapped, false)).toBe(false);
  });

  it('replaces it when forced, or when the crawl found devices', () => {
    expect(shouldReplaceGraph(empty, mapped, true)).toBe(true);
    expect(shouldReplaceGraph(mapped, mapped, false)).toBe(true);
  });

  it('replaces a map without devices, or no map at all', () => {
    expect(shouldReplaceGraph(empty, hostsOnly, false)).toBe(true);
    expect(shouldReplaceGraph(empty, null, false)).toBe(true);
  });
});

describe('appendTail', () => {
  it('keeps a bounded tail with the last line intact', () => {
    let buffer = '';
    for (let i = 0; i < 2000; i++) buffer = appendTail(buffer, `INFO line ${i} of a long scan log\n`);
    buffer = appendTail(buffer, 'vulnmapper: the last line\n');
    expect(buffer.length).toBe(STDERR_TAIL);
    expect(failureMessage(buffer, 1)).toBe('vulnmapper: the last line');
  });
});

describe('nvdKeyOf', () => {
  it('reads only the stage block boolean', () => {
    expect(nvdKeyOf({ metadata: { device_cves: { api_key: true } } })).toBe(true);
    expect(nvdKeyOf({ metadata: { device_cves: { api_key: false } } })).toBe(false);
    expect(nvdKeyOf({ metadata: {} })).toBeNull();
    expect(nvdKeyOf(null)).toBeNull();
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

describe('startScan', () => {
  it('runs one scan at a time, whatever starts it, and reports how it ended', async () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), 'vm-scan-'));
    const logger = { info: jest.fn(), warn: jest.fn() } as any;
    // node rejects "-m vulnmapper", so this scan fails quickly without a scanner
    const opts = { pythonBin: process.execPath, backendDir: dir, graphPath: path.join(dir, 'graph.json'), logger };
    const ended = new Promise<[boolean, string]>((resolve) => {
      expect(startScan({ ...opts, trigger: 'scheduled', onDone: (ok, m) => resolve([ok, m]) })).toBe(true);
    });
    expect(getScan()).toMatchObject({ status: 'running', trigger: 'scheduled' });
    expect(startScan({ ...opts, trigger: 'manual' })).toBe(false); // the lock
    const [ok] = await ended;
    expect(ok).toBe(false);
    expect(getScan().status).toBe('failed');
  });
});

describe('temporary files', () => {
  it('are gone before a failed scan releases the lock', async () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), 'vm-fail-'));
    const temps = ['vulnerabilities.json', 'attack_paths.json'].map((f) => path.join(dir, `${f}.tmp-${process.pid}`));
    temps.forEach((f) => writeFileSync(f, '{}'));
    const logger = { info: jest.fn(), warn: jest.fn() } as any;
    // node rejects "-m vulnmapper": a scan that exits non-zero
    const atDone = await new Promise<boolean[]>((resolve) => {
      startScan({
        pythonBin: process.execPath,
        backendDir: dir,
        graphPath: path.join(dir, 'graph.json'),
        onDone: () => resolve(temps.map(existsSync)), // the moment the lock is free
        logger,
      });
    });
    expect(atDone).toEqual([false, false]);
  });
});

describe('scan history', () => {
  it('archives a successful scan before releasing the lock', async () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), 'vm-ok-'));
    const scanner = path.join(dir, 'ok.sh'); // "-m vulnmapper --vulns-out V ...": write V, print a graph
    writeFileSync(scanner, '#!/bin/sh\necho "{}" > "$4"\necho \'{"nodes": [], "edges": [], "metadata": {}}\'\n', { mode: 0o755 });
    const statusWhenArchived: string[] = [];
    const spy = jest.spyOn(history, 'archiveScan').mockImplementation(async () => {
      statusWhenArchived.push(getScan().status);
      return {} as any;
    });
    const logger = { info: jest.fn(), warn: jest.fn() } as any;
    const ended = new Promise<[boolean, string]>((resolve) => {
      startScan({ pythonBin: scanner, backendDir: dir, graphPath: path.join(dir, 'graph.json'), onDone: (ok, m) => resolve([ok, m]), logger });
    });
    expect(await ended).toEqual([true, 'Scan completed; graph updated.']);
    expect(statusWhenArchived).toEqual(['running']);
    spy.mockRestore();
  });
});

describe('scan timeout', () => {
  it('kills a hung scan, fails it and discards its temporary files', async () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), 'vm-hang-'));
    const hang = path.join(dir, 'hang.sh'); // a "python" that never finishes
    writeFileSync(hang, '#!/bin/sh\nexec sleep 30\n', { mode: 0o755 });
    const temps = ['vulnerabilities.json', 'attack_paths.json'].map((f) => path.join(dir, `${f}.tmp-${process.pid}`));
    temps.forEach((f) => writeFileSync(f, '{}'));
    const logger = { info: jest.fn(), warn: jest.fn() } as any;
    const ended = new Promise<[boolean, string]>((resolve) => {
      startScan({
        pythonBin: hang,
        backendDir: dir,
        graphPath: path.join(dir, 'graph.json'),
        timeoutSeconds: 0.2,
        onDone: (ok, m) => resolve([ok, m]),
        logger,
      });
    });
    expect(await ended).toEqual([false, 'scan timed out after 0.2 s']);
    expect(getScan().status).toBe('failed');
    temps.forEach((f) => expect(existsSync(f)).toBe(false));
  });
});

describe('runExclusive', () => {
  it('shares the scan lock both ways', async () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), 'vm-lock-'));
    const logger = { info: jest.fn(), warn: jest.fn() } as any;
    const opts = { pythonBin: process.execPath, backendDir: dir, graphPath: path.join(dir, 'graph.json'), logger };
    let release: () => void = () => undefined;
    const task = runExclusive(() => new Promise<void>((r) => (release = r)));
    expect(task).not.toBeNull();
    expect(startScan(opts)).toBe(false); // no scan during the task
    expect(runExclusive(async () => undefined)).toBeNull(); // nor a second task
    release();
    await task;
    const ended = new Promise<void>((resolve) => {
      expect(startScan({ ...opts, onDone: () => resolve() })).toBe(true);
    });
    expect(runExclusive(async () => undefined)).toBeNull(); // no task during a scan
    await ended;
  });
});
