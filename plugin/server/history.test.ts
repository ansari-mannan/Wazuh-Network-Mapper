import { copyFileSync, existsSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'fs';
import os from 'os';
import path from 'path';
import { archiveScan, historyDir, historyId, historyParams, readChanges, readIndex, scanCounts } from './history';

const FIXTURES = path.join(__dirname, '..', 'test', 'fixtures');
const labGraph = JSON.parse(readFileSync(path.join(FIXTURES, 'lab.graph.json'), 'utf8'));
const labVulns = JSON.parse(readFileSync(path.join(FIXTURES, 'lab.vulnerabilities.json'), 'utf8'));

function dataDir(withPaths = true) {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'vm-history-'));
  copyFileSync(path.join(FIXTURES, 'lab.graph.json'), path.join(dir, 'graph.json'));
  copyFileSync(path.join(FIXTURES, 'lab.vulnerabilities.json'), path.join(dir, 'vulnerabilities.json'));
  if (withPaths) copyFileSync(path.join(FIXTURES, 'lab.attack_paths.json'), path.join(dir, 'attack_paths.json'));
  return path.join(dir, 'graph.json');
}

const minute = (n: number) => new Date(Date.UTC(2026, 9, 13, 10, n));

describe('scanCounts', () => {
  it('counts the lab scan from its own files', () => {
    const c = scanCounts(labGraph, labVulns);
    expect(c.devices).toBe(labGraph.nodes.filter((n: any) => n.kind === 'device').length);
    expect(c.endpoints).toBe(labGraph.nodes.filter((n: any) => n.kind === 'endpoint').length);
    expect(c.configFindings).toBe(4); // metadata.checklist: 4 medium
    // every host's distinct CVEs land in exactly one of the two
    const perAsset = Object.values(labVulns.hosts).reduce(
      (sum: number, h: any) => sum + new Set((h.findings || []).map((f: any) => f.cve)).size,
      0
    );
    expect(c.cvesConfirmed + c.cvesPotential).toBe(perAsset);
    expect(c.cvesConfirmed).toBeGreaterThan(0);
  });

  it('counts no CVEs without a vulnerabilities file', () => {
    const c = scanCounts(labGraph, null);
    expect(c.cvesConfirmed + c.cvesPotential).toBe(0);
  });
});

describe('archiveScan', () => {
  it('copies the three files and records the summary with the stages', async () => {
    const graphPath = dataDir();
    const entry = await archiveScan(graphPath, 'scheduled', minute(0));
    expect(entry).toMatchObject({ id: '2026-10-13T10-00-00-000Z', trigger: 'scheduled' });
    expect(entry.files).toEqual(['graph.json', 'vulnerabilities.json', 'attack_paths.json']);
    expect(entry.stages).toEqual(labGraph.metadata.stages);
    const dir = path.join(historyDir(graphPath), entry.id);
    expect(readdirSync(dir).sort()).toEqual(['attack_paths.json', 'graph.json', 'vulnerabilities.json']);
    expect(await readIndex(historyDir(graphPath))).toEqual([entry]);
  });

  it('leaves out attack_paths.json when the scan did not write one', async () => {
    const entry = await archiveScan(dataDir(false), 'manual', minute(0));
    expect(entry.files).toEqual(['graph.json', 'vulnerabilities.json']);
  });

  it('keeps the newest 10 and deletes the older folders', async () => {
    const graphPath = dataDir();
    for (let i = 0; i < 12; i++) await archiveScan(graphPath, 'manual', minute(i));
    const index = await readIndex(historyDir(graphPath));
    expect(index.map((e) => e.id)).toEqual(
      Array.from({ length: 10 }, (_, i) => historyId(minute(11 - i)))
    );
    const folders = readdirSync(historyDir(graphPath)).filter((f) => f !== 'index.json');
    expect(folders.sort()).toEqual(index.map((e) => e.id).sort());
    expect(existsSync(path.join(historyDir(graphPath), historyId(minute(0))))).toBe(false);
  });
});

describe('readChanges', () => {
  it('returns the scan and the one before it', async () => {
    const graphPath = dataDir();
    await archiveScan(graphPath, 'manual', minute(0));
    const second = await archiveScan(graphPath, 'scheduled', minute(1));
    const body = await readChanges(graphPath, second.id);
    expect(body!.current.entry.id).toBe(second.id);
    expect(body!.previous!.entry.id).toBe(historyId(minute(0)));
    expect(body!.current.graph.nodes.length).toBe(labGraph.nodes.length);
    expect((await readChanges(graphPath, historyId(minute(0))))!.previous).toBeNull();
  });

  it('answers only for ids in the index', async () => {
    const graphPath = dataDir();
    await archiveScan(graphPath, 'manual', minute(0));
    expect(await readChanges(graphPath, historyId(minute(5)))).toBeNull();
  });

  it('ignores index entries whose id is not a history id', async () => {
    const graphPath = dataDir();
    await archiveScan(graphPath, 'manual', minute(0));
    const file = path.join(historyDir(graphPath), 'index.json');
    const index = JSON.parse(readFileSync(file, 'utf8'));
    writeFileSync(file, JSON.stringify([{ ...index[0], id: '../../etc' }, ...index]));
    expect((await readIndex(historyDir(graphPath))).map((e) => e.id)).toEqual([historyId(minute(0))]);
  });
});

describe('historyParams', () => {
  it('accepts a history id and nothing else', () => {
    expect(historyParams.validate({ id: '2026-10-13T10-30-00-000Z' })).toEqual({ id: '2026-10-13T10-30-00-000Z' });
    for (const id of ['../graph', '..%2Fgraph', '2026-10-13T10:30:00.000Z', 'index.json', '', '2026-10-13T10-30-00-000Z/../x']) {
      expect(() => historyParams.validate({ id })).toThrow();
    }
  });
});
