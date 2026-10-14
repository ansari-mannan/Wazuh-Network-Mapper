// Scan history: after each successful scan, copies of its three output files
// in history/<id>/ beside the graph, and a summary of each in
// history/index.json (newest first, the last HISTORY_KEEP only). The copies
// hold MACs and serials like the graph itself; no credential is ever in them.
import { promises as fs } from 'fs';
import path from 'path';
import { schema } from '@osd/config-schema';
import { GraphResponse, HistoryEntry, ScanTrigger, VulnerabilitiesDoc } from '../common';
import { writeFileAtomic } from './fsutil';

export const HISTORY_KEEP = 10;
export const ARCHIVED_FILES = ['graph.json', 'vulnerabilities.json', 'attack_paths.json'] as const;
// An id is the scan's finish time made safe for a folder name.
const ID_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-\d{3}Z$/;

// GET /api/vulnmapper/history/{id}/changes's params.
export const historyParams = schema.object({
  id: schema.string({
    maxLength: 32,
    validate: (v) => (ID_PATTERN.test(v) ? undefined : 'not a scan history id'),
  }),
});

export function historyDir(graphPath: string): string {
  return path.join(path.dirname(path.resolve(graphPath)), 'history');
}

export const historyId = (time: Date) => time.toISOString().replace(/[:.]/g, '-');

/** index.json's text as entries; anything unreadable is an empty history. */
export function parseIndex(text: string | null): HistoryEntry[] {
  try {
    const doc = text ? JSON.parse(text) : [];
    return Array.isArray(doc) ? doc.filter((e) => e && typeof e.id === 'string' && ID_PATTERN.test(e.id)) : [];
  } catch {
    return [];
  }
}

export async function readIndex(dir: string): Promise<HistoryEntry[]> {
  try {
    return parseIndex(await fs.readFile(path.join(dir, 'index.json'), 'utf8'));
  } catch {
    return [];
  }
}

/**
 * The counts a history row shows, from the scan's own files: nodes by kind,
 * distinct CVEs per asset summed (confirmed only on a host a Wazuh agent
 * reports from, as in public/lib/report.ts) and configuration findings.
 */
export function scanCounts(graph: GraphResponse, vulns: VulnerabilitiesDoc | null): HistoryEntry['counts'] {
  const counts = { devices: 0, endpoints: 0, cvesConfirmed: 0, cvesPotential: 0, configFindings: 0 };
  for (const node of graph.nodes) {
    if (node.kind === 'device') {
      counts.devices += 1;
      counts.configFindings += (node.config_findings || []).length;
    } else if (node.kind === 'endpoint') {
      counts.endpoints += 1;
    }
    const distinct = new Set((vulns?.hosts[node.node_id]?.findings || []).map((f) => f.cve).filter(Boolean));
    if (node.kind === 'endpoint' && !node.unmanaged) counts.cvesConfirmed += distinct.size;
    else counts.cvesPotential += distinct.size;
  }
  return counts;
}

/** The new index with `entry` first and only the newest `keep`; also the entries dropped. */
export function pruneIndex(index: HistoryEntry[], entry: HistoryEntry, keep = HISTORY_KEEP) {
  const next = [entry, ...index.filter((e) => e.id !== entry.id)];
  return { index: next.slice(0, keep), dropped: next.slice(keep) };
}

let chain: Promise<unknown> = Promise.resolve();

/**
 * Archive the scan whose files are now beside graphPath. Called only after a
 * successful scan; a missing attack_paths.json (stage skipped) is left out.
 * Archives run one after another so the index is never written twice at once.
 */
export function archiveScan(graphPath: string, trigger: ScanTrigger, time = new Date()): Promise<HistoryEntry> {
  const run = async () => {
    const dir = historyDir(graphPath);
    const id = historyId(time);
    const target = path.join(dir, id);
    await fs.mkdir(target, { recursive: true });
    const besideGraph = path.dirname(path.resolve(graphPath));
    const files: string[] = [];
    for (const name of ARCHIVED_FILES) {
      const from = name === 'graph.json' ? graphPath : path.join(besideGraph, name);
      try {
        await fs.copyFile(from, path.join(target, name));
        files.push(name);
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e;
      }
    }
    const graph: GraphResponse = JSON.parse(await fs.readFile(path.join(target, 'graph.json'), 'utf8'));
    const vulns: VulnerabilitiesDoc | null = files.includes('vulnerabilities.json')
      ? JSON.parse(await fs.readFile(path.join(target, 'vulnerabilities.json'), 'utf8'))
      : null;
    const entry: HistoryEntry = {
      id,
      time: time.toISOString(),
      trigger,
      files,
      counts: scanCounts(graph, vulns),
      stages: graph.metadata?.stages || [],
    };
    const { index, dropped } = pruneIndex(await readIndex(dir), entry);
    const file = path.join(dir, 'index.json');
    await writeFileAtomic(file, JSON.stringify(index, null, 2));
    for (const old of dropped) await fs.rm(path.join(dir, old.id), { recursive: true, force: true });
    return entry;
  };
  const next = chain.then(run, run);
  chain = next.catch(() => undefined);
  return next;
}

/**
 * The files of one archived scan and of the scan before it, for the browser's
 * "what changed". The id must be in the index: it is never used as a path
 * until it has been found there, so it cannot reach another folder.
 */
export async function readChanges(graphPath: string, id: string) {
  const dir = historyDir(graphPath);
  const index = await readIndex(dir);
  const at = index.findIndex((e) => e.id === id);
  if (at < 0) return null;
  const load = async (entry: HistoryEntry) => {
    const read = async (name: string) =>
      entry.files.includes(name) ? JSON.parse(await fs.readFile(path.join(dir, entry.id, name), 'utf8')) : null;
    return {
      entry,
      graph: await read('graph.json'),
      vulns: await read('vulnerabilities.json'),
      attackPaths: await read('attack_paths.json'),
    };
  };
  const previous = index[at + 1];
  return { current: await load(index[at]), previous: previous ? await load(previous) : null };
}
