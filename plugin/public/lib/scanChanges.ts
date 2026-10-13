// What changed between two archived scans (the scan history), computed only
// from their files: assets added, removed, gone offline or back, CVEs newly
// found or no longer present per asset, and risk-band changes.
import { ArchivedScan, GraphNode } from '../../common';
import { isOfflineHost } from '../components/topology/inactive';
import { findingsBadge } from './findingsBadge';
import { displayRiskLevel, nodeRiskScore, RiskLevel } from './riskRule';

export type ChangedAsset = { id: string; name: string; kind: GraphNode['kind'] };
export type CveChange = { asset: ChangedAsset; cves: string[] };

export type ScanChanges = {
  added: ChangedAsset[];
  removed: ChangedAsset[];
  wentOffline: ChangedAsset[];
  backOnline: ChangedAsset[];
  /** null when either scan has no vulnerabilities.json to compare */
  newCves: CveChange[] | null;
  goneCves: CveChange[] | null;
  riskChanged: Array<{ asset: ChangedAsset; from: RiskLevel; to: RiskLevel }>;
};

type Scan = Pick<ArchivedScan, 'graph' | 'vulns' | 'attackPaths'>;

const asset = (n: GraphNode): ChangedAsset => ({ id: n.node_id, name: n.hostname || n.ip || n.node_id, kind: n.kind });

/**
 * The shared offline rule (topology/inactive.ts) on what the archive holds: the
 * Wazuh agent status in the graph, plus the hosts the attack-path engine listed
 * as offline (which include liveness-inactive hosts when it had a fresh pass).
 */
function offlineSet(scan: Scan): Set<string> {
  const out = new Set((scan.attackPaths?.offline_starts || []).map((o) => o.id));
  for (const n of scan.graph.nodes) if (isOfflineHost(n, null)) out.add(n.node_id);
  return out;
}

const displayedRisk = (n: GraphNode) => displayRiskLevel(nodeRiskScore(n), findingsBadge(n)?.severity ?? null);

function cvesOf(scan: Scan, id: string): Set<string> {
  return new Set((scan.vulns?.hosts[id]?.findings || []).map((f) => f.cve).filter(Boolean));
}

/**
 * Changes from `before` to `after`. CVEs and risk are compared only for assets
 * in both scans and online in both: an added or removed asset is listed as
 * such, and an offline host is not assessed (as in the report), so its CVEs
 * are neither "new" nor "fixed".
 */
export function scanChanges(before: Scan, after: Scan): ScanChanges {
  const prev = new Map(before.graph.nodes.map((n) => [n.node_id, n]));
  const next = new Map(after.graph.nodes.map((n) => [n.node_id, n]));
  const offBefore = offlineSet(before);
  const offAfter = offlineSet(after);
  const compareCves = Boolean(before.vulns && after.vulns);

  const out: ScanChanges = {
    added: [],
    removed: [],
    wentOffline: [],
    backOnline: [],
    newCves: compareCves ? [] : null,
    goneCves: compareCves ? [] : null,
    riskChanged: [],
  };
  for (const [id, n] of next) {
    const old = prev.get(id);
    if (!old) {
      out.added.push(asset(n));
      continue;
    }
    if (!offBefore.has(id) && offAfter.has(id)) out.wentOffline.push(asset(n));
    else if (offBefore.has(id) && !offAfter.has(id)) out.backOnline.push(asset(n));
    if (offBefore.has(id) || offAfter.has(id)) continue;
    if (compareCves) {
      const was = cvesOf(before, id);
      const now = cvesOf(after, id);
      const found = [...now].filter((c) => !was.has(c)).sort();
      const gone = [...was].filter((c) => !now.has(c)).sort();
      if (found.length) out.newCves!.push({ asset: asset(n), cves: found });
      if (gone.length) out.goneCves!.push({ asset: asset(n), cves: gone });
    }
    const from = displayedRisk(old);
    const to = displayedRisk(n);
    if (from !== to) out.riskChanged.push({ asset: asset(n), from, to });
  }
  for (const [id, n] of prev) if (!next.has(id)) out.removed.push(asset(n));
  return out;
}

const count = (list: CveChange[] | null) => (list || []).reduce((sum, c) => sum + c.cves.length, 0);
const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? '' : 's'}`;

/** One line for the overview: "+2 hosts, 15 new CVEs, 3 fixed". */
export function changesSummary(c: ScanChanges): string {
  const hosts = (list: ChangedAsset[]) => list.filter((a) => a.kind === 'endpoint').length;
  const devices = (list: ChangedAsset[]) => list.filter((a) => a.kind === 'device').length;
  const parts: string[] = [];
  if (hosts(c.added)) parts.push(`+${plural(hosts(c.added), 'host')}`);
  if (hosts(c.removed)) parts.push(`−${plural(hosts(c.removed), 'host')}`);
  if (devices(c.added)) parts.push(`+${plural(devices(c.added), 'device')}`);
  if (devices(c.removed)) parts.push(`−${plural(devices(c.removed), 'device')}`);
  if (c.wentOffline.length) parts.push(`${c.wentOffline.length} went offline`);
  if (c.backOnline.length) parts.push(`${c.backOnline.length} back online`);
  if (count(c.newCves)) parts.push(`${count(c.newCves)} new CVE${count(c.newCves) === 1 ? '' : 's'}`);
  if (count(c.goneCves)) parts.push(`${count(c.goneCves)} fixed`);
  if (c.riskChanged.length) parts.push(`${plural(c.riskChanged.length, 'risk change')}`);
  return parts.length ? parts.join(', ') : 'no changes';
}
