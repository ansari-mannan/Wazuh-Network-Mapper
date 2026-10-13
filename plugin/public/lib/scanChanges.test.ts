import labGraph from '../../test/fixtures/lab.graph.json';
import labVulns from '../../test/fixtures/lab.vulnerabilities.json';
import labPaths from '../../test/fixtures/lab.attack_paths.json';
import { changesSummary, scanChanges } from './scanChanges';

const host = (id: string, extra: Record<string, unknown> = {}) => ({
  node_id: id,
  kind: 'endpoint',
  hostname: id,
  agent_id: '001',
  status: 'active',
  risk_score: 5,
  ...extra,
});
const device = (id: string, extra: Record<string, unknown> = {}) => ({
  node_id: id,
  kind: 'device',
  hostname: id,
  risk_score: 0,
  cve_lookup: { status: 'ok' },
  ...extra,
});
const vulnsFor = (hosts: Record<string, string[]>) => ({
  metadata: {},
  cves: {},
  hosts: Object.fromEntries(
    Object.entries(hosts).map(([id, cves]) => [
      id,
      { kind: 'endpoint', findings: cves.map((cve) => ({ cve, package: null, version: null, detected_at: null })) },
    ])
  ),
});
const scan = (nodes: any[], vulns: any = vulnsFor({}), attackPaths: any = null): any => ({
  graph: { nodes, edges: [], metadata: {} },
  vulns,
  attackPaths,
});

describe('scanChanges', () => {
  it('finds nothing between a scan and itself', () => {
    const lab = scan(labGraph.nodes, labVulns, labPaths);
    const c = scanChanges(lab, lab);
    expect(changesSummary(c)).toBe('no changes');
  });

  it('lists added and removed assets', () => {
    const c = scanChanges(scan([host('a'), device('sw1')]), scan([host('a'), host('b'), device('sw2')]));
    expect(c.added.map((a) => a.id)).toEqual(['b', 'sw2']);
    expect(c.removed.map((a) => a.id)).toEqual(['sw1']);
    expect(changesSummary(c)).toBe('+1 host, +1 device, −1 device');
  });

  it('lists CVEs newly found and no longer present per asset', () => {
    const c = scanChanges(
      scan([host('a'), host('b')], vulnsFor({ a: ['CVE-1', 'CVE-2'], b: ['CVE-9'] })),
      scan([host('a'), host('b')], vulnsFor({ a: ['CVE-2', 'CVE-3', 'CVE-4'], b: ['CVE-9'] }))
    );
    expect(c.newCves).toEqual([{ asset: { id: 'a', name: 'a', kind: 'endpoint' }, cves: ['CVE-3', 'CVE-4'] }]);
    expect(c.goneCves).toEqual([{ asset: { id: 'a', name: 'a', kind: 'endpoint' }, cves: ['CVE-1'] }]);
    expect(changesSummary(c)).toBe('2 new CVEs, 1 fixed');
  });

  it('shows a host whose agent went offline as gone offline, not removed, and its CVEs not as fixed', () => {
    const c = scanChanges(
      scan([host('a')], vulnsFor({ a: ['CVE-1'] })),
      scan([host('a', { status: 'disconnected' })], vulnsFor({}))
    );
    expect(c.wentOffline.map((a) => a.id)).toEqual(['a']);
    expect(c.removed).toEqual([]);
    expect(c.goneCves).toEqual([]);
    expect(changesSummary(c)).toBe('1 went offline');
  });

  it('takes a host the attack-path engine listed offline (liveness) as offline too', () => {
    const offline = { offline_starts: [{ id: 'a', kind: 'managed_host', reason: 'offline', detail: 'x' }] };
    const c = scanChanges(scan([host('a')]), scan([host('a')], vulnsFor({}), offline));
    expect(c.wentOffline.map((a) => a.id)).toEqual(['a']);
    expect(scanChanges(scan([host('a')], vulnsFor({}), offline), scan([host('a')])).backOnline.map((a) => a.id)).toEqual(['a']);
  });

  it('lists risk band changes', () => {
    const c = scanChanges(scan([host('a', { risk_score: 5 })]), scan([host('a', { risk_score: 9.8 })]));
    expect(c.riskChanged).toEqual([{ asset: { id: 'a', name: 'a', kind: 'endpoint' }, from: 'medium', to: 'critical' }]);
  });

  it('does not compare CVEs when a scan has no vulnerabilities file', () => {
    const c = scanChanges(scan([host('a')], null), scan([host('a')], vulnsFor({ a: ['CVE-1'] })));
    expect(c.newCves).toBeNull();
    expect(changesSummary(c)).toBe('no changes');
  });
});
