import {
  AttackPathsDoc,
  ConfigFinding,
  DeviceNode,
  EndpointNode,
  GraphResponse,
  Tier,
  VulnerabilitiesDoc,
} from '../../common';
import {
  addressRanges,
  buildAssetReports,
  capCves,
  executiveSummary,
  mostCves,
  rankAssetReports,
  remediationActions,
  reportAssets,
  severityBand,
  ALL_FILTERS,
} from './report';

// --- fixtures ---------------------------------------------------------------

const endpoint = (o: Partial<EndpointNode> & { node_id: string }): EndpointNode => ({
  kind: 'endpoint',
  ip: null,
  hostname: null,
  vendor: null,
  model: null,
  firmware: null,
  serial: null,
  mac: null,
  discovery_method: 'wazuh',
  status: 'active',
  risk_score: null,
  discovery_order: 0,
  parent_id: null,
  role: 'host',
  agent_id: '1',
  top_cves: [],
  ...o,
});

const device = (o: Partial<DeviceNode> & { node_id: string }): DeviceNode => ({
  kind: 'device',
  ip: null,
  hostname: null,
  vendor: null,
  model: null,
  firmware: null,
  serial: null,
  mac: null,
  discovery_method: 'snmp',
  status: 'online',
  risk_score: null,
  discovery_order: 0,
  parent_id: null,
  role: 'l2-switch',
  ...o,
});

const telnetFinding: ConfigFinding = {
  id: 'telnet-enabled',
  title: 'Telnet enabled',
  severity: 'high',
  why: 'Telnet sends credentials in clear text.',
  remediation: 'Disable Telnet and use SSH.',
  references: [
    { source: 'DISA', document: 'Cisco IOS Switch L2S STIG', release: null, rule_id: 'V-220630', stig_id: null, srg_id: null, title: 'The switch must not have Telnet enabled.', url: 'https://example.invalid/stig', severity: 'high', category: 'CAT II', cci: null, nist: null, relation: 'requires' },
  ],
  cwe: null,
  evidence: null,
};

// A node's OVSS roll-up as the scanner writes it.
const ovss = (risk_score: number, node_tier: Tier, hist: Partial<Record<Tier | 'Unrated', number>>) => ({
  risk_score,
  node_tier,
  ovss_status: 'assessed' as const,
  ovss_hist: { P0: 0, P1: 0, P2: 0, P3: 0, Unrated: 0, ...hist },
});

const graph: GraphResponse = {
  nodes: [
    endpoint({ node_id: 'endpoint:web', hostname: 'web-01', ip: '10.0.0.10', ...ovss(7.35, 'P0', { P0: 1, P2: 2 }) }),
    endpoint({ node_id: 'endpoint:db', hostname: 'db-01', ip: '10.0.0.11', ...ovss(4.6, 'P1', { P1: 1, P3: 1 }) }),
    // ties db on OVSS and on the histogram; more CVEs ranks it first
    device({ node_id: 'device:sw', hostname: 'sw-01', ip: '10.0.1.1', ...ovss(4.6, 'P1', { P1: 1, P3: 1, Unrated: 1 }), config_findings: [telnetFinding], cve_lookup: { status: 'ok', match: 'cpe', product: 'Cisco IOS 12.2', cpe: null, source: 'nvd', fetched_at: null, stale: false, total: 3 } }),
    endpoint({ node_id: 'endpoint:printer', hostname: 'printer-09', ip: '10.0.0.20', ...ovss(1.5, 'P3', { P3: 1 }), unmanaged: true, agent_id: null, open_ports: [{ port: 9100, protocol: 'tcp', service: 'jetdirect', product: null, version: null }], cve_lookup: { status: 'ok', match: null, product: 'HP', cpe: null, source: 'nmap', fetched_at: null, stale: false, total: 1 } }),
    endpoint({ node_id: 'endpoint:unknown', hostname: 'unknown-5', ip: '10.0.0.30', unmanaged: true, agent_id: null, ovss_status: 'Unassessed', ovss_reason: 'no findings returned' }),
  ],
  edges: [],
  metadata: {},
};

const vulns: VulnerabilitiesDoc = {
  metadata: {},
  cves: {
    'CVE-A': { cvss: 9.8, cvss_version: '3.1', severity: 'Critical', description: 'crit', reference: 'https://x/a' },
    'CVE-B': { cvss: 7.5, cvss_version: '3.1', severity: 'High', description: 'high', reference: null },
    'CVE-C': { cvss: 5.0, cvss_version: '3.1', severity: 'Medium', description: 'med', reference: null },
    'CVE-D': { cvss: 3.0, cvss_version: '3.1', severity: 'Low', description: 'low', reference: null },
    'CVE-E': { cvss: null, cvss_version: null, severity: '', description: 'no score', reference: null },
  },
  hosts: {
    'endpoint:web': { kind: 'endpoint', hostname: 'web-01', agent_id: '1', findings: [
      { cve: 'CVE-A', package: 'openssl', version: '1.1', detected_at: null, score: 7.35, tier: 'P0', kev: true, epss: 0.2, cvss_src: 'CNA', cvss_ver: '3.1', conflict: 0 },
      { cve: 'CVE-A', package: 'openssl', version: '1.1', detected_at: null }, // duplicate -> one distinct
      // a lower CVSS but a higher tier than CVE-B would have: OVSS orders the rows
      { cve: 'CVE-C', package: 'nginx', version: '1.0', detected_at: null, score: 3.1, tier: 'P2' },
      { cve: 'CVE-B', package: 'openssl', version: '1.1', detected_at: null, score: 2.6, tier: 'P2' },
    ] },
    'endpoint:db': { kind: 'endpoint', hostname: 'db-01', agent_id: '1', findings: [
      { cve: 'CVE-B', package: 'postgres', version: '14', detected_at: null },
      { cve: 'CVE-D', package: 'postgres', version: '14', detected_at: null },
    ] },
    'device:sw': { kind: 'device', hostname: 'sw-01', agent_id: null, findings: [
      { cve: 'CVE-B', package: 'Cisco IOS', version: '12.2', detected_at: null },
      { cve: 'CVE-C', package: 'Cisco IOS', version: '12.2', detected_at: null },
      { cve: 'CVE-E', package: 'Cisco IOS', version: '12.2', detected_at: null },
    ] },
    'endpoint:printer': { kind: 'endpoint', hostname: 'printer-09', agent_id: null, findings: [
      { cve: 'CVE-C', package: 'jetdirect', version: null, detected_at: null },
    ] },
    // unknown-5 absent from the file: no findings at all.
  },
};

const attackPaths: AttackPathsDoc = {
  metadata: { state: 'ok' },
  targets: [],
  starting_points: [],
  per_asset: [{ id: 'endpoint:web', kind: 'endpoint', label: 'web-01', dependants: 0, verified: true, routes_through: 2 }],
  not_placed: [],
};

const reports = buildAssetReports(graph, vulns, attackPaths);
const byId = (id: string) => reports.find((r) => r.id === id)!;

// --- tests ------------------------------------------------------------------

describe('severityBand', () => {
  it('uses the CVSS score, falling back to the severity word when unscored', () => {
    expect(severityBand(9.8)).toBe('critical');
    expect(severityBand(7.0)).toBe('high');
    expect(severityBand(4.0)).toBe('medium');
    expect(severityBand(3.9)).toBe('low');
    expect(severityBand(null, 'High')).toBe('high');
    expect(severityBand(null, null)).toBe('unknown');
    expect(severityBand(null, 'bogus')).toBe('unknown');
  });
});

describe('confirmed vs potential counts', () => {
  it('counts a managed host as confirmed and a device/unmanaged host as potential', () => {
    expect(byId('endpoint:web').counts.confirmed).toEqual({ critical: 1, high: 1, medium: 1, low: 0, unknown: 0 });
    expect(byId('endpoint:web').counts.potential).toEqual({ critical: 0, high: 0, medium: 0, low: 0, unknown: 0 });
    expect(byId('endpoint:web').counts.total).toBe(3); // the duplicate CVE-A is one distinct
    // device: potential, and CVE-E (no score) lands in unknown
    expect(byId('device:sw').counts.potential).toEqual({ critical: 0, high: 1, medium: 1, low: 0, unknown: 1 });
    expect(byId('device:sw').counts.confirmed.high).toBe(0);
    expect(byId('endpoint:printer').counts.potential.medium).toBe(1);
  });
});

describe('ranking', () => {
  it('orders worst-first: node OVSS, then the tier histogram, then total, then name', () => {
    // web (7.35) > sw (4.6, 3 cves) > db (4.6, 2 cves) > printer (1.5) > unknown (Unassessed)
    expect(rankAssetReports(reports).map((r) => r.id)).toEqual([
      'endpoint:web',
      'device:sw',
      'endpoint:db',
      'endpoint:printer',
      'endpoint:unknown',
    ]);
  });
});

describe('ranking by tier histogram', () => {
  it('breaks an OVSS tie on more P0, then more P1', () => {
    const a = { ...byId('endpoint:db'), name: 'a', tiers: { P0: 0, P1: 2, P2: 0, P3: 0, Unrated: 0 } };
    const b = { ...byId('endpoint:db'), name: 'b', tiers: { P0: 0, P1: 1, P2: 5, P3: 0, Unrated: 0 } };
    expect(rankAssetReports([b, a]).map((r) => r.name)).toEqual(['a', 'b']);
  });
});

describe('OVSS on CVE rows', () => {
  it('carries each finding\'s tier, KEV, EPSS and source, ordered by OVSS then CVSS', () => {
    const web = byId('endpoint:web');
    expect(web.cves.map((c) => c.cve)).toEqual(['CVE-A', 'CVE-C', 'CVE-B']);
    expect(web.cves[0]).toMatchObject({ tier: 'P0', score: 7.35, kev: true, epss: 0.2, cvss_src: 'CNA', cvss_ver: '3.1', conflict: 0 });
    expect(web.ovss).toBe(7.35);
    expect(byId('endpoint:unknown').ovss).toBeNull();
    expect(byId('device:sw').level).toBe('P1'); // the tier, not its high config finding
  });
});

describe('filters', () => {
  it('severity filter keeps only chosen bands and recomputes counts', () => {
    const out = reportAssets(reports, { ...ALL_FILTERS, severities: ['critical'] });
    expect(out.map((r) => r.id)).toEqual(['endpoint:web']); // only web has a critical
    expect(out[0].cves.map((c) => c.cve)).toEqual(['CVE-A']);
    expect(out[0].counts.total).toBe(1);
  });

  it('confidence filter keeps only confirmed or only potential', () => {
    const confirmed = reportAssets(reports, { ...ALL_FILTERS, confidence: 'confirmed' }).map((r) => r.id);
    expect(confirmed).toEqual(['endpoint:web', 'endpoint:db']); // the two managed hosts
    const potential = reportAssets(reports, { ...ALL_FILTERS, confidence: 'potential' }).map((r) => r.id);
    expect(potential).toEqual(['device:sw', 'endpoint:printer']);
  });

  it('on-path filter keeps only assets a route passes through', () => {
    expect(reportAssets(reports, { ...ALL_FILTERS, onPath: true }).map((r) => r.id)).toEqual(['endpoint:web']);
  });

  it('with no narrowing filter an asset with no CVEs still appears', () => {
    expect(reportAssets(reports, ALL_FILTERS).map((r) => r.id)).toContain('endpoint:unknown');
  });
});

describe('capCves', () => {
  it('shows the worst N and reports the full total', () => {
    const { shown, total, capped } = capCves(byId('endpoint:web').cves, 2);
    expect(total).toBe(3);
    expect(capped).toBe(true);
    expect(shown.map((c) => c.cve)).toEqual(['CVE-A', 'CVE-C']); // worst two by OVSS
    expect(capCves(byId('endpoint:db').cves, 2).capped).toBe(false);
  });
});

describe('remediationActions', () => {
  it('uses a configuration finding’s stored text verbatim with its category', () => {
    const sw = remediationActions(byId('device:sw'));
    const cfg = sw.find((a) => a.source === 'config')!;
    expect(cfg.text).toBe('Disable Telnet and use SSH.');
    expect(cfg.category).toBe('CAT II');
    expect(cfg.reference?.url).toBe('https://example.invalid/stig');
  });

  it('gives the firmware line for a device, never an invented fix', () => {
    const cve = remediationActions(byId('device:sw')).find((a) => a.source === 'cve')!;
    expect(cve.text).toContain("apply the vendor's latest firmware");
    expect(cve.text).toContain('not confirmed on the device');
  });

  it('gives the OS/package line for a managed host, naming the worst packages', () => {
    const cve = remediationActions(byId('endpoint:web')).find((a) => a.source === 'cve')!;
    expect(cve.text).toBe('Apply operating-system and package updates. 3 findings affect openssl and nginx.');
  });

  it('gives the service line for an nmap-found service', () => {
    const cve = remediationActions(byId('endpoint:printer')).find((a) => a.source === 'cve')!;
    expect(cve.text).toBe('Verify the service and update it; detected by version only.');
  });

  it('tells an unmanaged host to deploy an agent', () => {
    const texts = remediationActions(byId('endpoint:unknown')).map((a) => a.text);
    expect(texts).toEqual(['Deploy a Wazuh agent or document this asset; its software and vulnerabilities are otherwise unknown.']);
  });

  it('notes an attack path last', () => {
    const web = remediationActions(byId('endpoint:web'));
    expect(web[web.length - 1]).toMatchObject({ source: 'path', text: 'This asset lies on 2 exposure paths; addressing the above reduces them.' });
  });
});

describe('executiveSummary', () => {
  it('reports coverage, the severity split, the on-path count and the worst assets', () => {
    const s = executiveSummary(reports);
    expect(s.totalAssets).toBe(5);
    expect(s.managed).toBe(2); // web, db
    expect(s.totalHosts).toBe(4); // the four endpoints (the switch is not a host)
    expect(s.counts.confirmed).toEqual({ critical: 1, high: 2, medium: 1, low: 1, unknown: 0 });
    expect(s.counts.potential).toEqual({ critical: 0, high: 1, medium: 2, low: 0, unknown: 1 });
    expect(s.onPathAssets).toBe(1);
    expect(s.tiers).toEqual({ P0: 1, P1: 2, P2: 2, P3: 3, Unrated: 1 });
    expect(s.worstAssets[0]).toBe('web-01');
  });
});

describe('mostCves', () => {
  it('orders the bars by CVE count, most first, whatever the risk rank', () => {
    const many = { ...byId('endpoint:db'), name: 'Mannan-PC', counts: { ...byId('endpoint:db').counts, total: 1574 } };
    const few = { ...byId('endpoint:web'), name: 'CYFOR-3', counts: { ...byId('endpoint:web').counts, total: 302 } };
    // web outranks db on OVSS (7.35 vs 4.6); the chart still puts the 1,574 first
    expect(rankAssetReports([many, few])[0].name).toBe('CYFOR-3');
    expect(mostCves([few, many]).map((r) => r.name)).toEqual(['Mannan-PC', 'CYFOR-3']);
  });
  it('leaves out assets with no CVEs and keeps at most the limit', () => {
    expect(mostCves(reports).map((r) => r.id)).not.toContain('endpoint:unknown');
    expect(mostCves(reports, 2)).toHaveLength(2);
  });
});

describe('offline hosts', () => {
  const offline = new Set(['endpoint:web']);
  const without = buildAssetReports(graph, vulns, attackPaths, offline);
  it('are left out of the rows, the ranking and the summary counts', () => {
    expect(without.map((r) => r.id)).not.toContain('endpoint:web');
    const s = executiveSummary(without);
    expect(s.totalAssets).toBe(4);
    expect(s.managed).toBe(1); // db only
    expect(s.totalHosts).toBe(3);
    expect(s.counts.confirmed.critical).toBe(0); // web's CVE-A is gone
    expect(s.worstAssets).not.toContain('web-01');
  });
});

describe('addressRanges', () => {
  it('lists the distinct /24s seen', () => {
    expect(addressRanges(graph)).toEqual(['10.0.0.0/24', '10.0.1.0/24']);
  });
});
