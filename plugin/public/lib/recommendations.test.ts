import {
  AttackPathsDoc,
  ConfigFinding,
  DeviceNode,
  EndpointNode,
  GraphResponse,
  RecommendationsFile,
  VulnerabilitiesDoc,
} from '../../common';
import { buildRecommendations, recommendationProgress } from './recommendations';

// --- fixtures ---------------------------------------------------------------

const endpoint = (o: Partial<EndpointNode> & { node_id: string }): EndpointNode => ({
  kind: 'endpoint', ip: null, hostname: null, vendor: null, model: null, firmware: null, serial: null,
  mac: null, discovery_method: 'wazuh', status: 'active', risk_score: null, discovery_order: 0,
  parent_id: null, role: 'host', agent_id: '1', top_cves: [], ...o,
});

const device = (o: Partial<DeviceNode> & { node_id: string }): DeviceNode => ({
  kind: 'device', ip: null, hostname: null, vendor: null, model: null, firmware: null, serial: null,
  mac: null, discovery_method: 'snmp', status: 'online', risk_score: null, discovery_order: 0,
  parent_id: null, role: 'l2-switch', ...o,
});

const finding = (id: string, title: string): ConfigFinding => ({
  id, title, severity: 'high', why: 'why', remediation: `Fix ${title}.`,
  references: [{ source: 'DISA', document: 'STIG', release: null, rule_id: 'V-1', stig_id: null, srg_id: null, title: 'Rule', url: 'https://x/stig', severity: 'high', category: 'CAT II', cci: null, nist: null, relation: 'requires' }],
  cwe: null, evidence: null,
});

const telnet = finding('telnet-enabled', 'Telnet');
const weakpw = finding('weak-password', 'Weak password');
const badsnmp = finding('bad-snmp', 'Default community');

// telnet on 3 devices; weakpw on 2 (one on-path); badsnmp on 2 (none on-path);
// one managed endpoint with a critical CVE; one unmanaged endpoint (coverage).
const graph: GraphResponse = {
  nodes: [
    device({ node_id: 'sw1', hostname: 'sw1', config_findings: [telnet] }),
    device({ node_id: 'sw2', hostname: 'sw2', config_findings: [telnet] }),
    device({ node_id: 'sw3', hostname: 'sw3', config_findings: [telnet] }),
    device({ node_id: 'sw4', hostname: 'sw4', config_findings: [weakpw] }),
    device({ node_id: 'sw5', hostname: 'sw5', config_findings: [weakpw] }),
    device({ node_id: 'sw6', hostname: 'sw6', config_findings: [badsnmp] }),
    device({ node_id: 'sw7', hostname: 'sw7', config_findings: [badsnmp] }),
    endpoint({ node_id: 'web', hostname: 'web', agent_id: '1' }),
    endpoint({ node_id: 'printer', hostname: 'printer', unmanaged: true, agent_id: null }),
  ],
  edges: [],
  metadata: {},
};

const vulns: VulnerabilitiesDoc = {
  metadata: {},
  cves: { 'CVE-A': { cvss: 9.8, cvss_version: '3.1', severity: 'Critical', description: null, reference: null } },
  hosts: { web: { kind: 'endpoint', hostname: 'web', agent_id: '1', findings: [{ cve: 'CVE-A', package: 'openssl', version: '1', detected_at: null }] } },
};

const attackPaths: AttackPathsDoc = {
  metadata: { state: 'ok' }, targets: [], starting_points: [],
  per_asset: [{ id: 'sw4', kind: 'device', label: 'sw4', dependants: 0, verified: true, routes_through: 1 }],
  not_placed: [],
};

const build = (file: RecommendationsFile | null = null) => buildRecommendations(graph, vulns, attackPaths, file);
const byKey = (key: string) => build().find((r) => r.key === key)!;

// --- tests ------------------------------------------------------------------

describe('buildRecommendations', () => {
  it('deduplicates a config finding across devices into one item listing all affected assets', () => {
    const rec = byKey('config:telnet-enabled');
    expect(rec.affectedCount).toBe(3);
    expect(rec.affected.map((a) => a.id).sort()).toEqual(['sw1', 'sw2', 'sw3']);
    expect(rec.action).toBe('Fix Telnet.'); // the stored remediation text, verbatim
    expect(rec.category).toBe('CAT II');
  });

  it('ranks worst-first: critical before high, then more affected, then more on-path', () => {
    expect(build().map((r) => r.key)).toEqual([
      'cve:os-updates',       // critical
      'config:telnet-enabled', // high, 3 affected
      'config:weak-password',  // high, 2 affected, 1 on-path
      'config:bad-snmp',       // high, 2 affected, 0 on-path
      'coverage:agents',       // advisory (null), last
    ]);
  });

  it('does not count offline hosts as affected assets', () => {
    const keys = buildRecommendations(graph, vulns, attackPaths, null, new Set(['web', 'printer'])).map((r) => r.key);
    expect(keys).not.toContain('cve:os-updates');
    expect(keys).not.toContain('coverage:agents');
  });

  it('uses the finding id for a stable key', () => {
    expect(byKey('config:telnet-enabled').key).toBe('config:telnet-enabled');
  });

  it('sets the worst CVE severity on the OS-updates bucket', () => {
    expect(byKey('cve:os-updates').severity).toBe('critical');
    expect(byKey('cve:os-updates').action).toBe('Apply operating-system and package updates.');
  });

  it('overlays a statuses file, ignores a stale key, and defaults absent keys to open', () => {
    const file: RecommendationsFile = {
      statuses: {
        'config:telnet-enabled': { status: 'done', updated: 'now' },
        'config:gone': { status: 'accepted_risk', updated: 'now' }, // not in the current set
      },
    };
    const recs = build(file);
    expect(recs.find((r) => r.key === 'config:telnet-enabled')!.status).toBe('done');
    expect(recs.find((r) => r.key === 'coverage:agents')!.status).toBe('open'); // absent → open
    expect(recs.some((r) => r.key === 'config:gone')).toBe(false); // stale key ignored
  });
});

describe('recommendationProgress', () => {
  it('counts done and accepted_risk as addressed', () => {
    const file: RecommendationsFile = {
      statuses: {
        'config:telnet-enabled': { status: 'done', updated: 'now' },
        'config:weak-password': { status: 'accepted_risk', updated: 'now' },
        'config:bad-snmp': { status: 'in_progress', updated: 'now' },
      },
    };
    const p = recommendationProgress(build(file));
    expect(p.total).toBe(5);
    expect(p.addressed).toBe(2);
    expect(p.byStatus.in_progress).toBe(1);
    expect(p.byStatus.open).toBe(2);
  });
});
