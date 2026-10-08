import { CveLookup, CveLookupStatus } from '../../common';
import { nodeRiskScore, riskCounts, riskLevel, RiskNode } from './riskRule';

const lookup = (status: CveLookupStatus, match: CveLookup['match'] = 'cpe'): CveLookup => ({
  status,
  match,
  product: 'Cisco IOS 12.2(55)SE12',
  cpe: null,
  source: 'nvd',
  fetched_at: '2026-10-09T08:00:06+00:00',
  stale: false,
  total: 0,
});

describe('nodeRiskScore', () => {
  it('uses an endpoint risk score as it is', () => {
    expect(nodeRiskScore({ kind: 'endpoint', risk_score: 7.1 })).toBe(7.1);
    expect(nodeRiskScore({ kind: 'endpoint', risk_score: null })).toBeNull();
    expect(nodeRiskScore({ kind: 'endpoint', risk_score: 0 })).toBe(0);
  });

  it('shows a device score when its lookup is ok, a real 0.0 included', () => {
    expect(nodeRiskScore({ kind: 'device', risk_score: 8.9, cve_lookup: lookup('ok') })).toBe(8.9);
    expect(nodeRiskScore({ kind: 'device', risk_score: 0, cve_lookup: lookup('ok') })).toBe(0);
  });

  it('leaves a keyword lookup with nothing found unscored', () => {
    expect(nodeRiskScore({ kind: 'device', risk_score: null, cve_lookup: lookup('ok', 'keyword') })).toBeNull();
  });

  it('treats every other status as unscored', () => {
    const others: CveLookupStatus[] = ['unidentified', 'unavailable', 'unverified'];
    for (const status of others) {
      expect(nodeRiskScore({ kind: 'device', risk_score: 0, cve_lookup: lookup(status) })).toBeNull();
    }
  });

  it('keeps the old rule for an old graph without cve_lookup', () => {
    // the scanner used to write 0 for every device
    expect(nodeRiskScore({ kind: 'device', risk_score: 0 })).toBeNull();
    expect(nodeRiskScore({ kind: 'device', risk_score: 0, max_cvss: null, top_cves: [] })).toBeNull();
    expect(nodeRiskScore({ kind: 'device', risk_score: 6.5, max_cvss: 7.2 })).toBe(6.5);
    expect(nodeRiskScore({ kind: 'device', risk_score: null, max_cvss: 7.2 })).toBe(7.2);
  });
});

describe('riskLevel', () => {
  it('uses the CVSS v3 bands and keeps 0 apart from unscored', () => {
    expect(riskLevel(9.0)).toBe('critical');
    expect(riskLevel(8.9)).toBe('high');
    expect(riskLevel(4.0)).toBe('medium');
    expect(riskLevel(0)).toBe('low');
    expect(riskLevel(null)).toBe('unscored');
  });
});

describe('riskCounts', () => {
  it('counts endpoints and devices together and adds up to the total', () => {
    const nodes: RiskNode[] = [
      { kind: 'endpoint', risk_score: 9.5 },
      { kind: 'endpoint', risk_score: null },
      { kind: 'device', risk_score: 8.9, cve_lookup: lookup('ok') },
      { kind: 'device', risk_score: 0, cve_lookup: lookup('ok') },
      { kind: 'device', risk_score: null, cve_lookup: lookup('ok', 'keyword') },
      { kind: 'device', risk_score: 0 },
    ];
    const c = riskCounts(nodes);
    expect(c).toEqual({
      total: 6,
      critical: 1,
      high: 1,
      medium: 0,
      low: 1,
      unscored: 3,
      devices: { scored: 2, unscored: 2 },
      endpoints: { scored: 1, unscored: 1 },
    });
    expect(c.critical + c.high + c.medium + c.low + c.unscored).toBe(c.total);
  });
});
