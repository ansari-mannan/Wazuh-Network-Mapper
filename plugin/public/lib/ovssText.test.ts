import { conflictText, cvssSourceText, epssText, exposureText, ovssLine, threatFeedWarning, tierReason } from './ovssText';

describe('ovssLine', () => {
  it('names the tier and score of an assessed node', () => {
    expect(ovssLine({ risk_score: 6.125, node_tier: 'P1', ovss_status: 'assessed' })).toBe('P1 · OVSS 6.125');
  });

  it('says why a node has no score, and that Unassessed is not clean', () => {
    expect(ovssLine({ risk_score: null, ovss_status: 'Unrated' })).toMatch(/^Unrated/);
    expect(ovssLine({ risk_score: null, ovss_status: 'Unassessed', ovss_reason: 'cpe match returned 0 CVEs' })).toBe(
      'Unassessed: cpe match returned 0 CVEs'
    );
    expect(ovssLine({ risk_score: 7.6 })).toMatch(/before OVSS/);
  });
});

describe('finding details', () => {
  it('formats EPSS as a percentage', () => {
    expect(epssText(0.271)).toBe('EPSS 27.1%');
    expect(epssText(undefined)).toBe('EPSS 0%');
  });

  it('names the CVSS source and version', () => {
    expect(cvssSourceText({ cvss_src: 'CNA', cvss_ver: '3.1' })).toBe('CNA · v3.1');
    expect(cvssSourceText({ cvss_src: 'tool', cvss_ver: '2.0' })).toBe('scanner · v2.0');
    expect(cvssSourceText({ cvss_src: null })).toBe('');
  });

  it('explains a conflict only when flagged', () => {
    expect(conflictText({ conflict: 1, cvss_src: 'CNA', cvss_used: 7.5, cvss_tool: 9.1 })).toMatch(/CNA score \(7.5\)/);
    expect(conflictText({ conflict: 0 })).toBe('');
  });

  it('describes exposure', () => {
    expect(exposureText(1.0, null)).toBe('Egress device (1)');
    expect(exposureText(0.3, null)).toBe('Isolated VLAN (0.3)');
    expect(exposureText(0.5, null)).toBe('Internal (0.5)');
    expect(exposureText(0.5, 'exposure_unknown')).toBe('Unknown placement (0.5)');
  });
});

describe('threatFeedWarning', () => {
  it('warns when either feed was unavailable', () => {
    const feeds = { kev: 'fresh', epss: 'unavailable', kev_date: null, epss_date: null } as const;
    expect(threatFeedWarning(feeds)).toMatch(/^Threat data \(KEV\/EPSS\) unavailable/);
    expect(threatFeedWarning({ ...feeds, epss: 'stale' })).toBe('');
    expect(threatFeedWarning(undefined)).toBe('');
  });
});

describe('tierReason', () => {
  it('names the KEV finding that drives a P0', () => {
    const r = tierReason('P0', [
      { cve: 'CVE-2020-1', score: 5.1, tier: 'P1', kev: false, confidence: 'confirmed' },
      { cve: 'CVE-2017-6736', score: 8.575, tier: 'P0', kev: true, confidence: 'potential' },
    ]);
    expect(r).toEqual({ line: 'P0 · 8.575 · driven by CVE-2017-6736 (CISA KEV)', rule: 'Score 8.575: P0 at 6.75 and above' });
  });

  it('shows both CVEs when the score and the tier come from different ones', () => {
    const r = tierReason('P0', [
      { cve: 'CVE-A', score: 6.0, tier: 'P0', kev: true, exposure: 1, confidence: 'potential' },
      { cve: 'CVE-B', score: 6.5, tier: 'P1', kev: false, exposure: 1, confidence: 'potential' },
    ]);
    expect(r).toEqual({
      line: 'Highest score 6.5 (CVE-B); tier P0 from CVE-A (CISA KEV)',
      rule: 'Known exploited on the internet edge',
    });
  });

  it('says a potential finding was capped at P1', () => {
    const r = tierReason('P1', [{ cve: 'CVE-C', score: 7.2, tier: 'P1', kev: false, confidence: 'potential' }]);
    expect(r).toEqual({ line: 'P1 · 7.2 · driven by CVE-C', rule: 'Potential finding, capped at P1' });
  });

  it('explains a confirmed finding by its score band, and KEV lifting a low score', () => {
    expect(tierReason('P2', [{ cve: 'CVE-D', score: 3, tier: 'P2', confidence: 'confirmed' }])).toEqual({
      line: 'P2 · 3 · driven by CVE-D',
      rule: 'Score 3: P2 at 2.5 and above',
    });
    expect(tierReason('P1', [{ cve: 'CVE-E', score: 2, tier: 'P1', kev: true, confidence: 'confirmed' }])?.rule).toBe(
      'Known exploited (CISA KEV)'
    );
  });

  it('is null without a tier or a finding that carries it', () => {
    expect(tierReason(null, [{ cve: 'CVE-F', score: 3, tier: 'P2' }])).toBeNull();
    expect(tierReason('P0', [{ cve: 'CVE-F', score: 3, tier: 'P2' }])).toBeNull();
    expect(tierReason('P0', undefined)).toBeNull();
  });
});
