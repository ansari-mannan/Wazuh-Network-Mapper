import { conflictText, cvssSourceText, epssText, exposureText, ovssLine, threatFeedWarning } from './ovssText';

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
