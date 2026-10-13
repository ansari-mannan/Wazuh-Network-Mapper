import { nodeLevel, riskLevel, tierCounts, tierRank, TierNode } from './riskRule';

describe('riskLevel', () => {
  it('uses the CVSS v3 bands and keeps 0 apart from unscored', () => {
    expect(riskLevel(9.0)).toBe('critical');
    expect(riskLevel(8.9)).toBe('high');
    expect(riskLevel(4.0)).toBe('medium');
    expect(riskLevel(0)).toBe('low');
    expect(riskLevel(null)).toBe('unscored');
  });
});

describe('nodeLevel', () => {
  it('shows the OVSS tier when the node has no more severe finding', () => {
    expect(nodeLevel({ kind: 'device', node_tier: 'P0' }, null)).toBe('P0');
    expect(nodeLevel({ kind: 'device', node_tier: 'P0' }, 'high')).toBe('P0');
    expect(nodeLevel({ kind: 'device', node_tier: 'P1' }, 'high')).toBe('P1'); // equal: the tier
    expect(nodeLevel({ kind: 'device', node_tier: 'P2' }, 'medium')).toBe('P2');
    expect(nodeLevel({ kind: 'device', node_tier: 'P3' }, 'low')).toBe('P3');
  });

  it('raises a tier to a more severe finding (high as P1, medium as P2)', () => {
    expect(nodeLevel({ kind: 'device', node_tier: 'P3' }, 'high')).toBe('high');
    expect(nodeLevel({ kind: 'device', node_tier: 'P2' }, 'high')).toBe('high');
    expect(nodeLevel({ kind: 'device', node_tier: 'P3' }, 'medium')).toBe('medium');
  });

  it('falls back to the worst configuration finding, never grey', () => {
    expect(nodeLevel({ kind: 'device', node_tier: null, ovss_status: 'Unassessed' }, 'high')).toBe('high');
    expect(nodeLevel({ kind: 'device' }, 'medium')).toBe('medium');
  });

  it('is none with neither (an advisory finding has no severity)', () => {
    expect(nodeLevel({ kind: 'endpoint', node_tier: null, ovss_status: 'Unrated' }, null)).toBe('none');
  });
});

describe('tierRank', () => {
  it('orders P0 first and no tier last', () => {
    expect([tierRank('P0'), tierRank('P1'), tierRank('P2'), tierRank('P3'), tierRank(null)]).toEqual([4, 3, 2, 1, 0]);
  });
});

describe('tierCounts', () => {
  it('counts endpoints and devices together and adds up to the total', () => {
    const nodes: TierNode[] = [
      { kind: 'endpoint', node_tier: 'P0', ovss_status: 'assessed' },
      { kind: 'device', node_tier: 'P0', ovss_status: 'assessed' },
      { kind: 'device', node_tier: 'P2', ovss_status: 'assessed' },
      { kind: 'endpoint', node_tier: null, ovss_status: 'Unrated' },
      { kind: 'endpoint', node_tier: null, ovss_status: 'Unassessed' },
      { kind: 'device' }, // a graph written before OVSS
    ];
    const c = tierCounts(nodes);
    expect(c).toEqual({ total: 6, P0: 2, P1: 0, P2: 1, P3: 0, unrated: 1, unassessed: 1, notScored: 1 });
    expect(c.P0 + c.P1 + c.P2 + c.P3 + c.unrated + c.unassessed + c.notScored).toBe(c.total);
  });
});
