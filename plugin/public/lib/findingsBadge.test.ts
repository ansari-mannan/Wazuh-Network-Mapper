import { GraphNode } from '../../common';
import { findingsBadge, findingsBadgeText } from './findingsBadge';

const device = (over: Partial<GraphNode>): GraphNode => ({ kind: 'device', ...over } as GraphNode);

describe('findingsBadge', () => {
  it('uses the worst severity with its count, from config_summary', () => {
    const node = device({ config_summary: { findings: { high: 2, medium: 3, low: 1, advisory: 4 } } } as Partial<GraphNode>);
    expect(findingsBadge(node)).toEqual({ count: 2, severity: 'high' });
    expect(findingsBadgeText(findingsBadge(node)!)).toBe('2 high');
  });

  it('falls back to counting the findings list when there is no summary', () => {
    const node = device({
      config_findings: [
        { id: 'a', title: 'x', severity: 'medium', why: '', remediation: '', references: [], cwe: null, evidence: null },
        { id: 'b', title: 'y', severity: 'medium', why: '', remediation: '', references: [], cwe: null, evidence: null },
        { id: 'c', title: 'z', severity: null, why: '', remediation: '', references: [], cwe: null, evidence: null },
      ],
    } as Partial<GraphNode>);
    expect(findingsBadge(node)).toEqual({ count: 2, severity: 'medium' });
  });

  it('is null when there are no high/medium/low findings', () => {
    expect(findingsBadge(device({ config_summary: { findings: { high: 0, medium: 0, low: 0, advisory: 5 } } } as Partial<GraphNode>))).toBeNull();
    expect(findingsBadge(device({}))).toBeNull();
  });

  it('is null for an endpoint', () => {
    expect(findingsBadge({ kind: 'endpoint' } as GraphNode)).toBeNull();
  });
});
