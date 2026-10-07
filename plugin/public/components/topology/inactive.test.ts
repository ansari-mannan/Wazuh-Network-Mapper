import { GraphNode, LivenessResponse, NodeLiveness } from '../../../common';
import { hiddenKeyOf, inactiveHosts } from './inactive';

function node(node_id: string, kind: 'device' | 'endpoint', discovery_method: string): GraphNode {
  return { node_id, kind, discovery_method, ip: null, hostname: null } as GraphNode;
}

function liveness(states: Record<string, NodeLiveness['state']>): LivenessResponse {
  const nodes: Record<string, NodeLiveness> = {};
  for (const [id, state] of Object.entries(states)) nodes[id] = { state, method: 'icmp' };
  return { enabled: true, intervalSeconds: 10, checkedAt: 'T', nodes, graphMtime: null };
}

const graph = {
  nodes: [
    node('device:sw', 'device', 'snmp_lldp'),
    node('endpoint:004', 'endpoint', 'wazuh'),
    node('host:aa', 'endpoint', 'snmp_fdb'),
    node('host:bb', 'endpoint', 'lldp_host'),
    node('endpoint:001', 'endpoint', 'wazuh'),
  ],
};

describe('inactiveHosts', () => {
  it('takes every inactive endpoint, whatever its discovery method', () => {
    const live = liveness({
      'device:sw': 'inactive',
      'endpoint:004': 'inactive',
      'host:aa': 'inactive',
      'host:bb': 'inactive',
      'endpoint:001': 'active',
    });
    expect(inactiveHosts(graph, live).map((n) => n.node_id)).toEqual([
      'endpoint:004',
      'host:aa',
      'host:bb',
    ]);
  });

  it('never takes a device, even when it is inactive', () => {
    expect(inactiveHosts(graph, liveness({ 'device:sw': 'inactive' }))).toEqual([]);
  });

  it('leaves unknown, active and unchecked endpoints alone', () => {
    const live = liveness({ 'endpoint:004': 'unknown', 'host:aa': 'active' });
    expect(inactiveHosts(graph, live)).toEqual([]);
  });
});

describe('hiddenKeyOf', () => {
  it('is the same for the same set in any order', () => {
    const a = [node('b', 'endpoint', 'wazuh'), node('a', 'endpoint', 'wazuh')];
    const b = [node('a', 'endpoint', 'wazuh'), node('b', 'endpoint', 'wazuh')];
    expect(hiddenKeyOf(a)).toBe(hiddenKeyOf(b));
    expect(hiddenKeyOf(a)).toBe('a\nb');
    expect(hiddenKeyOf([])).toBe('');
  });
});
