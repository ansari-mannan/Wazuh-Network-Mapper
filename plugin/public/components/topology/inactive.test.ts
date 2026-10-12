import { GraphNode, LivenessResponse, NodeLiveness } from '../../../common';
import { hiddenKeyOf, isOfflineHost, offlineHosts } from './inactive';

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

describe('offlineHosts', () => {
  it('takes every inactive endpoint, whatever its discovery method', () => {
    const live = liveness({
      'device:sw': 'inactive',
      'endpoint:004': 'inactive',
      'host:aa': 'inactive',
      'host:bb': 'inactive',
      'endpoint:001': 'active',
    });
    expect(offlineHosts(graph, live).map((n) => n.node_id)).toEqual([
      'endpoint:004',
      'host:aa',
      'host:bb',
    ]);
  });

  it('never takes a device, even when it is inactive', () => {
    expect(offlineHosts(graph, liveness({ 'device:sw': 'inactive' }))).toEqual([]);
  });

  it('leaves unknown, active and unchecked endpoints alone', () => {
    const live = liveness({ 'endpoint:004': 'unknown', 'host:aa': 'active' });
    expect(offlineHosts(graph, live)).toEqual([]);
  });
});

describe('isOfflineHost', () => {
  const agent = (status: string) =>
    ({ ...node('endpoint:009', 'endpoint', 'wazuh'), agent_id: '009', status } as GraphNode);
  const off: LivenessResponse = { ...liveness({ 'endpoint:009': 'inactive' }), enabled: false };

  it('takes a disconnected or never-connected Wazuh agent, liveness on or off', () => {
    expect(isOfflineHost(agent('disconnected'), null)).toBe(true);
    expect(isOfflineHost(agent('never_connected'), null)).toBe(true);
    expect(isOfflineHost(agent('active'), null)).toBe(false);
  });

  it('takes a liveness-inactive host only while liveness is on', () => {
    expect(isOfflineHost(agent('active'), liveness({ 'endpoint:009': 'inactive' }))).toBe(true);
    expect(isOfflineHost(agent('active'), off)).toBe(false);
  });

  it('never takes a device, whatever its status', () => {
    const sw = { ...node('device:sw', 'device', 'snmp_lldp'), status: 'disconnected' } as GraphNode;
    expect(isOfflineHost(sw, liveness({ 'device:sw': 'inactive' }))).toBe(false);
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
