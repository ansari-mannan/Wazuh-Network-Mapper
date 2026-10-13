import { GraphNode, LivenessResponse, NodeLiveness } from '../../../common';
import { isOfflineHost } from './inactive';
import { isOffline } from './nodeStyle';

function node(node_id: string, kind: 'device' | 'endpoint', fields: Partial<GraphNode> = {}): GraphNode {
  return { node_id, kind, discovery_method: 'x', ip: null, hostname: null, ...fields } as GraphNode;
}

function liveness(states: Record<string, NodeLiveness['state']>, enabled = true): LivenessResponse {
  const nodes: Record<string, NodeLiveness> = {};
  for (const [id, state] of Object.entries(states)) nodes[id] = { state, method: 'icmp' };
  return { enabled, intervalSeconds: 10, checkedAt: 'T', nodes, graphMtime: null };
}

describe('isOffline (map dimming)', () => {
  const hosts = [
    node('endpoint:1', 'endpoint', { agent_id: '1', status: 'disconnected' }),
    node('endpoint:2', 'endpoint', { agent_id: '2', status: 'never_connected' }),
    node('endpoint:3', 'endpoint', { agent_id: '3', status: 'active' }),
    node('host:a', 'endpoint', { status: 'discovered' }),
    node('host:b', 'endpoint', { status: 'discovered' }),
  ];
  const live = liveness({ 'endpoint:3': 'inactive', 'host:a': 'active', 'host:b': 'inactive' });

  it('dims a host exactly when the shared offline rule leaves it out', () => {
    for (const l of [null, live, liveness({}, false)]) {
      for (const h of hosts) expect(isOffline(h, l)).toBe(isOfflineHost(h, l));
    }
  });

  it('no longer dims a host only because a switch table found it', () => {
    expect(isOffline(hosts[3], null)).toBe(false);
  });

  it('dims a never-connected agent, which the older rule did not', () => {
    expect(isOffline(hosts[1], null)).toBe(true);
  });

  it('still dims a device that liveness reports inactive, or one only seen in a table', () => {
    expect(isOffline(node('device:a', 'device', { status: 'online' }), liveness({ 'device:a': 'inactive' }))).toBe(true);
    expect(isOffline(node('device:b', 'device', { status: 'discovered' }), null)).toBe(true);
    expect(isOffline(node('device:c', 'device', { status: 'online' }), null)).toBe(false);
  });
});
