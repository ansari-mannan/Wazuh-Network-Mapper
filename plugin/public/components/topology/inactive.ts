import { GraphNode, GraphResponse, LivenessResponse } from '../../../common';

// Wazuh agent states that mean the host is not there (the Manager API's words).
const AGENT_OFFLINE = new Set(['disconnected', 'never_connected']);

/**
 * The one rule for an offline host, used by the map, the vulnerability report
 * and the recommendations: an endpoint whose Wazuh agent is disconnected or
 * never connected, or (when liveness is on) that liveness reports inactive,
 * whatever found it. Devices are never offline here: removing a switch would
 * orphan everything that hangs off it, so an inactive device stays, dimmed.
 */
export function isOfflineHost(
  node: GraphNode,
  liveness: LivenessResponse | null | undefined
): boolean {
  if (node.kind !== 'endpoint') return false;
  if (node.agent_id && AGENT_OFFLINE.has((node.status || '').toLowerCase())) return true;
  return Boolean(liveness?.enabled) && liveness?.nodes[node.node_id]?.state === 'inactive';
}

export function offlineHosts(
  graph: Pick<GraphResponse, 'nodes'>,
  liveness: LivenessResponse | null | undefined
): GraphNode[] {
  return graph.nodes.filter((n) => isOfflineHost(n, liveness));
}

/**
 * The detail panel's node once `hidden` leaves the map ("Hide inactive hosts"
 * on): a hidden host's panel closes, any other stays open.
 */
export function visibleSelection(selectedId: string | null, hidden: GraphNode[]): string | null {
  return selectedId && hidden.some((n) => n.node_id === selectedId) ? null : selectedId;
}

/**
 * The hidden set as a string (sorted node_ids, one per line). The canvas
 * re-lays out only when this changes, not on every liveness poll.
 */
export function hiddenKeyOf(hidden: GraphNode[]): string {
  return hidden
    .map((n) => n.node_id)
    .sort()
    .join('\n');
}
