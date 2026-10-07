import { GraphNode, GraphResponse, LivenessResponse } from '../../../common';

// Hosts that leave the canvas while "Hide inactive hosts" is on: every
// endpoint liveness reports inactive, whatever found it (Wazuh agent, switch
// table, LLDP). Devices never leave: removing a switch would orphan everything
// that hangs off it, so an inactive device stays on the canvas, dimmed.
export function inactiveHosts(
  graph: Pick<GraphResponse, 'nodes'>,
  liveness: LivenessResponse
): GraphNode[] {
  return graph.nodes.filter(
    (n) => n.kind === 'endpoint' && liveness.nodes[n.node_id]?.state === 'inactive'
  );
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
