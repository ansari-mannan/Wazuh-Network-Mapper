import dagre from "@dagrejs/dagre";
import type { GraphNode, GraphEdge } from "@/lib/vulnmapperApi";

// React Flow does NOT auto-layout — it renders whatever x/y you hand it. So we
// run dagre over the graph to compute a top-down hierarchy before rendering.
// Ported verbatim from gui/frontend/src/layout.js.
const NODE_W = 184;
const NODE_H = 84;

export type PositionedNode = { id: string; x: number; y: number; data: GraphNode };

/**
 * Compute node positions for a top-down (TB) hierarchy.
 *
 * The hierarchy edges fed to dagre come from `parent_id`, NOT the raw `edges`
 * array: an `endpoint_link` edge points host -> switch, which is the opposite of
 * the parent -> child direction we want for a top-down tree (root = the node with
 * parent_id null, e.g. the L3-Switch). Every node is still added to the graph, so
 * unparented endpoints (parent_id null, no edges) are laid out as their own roots
 * spread across the top rank instead of being stacked at the origin.
 *
 * Returns [{ id, x, y, data }] with x/y as the React Flow top-left corner.
 */
export function layoutGraph(nodes: GraphNode[], _edges: GraphEdge[]): PositionedNode[] {
  const g = new dagre.graphlib.Graph();
  g.setGraph({ rankdir: "TB", nodesep: 64, ranksep: 96, marginx: 48, marginy: 48 });
  g.setDefaultEdgeLabel(() => ({}));

  const ids = new Set(nodes.map((n) => n.node_id));
  for (const n of nodes) {
    g.setNode(n.node_id, { width: NODE_W, height: NODE_H });
  }
  for (const n of nodes) {
    if (n.parent_id && ids.has(n.parent_id)) {
      g.setEdge(n.parent_id, n.node_id); // parent (above) -> child (below)
    }
  }

  dagre.layout(g);

  return nodes.map((n) => {
    const { x, y } = g.node(n.node_id);
    // dagre returns the node centre; React Flow wants the top-left corner.
    return { id: n.node_id, x: x - NODE_W / 2, y: y - NODE_H / 2, data: n };
  });
}

export const NODE_SIZE = { width: NODE_W, height: NODE_H };
