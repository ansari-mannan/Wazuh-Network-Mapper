import React, { CSSProperties, forwardRef, useImperativeHandle, useMemo, useRef } from 'react';
import ReactFlow, {
  Background,
  Controls,
  Edge,
  MarkerType,
  NodeChange,
  ReactFlowInstance,
  XYPosition,
  useNodesState,
} from 'react-flow-renderer';
import { GraphResponse } from '../../../common';
import { layoutGraph, LayoutEdge } from './layout';
import { CustomNode, TopologyFlowNode } from './CustomNode';
import { graphColors, themeVars } from '../../lib/theme';

// Ported from frontend/risk-module/ui/topology/TopologyView.tsx (@xyflow/react
// v12 -> react-flow-renderer v10). Renders the dagre-positioned graph with
// distinct edge styles for lldp, endpoint_link (by confidence) and inferred links.
// Differences from the original: nodes are draggable, and every link is drawn
// from the upper node to the lower one (see orientForDrawing).
const nodeTypes = { device: CustomNode };

type EdgeStyle = CSSProperties & { stroke: string };

// Edge visual style by relationship type + placement confidence (Issue 6).
export function edgeStyle(e: Pick<LayoutEdge, 'inferred' | 'type' | 'confidence'>): EdgeStyle {
  if (e.inferred) {
    return { stroke: graphColors.edgeInferred, strokeWidth: 1.5, strokeDasharray: '6 3', opacity: 0.9 };
  }
  if (e.type === 'endpoint_link') {
    // FDB-confidence links are visually distinct (lighter, finer dash) from the
    // higher-confidence LLDP-confidence ones.
    if (e.confidence === 'fdb') {
      return { stroke: graphColors.edgeFdb, strokeWidth: 1.5, strokeDasharray: '3 3', opacity: 0.9 };
    }
    return { stroke: graphColors.edgeEndpoint, strokeWidth: 1.5, strokeDasharray: '6 3', opacity: 0.9 };
  }
  // lldp (and anything else) -> solid, clearly visible, with a direction arrow.
  return { stroke: graphColors.edgeLldp, strokeWidth: 2 };
}

/**
 * The data records links in discovery order (host -> switch, or a switch that
 * happens to be the deeper node -> its neighbour). Drawn as-is, a link whose
 * source sits below its target leaves the bottom handle and loops back up into
 * the top handle. So each link is drawn from the node that is higher in the
 * computed layout (its bottom handle) to the lower one (its top handle). Only
 * the drawing is flipped; the data and the layout ranks are untouched. Links
 * between nodes on the same row keep their recorded direction.
 */
function orientForDrawing(
  e: LayoutEdge,
  layoutY: Map<string, number>
): { source: string; target: string } {
  const ys = layoutY.get(e.source);
  const yt = layoutY.get(e.target);
  if (ys !== undefined && yt !== undefined && ys > yt) {
    return { source: e.target, target: e.source };
  }
  return { source: e.source, target: e.target };
}

// Positions of nodes the user dragged, per loaded graph object. Kept outside the
// component so they survive leaving and re-entering the page; a reload fetches
// a new graph object, so the moved positions are dropped with the old one.
const movedPositions = new WeakMap<GraphResponse, Map<string, XYPosition>>();

export interface TopologyViewHandle {
  /** put every node back on its computed layout position and refit */
  resetLayout: () => void;
}

interface TopologyViewProps {
  graph: GraphResponse;
  onSelect: (nodeId: string | null) => void;
  selectedId: string | null;
}

export const TopologyView = forwardRef<TopologyViewHandle, TopologyViewProps>(
  ({ graph, onSelect, selectedId }, ref) => {
    const { layoutNodes, edges } = useMemo(() => {
      // layoutGraph is the pure layout-prep module: it computes positions/ranks
      // from the real edges and returns the edges to draw (incl. dashed "inferred"
      // links). We only translate its output into React Flow styling here.
      const { nodes: laidOut, edges: laidEdges } = layoutGraph(graph);
      const layoutY = new Map(laidOut.map((n) => [n.id, n.position.y]));
      const rfNodes: TopologyFlowNode[] = laidOut.map((p) => ({
        id: p.id,
        type: p.type,
        position: p.position,
        data: p.data,
      }));

      // Three legible channels (Issue 6):
      //   lldp           -> solid slate, width 2, arrow (confirmed device adjacency)
      //   endpoint_link  -> dashed slate, width 1.5 (a host attached to an access port)
      //     confidence=fdb -> lighter + finer dash (inferred-from-forwarding-table)
      //   inferred       -> dashed amber (tentative, subnet-guessed; not confirmed)
      const rfEdges: Edge[] = laidEdges.map((e) => {
        const style = edgeStyle(e);
        return {
          id: e.id,
          ...orientForDrawing(e, layoutY),
          label: e.inferred ? 'inferred' : e.label,
          style,
          labelStyle: {
            fontSize: 10,
            fill: e.inferred ? graphColors.labelInferred : themeVars.euiTextSubduedColor,
          },
          labelBgStyle: { fill: themeVars.euiColorEmptyShade, fillOpacity: 0.85 },
          markerEnd: {
            type: MarkerType.ArrowClosed,
            color: style.stroke,
            width: 16,
            height: 16,
          },
        };
      });

      return { layoutNodes: rfNodes, edges: rfEdges };
    }, [graph]);

    const moved = useMemo(() => {
      let m = movedPositions.get(graph);
      if (!m) movedPositions.set(graph, (m = new Map()));
      return m;
    }, [graph]);

    const withMoves = (list: TopologyFlowNode[]) =>
      list.map((n) => (moved.has(n.id) ? { ...n, position: moved.get(n.id)! } : n));

    const [nodes, setNodes, onNodesChange] = useNodesState(withMoves(layoutNodes));
    const instance = useRef<ReactFlowInstance | null>(null);

    // A new graph (reload) replaces the nodes outright.
    const lastLayout = useRef(layoutNodes);
    if (lastLayout.current !== layoutNodes) {
      lastLayout.current = layoutNodes;
      setNodes(withMoves(layoutNodes));
    }

    useImperativeHandle(ref, () => ({
      resetLayout: () => {
        moved.clear();
        setNodes(layoutNodes);
        window.requestAnimationFrame(() => instance.current?.fitView());
      },
    }));

    const handleNodesChange = (changes: NodeChange[]) => {
      for (const c of changes) {
        if (c.type === 'position' && c.position) moved.set(c.id, c.position);
      }
      onNodesChange(changes);
    };

    if (!graph.nodes || graph.nodes.length === 0) {
      return <div className="empty">The graph is empty (0 nodes).</div>;
    }

    return (
      <div className="canvas">
        <ReactFlow
          nodes={nodes.map((n) => (n.selected === (n.id === selectedId) ? n : { ...n, selected: n.id === selectedId }))}
          edges={edges}
          nodeTypes={nodeTypes}
          onNodesChange={handleNodesChange}
          onNodeClick={(_, n) => onSelect(n.id)}
          onPaneClick={() => onSelect(null)}
          onInit={(rf) => {
            instance.current = rf;
          }}
          fitView
          minZoom={0.15}
          nodesDraggable
          nodesConnectable={false}
          elementsSelectable
        >
          <Background color={themeVars.euiColorLightShade} gap={22} size={1} />
          <Controls showInteractive={false} />
        </ReactFlow>
      </div>
    );
  }
);
