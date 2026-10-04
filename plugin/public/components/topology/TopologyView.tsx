import React, { CSSProperties, useMemo } from 'react';
import ReactFlow, { Background, Controls, Edge, MarkerType } from 'react-flow-renderer';
import { GraphResponse } from '../../../common';
import { layoutGraph, LayoutEdge } from './layout';
import { CustomNode, TopologyFlowNode } from './CustomNode';

// Ported from frontend/risk-module/ui/topology/TopologyView.tsx (@xyflow/react
// v12 -> react-flow-renderer v10). Renders the dagre-positioned graph with
// distinct edge styles for lldp, endpoint_link (by confidence) and inferred links.
const nodeTypes = { device: CustomNode };

type EdgeStyle = CSSProperties & { stroke: string };

// Edge visual style by relationship type + placement confidence (Issue 6).
export function edgeStyle(e: Pick<LayoutEdge, 'inferred' | 'type' | 'confidence'>): EdgeStyle {
  if (e.inferred) {
    return { stroke: '#f59e0b', strokeWidth: 1.5, strokeDasharray: '6 3', opacity: 0.9 };
  }
  if (e.type === 'endpoint_link') {
    // FDB-confidence links are visually distinct (lighter, finer dash) from the
    // higher-confidence LLDP-confidence ones.
    if (e.confidence === 'fdb') {
      return { stroke: '#94a3b8', strokeWidth: 1.5, strokeDasharray: '3 3', opacity: 0.9 };
    }
    return { stroke: '#64748b', strokeWidth: 1.5, strokeDasharray: '6 3', opacity: 0.9 };
  }
  // lldp (and anything else) -> solid, clearly visible, with a direction arrow.
  return { stroke: '#475569', strokeWidth: 2 };
}

interface TopologyViewProps {
  graph: GraphResponse | null;
  onSelect: (nodeId: string) => void;
}

export function TopologyView({ graph, onSelect }: TopologyViewProps) {
  const { nodes, edges } = useMemo(() => {
    if (!graph) return { nodes: [] as TopologyFlowNode[], edges: [] as Edge[] };

    // layoutGraph is the pure layout-prep module: it computes positions/ranks
    // from the real edges and returns the edges to draw (incl. dashed "inferred"
    // links). We only translate its output into React Flow styling here.
    const { nodes: laidOut, edges: laidEdges } = layoutGraph(graph);
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
        source: e.source,
        target: e.target,
        label: e.inferred ? 'inferred' : e.label,
        style,
        labelStyle: { fontSize: 10, fill: e.inferred ? '#b45309' : '#475569' },
        labelBgStyle: { fill: '#f8fafc', fillOpacity: 0.85 },
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color: style.stroke,
          width: 16,
          height: 16,
        },
      };
    });

    return { nodes: rfNodes, edges: rfEdges };
  }, [graph]);

  if (!graph) {
    return <div className="empty">No graph loaded yet.</div>;
  }
  if (!graph.nodes || graph.nodes.length === 0) {
    return <div className="empty">The graph is empty (0 nodes).</div>;
  }

  return (
    <div className="canvas">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        onNodeClick={(_, n) => onSelect(n.id)}
        fitView
        minZoom={0.15}
        nodesDraggable={false}
        nodesConnectable={false}
      >
        <Background color="#e2e8f0" gap={22} size={1} />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  );
}
