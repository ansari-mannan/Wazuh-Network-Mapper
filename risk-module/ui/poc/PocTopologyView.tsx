"use client";

import { useMemo } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  MarkerType,
  type Edge,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import type { GraphResponse } from "@/lib/vulnmapperApi";
import { layoutGraph } from "./layout";
import CustomNode, { type PocFlowNode } from "./CustomNode";

// Ported from gui/frontend/src/components/TopologyView.jsx (reactflow ->
// @xyflow/react). Renders the dagre-positioned graph: lldp edges solid grey,
// endpoint_link edges dashed light grey, arrow markers, port labels on edges.
const nodeTypes = { device: CustomNode };

interface PocTopologyViewProps {
  graph: GraphResponse | null;
  onSelect: (nodeId: string) => void;
}

export default function PocTopologyView({ graph, onSelect }: PocTopologyViewProps) {
  const { nodes, edges } = useMemo(() => {
    if (!graph) return { nodes: [] as PocFlowNode[], edges: [] as Edge[] };

    const positioned = layoutGraph(graph.nodes, graph.edges);
    const rfNodes: PocFlowNode[] = positioned.map((p) => ({
      id: p.id,
      type: "device",
      position: { x: p.x, y: p.y },
      data: p.data,
    }));

    // Render the real edges (with their port labels). lldp = solid grey,
    // endpoint_link = dashed (a softer "attached to" relationship).
    const rfEdges: Edge[] = (graph.edges || []).map((e, i) => {
      const isLink = e.type === "endpoint_link";
      return {
        id: `e${i}`,
        source: e.source,
        target: e.target,
        label: e.local_port || undefined,
        style: {
          stroke: isLink ? "#cbd5e1" : "#94a3b8",
          strokeWidth: 1.5,
          strokeDasharray: isLink ? "5 4" : undefined,
        },
        labelStyle: { fontSize: 10, fill: "#64748b" },
        labelBgStyle: { fill: "#f8fafc", fillOpacity: 0.85 },
        markerEnd: { type: MarkerType.ArrowClosed, color: "#94a3b8", width: 16, height: 16 },
      };
    });

    return { nodes: rfNodes, edges: rfEdges };
  }, [graph]);

  if (!graph) {
    return <div className="empty">No graph loaded yet — click “Load Graph”.</div>;
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
        proOptions={{ hideAttribution: true }}
        nodesDraggable={false}
        nodesConnectable={false}
      >
        <Background color="#e2e8f0" gap={22} size={1} />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  );
}
