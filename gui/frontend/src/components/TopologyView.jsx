import React, { useMemo } from "react";
import ReactFlow, { Background, Controls, MarkerType } from "reactflow";
import { layoutGraph } from "../layout.js";
import CustomNode from "./CustomNode.jsx";

const nodeTypes = { device: CustomNode };

export default function TopologyView({ graph, onSelect }) {
  const { nodes, edges } = useMemo(() => {
    if (!graph) return { nodes: [], edges: [] };

    const positioned = layoutGraph(graph.nodes, graph.edges);
    const rfNodes = positioned.map((p) => ({
      id: p.id,
      type: "device",
      position: { x: p.x, y: p.y },
      data: p.data,
    }));

    // Render the real edges (with their port labels). lldp = solid grey,
    // endpoint_link = dashed (a softer "attached to" relationship).
    const rfEdges = (graph.edges || []).map((e, i) => {
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
