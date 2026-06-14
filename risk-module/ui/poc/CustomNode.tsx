import { Handle, Position, type NodeProps, type Node } from "@xyflow/react";
import type { GraphNode } from "@/lib/vulnmapperApi";
import { iconForRole } from "./icons";
import { isOffline, riskColor, riskLabel } from "./nodeStyle";

// A React Flow node whose `data` payload is a real graph node.
export type PocFlowNode = Node<GraphNode, "device">;

// One graph node. Risk is a small dot + a thin ring (CSS var --risk), never a
// full-node recolor. Offline nodes get the node--offline modifier (dim + dashed).
// Ported from gui/frontend/src/components/CustomNode.jsx (reactflow -> @xyflow/react).
export default function CustomNode({ data }: NodeProps<PocFlowNode>) {
  const Icon = iconForRole(data.role);
  const color = riskColor(data.risk_score);
  const offline = isOffline(data.status);
  const label = data.hostname || data.ip || data.node_id;

  return (
    <div
      className={`node ${offline ? "node--offline" : ""}`}
      style={{ ["--risk" as string]: color }}
      title={`${label} · risk ${riskLabel(data.risk_score)}`}
    >
      <Handle type="target" position={Position.Top} className="handle" />
      <span className="node__dot" style={{ background: color }} />
      <Icon className="node__icon" size={26} strokeWidth={1.5} />
      <div className="node__label">{label}</div>
      {data.role && <div className="node__role">{data.role}</div>}
      <Handle type="source" position={Position.Bottom} className="handle" />
    </div>
  );
}
