import React from 'react';
import { Handle, Position, Node, NodeProps } from 'react-flow-renderer';
import { GraphNode } from '../../../common';
import { iconForRole } from './icons';
import { isOffline, riskBorder, riskLabel, statusDot } from './nodeStyle';
import { nodeRiskScore } from '../../lib/risk';
import { useLiveness } from '../../lib/liveness';

// A React Flow node whose `data` payload is a real graph node.
export type TopologyFlowNode = Node<GraphNode>;

// One graph node. Two INDEPENDENT visual channels:
//   * the corner dot  -> LIVENESS (statusDot): green up / grey unconfirmed / red down
//   * the node border -> RISK     (riskBorder): thicker + redder = more critical
// A stale endpoint (duplicate IP of a live host) is dimmed. Offline nodes keep
// the dashed/dim treatment too.
// Ported from frontend/risk-module/ui/topology/CustomNode.tsx
// (@xyflow/react v12 -> react-flow-renderer v10).
export function CustomNode({ data }: NodeProps<GraphNode>) {
  const { liveness: livenessContext } = useLiveness();
  const liveness = livenessContext?.nodes?.[data.node_id];
  const Icon = iconForRole(data.role);
  const dot = statusDot(data.status, liveness);
  const risk = nodeRiskScore(data);
  const border = riskBorder(risk);
  const dimmed = data.stale || isOffline(data.status, liveness);
  const label = data.hostname || data.ip || data.node_id;

  return (
    <div
      className={`node ${dimmed ? 'node--offline' : ''}`}
      style={{
        borderColor: border.color,
        borderWidth: border.width,
        opacity: data.stale ? 0.55 : undefined,
      }}
      title={`${label} · ${data.status || '?'} · risk ${riskLabel(risk)}`}
    >
      <Handle type="target" position={Position.Top} className="handle" />
      <span className="node__dot" style={{ background: dot }} />
      <Icon className="node__icon" size={26} strokeWidth={1.5} />
      <div className="node__label">{label}</div>
      {data.role && <div className="node__role">{data.role}</div>}
      <Handle type="source" position={Position.Bottom} className="handle" />
    </div>
  );
}
