import React from 'react';
import { EuiBadge } from '@elastic/eui';
import { Handle, Position, Node, NodeProps } from 'react-flow-renderer';
import { GraphNode } from '../../../common';
import { iconForRole } from './icons';
import { isOffline, riskBorderForLevel, riskLabel, statusDot } from './nodeStyle';
import { displayRiskLevel, nodeRiskScore, RISK_META } from '../../lib/risk';
import { findingsBadge, findingsBadgeText } from '../../lib/findingsBadge';
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
  const findings = findingsBadge(data);
  // At-a-glance colour = worse of the CVE band and the worst config finding, so a
  // device with no CVE score but a high finding is not shown grey (see displayRiskLevel).
  const border = riskBorderForLevel(displayRiskLevel(risk, findings?.severity ?? null));
  const dimmed = data.stale || isOffline(data.status, liveness);
  const label = data.hostname || data.ip || data.node_id;

  return (
    // The unmanaged label sits beside the node, not in it, so an offline node's
    // dimming does not fade it.
    <div className="nodeWrap">
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
        {findings && (
          <span className="node__findings" title={`${findingsBadgeText(findings)}-severity configuration finding(s)`}>
            <EuiBadge color={RISK_META[findings.severity].color}>{findingsBadgeText(findings)}</EuiBadge>
          </span>
        )}
        <Handle type="source" position={Position.Bottom} className="handle" />
      </div>
      {data.unmanaged && (
        <span className="node__badge" title="No Wazuh agent reports from this machine">
          Unmanaged
        </span>
      )}
    </div>
  );
}
