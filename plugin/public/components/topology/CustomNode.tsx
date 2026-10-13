// How one node is drawn on the map: icon, risk border, liveness dot, findings
// badge, dimmed when offline.
import React from 'react';
import { EuiBadge } from '@elastic/eui';
import { Handle, Position, Node, NodeProps } from 'react-flow-renderer';
import { GraphNode } from '../../../common';
import { iconForRole } from './icons';
import { borderForLevel, isOffline, statusDot } from './nodeStyle';
import { nodeLevel, RISK_META, TIER_META } from '../../lib/risk';
import { ovssLine } from '../../lib/ovssText';
import { findingsBadge, findingsBadgeText } from '../../lib/findingsBadge';
import { roleLabel } from '../../lib/roleLabel';
import { RouteMark } from './highlight';
import { useLiveness } from '../../lib/liveness';

// A React Flow node whose `data` payload is a real graph node, plus its place
// on the route being shown (Attack paths "Show on map").
export type TopologyNodeData = GraphNode & { route?: RouteMark };
export type TopologyFlowNode = Node<TopologyNodeData>;

// One graph node. Two INDEPENDENT visual channels:
//   * the corner dot  -> LIVENESS (statusDot): green up / grey unconfirmed / red down
//   * the node border -> RISK     (borderForLevel): the OVSS tier, thicker + redder
//                        = more urgent; the tier also rides as a badge
// A stale endpoint (duplicate IP of a live host) is dimmed. Offline nodes keep
// the dashed/dim treatment too.
export function CustomNode({ data }: NodeProps<TopologyNodeData>) {
  const { liveness: livenessContext } = useLiveness();
  const liveness = livenessContext?.nodes?.[data.node_id];
  const Icon = iconForRole(data.role);
  const dot = statusDot(data.status, liveness);
  const findings = findingsBadge(data);
  // At-a-glance colour = the more severe of the OVSS tier and the worst config
  // finding, so a calm tier never hides a high finding (see nodeLevel).
  const border = borderForLevel(nodeLevel(data, findings?.severity ?? null));
  const dimmed = data.stale || isOffline(data, livenessContext);
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
        title={`${label} · ${data.status || '?'} · ${ovssLine(data)}`}
      >
        <Handle type="target" position={Position.Top} className="handle" />
        <span className="node__dot" style={{ background: dot }} />
        <Icon className="node__icon" size={26} strokeWidth={1.5} />
        <div className="node__label">{label}</div>
        {data.role && <div className="node__role">{roleLabel(data.role, data.kind)}</div>}
        {data.node_tier && (
          <span className="node__tier" title={ovssLine(data)}>
            <EuiBadge color={TIER_META[data.node_tier].color}>{data.node_tier}</EuiBadge>
          </span>
        )}
        {findings && (
          <span className="node__findings" title={`${findingsBadgeText(findings)}-severity configuration finding(s)`}>
            <EuiBadge color={RISK_META[findings.severity].color}>{findingsBadgeText(findings)}</EuiBadge>
          </span>
        )}
        <Handle type="source" position={Position.Bottom} className="handle" />
      </div>
      {data.route && (
        <span className="node__step" title={`Step ${data.route.step} of the route`}>
          {data.route.step}
        </span>
      )}
      {data.route?.end && (
        <span className={`node__end node__end--${data.route.end}`}>
          {data.route.end === 'start' ? 'Start' : 'Target'}
        </span>
      )}
      {data.unmanaged && (
        <span className="node__badge" title="No Wazuh agent reports from this machine">
          Unmanaged
        </span>
      )}
    </div>
  );
}
