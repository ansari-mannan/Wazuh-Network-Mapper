import React from "react";
import { Handle, Position } from "reactflow";
import { iconForRole } from "../icons.jsx";
import { isOffline, riskBorder, riskLabel, statusDot } from "../nodeStyle.js";

// One graph node. Two INDEPENDENT visual channels:
//   * the corner dot  -> LIVENESS (statusDot): green up / grey unconfirmed / red down
//   * the node border -> RISK     (riskBorder): thicker + redder = more critical
// A stale endpoint (duplicate IP of a live host) is dimmed. Offline nodes keep
// the dashed/dim treatment too.
export default function CustomNode({ data }) {
  const Icon = iconForRole(data.role);
  const dot = statusDot(data.status);
  const border = riskBorder(data.risk_score);
  const dimmed = data.stale || isOffline(data.status);
  const label = data.hostname || data.ip || data.node_id;

  return (
    <div
      className={`node ${dimmed ? "node--offline" : ""}`}
      style={{
        borderColor: border.color,
        borderWidth: border.width,
        opacity: data.stale ? 0.55 : undefined,
      }}
      title={`${label} · ${data.status || "?"} · risk ${riskLabel(data.risk_score)}`}
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
