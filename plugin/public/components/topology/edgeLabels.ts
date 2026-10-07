import { GraphEdge } from '../../../common';

// Port labels for a drawn link. A device-to-device (lldp) link carries two
// ports: local_port belongs to the RECORDED source, remote_port to the recorded
// target. The map draws every link from the upper node to the lower one, which
// can be the reverse of the recorded direction, so each port is attached to the
// drawn end that belongs to its own device. A host link (endpoint_link) carries
// only the switch's port and keeps it as one label in the middle.

export type PortLabels = {
  /** port of the drawn source (upper) device, shown near that end */
  sourcePort?: string;
  /** port of the drawn target (lower) device, shown near that end */
  targetPort?: string;
  /** single label in the middle of the link */
  center?: string;
};

export function portLabels(
  e: Pick<GraphEdge, 'type' | 'local_port' | 'remote_port'>,
  flipped: boolean
): PortLabels {
  if (e.type !== 'lldp') return { center: e.local_port || undefined };
  const recordedSource = e.local_port || undefined;
  const recordedTarget = e.remote_port || undefined;
  return flipped
    ? { sourcePort: recordedTarget, targetPort: recordedSource }
    : { sourcePort: recordedSource, targetPort: recordedTarget };
}

// The control-point offset React Flow v10 uses for a bezier edge leaving a
// bottom handle / entering a top handle (default curvature 0.25).
function controlOffset(distance: number, curvature: number): number {
  return distance >= 0 ? 0.5 * distance : curvature * 25 * Math.sqrt(-distance);
}

/**
 * The point at parameter t (0 = source, 1 = target) on the bezier React Flow
 * draws from a source's bottom handle to a target's top handle. Used to put a
 * port label a little way along the link from its own end.
 */
export function pointOnLink(
  sourceX: number,
  sourceY: number,
  targetX: number,
  targetY: number,
  t: number,
  curvature = 0.25
): { x: number; y: number } {
  const c1 = { x: sourceX, y: sourceY + controlOffset(targetY - sourceY, curvature) };
  const c2 = { x: targetX, y: targetY - controlOffset(targetY - sourceY, curvature) };
  const u = 1 - t;
  const a = u * u * u;
  const b = 3 * u * u * t;
  const c = 3 * u * t * t;
  const d = t * t * t;
  return {
    x: a * sourceX + b * c1.x + c * c2.x + d * targetX,
    y: a * sourceY + b * c1.y + c * c2.y + d * targetY,
  };
}
