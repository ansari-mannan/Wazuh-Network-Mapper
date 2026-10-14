// A device's front panel as inline SVG, drawn from lib/faceplate's layout:
// sockets with a link LED each, the route ring and the dashed outline of an
// inferred port, a legend, and the logical interfaces folded underneath.
// Colours are CSS classes (faceplate.scss), so they follow the dashboard theme.
import React, { useMemo, useState } from 'react';
import {
  EuiAccordion,
  EuiButtonEmpty,
  EuiHealth,
  EuiModal,
  EuiModalBody,
  EuiModalHeader,
  EuiModalHeaderTitle,
  EuiSpacer,
} from '@elastic/eui';
import { DeviceNode, DevicePort, GraphEdge } from '../../../common';
import {
  COMPACT_ABOVE,
  Faceplate as Layout,
  faceplateOf,
  isInferred,
  Neighbour,
  neighboursOf,
  PlacedPort,
  PORT_H,
  PORT_W,
  portKey,
  portNeighbours,
  portTooltip,
  routePortKeys,
} from '../../lib/faceplate';
import { graphColors } from '../../lib/theme';
import { radioClients } from '../../lib/wireless';

interface PanelProps {
  node: DeviceNode;
  fp: Layout;
  byPort: Map<string, Neighbour[]>;
  routeKeys: Set<string>;
  /** an access point's clients per radio, from its wireless links */
  clients: Map<string, number>;
  compact?: boolean;
  onSelectNode?: (nodeId: string) => void;
}

const onRouteOf = (port: DevicePort, routeKeys: Set<string>) =>
  routeKeys.has(portKey(port.name)) || (!!port.alias && routeKeys.has(portKey(port.alias)));

function Socket({ p, node, byPort, routeKeys, clients, compact, onSelectNode }: Omit<PanelProps, 'fp'> & { p: PlacedPort }) {
  const { port, kind, x, y } = p;
  const neighbours = neighboursOf(port, byPort);
  const inferred = isInferred(port, node);
  const onRoute = onRouteOf(port, routeKeys);
  const count = kind === 'radio' ? clients.get(port.name) ?? 0 : undefined;
  const tip = portTooltip(port, neighbours, { inferred, onRoute, clients: count }).join('\n');
  const target = onSelectNode && neighbours[0]?.nodeId;
  const select = target ? () => onSelectNode!(target) : undefined;
  const w = PORT_W;
  const h = PORT_H;
  return (
    <g
      className={`vmFpPort vmFpPort--${port.state}${select ? ' vmFpPort--link' : ''}`}
      data-port={port.name}
      onClick={select}
      onKeyDown={select && ((e) => (e.key === 'Enter' || e.key === ' ') && select())}
      tabIndex={select ? 0 : undefined}
      role={select ? 'button' : 'img'}
      aria-label={tip.replace(/\n/g, '. ')}
    >
      <title>{tip}</title>
      {onRoute && (
        <rect className="vmFpRoute" x={x - 3} y={y - 3} width={w + 6} height={h + 6} rx={4} fill="none" strokeWidth={2.2} />
      )}
      {kind === 'radio' ? (
        <>
          <line className="vmFpPin" x1={x + w / 2} y1={y + h / 2} x2={x + w / 2} y2={y - 6} strokeWidth={2} />
          <circle className="vmFpLed" cx={x + w / 2} cy={y + h / 2} r={7} />
          <text className="vmFpCount" x={x + w / 2} y={y + h / 2 + 3} fontSize={8} fontWeight={700} textAnchor="middle">
            {count}
          </text>
        </>
      ) : (
        <>
          <rect
            className={`vmFpFace${inferred ? ' vmFpFace--inferred' : ''}`}
            x={x}
            y={y}
            width={w}
            height={h}
            rx={2}
            strokeWidth={inferred ? 1.4 : 1}
            strokeDasharray={inferred ? '3 2' : undefined}
          />
          {kind === 'sfp' ? (
            <rect className="vmFpPin" x={x + 3} y={y + 3} width={w - 6} height={h - 6} rx={1} fill="none" />
          ) : (
            <>
              <rect className="vmFpNotch" x={x + w * 0.3} y={y + h - 4} width={w * 0.4} height={4} />
              {[0, 1, 2, 3, 4, 5].map((i) => (
                <rect key={i} className="vmFpPinFill" x={x + 3 + (i * (w - 6)) / 6} y={y + 2} width={(w - 6) / 6 - 1} height={3} />
              ))}
            </>
          )}
          <rect className="vmFpLed" x={x + 2} y={y + h * 0.45} width={w - 4} height={h * 0.3} rx={1.5} />
        </>
      )}
      {!compact && (
        <text className="vmFpLabel" x={x + w / 2} y={p.labelY} fontSize={7} textAnchor="middle">
          {p.label}
        </text>
      )}
    </g>
  );
}

/** The panel itself: chassis, vendor text (plain, no logo), captions and sockets. */
export function FaceplatePanel({ node, fp, byPort, routeKeys, clients, compact, onSelectNode, width }: PanelProps & { width?: number }) {
  const { chassis, height: H, width: W } = fp;
  const rx = chassis === 'puck' ? H / 2 : chassis === 'desktop' ? 10 : chassis === 'rack' ? 5 : 4;
  const textX = chassis === 'puck' ? 30 : 14;
  return (
    <svg
      className={`vmFaceplate vmFaceplate--${chassis}`}
      viewBox={`0 0 ${W} ${H}`}
      width={width ?? '100%'}
      // a small panel keeps its size rather than filling the card
      style={width ? undefined : { maxWidth: W * 1.6 }}
      role="group"
      aria-label={`${node.hostname || node.ip || node.node_id} front panel`}
      data-test-subj="vmFaceplate"
    >
      <rect className="vmFpChassis" x={1} y={1} width={W - 2} height={H - 2} rx={rx} strokeWidth={2} />
      {chassis === 'rack' && <rect className="vmFpChassisHi" x={1} y={1} width={W - 2} height={6} rx={3} />}
      {node.vendor && (
        <text className="vmFpLabel" x={textX} y={chassis === 'rack' || chassis === 'generic' ? 26 : 30} fontSize={10} fontWeight={700}>
          {node.vendor}
        </text>
      )}
      {node.model && (
        <text className="vmFpLabel" x={textX} y={chassis === 'rack' || chassis === 'generic' ? 40 : 44} fontSize={8}>
          {node.model}
        </text>
      )}
      {!compact &&
        fp.captions.map((c) => (
          <g key={`${c.text}-${c.x}`}>
            <text className="vmFpLabel" x={c.x} y={fp.captionY} fontSize={7.5}>
              {c.text}
            </text>
            <line className="vmFpRule" x1={c.x} y1={fp.captionY + 3} x2={c.x + c.width} y2={fp.captionY + 3} strokeWidth={0.6} />
          </g>
        ))}
      {fp.ports.map((p) => (
        <Socket
          key={p.port.name}
          p={p}
          node={node}
          byPort={byPort}
          routeKeys={routeKeys}
          clients={clients}
          compact={compact}
          onSelectNode={onSelectNode}
        />
      ))}
    </svg>
  );
}

function Legend() {
  const item = (cls: string, text: string) => (
    <span key={cls}>
      <i className={`vmFpSwatch vmFpSwatch--${cls}`} />
      {text}
    </span>
  );
  return (
    <div className="vmFpLegend" data-test-subj="vmFaceplateLegend">
      {item('up', 'Up')}
      {item('link_lost', 'Down: link lost')}
      {item('unused', 'Not connected')}
      {item('shutdown', 'Shut down')}
      {item('route', 'On attack route')}
      {item('inferred', 'Inferred from neighbour')}
    </div>
  );
}

const CHIP_COLOR = { up: 'success', link_lost: 'danger', unused: 'danger', shutdown: 'subdued' } as const;

function LogicalInterfaces({ node, ports }: { node: DeviceNode; ports: DevicePort[] }) {
  if (!ports.length) return null;
  const up = ports.filter((p) => p.state === 'up').length;
  return (
    <EuiAccordion
      id={`vmLogical-${node.node_id}`}
      buttonContent={`Logical interfaces (${ports.length}, ${up} up)`}
      paddingSize="s"
      data-test-subj="vmLogicalInterfaces"
    >
      <div className="vmFpChips">
        {ports.map((p) => (
          <span className="vmFpChip" key={p.name} title={p.alias || undefined}>
            <EuiHealth color={CHIP_COLOR[p.state]} textSize="xs">
              {p.name}
            </EuiHealth>
          </span>
        ))}
      </div>
    </EuiAccordion>
  );
}

export function Faceplate({
  node,
  edges,
  route = [],
  onSelectNode,
}: {
  node: DeviceNode;
  edges: GraphEdge[];
  /** the highlighted route's walk, start to target (empty when none is shown) */
  route?: string[];
  /** select another node on the map (a port's neighbour) */
  onSelectNode?: (nodeId: string) => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const fp = useMemo(() => faceplateOf(node), [node]);
  const byPort = useMemo(() => portNeighbours(node.node_id, edges), [node.node_id, edges]);
  const routeKeys = useMemo(() => routePortKeys(node.node_id, route, byPort), [node.node_id, route, byPort]);
  const clients = useMemo(() => radioClients(node.node_id, edges), [node.node_id, edges]);
  const compact = fp.ports.length > COMPACT_ABOVE;
  const panel = { node, fp, byPort, routeKeys, clients, onSelectNode };
  return (
    <div className="vmFp" style={{ '--vm-route': graphColors.route } as React.CSSProperties}>
      <FaceplatePanel {...panel} compact={compact} />
      {compact && (
        <EuiButtonEmpty size="xs" iconType="expand" onClick={() => setExpanded(true)} data-test-subj="vmFaceplateExpand">
          Expand ({fp.ports.length} ports)
        </EuiButtonEmpty>
      )}
      <Legend />
      <EuiSpacer size="s" />
      <LogicalInterfaces node={node} ports={fp.logical} />
      {expanded && (
        <EuiModal onClose={() => setExpanded(false)} maxWidth={false} className="vmFpModal" data-test-subj="vmFaceplateModal">
          <EuiModalHeader>
            <EuiModalHeaderTitle>{node.hostname || node.ip || node.node_id}: front panel</EuiModalHeaderTitle>
          </EuiModalHeader>
          <EuiModalBody>
            <div className="vmFp vmFpScroll" style={{ '--vm-route': graphColors.route } as React.CSSProperties}>
              <FaceplatePanel
                {...panel}
                width={Math.round(fp.width * 1.6)}
                onSelectNode={
                  onSelectNode &&
                  ((id) => {
                    setExpanded(false);
                    onSelectNode(id);
                  })
                }
              />
              <Legend />
            </div>
          </EuiModalBody>
        </EuiModal>
      )}
    </div>
  );
}
