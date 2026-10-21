// A device's front panel as inline SVG, drawn from lib/faceplate's layout:
// sockets with a link LED each, the route ring and the dashed outline of an
// inferred port, a legend, and the logical interfaces folded underneath.
// Colours are CSS classes (faceplate.scss), so they follow the dashboard theme.
import React, { useLayoutEffect, useMemo, useRef, useState } from 'react';
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
  CAPTION_SIZE,
  LABEL_SIZE,
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
  COMPACT_ABOVE,
  MAX_SCALE,
  pickLayout,
  portTooltip,
  routePortKeys,
  speedLed,
  tipText,
} from '../../lib/faceplate';
import { graphColors } from '../../lib/theme';
import { radioClients } from '../../lib/wireless';
import { useHoverTip } from '../layout/HoverTip';
import { RouteEntry } from '../topology/highlight';

interface PanelProps {
  node: DeviceNode;
  fp: Layout;
  byPort: Map<string, Neighbour[]>;
  routeKeys: Set<string>;
  /** the spare ports a highlighted route enters this device by, and their VLAN */
  entryKeys?: Set<string>;
  entryVlan?: number;
  /** an access point's clients per radio, from its wireless links */
  clients: Map<string, number>;
  compact?: boolean;
  onSelectNode?: (nodeId: string) => void;
}

const onRouteOf = (port: DevicePort, routeKeys: Set<string>) =>
  routeKeys.has(portKey(port.name)) || (!!port.alias && routeKeys.has(portKey(port.alias)));

function Socket({ p, node, byPort, routeKeys, entryKeys, entryVlan, clients, compact, onSelectNode }: Omit<PanelProps, 'fp'> & { p: PlacedPort }) {
  const { port, kind, x, y } = p;
  const neighbours = neighboursOf(port, byPort);
  const inferred = isInferred(port, node);
  const entry = !!entryKeys && onRouteOf(port, entryKeys);
  const onRoute = entry || onRouteOf(port, routeKeys);
  const count = kind === 'radio' ? clients.get(port.name) ?? 0 : undefined;
  const content = portTooltip(port, neighbours, { inferred, onRoute, clients: count, entryVlan: entry ? entryVlan : undefined });
  const { tip, bind } = useHoverTip();
  const events = bind(content);
  const target = onSelectNode && neighbours[0]?.nodeId;
  const select = target ? () => onSelectNode!(target) : undefined;
  const w = PORT_W;
  const h = PORT_H;
  return (
    <g
      className={`vmFpPort vmFpPort--${port.state}${select ? ' vmFpPort--link' : ''}`}
      data-port={port.name}
      onClick={select}
      {...events}
      onFocus={(e) => {
        events.onFocus(e);
        // in a scrolled strip, bring the focused port into view
        (e.currentTarget as Element).scrollIntoView?.({ block: 'nearest', inline: 'nearest' });
      }}
      onKeyDown={(e) => {
        events.onKeyDown(e);
        if (select && (e.key === 'Enter' || e.key === ' ')) select();
      }}
      // focusable whether or not it is a button, so the keyboard gets the tooltip too
      tabIndex={0}
      role={select ? 'button' : 'img'}
      aria-label={tipText(content)}
    >
      {tip}
      {onRoute && (
        <rect className="vmFpRoute" x={x - 3} y={y - 3} width={w + 6} height={h + 6} rx={4} fill="none" strokeWidth={2.2} />
      )}
      {kind === 'radio' ? (
        <>
          <line className="vmFpPin" x1={x + w / 2} y1={y + h / 2} x2={x + w / 2} y2={y - 2} strokeWidth={2} />
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
          {/* the link LED, and beside it the speed LED */}
          <rect className="vmFpLed" x={x + 2} y={y + h * 0.45} width={w / 2 - 3} height={h * 0.3} rx={1.5} />
          <rect
            className={`vmFpSpeed vmFpSpeed--${speedLed(port)}`}
            x={x + w / 2 + 1}
            y={y + h * 0.45}
            width={w / 2 - 3}
            height={h * 0.3}
            rx={1.5}
          />
        </>
      )}
      {!compact && (
        <text className="vmFpLabel" x={x + w / 2} y={p.labelY} fontSize={LABEL_SIZE} textAnchor="middle">
          {p.label}
        </text>
      )}
    </g>
  );
}

/** The panel itself: chassis, vendor text (plain, no logo), captions and sockets. */
export function FaceplatePanel({ node, fp, byPort, routeKeys, entryKeys, entryVlan, clients, compact, onSelectNode, width }: PanelProps & { width?: number }) {
  const { chassis, height: H, width: W, furniture: f } = fp;
  const rx = chassis === 'puck' ? H / 2 : chassis === 'desktop' ? 10 : chassis === 'rack' ? 3 : 4;
  // the decoration is left off the compact panel; the Expand modal has it
  const decor = !compact;
  const ear = decor ? f.ear : 0;
  const gradient = `vmFpGrad-${node.node_id.replace(/[^A-Za-z0-9]/g, '')}`;
  return (
    <svg
      className={`vmFaceplate vmFaceplate--${chassis}`}
      viewBox={`0 0 ${W} ${H}`}
      width={width ?? '100%'}
      // a small panel keeps its size rather than filling the card
      style={width ? undefined : { maxWidth: W * MAX_SCALE }}
      role="group"
      aria-label={`${node.hostname || node.ip || node.node_id} front panel`}
      data-test-subj="vmFaceplate"
    >
      {decor && (
        <defs>
          <linearGradient id={gradient} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" className="vmFpGradTop" />
            <stop offset="0.3" className="vmFpGradBody" />
          </linearGradient>
        </defs>
      )}
      <rect
        className="vmFpChassis"
        x={ear + 1}
        y={1}
        width={W - 2 * ear - 2}
        height={H - 2}
        rx={rx}
        strokeWidth={2}
        fill={decor ? `url(#${gradient})` : undefined}
      />
      {ear > 0 &&
        [0, W - ear].map((ex) => (
          <g key={ex} className="vmFpEar">
            <rect x={ex + 0.5} y={1} width={ear - 1} height={H - 2} rx={2} />
            {[H * 0.27, H * 0.73].map((cy) => (
              <circle key={cy} className="vmFpScrew" cx={ex + ear / 2} cy={cy} r={2.4} />
            ))}
          </g>
        ))}
      {decor && <rect className="vmFpPlate" x={f.plate.x} y={f.plate.y} width={f.plate.w} height={f.plate.h} rx={2} />}
      {decor &&
        Array.from({ length: Math.floor(f.grille.w / 4) }, (_, i) => (
          <rect key={i} className="vmFpGrille" x={f.grille.x + i * 4} y={f.grille.y} width={1.6} height={f.grille.h} rx={0.8} />
        ))}
      <circle className={`vmFpPwr vmFpPwr--${f.pwr.on ? 'on' : 'off'}`} cx={f.pwr.cx} cy={f.pwr.cy} r={2.6}>
        <title>{f.pwr.on ? 'Answered SNMP in this scan' : 'Did not answer SNMP in this scan'}</title>
      </circle>
      {fp.texts
        .filter((t) => decor || !t.decor)
        .map((t, i) => (
          <text key={i} className="vmFpLabel" x={t.x} y={t.y} fontSize={t.size} fontWeight={t.bold ? 700 : undefined}>
            {t.text}
          </text>
        ))}
      {fp.captions.map((c) => (
        <g key={`${c.text}-${c.x}`}>
          <text className="vmFpLabel" x={c.x} y={fp.captionY} fontSize={CAPTION_SIZE}>
            {c.text}
          </text>
          {/* the underline goes on the compact panel, the caption stays */}
          {!compact && (
            <line className="vmFpRule" x1={c.x} y1={fp.captionY + 3} x2={c.x + c.width} y2={fp.captionY + 3} strokeWidth={0.6} />
          )}
        </g>
      ))}
      {fp.dividers.map((dx) => (
        <line key={dx} className="vmFpDivider" x1={dx} y1={4} x2={dx} y2={H - 4} strokeWidth={1} />
      ))}
      {fp.ports.map((p) => (
        <Socket
          key={p.port.name}
          p={p}
          node={node}
          byPort={byPort}
          routeKeys={routeKeys}
          entryKeys={entryKeys}
          entryVlan={entryVlan}
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
      {item('fast', 'Speed ≥ 1 Gb/s')}
      {item('slow', 'Speed 10–100 Mb/s')}
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

type ObserverClass = new (callback: (entries: Array<{ contentRect: { width: number } }>) => void) => {
  observe: (el: Element) => void;
  disconnect: () => void;
};

/** The element's width in px, kept up to date; 0 until measured (and in tests without layout). */
function useWidth(): [React.RefObject<HTMLDivElement>, number] {
  const ref = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(0);
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    setWidth(el.clientWidth);
    // the dashboard's TS lib types ResizeObserver but does not declare the global
    const Observer = (window as unknown as { ResizeObserver?: ObserverClass }).ResizeObserver;
    if (!Observer) return;
    const observer = new Observer((entries) => setWidth(Math.floor(entries[0].contentRect.width)));
    observer.observe(el);
    return () => observer.disconnect();
  }, []);
  return [ref, width];
}

/**
 * The panel's wrapper: centred when narrower than the card; when wider, it
 * scrolls sideways (thin scrollbar) with a fade on the right while more of
 * the strip is out of view.
 */
function Strip({ scroll, children }: { scroll: boolean; children: React.ReactNode }) {
  const ref = useRef<HTMLDivElement>(null);
  const [more, setMore] = useState(false);
  const update = () => {
    const el = ref.current;
    setMore(Boolean(el && el.scrollLeft + el.clientWidth < el.scrollWidth - 1));
  };
  useLayoutEffect(update, [scroll]);
  return (
    <div className={`vmFpStripWrap${scroll && more ? ' vmFpStripWrap--more' : ''}`}>
      <div
        ref={ref}
        className={`vmFpStrip${scroll ? ' vmFpStrip--scroll' : ''}`}
        onScroll={update}
        data-test-subj="vmFaceplateStrip"
      >
        {children}
      </div>
    </div>
  );
}

export function Faceplate({
  node,
  edges,
  route = [],
  entry,
  onSelectNode,
}: {
  node: DeviceNode;
  edges: GraphEdge[];
  /** the highlighted route's walk, start to target (empty when none is shown) */
  route?: string[];
  /** the spare ports that route enters by, ringed when they are on this device */
  entry?: RouteEntry;
  /** select another node on the map (a port's neighbour) */
  onSelectNode?: (nodeId: string) => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const [box, available] = useWidth();
  const { fp, compact, width: drawnWidth, scroll } = useMemo(() => pickLayout(node, available), [node, available]);
  const byPort = useMemo(() => portNeighbours(node.node_id, edges), [node.node_id, edges]);
  const routeKeys = useMemo(() => routePortKeys(node.node_id, route, byPort), [node.node_id, route, byPort]);
  const clients = useMemo(() => radioClients(node.node_id, edges), [node.node_id, edges]);
  const entryKeys = useMemo(
    () => (entry?.switch === node.node_id ? new Set(entry.ports.map(portKey)) : undefined),
    [entry, node.node_id]
  );
  const panel = { node, fp, byPort, routeKeys, entryKeys, entryVlan: entry?.vlan, clients, onSelectNode };
  const full = useMemo(() => faceplateOf(node), [node]); // the Expand modal's, at full size
  // a big rack switch can always be opened larger, whether or not its strip scrolls
  const expandable = compact || (fp.chassis === 'rack' && fp.ports.length > COMPACT_ABOVE);
  return (
    <div ref={box} className="vmFp" style={{ '--vm-route': graphColors.route } as React.CSSProperties}>
      <Strip scroll={scroll}>
        <FaceplatePanel {...panel} compact={compact} width={drawnWidth || undefined} />
      </Strip>
      {expandable && (
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
                fp={full}
                width={Math.round(full.width * 1.6)}
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
