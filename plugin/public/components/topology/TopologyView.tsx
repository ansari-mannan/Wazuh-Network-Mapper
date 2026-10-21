// Renders the dagre-positioned graph with distinct edge styles for lldp,
// endpoint_link (by confidence) and inferred links. Nodes are draggable, and
// every link is drawn from the upper node to the lower one (see orientForDrawing).
import React, { CSSProperties, forwardRef, useImperativeHandle, useMemo, useRef } from 'react';
import ReactFlow, {
  Background,
  BezierEdge,
  Controls,
  Edge,
  EdgeProps,
  EdgeText,
  MarkerType,
  Node,
  NodeChange,
  ReactFlowInstance,
  XYPosition,
  useNodesState,
} from 'react-flow-renderer';
import { GraphResponse } from '../../../common';
import { layoutGraph, LayoutEdge } from './layout';
import { highlightClass, routeArrows, routeMarks } from './highlight';
import { CustomNode, SpareStartNode, TopologyFlowNode } from './CustomNode';
import { pointOnLink, portLabels, PortLabels } from './edgeLabels';
import { graphColors, themeVars } from '../../lib/theme';
import { isWireless, wirelessText } from '../../lib/wireless';
import { useHoverTip } from '../layout/HoverTip';

const nodeTypes = { device: CustomNode, spareStart: SpareStartNode };

// Where the virtual spare-port start sits, from the switch that holds the ports.
const SPARE_START_OFFSET = { x: -200, y: -110 };

// How far along a device-to-device link its two port labels sit, from each end.
const PORT_LABEL_T = 0.22;

// A device-to-device link: the usual bezier, with each device's port printed
// near that device's end of the line instead of one label in the middle.
function PortsEdge(props: EdgeProps<PortLabels>) {
  const { sourceX, sourceY, targetX, targetY, data, labelStyle, labelBgStyle } = props;
  const end = (port: string | undefined, t: number, which: string) => {
    if (!port) return null;
    const { x, y } = pointOnLink(sourceX, sourceY, targetX, targetY, t);
    return (
      <EdgeText
        x={x}
        y={y}
        label={port}
        labelStyle={labelStyle}
        labelShowBg
        labelBgStyle={labelBgStyle}
        labelBgPadding={[3, 2]}
        labelBgBorderRadius={2}
        className={`vmPortLabel vmPortLabel--${which}`}
      />
    );
  };
  return (
    <>
      <BezierEdge {...props} label={undefined} />
      {end(data?.sourcePort, PORT_LABEL_T, 'source')}
      {end(data?.targetPort, 1 - PORT_LABEL_T, 'target')}
    </>
  );
}

/** The Wi-Fi mark: a dot and two arcs, centred on (x, y). */
export function WifiGlyph({ x, y, color, background }: { x: number; y: number; color: string; background: string }) {
  return (
    <g className="vmWifiGlyph" transform={`translate(${x} ${y})`}>
      <circle r={9} fill={background} stroke={color} strokeWidth={1.2} />
      <g fill="none" stroke={color} strokeWidth={1.4} strokeLinecap="round">
        <path d="M -5 -1 A 7 7 0 0 1 5 -1" />
        <path d="M -2.6 1.6 A 3.6 3.6 0 0 1 2.6 1.6" />
      </g>
      <circle cy={4} r={1.3} fill={color} />
    </g>
  );
}

// A Wi-Fi client's link: the dashed line, the Wi-Fi mark at its middle and
// "Wireless · SSID · band (radio)" on hover or keyboard focus.
function WifiEdge(props: EdgeProps<{ tooltip: string }>) {
  const { sourceX, sourceY, targetX, targetY, data, style } = props;
  const mid = pointOnLink(sourceX, sourceY, targetX, targetY, 0.5);
  const { tip, bind } = useHoverTip();
  const text = data?.tooltip || 'Wireless';
  return (
    <g className="vmWifiEdge" tabIndex={0} role="img" aria-label={text} {...bind({ title: text, lines: [] })}>
      {tip}
      <BezierEdge {...props} label={undefined} />
      <WifiGlyph x={mid.x} y={mid.y} color={String(style?.stroke)} background={themeVars.euiColorEmptyShade} />
    </g>
  );
}

const edgeTypes = { ports: PortsEdge, wifi: WifiEdge };

type EdgeStyle = CSSProperties & { stroke: string };

// a Wi-Fi link stays dashed, on a route too
const WIFI_DASH = '5 5';
export const ROUTE_DASH = '10 6';

// Edge visual style by relationship type + placement confidence (Issue 6).
export function edgeStyle(e: Pick<LayoutEdge, 'inferred' | 'type' | 'confidence'> & { label?: string }): EdgeStyle {
  if (e.inferred) {
    return { stroke: graphColors.edgeInferred, strokeWidth: 1.5, strokeDasharray: '6 3', opacity: 0.9 };
  }
  if (e.type === 'endpoint_link') {
    // A Wi-Fi client hangs off its access point: teal dashes with a Wi-Fi
    // mark (WifiEdge), unlike any wired host link.
    if (isWireless({ ...e, local_port: e.label })) {
      return { stroke: graphColors.edgeWifi, strokeWidth: 2, strokeDasharray: WIFI_DASH, strokeLinecap: 'round' };
    }
    // FDB-confidence links are visually distinct (lighter, finer dash) from the
    // higher-confidence LLDP-confidence ones.
    if (e.confidence === 'fdb') {
      return { stroke: graphColors.edgeFdb, strokeWidth: 1.5, strokeDasharray: '3 3', opacity: 0.9 };
    }
    return { stroke: graphColors.edgeEndpoint, strokeWidth: 1.5, strokeDasharray: '6 3', opacity: 0.9 };
  }
  // lldp (and anything else) -> solid, clearly visible, with a direction arrow.
  return { stroke: graphColors.edgeLldp, strokeWidth: 2 };
}

/**
 * The data records links in discovery order (host -> switch, or a switch that
 * happens to be the deeper node -> its neighbour). Drawn as-is, a link whose
 * source sits below its target leaves the bottom handle and loops back up into
 * the top handle. So each link is drawn from the node that is higher in the
 * computed layout (its bottom handle) to the lower one (its top handle). Only
 * the drawing is flipped; the data and the layout ranks are untouched. Links
 * between nodes on the same row keep their recorded direction.
 */
function orientForDrawing(
  e: LayoutEdge,
  layoutY: Map<string, number>
): { source: string; target: string } {
  const ys = layoutY.get(e.source);
  const yt = layoutY.get(e.target);
  if (ys !== undefined && yt !== undefined && ys > yt) {
    return { source: e.target, target: e.source };
  }
  return { source: e.source, target: e.target };
}

// Positions of nodes the user dragged, per loaded graph object. Kept outside the
// component so they survive leaving and re-entering the page; a reload fetches
// a new graph object, so the moved positions are dropped with the old one.
const movedPositions = new WeakMap<GraphResponse, Map<string, XYPosition>>();

export interface TopologyViewHandle {
  /** put every node back on its computed layout position and refit */
  resetLayout: () => void;
}

interface TopologyViewProps {
  graph: GraphResponse;
  onSelect: (nodeId: string | null) => void;
  selectedId: string | null;
  /**
   * node_ids left off the canvas (with their edges), sorted and joined by
   * newlines. A string so the layout re-runs only when the set changes, not
   * whenever the caller builds a new array.
   */
  hiddenKey?: string;
  /**
   * node_ids of one route to spotlight (comma-separated), from Attack paths
   * "Show on map". When set, hosts off the route and edges off it are dimmed.
   */
  highlightKey?: string;
  /**
   * node_ids the route only passes through (comma-separated): switches/routers on
   * the physical path between its assets. Together with highlightKey, the set
   * of nodes on the route.
   */
  passKey?: string;
  /**
   * The route's nodes in travel order, start to target (comma-separated; see
   * attackPaths.physicalPathWalk). Numbers the nodes and orients the arrows.
   */
  routeKey?: string;
  /**
   * Set when the route starts at spare switch ports ("9 spare ports · VLAN 20"):
   * the walk's first id is then no graph node but a virtual start marker, drawn
   * beside the next node (the switch) only while the route is shown.
   */
  startLabel?: string;
}

// A link the route travels along: thicker, in the route colour, with marching
// dashes and a glow (topology.scss .vmRouteEdge), and the arrowhead at
// the end the route goes to. The link keeps the direction it is drawn in (from
// the upper node to the lower), so going "up" puts the arrow at its start.
function routeEdge(e: Edge, arrow: 'start' | 'end'): Edge {
  const marker = { type: MarkerType.ArrowClosed, color: graphColors.route, width: 18, height: 18 };
  return {
    ...e,
    // the dashes march the way the route goes, so backwards on a link drawn the other way
    className: arrow === 'start' ? 'vmRouteEdge vmRouteEdge--reverse' : 'vmRouteEdge',
    style: {
      ...e.style,
      stroke: graphColors.route,
      strokeWidth: 4,
      strokeDasharray: e.type === 'wifi' ? WIFI_DASH : ROUTE_DASH,
      opacity: 1,
    },
    markerEnd: arrow === 'end' ? marker : undefined,
    markerStart: arrow === 'start' ? { ...marker, orient: 'auto-start-reverse' } : undefined,
  };
}

// The graph without the hidden nodes and any edge that touches one.
function withoutHidden(graph: GraphResponse, hiddenKey: string): GraphResponse {
  if (!hiddenKey) return graph;
  const hidden = new Set(hiddenKey.split('\n'));
  return {
    ...graph,
    nodes: graph.nodes.filter((n) => !hidden.has(n.node_id)),
    edges: graph.edges.filter((e) => !hidden.has(e.source) && !hidden.has(e.target)),
  };
}

export const TopologyView = forwardRef<TopologyViewHandle, TopologyViewProps>(
  (
    { graph, onSelect, selectedId, hiddenKey = '', highlightKey = '', passKey = '', routeKey = '', startLabel = '' },
    ref
  ) => {
    const highlight = useMemo(
      () => (highlightKey ? new Set(highlightKey.split(',')) : null),
      [highlightKey]
    );
    const passThrough = useMemo(() => new Set(passKey ? passKey.split(',') : []), [passKey]);
    const walk = useMemo(() => (routeKey ? routeKey.split(',') : []), [routeKey]);
    const marks = useMemo(() => (walk.length ? routeMarks(walk) : null), [walk]);
    const { layoutNodes, edges } = useMemo(() => {
      // layoutGraph is the pure layout-prep module: it computes positions/ranks
      // from the real edges and returns the edges to draw (incl. dashed "inferred"
      // links). We only translate its output into React Flow styling here.
      const { nodes: laidOut, edges: laidEdges } = layoutGraph(withoutHidden(graph, hiddenKey));
      const layoutY = new Map(laidOut.map((n) => [n.id, n.position.y]));
      const rfNodes: TopologyFlowNode[] = laidOut.map((p) => ({
        id: p.id,
        type: p.type,
        position: p.position,
        data: p.data,
      }));

      // Three legible channels (Issue 6):
      //   lldp           -> solid slate, width 2, arrow (confirmed device adjacency)
      //   endpoint_link  -> dashed slate, width 1.5 (a host attached to an access port)
      //     confidence=fdb -> lighter + finer dash (inferred-from-forwarding-table)
      //   inferred       -> dashed amber (tentative, subnet-guessed; not confirmed)
      // Port labels: an lldp link shows each device's port at that device's
      // end (see edgeLabels.ts); a host link shows the switch port in the middle.
      const ssidOf = new Map(
        graph.nodes.map((n) => [n.node_id, n.kind === 'endpoint' ? n.wifi?.ssid : undefined])
      );
      const rfEdges: Edge[] = laidEdges.map((e) => {
        const style = edgeStyle(e);
        const wifi = !e.inferred && isWireless({ ...e, local_port: e.label });
        const drawn = orientForDrawing(e, layoutY);
        const ports =
          e.type === 'lldp'
            ? portLabels(
                { type: 'lldp', local_port: e.label, remote_port: e.remotePort },
                drawn.source !== e.source
              )
            : null;
        return {
          id: e.id,
          ...drawn,
          ...(ports ? { type: 'ports', data: ports } : {}),
          ...(wifi ? { type: 'wifi', data: { tooltip: wirelessText(ssidOf.get(e.source), e.label) } } : {}),
          label: e.inferred ? 'inferred' : ports || wifi ? undefined : e.label,
          style,
          labelStyle: {
            fontSize: 10,
            fill: e.inferred ? graphColors.labelInferred : themeVars.euiTextSubduedColor,
          },
          labelBgStyle: { fill: themeVars.euiColorEmptyShade, fillOpacity: 0.85 },
          markerEnd: {
            type: MarkerType.ArrowClosed,
            color: style.stroke,
            width: 16,
            height: 16,
          },
        };
      });

      return { layoutNodes: rfNodes, edges: rfEdges };
    }, [graph, hiddenKey]);
    // The spare-port start marker and its link to the switch: display only, so
    // never part of the layout, the counts or the moved positions.
    const spareEdge = useMemo<Edge | null>(
      () =>
        startLabel && walk.length > 1 && !layoutNodes.some((n) => n.id === walk[0])
          ? { id: `vmSpareStart->${walk[1]}`, source: walk[0], target: walk[1], style: {} }
          : null,
      [startLabel, walk, layoutNodes]
    );
    const drawnEdges = useMemo(() => (spareEdge ? [...edges, spareEdge] : edges), [edges, spareEdge]);
    const arrows = useMemo(() => (walk.length ? routeArrows(walk, drawnEdges) : null), [walk, drawnEdges]);

    const moved = useMemo(() => {
      let m = movedPositions.get(graph);
      if (!m) movedPositions.set(graph, (m = new Map()));
      return m;
    }, [graph]);

    const withMoves = (list: TopologyFlowNode[]) =>
      list.map((n) => (moved.has(n.id) ? { ...n, position: moved.get(n.id)! } : n));

    const [nodes, setNodes, onNodesChange] = useNodesState(withMoves(layoutNodes));
    const instance = useRef<ReactFlowInstance | null>(null);

    // A new graph (reload), or a change in the hidden set, replaces the nodes;
    // positions the user dragged are kept (they are keyed by the full graph).
    const lastLayout = useRef(layoutNodes);
    if (lastLayout.current !== layoutNodes) {
      lastLayout.current = layoutNodes;
      setNodes(withMoves(layoutNodes));
    }

    useImperativeHandle(ref, () => ({
      resetLayout: () => {
        moved.clear();
        setNodes(layoutNodes);
        window.requestAnimationFrame(() => instance.current?.fitView());
      },
    }));

    const handleNodesChange = (changes: NodeChange[]) => {
      for (const c of changes) {
        if (c.type === 'position' && c.position) moved.set(c.id, c.position);
      }
      onNodesChange(changes);
    };

    if (!graph.nodes || graph.nodes.length === 0) {
      return <div className="empty">The graph is empty (0 nodes).</div>;
    }

    // Spotlight one route (highlight.ts): its nodes ringed and numbered in
    // travel order, its links pointing the way it travels; every node off it
    // fades.
    const lit = (id: string) => highlight!.has(id) || passThrough.has(id);
    const displayNodes: Node[] = nodes.map((n) => {
      const sel = n.id === selectedId;
      const className = highlightClass(n.id, highlight, passThrough, marks);
      const route = (highlight && marks?.get(n.id)) || undefined;
      return n.selected === sel && (n.className || '') === className && n.data.route === route
        ? n
        : { ...n, selected: sel, className, data: { ...n.data, route } };
    });
    const anchor = spareEdge && nodes.find((n) => n.id === spareEdge.target);
    if (highlight && anchor) {
      displayNodes.push({
        id: spareEdge!.source,
        type: 'spareStart',
        position: { x: anchor.position.x + SPARE_START_OFFSET.x, y: anchor.position.y + SPARE_START_OFFSET.y },
        data: { label: startLabel, route: marks?.get(spareEdge!.source) },
        className: 'vmOnRoute',
        draggable: false,
        selectable: false,
      });
    }
    const displayEdges = !highlight
      ? edges
      : (anchor ? drawnEdges : edges).map((e) => {
          const arrow = arrows?.get(e.id);
          if (arrow) return routeEdge(e, arrow);
          // a link off the route fades; an old link without the walk lights
          // every edge between two lit nodes instead
          return !arrows && lit(e.source) && lit(e.target) ? e : { ...e, style: { ...e.style, opacity: 0.12 } };
        });

    return (
      <div
        className="canvas"
        style={{ '--vm-route': graphColors.route, '--vm-route-text': graphColors.routeText } as CSSProperties}
      >
        <ReactFlow
          nodes={displayNodes}
          edges={displayEdges}
          nodeTypes={nodeTypes}
          edgeTypes={edgeTypes}
          onNodesChange={handleNodesChange}
          onNodeClick={(_, n) => n.type !== 'spareStart' && onSelect(n.id)}
          onPaneClick={() => onSelect(null)}
          onInit={(rf) => {
            instance.current = rf;
          }}
          fitView
          minZoom={0.15}
          nodesDraggable
          nodesConnectable={false}
          elementsSelectable
        >
          <Background color={themeVars.euiColorLightShade} gap={22} size={1} />
          <Controls showInteractive={false} />
        </ReactFlow>
      </div>
    );
  }
);
