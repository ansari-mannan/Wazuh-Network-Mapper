// Where every node goes on the map: a top-down layered layout from dagre.
import * as dagre from "@dagrejs/dagre";
import { GraphNode, GraphEdge, GraphResponse } from "../../../common";

// React Flow does NOT auto-layout - it renders whatever x/y you hand it. So we
// run dagre over the graph to compute a top-down hierarchy before rendering.
//
// CORE PRINCIPLE: ROOT SELECTION is separate from DEPTH ASSIGNMENT.
//   - ROLE only picks the root (the viewing origin) and the node icon. It is
//     NEVER used to decide a node's depth/tier.
//   - DEPTH is the hop distance from the root over the ACTUAL edges, so the
//     diagram reflects real cabling instead of an assumed firewall→L3→L2→host
//     textbook order. A firewall wired below an L2 switch will be drawn below it.
const NODE_W = 184;
const NODE_H = 84;

type Adjacency = Map<string, Set<string>>;

export type LayoutNode = {
  id: string;
  type: "device";
  position: { x: number; y: number };
  tier: number;
  data: GraphNode;
};

export type LayoutEdge = {
  id: string;
  source: string;
  target: string;
  label: string | undefined;
  /** remote_port of the recorded target (lldp links); label is local_port */
  remotePort?: string;
  type: GraphEdge["type"] | "inferred";
  confidence?: string;
  inferred: boolean;
};

export type LayoutResult = { nodes: LayoutNode[]; edges: LayoutEdge[] };

/**
 * UNDIRECTED adjacency from graph.edges. A physical link is bidirectional; the
 * source/target direction in the JSON only records who-discovered-whom, so we
 * ignore it here. Dangling edges (endpoint missing from nodes) are skipped.
 */
function buildAdjacency(nodes: GraphNode[], edges: GraphEdge[] | undefined): Adjacency {
  const ids = new Set(nodes.map((n) => n.node_id));
  const adj: Adjacency = new Map();
  for (const n of nodes) adj.set(n.node_id, new Set());
  for (const e of edges || []) {
    if (!ids.has(e.source) || !ids.has(e.target)) continue;
    adj.get(e.source)!.add(e.target);
    adj.get(e.target)!.add(e.source);
  }
  return adj;
}

/**
 * ROOT SELECTION - picks ONLY the viewing origin. Role is used here (and for
 * icons) but never for depth. Generic / blackbox-safe: no hardcoded names.
 * Priority: firewall → router → l3-switch → an unparented device → highest-degree
 * device → any node.
 */
export function pickRoot(nodes: GraphNode[], adj: Adjacency): string | null {
  if (!nodes.length) return null;

  const byRole = (role: string) =>
    nodes.find((n) => (n.role || "").toLowerCase() === role);
  const byRoleHit = byRole("firewall") || byRole("router") || byRole("l3-switch");
  if (byRoleHit) return byRoleHit.node_id;

  const unparentedDevice = nodes.find(
    (n) => n.parent_id == null && n.kind === "device"
  );
  if (unparentedDevice) return unparentedDevice.node_id;

  const pool = nodes.filter((n) => n.kind === "device");
  const candidates = pool.length ? pool : nodes;
  const degree = (n: GraphNode) => adj.get(n.node_id)?.size || 0;
  return candidates.reduce((a, b) => (degree(b) > degree(a) ? b : a)).node_id;
}

/**
 * DEPTH ASSIGNMENT - BFS over the UNDIRECTED graph from the root. Each reached
 * node's depth = hop count from the root. First-seen (shortest hop) wins, so
 * redundant links don't inflate depth; the `depth.has` check also guards against
 * cycles. Role plays no part here. Returns Map<node_id, depth>; nodes not in the
 * map were never reached (handled later as disconnected).
 */
export function bfsDepths(rootId: string | null, adj: Adjacency): Map<string, number> {
  const depth = new Map<string, number>();
  if (rootId == null) return depth;
  depth.set(rootId, 0);
  const queue = [rootId];
  for (let head = 0; head < queue.length; head++) {
    const cur = queue[head];
    const d = depth.get(cur)!;
    for (const nb of adj.get(cur) || []) {
      if (depth.has(nb)) continue; // shortest-hop wins; also breaks cycles
      depth.set(nb, d + 1);
      queue.push(nb);
    }
  }
  return depth;
}

/**
 * EDGE ORIENTATION - a dagre ranking edge points from the SHALLOWER endpoint to
 * the DEEPER one, so layout flows root → leaves regardless of how the link was
 * recorded. Returns null when:
 *   - either endpoint has no depth (disconnected; handled separately), or
 *   - the endpoints are at EQUAL depth (e.g. two core switches): the link is
 *     still drawn, but it must NOT rank one peer under the other - leaving it out
 *     of the ranking set keeps them side-by-side on the same rank.
 */
export function orientEdge(
  source: string,
  target: string,
  depth: Map<string, number>
): { from: string; to: string } | null {
  const ds = depth.get(source);
  const dt = depth.get(target);
  if (ds == null || dt == null) return null;
  if (ds === dt) return null; // same rank: render, but don't use for ranking
  return ds < dt ? { from: source, to: target } : { from: target, to: source };
}

// /24 of an IPv4 address, e.g. "172.20.40.1" -> "172.20.40". Used to infer which
// switch an unparented host probably hangs off when there's no confirmed link.
export function subnet24(ip: unknown): string | null {
  if (typeof ip !== "string") return null;
  const parts = ip.split(".");
  return parts.length === 4 ? parts.slice(0, 3).join(".") : null;
}


// ---- Rank folding ---------------------------------------------------------
// A rank holding hundreds of nodes (unlinked devices, flat meshes) comes out of
// dagre as one strip tens of thousands of px wide, unreadable once fitted to the
// screen. Each rank is folded into stacked lines (centred on one shared axis),
// capped both by node count and by pixel width, and every rank below is pushed
// down to match.
export const ROW_GAP = 40;
const NODE_GAP = 64;
const RANK_GAP = 96;

export function rowCapacity(count: number): number {
  return Math.max(10, Math.ceil(Math.sqrt(count * 1.2)));
}

/**
 * A box fed to the folder. `w`/`h` are the space the node reserves, which is
 * wider and taller than the node itself when it carries a pendant block; the
 * folder writes the box's top-left corner back into `position`.
 */
export type WrapItem = {
  id: string;
  position: { x: number; y: number };
  w: number;
  h: number;
};

/**
 * Folds every rank into stacked lines. `parentsOf` lists, per node, the ranked
 * nodes above it; when it is given, each rank is ordered by the mean x of its
 * already-placed parents (a barycentre pass) instead of by dagre's own x.
 * dagre orders a rank for one straight line, which stops being the right order
 * once that line is folded into three or four, so without this pass a child can
 * land several lines away from its parent horizontally.
 */
export function wrapRanks(
  items: WrapItem[],
  perRow: number,
  parentsOf?: Map<string, string[]>
): void {
  const ranks = new Map<number, WrapItem[]>();
  for (const it of items) {
    const y = Math.round(it.position.y);
    ranks.set(y, [...(ranks.get(y) || []), it]);
  }
  const maxLineW = perRow * (NODE_W + NODE_GAP);
  const centre = new Map<string, number>();
  let top = 0;
  for (const y of [...ranks.keys()].sort((a, b) => a - b)) {
    // dagre keeps separate components far apart; re-space every rank on one
    // shared axis (x=0) in dagre's left-to-right order so the map stays compact.
    const row = ranks.get(y)!.sort((a, b) => a.position.x - b.position.x);
    if (parentsOf) {
      const bary = new Map<WrapItem, number>();
      const anchored: WrapItem[] = [];
      const loose: WrapItem[] = [];
      for (const it of row) {
        const placed = (parentsOf.get(it.id) || [])
          .map((id) => centre.get(id))
          .filter((v): v is number => v != null);
        if (placed.length) {
          bary.set(it, placed.reduce((a, b) => a + b, 0) / placed.length);
          anchored.push(it);
        } else {
          // Nothing above it yet: keep dagre's own order for these.
          loose.push(it);
        }
      }
      anchored.sort((a, b) => bary.get(a)! - bary.get(b)!);
      row.length = 0;
      row.push(...anchored, ...loose);
    }
    const lines: WrapItem[][] = [];
    let width = 0;
    for (const it of row) {
      const last = lines[lines.length - 1];
      const grown = width + NODE_GAP + it.w;
      if (!last || last.length >= perRow || (last.length > 0 && grown > maxLineW)) {
        lines.push([it]);
        width = it.w;
      } else {
        last.push(it);
        width = grown;
      }
    }
    for (const line of lines) {
      const lineW = line.reduce((s, it) => s + it.w, 0) + (line.length - 1) * NODE_GAP;
      let x = -lineW / 2;
      let height = 0;
      for (const it of line) {
        it.position.x = x;
        it.position.y = top;
        centre.set(it.id, x + it.w / 2);
        x += it.w + NODE_GAP;
        height = Math.max(height, it.h);
      }
      top += height + ROW_GAP;
    }
    top += RANK_GAP - ROW_GAP;
  }
}

// ---- Pendant clustering ---------------------------------------------------
// Most nodes on a real network map are pendants: a device whose only neighbour
// is one switch, or an unlinked device tied to a switch by subnet inference
// alone. Fed to dagre as ordinary nodes they stretch a single rank over tens of
// thousands of px, and folding that rank then scatters one switch's own hosts
// across several lines far away from it. So pendants are kept out of dagre and
// drawn as a compact grid directly under their parent, which keeps every one of
// those links short and local.
const PEND_GAP_X = 24;
const PEND_GAP_Y = 18;
const PEND_TOP_GAP = 44;
const PEND_COLS_MAX = 14;
// A pendant block is deliberately wide and flat rather than square: a rank's
// line is as tall as its tallest box, so a square block of 51 hosts would push
// every later rank down by its own height. Three rows is the readable ceiling.
const PEND_ROWS_MAX = 3;
// Below this count a single row reads better than a short grid.
const PEND_ROW_MIN = 4;
// Clear air between the lowest ranked node and the lane of orphan nodes.
const LANE_GAP = 150;

export function gridCols(count: number, max: number): number {
  const flat = Math.max(Math.ceil(count / PEND_ROWS_MAX), Math.min(count, PEND_ROW_MIN));
  return Math.max(1, Math.min(max, flat));
}

type Block = { cols: number; w: number; h: number };

export function blockOf(count: number, maxCols: number): Block {
  const cols = gridCols(count, maxCols);
  const rows = Math.ceil(count / cols);
  return {
    cols,
    w: cols * NODE_W + (cols - 1) * PEND_GAP_X,
    h: rows * NODE_H + (rows - 1) * PEND_GAP_Y,
  };
}

/** Top-left corners of `count` grid cells, the grid centred on `cx` at `top`. */
export function gridPositions(count: number, block: Block, cx: number, top: number) {
  const out: { x: number; y: number }[] = [];
  for (let i = 0; i < count; i++) {
    const col = i % block.cols;
    const row = Math.floor(i / block.cols);
    const inRow = Math.min(block.cols, count - row * block.cols);
    const rowW = inRow * NODE_W + (inRow - 1) * PEND_GAP_X;
    out.push({
      x: cx - rowW / 2 + col * (NODE_W + PEND_GAP_X),
      y: top + row * (NODE_H + PEND_GAP_Y),
    });
  }
  return out;
}

/**
 * Which nodes hang off a single parent and can be drawn as a block under it:
 *   - a BFS-reached node whose only neighbour is that parent, and
 *   - an unlinked node attached to it by subnet inference.
 * A node that is itself a parent never counts as a pendant, so no chain is ever
 * collapsed and a subnet host always stays in the backbone. The root never
 * becomes a pendant, and a two-node component is left as dagre drew it.
 */
export function pendantGroups(
  adj: Adjacency,
  depth: Map<string, number>,
  inferredEdges: { from: string; to: string }[],
  rootId: string | null
): Map<string, string[]> {
  const parentOf = new Map<string, string>();
  for (const [id, nbs] of adj) {
    if (!depth.has(id) || id === rootId || nbs.size !== 1) continue;
    const parent = [...nbs][0];
    if ((adj.get(parent)?.size || 0) < 2) continue;
    parentOf.set(id, parent);
  }
  for (const ie of inferredEdges) parentOf.set(ie.to, ie.from);
  for (const parent of new Set(parentOf.values())) parentOf.delete(parent);
  const groups = new Map<string, string[]>();
  for (const [child, parent] of parentOf) {
    groups.set(parent, [...(groups.get(parent) || []), child]);
  }
  return groups;
}

/**
 * Pure layout-prep. Input: the raw graph.json ({ nodes, edges }). Output:
 *   {
 *     nodes: [{ id, type, position:{x,y}, tier, data }],
 *     edges: [{ id, source, target, label, type, inferred }],
 *   }
 * No side effects; the input objects are passed through untouched on `data`.
 * `parent_id` is intentionally NOT used for layout - it's discovery provenance,
 * not display hierarchy (it stays on `data` for the detail panel).
 */
export function layoutGraph(
  graph: Pick<GraphResponse, "nodes" | "edges"> | null | undefined
): LayoutResult {
  const nodes = (graph && graph.nodes) || [];
  const rawEdges = (graph && graph.edges) || [];
  if (!nodes.length) return { nodes: [], edges: [] };

  const adj = buildAdjacency(nodes, rawEdges);
  const root = pickRoot(nodes, adj);
  const depth = bfsDepths(root, adj);

  // tier = the rank each node lands on. Starts as BFS depth, then we place the
  // disconnected nodes: by subnet inference if possible, else an orphan lane.
  const tier = new Map(depth);
  const placedDevices = nodes.filter(
    (n) => n.kind === "device" && depth.has(n.node_id)
  );
  const inferredEdges: { from: string; to: string }[] = []; // device -> host - dashed/tentative
  const orphans: string[] = []; // node_ids with no link and no subnet match

  for (const n of nodes) {
    if (tier.has(n.node_id)) continue; // reached by BFS
    const sub = subnet24(n.ip);
    const host = sub
      ? placedDevices.find((d) => subnet24(d.ip) === sub)
      : null;
    if (host) {
      // Inherits depth = device.depth + 1 via the same orientation rule.
      tier.set(n.node_id, tier.get(host.node_id)! + 1);
      inferredEdges.push({ from: host.node_id, to: n.node_id });
    } else {
      orphans.push(n.node_id);
    }
  }

  // Orphans sink to a dedicated lane below everything so they never float to the top.
  let maxTier = 0;
  for (const v of tier.values()) maxTier = Math.max(maxTier, v);
  const orphanRank = maxTier + 1;
  for (const id of orphans) tier.set(id, orphanRank);

  // Pendants leave the ranked graph and follow their parent instead.
  const groups = pendantGroups(adj, depth, inferredEdges, root);
  const isPendant = new Set<string>();
  for (const children of groups.values()) for (const c of children) isPendant.add(c);
  const onLane = new Set(orphans);
  const backbone = nodes.filter((n) => !isPendant.has(n.node_id) && !onLane.has(n.node_id));

  // Build the oriented DAG edge set fed to dagre (these only drive ranking; the
  // rendered edge set is built separately below). Only backbone links rank.
  const inBackbone = new Set(backbone.map((n) => n.node_id));
  const ranking: [string, string][] = [];
  for (const e of rawEdges) {
    if (!inBackbone.has(e.source) || !inBackbone.has(e.target)) continue;
    const o = orientEdge(e.source, e.target, tier);
    if (o) ranking.push([o.from, o.to]);
  }

  // Each box reserves room for the node plus the grid of its pendants, so dagre
  // and the rank folder keep two neighbouring blocks from overlapping.
  const blocks = new Map<string, Block>();
  for (const [parent, children] of groups) {
    blocks.set(parent, blockOf(children.length, PEND_COLS_MAX));
  }
  const boxW = (id: string) => Math.max(NODE_W, blocks.get(id)?.w || 0);
  const boxH = (id: string) =>
    NODE_H + (blocks.has(id) ? PEND_TOP_GAP + blocks.get(id)!.h : 0);

  // Run dagre over the backbone, fold its ranks, then place the pendant grids.
  const boxes = new Map<string, WrapItem>();
  if (backbone.length) {
    const g = new dagre.graphlib.Graph();
    g.setGraph({ rankdir: "TB", nodesep: 64, ranksep: 96, marginx: 48, marginy: 48 });
    g.setDefaultEdgeLabel(() => ({}));
    for (const n of backbone) {
      g.setNode(n.node_id, { width: boxW(n.node_id), height: boxH(n.node_id) });
    }
    for (const [from, to] of ranking) g.setEdge(from, to);
    dagre.layout(g);
    for (const n of backbone) {
      const { x, y } = g.node(n.node_id);
      const w = boxW(n.node_id);
      const h = boxH(n.node_id);
      boxes.set(n.node_id, {
        id: n.node_id,
        position: { x: x - w / 2, y: y - h / 2 },
        w,
        h,
      });
    }
    const parentsOf = new Map<string, string[]>();
    for (const [from, to] of ranking) {
      parentsOf.set(to, [...(parentsOf.get(to) || []), from]);
    }
    wrapRanks([...boxes.values()], rowCapacity(nodes.length), parentsOf);
  }

  const place = new Map<string, { x: number; y: number }>();
  let lowest = 0;
  for (const [id, box] of boxes) {
    // The node sits at the top of its box, centred over its own pendant grid.
    place.set(id, { x: box.position.x + (box.w - NODE_W) / 2, y: box.position.y });
    lowest = Math.max(lowest, box.position.y + box.h);
    const children = groups.get(id);
    if (!children) continue;
    const cells = gridPositions(
      children.length,
      blocks.get(id)!,
      box.position.x + box.w / 2,
      box.position.y + NODE_H + PEND_TOP_GAP
    );
    children.forEach((c, i) => place.set(c, cells[i]));
  }

  // The orphan lane: its own grid under the whole map, never a single long row.
  if (orphans.length) {
    const block = blockOf(orphans.length, rowCapacity(nodes.length));
    const cells = gridPositions(orphans.length, block, 0, lowest + LANE_GAP);
    orphans.forEach((id, i) => place.set(id, cells[i]));
  }

  const outNodes: LayoutNode[] = nodes.map((n) => ({
    id: n.node_id,
    type: "device",
    position: place.get(n.node_id) || { x: 0, y: 0 },
    tier: tier.get(n.node_id) ?? orphanRank,
    data: n,
  }));

  // Rendered edges: every confirmed link (inferred:false) plus the dashed
  // inferred links so the UI can style them as tentative.
  const ids = new Set(nodes.map((n) => n.node_id));
  const confirmed: LayoutEdge[] = rawEdges
    .filter((e) => ids.has(e.source) && ids.has(e.target))
    .map((e, i) => ({
      id: `e${i}`,
      source: e.source,
      target: e.target,
      label: e.local_port || undefined,
      remotePort: e.remote_port || undefined,
      type: e.type,
      confidence: e.confidence,
      inferred: false,
    }));
  const inferred: LayoutEdge[] = inferredEdges.map((ie, i) => ({
    id: `inf${i}`,
    source: ie.from,
    target: ie.to,
    label: undefined,
    type: "inferred",
    inferred: true,
  }));

  return { nodes: outNodes, edges: [...confirmed, ...inferred] };
}
