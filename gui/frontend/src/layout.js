import dagre from "@dagrejs/dagre";

// React Flow does NOT auto-layout — it renders whatever x/y you hand it. So we
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

/**
 * UNDIRECTED adjacency from graph.edges. A physical link is bidirectional; the
 * source/target direction in the JSON only records who-discovered-whom, so we
 * ignore it here. Dangling edges (endpoint missing from nodes) are skipped.
 */
function buildAdjacency(nodes, edges) {
  const ids = new Set(nodes.map((n) => n.node_id));
  const adj = new Map();
  for (const n of nodes) adj.set(n.node_id, new Set());
  for (const e of edges || []) {
    if (!ids.has(e.source) || !ids.has(e.target)) continue;
    adj.get(e.source).add(e.target);
    adj.get(e.target).add(e.source);
  }
  return adj;
}

/**
 * ROOT SELECTION — picks ONLY the viewing origin. Role is used here (and for
 * icons) but never for depth. Generic / blackbox-safe: no hardcoded names.
 * Priority: firewall → router → l3-switch → an unparented device → highest-degree
 * device → any node.
 */
export function pickRoot(nodes, adj) {
  if (!nodes.length) return null;

  const byRole = (role) =>
    nodes.find((n) => (n.role || "").toLowerCase() === role);
  const byRoleHit = byRole("firewall") || byRole("router") || byRole("l3-switch");
  if (byRoleHit) return byRoleHit.node_id;

  const unparentedDevice = nodes.find(
    (n) => n.parent_id == null && n.kind === "device"
  );
  if (unparentedDevice) return unparentedDevice.node_id;

  const pool = nodes.filter((n) => n.kind === "device");
  const candidates = pool.length ? pool : nodes;
  const degree = (n) => adj.get(n.node_id)?.size || 0;
  return candidates.reduce((a, b) => (degree(b) > degree(a) ? b : a)).node_id;
}

/**
 * DEPTH ASSIGNMENT — BFS over the UNDIRECTED graph from the root. Each reached
 * node's depth = hop count from the root. First-seen (shortest hop) wins, so
 * redundant links don't inflate depth; the `depth.has` check also guards against
 * cycles. Role plays no part here. Returns Map<node_id, depth>; nodes not in the
 * map were never reached (handled later as disconnected).
 */
export function bfsDepths(rootId, adj) {
  const depth = new Map();
  if (rootId == null) return depth;
  depth.set(rootId, 0);
  const queue = [rootId];
  for (let head = 0; head < queue.length; head++) {
    const cur = queue[head];
    const d = depth.get(cur);
    for (const nb of adj.get(cur) || []) {
      if (depth.has(nb)) continue; // shortest-hop wins; also breaks cycles
      depth.set(nb, d + 1);
      queue.push(nb);
    }
  }
  return depth;
}

/**
 * EDGE ORIENTATION — a dagre ranking edge points from the SHALLOWER endpoint to
 * the DEEPER one, so layout flows root → leaves regardless of how the link was
 * recorded. Returns null when:
 *   - either endpoint has no depth (disconnected; handled separately), or
 *   - the endpoints are at EQUAL depth (e.g. two core switches): the link is
 *     still drawn, but it must NOT rank one peer under the other — leaving it out
 *     of the ranking set keeps them side-by-side on the same rank.
 */
export function orientEdge(source, target, depth) {
  const ds = depth.get(source);
  const dt = depth.get(target);
  if (ds == null || dt == null) return null;
  if (ds === dt) return null; // same rank: render, but don't use for ranking
  return ds < dt ? { from: source, to: target } : { from: target, to: source };
}

// /24 of an IPv4 address, e.g. "172.20.40.1" -> "172.20.40". Used to infer which
// switch an unparented host probably hangs off when there's no confirmed link.
function subnet24(ip) {
  if (typeof ip !== "string") return null;
  const parts = ip.split(".");
  return parts.length === 4 ? parts.slice(0, 3).join(".") : null;
}

/**
 * Pure layout-prep. Input: the raw graph.json ({ nodes, edges }). Output:
 *   {
 *     nodes: [{ id, type, position:{x,y}, tier, data }],
 *     edges: [{ id, source, target, label, type, inferred }],
 *   }
 * No side effects; the input objects are passed through untouched on `data`.
 * `parent_id` is intentionally NOT used for layout — it's discovery provenance,
 * not display hierarchy (it stays on `data` for the detail panel).
 */
export function layoutGraph(graph) {
  const nodes = (graph && graph.nodes) || [];
  const rawEdges = (graph && graph.edges) || [];
  if (!nodes.length) return { nodes: [], edges: [] };

  const adj = buildAdjacency(nodes, rawEdges);
  const root = pickRoot(nodes, adj);
  const depth = bfsDepths(root, adj);

  // tier = the rank each node lands on. Starts as BFS depth, then we place the
  // disconnected nodes: by subnet inference if possible, else a bottom lane.
  const tier = new Map(depth);
  const placedDevices = nodes.filter(
    (n) => n.kind === "device" && depth.has(n.node_id)
  );
  const inferredEdges = []; // { from: device, to: host } — dashed/tentative
  const bottomLane = []; // node_ids with no link and no subnet match

  for (const n of nodes) {
    if (tier.has(n.node_id)) continue; // reached by BFS
    const sub = subnet24(n.ip);
    const host = sub
      ? placedDevices.find((d) => subnet24(d.ip) === sub)
      : null;
    if (host) {
      // Inherits depth = device.depth + 1 via the same orientation rule.
      tier.set(n.node_id, tier.get(host.node_id) + 1);
      inferredEdges.push({ from: host.node_id, to: n.node_id });
    } else {
      bottomLane.push(n.node_id);
    }
  }

  // Disconnected-with-no-inference nodes sink to a dedicated bottom rank so they
  // never float to the top.
  let maxTier = 0;
  for (const v of tier.values()) maxTier = Math.max(maxTier, v);
  const bottomRank = maxTier + 1;
  for (const id of bottomLane) tier.set(id, bottomRank);

  // Build the oriented DAG edge set fed to dagre (these only drive ranking; the
  // rendered edge set is built separately below).
  const ranking = [];
  for (const e of rawEdges) {
    const o = orientEdge(e.source, e.target, tier);
    if (o) ranking.push([o.from, o.to]);
  }
  for (const ie of inferredEdges) ranking.push([ie.from, ie.to]);
  // Anchor each bottom-lane node beneath the deepest placed rank so dagre ranks
  // them strictly last. Layout-only edges — not rendered.
  if (bottomLane.length) {
    const onBottom = new Set(bottomLane);
    const anchors = nodes
      .filter((n) => tier.get(n.node_id) === maxTier && !onBottom.has(n.node_id))
      .map((n) => n.node_id);
    const sources = anchors.length ? anchors : root != null ? [root] : [];
    for (const id of bottomLane) for (const a of sources) ranking.push([a, id]);
  }

  // Run dagre, then map its node centres back to React Flow top-left corners.
  const g = new dagre.graphlib.Graph();
  g.setGraph({ rankdir: "TB", nodesep: 64, ranksep: 96, marginx: 48, marginy: 48 });
  g.setDefaultEdgeLabel(() => ({}));
  for (const n of nodes) g.setNode(n.node_id, { width: NODE_W, height: NODE_H });
  for (const [from, to] of ranking) g.setEdge(from, to);
  dagre.layout(g);

  const outNodes = nodes.map((n) => {
    const { x, y } = g.node(n.node_id);
    return {
      id: n.node_id,
      type: "device",
      position: { x: x - NODE_W / 2, y: y - NODE_H / 2 },
      tier: tier.get(n.node_id) ?? bottomRank,
      data: n,
    };
  });

  // Rendered edges: every confirmed link (inferred:false) plus the dashed
  // inferred links so the UI can style them as tentative.
  const ids = new Set(nodes.map((n) => n.node_id));
  const confirmed = rawEdges
    .filter((e) => ids.has(e.source) && ids.has(e.target))
    .map((e, i) => ({
      id: `e${i}`,
      source: e.source,
      target: e.target,
      label: e.local_port || undefined,
      type: e.type,
      confidence: e.confidence,
      inferred: false,
    }));
  const inferred = inferredEdges.map((ie, i) => ({
    id: `inf${i}`,
    source: ie.from,
    target: ie.to,
    label: undefined,
    type: "inferred",
    inferred: true,
  }));

  return { nodes: outNodes, edges: [...confirmed, ...inferred] };
}

export const NODE_SIZE = { width: NODE_W, height: NODE_H };
