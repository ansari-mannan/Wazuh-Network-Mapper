// A network device's front panel, laid out from the scan's own port list:
// which ports are physical, where each one sits and what the chassis looks
// like. Nothing is per model; the count and the names decide. Pure (no React,
// no theme): components/device/Faceplate.tsx draws it.
import type { DeviceNode, DevicePort, GraphEdge, PortState } from '../../common';
import { bandOf } from './wireless';

export type PortKind = 'copper' | 'sfp' | 'console' | 'logical' | 'radio';
// rack 1U (switches), desktop box (routers, firewalls), puck (access points),
// or a plain box when the role is unknown or the graph has no port list
export type Chassis = 'rack' | 'desktop' | 'puck' | 'generic';

export interface PlacedPort {
  port: DevicePort;
  kind: PortKind;
  label: string;
  x: number;
  y: number;
  labelY: number;
}

export interface Caption {
  text: string;
  x: number;
  width: number;
}

export interface PanelText {
  text: string;
  x: number;
  /** baseline */
  y: number;
  size: number;
  bold?: boolean;
}

export interface Faceplate {
  chassis: Chassis;
  width: number;
  height: number;
  /** where the vendor/model text and system LEDs go, from x = 0 */
  brandWidth: number;
  ports: PlacedPort[];
  captions: Caption[];
  /** the captions' baseline; their rule is 3 below */
  captionY: number;
  /** text on the chassis itself (vendor, model) */
  texts: PanelText[];
  /** Vlan, Loopback, sub-interfaces...: listed under the panel, not drawn on it */
  logical: DevicePort[];
}

export const PORT_W = 22;
export const PORT_H = 18;
const GAP_X = 4;
const GAP_Y = 6;
const BLOCK_GAP = 12; // between blocks of 12 access ports
const GROUP_GAP = 22; // between console, access and uplink blocks
const RIGHT_PAD = 12;

/** Above this many physical ports the card shows a compact panel and an Expand button. */
export const COMPACT_ABOVE = 26;

/**
 * Port names compared in any form: "FastEthernet1/0/3" = "Fa1/0/3" (the
 * backend's checklist port_key).
 */
export function portKey(name: string): string {
  const m = /^\s*([A-Za-z][A-Za-z-]*)\s*(.*)$/.exec(String(name ?? ''));
  return m ? `${m[1].slice(0, 2).toLowerCase()}|${m[2].trim()}` : `${String(name).toLowerCase()}|`;
}

const LOGICAL_NAME = /^(vlan|vl\d|loopback|lo\d|port-channel|po\d|tunnel|tu\d|null|nu\d|stack|bvi)/i;
const RADIO_NAME = /^dot11radio/i;
const CONSOLE_NAME = /^(console|con\d|mgmt|management|me\d|aux|ha\d*$)/i;
const SFP_NAME = /^(te\d|tengig|twe|fo\d|forty|hu\d|hundred|sfp|xe-)/i;
// IANAifType: other, softwareLoopback, propVirtual, tunnel, l2vlan, l3ipvlan, ieee8023adLag
const LOGICAL_TYPES = new Set([1, 24, 53, 131, 135, 136, 161]);
const RADIO_TYPE = 71; // ieee80211

/** What a port is: by its name first, then by its ifType. */
export function portKind(port: Pick<DevicePort, 'name' | 'type' | 'speed_mbps'>): PortKind {
  const { name, type } = port;
  // a sub-interface (Gi0.80, Dot11Radio0.80, ssl.root) is never a socket
  if (name.includes('.')) return 'logical';
  if (RADIO_NAME.test(name)) return 'radio';
  if (LOGICAL_NAME.test(name)) return 'logical';
  if (CONSOLE_NAME.test(name)) return 'console';
  if (SFP_NAME.test(name)) return 'sfp';
  if (type === RADIO_TYPE) return 'radio';
  if (type != null && LOGICAL_TYPES.has(type)) return 'logical';
  if ((port.speed_mbps ?? 0) >= 10000) return 'sfp';
  return 'copper';
}

/**
 * The device's ports: its `ports` list, or for an older graph one built from
 * port_status (no admin state there, so never "shutdown").
 */
export function portsOf(node: DeviceNode): DevicePort[] {
  if (node.ports && node.ports.length) return node.ports;
  const plugged = new Set((node.neighbor_ports || []).map(portKey));
  return Object.entries(node.port_status || {}).map(([name, oper]) => ({
    name,
    oper,
    state: (oper === 'up' ? 'up' : plugged.has(portKey(name)) ? 'link_lost' : 'unused') as PortState,
  }));
}

export function chassisFor(node: DeviceNode): Chassis {
  if (!node.ports || !node.ports.length) return 'generic';
  switch (node.role) {
    case 'l2-switch':
    case 'l3-switch':
      return 'rack';
    case 'router':
    case 'firewall':
      return 'desktop';
    case 'access-point':
      return 'puck';
    default:
      return 'generic';
  }
}

const trailingNumber = (name: string) => (/(\d+)$/.exec(name) || [])[1];
// "FastEthernet1/0/" for "FastEthernet1/0/7": ports of one family share it
const family = (name: string) => name.replace(/\d+$/, '');

/** "GigabitEthernet1/0/24" -> "Gi1/0/24"; short names ("wan1", "dmz") in capitals. */
export function shortName(name: string): string {
  if (name.length <= 5) return name.toUpperCase();
  const m = /^([A-Za-z])([A-Za-z])[A-Za-z-]*\s*(.*)$/.exec(name);
  return m && m[3] ? `${m[1].toUpperCase()}${m[2].toLowerCase()}${m[3]}` : name;
}

// ---- vertical bands --------------------------------------------------------
// Every panel has the same bands, top to bottom: the group captions with
// their rule, the labels of the top row, the top row, the bottom row and its
// labels. A caption never shares a line with a port label, and a label sits
// only above the top row or below the bottom row (a one-row block sits
// halfway down with its labels below it, in its own columns).
export const CAPTION_SIZE = 7.5;
export const LABEL_SIZE = 7;
const CAPTION_Y = 10; // caption baseline; its rule is 3 below
const ROW1_ONE = 24; // the row of a one-row panel
const ROW1_TWO = 27; // the top row of a two-row panel
const LABEL_GAP = 4; // from a row to the baseline above it / the label's top below it

/** A text's width as drawn (generous: capitals of the dashboard's sans font). */
export const textWidth = (text: string, size: number) => text.length * size * 0.65;

/** `text` cut with an ellipsis to fit `width` at font `size`. */
export function fitText(text: string, width: number, size: number): string {
  const max = Math.floor(width / (size * 0.65));
  return text.length <= max ? text : `${text.slice(0, Math.max(1, max - 1))}…`;
}

type Entry = { port: DevicePort; kind: PortKind };

interface Block {
  list: Entry[];
  twoRows: boolean;
  label: (p: DevicePort) => string;
  caption: string;
  /** columns per block of ports before a wider gap (6 = blocks of 12 ports on two rows) */
  blockCols?: number;
  /** space before this block (default GROUP_GAP) */
  gapBefore?: number;
}

/**
 * Places the blocks left to right from `x0`: a block's width is its ports'
 * or its caption's, whichever is wider, so captions never run into each other.
 */
function placeBlocks(blocks: Block[], x0: number) {
  blocks = blocks.filter((b) => b.list.length);
  const rows = blocks.some((b) => b.twoRows) ? 2 : 1;
  const row1 = rows === 2 ? ROW1_TWO : ROW1_ONE;
  const row2 = row1 + PORT_H + GAP_Y;
  const middle = (row1 + row2) / 2;
  const below = (y: number) => y + PORT_H + LABEL_GAP + LABEL_SIZE;
  const ports: PlacedPort[] = [];
  const captions: Caption[] = [];
  let x = x0;
  blocks.forEach((b, n) => {
    if (n > 0) x += b.gapBefore ?? GROUP_GAP;
    let right = x;
    // columns wide enough for the block's longest label
    const pitch = Math.max(PORT_W + GAP_X, ...b.list.map(({ port }) => textWidth(b.label(port), LABEL_SIZE) + 3));
    b.list.forEach(({ port, kind }, i) => {
      const col = b.twoRows ? Math.floor(i / 2) : i;
      const bottom = b.twoRows && i % 2 === 1;
      const px = x + col * pitch + Math.floor(col / (b.blockCols ?? Infinity)) * BLOCK_GAP;
      const y = !b.twoRows ? (rows === 2 ? middle : row1) : bottom ? row2 : row1;
      const labelY = b.twoRows && !bottom ? row1 - LABEL_GAP : below(y);
      ports.push({ port, kind, label: b.label(port), x: px, y, labelY });
      right = Math.max(right, px + PORT_W);
    });
    const width = Math.max(right - x, b.caption ? textWidth(b.caption, CAPTION_SIZE) : 0);
    if (b.caption) captions.push({ text: b.caption, x, width });
    x += width;
  });
  return {
    ports,
    captions,
    captionY: CAPTION_Y,
    right: x,
    height: (rows === 2 ? below(row2) : below(row1)) + 8,
  };
}

/**
 * The rack (and generic) panel: console/management on the left, the numbered
 * access ports in blocks of 12 (odd on top, even below; fewer than 8 in one
 * row), and the uplinks (every other physical port: the trailing Gi/Te/SFP
 * ports) in their own block on the right.
 */
function rackBlocks(physical: Entry[]): Block[] {
  const consoles = physical.filter((p) => p.kind === 'console');
  const rest = physical.filter((p) => p.kind !== 'console');
  // the access ports are the biggest family; ties go to the first one seen
  const counts = new Map<string, number>();
  for (const { port } of rest) counts.set(family(port.name), (counts.get(family(port.name)) || 0) + 1);
  let accessFamily = '';
  for (const [f, n] of counts) if (n > (counts.get(accessFamily) || 0)) accessFamily = f;
  const access = rest.filter(({ port }) => family(port.name) === accessFamily);
  const uplinks = rest.filter(({ port }) => family(port.name) !== accessFamily);
  return [
    { list: consoles, twoRows: false, label: (p) => shortName(p.name), caption: 'MGMT' },
    {
      list: access,
      twoRows: access.length >= 8,
      label: (p) => trailingNumber(p.name) || shortName(p.name),
      caption: '',
      blockCols: 6,
    },
    {
      list: uplinks,
      twoRows: uplinks.length > 4,
      label: (p) => `${p.name.charAt(0).toUpperCase()}${trailingNumber(p.name) || ''}`,
      caption: uplinks.every((p) => p.kind === 'sfp') ? 'SFP' : 'UPLINK',
    },
  ];
}

const DESKTOP_GROUPS: Array<[RegExp, string]> = [
  [/^(port|internal|lan)\d*$/i, 'INTERNAL'],
  [/^dmz\d*$/i, 'DMZ'],
  [/^wan\d*$/i, 'WAN'],
];
const groupOf = (name: string) =>
  (DESKTOP_GROUPS.find(([re]) => re.test(name)) || [null, name.slice(0, 2).toUpperCase()])[1];
// INTERNAL first and the WAN side last, like the box's own print
const groupRank = (g: string) => (g === 'INTERNAL' ? 0 : g === 'DMZ' ? 2 : g === 'WAN' ? 3 : 1);

/**
 * A desktop box (router, firewall) or an access point's puck: one row of
 * sockets, grouped and captioned by name family (port1-7 as INTERNAL, dmz,
 * wan1-2...). An access point's radios come first, as antenna LEDs.
 */
function rowBlocks(physical: Entry[]): Block[] {
  const groups = new Map<string, Entry[]>();
  for (const p of physical) {
    const g = p.kind === 'radio' ? 'RADIO' : groupOf(p.port.name);
    groups.set(g, [...(groups.get(g) || []), p]);
  }
  const order = [...groups.keys()].sort(
    (a, b) => (a === 'RADIO' ? -1 : b === 'RADIO' ? 1 : groupRank(a) - groupRank(b))
  );
  return order.map((g) => ({
    list: groups.get(g)!,
    twoRows: false,
    caption: g,
    gapBefore: 20,
    label: (p: DevicePort) =>
      (g === 'INTERNAL' && trailingNumber(p.name)) ||
      (g === 'RADIO' && (bandOf(p.name) || `R${trailingNumber(p.name) ?? ''}`)) ||
      shortName(p.name),
  }));
}

/** The whole front panel of one device. */
export function faceplateOf(node: DeviceNode): Faceplate {
  const chassis = chassisFor(node);
  const all = portsOf(node).map((port) => ({ port, kind: portKind(port) }));
  const logical = all.filter((p) => p.kind === 'logical' || (p.kind === 'radio' && chassis !== 'puck'));
  const physical = all.filter((p) => !logical.includes(p));
  const brandWidth = chassis === 'generic' ? 96 : chassis === 'puck' ? 110 : chassis === 'desktop' ? 150 : 120;
  const blocks = chassis === 'desktop' || chassis === 'puck' ? rowBlocks(physical) : rackBlocks(physical);
  const { ports, captions, captionY, right, height } = placeBlocks(blocks, brandWidth);
  // vendor and model, plain text, cut to the brand area
  const textX = chassis === 'puck' ? 30 : 14;
  const room = brandWidth - textX - 8;
  const texts: PanelText[] = [];
  if (node.vendor) texts.push({ text: fitText(node.vendor, room, 10), x: textX, y: 26, size: 10, bold: true });
  if (node.model) texts.push({ text: fitText(node.model, room, 8), x: textX, y: 40, size: 8 });
  return {
    chassis,
    brandWidth,
    logical: logical.map((p) => p.port),
    ports,
    captions,
    captionY,
    texts,
    width: Math.max(right, brandWidth) + (chassis === 'desktop' || chassis === 'puck' ? 16 : RIGHT_PAD),
    height,
  };
}

export interface TextBox {
  text: string;
  x: number;
  y: number;
  w: number;
  h: number;
}

/** Every text the full-size panel draws, as a box (captions, port labels, brand texts). */
export function textBoxes(fp: Faceplate): TextBox[] {
  const box = (text: string, x: number, base: number, size: number, middle = false): TextBox => {
    const w = textWidth(text, size);
    return { text, x: middle ? x - w / 2 : x, y: base - 0.8 * size, w, h: size * 1.05 };
  };
  return [
    ...fp.captions.map((c) => box(c.text, c.x, fp.captionY, CAPTION_SIZE)),
    ...fp.ports.map((p) => box(p.label, p.x + PORT_W / 2, p.labelY, LABEL_SIZE, true)),
    ...fp.texts.map((t) => box(t.text, t.x, t.y, t.size)),
  ];
}

// ---- what is plugged in -------------------------------------------------------

export interface Neighbour {
  nodeId: string;
  /** "L2-Switch Fa0/1", or a host's name */
  text: string;
}

/**
 * Who sits on each of the device's ports, keyed by portKey: the far end of
 * its device links (with that end's port) and the hosts placed on it.
 */
export function portNeighbours(nodeId: string, edges: GraphEdge[]): Map<string, Neighbour[]> {
  const out = new Map<string, Neighbour[]>();
  const add = (port: string | undefined, nb: Neighbour) => {
    if (!port) return;
    const key = portKey(port);
    out.set(key, [...(out.get(key) || []), nb]);
  };
  const named = (id: string, name: string | undefined, port?: string) =>
    `${name || id}${port ? ` ${port}` : ''}`;
  for (const e of edges) {
    if (e.type === 'lldp') {
      // local_port is the recorded source's port, remote_port the target's
      if (e.source === nodeId) add(e.local_port, { nodeId: e.target, text: named(e.target, e.target_name, e.remote_port) });
      else if (e.target === nodeId) add(e.remote_port, { nodeId: e.source, text: named(e.source, e.source_name, e.local_port) });
    } else if (e.target === nodeId) {
      add(e.local_port, { nodeId: e.source, text: named(e.source, e.source_name) });
    }
  }
  return out;
}

/** A port's neighbours, matched by its name or its alias. */
export function neighboursOf(port: DevicePort, byPort: Map<string, Neighbour[]>): Neighbour[] {
  const keys = new Set([portKey(port.name), ...(port.alias ? [portKey(port.alias)] : [])]);
  return [...keys].flatMap((k) => byPort.get(k) || []);
}

/** Whether a port is known only from its neighbour's side of the link (inferred_ports). */
export function isInferred(port: DevicePort, node: DeviceNode): boolean {
  const inferred = new Set((node.inferred_ports || []).map(portKey));
  return inferred.has(portKey(port.name)) || (!!port.alias && inferred.has(portKey(port.alias)));
}

/**
 * The ports a highlighted route leaves or enters this device by: those whose
 * neighbour is the node before or after it in the route walk.
 */
export function routePortKeys(nodeId: string, walk: string[], byPort: Map<string, Neighbour[]>): Set<string> {
  const adjacent = new Set<string>();
  walk.forEach((id, i) => {
    if (id !== nodeId) return;
    if (i > 0) adjacent.add(walk[i - 1]);
    if (i + 1 < walk.length) adjacent.add(walk[i + 1]);
  });
  const keys = new Set<string>();
  for (const [key, nbs] of byPort) if (nbs.some((nb) => adjacent.has(nb.nodeId))) keys.add(key);
  return keys;
}

/** A port's state in words, for its tooltip. */
export const STATE_TEXT: Record<PortState, string> = {
  up: 'Up',
  link_lost: 'Down: link lost',
  unused: 'Not connected',
  shutdown: 'Shut down (admin)',
};

/** "100 Mb/s", "1 Gb/s", "10 Gb/s"; '' when unknown. */
export function speedText(mbps: number | null | undefined): string {
  if (!mbps) return '';
  return mbps >= 1000 ? `${mbps / 1000} Gb/s` : `${mbps} Mb/s`;
}

/** A hover/focus tooltip: a bold title, plain lines, and the route line in violet. */
export interface TipContent {
  title: string;
  lines: string[];
  route?: boolean;
}

export const ROUTE_LINE = 'On an attack route';

/** The tooltip as one sentence per line, for an aria-label. */
export function tipText(tip: TipContent): string {
  return [tip.title, ...tip.lines, ...(tip.route ? [ROUTE_LINE] : [])].join('. ');
}

/**
 * A port's tooltip: its full name, then the state in words, an access
 * point radio's client count, alias, speed, neighbours, whether it is
 * inferred, and whether it is on the shown route.
 */
export function portTooltip(
  port: DevicePort,
  neighbours: Neighbour[],
  flags: { inferred?: boolean; onRoute?: boolean; clients?: number } = {}
): TipContent {
  const lines = [STATE_TEXT[port.state]];
  if (flags.clients !== undefined) lines.push(`${flags.clients} Wi-Fi client${flags.clients === 1 ? '' : 's'}`);
  if (port.alias) lines.push(`Alias: ${port.alias}`);
  const speed = speedText(port.speed_mbps);
  if (speed) lines.push(`Speed: ${speed}`);
  if (neighbours.length) lines.push(`Neighbour: ${neighbours.map((n) => n.text).join(', ')}`);
  if (flags.inferred) lines.push('Known from the neighbour’s side of the link');
  return { title: port.name, lines, route: Boolean(flags.onRoute) };
}
