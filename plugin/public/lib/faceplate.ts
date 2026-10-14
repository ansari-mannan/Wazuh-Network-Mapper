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

export interface Faceplate {
  chassis: Chassis;
  width: number;
  height: number;
  /** where the vendor/model text and system LEDs go, from x = 0 */
  brandWidth: number;
  ports: PlacedPort[];
  captions: Caption[];
  /** captions sit above this y */
  captionY: number;
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

/**
 * Ports in a grid from (x0, y0). Two rows put the 1st, 3rd, ... port on top
 * and the 2nd, 4th, ... below (Cisco/HP numbering), in blocks of 12; one row
 * sits halfway down.
 */
function grid(
  ports: Array<{ port: DevicePort; kind: PortKind }>,
  x0: number,
  y0: number,
  twoRows: boolean,
  label: (p: DevicePort) => string
): { placed: PlacedPort[]; width: number } {
  if (!ports.length) return { placed: [], width: 0 };
  let right = x0;
  const placed = ports.map(({ port, kind }, i) => {
    const col = twoRows ? Math.floor(i / 2) : i;
    const bottom = twoRows && i % 2 === 1;
    const x = x0 + col * (PORT_W + GAP_X) + (twoRows ? Math.floor(col / 6) * BLOCK_GAP : 0);
    const y = y0 + (bottom ? PORT_H + GAP_Y : twoRows ? 0 : (PORT_H + GAP_Y) / 2);
    right = Math.max(right, x + PORT_W);
    return { port, kind, label: label(port), x, y, labelY: twoRows && !bottom ? y - 3 : y + PORT_H + 9 };
  });
  return { placed, width: right - x0 };
}

/**
 * The rack (and generic) panel: console/management on the left, the numbered
 * access ports in blocks of 12, and the uplinks (every other physical port:
 * the trailing Gi/Te/SFP ports) in their own block on the right.
 */
function rackLayout(physical: Array<{ port: DevicePort; kind: PortKind }>, brandWidth: number) {
  const top = 16;
  const consoles = physical.filter((p) => p.kind === 'console');
  const rest = physical.filter((p) => p.kind !== 'console');
  // the access ports are the biggest family; ties go to the first one seen
  const counts = new Map<string, number>();
  for (const { port } of rest) counts.set(family(port.name), (counts.get(family(port.name)) || 0) + 1);
  let accessFamily = '';
  for (const [f, n] of counts) if (n > (counts.get(accessFamily) || 0)) accessFamily = f;
  const access = rest.filter(({ port }) => family(port.name) === accessFamily);
  const uplinks = rest.filter(({ port }) => family(port.name) !== accessFamily);

  const ports: PlacedPort[] = [];
  const captions: Caption[] = [];
  let x = brandWidth;
  const block = (
    list: typeof physical,
    twoRows: boolean,
    label: (p: DevicePort) => string,
    caption: string
  ) => {
    if (!list.length) return;
    const { placed, width } = grid(list, x, top, twoRows, label);
    ports.push(...placed);
    if (caption) captions.push({ text: caption, x, width });
    x += width + GROUP_GAP;
  };
  block(consoles, false, (p) => shortName(p.name), 'MGMT');
  block(access, access.length >= 8, (p) => trailingNumber(p.name) || shortName(p.name), '');
  const allSfp = uplinks.every((p) => p.kind === 'sfp');
  block(
    uplinks,
    uplinks.length > 4,
    (p) => `${p.name.charAt(0).toUpperCase()}${trailingNumber(p.name) || ''}`,
    allSfp ? 'SFP' : 'UPLINK'
  );
  return {
    ports,
    captions,
    captionY: top - 4,
    width: Math.max(x - GROUP_GAP, brandWidth) + RIGHT_PAD,
    height: top * 2 + PORT_H * 2 + GAP_Y + 14,
  };
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
function rowLayout(physical: Array<{ port: DevicePort; kind: PortKind }>, brandWidth: number) {
  const top = 34;
  const groups = new Map<string, typeof physical>();
  for (const p of physical) {
    const g = p.kind === 'radio' ? 'RADIO' : groupOf(p.port.name);
    groups.set(g, [...(groups.get(g) || []), p]);
  }
  const order = [...groups.keys()].sort(
    (a, b) => (a === 'RADIO' ? -1 : b === 'RADIO' ? 1 : groupRank(a) - groupRank(b))
  );
  const ports: PlacedPort[] = [];
  const captions: Caption[] = [];
  let x = brandWidth;
  for (const g of order) {
    const label = (p: DevicePort) =>
      (g === 'INTERNAL' && trailingNumber(p.name)) || (g === 'RADIO' && (bandOf(p.name) || `R${trailingNumber(p.name) ?? ''}`)) || shortName(p.name);
    groups.get(g)!.forEach(({ port, kind }, i) => {
      const px = x + i * (PORT_W + 8);
      ports.push({ port, kind, label: label(port), x: px, y: top, labelY: top + PORT_H + 11 });
    });
    const width = groups.get(g)!.length * (PORT_W + 8) - 8;
    captions.push({ text: g, x, width });
    x += width + 20;
  }
  return { ports, captions, captionY: top - 10, width: Math.max(x - 20, brandWidth) + 16, height: 82 };
}

/** The whole front panel of one device. */
export function faceplateOf(node: DeviceNode): Faceplate {
  const chassis = chassisFor(node);
  const all = portsOf(node).map((port) => ({ port, kind: portKind(port) }));
  const logical = all.filter((p) => p.kind === 'logical' || (p.kind === 'radio' && chassis !== 'puck'));
  const physical = all.filter((p) => !logical.includes(p));
  const brandWidth = chassis === 'generic' ? 96 : chassis === 'puck' ? 110 : chassis === 'desktop' ? 150 : 120;
  const laid = chassis === 'desktop' || chassis === 'puck'
    ? rowLayout(physical, brandWidth)
    : rackLayout(physical, brandWidth);
  return { chassis, brandWidth, logical: logical.map((p) => p.port), ...laid };
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

/**
 * A port's tooltip, one fact per line: full name, alias, speed, state in
 * words, neighbours, and whether it is inferred or on the shown route.
 */
export function portTooltip(
  port: DevicePort,
  neighbours: Neighbour[],
  flags: { inferred?: boolean; onRoute?: boolean; clients?: number } = {}
): string[] {
  const lines = [port.name];
  if (flags.clients !== undefined) lines.push(`${flags.clients} Wi-Fi client${flags.clients === 1 ? '' : 's'}`);
  if (port.alias) lines.push(`Alias: ${port.alias}`);
  const speed = speedText(port.speed_mbps);
  lines.push(speed ? `${STATE_TEXT[port.state]} · ${speed}` : STATE_TEXT[port.state]);
  if (neighbours.length) lines.push(`Neighbour: ${neighbours.map((n) => n.text).join(', ')}`);
  if (flags.inferred) lines.push('Known from the neighbour’s side of the link');
  if (flags.onRoute) lines.push('On the highlighted attack route');
  return lines;
}
