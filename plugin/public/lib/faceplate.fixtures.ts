// Synthetic devices for the faceplate and wireless-link tests: made-up names
// and addresses, no captured MACs or serials.
import type { DeviceNode, DevicePort, EndpointNode, GraphEdge, GraphResponse, PortState } from '../../common';

export const port = (name: string, state: PortState = 'unused', extra: Partial<DevicePort> = {}): DevicePort => ({
  name,
  oper: state === 'up' ? 'up' : 'down',
  admin: state === 'shutdown' ? 'down' : 'up',
  type: /^(vlan|null|bvi)|\./i.test(name) ? 53 : 6,
  speed_mbps: null,
  alias: null,
  state,
  ...extra,
});

const range = (n: number) => Array.from({ length: n }, (_, i) => i + 1);

export function device(id: string, role: string, ports: DevicePort[] | undefined, extra: Partial<DeviceNode> = {}): DeviceNode {
  return {
    node_id: id,
    kind: 'device',
    ip: '192.0.2.1',
    hostname: id.replace('device:', ''),
    vendor: 'Cisco',
    model: null,
    firmware: null,
    serial: null,
    mac: null,
    discovery_method: 'snmp_lldp',
    status: 'online',
    role,
    risk_score: null,
    discovery_order: 1,
    parent_id: null,
    ...(ports ? { ports } : {}),
    ...extra,
  } as DeviceNode;
}

/** 24 Fast Ethernet access ports + 2 Gigabit uplinks, with VLANs. */
export const switch24 = device(
  'device:sw24',
  'l3-switch',
  [
    port('Vlan1', 'unused'),
    port('Vlan10', 'up'),
    ...range(24).map((n) =>
      port(
        `FastEthernet1/0/${n}`,
        [1, 2, 6, 15].includes(n) ? 'up' : n === 5 ? 'link_lost' : n === 24 ? 'shutdown' : 'unused',
        { speed_mbps: 100, alias: n === 1 ? 'Uplink to firewall' : null }
      )
    ),
    port('GigabitEthernet1/0/1', 'unused', { speed_mbps: 1000 }),
    port('GigabitEthernet1/0/2', 'unused', { speed_mbps: 1000 }),
    port('Null0', 'up', { type: 1 }),
  ],
  { model: 'WS-C3750-24TS', neighbor_ports: ['Fa1/0/1', 'Fa1/0/2', 'Fa1/0/5'] }
);

/** 48 Fast Ethernet access ports + 2 Gigabit uplinks. */
export const switch48 = device(
  'device:sw48',
  'l2-switch',
  [
    port('Vlan1', 'up'),
    ...range(48).map((n) => port(`FastEthernet0/${n}`, n === 1 || n === 7 ? 'up' : 'unused')),
    port('GigabitEthernet0/1', 'up'),
    port('GigabitEthernet0/2', 'unused'),
  ],
  { model: 'WS-C2960-48TT-L' }
);

/** An 8-port desk switch. */
export const switch8 = device(
  'device:sw8',
  'l2-switch',
  range(8).map((n) => port(`GigabitEthernet0/${n}`, n <= 2 ? 'up' : 'unused')),
  { model: 'Compact 8' }
);

/** A firewall: port1-7 inside, dmz, wan1 (named by its neighbour by alias), wan2. */
export const fortigate = device(
  'device:fw',
  'router',
  [
    ...range(7).map((n) => port(`port${n}`, n <= 3 ? 'up' : n === 4 ? 'link_lost' : 'unused')),
    port('dmz', 'shutdown'),
    port('wan1', 'up', { alias: 'Layer-3_UPLINK', speed_mbps: 1000 }),
    port('wan2', 'unused'),
    port('ssl.root', 'up', { type: 131 }),
  ],
  { vendor: 'Fortinet', model: 'FortiGate-60D', inferred_ports: ['Layer-3_UPLINK'], neighbor_ports: ['Layer-3_UPLINK'] }
);

/** A larger firewall: mgmt, ha, port1-16, wan1-2 and dmz1-2, in its own ifIndex order. */
export const fortigate200D = device(
  'device:fw200',
  'router',
  [
    port('mgmt', 'up'),
    port('ha', 'unused'),
    ...range(16).map((n) => port(`port${n}`, n <= 5 ? 'up' : n === 9 ? 'link_lost' : n === 16 ? 'shutdown' : 'unused')),
    port('wan1', 'up', { speed_mbps: 1000 }),
    port('wan2', 'unused'),
    port('dmz1', 'up', { speed_mbps: 100 }),
    port('dmz2', 'unused'),
  ],
  { vendor: 'Fortinet', model: 'FortiGate-200D' }
);

/** A firewall from an older graph: only port_status, FortiOS virtual interfaces among them. */
export const fortigateStatusOnly = device('device:fwold', 'router', undefined, {
  vendor: 'Fortinet',
  model: 'FortiGate-100E',
  port_status: {
    mgmt: 'up',
    port1: 'up',
    port2: 'up',
    port3: 'down',
    port4: 'down',
    wan1: 'up',
    wan2: 'down',
    dmz1: 'up',
    dmz2: 'down',
    modem: 'down',
    'ssl.root': 'up',
    lan: 'down',
  },
  neighbor_ports: ['port3'],
});

/** An access point with two radios. */
export const accessPoint = device(
  'device:ap',
  'access-point',
  [
    port('Dot11Radio0', 'up', { type: 71 }),
    port('Dot11Radio1', 'up', { type: 71 }),
    port('GigabitEthernet0', 'up', { speed_mbps: 1000 }),
    port('Dot11Radio0.80', 'up'),
    port('Dot11Radio1.80', 'up'),
    port('BVI1', 'up'),
  ],
  { model: 'AIR-AP1142N', wifi_clients: 3 }
);

/** A polled device of unknown role from an older graph: only port_status. */
export const unknownDevice = device('device:unknown', 'Unknown Network Device', undefined, {
  vendor: null,
  port_status: { 'Gi0/1': 'up', 'Gi0/2': 'down', 'Gi0/3': 'down', Vlan1: 'up' },
  neighbor_ports: ['Gi0/2'],
});

const host = (id: string, name: string, wifi?: EndpointNode['wifi']): EndpointNode =>
  ({
    node_id: id,
    kind: 'endpoint',
    ip: null,
    hostname: name,
    vendor: null,
    model: null,
    firmware: null,
    serial: null,
    mac: null,
    discovery_method: wifi ? 'snmp_wifi' : 'wazuh',
    status: 'active',
    role: 'host',
    risk_score: null,
    discovery_order: 2,
    parent_id: null,
    agent_id: null,
    top_cves: [],
    ...(wifi ? { wifi } : {}),
  } as EndpointNode);

const edge = (source: string, target: string, extra: Partial<GraphEdge>): GraphEdge => ({
  source,
  target,
  type: 'endpoint_link',
  source_name: source.split(':').pop(),
  target_name: target.split(':').pop(),
  ...extra,
});

/** The switch, the firewall and the AP linked, with wired and wireless clients. */
export const smallGraph: GraphResponse = {
  nodes: [
    switch24,
    fortigate,
    accessPoint,
    host('endpoint:101', 'wired-pc'),
    host('host:wifi1', 'laptop', { ssid: 'OFFICE', access_point: 'device:ap', radio: 'Dot11Radio0' }),
    host('host:wifi2', 'phone', { ssid: 'OFFICE-5G', access_point: 'device:ap', radio: 'Dot11Radio1' }),
    host('host:wifi3', 'tablet', { ssid: 'OFFICE-5G', access_point: 'device:ap', radio: 'Dot11Radio1' }),
  ],
  edges: [
    edge('device:fw', 'device:sw24', { type: 'lldp', local_port: 'Layer-3_UPLINK', remote_port: 'Fa1/0/1' }),
    edge('device:sw24', 'device:ap', { type: 'lldp', local_port: 'Fa1/0/6', remote_port: 'GigabitEthernet0', protocol: 'cdp' }),
    edge('endpoint:101', 'device:sw24', { local_port: 'Fa1/0/15', confidence: 'lldp' }),
    edge('host:wifi1', 'device:ap', { local_port: 'Dot11Radio0', confidence: 'wifi' }),
    edge('host:wifi2', 'device:ap', { local_port: 'Dot11Radio1', confidence: 'wifi' }),
    edge('host:wifi3', 'device:ap', { local_port: 'Dot11Radio1', confidence: 'wifi' }),
  ],
  metadata: {} as GraphResponse['metadata'],
};
