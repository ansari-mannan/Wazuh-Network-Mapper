import type { DeviceNode } from '../../common';
import {
  chassisFor,
  faceplateOf,
  isInferred,
  neighboursOf,
  portKey,
  portKind,
  portNeighbours,
  portsOf,
  pickLayout,
  portTooltip,
  tipText,
  routePortKeys,
  shortName,
  speedText,
  speedLed,
  textWidth,
  textBoxes,
  PORT_W,
  PORT_H,
} from './faceplate';
import {
  accessPoint,
  fortigate,
  fortigate200D,
  fortigateStatusOnly,
  fortigateLabStyle,
  port,
  smallGraph,
  switch24,
  switch48,
  switch8,
  switchHp48,
  unknownDevice,
} from './faceplate.fixtures';

const byName = (fp: ReturnType<typeof faceplateOf>) => new Map(fp.ports.map((p) => [p.port.name, p]));

describe('portKind', () => {
  it.each([
    ['FastEthernet1/0/1', 6, 'copper'],
    ['GigabitEthernet0/1', 6, 'copper'],
    ['TenGigabitEthernet1/1/1', 6, 'sfp'],
    ['Te1/1/2', null, 'sfp'],
    ['mgmt', 6, 'console'],
    ['Console', null, 'console'],
    ['Vlan10', 53, 'logical'],
    ['Loopback0', 24, 'logical'],
    ['Port-channel1', 161, 'logical'],
    ['Po2', null, 'logical'],
    ['Tunnel5', 131, 'logical'],
    ['Null0', 1, 'logical'],
    ['StackPort1', 53, 'logical'],
    ['BVI1', 53, 'logical'],
    ['GigabitEthernet0.80', 135, 'logical'],
    ['Dot11Radio0', 71, 'radio'],
    ['Dot11Radio0.80', 135, 'logical'],
    ['wlan0', 71, 'radio'], // no name rule: the ifType decides
    ['ifx', 136, 'logical'],
    ['port1', 6, 'copper'],
    // FortiOS virtual interfaces, with no ifType (a port_status-only graph)
    ['ssl.root', null, 'logical'],
    ['naf.root', null, 'logical'],
    ['l2t.root', null, 'logical'],
    ['modem', null, 'logical'],
    ['npu0_vlink0', null, 'logical'],
    ['fortilink', null, 'logical'],
    ['vsys_ha', null, 'logical'],
    ['root', null, 'logical'],
    ['lan', null, 'copper'],
    ['srv-net', null, 'copper'],
  ])('%s (ifType %s) is %s', (name, type, kind) => {
    expect(portKind({ name, type })).toBe(kind);
  });

  it('takes a 10 Gb/s port of unknown name as SFP', () => {
    expect(portKind({ name: 'eth9', type: 6, speed_mbps: 10000 })).toBe('sfp');
  });
});

describe('names', () => {
  it('compares port names in any form', () => {
    expect(portKey('FastEthernet1/0/3')).toBe(portKey('Fa1/0/3'));
    expect(portKey('GigabitEthernet0')).toBe(portKey('Gi0'));
    expect(portKey('Fa0/1')).not.toBe(portKey('Fa0/10'));
  });

  it('shortens long names and capitalises short ones', () => {
    expect(shortName('GigabitEthernet1/0/24')).toBe('Gi1/0/24');
    expect(shortName('wan1')).toBe('WAN1');
    expect(speedText(100)).toBe('100 Mb/s');
    expect(speedText(1000)).toBe('1 Gb/s');
    expect(speedText(null)).toBe('');
  });
});

describe('chassis by role', () => {
  it.each([
    [switch24, 'rack'],
    [switch48, 'rack'],
    [fortigate, 'desktop'],
    [accessPoint, 'puck'],
    [unknownDevice, 'generic'],
    [{ ...switch8, role: 'phone' }, 'generic'],
    // no ports list (an older graph's port_status): the role still decides
    [fortigateStatusOnly, 'desktop'],
    [{ ...switch8, ports: undefined, port_status: { 'Gi0/1': 'up' } }, 'rack'],
    [{ ...accessPoint, ports: undefined, port_status: { Dot11Radio0: 'up' } }, 'puck'],
  ])('%#', (node, chassis) => {
    expect(chassisFor(node as any)).toBe(chassis);
  });
});

describe('rack layout', () => {
  it('24+2: two blocks of 12, odd ports on top, uplinks in their own block on the right', () => {
    const fp = faceplateOf(switch24);
    const ports = byName(fp);
    expect(fp.ports).toHaveLength(26);
    expect(fp.logical.map((p) => p.name)).toEqual(['Vlan1', 'Vlan10', 'Null0']);
    const p = (n: number) => ports.get(`FastEthernet1/0/${n}`)!;
    expect(p(1).y).toBe(p(3).y);
    expect(p(2).y).toBeGreaterThan(p(1).y);
    expect(p(2).x).toBe(p(1).x);
    expect(p(1).label).toBe('1');
    // ports 12 and 13 sit in different blocks: a wider gap than within a block
    const step = p(3).x - p(1).x;
    expect(p(13).x - p(11).x).toBeGreaterThan(step);
    const g1 = ports.get('GigabitEthernet1/0/1')!;
    expect(g1.x).toBeGreaterThan(p(24).x + 20);
    expect(g1.label).toBe('G1');
    expect(g1.kind).toBe('copper');
    expect(fp.captions.map((c) => c.text)).toEqual(['UPLINK']);
    expect(fp.width).toBeGreaterThan(g1.x + 22);
  });

  it('48+2: four blocks, and a wider chassis than 24 ports', () => {
    const fp = faceplateOf(switch48);
    const xs = fp.ports.filter((p) => p.port.name.startsWith('Fast')).map((p) => p.x);
    const gaps = xs.slice(1).map((x, i) => x - xs[i]).filter((d) => d > 26);
    expect(gaps).toHaveLength(3); // between blocks 1-2, 2-3, 3-4
    expect(fp.width).toBeGreaterThan(faceplateOf(switch24).width);
    expect(fp.ports).toHaveLength(50);
  });

  it('8 ports fill two rows of four; 7 go in one row', () => {
    const eight = faceplateOf(switch8);
    expect(new Set(eight.ports.map((p) => p.y)).size).toBe(2);
    const seven = faceplateOf({ ...switch8, ports: switch8.ports!.slice(0, 7) });
    expect(new Set(seven.ports.map((p) => p.y)).size).toBe(1);
    expect(seven.width).toBeLessThan(faceplateOf(switch24).width);
  });

  it('puts console and management ports on the left', () => {
    const fp = faceplateOf({ ...switch8, ports: [...switch8.ports!, port('mgmt0', 'up')] });
    const mgmt = byName(fp).get('mgmt0')!;
    expect(Math.min(...fp.ports.map((p) => p.x))).toBe(mgmt.x);
    expect(fp.captions[0].text).toBe('MGMT');
  });

  it('labels a 10G uplink block SFP', () => {
    const fp = faceplateOf({
      ...switch8,
      ports: [...switch8.ports!, port('TenGigabitEthernet1/1/1'), port('TenGigabitEthernet1/1/2')],
    });
    expect(fp.captions.map((c) => c.text)).toEqual(['SFP']);
    expect(byName(fp).get('TenGigabitEthernet1/1/1')!.kind).toBe('sfp');
  });
});

describe('desktop layout (firewall)', () => {
  it('groups by name family: INTERNAL, DMZ, WAN (internet), in one row', () => {
    const fp = faceplateOf(fortigate);
    expect(fp.captions.map((c) => c.text)).toEqual(['INTERNAL', 'DMZ', 'WAN (internet)']);
    expect(fp.ports.map((p) => p.label)).toEqual(['1', '2', '3', '4', '5', '6', '7', 'DMZ', 'WAN1', 'WAN2']);
    expect(new Set(fp.ports.map((p) => p.y)).size).toBe(1);
    expect(fp.logical.map((p) => p.name)).toEqual(['ssl.root']);
  });

  it('knows wan1 only from its neighbour, by alias', () => {
    const wan1 = fortigate.ports!.find((p) => p.name === 'wan1')!;
    expect(isInferred(wan1, fortigate)).toBe(true);
    expect(isInferred(fortigate.ports![0], fortigate)).toBe(false);
  });
});

describe('desktop layout (FortiGate 200D)', () => {
  const fp = faceplateOf(fortigate200D);
  const x = (name: string) => fp.ports.find((p) => p.port.name === name)!.x;

  it('groups MGMT/HA, INTERNAL, DMZ, then WAN (internet), each captioned', () => {
    expect(fp.captions.map((c) => c.text)).toEqual(['MGMT/HA', 'INTERNAL', 'DMZ', 'WAN (internet)']);
    expect(fp.ports.map((p) => p.port.name)).toEqual([
      'mgmt', 'ha', ...Array.from({ length: 16 }, (_, i) => `port${i + 1}`), 'dmz1', 'dmz2', 'wan1', 'wan2',
    ]);
  });

  it('shows every port exactly once, labelled by its full short name', () => {
    const names = fp.ports.map((p) => p.port.name);
    expect(new Set(names).size).toBe(names.length);
    expect(names).toHaveLength(fortigate200D.ports!.length);
    expect(fp.ports.map((p) => p.label)).toEqual([
      'MGMT', 'HA', ...Array.from({ length: 16 }, (_, i) => String(i + 1)), 'DMZ1', 'DMZ2', 'WAN1', 'WAN2',
    ]);
    // a number, or a whole name in capitals: never a one-letter abbreviation like "W1"
    for (const p of fp.ports) expect(p.label).toMatch(/^(\d+|[A-Z]{2,}\d*)$/);
  });

  it('puts 16 internal ports on two rows, 1-8 on top and 9-16 below, not odd/even', () => {
    expect(x('port1')).toBe(x('port9'));
    expect(fp.ports.find((p) => p.port.name === 'port2')!.y).toBe(fp.ports.find((p) => p.port.name === 'port1')!.y);
    expect(fp.ports.find((p) => p.port.name === 'port9')!.y).toBeGreaterThan(fp.ports.find((p) => p.port.name === 'port1')!.y);
  });

  it('keeps WAN rightmost, behind a divider and a wider gap', () => {
    const others = fp.ports.filter((p) => !p.port.name.startsWith('wan'));
    const lastOther = Math.max(...others.map((p) => p.x + PORT_W));
    const wanCaption = fp.captions.find((c) => c.text === 'WAN (internet)')!;
    expect(Math.min(x('wan1'), x('wan2'))).toBeGreaterThan(lastOther);
    expect(fp.captions[fp.captions.length - 1]).toBe(wanCaption);
    expect(fp.dividers).toHaveLength(1);
    const dmzCaption = fp.captions.find((c) => c.text === 'DMZ')!;
    expect(fp.dividers[0]).toBeGreaterThan(Math.max(lastOther, dmzCaption.x + dmzCaption.width));
    expect(fp.dividers[0]).toBeLessThan(x('wan1'));
    expect(x('wan1') - lastOther).toBeGreaterThan(30);
  });

  it('switches have no divider', () => {
    expect(faceplateOf(switch24).dividers).toEqual([]);
  });
});

describe('puck layout (access point)', () => {
  it('shows the radios first, as their own group, and folds the sub-interfaces', () => {
    const fp = faceplateOf(accessPoint);
    expect(fp.chassis).toBe('puck');
    expect(fp.ports.map((p) => [p.port.name, p.kind])).toEqual([
      ['Dot11Radio0', 'radio'],
      ['Dot11Radio1', 'radio'],
      ['GigabitEthernet0', 'copper'],
    ]);
    expect(fp.captions.map((c) => c.text)).toEqual(['RADIO', 'PORTS']);
    expect(fp.ports.map((p) => p.label)).toEqual(['2.4 GHz', '5 GHz', 'Gi0']);
    expect(fp.logical.map((p) => p.name)).toEqual(['Dot11Radio0.80', 'Dot11Radio1.80', 'BVI1']);
  });
});

describe('generic layout', () => {
  it('is built from port_status when the graph has no port list', () => {
    const fp = faceplateOf(unknownDevice);
    expect(fp.chassis).toBe('generic');
    expect(portsOf(unknownDevice).map((p) => [p.name, p.state])).toEqual([
      ['Gi0/1', 'up'],
      ['Gi0/2', 'link_lost'], // a neighbour is listed on it
      ['Gi0/3', 'unused'],
      ['Vlan1', 'up'],
    ]);
    expect(fp.ports.map((p) => p.port.name)).toEqual(['Gi0/1', 'Gi0/2', 'Gi0/3']);
    expect(fp.logical.map((p) => p.name)).toEqual(['Vlan1']);
  });

  it('is empty, not broken, with no ports at all', () => {
    const fp = faceplateOf({ ...unknownDevice, port_status: undefined });
    expect(fp.ports).toEqual([]);
    expect(fp.width).toBeGreaterThan(0);
  });
});

describe('neighbours', () => {
  const byPort = portNeighbours('device:sw24', smallGraph.edges);

  it('names the far end of each link and the hosts on each port', () => {
    const fa = (n: number) => neighboursOf(switch24.ports!.find((p) => p.name === `FastEthernet1/0/${n}`)!, byPort);
    expect(fa(1)).toEqual([{ nodeId: 'device:fw', text: 'fw Layer-3_UPLINK' }]);
    expect(fa(6)).toEqual([{ nodeId: 'device:ap', text: 'ap GigabitEthernet0' }]);
    expect(fa(15)).toEqual([{ nodeId: 'endpoint:101', text: '101' }]);
    expect(fa(3)).toEqual([]);
  });

  it('matches a port by its alias on the other side', () => {
    const fw = portNeighbours('device:fw', smallGraph.edges);
    const wan1 = fortigate.ports!.find((p) => p.name === 'wan1')!;
    expect(neighboursOf(wan1, fw)).toEqual([{ nodeId: 'device:sw24', text: 'sw24 Fa1/0/1' }]);
  });

  it('finds the ports a route enters and leaves by', () => {
    const keys = routePortKeys('device:sw24', ['device:fw', 'device:sw24', 'device:ap'], byPort);
    expect([...keys].sort()).toEqual([portKey('Fa1/0/1'), portKey('Fa1/0/6')].sort());
    expect(routePortKeys('device:sw24', ['endpoint:101'], byPort).size).toBe(0);
  });
});

describe('portTooltip', () => {
  it('gives the name as title, then state, alias, speed, neighbour, and the route flag', () => {
    const fa1 = switch24.ports!.find((p) => p.name === 'FastEthernet1/0/1')!;
    const tip = portTooltip(fa1, [{ nodeId: 'device:fw', text: 'fw wan1' }], { onRoute: true });
    expect(tip).toEqual({
      title: 'FastEthernet1/0/1',
      lines: ['Up', 'Alias: Uplink to firewall', 'Speed: 100 Mb/s', 'Neighbour: fw wan1'],
      route: true,
    });
    expect(tipText(tip)).toBe(
      'FastEthernet1/0/1. Up. Alias: Uplink to firewall. Speed: 100 Mb/s. Neighbour: fw wan1. On an attack route'
    );
    expect(portTooltip(port('dmz', 'shutdown'), [])).toEqual({ title: 'dmz', lines: ['Shut down (admin)'], route: false });
  });
});

describe('no overlapping text', () => {
  const fixtures: Array<[string, DeviceNode]> = [
    ['24+2 switch', switch24],
    ['48+2 switch', switch48],
    ['48+4 HP switch', switchHp48],
    ['8-port switch', switch8],
    ['7-port switch', { ...switch8, ports: switch8.ports!.slice(0, 7) }],
    ['switch with mgmt and 10G uplinks', {
      ...switch8,
      ports: [port('mgmt0', 'up'), ...switch8.ports!, port('TenGigabitEthernet1/1/1'), port('TenGigabitEthernet1/1/2')],
    }],
    ['FortiGate 60D', fortigate],
    ['FortiGate 200D', fortigate200D],
    ['FortiGate with only port_status', fortigateStatusOnly],
    ['lab-style FortiGate', fortigateLabStyle],
    ['access point', accessPoint],
    ['unknown device', unknownDevice],
  ];
  const hit = (a: { x: number; y: number; w: number; h: number }, b: typeof a) =>
    a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h;

  // every fixture in every layout: one row, split (a narrow card) and banded (a big rack)
  const cases = fixtures.flatMap(([name, node]) => [
    [name, node, {}],
    [`${name}, split`, node, { split: true }],
    [`${name}, banded`, node, { banded: true }],
  ]) as Array<[string, DeviceNode, { split?: boolean; banded?: boolean }]>;
  it.each(cases)('%s', (_name, node, options) => {
    const fp = faceplateOf(node, options);
    const boxes = textBoxes(fp);
    for (let i = 0; i < boxes.length; i++) {
      for (let j = i + 1; j < boxes.length; j++) {
        if (hit(boxes[i], boxes[j])) throw new Error(`"${boxes[i].text}" overlaps "${boxes[j].text}"`);
      }
    }
    // no text on a socket, and every label clear of the caption rule and inside the chassis
    const sockets = fp.ports.map((p) => ({ x: p.x, y: p.y, w: PORT_W, h: PORT_H }));
    for (const b of boxes) {
      for (const s of sockets) if (hit(b, s)) throw new Error(`"${b.text}" overlaps a port`);
      expect(b.x).toBeGreaterThanOrEqual(0);
      expect(b.x + b.w).toBeLessThanOrEqual(fp.width);
      expect(b.y + b.h).toBeLessThanOrEqual(fp.height);
    }
    for (const p of fp.ports) {
      expect(p.labelY - 0.8 * 7).toBeGreaterThan(fp.captionY + 3);
      // a label is above its port or below it, never beside it
      expect(p.labelY < p.y || p.labelY - 0.8 * 7 > p.y + PORT_H).toBe(true);
    }
  });
});

describe('speed LED and furniture', () => {
  it('lights green at 1 Gb/s and up, amber below, off when down or unknown', () => {
    expect(speedLed(port('Gi0/1', 'up', { speed_mbps: 1000 }))).toBe('fast');
    expect(speedLed(port('Te1/1/1', 'up', { speed_mbps: 10000 }))).toBe('fast');
    expect(speedLed(port('Fa0/1', 'up', { speed_mbps: 100 }))).toBe('slow');
    expect(speedLed(port('Fa0/2', 'up', { speed_mbps: 10 }))).toBe('slow');
    expect(speedLed(port('Fa0/3', 'link_lost', { speed_mbps: 100 }))).toBe('off');
    expect(speedLed(port('Fa0/4', 'up', { speed_mbps: null }))).toBe('off');
  });

  it('cuts a long hostname to the name plate', () => {
    const fp = faceplateOf({ ...switch24, hostname: 'core-distribution-switch-building-7-floor-2' });
    const name = fp.texts.find((t) => t.decor)!;
    expect(name.text.startsWith('core-distribution')).toBe(true);
    expect(name.text.endsWith('…')).toBe(true);
    expect(textBoxes(fp).find((b) => b.text === name.text)!.w).toBeLessThanOrEqual(fp.furniture.plate.w);
  });

  it('PWR follows whether the device answered SNMP; ears only on a 1U rack', () => {
    expect(faceplateOf(switch24).furniture.pwr.on).toBe(true);
    expect(faceplateOf({ ...switch24, status: 'unreachable' }).furniture.pwr.on).toBe(false);
    expect(faceplateOf(switch24).furniture.ear).toBeGreaterThan(0);
    expect(faceplateOf(fortigate).furniture.ear).toBe(0);
  });
});

describe('desktop layout from port_status only', () => {
  const fp = faceplateOf(fortigateStatusOnly);

  it('groups like a full port list, with WAN on the right behind the divider', () => {
    expect(fp.chassis).toBe('desktop');
    expect(fp.captions.map((c) => c.text)).toEqual(['MGMT/HA', 'INTERNAL', 'DMZ', 'WAN (internet)']);
    expect(fp.ports.map((p) => p.label)).toEqual(['MGMT', '1', '2', '3', '4', 'LAN', 'DMZ1', 'DMZ2', 'WAN1', 'WAN2']);
    expect(fp.dividers).toHaveLength(1);
    expect(fp.logical.map((p) => p.name)).toEqual(['modem', 'ssl.root']);
    // a neighbour on a down port: link lost
    expect(fp.ports.find((p) => p.port.name === 'port3')!.port.state).toBe('link_lost');
  });

  it('gives any other physical name its own full label in a PORTS group before WAN', () => {
    const other = faceplateOf({
      ...fortigateStatusOnly,
      port_status: { ...fortigateStatusOnly.port_status, 'srv-net': 'up', x1: 'down' },
    });
    expect(other.captions.map((c) => c.text)).toEqual(['MGMT/HA', 'INTERNAL', 'DMZ', 'PORTS', 'WAN (internet)']);
    const labels = other.ports.filter((p) => ['srv-net', 'x1'].includes(p.port.name)).map((p) => p.label);
    expect(labels).toEqual(['srv-net', 'X1']);
  });
});

describe('fitting the card', () => {
  it('uses the full panel when it fits at scale 1, the split one next, compact last', () => {
    const full = faceplateOf(fortigateLabStyle);
    const split = faceplateOf(fortigateLabStyle, { split: true });
    expect(split.width).toBeLessThan(full.width);
    expect(pickLayout(fortigateLabStyle, full.width)).toEqual({ fp: full, compact: false });
    expect(pickLayout(fortigateLabStyle, full.width - 1)).toEqual({ fp: split, compact: false });
    expect(pickLayout(fortigateLabStyle, split.width - 1)).toEqual({ fp: split, compact: true });
    // a big rack switch: banded before compact, compact only when even banded won't fit
    const banded = faceplateOf(switch48, { banded: true });
    expect(banded.width).toBeLessThanOrEqual(560);
    expect(pickLayout(switch48, 560)).toEqual({ fp: banded, compact: false });
    expect(pickLayout(switch48, banded.width - 1)).toEqual({ fp: banded, compact: true });
    // a 24-port switch still fits in one row
    expect(pickLayout(switch24, 560)).toEqual({ fp: faceplateOf(switch24), compact: false });
    // not measured yet: the old rule
    expect(pickLayout(switch48, 0).compact).toBe(true);
    expect(pickLayout(switch24, 0).compact).toBe(false);
  });

  it('splits each group of more than 2 ports onto two rows, left to right, WAN still last', () => {
    const split = faceplateOf(fortigateLabStyle, { split: true });
    const at = (name: string) => split.ports.find((p) => p.port.name === name)!;
    // INTERNAL is port1-4 then lan: 1, 2, 3 on top, 4 and LAN below
    expect(at('port1').y).toBe(at('port3').y);
    expect(at('port4').y).toBeGreaterThan(at('port1').y);
    expect(at('port4').x).toBe(at('port1').x);
    expect(at('lan').x).toBe(at('port2').x);
    expect(split.captions.map((c) => c.text)).toEqual(['MGMT/HA', 'INTERNAL', 'DMZ', 'PORTS', 'WAN (internet)']);
    expect(Math.min(at('wan1').x, at('wan2').x)).toBeGreaterThan(split.dividers[0]);
  });

  it('puts the strip on top: vendor and name plate left, PWR right, above every caption', () => {
    const fp = faceplateOf(fortigate200D);
    const pwr = fp.texts.find((t) => t.text === 'PWR')!;
    const vendor = fp.texts.find((t) => t.text === 'Fortinet')!;
    expect(vendor.x).toBeLessThan(fp.furniture.plate.x);
    expect(pwr.x).toBeGreaterThan(fp.furniture.plate.x + fp.furniture.plate.w);
    expect(pwr.x + textWidth('PWR', pwr.size)).toBeLessThanOrEqual(fp.width);
    for (const t of fp.texts) expect(t.y).toBeLessThan(fp.captionY - 9);
    // ports start at the left margin: no brand column any more
    expect(Math.min(...fp.ports.map((p) => p.x))).toBeLessThan(20);
  });
});

describe('banded rack layout', () => {
  it.each([
    ['48+2 Cisco', switch48, 'FastEthernet0/', 'GigabitEthernet0/1'],
    ['48+4 HP', switchHp48, 'GigabitEthernet1/0/', 'Ten-GigabitEthernet1/0/49'],
  ] as Array<[string, DeviceNode, string, string]>)('%s: 1-24 on top, 25-48 below, uplinks right of the first band', (_n, node, prefix, uplink) => {
    const full = faceplateOf(node);
    const fp = faceplateOf(node, { banded: true });
    const at = (n: number) => fp.ports.find((p) => p.port.name === `${prefix}${n}`)!;
    expect(fp.width).toBeLessThan(full.width);
    expect(fp.height).toBeGreaterThan(full.height);
    // each band as before: odd on top, even below, in blocks of 12
    expect(at(1).y).toBe(at(23).y);
    expect(at(2).y).toBeGreaterThan(at(1).y);
    // the second band sits under the first, lined up with it
    expect(at(25).x).toBe(at(1).x);
    expect(at(25).y).toBeGreaterThan(at(24).y);
    expect(at(26).y).toBeGreaterThan(at(25).y);
    expect(at(48).x).toBe(at(24).x);
    // the uplinks to the right of the first band, at its height
    const up = fp.ports.find((p) => p.port.name === uplink)!;
    expect(up.x).toBeGreaterThan(at(23).x);
    expect(up.y).toBeLessThan(at(25).y);
    // every port once, numbered
    expect(new Set(fp.ports.map((p) => p.port.name)).size).toBe(fp.ports.length);
    expect(fp.ports.length).toBe(full.ports.length);
    expect(at(37).label).toBe('37');
  });

  it('labels HP Ten-Gigabit uplinks as SFP', () => {
    const fp = faceplateOf(switchHp48, { banded: true });
    expect(fp.captions.map((c) => c.text)).toEqual(['SFP']);
  });

  it('a switch of 24 or fewer has a single band', () => {
    expect(faceplateOf(switch24, { banded: true })).toEqual(faceplateOf(switch24));
  });
});
