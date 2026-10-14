/**
 * @jest-environment jsdom
 */
// The device front panel rendered for each kind of device (synthetic devices,
// lib/faceplate.fixtures.ts), checked by what a user sees and by snapshot.
import React from 'react';
import ReactDOM from 'react-dom';
import { act } from 'react-dom/test-utils';
import { DeviceNode } from '../../../common';
import { Faceplate } from './Faceplate';
import { faceplateOf } from '../../lib/faceplate';
import {
  accessPoint,
  fortigate,
  fortigate200D,
  fortigateStatusOnly,
  fortigateLabStyle,
  smallGraph,
  switch24,
  switch48,
  switch8,
  switchHp1920,
  unknownDevice,
} from '../../lib/faceplate.fixtures';

let root: HTMLDivElement;
beforeEach(() => {
  root = document.createElement('div');
  document.body.appendChild(root);
});
afterEach(() => {
  act(() => {
    ReactDOM.unmountComponentAtNode(root);
  });
  document.body.innerHTML = '';
});

function render(node: DeviceNode, props: Partial<React.ComponentProps<typeof Faceplate>> = {}) {
  act(() => {
    ReactDOM.render(<Faceplate node={node} edges={smallGraph.edges} {...props} />, root);
  });
  return root;
}

const sockets = (el: ParentNode) => Array.from(el.querySelectorAll('[data-test-subj="vmFaceplate"] .vmFpPort'));
const socket = (el: ParentNode, name: string) => el.querySelector(`.vmFpPort[data-port="${name}"]`)!;
const labels = (el: ParentNode) => Array.from(el.querySelectorAll('.vmFpPort text')).map((t) => t.textContent);
const fire = (target: Element, event: Event) =>
  act(() => {
    target.dispatchEvent(event);
  });
const hover = (target: Element, x = 10, y = 10) =>
  fire(target, new MouseEvent('mousemove', { bubbles: true, clientX: x, clientY: y }));
const box = () => document.querySelector('[data-test-subj="vmHoverTip"]') as HTMLElement | null;
// the tooltip's lines: the bold name, then each line (the route line last)
const tipLines = () => Array.from(box()!.children).map((c) => c.textContent);
const html = () =>
  document.body.innerHTML.replace(/(id|aria-labelledby|aria-controls|aria-describedby)="[^"]*"/g, '$1="X"').replace(/></g, '>\n<');

describe('Faceplate', () => {
  it('24+2 Cisco switch: rack panel, states, route ring, inferred-free, logical folded', () => {
    const el = render(switch24, { route: ['device:fw', 'device:sw24', 'endpoint:101'] });
    expect(el.querySelector('svg')!.getAttribute('class')).toContain('vmFaceplate--rack');
    expect(sockets(el)).toHaveLength(26);
    expect(el.querySelector('[data-test-subj="vmFaceplateExpand"]')).toBeNull();
    expect(socket(el, 'FastEthernet1/0/1').getAttribute('class')).toContain('vmFpPort--up');
    expect(socket(el, 'FastEthernet1/0/5').getAttribute('class')).toContain('vmFpPort--link_lost');
    expect(socket(el, 'FastEthernet1/0/24').getAttribute('class')).toContain('vmFpPort--shutdown');
    expect(socket(el, 'FastEthernet1/0/3').getAttribute('class')).toContain('vmFpPort--unused');
    // the route enters by Fa1/0/1 (from the firewall) and leaves by Fa1/0/15 (to the host)
    const ringed = Array.from(el.querySelectorAll('.vmFpRoute')).map((r) => r.parentElement!.getAttribute('data-port'));
    expect(ringed).toEqual(['FastEthernet1/0/1', 'FastEthernet1/0/15']);
    const fa1 = socket(el, 'FastEthernet1/0/1');
    expect(box()).toBeNull();
    hover(fa1);
    expect(tipLines()).toEqual([
      'FastEthernet1/0/1',
      'Up',
      'Alias: Uplink to firewall',
      'Speed: 100 Mb/s',
      'Neighbour: fw Layer-3_UPLINK',
      'On an attack route',
    ]);
    expect(box()!.querySelector('b')!.textContent).toBe('FastEthernet1/0/1');
    expect(box()!.querySelector('.vmTip__route')!.textContent).toBe('On an attack route');
    // screen readers get the same text from the port itself
    expect(fa1.getAttribute('aria-label')).toBe(
      'FastEthernet1/0/1. Up. Alias: Uplink to firewall. Speed: 100 Mb/s. Neighbour: fw Layer-3_UPLINK. On an attack route'
    );
    fire(fa1, new MouseEvent('mouseout', { bubbles: true, relatedTarget: document.body }));
    expect(box()).toBeNull();
    expect(el.textContent).toContain('Cisco');
    expect(el.textContent).toContain('WS-C3750-24TS');
    expect(el.querySelector('[data-test-subj="vmLogicalInterfaces"]')!.textContent).toContain(
      'Logical interfaces (3, 2 up)'
    );
    expect(el.querySelector('[data-test-subj="vmFaceplateLegend"]')!.textContent).toBe(
      'UpDown: link lostNot connectedShut downOn attack routeInferred from neighbourSpeed ≥ 1 Gb/sSpeed 10–100 Mb/s'
    );
    // the speed LED beside each link LED: amber for an up 100 Mb/s port, off when not connected
    const speed = (name: string) => socket(el, name).querySelector('.vmFpSpeed')!.getAttribute('class');
    expect(speed('FastEthernet1/0/1')).toBe('vmFpSpeed vmFpSpeed--slow');
    expect(speed('FastEthernet1/0/3')).toBe('vmFpSpeed vmFpSpeed--off');
    // decoration in the full panel: ears with two screws each, grille, name plate, gradient
    const svg = el.querySelector('[data-test-subj="vmFaceplate"]')!;
    expect(svg.querySelectorAll('.vmFpEar')).toHaveLength(2);
    expect(svg.querySelectorAll('.vmFpScrew')).toHaveLength(4);
    expect(svg.querySelectorAll('.vmFpGrille').length).toBeGreaterThan(5);
    expect(svg.querySelector('.vmFpPlate')).not.toBeNull();
    expect(svg.querySelector('linearGradient')).not.toBeNull();
    expect(svg.textContent).toContain('sw24'); // the hostname on the name plate
    // the PWR LED is the only system LED, lit: the device answered SNMP
    expect(svg.querySelector('.vmFpPwr')!.getAttribute('class')).toBe('vmFpPwr vmFpPwr--on');
    expect(svg.textContent).not.toMatch(/SYST|RPS|STAT/);
    expect(html()).toMatchSnapshot();
  });

  it('clicking a port with a neighbour selects that node', () => {
    const onSelectNode = jest.fn();
    const el = render(switch24, { onSelectNode });
    const fa6 = socket(el, 'FastEthernet1/0/6');
    expect(fa6.getAttribute('role')).toBe('button');
    act(() => {
      fa6.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    });
    expect(onSelectNode).toHaveBeenCalledWith('device:ap');
    // no neighbour: not a button
    expect(socket(el, 'FastEthernet1/0/3').getAttribute('role')).toBe('img');
  });

  it('the tooltip shows on keyboard focus and hides on blur and Escape', () => {
    const el = render(switch24);
    const fa3 = socket(el, 'FastEthernet1/0/3');
    expect(fa3.getAttribute('tabindex')).toBe('0'); // no neighbour, still reachable by keyboard
    fire(fa3, new FocusEvent('focus'));
    expect(tipLines()).toEqual(['FastEthernet1/0/3', 'Not connected', 'Speed: 100 Mb/s']);
    fire(fa3, new FocusEvent('blur'));
    expect(box()).toBeNull();
    fire(fa3, new FocusEvent('focus'));
    fire(fa3, new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
    expect(box()).toBeNull();
  });

  it('keeps the tooltip inside the viewport near the right and bottom edges', () => {
    const el = render(switch24);
    const rect = { width: 200, height: 90, top: 0, left: 0, right: 200, bottom: 90, x: 0, y: 0, toJSON: () => ({}) };
    const spy = jest.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockReturnValue(rect as DOMRect);
    hover(socket(el, 'FastEthernet1/0/1'), window.innerWidth - 5, window.innerHeight - 5);
    const { left, top } = box()!.style;
    expect(parseFloat(left)).toBe(window.innerWidth - 200 - 8);
    expect(parseFloat(top)).toBe(window.innerHeight - 5 - 90 - 14);
    hover(socket(el, 'FastEthernet1/0/1'), 20, 30);
    expect([box()!.style.left, box()!.style.top]).toEqual(['34px', '44px']);
    spy.mockRestore();
  });

  it('48+2 switch: the full strip with every detail, and Expand opens it larger in a modal', () => {
    const el = render(switch48);
    expect(sockets(el)).toHaveLength(50);
    // a rack switch is never compact: ears, name plate and port numbers stay
    const card = el.querySelector('[data-test-subj="vmFaceplate"]')!;
    expect(card.querySelectorAll('.vmFpEar')).toHaveLength(2);
    expect(card.querySelector('.vmFpPlate')).not.toBeNull();
    expect(card.textContent).toContain('WS-C2960-48TT-L');
    expect(labels(el).slice(0, 4)).toEqual(['1', '2', '3', '4']);
    const expand = el.querySelector('[data-test-subj="vmFaceplateExpand"]') as HTMLElement;
    expect(expand.textContent).toBe('Expand (50 ports)');
    act(() => {
      expand.click();
    });
    const modal = document.querySelector('[data-test-subj="vmFaceplateModal"]')!;
    expect(modal).not.toBeNull();
    const full = modal.querySelector('[data-test-subj="vmFaceplate"]')!;
    expect(Number(full.getAttribute('width'))).toBeGreaterThan(1000);
    expect(labels(modal).slice(0, 4)).toEqual(['1', '2', '3', '4']);
    // the modal has the decoration
    expect(full.querySelectorAll('.vmFpEar')).toHaveLength(2);
    expect(full.querySelector('.vmFpPlate')).not.toBeNull();
    expect(full.textContent).toContain('WS-C2960-48TT-L');
    expect(html()).toMatchSnapshot();
  });

  it('8-port switch: two rows of four, no uplink block', () => {
    const el = render(switch8);
    expect(sockets(el)).toHaveLength(8);
    expect(new Set(sockets(el).map((s) => s.querySelector('.vmFpFace')!.getAttribute('y'))).size).toBe(2);
    expect(el.querySelector('[data-test-subj="vmLogicalInterfaces"]')).toBeNull();
    expect(html()).toMatchSnapshot();
  });

  it('FortiGate: desktop box, INTERNAL/DMZ/WAN groups, dashed inferred wan1', () => {
    const el = render(fortigate);
    expect(el.querySelector('svg')!.getAttribute('class')).toContain('vmFaceplate--desktop');
    expect(el.textContent).toContain('INTERNAL');
    expect(labels(el)).toEqual(['1', '2', '3', '4', '5', '6', '7', 'DMZ', 'WAN1', 'WAN2']);
    const wan1 = socket(el, 'wan1').querySelector('.vmFpFace')!;
    expect(wan1.getAttribute('class')).toContain('vmFpFace--inferred');
    expect(wan1.getAttribute('stroke-dasharray')).toBe('3 2');
    expect(socket(el, 'dmz').getAttribute('class')).toContain('vmFpPort--shutdown');
    hover(socket(el, 'wan1'));
    expect(tipLines()).toContain('Neighbour: sw24 Fa1/0/1');
    expect(box()!.querySelector('.vmTip__route')).toBeNull();
    fire(socket(el, 'wan1'), new MouseEvent('mouseout', { bubbles: true, relatedTarget: document.body }));
    expect(el.textContent).toContain('Logical interfaces (1, 1 up)');
    expect(html()).toMatchSnapshot();
  });

  it('FortiGate 200D: MGMT/HA, INTERNAL on two rows, DMZ, and WAN rightmost behind a divider', () => {
    const el = render(fortigate200D);
    const svg = el.querySelector('[data-test-subj="vmFaceplate"]')!;
    const captions = Array.from(svg.querySelectorAll('g > text.vmFpLabel'))
      .map((t) => t.textContent)
      .filter((t) => ['MGMT/HA', 'INTERNAL', 'DMZ', 'WAN (internet)'].includes(t!));
    expect(captions).toEqual(['MGMT/HA', 'INTERNAL', 'DMZ', 'WAN (internet)']);
    expect(labels(el)).toEqual([
      'MGMT', 'HA', ...Array.from({ length: 16 }, (_, i) => String(i + 1)), 'DMZ1', 'DMZ2', 'WAN1', 'WAN2',
    ]);
    // every port drawn once
    const drawn = sockets(el).map((s) => s.getAttribute('data-port'));
    expect(new Set(drawn).size).toBe(22);
    const faceX = (name: string) => Number(socket(el, name).querySelector('.vmFpFace')!.getAttribute('x'));
    const nonWan = drawn.filter((n) => !n!.startsWith('wan')).map((n) => faceX(n!));
    const divider = svg.querySelectorAll('line.vmFpDivider');
    expect(divider).toHaveLength(1);
    const dx = Number(divider[0].getAttribute('x1'));
    expect(Math.max(...nonWan)).toBeLessThan(dx);
    expect(dx).toBeLessThan(Math.min(faceX('wan1'), faceX('wan2')));
    expect(socket(el, 'port9').getAttribute('class')).toContain('vmFpPort--link_lost');
    expect(socket(el, 'port16').getAttribute('class')).toContain('vmFpPort--shutdown');
    expect(html()).toMatchSnapshot();
  });

  it('firewall with only port_status: desktop layout, WAN far right, virtual interfaces folded', () => {
    const el = render(fortigateStatusOnly);
    const svg = el.querySelector('[data-test-subj="vmFaceplate"]')!;
    expect(svg.getAttribute('class')).toContain('vmFaceplate--desktop');
    expect(labels(el)).toEqual(['MGMT', '1', '2', '3', '4', 'LAN', 'DMZ1', 'DMZ2', 'WAN1', 'WAN2']);
    expect(svg.textContent).toContain('WAN (internet)');
    const faceX = (name: string) => Number(socket(el, name).querySelector('.vmFpFace')!.getAttribute('x'));
    const dx = Number(svg.querySelector('line.vmFpDivider')!.getAttribute('x1'));
    const others = sockets(el)
      .map((s) => s.getAttribute('data-port')!)
      .filter((n) => !n.startsWith('wan'));
    expect(Math.max(...others.map(faceX))).toBeLessThan(dx);
    expect(dx).toBeLessThan(Math.min(faceX('wan1'), faceX('wan2')));
    // modem and ssl.root are not sockets: they are listed under Logical interfaces
    expect(socket(el, 'modem')).toBeNull();
    expect(socket(el, 'ssl.root')).toBeNull();
    const logical = el.querySelector('[data-test-subj="vmLogicalInterfaces"]')!;
    expect(logical.textContent).toContain('Logical interfaces (2, 1 up)');
    expect(logical.textContent).toContain('modem');
    expect(logical.textContent).toContain('ssl.root');
    expect(html()).toMatchSnapshot();
  });

  it('access point: puck with the radios as antenna LEDs showing their client counts', () => {
    const el = render(accessPoint);
    expect(el.querySelector('svg')!.getAttribute('class')).toContain('vmFaceplate--puck');
    expect(el.querySelectorAll('circle.vmFpLed')).toHaveLength(2);
    // one client on the 2.4 GHz radio, two on the 5 GHz one (from the wifi links)
    expect(Array.from(el.querySelectorAll('.vmFpCount')).map((t) => t.textContent)).toEqual(['1', '2']);
    expect(labels(el)).toEqual(['1', '2.4 GHz', '2', '5 GHz', 'Gi0']);
    expect(socket(el, 'Dot11Radio1').getAttribute('aria-label')).toBe(
      'Dot11Radio1. Up. 2 Wi-Fi clients. Neighbour: wifi2, wifi3'
    );
    expect(el.textContent).toContain('Logical interfaces (3, 3 up)');
    expect(html()).toMatchSnapshot();
  });

  it('unknown device with only port_status: a plain panel, PWR off when SNMP did not answer', () => {
    const el = render({ ...unknownDevice, status: 'unreachable' });
    expect(el.querySelector('.vmFpPwr')!.getAttribute('class')).toBe('vmFpPwr vmFpPwr--off');
    expect(el.querySelectorAll('.vmFpEar')).toHaveLength(0); // only a 1U rack has ears
    expect(el.querySelector('svg')!.getAttribute('class')).toContain('vmFaceplate--generic');
    expect(sockets(el).map((s) => s.getAttribute('class'))).toEqual([
      'vmFpPort vmFpPort--up',
      'vmFpPort vmFpPort--link_lost',
      'vmFpPort vmFpPort--unused',
    ]);
    expect(html()).toMatchSnapshot();
  });

  describe('in a measured card', () => {
    // jsdom has no layout: the card (.vmFp) reports the width under test
    let width = 560;
    beforeEach(() => {
      jest.spyOn(HTMLElement.prototype, 'clientWidth', 'get').mockImplementation(function (this: HTMLElement) {
        return this.classList.contains('vmFp') || this.classList.contains('vmFpStrip') ? width : 0;
      });
    });
    afterEach(() => jest.restoreAllMocks());

    // on-screen size of one viewBox unit: the drawn width over the viewBox width
    const scaleOf = (svg: Element) => Number(svg.getAttribute('width')) / Number(svg.getAttribute('viewBox')!.split(' ')[2]);
    const card = (el: ParentNode) => el.querySelector('[data-test-subj="vmFaceplate"]')!;

    it.each([
      ['FortiGate 200D', fortigate200D],
      ['lab-style firewall', fortigateLabStyle],
      ['24+2 switch', switch24],
    ] as Array<[string, DeviceNode]>)('%s in 560 px: one readable panel, ports >= 22 px, labels >= 9 px', (_n, node) => {
      width = 560;
      const el = render(node);
      const svg = card(el);
      expect(el.querySelector('[data-test-subj="vmFaceplateExpand"]')).toBeNull();
      expect(Number(svg.getAttribute('width'))).toBeLessThanOrEqual(560);
      // fits without scrolling
      expect(el.querySelector('[data-test-subj="vmFaceplateStrip"]')!.getAttribute('class')).not.toContain('--scroll');
      const port = Number(svg.querySelector('.vmFpFace')!.getAttribute('width'));
      expect(port * scaleOf(svg)).toBeGreaterThanOrEqual(22);
      for (const t of Array.from(svg.querySelectorAll('.vmFpPort text.vmFpLabel'))) {
        expect(Number(t.getAttribute('font-size')) * scaleOf(svg)).toBeGreaterThanOrEqual(9);
      }
    });

    it('a card too narrow for one row splits the groups onto two rows, WAN still far right', () => {
      // as wide as the split panel needs: too narrow for the one-row one
      width = Math.ceil(faceplateOf(fortigateLabStyle, { split: true }).width);
      expect(faceplateOf(fortigateLabStyle).width).toBeGreaterThan(width);
      const el = render(fortigateLabStyle);
      const svg = card(el);
      expect(el.querySelector('[data-test-subj="vmFaceplateExpand"]')).toBeNull();
      expect(Number(svg.querySelector('.vmFpFace')!.getAttribute('width')) * scaleOf(svg)).toBeGreaterThanOrEqual(22);
      const y = (name: string) => Number(socket(el, name).querySelector('.vmFpFace')!.getAttribute('y'));
      expect(y('port4')).toBeGreaterThan(y('port1')); // INTERNAL on two rows
      const faceX = (name: string) => Number(socket(el, name).querySelector('.vmFpFace')!.getAttribute('x'));
      const dx = Number(svg.querySelector('line.vmFpDivider')!.getAttribute('x1'));
      expect(dx).toBeLessThan(Math.min(faceX('wan1'), faceX('wan2')));
      expect(Math.max(faceX('srv-net'), faceX('dmz2'), faceX('lan'))).toBeLessThan(dx);
      expect(html()).toMatchSnapshot();
    });

    it.each([
      ['HP 1920-48G (1-52)', switchHp1920, 'GigabitEthernet1/0/', ['G49', 'G50', 'G51', 'G52']],
      ['Cisco 2960-48TT', switch48, 'FastEthernet0/', ['G1', 'G2']],
    ] as Array<[string, DeviceNode, string, string[]]>)(
      '%s in 560 px: one strip with full detail, ports >= 22 px, scrolling, Expand',
      (_n, node, prefix, uplinks) => {
        width = 560;
        const el = render(node);
        const svg = card(el);
        // one strip: the access ports on two rows only
        const face = (n: number) => socket(el, `${prefix}${n}`).querySelector('.vmFpFace')!;
        const rows = new Set(Array.from({ length: 48 }, (_, i) => face(i + 1).getAttribute('y')));
        expect(rows.size).toBe(2);
        expect(face(47).getAttribute('y')).toBe(face(1).getAttribute('y'));
        // full detail: ears the full height, name plate, grille, PWR, every number
        const height = Number(svg.getAttribute('viewBox')!.split(' ')[3]);
        const ears = Array.from(svg.querySelectorAll('.vmFpEar rect'));
        expect(ears).toHaveLength(2);
        for (const ear of ears) expect(Number(ear.getAttribute('height'))).toBe(height - 2);
        for (const cls of ['.vmFpPlate', '.vmFpGrille', '.vmFpPwr']) expect(svg.querySelector(cls)).not.toBeNull();
        const numbers = labels(el).filter((l) => /^\d+$/.test(l!)).map(Number).sort((a, b) => a - b);
        expect(numbers).toEqual(Array.from({ length: 48 }, (_, i) => i + 1));
        // the uplink block at the right end
        expect(labels(el).filter((l) => !/^\d+$/.test(l!))).toEqual(uplinks);
        const rightmostAccess = Math.max(...Array.from({ length: 48 }, (_, i) => Number(face(i + 1).getAttribute('x'))));
        for (const s of sockets(el).filter((x) => !x.getAttribute('data-port')!.startsWith(prefix) || Number(x.getAttribute('data-port')!.split('/').pop()) > 48)) {
          expect(Number(s.querySelector('.vmFpFace')!.getAttribute('x'))).toBeGreaterThan(rightmostAccess);
        }
        // scale 1 (ports 22 px), wider than the card: the strip scrolls; Expand is there
        expect(Number(face(1).getAttribute('width')) * scaleOf(svg)).toBeGreaterThanOrEqual(21.9);
        expect(Number(svg.getAttribute('width'))).toBeGreaterThan(560);
        expect(el.querySelector('[data-test-subj="vmFaceplateStrip"]')!.getAttribute('class')).toContain('vmFpStrip--scroll');
        expect(el.querySelector('[data-test-subj="vmFaceplateExpand"]')).not.toBeNull();
        expect(html()).toMatchSnapshot();
      }
    );

    it('fades the right edge while more of the strip is out of view', () => {
      width = 560;
      const el = render(switch48);
      const strip = el.querySelector('[data-test-subj="vmFaceplateStrip"]') as HTMLElement;
      const wrap = strip.parentElement!;
      // the card's scroll extent: the drawn panel's width
      jest.spyOn(strip, 'scrollWidth', 'get').mockReturnValue(Number(card(el).getAttribute('width')));
      act(() => {
        strip.dispatchEvent(new Event('scroll'));
      });
      expect(wrap.getAttribute('class')).toContain('vmFpStripWrap--more');
      strip.scrollLeft = strip.scrollWidth - 560;
      act(() => {
        strip.dispatchEvent(new Event('scroll'));
      });
      expect(wrap.getAttribute('class')).not.toContain('vmFpStripWrap--more');
    });

    it('scrolls a focused port into view, and its tooltip still shows', () => {
      width = 560;
      const scrollIntoView = jest.fn();
      (Element.prototype as any).scrollIntoView = scrollIntoView;
      const el = render(switch48);
      const port48 = socket(el, 'FastEthernet0/48');
      fire(port48, new FocusEvent('focus'));
      expect(scrollIntoView).toHaveBeenCalledWith({ block: 'nearest', inline: 'nearest' });
      expect(tipLines()[0]).toBe('FastEthernet0/48');
      delete (Element.prototype as any).scrollIntoView;
    });

    it('a firewall too narrow for even the split panel is compact, with Expand', () => {
      width = 200;
      const el = render(fortigateLabStyle);
      const svg = card(el);
      expect(svg.querySelector('.vmFpRule')).toBeNull(); // captions keep no underline
      expect(Number(svg.getAttribute('width'))).toBe(200);
      expect(el.querySelector('[data-test-subj="vmFaceplateExpand"]')).not.toBeNull();
    });
  });
});
