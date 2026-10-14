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
import {
  accessPoint,
  fortigate,
  fortigate200D,
  smallGraph,
  switch24,
  switch48,
  switch8,
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
      'UpDown: link lostNot connectedShut downOn attack routeInferred from neighbour'
    );
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

  it('48+2 switch: a compact panel and an Expand button that opens the full one in a modal', () => {
    const el = render(switch48);
    expect(sockets(el)).toHaveLength(50);
    expect(labels(el)).toEqual([]); // compact: no port numbers
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

  it('unknown device with only port_status: a plain panel', () => {
    const el = render(unknownDevice);
    expect(el.querySelector('svg')!.getAttribute('class')).toContain('vmFaceplate--generic');
    expect(sockets(el).map((s) => s.getAttribute('class'))).toEqual([
      'vmFpPort vmFpPort--up',
      'vmFpPort vmFpPort--link_lost',
      'vmFpPort vmFpPort--unused',
    ]);
    expect(html()).toMatchSnapshot();
  });
});
