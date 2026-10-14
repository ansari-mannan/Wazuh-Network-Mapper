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
    expect(socket(el, 'FastEthernet1/0/1').querySelector('title')!.textContent).toBe(
      'FastEthernet1/0/1\nAlias: Uplink to firewall\nUp · 100 Mb/s\nNeighbour: fw Layer-3_UPLINK\nOn the highlighted attack route'
    );
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
    expect(socket(el, 'wan1').querySelector('title')!.textContent).toContain('Neighbour: sw24 Fa1/0/1');
    expect(el.textContent).toContain('Logical interfaces (1, 1 up)');
    expect(html()).toMatchSnapshot();
  });

  it('access point: puck with the radios as antenna LEDs', () => {
    const el = render(accessPoint);
    expect(el.querySelector('svg')!.getAttribute('class')).toContain('vmFaceplate--puck');
    expect(el.querySelectorAll('circle.vmFpLed')).toHaveLength(2);
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
