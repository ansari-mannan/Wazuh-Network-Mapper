/**
 * @jest-environment jsdom
 */
// The map with one wired and one wireless client. React Flow lays out edges
// only after measuring nodes, which jsdom cannot, so ReactFlow is replaced by
// a stub that draws each edge it is given (the custom wifi edge for real).
import React from 'react';
import ReactDOM from 'react-dom';
import { act } from 'react-dom/test-utils';
import { GraphResponse } from '../../../common';
import { smallGraph } from '../../lib/faceplate.fixtures';
import labGraph from '../../../test/fixtures/lab.graph.json';

// jsdom's globals lack structuredClone, which dagre uses; Node's serializer does the same job
// eslint-disable-next-line @typescript-eslint/no-var-requires
const v8 = require('v8');
(global as any).structuredClone ??= (value: unknown) => v8.deserialize(v8.serialize(value));
// nor SVG layout, which an edge label measures itself with
(SVGElement.prototype as any).getBBox ??= () => ({ x: 0, y: 0, width: 0, height: 0 });

// the nodes the stub was last given (it draws only the edges)
const mockNodes: any[] = [];
jest.mock('react-flow-renderer', () => {
  const actual = jest.requireActual('react-flow-renderer');
  const ReactFlowStub = ({ nodes, edges, edgeTypes }: any) => {
    mockNodes.splice(0, mockNodes.length, ...nodes);
    return (
    <svg>
      {edges.map((e: any, i: number) => {
        const Custom = e.type === 'wifi' || e.type === 'loop' ? edgeTypes[e.type] : null;
        const ends = { sourceX: 0, sourceY: 0, targetX: 100, targetY: 100 + i };
        return (
          <g key={e.id} className={e.className} data-edge={`${e.source}->${e.target}`} data-type={e.type || 'default'}>
            {Custom ? (
              <Custom id={e.id} {...ends} data={e.data} style={e.style} markerEnd={e.markerEnd && 'url(#end)'}
                markerStart={e.markerStart && 'url(#start)'}
              />
            ) : (
              <path style={e.style} />
            )}
          </g>
        );
      })}
    </svg>
    );
  };
  return { __esModule: true, ...actual, default: ReactFlowStub };
});

import { LOOP_REACH, NODE_HALF_W, ROUTE_DASH, TopologyView } from './TopologyView';
import { RouteEntry } from './highlight';
import { MapLegend } from './MapLegend';
import { graphColors } from '../../lib/theme';

// a switch and an access point, a wired host on the switch and a laptop on the AP's 2.4 GHz radio
const ids = ['device:sw24', 'device:ap', 'endpoint:101', 'host:wifi1'];
const graph: GraphResponse = {
  ...smallGraph,
  nodes: smallGraph.nodes.filter((n) => ids.includes(n.node_id)),
  edges: smallGraph.edges.filter((e) => ids.includes(e.source) && ids.includes(e.target)),
};

let root: HTMLDivElement;
beforeEach(() => {
  root = document.createElement('div');
  document.body.appendChild(root);
});
afterEach(() => {
  act(() => {
    ReactDOM.unmountComponentAtNode(root);
  });
  root.remove();
});

function render(el: React.ReactElement) {
  act(() => {
    ReactDOM.render(el, root);
  });
  return root;
}

const edgeOf = (from: string, to: string) =>
  root.querySelector(`[data-edge="${from}->${to}"], [data-edge="${to}->${from}"]`)!;

describe('map: wired and wireless clients', () => {
  it('draws the wireless link dashed with a Wi-Fi mark and tooltip, the wired one plainly', () => {
    render(<TopologyView graph={graph} onSelect={() => {}} selectedId={null} />);
    const wifi = edgeOf('host:wifi1', 'device:ap');
    expect(wifi.getAttribute('data-type')).toBe('wifi');
    const target = wifi.querySelector('.vmWifiEdge')!;
    expect(target.getAttribute('aria-label')).toBe('Wireless · OFFICE · 2.4 GHz (Dot11Radio0)');
    act(() => {
      target.dispatchEvent(new MouseEvent('mousemove', { bubbles: true, clientX: 5, clientY: 5 }));
    });
    // the same dark box as the front panel's ports
    const tip = document.querySelector('.vmTip[data-test-subj="vmHoverTip"]')!;
    expect(tip.querySelector('b')!.textContent).toBe('Wireless · OFFICE · 2.4 GHz (Dot11Radio0)');
    act(() => {
      target.dispatchEvent(new MouseEvent('mouseout', { bubbles: true, relatedTarget: document.body }));
    });
    expect(document.querySelector('.vmTip')).toBeNull();
    expect(wifi.querySelector('.vmWifiGlyph')).not.toBeNull();
    expect((wifi.querySelector('path.react-flow__edge-path') as SVGElement).style.strokeDasharray).toBe('5 5');

    const wired = edgeOf('endpoint:101', 'device:sw24');
    expect(wired.getAttribute('data-type')).toBe('default');
    expect(wired.querySelector('.vmWifiGlyph')).toBeNull();
    expect(wired.querySelector('.vmWifiEdge')).toBeNull();
    expect(root.innerHTML.replace(/></g, '>\n<')).toMatchSnapshot();
  });

  it('on a highlighted route the wireless link stays dashed, in the route colour, with an arrow', () => {
    render(
      <TopologyView
        graph={graph}
        onSelect={() => {}}
        selectedId={null}
        highlightKey="host:wifi1,device:ap"
        routeKey="host:wifi1,device:ap,device:sw24"
      />
    );
    const path = edgeOf('host:wifi1', 'device:ap').querySelector('path.react-flow__edge-path') as SVGElement;
    expect(path.style.strokeDasharray).toBe('5 5');
    expect(path.style.strokeWidth).toBe('4');
    // the route token draws the link, its arrow and (as --vm-route) the node rings
    expect(path.style.stroke).toBe(graphColors.route);
    expect(edgeOf('host:wifi1', 'device:ap').getAttribute('class')).toContain('vmRouteEdge');
    expect((root.querySelector('.canvas') as HTMLElement).style.getPropertyValue('--vm-route')).toBe(graphColors.route);
    // the arrow points the way the route travels, at whichever end that is drawn
    expect([path.getAttribute('marker-end'), path.getAttribute('marker-start')]).toContain(
      edgeOf('host:wifi1', 'device:ap').getAttribute('data-edge') === 'host:wifi1->device:ap' ? 'url(#end)' : 'url(#start)'
    );
    // the wired host is off the route: faded
    expect((edgeOf('endpoint:101', 'device:sw24').querySelector('path') as SVGElement).style.opacity).toBe('0.12');
  });

  it('lists the wireless link in the legend', () => {
    render(<MapLegend />);
    expect(root.textContent).toBe('Device linkHost linkWireless linkInferred');
    expect(root.querySelectorAll('.vmWifiGlyph')).toHaveLength(1);
  });
});

describe('map: a route from spare switch ports', () => {
  const L3 = 'device:00:23:ac:e5:74:00';
  const L2 = 'device:00:17:95:be:b2:00';
  const lab = labGraph as unknown as GraphResponse;
  const ports = ['Fa1/0/7', 'Fa1/0/8', 'Fa1/0/9', 'Fa1/0/10', 'Fa1/0/11'];
  const show = (walk: string[], entry: RouteEntry) =>
    render(
      <TopologyView graph={lab} onSelect={() => {}} selectedId={null}
        highlightKey={walk.join(',')} routeKey={walk.join(',')} entry={entry}
      />
    );
  const node = (id: string) => mockNodes.find((n) => n.id === id)!;
  const tags = (id: string) => [node(id).data.route?.step, node(id).data.route?.end];
  const chips = () => mockNodes.filter((n) => n.data.entry);
  const real = () => mockNodes.length;

  it('one hop: a loop from the switch back into itself, labelled with its ports, tagged Start · Target', () => {
    show([L3], { switch: L3, vlan: 20, ports });
    const loop = edgeOf(L3, L3);
    expect(loop.getAttribute('data-type')).toBe('loop');
    expect(loop.getAttribute('class')).toContain('vmRouteEdge');
    const path = loop.querySelector('path.react-flow__edge-path') as SVGElement;
    expect(path.style.stroke).toBe(graphColors.route);
    expect(path.style.strokeDasharray).toBe(ROUTE_DASH);
    expect(path.getAttribute('marker-end')).toBe('url(#end)');
    // compact label, the full list in the tooltip
    expect(loop.textContent).toBe('Fa1/0/7, Fa1/0/8 +3 · VLAN 20');
    expect(loop.querySelector('.vmLoopEdge')!.getAttribute('aria-label')).toBe(
      'Entry: Fa1/0/7, Fa1/0/8, Fa1/0/9, Fa1/0/10, Fa1/0/11 · VLAN 20'
    );
    expect(tags(L3)).toEqual([1, 'both']);
    expect(chips()).toEqual([]);
    expect(real()).toBe(lab.nodes.length);
  });

  it('one hop: the loop label is a pill clear of the node and the loop', () => {
    show([L3], { switch: L3, vlan: 20, ports });
    // the stub hands the loop sourceX 0, sourceY 0 (bottom handle) and targetY 100 (top handle)
    const nodeBox = { left: -NODE_HALF_W, right: NODE_HALF_W, top: 0, bottom: 100 };
    const pill = edgeOf(L3, L3).querySelector('.vmLoopLabel rect')!;
    const n = (a: string) => Number(pill.getAttribute(a));
    const box = { left: n('x'), right: n('x') + n('width'), top: n('y'), bottom: n('y') + n('height') };
    const intersects = (a: typeof box, b: typeof box) =>
      a.left < b.right && b.left < a.right && a.top < b.bottom && b.top < a.bottom;
    expect(intersects(box, nodeBox)).toBe(false);
    expect(box.left).toBeGreaterThan(NODE_HALF_W + LOOP_REACH); // past the loop's outer edge
    expect(n('width')).toBeGreaterThan(0);
    // surface fill, thin route-coloured border; the full list stays in the tooltip
    expect(pill.getAttribute('stroke')).toBe(graphColors.route);
    expect(pill.getAttribute('stroke-width')).toBe('1');
    expect(edgeOf(L3, L3).querySelector('.vmLoopLabel text')!.getAttribute('x')).toBe(String(box.left + 6));
  });

  it('two hops: the Start tag and an entry chip on the first switch, no loop', () => {
    show([L2, L3], { switch: L2, vlan: 10, ports: ['Fa0/9', 'Fa0/10', 'Fa0/11'] });
    expect(tags(L2)).toEqual([1, 'start']);
    expect(tags(L3)).toEqual([2, 'target']);
    expect(chips().map((n) => [n.id, n.data.entry.short, n.data.entry.full])).toEqual([
      [L2, 'Fa0/9, Fa0/10 +1 · VLAN 10', 'Fa0/9, Fa0/10, Fa0/11 · VLAN 10'],
    ]);
    expect(root.querySelector('[data-type="loop"]')).toBeNull();
    expect(real()).toBe(lab.nodes.length);
  });

  it('nothing of the entry shows without the highlight', () => {
    render(<TopologyView graph={lab} onSelect={() => {}} selectedId={null} entry={{ switch: L3, vlan: 20, ports }} />);
    expect(root.querySelector('[data-type="loop"]')).toBeNull();
    expect(chips()).toEqual([]);
    expect(real()).toBe(lab.nodes.length);
  });
});
