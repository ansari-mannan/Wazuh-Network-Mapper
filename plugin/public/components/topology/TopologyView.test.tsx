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

jest.mock('react-flow-renderer', () => {
  const actual = jest.requireActual('react-flow-renderer');
  const ReactFlowStub = ({ nodes, edges, edgeTypes }: any) => (
    <svg>
      {nodes.map((n: any) => (
        <g key={n.id} data-node={n.id} data-type={n.type} data-step={n.data.route?.step} data-end={n.data.route?.end}
          data-label={n.type === 'spareStart' ? n.data.label : undefined}
        />
      ))}
      {edges.map((e: any, i: number) => {
        const Custom = e.type === 'wifi' ? edgeTypes.wifi : null;
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
  return { __esModule: true, ...actual, default: ReactFlowStub };
});

import { ROUTE_DASH, TopologyView } from './TopologyView';
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
  const show = (walk: string[], startLabel: string) =>
    render(
      <TopologyView graph={lab} onSelect={() => {}} selectedId={null}
        highlightKey={walk.join(',')} routeKey={walk.join(',')} startLabel={startLabel}
      />
    );
  const node = (id: string) => root.querySelector(`[data-node="${id}"]`)!;
  const marker = () => root.querySelector('[data-type="spareStart"]');
  const tags = (id: string) => [node(id).getAttribute('data-step'), node(id).getAttribute('data-end')];

  it('one hop: the marker is the start, the switch it sits on is the target', () => {
    const start = `start:spare-ports:${L3}:20`;
    show([start, L3], '9 spare ports · VLAN 20');
    expect(marker()!.getAttribute('data-label')).toBe('9 spare ports · VLAN 20');
    expect(tags(start)).toEqual(['1', 'start']);
    expect(tags(L3)).toEqual(['2', 'target']);
    expect(root.querySelectorAll('[data-end="start"]')).toHaveLength(1);
    // joined to the switch by a route-coloured dashed link pointing at it
    const link = root.querySelector(`[data-edge="${start}->${L3}"]`)!;
    expect(link.getAttribute('class')).toContain('vmRouteEdge');
    expect((link.querySelector('path') as SVGElement).style.strokeDasharray).toBe(ROUTE_DASH);
  });

  it('two hops: marker, then the L2 switch, then the L3 target', () => {
    const start = `start:spare-ports:${L2}:10`;
    show([start, L2, L3], '10 spare ports · VLAN 10');
    expect(tags(start)).toEqual(['1', 'start']);
    expect(tags(L2)).toEqual(['2', null]);
    expect(tags(L3)).toEqual(['3', 'target']);
    expect(root.querySelector(`[data-edge="${start}->${L2}"]`)).not.toBeNull();
  });

  it('the marker is no graph node: the real nodes are the same with or without it', () => {
    const real = () => root.querySelectorAll('[data-type="device"]').length;
    render(<TopologyView graph={lab} onSelect={() => {}} selectedId={null} />);
    expect(real()).toBe(lab.nodes.length);
    expect(marker()).toBeNull();
    show([`start:spare-ports:${L3}:20`, L3], '9 spare ports · VLAN 20');
    expect(real()).toBe(lab.nodes.length);
    expect(marker()).not.toBeNull();
  });
});
