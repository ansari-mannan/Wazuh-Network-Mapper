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

// jsdom's globals lack structuredClone, which dagre uses; Node's serializer does the same job
// eslint-disable-next-line @typescript-eslint/no-var-requires
const v8 = require('v8');
(global as any).structuredClone ??= (value: unknown) => v8.deserialize(v8.serialize(value));

jest.mock('react-flow-renderer', () => {
  const actual = jest.requireActual('react-flow-renderer');
  const ReactFlowStub = ({ edges, edgeTypes }: any) => (
    <svg>
      {edges.map((e: any, i: number) => {
        const Custom = e.type === 'wifi' ? edgeTypes.wifi : null;
        const ends = { sourceX: 0, sourceY: 0, targetX: 100, targetY: 100 + i };
        return (
          <g key={e.id} data-edge={`${e.source}->${e.target}`} data-type={e.type || 'default'}>
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

import { TopologyView } from './TopologyView';
import { MapLegend } from './MapLegend';

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
    expect(wifi.querySelector('title')!.textContent).toBe('Wireless · OFFICE · 2.4 GHz (Dot11Radio0)');
    expect(wifi.querySelector('.vmWifiGlyph')).not.toBeNull();
    expect((wifi.querySelector('path.react-flow__edge-path') as SVGElement).style.strokeDasharray).toBe('5 5');

    const wired = edgeOf('endpoint:101', 'device:sw24');
    expect(wired.getAttribute('data-type')).toBe('default');
    expect(wired.querySelector('.vmWifiGlyph')).toBeNull();
    expect(wired.querySelector('title')).toBeNull();
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
    expect(path.style.strokeWidth).toBe('3');
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
