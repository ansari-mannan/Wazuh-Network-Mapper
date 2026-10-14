/**
 * @jest-environment jsdom
 */
// Renders the larger pages on the backend's golden lab outputs and compares the
// HTML with a stored snapshot, so a refactor that changes what a user sees
// fails here. EUI's generated element ids differ per run and are blanked.
import React from 'react';
import ReactDOM from 'react-dom';
import { act } from 'react-dom/test-utils';
import labGraph from '../test/fixtures/lab.graph.json';
import labVulns from '../test/fixtures/lab.vulnerabilities.json';
import labPaths from '../test/fixtures/lab.attack_paths.json';
import labLiveness from '../test/fixtures/lab.liveness.json';
import unmanagedGraph from '../test/fixtures/unmanaged.graph.json';

const data: Record<string, any> = {};

jest.mock('./lib/graph', () => ({ useGraph: () => data.graph }));
jest.mock('./lib/vulnerabilities', () => ({ useVulnerabilities: () => data.vulns }));
jest.mock('./lib/attackPathsData', () => ({ useAttackPaths: () => data.paths }));
// the schedule and history panels fetch on mount; leave them loading
jest.mock('./lib/services', () => ({ useServices: () => ({ http: { get: () => new Promise(() => undefined) } }) }));
jest.mock('./lib/scan', () => ({ useScan: () => data.scan }));
jest.mock('./lib/liveness', () => {
  const { offlineHosts } = jest.requireActual('./components/topology/inactive');
  return {
    useLiveness: () => ({ liveness: data.liveness }),
    useOfflineHosts: () => offlineHosts(data.graph.graph, data.liveness),
  };
});

import { VulnerabilityReportPage } from './components/vulnreport/VulnerabilityReportPage';
import { DeviceDetail } from './components/topology/DeviceDetail';
import { ScanSettingsPage } from './components/scan/ScanSettingsPage';
import { DRAWER_PAD, DRAWER_WIDTH, drawerWidth } from './lib/faceplate';
import { accessPoint, fortigate, smallGraph, switch24, switch48, switchHp1920 } from './lib/faceplate.fixtures';

function html(element: React.ReactElement): string {
  const root = document.createElement('div');
  document.body.appendChild(root);
  act(() => {
    ReactDOM.render(element, root);
  });
  // flyouts render into a portal on document.body, so read the whole body
  const out = document.body.innerHTML
    .replace(/(id|for|aria-labelledby|aria-describedby|aria-controls|list)="[^"]*"/g, '$1="X"')
    .replace(/"[^"]*[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}[^"]*"/g, '"X"')
    .replace(/></g, '>\n<');
  act(() => {
    ReactDOM.unmountComponentAtNode(root);
  });
  document.body.innerHTML = '';
  return out;
}

const liveness = {
  enabled: true,
  intervalSeconds: 20,
  checkedAt: '2026-10-07T09:01:00+00:00',
  graphMtime: null,
  nodes: labLiveness.passes[2].nodes,
};

function load(graph: any) {
  data.graph = { graph, fileTime: '2026-10-07T09:00:00+00:00', loading: false, error: null };
  data.vulns = { doc: labVulns, loading: false, error: null };
  data.paths = { doc: labPaths, loading: false, error: null, reload: async () => {} };
  data.liveness = liveness;
}

describe('page rendering on the golden lab outputs', () => {
  // "last check-in 5 d ago" is relative to now: pin now so the snapshot holds.
  beforeAll(() => jest.spyOn(Date, 'now').mockReturnValue(Date.parse('2026-10-12T12:00:00Z')));
  afterAll(() => jest.restoreAllMocks());
  beforeEach(() => load(labGraph));

  it('vulnerability report', () => {
    expect(html(<VulnerabilityReportPage />)).toMatchSnapshot();
  });

  it('vulnerability report with liveness off', () => {
    data.liveness = { enabled: false, nodes: {} };
    expect(html(<VulnerabilityReportPage />)).toMatchSnapshot();
  });

  for (const [name, graph] of [
    ['lab', labGraph],
    ['unmanaged', unmanagedGraph],
  ] as Array<[string, any]>) {
    for (const node of graph.nodes) {
      it(`device detail: ${name} ${node.node_id}`, () => {
        load(graph);
        const out = html(<DeviceDetail node={node} onClose={() => {}} />);
        // a device's front panel is the first section of its drawer
        const first = /euiFlyoutBody[\s\S]*?<h3[^>]*>([^<]*)<\/h3>/.exec(out)![1];
        expect(first).toBe(node.kind === 'device' ? 'Ports' : 'Protect this asset');
        expect(out).toMatchSnapshot();
      });
    }
  }

  const scans: Array<[string, any]> = [
    ['none', null],
    ['idle', { status: 'idle', defaults: { checkDefaultCommunities: true } }],
    ['running', { status: 'running', stage: 'Crawling the network over SNMP/LLDP', startedAt: '2026-10-07T09:00:00Z' }],
    ['failed', { status: 'failed', message: 'nmap exploded', finishedAt: '2026-10-07T09:00:00Z' }],
    ['done', { status: 'done', message: 'Scan finished.', finishedAt: '2026-10-07T09:00:00Z', nmapAvailable: false, defaults: { nmapUnmanaged: true } }],
  ];
  for (const [name, scan] of scans) {
    it(`scan settings: ${name}`, () => {
      data.scan = { scan, start: async () => {} };
      expect(html(<ScanSettingsPage />)).toMatchSnapshot();
    });
  }
});

describe('device drawer width', () => {
  const graph = { ...smallGraph, nodes: [...smallGraph.nodes, switchHp1920, switch48, accessPoint] };
  const realWidth = window.innerWidth;
  afterEach(() => {
    Object.defineProperty(window, 'innerWidth', { configurable: true, value: realWidth });
    jest.restoreAllMocks();
    document.body.innerHTML = '';
  });

  // opens the drawer in a window `windowWidth` px wide; jsdom has no layout, so
  // the card reports the inner width of the drawer it sits in
  function open(node: any, windowWidth: number) {
    Object.defineProperty(window, 'innerWidth', { configurable: true, value: windowWidth });
    load(graph);
    const inner = (drawerWidth(node, windowWidth) ?? DRAWER_WIDTH) - DRAWER_PAD;
    jest.spyOn(HTMLElement.prototype, 'clientWidth', 'get').mockImplementation(function (this: HTMLElement) {
      return this.classList.contains('vmFp') || this.classList.contains('vmFpStrip') ? inner : 0;
    });
    const root = document.createElement('div');
    document.body.appendChild(root);
    act(() => {
      ReactDOM.render(<DeviceDetail node={node} onClose={() => {}} />, root);
    });
    const flyout = document.querySelector('[data-test-subj="vmDetailFlyout"]') as HTMLElement;
    const svg = flyout.querySelector('[data-test-subj="vmFaceplate"]')!;
    const scale = Number(svg.getAttribute('width')) / Number(svg.getAttribute('viewBox')!.split(' ')[2]);
    const scrolls = flyout.querySelector('[data-test-subj="vmFaceplateStrip"]')!.className.includes('--scroll');
    act(() => {
      ReactDOM.unmountComponentAtNode(root);
    });
    return { flyout, scale, scrolls };
  }

  it.each([
    ['48+4 HP', switchHp1920],
    ['48+2 Cisco', switch48],
  ])('%s at 1600 px: a drawer wide enough for the strip at scale >= 1, no scroll', (_n, node) => {
    const { flyout, scale, scrolls } = open(node, 1600);
    const wide = drawerWidth(node, 1600)!;
    expect(wide).toBeGreaterThan(DRAWER_WIDTH);
    expect(flyout.style.width).toBe(`${wide}px`);
    expect(flyout.className).toContain('vmDetailWide');
    expect(scale).toBeGreaterThanOrEqual(1);
    expect(scrolls).toBe(false);
  });

  it.each([
    ['24+2 switch', switch24],
    ['firewall', fortigate],
    ['access point', accessPoint],
  ])('%s at 1600 px keeps the usual width, and its panel fits', (_n, node) => {
    const { flyout, scale, scrolls } = open(node, 1600);
    expect(flyout.style.width).toBe('');
    expect(flyout.style.maxWidth).toBe(`${DRAWER_WIDTH}px`);
    expect(flyout.className).not.toContain('vmDetailWide');
    expect(scale).toBeGreaterThanOrEqual(1);
    expect(scrolls).toBe(false);
  });

  it('48+4 HP at 800 px: the drawer is capped at 90% and the strip scrolls', () => {
    const { flyout, scrolls } = open(switchHp1920, 800);
    expect(flyout.style.width).toBe('720px');
    expect(scrolls).toBe(true);
  });
});
