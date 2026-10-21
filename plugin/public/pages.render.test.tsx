/**
 * @jest-environment jsdom
 */
// Renders the larger pages on the backend's golden lab outputs and compares the
// HTML with a stored snapshot, so a refactor that changes what a user sees
// fails here. EUI's generated element ids differ per run and are blanked.
import React from 'react';
import ReactDOM from 'react-dom';
import { act, Simulate } from 'react-dom/test-utils';
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
jest.mock('./lib/services', () => ({
  useServices: () => ({ http: { get: () => new Promise(() => undefined) }, history: data.history }),
}));
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
import { AttackPathsPage } from './components/attackpaths/AttackPathsPage';
import { ON_PATH_HELP } from './components/vulnreport/ReportControls';
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

describe('vulnerability report: staged filters', () => {
  beforeAll(() => jest.spyOn(Date, 'now').mockReturnValue(Date.parse('2026-10-12T12:00:00Z')));
  afterAll(() => jest.restoreAllMocks());
  let root: HTMLDivElement;
  beforeEach(() => {
    load(labGraph);
    root = document.createElement('div');
    document.body.appendChild(root);
    act(() => {
      ReactDOM.render(<VulnerabilityReportPage />, root);
    });
  });
  afterEach(() => {
    act(() => {
      ReactDOM.unmountComponentAtNode(root);
    });
    document.body.innerHTML = '';
  });

  const q = (subj: string) => root.querySelector(`[data-test-subj="${subj}"]`) as HTMLElement | null;
  const result = () => q('vmReportResultText')!.textContent;
  const report = () => q('vmReport')!.innerHTML;
  const confidence = () => q('vmConfidence') as HTMLSelectElement;
  const pick = (value: string) =>
    act(() => {
      Simulate.change(confidence(), { target: { value } } as any);
    });
  const click = (el: HTMLElement) =>
    act(() => {
      el.click();
    });
  const applyButton = () => q('vmApplyFilters') as HTMLButtonElement;

  it('a changed filter does not change the report until Apply', () => {
    const before = { result: result(), report: report() };
    expect(applyButton().disabled).toBe(true);
    expect(q('vmFiltersChanged')).toBeNull();
    pick('confirmed');
    // the draft changed, the report did not
    expect(result()).toBe(before.result);
    expect(report()).toBe(before.report);
    expect(applyButton().disabled).toBe(false);
    expect(applyButton().className).toContain('vmApply--dirty');
    expect(q('vmFiltersChanged')!.textContent).toBe('Filters changed: press Apply');
    click(applyButton());
    expect(report()).not.toBe(before.report);
    expect(result()).not.toBe(before.result);
    expect(q('vmFilterBadge-confidence')!.textContent).toContain('Confirmed only');
    expect(applyButton().disabled).toBe(true);
    expect(q('vmFiltersChanged')).toBeNull();
  });

  it('Enter in a control applies the draft', () => {
    const before = result();
    pick('potential');
    expect(result()).toBe(before);
    act(() => {
      Simulate.keyDown(confidence(), { key: 'Enter' });
    });
    expect(result()).not.toBe(before);
    expect(q('vmFilterBadge-confidence')!.textContent).toContain('Potential only');
  });

  it('Reset restores the defaults and applies them', () => {
    const before = { result: result(), report: report() };
    pick('confirmed');
    click(applyButton());
    expect(result()).not.toBe(before.result);
    click(q('vmResetFilters')!);
    expect(result()).toBe(before.result);
    expect(report()).toBe(before.report);
    expect(confidence().value).toBe('all');
    expect(q('vmFilterBadge-confidence')).toBeNull();
  });

  it('removing a badge applies at once', () => {
    const before = result();
    pick('confirmed');
    click(applyButton());
    const remove = q('vmFilterBadge-confidence')!.querySelector('button')!;
    expect(remove.getAttribute('aria-label')).toBe('Remove filter: Confirmed only');
    click(remove);
    expect(result()).toBe(before);
    expect(q('vmFilterBadge-confidence')).toBeNull();
    expect(confidence().value).toBe('all');
  });

  it('shows what the applied filters show', () => {
    expect(result()).toMatch(/^Showing \d+ assets?, \d+ findings?$/);
  });

  it('explains the attack path switch, and disables it with no protected asset', () => {
    expect(root.textContent).toContain(ON_PATH_HELP);
    const enabled = q('vmOnPathSwitch') as HTMLButtonElement;
    expect(enabled.disabled).toBe(false);
    act(() => {
      ReactDOM.unmountComponentAtNode(root);
    });
    data.paths = { doc: { ...labPaths, targets: [] }, loading: false, error: null, reload: async () => {} };
    act(() => {
      ReactDOM.render(<VulnerabilityReportPage />, root);
    });
    const disabled = q('vmOnPathSwitch') as HTMLButtonElement;
    expect(disabled.disabled).toBe(true);
    // the help is the tooltip on the disabled switch
    expect(disabled.closest('.euiToolTipAnchor')).not.toBeNull();
  });
});

describe('attack paths: the selected route card', () => {
  let root: HTMLDivElement;
  // three routes to one target; a copy of route #2 from another start is #3
  const [r1, r2] = labPaths.targets[1].routes;
  const three = { ...r2, rank: 3, start: 'host:00:00:00:00:00:03', likelihood: r2.likelihood - 0.1 };
  const doc = { ...labPaths, targets: [{ ...labPaths.targets[1], routes: [r1, r2, three] }] };

  beforeEach(() => {
    load(labGraph);
    data.paths = { doc, loading: false, error: null, reload: async () => {} };
    root = document.createElement('div');
    document.body.appendChild(root);
    act(() => {
      ReactDOM.render(<AttackPathsPage />, root);
    });
  });
  afterEach(() => {
    act(() => {
      ReactDOM.unmountComponentAtNode(root);
    });
    document.body.innerHTML = '';
  });

  const cards = () => Array.from(root.querySelectorAll<HTMLElement>('[data-test-subj="vmRouteTile"]'));
  // the rank of each selected card
  const selected = () =>
    cards()
      .filter((c) => c.getAttribute('aria-selected') === 'true')
      .map((c) => /#(\d+)/.exec(c.textContent!)![1]);

  it('marks only the clicked card selected, and arrow keys move it', () => {
    expect(selected()).toEqual(['1']);
    act(() => {
      Simulate.click(cards()[2]);
    });
    expect(selected()).toEqual(['3']);
    const card = cards()[2];
    expect(card.getAttribute('aria-current')).toBe('true');
    expect(card.textContent).toContain('Selected');
    expect(cards().filter((c) => c.textContent!.includes('Selected'))).toHaveLength(1);

    const key = (k: string) =>
      act(() => {
        Simulate.keyDown(root.querySelector('.vmRouteTile--selected')!, { key: k });
      });
    key('ArrowUp');
    expect(selected()).toEqual(['2']);
    key('ArrowUp');
    key('ArrowUp');
    expect(selected()).toEqual(['1']);
    key('ArrowDown');
    expect(selected()).toEqual(['2']);
  });
});

describe('attack paths: spare-port starts', () => {
  // the lab's L3-Switch protected, reached from its own spare ports (one hop)
  // and from spare ports on L2-Switch (two hops)
  const L3 = 'device:00:23:ac:e5:74:00';
  const L2 = 'device:00:17:95:be:b2:00';
  const onL3 = `start:spare-ports:${L3}:20`;
  const onL2 = `start:spare-ports:${L2}:10`;
  const l3Ports = Array.from({ length: 9 }, (_, i) => `Fa1/0/${i + 7}`);
  const l2Ports = Array.from({ length: 10 }, (_, i) => `Fa0/${i + 9}`);
  const telnet = (from: string, to: string) =>
    ({ kind: 'misconfiguration', from, to, value: 0.2, check: 'mgmt-telnet-enabled', title: 'Telnet enabled' }) as const;
  const route = (start: string, steps: any[], rank: number) => ({
    ...labPaths.targets[1].routes[0], target: L3, start, start_kind: 'spare_ports', steps, rank, likelihood: 0.2 / rank,
  });
  const doc = {
    ...labPaths,
    starting_points: [
      { id: onL3, kind: 'spare_ports', switch: L3, switch_label: 'L3-Switch', vlans: [20], listed_ports: 9, ports: l3Ports },
      { id: onL2, kind: 'spare_ports', switch: L2, switch_label: 'L2-Switch', vlans: [10], listed_ports: 10, ports: l2Ports },
    ],
    targets: [{ ...labPaths.targets[1], routes: [route(onL3, [telnet(onL3, L3)], 1), route(onL2, [telnet(onL2, L2), telnet(L2, L3)], 2)] }],
  };
  let root: HTMLDivElement;
  let pushed: string[];
  beforeEach(() => {
    load(labGraph);
    data.paths = { doc, loading: false, error: null, reload: async () => {} };
    pushed = [];
    data.history = { push: (url: string) => pushed.push(url) };
    root = document.createElement('div');
    document.body.appendChild(root);
    act(() => {
      ReactDOM.render(<AttackPathsPage />, root);
    });
  });
  afterEach(() => {
    act(() => {
      ReactDOM.unmountComponentAtNode(root);
    });
    document.body.innerHTML = '';
  });
  const cards = () => Array.from(root.querySelectorAll<HTMLElement>('[data-test-subj="vmRouteTile"]'));

  it('cards name the switch that holds the ports, and say when it is the target', () => {
    expect(cards()[0].textContent).toContain('from 9 spare port(s) in VLAN 20 on L3-Switch (on the target itself)');
    expect(cards()[1].textContent).toContain('from 10 spare port(s) in VLAN 10 on L2-Switch');
    expect(cards()[1].textContent).not.toContain('on the target itself');
    expect(root.querySelector('[data-test-subj="vmRouteDetail"]')!.textContent).toContain(
      'Assumes 9 spare port(s) in VLAN 20 on L3-Switch (on the target itself)'
    );
  });

  // the map URL "Show on map" opens, and step 1 of the selected route's cards
  const showOnMap = (card: number) => {
    act(() => {
      Simulate.click(cards()[card]);
    });
    act(() => {
      Simulate.click(root.querySelector('[data-test-subj="vmShowOnMap"]')!);
    });
    return new URLSearchParams(pushed[0].split('?')[1]);
  };
  const firstStep = () => root.querySelector('[data-test-subj="vmRouteDetail"] .euiPanel')!.textContent;

  it('one hop: the map walks the target alone, entered by its own spare ports', () => {
    const q = showOnMap(0);
    expect(q.get('route')).toBe(L3);
    expect([q.get('entry'), q.get('vlan'), q.get('ports')]).toEqual([L3, '20', l3Ports.join(',')]);
    expect(firstStep()).toBe('Plug into a spare port in VLAN 20 on L3-Switch');
  });

  it('the switch drawer opens on its front panel with the entry ports ringed', () => {
    const l3 = labGraph.nodes.find((n: any) => n.node_id === L3) as any;
    const entry = { switch: L3, vlan: 20, ports: ['Fa1/0/2', 'Fa1/0/3'] };
    act(() => {
      ReactDOM.render(<DeviceDetail node={l3} onClose={() => {}} route={[L3]} entry={entry} />, root);
    });
    const flyout = document.querySelector('[data-test-subj="vmDetailFlyout"]')!;
    expect(flyout.querySelector('h3')!.textContent).toBe('Ports');
    const ringed = Array.from(flyout.querySelectorAll('.vmFpRoute')).map((r) => r.parentElement!.getAttribute('data-port'));
    expect(ringed).toEqual(['FastEthernet1/0/2', 'FastEthernet1/0/3']);
  });

  it('two hops: the map walks L2 -> L3, entered by the spare ports on L2', () => {
    const q = showOnMap(1);
    expect(q.get('route')).toBe(`${L2},${L3}`);
    expect([q.get('entry'), q.get('vlan'), q.get('ports')]).toEqual([L2, '10', l2Ports.join(',')]);
    expect(firstStep()).toBe('Plug into a spare port in VLAN 10 on L2-Switch');
  });
});
