import { AttackPathsDoc, AttackRoute, AttackStep, AttackTarget, GraphNode } from '../../common';
import {
  compareRoutes,
  IMPORTANCE_RANK,
  likelihoodLabel,
  likelihoodText,
  isStale,
  pageState,
  physicalPathNodeIds,
  physicalPathWalk,
  routeWalk,
  startKindLabel,
  stepText,
  targetState,
} from './attackPaths';

const upper = (id: string) => id.toUpperCase();

function route(likelihood: number, highest_base_score: number): AttackRoute {
  return { likelihood, highest_base_score } as AttackRoute;
}

describe('likelihoodLabel', () => {
  it('maps the engine step values to their own bands', () => {
    expect(likelihoodLabel(0.9)).toBe('Very likely'); // low complexity
    expect(likelihoodLabel(0.6)).toBe('Likely'); // medium complexity
    expect(likelihoodLabel(0.2)).toBe('Possible'); // high complexity
  });

  it('calls a chain of steps unlikely', () => {
    expect(likelihoodLabel(0.9 * 0.2)).toBe('Unlikely'); // 0.18
    expect(likelihoodLabel(0.01)).toBe('Unlikely');
  });

  it('shows the label with the value as a percentage', () => {
    expect(likelihoodText(0.9)).toBe('Very likely · 90%');
    expect(likelihoodText(0.6)).toBe('Likely · 60%');
    expect(likelihoodText(0.18)).toBe('Unlikely · 18%');
  });
});

describe('compareRoutes', () => {
  it('orders by likelihood, then by highest base score', () => {
    const routes = [route(0.6, 9.8), route(0.9, 5.0), route(0.9, 8.9)];
    expect(routes.slice().sort(compareRoutes)).toEqual([
      route(0.9, 8.9),
      route(0.9, 5.0),
      route(0.6, 9.8),
    ]);
  });
});

describe('IMPORTANCE_RANK', () => {
  it('ranks high before moderate before low', () => {
    expect(IMPORTANCE_RANK.high).toBeLessThan(IMPORTANCE_RANK.moderate);
    expect(IMPORTANCE_RANK.moderate).toBeLessThan(IMPORTANCE_RANK.low);
  });
});

describe('stepText', () => {
  it('renders a weakness step: the asset reached and the CVE with its complexity', () => {
    const step = { kind: 'weakness', to: 'device:x', cve: 'CVE-2006-4950', attack_complexity: 'LOW' } as AttackStep;
    expect(stepText(step, upper)).toEqual({
      kind: 'weakness',
      heading: 'DEVICE:X',
      detail: 'CVE-2006-4950 · low complexity',
    });
  });

  it('renders a misconfiguration step: the finding title and its check name', () => {
    const step = { kind: 'misconfiguration', to: 'device:x', title: 'Telnet enabled', check: 'telnet-enabled' } as AttackStep;
    expect(stepText(step, upper)).toEqual({
      kind: 'misconfiguration',
      heading: 'DEVICE:X',
      detail: 'Telnet enabled · check telnet-enabled',
    });
  });

  it('renders a transit step: the device passed through, lighter than a takeover', () => {
    const step = { kind: 'transit', through: 'device:r', to: 'device:x', note: 'firewall and access rules are not read' } as AttackStep;
    expect(stepText(step, upper)).toEqual({
      kind: 'transit',
      heading: 'passes through DEVICE:R',
      detail: 'firewall and access rules are not read',
    });
  });
});

describe('pageState', () => {
  const doc = (state: string) => ({ metadata: { state } } as Pick<AttackPathsDoc, 'metadata'>);
  it('shows the absent state when there is no file', () => {
    expect(pageState(null)).toBe('absent');
    expect(pageState(doc('absent'))).toBe('absent');
  });
  it('shows the no-targets empty state', () => {
    expect(pageState(doc('no_targets'))).toBe('no_targets');
  });
  it('shows the routes when the file is ok', () => {
    expect(pageState(doc('ok'))).toBe('ok');
  });
});

describe('isStale', () => {
  const doc = (source_scan?: string, state = 'ok') =>
    ({ metadata: { state, source_scan } } as Pick<AttackPathsDoc, 'metadata'>);
  it('is current when computed from the graph shown', () => {
    expect(isStale(doc('2026-10-12T10:00:00Z'), '2026-10-12T10:00:00+00:00')).toBe(false);
  });
  it('is out of date when computed from an older scan', () => {
    expect(isStale(doc('2026-10-11T10:00:00Z'), '2026-10-12T10:00:00Z')).toBe(true);
    expect(isStale(doc(undefined), '2026-10-12T10:00:00Z')).toBe(true);
  });
  it('is never out of date with no file or no graph time', () => {
    expect(isStale(null, '2026-10-12T10:00:00Z')).toBe(false);
    expect(isStale(doc(undefined, 'absent'), '2026-10-12T10:00:00Z')).toBe(false);
    expect(isStale(doc('2026-10-11T10:00:00Z'), undefined)).toBe(false);
  });
});

describe('targetState', () => {
  it('is missing when the id is not in the graph', () => {
    expect(targetState({ present: false } as AttackTarget)).toBe('missing');
  });
  it('is a calm no-routes result when present but nothing reaches it', () => {
    expect(targetState({ present: true, routes: [] } as unknown as AttackTarget)).toBe('no_routes');
  });
  it('is ok when there are routes', () => {
    expect(targetState({ present: true, routes: [route(0.9, 8.9)] } as unknown as AttackTarget)).toBe('ok');
  });
});

describe('physicalPathNodeIds', () => {
  // hostA — hpSwitch — l3 — hostB (a tree, as the map is)
  const edges = [
    { source: 'hostA', target: 'hpSwitch' },
    { source: 'hpSwitch', target: 'l3' },
    { source: 'l3', target: 'hostB' },
  ];

  it('lights the switch between two assets, not just the endpoints', () => {
    expect(new Set(physicalPathNodeIds(['hostA', 'l3'], edges))).toEqual(
      new Set(['hostA', 'hpSwitch', 'l3'])
    );
  });

  it('threads every device on the way across several hops', () => {
    expect(new Set(physicalPathNodeIds(['hostA', 'hostB'], edges))).toEqual(
      new Set(['hostA', 'hpSwitch', 'l3', 'hostB'])
    );
  });

  // An unparented host (no edges): the map places it under the device in its
  // /24; failing that, it joins at its VLAN's access switch.
  const n = (node_id: string, kind: 'device' | 'endpoint', ip: string | null, vlan?: number) =>
    ({ node_id, kind, ip, vlan } as GraphNode);
  const nodes = [
    n('hostA', 'endpoint', '10.0.1.5', 10),
    n('hpSwitch', 'device', '10.0.1.2'),
    n('l3', 'device', '10.0.2.1'),
    n('hostB', 'endpoint', '10.0.2.9', 20),
    n('orphan', 'endpoint', '10.0.1.77', 10),
    n('roamer', 'endpoint', '192.168.9.9', 10),
  ];

  it('lights the switches to an unparented host through the device it is placed under', () => {
    expect(new Set(physicalPathNodeIds(['hostB', 'orphan'], edges, nodes))).toEqual(
      new Set(['hostB', 'l3', 'hpSwitch', 'orphan'])
    );
  });

  it('falls back to the VLAN’s access switch when no device shares the /24', () => {
    expect(new Set(physicalPathNodeIds(['hostB', 'roamer'], edges, nodes))).toEqual(
      new Set(['hostB', 'l3', 'hpSwitch', 'roamer'])
    );
  });

  it('walks through the router a transit step crosses', () => {
    const r = {
      start: 'hostA',
      steps: [
        { kind: 'transit', from: 'hostA', through: 'l3', to: 'hostB' },
        { kind: 'weakness', from: 'l3', to: 'hostB' },
      ],
    } as unknown as AttackRoute;
    expect(routeWalk(r)).toEqual(['hostA', 'l3', 'hostB']);
  });

  it('falls back to the two endpoints when no physical path exists', () => {
    expect(new Set(physicalPathNodeIds(['hostA', 'island'], edges))).toEqual(
      new Set(['hostA', 'island'])
    );
  });
});

describe('startKindLabel', () => {
  it('names each starting-point kind in words', () => {
    expect(startKindLabel('managed_host')).toBe('a managed host');
    expect(startKindLabel('unmanaged_host')).toBe('an unmanaged host');
    expect(startKindLabel('spare_ports')).toBe('spare switch ports');
  });
});

describe('physicalPathWalk', () => {
  // hostA — hpSwitch — l3 — hostB, recorded parent to child (l3 first)
  const edges = [
    { source: 'hpSwitch', target: 'hostA' },
    { source: 'l3', target: 'hpSwitch' },
    { source: 'l3', target: 'hostB' },
  ];

  it('orders the path start to target, switches in the order crossed', () => {
    expect(physicalPathWalk(['hostA', 'l3', 'hostB'], edges)).toEqual(['hostA', 'hpSwitch', 'l3', 'hostB']);
  });

  it('crosses the same nodes as physicalPathNodeIds', () => {
    const walk = ['hostA', 'hostB'];
    expect(new Set(physicalPathWalk(walk, edges))).toEqual(new Set(physicalPathNodeIds(walk, edges)));
  });
});
