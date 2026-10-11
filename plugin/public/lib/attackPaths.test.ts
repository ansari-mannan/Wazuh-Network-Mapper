import { AttackPathsDoc, AttackRoute, AttackStep, AttackTarget } from '../../common';
import {
  compareRoutes,
  IMPORTANCE_RANK,
  likelihoodLabel,
  likelihoodText,
  pageState,
  physicalPathNodeIds,
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

  it('shows the label with the value beside it', () => {
    expect(likelihoodText(0.9)).toBe('Very likely · 0.90');
    expect(likelihoodText(0.18)).toBe('Unlikely · 0.18');
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
