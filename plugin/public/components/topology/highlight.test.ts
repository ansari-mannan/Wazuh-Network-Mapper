import { highlightClass, routeArrows, routeMarks } from './highlight';

// The lab route CYFOR-4 -> HP-Switch -> L3-Switch. The map draws parent to
// child (L3 above HP above the host), the reverse of the route's travel.
const walk = ['host:cyfor4', 'device:hp', 'device:l3'];
const links = [
  { id: 'l3-hp', source: 'device:l3', target: 'device:hp' },
  { id: 'hp-host', source: 'device:hp', target: 'host:cyfor4' },
  { id: 'l3-l2', source: 'device:l3', target: 'device:l2' },
];

describe('routeArrows', () => {
  it('points each route link along the walk, whatever the drawn direction', () => {
    const arrows = routeArrows(walk, links);
    // drawn hp -> host, travelled host -> hp: the arrow goes on the drawn start (hp)
    expect(arrows.get('hp-host')).toBe('start');
    expect(arrows.get('l3-hp')).toBe('start');
    // drawn as travelled: arrow on the drawn end
    expect(routeArrows(['device:l3', 'device:hp'], links).get('l3-hp')).toBe('end');
  });

  it('leaves links off the route without a route arrow', () => {
    expect(routeArrows(walk, links).has('l3-l2')).toBe(false);
  });
});

describe('routeMarks', () => {
  it('numbers the nodes in travel order and tags the two ends', () => {
    const marks = routeMarks(walk);
    expect([...marks].map(([id, m]) => [id, m.step, m.end])).toEqual([
      ['host:cyfor4', 1, 'start'],
      ['device:hp', 2, undefined],
      ['device:l3', 3, 'target'],
    ]);
  });

  it('keeps the first number for a node the route crosses twice', () => {
    const marks = routeMarks(['host:a', 'device:sw', 'host:b', 'device:sw', 'host:c']);
    expect(marks.get('device:sw')!.step).toBe(2);
    expect(marks.get('host:c')).toEqual({ step: 4, end: 'target' });
  });
});

describe('highlightClass', () => {
  const marks = routeMarks(walk);
  const route = new Set(['host:cyfor4', 'device:l3']);
  const pass = new Set(['device:hp']);

  it('leaves every node as drawn when no route is shown', () => {
    expect(highlightClass({ id: 'host:x', kind: 'endpoint' }, null, new Set(), null)).toBe('');
  });

  it('rings every node on the route, devices and hosts alike', () => {
    expect(highlightClass({ id: 'device:hp', kind: 'device' }, route, pass, marks)).toBe('vmOnRoute');
    expect(highlightClass({ id: 'host:cyfor4', kind: 'endpoint' }, route, pass, marks)).toBe('vmOnRoute');
  });

  it('draws a device off the route as on the normal map and dims a host off it', () => {
    expect(highlightClass({ id: 'device:l2', kind: 'device' }, route, pass, marks)).toBe('');
    expect(marks.has('device:l2')).toBe(false); // so no step badge or tag either
    expect(highlightClass({ id: 'host:x', kind: 'endpoint' }, route, pass, marks)).toBe('vmDim');
  });
});
