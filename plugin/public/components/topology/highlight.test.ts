import { highlightClass } from './highlight';

describe('highlightClass (route spotlight)', () => {
  const route = new Set(['endpoint:1', 'endpoint:2']);
  const pass = new Set(['device:sw']);

  it('leaves every node as drawn when no route is shown', () => {
    expect(highlightClass({ id: 'endpoint:9', kind: 'endpoint' }, null, new Set())).toBe('');
  });

  it('never dims a device, on the route or off it', () => {
    expect(highlightClass({ id: 'device:sw', kind: 'device' }, route, pass)).toBe('');
    expect(highlightClass({ id: 'device:other', kind: 'device' }, route, pass)).toBe('');
  });

  it('dims a host off the route and keeps a host on it', () => {
    expect(highlightClass({ id: 'endpoint:9', kind: 'endpoint' }, route, pass)).toBe('vmDim');
    expect(highlightClass({ id: 'endpoint:1', kind: 'endpoint' }, route, pass)).toBe('');
  });
});
