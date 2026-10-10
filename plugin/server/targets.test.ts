import { applyTarget, attackPathsFilePath, targetsFilePath } from './targets';

describe('applyTarget', () => {
  it('adds a new target with the UI note', () => {
    const next = applyTarget({}, 'endpoint:000', 'high');
    expect(next['endpoint:000'].importance).toBe('high');
    expect(next['endpoint:000'].note).toMatch(/topology map/i);
  });

  it('changes importance but keeps the existing note', () => {
    const current = { 'endpoint:000': { importance: 'low' as const, note: 'my own note' } };
    expect(applyTarget(current, 'endpoint:000', 'high')).toEqual({
      'endpoint:000': { importance: 'high', note: 'my own note' },
    });
  });

  it('removes a target when importance is null', () => {
    const current = { a: { importance: 'high' as const }, b: { importance: 'low' as const } };
    expect(applyTarget(current, 'a', null)).toEqual({ b: { importance: 'low' } });
  });

  it('does not mutate the input', () => {
    const current = { a: { importance: 'high' as const } };
    applyTarget(current, 'a', null);
    expect(current).toEqual({ a: { importance: 'high' } });
  });
});

describe('file paths', () => {
  it('place both files beside the graph', () => {
    expect(targetsFilePath('/data/graph.json')).toBe('/data/targets.json');
    expect(attackPathsFilePath('/data/graph.json')).toBe('/data/attack_paths.json');
  });
});
