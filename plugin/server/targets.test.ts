import { applyTarget, attackPathsFilePath, BUSY, recomputeArgs, targetsFilePath, updateTarget } from './targets';

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

describe('recomputeArgs', () => {
  it('rescores after a target change, with the liveness state when given', () => {
    expect(recomputeArgs('/d/graph.json', '/d/liveness.json', true)).toEqual([
      '-m', 'vulnmapper.scoring.rescore', '--graph', '/d/graph.json', '--liveness', '/d/liveness.json',
    ]);
  });

  it('only recomputes the attack paths otherwise', () => {
    expect(recomputeArgs('/d/graph.json')).toEqual(['-m', 'vulnmapper.attackpaths', '--graph', '/d/graph.json']);
  });
});

describe('updateTarget', () => {
  function setup(scanRunning: boolean) {
    const deps = {
      runExclusive: (task: () => Promise<void>) => (scanRunning ? null : task()),
      read: jest.fn(async () => ({})),
      write: jest.fn(async () => undefined),
      recompute: jest.fn(async () => undefined),
    };
    return deps;
  }

  it('refuses while a scan runs, without saving or rescoring', async () => {
    const deps = setup(true);
    expect(await updateTarget(deps, 'a', 'high')).toEqual({ status: 409, message: BUSY });
    expect(deps.write).not.toHaveBeenCalled();
    expect(deps.recompute).not.toHaveBeenCalled();
  });

  it('saves and rescores when idle', async () => {
    const deps = setup(false);
    const result = await updateTarget(deps, 'a', 'high');
    expect(result).toEqual({ status: 200, targets: { a: { importance: 'high', note: expect.any(String) } } });
    expect(deps.write).toHaveBeenCalledTimes(1);
    expect(deps.recompute).toHaveBeenCalledTimes(1);
  });

  it('reports a failed rescore after saving', async () => {
    const deps = setup(false);
    deps.recompute.mockRejectedValueOnce(new Error('boom'));
    expect(await updateTarget(deps, 'a', 'high')).toEqual({
      status: 500,
      message: 'targets saved, but the rescore failed: boom',
    });
  });
});
