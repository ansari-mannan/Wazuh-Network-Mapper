import { filesToReload, shouldReloadGraph } from './graphReload';

describe('shouldReloadGraph', () => {
  const T1 = '2026-10-07T09:00:00.000Z';
  const T2 = '2026-10-07T09:05:00.000Z';

  it('reloads when the graph file changed on the server', () => {
    expect(shouldReloadGraph(T2, T1, null)).toBe(true);
  });

  it('reloads when a graph appears that could not be loaded before', () => {
    expect(shouldReloadGraph(T2, null, null)).toBe(true);
  });

  it('does not reload for the graph already shown', () => {
    expect(shouldReloadGraph(T1, T1, null)).toBe(false);
  });

  it('does not reload without a file time', () => {
    expect(shouldReloadGraph(null, T1, null)).toBe(false);
    expect(shouldReloadGraph(undefined, T1, null)).toBe(false);
  });

  it('tries each new file time once, so a failing read does not loop', () => {
    expect(shouldReloadGraph(T2, T1, T2)).toBe(false);
  });
});

describe('filesToReload', () => {
  const at = (graph: string | null, vulnerabilities: string | null, attackPaths: string | null) => ({ graph, vulnerabilities, attackPaths });

  it('only records the times on the first poll, except a graph newer than the one shown', () => {
    expect(filesToReload(null, at('G1', 'V1', 'A1'), 'G1', null)).toEqual({ graph: false, vulnerabilities: false, attackPaths: false });
    expect(filesToReload(null, at('G2', 'V1', 'A1'), 'G1', null).graph).toBe(true);
  });

  it('reloads each document whose file changed', () => {
    // a liveness recompute: only the attack paths
    expect(filesToReload(at('G1', 'V1', 'A1'), at('G1', 'V1', 'A2'), 'G1', null)).toEqual({
      graph: false, vulnerabilities: false, attackPaths: true,
    });
    // a rescore elsewhere: all three, scan_time unchanged
    expect(filesToReload(at('G1', 'V1', 'A1'), at('G2', 'V2', 'A2'), 'G1', null)).toEqual({
      graph: true, vulnerabilities: true, attackPaths: true,
    });
  });

  it('does not reload a graph already shown or already tried', () => {
    expect(filesToReload(at('G1', 'V1', 'A1'), at('G2', 'V1', 'A1'), 'G2', null).graph).toBe(false);
    expect(filesToReload(at('G1', 'V1', 'A1'), at('G2', 'V1', 'A1'), 'G1', 'G2').graph).toBe(false);
  });
});
