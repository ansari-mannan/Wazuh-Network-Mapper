import { shouldReloadGraph } from './graphReload';

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
