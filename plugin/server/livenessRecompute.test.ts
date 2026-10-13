import { createLivenessRecompute, inactiveHosts } from './livenessRecompute';

const pass = (scanTime: string, inactive: string[]) => ({
  graph_scan_time: scanTime,
  nodes: {
    'endpoint:101': { state: inactive.includes('endpoint:101') ? 'inactive' : 'active' },
    'endpoint:104': { state: inactive.includes('endpoint:104') ? 'inactive' : 'active' },
    'device:sw': { state: 'inactive' }, // a device: never a start, never a reason
  },
});

function setup(enabled = true) {
  let scanRunning = false;
  const recompute = jest.fn(async () => undefined);
  const logger = { info: jest.fn(), warn: jest.fn() };
  const onPass = createLivenessRecompute({
    enabled,
    runExclusive: (task) => (scanRunning ? null : task()),
    recompute,
    logger,
  });
  return { onPass, recompute, logger, setScanRunning: (v: boolean) => (scanRunning = v) };
}

describe('inactiveHosts', () => {
  it('lists the hosts a pass marks inactive, without devices', () => {
    expect(inactiveHosts(pass('T1', ['endpoint:104']))).toEqual(['endpoint:104']);
    expect(inactiveHosts(null)).toEqual([]);
  });
});

describe('liveness recompute', () => {
  it('recomputes on the first pass, then when the inactive set changes', () => {
    const t = setup();
    expect(t.onPass(pass('T1', []))).toBe(true);
    expect(t.onPass(pass('T1', ['endpoint:104']))).toBe(true); // Mannan-PC went quiet
    expect(t.onPass(pass('T1', []))).toBe(true); // and came back
    expect(t.recompute).toHaveBeenCalledTimes(3);
  });

  it('does not recompute while the inactive set is unchanged', () => {
    const t = setup();
    t.onPass(pass('T1', ['endpoint:104']));
    expect(t.onPass(pass('T1', ['endpoint:104']))).toBe(false);
    expect(t.onPass(pass('T1', ['endpoint:104']))).toBe(false);
    expect(t.recompute).toHaveBeenCalledTimes(1);
  });

  it('recomputes once on the first pass for a new graph, even with the same set', () => {
    const t = setup();
    t.onPass(pass('T1', ['endpoint:104']));
    expect(t.onPass(pass('T2', ['endpoint:104']))).toBe(true); // a scan wrote paths without liveness
    expect(t.onPass(pass('T2', ['endpoint:104']))).toBe(false);
    expect(t.recompute).toHaveBeenCalledTimes(2);
  });

  it('skips while a scan runs and lets the next pass try again', () => {
    const t = setup();
    t.onPass(pass('T1', []));
    t.setScanRunning(true);
    expect(t.onPass(pass('T1', ['endpoint:104']))).toBe(false);
    expect(t.recompute).toHaveBeenCalledTimes(1);
    t.setScanRunning(false);
    expect(t.onPass(pass('T1', ['endpoint:104']))).toBe(true);
    expect(t.recompute).toHaveBeenCalledTimes(2);
  });

  it('does nothing with liveness off', () => {
    const t = setup(false);
    expect(t.onPass(pass('T1', ['endpoint:104']))).toBe(false);
    expect(t.recompute).not.toHaveBeenCalled();
  });

  it('logs a failed recompute', async () => {
    const t = setup();
    t.recompute.mockRejectedValueOnce(new Error('boom'));
    t.onPass(pass('T1', []));
    await new Promise((r) => setImmediate(r));
    expect(t.logger.warn).toHaveBeenCalledWith(expect.stringMatching(/boom/));
  });
});
