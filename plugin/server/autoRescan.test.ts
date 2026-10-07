import { ScanState } from '../common';
import { createAutoRescan } from './autoRescan';

const idle: ScanState = { status: 'idle', message: null, startedAt: null, finishedAt: null };
const suggested = { rescan_suggested: true, rescan_reasons: ['port Gi1/0/9 on L3-Switch came up'] };

function setup(opts: { enabled?: boolean; minIntervalSeconds?: number } = {}) {
  let clock = Date.parse('2026-10-07T09:00:00Z');
  let scan: ScanState = idle;
  const starts: number[] = [];
  const logs: string[] = [];
  const onPass = createAutoRescan({
    enabled: opts.enabled ?? true,
    minIntervalSeconds: opts.minIntervalSeconds ?? 120,
    getScan: () => scan,
    startScan: () => {
      if (scan.status === 'running') return false;
      starts.push(clock);
      scan = { ...idle, status: 'running', startedAt: new Date(clock).toISOString() };
      return true;
    },
    logger: { info: (m: string) => logs.push(m) },
    now: () => clock,
  });
  return {
    onPass,
    starts,
    logs,
    tick: (seconds: number) => (clock += seconds * 1000),
    finishScan: () => (scan = { ...scan, status: 'idle', finishedAt: new Date(clock).toISOString() }),
    setScan: (s: ScanState) => (scan = s),
  };
}

describe('auto rescan', () => {
  it('starts a scan when a pass suggests one', () => {
    const t = setup();
    expect(t.onPass(suggested)).toBe(true);
    expect(t.starts).toHaveLength(1);
    expect(t.logs[0]).toContain('port Gi1/0/9 on L3-Switch came up');
  });

  it('does nothing when the pass does not suggest one', () => {
    const t = setup();
    expect(t.onPass({ rescan_suggested: false, rescan_reasons: [] })).toBe(false);
    expect(t.onPass({})).toBe(false);
    expect(t.onPass(null)).toBe(false);
    expect(t.starts).toHaveLength(0);
  });

  it('never starts one while a scan runs', () => {
    const t = setup();
    t.setScan({ ...idle, status: 'running', startedAt: '2026-10-07T08:00:00Z' });
    expect(t.onPass(suggested)).toBe(false);
    expect(t.starts).toHaveLength(0);
  });

  it('starts at most one per minimum interval', () => {
    const t = setup({ minIntervalSeconds: 120 });
    t.onPass(suggested);
    t.tick(30);
    t.finishScan();
    for (let i = 0; i < 8; i++) {
      t.tick(10); // a pass every 10 s, still suggesting
      t.onPass(suggested);
    }
    expect(t.starts).toHaveLength(1); // 110 s after the first
    t.tick(10); // 120 s
    expect(t.onPass(suggested)).toBe(true);
    expect(t.starts).toHaveLength(2);
  });

  it('counts a manual scan towards the interval', () => {
    const t = setup({ minIntervalSeconds: 120 });
    t.setScan({ ...idle, status: 'idle', startedAt: '2026-10-07T08:59:00Z' }); // 60 s ago
    expect(t.onPass(suggested)).toBe(false);
    t.tick(60);
    expect(t.onPass(suggested)).toBe(true);
  });

  it('is off when liveness.autoRescan is false', () => {
    const t = setup({ enabled: false });
    expect(t.onPass(suggested)).toBe(false);
    expect(t.starts).toHaveLength(0);
  });
});
