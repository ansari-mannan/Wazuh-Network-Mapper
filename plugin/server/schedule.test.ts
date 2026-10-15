import { mkdtempSync, readFileSync, writeFileSync } from 'fs';
import os from 'os';
import path from 'path';
import { createScheduler, hasEnvCredential, nextRun, parseSchedule, scheduleBody, scheduleFilePath } from './schedule';

// Local-time dates, so the tests hold in any server time zone.
const at = (h: number, m = 0, day = 13) => new Date(2026, 9, day, h, m);

describe('parseSchedule', () => {
  it('reads a saved schedule', () => {
    const text = JSON.stringify({ frequency: 'daily', dailyHour: 3, lastRun: { at: 'x', status: 'skipped', message: 'm' } });
    expect(parseSchedule(text)).toEqual({ frequency: 'daily', dailyHour: 3, lastRun: { at: 'x', status: 'skipped', message: 'm' } });
  });

  it('reads no file, bad JSON or unknown values as off', () => {
    expect(parseSchedule(null).frequency).toBe('off');
    expect(parseSchedule('{nope').frequency).toBe('off');
    expect(parseSchedule(JSON.stringify({ frequency: '2h', dailyHour: 30 }))).toEqual({ frequency: 'off', dailyHour: 2, lastRun: null });
  });
});

describe('nextRun', () => {
  it('is null when off', () => {
    expect(nextRun({ frequency: 'off', dailyHour: 0 }, at(10))).toBeNull();
  });

  it('runs every N hours on the local hours divisible by N', () => {
    expect(nextRun({ frequency: '1h', dailyHour: 0 }, at(10, 30))).toEqual(at(11));
    expect(nextRun({ frequency: '3h', dailyHour: 0 }, at(10, 30))).toEqual(at(12));
    expect(nextRun({ frequency: '6h', dailyHour: 0 }, at(12))).toEqual(at(18)); // strictly after now
    expect(nextRun({ frequency: '12h', dailyHour: 0 }, at(13))).toEqual(at(0, 0, 14));
  });

  it('runs every 15 or 30 minutes on the local quarter or half hours', () => {
    expect(nextRun({ frequency: '15m', dailyHour: 0 }, at(10, 30))).toEqual(at(10, 45)); // strictly after now
    expect(nextRun({ frequency: '15m', dailyHour: 0 }, at(10, 52))).toEqual(at(11));
    expect(nextRun({ frequency: '30m', dailyHour: 0 }, at(10, 29))).toEqual(at(10, 30));
    expect(nextRun({ frequency: '30m', dailyHour: 0 }, at(23, 45))).toEqual(at(0, 0, 14));
  });

  it('runs daily at the chosen hour, today or tomorrow', () => {
    expect(nextRun({ frequency: 'daily', dailyHour: 22 }, at(10))).toEqual(at(22));
    expect(nextRun({ frequency: 'daily', dailyHour: 2 }, at(10))).toEqual(at(2, 0, 14));
  });
});

describe('hasEnvCredential', () => {
  it('accepts the variables the scanner reads', () => {
    expect(hasEnvCredential({ VULNMAPPER_SNMP_COMMUNITY: 'x y' })).toBe(true);
    expect(hasEnvCredential({ SNMP_COMMUNITIES: 'x' })).toBe(true);
    expect(hasEnvCredential({ SNMP_COMMUNITY: 'x' })).toBe(true);
    expect(hasEnvCredential({ SNMP_V3_USER: 'u' })).toBe(true);
    expect(hasEnvCredential({ SNMP_COMMUNITY: '  ' })).toBe(false);
    expect(hasEnvCredential({})).toBe(false);
  });
});

describe('scheduleBody', () => {
  it('accepts a frequency and a whole hour', () => {
    expect(scheduleBody.validate({ frequency: 'daily', dailyHour: 23 })).toEqual({ frequency: 'daily', dailyHour: 23 });
  });

  it('rejects anything else', () => {
    expect(() => scheduleBody.validate({ frequency: '2h', dailyHour: 1 })).toThrow();
    expect(() => scheduleBody.validate({ frequency: 'daily', dailyHour: 24 })).toThrow();
    expect(() => scheduleBody.validate({ frequency: 'daily', dailyHour: 1.5 })).toThrow();
    expect(() => scheduleBody.validate({ frequency: 'daily', dailyHour: 1, community: 'x' })).toThrow();
  });
});

describe('createScheduler', () => {
  let clock: Date;
  let file: string;
  const logger = { info: jest.fn(), warn: jest.fn() };

  beforeEach(() => {
    jest.useFakeTimers();
    clock = at(10, 30);
    jest.setSystemTime(clock);
    file = scheduleFilePath(path.join(mkdtempSync(path.join(os.tmpdir(), 'vm-sched-')), 'graph.json'));
  });
  afterEach(() => jest.useRealTimers());

  const make = (startScan: jest.Mock, hasCredential = true) =>
    createScheduler({ file, startScan, hasCredential: () => hasCredential, logger, now: () => new Date(Date.now()) });

  it('saves the choice, without anything else, and reloads it on start', async () => {
    const s = make(jest.fn());
    await s.set({ frequency: '1h', dailyHour: 2 });
    expect(JSON.parse(readFileSync(file, 'utf8'))).toEqual({ frequency: '1h', dailyHour: 2, lastRun: null });
    expect(s.get().nextRun).toBe(at(11).toISOString());
    s.stop();
    const again = make(jest.fn());
    await again.load();
    expect(again.get().nextRun).toBe(at(11).toISOString());
    again.stop();
  });

  it('starts a scan when due, records its result and arms the next slot', async () => {
    let done: (ok: boolean, m: string) => void = () => undefined;
    const startScan = jest.fn((cb) => ((done = cb), true));
    const s = make(startScan);
    await s.set({ frequency: '1h', dailyHour: 0 });
    jest.advanceTimersByTime(30 * 60 * 1000);
    expect(startScan).toHaveBeenCalledTimes(1);
    expect(s.get().nextRun).toBe(at(12).toISOString());
    done(true, 'Scan completed; graph updated.');
    expect(s.get().lastRun).toEqual({ at: at(11).toISOString(), status: 'completed', message: 'Scan completed; graph updated.' });
    s.stop();
  });

  it('skips a slot while a scan is running, logs it, and arms the next', async () => {
    const startScan = jest.fn(() => false); // the one-at-a-time lock said no
    const s = make(startScan);
    await s.set({ frequency: '1h', dailyHour: 0 });
    jest.advanceTimersByTime(30 * 60 * 1000);
    expect(s.get().lastRun?.status).toBe('skipped');
    expect(logger.info).toHaveBeenCalledWith(expect.stringMatching(/skipped: previous scan still running/));
    expect(s.get().lastRun?.message).toBe('previous scan still running');
    expect(s.get().nextRun).toBe(at(12).toISOString());
    jest.advanceTimersByTime(60 * 60 * 1000);
    expect(startScan).toHaveBeenCalledTimes(2);
    s.stop();
  });

  it('fires every 15 minutes', async () => {
    const startScan = jest.fn(() => true);
    const s = make(startScan);
    await s.set({ frequency: '15m', dailyHour: 0 });
    expect(s.get().nextRun).toBe(at(10, 45).toISOString());
    jest.advanceTimersByTime(15 * 60 * 1000);
    expect(startScan).toHaveBeenCalledTimes(1);
    jest.advanceTimersByTime(15 * 60 * 1000);
    expect(startScan).toHaveBeenCalledTimes(2);
    s.stop();
  });

  it('skips a 15-minute slot during a running scan without queueing it; the next one runs', async () => {
    let running = true; // a manual scan started before the slot
    const startScan = jest.fn(() => !running);
    const s = make(startScan);
    await s.set({ frequency: '15m', dailyHour: 0 });
    jest.advanceTimersByTime(15 * 60 * 1000); // 10:45, still running
    expect(s.get().lastRun).toMatchObject({ at: at(10, 45).toISOString(), status: 'skipped', message: 'previous scan still running' });
    running = false; // it finishes at 10:50: nothing starts then
    jest.advanceTimersByTime(5 * 60 * 1000);
    expect(startScan).toHaveBeenCalledTimes(1);
    jest.advanceTimersByTime(10 * 60 * 1000); // 11:00
    expect(startScan).toHaveBeenCalledTimes(2);
    expect(startScan).toHaveLastReturnedWith(true);
    s.stop();
  });

  it('fails clearly without an SNMP credential in the environment, without starting', async () => {
    const startScan = jest.fn(() => true);
    const s = make(startScan, false);
    await s.set({ frequency: '1h', dailyHour: 0 });
    jest.advanceTimersByTime(30 * 60 * 1000);
    expect(startScan).not.toHaveBeenCalled();
    expect(s.get().lastRun?.status).toBe('failed');
    expect(s.get().lastRun?.message).toMatch(/SNMP_COMMUNITIES/);
    s.stop();
  });

  it('turning it off disarms the timer', async () => {
    const startScan = jest.fn(() => true);
    const s = make(startScan);
    await s.set({ frequency: '1h', dailyHour: 0 });
    await s.set({ frequency: 'off', dailyHour: 0 });
    expect(s.get().nextRun).toBeNull();
    jest.advanceTimersByTime(3 * 60 * 60 * 1000);
    expect(startScan).not.toHaveBeenCalled();
  });

  it('never writes a credential: only the choice and the last run', async () => {
    writeFileSync(file, JSON.stringify({ frequency: '3h', dailyHour: 1, community: 'secret' }));
    const s = make(jest.fn());
    await s.load();
    await s.set({ frequency: '3h', dailyHour: 1 });
    expect(readFileSync(file, 'utf8')).not.toMatch(/secret|community/);
    s.stop();
  });
});
