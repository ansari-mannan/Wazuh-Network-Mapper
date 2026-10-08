import { configSchema } from './config';

describe('liveness config', () => {
  it('defaults to a 10 s interval, 2 misses and a 30 s check-in age', () => {
    const { liveness } = configSchema.validate({});
    expect(liveness.enabled).toBe(false);
    expect(liveness.intervalSeconds).toBe(10);
    expect(liveness.missThreshold).toBe(2);
    expect(liveness.agentMaxAgeSeconds).toBe(30);
  });

  it('rescans automatically by default, at most every 120 s', () => {
    const { liveness } = configSchema.validate({});
    expect(liveness.autoRescan).toBe(true);
    expect(liveness.minRescanIntervalSeconds).toBe(120);
    expect(() => configSchema.validate({ liveness: { minRescanIntervalSeconds: 59 } })).toThrow();
    expect(configSchema.validate({ liveness: { minRescanIntervalSeconds: 60 } }).liveness.minRescanIntervalSeconds).toBe(60);
  });

  it('keeps the minimums', () => {
    expect(() => configSchema.validate({ liveness: { intervalSeconds: 9 } })).toThrow();
    expect(() => configSchema.validate({ liveness: { missThreshold: 0 } })).toThrow();
    expect(() => configSchema.validate({ liveness: { intervalSeconds: 10, missThreshold: 1 } })).not.toThrow();
  });
});

describe('device CVE config', () => {
  it('looks devices up in NVD by default', () => {
    expect(configSchema.validate({}).deviceCves).toBe(true);
    expect(configSchema.validate({ deviceCves: false }).deviceCves).toBe(false);
  });
});
