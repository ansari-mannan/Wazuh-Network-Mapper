import { roleLabel } from './roleLabel';

describe('roleLabel', () => {
  it('names the known device roles', () => {
    expect(roleLabel('l3-switch')).toBe('Layer 3 switch');
    expect(roleLabel('l2-switch')).toBe('Layer 2 switch');
    expect(roleLabel('access-point')).toBe('Access point');
    expect(roleLabel('router', 'device')).toBe('Router / firewall');
  });

  it('never shows a raw code for any other device role', () => {
    expect(roleLabel('firewall')).toBe('Firewall');
    expect(roleLabel('wlan-ap')).toBe('Wlan ap');
    expect(roleLabel('unknown')).toBe('Unknown');
    expect(roleLabel('Unknown Network Device')).toBe('Unknown Network Device');
  });

  it("keeps a host's wording", () => {
    expect(roleLabel('host', 'endpoint')).toBe('host');
    expect(roleLabel('station', 'endpoint')).toBe('station');
  });
});
