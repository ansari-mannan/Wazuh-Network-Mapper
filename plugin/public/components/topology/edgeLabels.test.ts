import { pointOnLink, portLabels } from './edgeLabels';

// The 7 Oct lab scan records this link from L2-Switch (Fa0/1) to L3-Switch
// (Fa1/0/2); the map draws it top-down from L3-Switch, i.e. flipped.
const l2ToL3 = { type: 'lldp' as const, local_port: 'Fa0/1', remote_port: 'Fa1/0/2' };

describe('portLabels', () => {
  it('keeps each port with its own device when the drawing is flipped', () => {
    expect(portLabels(l2ToL3, true)).toEqual({ sourcePort: 'Fa1/0/2', targetPort: 'Fa0/1' });
  });

  it('keeps the recorded order when the drawing is not flipped', () => {
    expect(portLabels(l2ToL3, false)).toEqual({ sourcePort: 'Fa0/1', targetPort: 'Fa1/0/2' });
  });

  it('leaves a missing port out', () => {
    expect(portLabels({ type: 'lldp', local_port: 'Gi1/0/1' }, true)).toEqual({
      sourcePort: undefined,
      targetPort: 'Gi1/0/1',
    });
  });

  it('gives a host link only the switch port, in the middle', () => {
    const hostLink = { type: 'endpoint_link' as const, local_port: 'Fa1/0/15' };
    expect(portLabels(hostLink, true)).toEqual({ center: 'Fa1/0/15' });
    expect(portLabels(hostLink, false)).toEqual({ center: 'Fa1/0/15' });
    expect(portLabels({ type: 'endpoint_link' }, false)).toEqual({ center: undefined });
  });
});

describe('pointOnLink', () => {
  it('starts at the source and ends at the target', () => {
    expect(pointOnLink(0, 0, 200, 180, 0)).toEqual({ x: 0, y: 0 });
    expect(pointOnLink(0, 0, 200, 180, 1)).toEqual({ x: 200, y: 180 });
  });

  it('is the midpoint halfway along a symmetric link', () => {
    const p = pointOnLink(0, 0, 200, 180, 0.5);
    expect(p.x).toBeCloseTo(100);
    expect(p.y).toBeCloseTo(90);
  });

  it('stays near its own end for a small t', () => {
    const near = pointOnLink(100, 100, 400, 280, 0.2);
    expect(near.y).toBeGreaterThan(100);
    expect(near.y).toBeLessThan(190);
    expect(Math.abs(near.x - 100)).toBeLessThan(Math.abs(near.x - 400));
  });
});
