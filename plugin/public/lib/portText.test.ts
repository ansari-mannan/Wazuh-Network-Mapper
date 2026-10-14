import { portsText } from './portText';

describe('portsText', () => {
  it('marks the ports only the neighbour reported', () => {
    expect(portsText(['port1', 'to-core-sw'], ['to-core-sw'])).toBe('port1, to-core-sw (inferred from neighbour)');
    expect(portsText(['Gi1/0/1'], undefined)).toBe('Gi1/0/1');
    expect(portsText(undefined, ['x'])).toBe('');
  });
});
