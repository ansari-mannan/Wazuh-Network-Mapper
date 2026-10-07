import { NodeLiveness } from '../../common';
import { livenessMethod } from './livenessText';

const rec = (extra: Partial<NodeLiveness>): NodeLiveness => ({ state: 'active', method: null, ...extra });

describe('livenessMethod', () => {
  it('names each probe method in words', () => {
    expect(livenessMethod(rec({ method: 'icmp' }))).toBe('ping');
    expect(livenessMethod(rec({ method: 'snmp' }))).toBe('SNMP');
    expect(livenessMethod(rec({ method: 'port' }))).toBe('switch port down');
  });

  it('explains why a node was not checked', () => {
    expect(livenessMethod(rec({ reason: 'shared_ip' }))).toBe('not checked: IP shared with another node');
    expect(livenessMethod(rec({}))).toBe('not checked');
  });
});
