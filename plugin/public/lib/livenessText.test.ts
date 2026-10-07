import { NodeLiveness } from '../../common';
import { ago, livenessMethod } from './livenessText';

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

describe('livenessMethod for the Wazuh agent check-in', () => {
  const NOW = Date.parse('2026-10-07T09:00:20Z');
  const agent = (status: string, last_keepalive: string | null, extra: Partial<NodeLiveness> = {}) =>
    rec({ method: 'agent', agent: { status, last_keepalive }, ...extra });

  it('says how long ago the agent checked in', () => {
    expect(livenessMethod(agent('active', '2026-10-07T09:00:12+00:00'), NOW)).toBe(
      'Wazuh agent check-in, 8 s ago'
    );
  });

  it('names the manager itself rather than a far-future time', () => {
    expect(livenessMethod(agent('active', '9999-12-31T23:59:59+00:00'), NOW)).toBe(
      'Wazuh agent check-in (the Wazuh manager)'
    );
  });

  it('describes an agent the manager reports as gone', () => {
    expect(livenessMethod(agent('disconnected', '2026-10-07T06:00:20+00:00'), NOW)).toBe(
      'Wazuh agent disconnected, last check-in 3 h ago'
    );
    expect(livenessMethod(agent('never_connected', null), NOW)).toBe('Wazuh agent never connected');
    expect(livenessMethod(agent('pending', null), NOW)).toBe('Wazuh agent pending');
  });

  it('says when this pass could not read the Manager API', () => {
    expect(
      livenessMethod(agent('active', '2026-10-07T09:00:12+00:00', { reason: 'agent_unavailable' }), NOW)
    ).toBe('Wazuh agent check-in, 8 s ago (Manager API not reachable on the last check)');
    expect(livenessMethod(rec({ method: 'agent', reason: 'agent_not_listed' }), NOW)).toBe(
      'Wazuh agent check-in (agent not listed by the manager)'
    );
  });
});

describe('ago', () => {
  const NOW = Date.parse('2026-10-07T09:00:20Z');
  it('picks a readable unit', () => {
    expect(ago('2026-10-07T09:00:20Z', NOW)).toBe('0 s ago');
    expect(ago('2026-10-07T08:59:21Z', NOW)).toBe('59 s ago');
    expect(ago('2026-10-07T08:55:20Z', NOW)).toBe('5 min ago');
    expect(ago('2026-10-07T06:00:20Z', NOW)).toBe('3 h ago');
    expect(ago('2026-10-05T09:00:20Z', NOW)).toBe('2 d ago');
  });
  it('is null for a missing, bad or future time', () => {
    expect(ago(null, NOW)).toBeNull();
    expect(ago('garbage', NOW)).toBeNull();
    expect(ago('2026-10-07T09:10:00Z', NOW)).toBeNull();
  });
});
