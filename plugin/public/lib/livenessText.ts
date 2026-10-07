import { NodeLiveness } from '../../common';

// How a node's liveness was last decided, in words, for the detail flyout and
// the "Inactive (n)" panel.
export function livenessMethod(l: NodeLiveness): string {
  if (l.method === 'icmp') return 'ping';
  if (l.method === 'snmp') return 'SNMP';
  if (l.method === 'port') return 'switch port down';
  if (l.reason === 'shared_ip') return 'not checked: IP shared with another node';
  return 'not checked';
}
