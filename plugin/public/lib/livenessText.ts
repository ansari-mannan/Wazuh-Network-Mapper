import { NodeLiveness } from '../../common';

// How a node's liveness was last decided, in words, for the detail flyout and
// the "Inactive (n)" panel.

/** "8 s ago", "5 min ago", "3 h ago", "2 d ago"; null for a missing, bad or future time. */
export function ago(iso: string | null | undefined, now: number = Date.now()): string | null {
  if (!iso) return null;
  const t = Date.parse(iso);
  if (Number.isNaN(t) || t > now) return null;
  const s = Math.floor((now - t) / 1000);
  if (s < 60) return `${s} s ago`;
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
}

const AGENT_STATUS_WORDS: Record<string, string> = {
  disconnected: 'disconnected',
  pending: 'pending',
  never_connected: 'never connected',
};

function agentMethod(l: NodeLiveness, now: number): string {
  const status = l.agent?.status || '';
  const when = ago(l.agent?.last_keepalive, now);
  // agent 000, the manager, reports a far-future check-in time
  const inFuture = Date.parse(l.agent?.last_keepalive || '') > now;
  let text: string;
  if (AGENT_STATUS_WORDS[status]) {
    text = `Wazuh agent ${AGENT_STATUS_WORDS[status]}${when ? `, last check-in ${when}` : ''}`;
  } else if (status === 'active' && inFuture) {
    text = 'Wazuh agent check-in (the Wazuh manager)';
  } else {
    text = `Wazuh agent check-in${when ? `, ${when}` : ''}`;
  }
  if (l.reason === 'agent_unavailable') text += ' (Manager API not reachable on the last check)';
  if (l.reason === 'agent_not_listed') text += ' (agent not listed by the manager)';
  return text;
}

export function livenessMethod(l: NodeLiveness, now: number = Date.now()): string {
  if (l.method === 'agent') return agentMethod(l, now);
  if (l.method === 'icmp') return 'ping';
  if (l.method === 'snmp') return 'SNMP';
  if (l.method === 'port') return 'switch port down';
  if (l.method === 'wifi') {
    if (l.state === 'inactive' && l.port_down) return 'left the access point';
    const text = "access point's client list";
    return l.reason === 'wifi_unavailable'
      ? `${text} (access point not answering on the last check)`
      : text;
  }
  if (l.method === 'mac-table') {
    const text = "switch's MAC table";
    return l.reason === 'mac_table_unavailable'
      ? `${text} (switch not answering on the last check)`
      : text;
  }
  if (l.reason === 'shared_ip') return 'not checked: IP shared with another node';
  return 'not checked';
}
