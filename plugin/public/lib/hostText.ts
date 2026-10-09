import { Coverage, GraphNode } from '../../common';

// Plain words for hosts without a Wazuh agent (backend/vulnmapper/hosts.py),
// for the detail flyout and the overview. No theme imports: unit tested.

/** Why an unmanaged host's software and vulnerabilities are not known; empty for any other node. */
export function unmanagedText(node: GraphNode): string {
  if (node.kind !== 'endpoint' || !node.unmanaged) return '';
  const base = 'No Wazuh agent reports from this machine, so its software and vulnerabilities are not known.';
  return node.snmp
    ? `${base} It answered the scan over SNMP; what it reported is shown below, and any CVEs are matched by software version only.`
    : base;
}

/** The maker from the MAC, "Randomised or virtual address", or why there is none. */
export function manufacturerText(node: GraphNode): string {
  if (node.kind !== 'endpoint' || !node.mac_type) return '';
  if (node.mac_type === 'local') return 'Randomised or virtual address (names no manufacturer)';
  return node.mac_vendor || 'Not in the IEEE registry';
}

const NAME_SOURCES: Record<string, string> = {
  dns: 'Reverse DNS',
  snmp: 'Its own SNMP system name',
};

/** Where a name not from Wazuh came from; empty when it came from Wazuh or the network devices. */
export function nameSourceText(source: string | undefined): string {
  return source ? NAME_SOURCES[source] || source : '';
}

/** "7 of 10 hosts have a Wazuh agent". */
export function coverageText(c: Coverage): string {
  if (c.hosts === 0) return 'No hosts in this graph';
  return `${c.managed} of ${c.hosts} ${c.hosts === 1 ? 'host has' : 'hosts have'} a Wazuh agent`;
}
